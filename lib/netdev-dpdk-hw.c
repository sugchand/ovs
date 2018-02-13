/*
 * Copyright (c) 2018 Intel, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <errno.h>
#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <vdpo.h>
#include <timeval.h>

#include "dpif-netdev.h"
#include "openvswitch/vlog.h"
#include "netdev-dpdk-hw.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdkhw);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

#define DPDKHW_INIT_SUCCESS 0
#define OVS_CACHE_LINE_SIZE CACHE_LINE_SIZE
#define OVS_HWPORT_DPDK "ovs_dpdkhw"
#define DPDKHW_PORTNO_STR_SIZE ((sizeof(odp_port_t) << 1) + 1)

static int rte_dpdkhw_init = ENODEV;
/* One socket directory for all the switch devices */
static char *hw_vhost_sock_dir = NULL;
static struct ovs_mutex dpdkhw_mutex = OVS_MUTEX_INITIALIZER;
static struct ovs_mutex dpdkhw_flow_mutex OVS_ACQ_AFTER(dpdkhw_mutex) =
                                          OVS_MUTEX_INITIALIZER;

enum dpdkw_dev_type {
    DPDKHW_ETH_PORT = 0,
    DPDKHW_VHOST_PORT = 1
};

#define MAX_HW_DEV_NAME_LEN    128

#define MAX_HW_OFFLOAD_SWITCH_DEVICES 8
struct hw_switches {
    uint16_t num_devs; /* Number of hardware acceleration devices */
    struct dpdkhw_switch dpdkhw_switch[MAX_HW_OFFLOAD_SWITCH_DEVICES];
};
static struct hw_switches hw_switches;
struct dpdkhw_switch *get_hw_switch(uint16_t dev_id);

struct netdev_dpdkhw {
    struct netdev up;
    int max_packet_len;
    int mtu;
    uint16_t dev_id; /* unique id when multiple fpga co-exist on a board */
    uint16_t port_id; /* Port id in device, unique value in the device */
    uint8_t dpdk_port_id; /* The global port id used in DPDK. used for tx/rx */
    int numa_id; /* NUMA node where the hardware port resides */
    int socket_id; /* Socket-id to allocate memory for the port */
    enum dpdkw_dev_type type;
    struct ovs_mutex mutex OVS_ACQ_AFTER(dpdkhw_mutex);
    struct dpdk_mp *dpdk_mp;
    struct netdev_stats stats;
    /* Protects stats */
    rte_spinlock_t stats_lock;

    rte_spinlock_t tx_lock;
    struct eth_addr hwaddr;
    struct rte_eth_link link;
    int requested_mtu;
    enum netdev_flags flags;
    struct shash_node *node; /* Pointer to the hashmap node */
    struct netdev_rxq *hw_rxq; /* Exception Rx queue */
    struct hmap ufid_to_flow_map; /* hashmap to store hardware flows */
    /* XXX : WILL ADD MORE FIELDS ACCORDING TO THE HW CONFIG OPTIONS */
};

static bool
del_ufid_to_rteflow_mapping(const ovs_u128 *ufid,
                            const struct netdev *netdev)
                            OVS_REQUIRES(dpdkhw_flow_mutex)
{
    struct ufid_to_rteflow *data = NULL;
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    struct hmap *ufid_to_flow_map = &dev->ufid_to_flow_map;
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, ufid_to_flow_map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }
    if(data) {
        free(data->actions);
        free(data->hw_flows);
        hmap_remove(ufid_to_flow_map, &data->node);
        free(data);
        return true;
    }
    return false;
}

/*
 * Add flow mapping, return TRUE when a mapping is exists.
 * Reture FALSE if new flow is installed.
 */
static bool
add_ufid_to_rteflow_mapping(const ovs_u128 *ufid, const struct netdev *netdev,
                            const struct rte_flow *hw_flow,
                            struct match *match,
                            const struct nlattr *actions,
                            const size_t actions_len)
                            OVS_REQUIRES(dpdkhw_flow_mutex)
{
    #define HW_FLOW_BLOCK_SIZE  256
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    struct hmap *ufid_to_flow_map = &dev->ufid_to_flow_map;
    struct ufid_to_rteflow *ufid_to_flow;

    ufid_to_flow = get_ufid_to_rteflow_mapping(ufid, netdev);
    if (!ufid_to_flow) {
        /* flow map is not present, add it */
        ufid_to_flow  = xzalloc(sizeof *ufid_to_flow);
        ufid_to_flow->netdev = netdev;
        ufid_to_flow->ufid = *ufid;
        ufid_to_flow->netdev = netdev;
        ufid_to_flow->hw_flows = xzalloc(sizeof (struct rte_flow *) *
                                         HW_FLOW_BLOCK_SIZE);
        ufid_to_flow->hw_flow_size_allocated = HW_FLOW_BLOCK_SIZE;
        ufid_to_flow->hw_flow_size_used = 1;
        ufid_to_flow->hw_flows[0] = hw_flow;
        memcpy(&ufid_to_flow->match, match, sizeof *match);
        ufid_to_flow->actions = xzalloc(actions_len);
        memcpy(ufid_to_flow->actions, actions, actions_len);
        ufid_to_flow->action_len = actions_len;
        hmap_insert(ufid_to_flow_map, &ufid_to_flow->node, hash);
        return false;
    }
    else {
        if (ufid_to_flow->hw_flow_size_used <
            ufid_to_flow->hw_flow_size_allocated) {
            ufid_to_flow->hw_flows[ufid_to_flow->hw_flow_size_used++] =
                                                    hw_flow;
        }
        else {
            /* Need to reallocate the memory for more flows. */
            ufid_to_flow->hw_flow_size_allocated += HW_FLOW_BLOCK_SIZE;
            ufid_to_flow->hw_flows = xrealloc(ufid_to_flow->hw_flows,
                                     sizeof (struct rte_flow *) *
                                     ufid_to_flow->hw_flow_size_allocated);
            ufid_to_flow->hw_flows[ufid_to_flow->hw_flow_size_used++] =
                                                hw_flow;
        }
        return true;
    }
}

struct ufid_to_rteflow *
get_ufid_to_rteflow_mapping(const ovs_u128 *ufid,
                            const struct netdev *netdev)
                            OVS_REQUIRES(dpdkhw_flow_mutex)
{
    struct ufid_to_rteflow *data = NULL;
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    struct hmap *ufid_to_flow_map = &dev->ufid_to_flow_map;
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, ufid_to_flow_map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }
    return NULL;
}

int
get_max_configured_hw_switch_cnt(void)
{
    return hw_switches.num_devs;
}

/* Returns hardware switch configuration for 'dev_id' */
struct dpdkhw_switch *
get_hw_switch(uint16_t dev_id)
{
    int i;
    struct dpdkhw_switch *hw_switch;
    for (i = 0; i < MAX_HW_OFFLOAD_SWITCH_DEVICES; i++) {
        hw_switch = &hw_switches.dpdkhw_switch[i];
        if (hw_switch->dev_id == dev_id) {
            return hw_switch;
        }
    }
    return NULL;
}
