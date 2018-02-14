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

static int
netdev_dpdkhw_flow_put(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   const struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct offload_info *info OVS_UNUSED);

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

bool
netdev_is_dpdkhw_enabled(void)
{
    return (rte_dpdkhw_init == DPDKHW_INIT_SUCCESS);
}

static struct netdev_dpdkhw *
netdev_dpdkhw_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_dpdkhw, up);
}

static struct dpdk_netdev_flow_dump *
netdev_flow_dump_cast(const struct netdev_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpdk_netdev_flow_dump, dump);
}

uint16_t
netdev_get_dpdk_portno(struct netdev *netdev)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    return dev->dpdk_port_id;
}

inline bool
is_dpdkhw_port(const struct netdev *netdev)
{
    return (netdev->netdev_class->flow_put == netdev_dpdkhw_flow_put);
}

inline bool
is_netdev_on_switch(const struct netdev *netdev, const uint16_t switch_id)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    return (dev->dev_id == switch_id);
}

/*
 * Returns valid dpdk_hw netdev for the 'port_no'
 */
struct netdev *
get_hw_netdev(odp_port_t port_no, const struct hmap *hmap)
{
    struct netdev *netdev;

    netdev = netdev_ports_get_from_hmap(port_no, hmap);
    if(netdev) {
        /* The port exists, validate if it is hardware accelerated */
        if (is_dpdkhw_port(netdev)) {
            return netdev;
        }
    }
    return NULL;
}

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

/* XXX: use dpdk malloc for entire OVS. in fact huge page should be used
 * for all other segments data, bss and text. */

static void *
dpdkhw_rte_mzalloc(size_t sz)
{
    void *ptr;

    ptr = rte_zmalloc(OVS_HWPORT_DPDK, sz, OVS_CACHE_LINE_SIZE);
    if (ptr == NULL) {
        out_of_memory();
    }
    return ptr;
}

static struct netdev *
netdev_dpdkhw_alloc(void)
{
    struct netdev_dpdkhw *dev;
    VLOG_INFO("Allocating the port ..");
    dev = dpdkhw_rte_mzalloc(sizeof(*dev));
    if (dev) {
        return &dev->up;
    }
    return NULL;
}

static void
netdev_dpdkhw_dealloc(struct netdev *netdev)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    VLOG_INFO("Freeing the port");
    rte_free(dev);
}

/*
 * Validate if its necessary to configure the netdev again.
 * XXX :: Add more condition if necessary.
 */
inline static bool
need_netdev_reconfigure(struct netdev_dpdkhw *dev)
{
    if (dev->requested_mtu == dev->mtu) {
        return false;
    }
    return true;
}

static int
netdev_dpdkhw_mempool_configure(struct netdev_dpdkhw *dev)
                                OVS_REQUIRES(dpdkhw_mutex)
{
    uint32_t buf_size = dpdk_buf_size(dev->requested_mtu);
    struct dpdk_mp *mp;

    mp = dpdk_mp_get_ext(dev->socket_id, dpdk_framelen_to_mtu(buf_size));
    if (!mp) {
        VLOG_ERR("Insufficient memory to create memory pool for netdev "
                 "%s, with MTU %d on socket %d\n",
                 dev->up.name, dev->requested_mtu, dev->socket_id);
        return ENOMEM;
    } else {
        dpdk_mp_put_ext(dev->dpdk_mp);
        dev->dpdk_mp = mp;
    }
    return 0;
}

static int
dpdkhw_port_queue_setup(struct netdev_dpdkhw *dev, int n_rxq, int n_txq)
{
    int diag = 0;
    int i;
    struct rte_eth_conf conf = { 0 };
    while (n_rxq && n_txq) {
        if (diag) {
            VLOG_INFO("Retrying setup with (rxq:%d txq:%d)", n_rxq, n_txq);
        }
        diag = rte_eth_dev_configure(dev->dpdk_port_id, n_rxq, n_txq, &conf);
        if (diag) {
            VLOG_WARN("Interface %s eth_dev setup error %s\n",
                        dev->up.name, rte_strerror(-diag));
            break;
        }
        for (i = 0; i < n_txq; i++) {
            diag = rte_eth_tx_queue_setup(dev->dpdk_port_id, i,
                                          NIC_PORT_TX_Q_SIZE,
                                          dev->socket_id, NULL);
            if (diag) {
                VLOG_INFO("Interface %s port-id %d txq(%d) setup error: %s",
                            dev->up.name, dev->dpdk_port_id,
                            i, rte_strerror(-diag));
                break;
            }
        }
        /*
         * XXX :: There is no need of trying multiple times to configure ports.
         * Hardware supports only one queue for tx and rx. But keeping the code
         * same as DPDK ETH ports for multi queue support in future.
         */
        if (i != n_txq) {
            /* Retry with less tx queues */
            n_txq = i;
            continue;
        }
        for (i = 0; i < n_rxq; i++) {
            diag = rte_eth_rx_queue_setup(dev->dpdk_port_id, i,
                                          NIC_PORT_RX_Q_SIZE,
                                          dev->socket_id, NULL,
                                          dev->dpdk_mp->mp);
            if (diag) {
                VLOG_INFO("Interface %s rxq(%d) setup error: %s",
                          dev->up.name, i, rte_strerror(-diag));
                break;
            }
        }
        if (i != n_rxq) {
            /* Retry with less rx queues */
            n_rxq = i;
            continue;
        }

        dev->up.n_rxq = n_rxq;
        dev->up.n_txq = n_txq;

        return 0;
    }
    return diag;
}

static int
dpdkhw_port_init(struct netdev_dpdkhw *dev, enum dpdkw_dev_type type)
{
    int err;
    struct ether_addr eth_addr;
    char devargs[PATH_MAX];
    char vhost_path[PATH_MAX];
    struct dpdkhw_switch *hw_switch = NULL;
    uint8_t port_id;

    hw_switch = get_hw_switch(dev->dev_id);
    if (!hw_switch) {
        VLOG_ERR("Hardware switch for port is not configured");
        return -ENODEV;
    }
    if (type == DPDKHW_VHOST_PORT) {
        sprintf(vhost_path, "%s/%s-%d" ,hw_vhost_sock_dir, "hw-vhost-user",
                            dev->port_id);
        sprintf(devargs, "net_representor,parent=ifpga_%04x:%02x:%02x.%x,"
                         "vport_index=%u,num_queue=%u,iface_name=%s",
                         hw_switch->pci_addr.domain,
                         hw_switch->pci_addr.bus,
                         hw_switch->pci_addr.devid,
                         hw_switch->pci_addr.function,
                         dev->port_id, dev->up.n_rxq, vhost_path);
    }
    else {
        VLOG_ERR("Vhost ports are only supported now ");
        return -ENODEV;
    }

    err = rte_eth_dev_attach(devargs, &dev->dpdk_port_id);
    if (err) {
        VLOG_ERR("Failed to attach the dpdk port %d(hw-port-id %d)",
                 dev->dpdk_port_id, dev->port_id);
        return -ENODEV;
    }
    /* Representor port in DPDK has a internal vhost port to interact with
     * hardware. the dev attach will return internal vhost port, however any
     * ovs interaction must be via representor port than vhost port.
     */
    sprintf(devargs, "net_representor.%u.%u", hw_switch->hw_engid,
                                              dev->port_id);
    err = rte_eth_dev_get_port_by_name(devargs, &port_id);
    if (err) {
        VLOG_ERR("Failed to retrieve representor port for hw-vhost-port %d"
                 "(hw-port-id %d)", dev->dpdk_port_id, dev->port_id);
        return -ENODEV;
    }
    dev->dpdk_port_id = port_id; /* Use only representor port id */
    if (!rte_eth_dev_is_valid_port(dev->dpdk_port_id)) {
        VLOG_INFO("Port %d is not a valid DPDK port (hw-port-id %d)",
                  dev->dpdk_port_id, dev->port_id);
        return -ENODEV;
    }

    /*
     * XXX :: In any chance hardware ports may use more queues for every port?
     * If yes, need to allow user to configure it. For now lets configure it
     * as 1,
     */
    err = dpdkhw_port_queue_setup(dev, dev->up.n_rxq, dev->up.n_txq);
    if (err) {
        VLOG_INFO("Failed to setup queues on port %s, rxq %d, txq %d",
                dev->up.name, dev->up.n_rxq, dev->up.n_txq);
        return err;
    }
    err = rte_eth_dev_start(dev->dpdk_port_id);
    if (err) {
        VLOG_ERR("Interface %s start error: %s", dev->up.name,
                 rte_strerror(-err));
        return err;
    }

    rte_eth_promiscuous_enable(dev->dpdk_port_id);
    rte_eth_allmulticast_enable(dev->dpdk_port_id);

    memset(&eth_addr, 0x0, sizeof(eth_addr));
    rte_eth_macaddr_get(dev->dpdk_port_id, &eth_addr);
    VLOG_INFO_RL(&rl, "HW port %d: "ETH_ADDR_FMT"",
                    dev->port_id, ETH_ADDR_BYTES_ARGS(eth_addr.addr_bytes));
    memcpy(dev->hwaddr.ea, eth_addr.addr_bytes, ETH_ADDR_LEN);
    rte_eth_link_get_nowait(dev->dpdk_port_id, &dev->link);
    dev->flags = NETDEV_UP | NETDEV_PROMISC;
    VLOG_INFO("Init the port %s with hw-port-id %d dpdk-port-id %d",
              dev->up.name, dev->port_id, dev->dpdk_port_id);
    return 0;
}
/*
 * DPDKHW init is called after the set_config to do the proper init
 * based on the provided hardware port details
 */
static int
netdev_dpdkhw_init(struct netdev_dpdkhw *dev, enum dpdkw_dev_type type)
                     OVS_REQUIRES(dpdkhw_mutex)
{
    int err = 0;
    if (!need_netdev_reconfigure(dev)) {
        VLOG_INFO("%s is not configuring as there is no param change",
                    dev->up.name);
        return 0;
    }

    rte_spinlock_init(&dev->stats_lock);
    if (rte_dpdkhw_init != DPDKHW_INIT_SUCCESS) {
        VLOG_ERR("Cannot init dpdhardwport %s, OVS hardware offload is"
                 "disabled", dev->up.name);
    }

    /* Get the numa-id,socket for the port and set it.*/
    struct dpdkhw_switch *hw_switch = get_hw_switch(dev->dev_id);
    dev->numa_id = hw_switch->numa_id;
    dev->socket_id = hw_switch->socket_id;
    dev->type = type;
    dev->mtu = dev->requested_mtu;
    /* Initilize the tx queue lock for concurrent access */
    rte_spinlock_init(&dev->tx_lock);
    /* Initilize the flow hash map for the caching the flows */
    hmap_init(&dev->ufid_to_flow_map);

    err = netdev_dpdkhw_mempool_configure(dev);
    if (err) {
        VLOG_INFO("Failed to allocate mempool for device %s", dev->up.name);
        goto out;
    }
    err = dpdkhw_port_init(dev, type);
out:
    return err;
}

/* Reset the dpdhw port configuration to default values. */
static void
netdev_dpdkhw_config_reset(struct netdev_dpdkhw *dev)
{
    dev->dev_id = UINT16_MAX;
    dev->port_id = UINT16_MAX;
    dev->dpdk_port_id = UINT8_MAX;
    dev->numa_id = NUMA_NODE_0;
    dev->socket_id = SOCKET0;
    dev->requested_mtu = ETHER_MTU;
    dev->flags = 0;
}

static int
netdev_dpdkhw_construct(struct netdev *netdev)
{
    ovs_mutex_lock(&dpdkhw_mutex);
    VLOG_INFO("Port is constructed with default set of values %s", netdev->name);
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    netdev_dpdkhw_config_reset(dev);
    ovs_mutex_unlock(&dpdkhw_mutex);
    return 0;
}

static int netdev_dpdkhw_class_init(void)
{
    VLOG_INFO("hardware netdev type initialized successfully");
    return 0;
}

static void
netdev_dpdkhw_destruct(struct netdev *netdev)
{
    ovs_mutex_lock(&dpdkhw_mutex);
    VLOG_INFO("Destructing the port.");
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    dpdk_mp_put_ext(dev->dpdk_mp);
    ovs_mutex_unlock(&dpdkhw_mutex);
    return;
}

/*
 * The hardware port can be added to OVS with device-id and port-id as
 * below.
 *`
 *   ovs-vsctl --timeout 10 add-port br0 dpdk1 -- \
 *   set Interface dpdk1 type=dpdkhw options:device-id=0,port-id=1
 *`
 * args will be
 *`  0,port-id=1 `
 *
 */
static void
process_dpdkhw_args(struct netdev_dpdkhw *dev, const char *args)
{
    char *device;
    char *hw_port;
    char *port_str = "port-id=";

    if (!args || !strlen(args)) {
        return;
    }
    device = xmemdup0(args, strcspn(args, ","));
    if (!strlen(device)) {
        goto out;
    }
    dev->dev_id = atoi(device);

    hw_port = strstr(args, port_str);
    if(!hw_port) {
        goto out;
    }
    if (strlen(hw_port) > strlen(port_str)) {
        hw_port += strlen(port_str);
        hw_port = xmemdup0(hw_port, strcspn(hw_port, ","));
        if(strlen(hw_port)) {
            dev->port_id = atoi(hw_port);
        }
        free(hw_port);
    }
out:
    free(device);
}

/*
 * Set the hardware port configiuration.
 * The init of port is delayed until the set_config to do proper init on the
 * device
 */
static int
netdev_dpdkhw_set_config(struct netdev *netdev, const struct smap *args,
                         char **errp)
{
    const char *hw_args;
    int err = 0;
    ovs_mutex_lock(&dpdkhw_mutex);
    VLOG_INFO("Configuring the port %s", netdev->name);
    hw_args = smap_get(args, "device-id");

    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    process_dpdkhw_args(dev, hw_args);
    /* XXX :: Only vhost port type for now. Need to add phy as well.
     * have to test if port is phy or vhost here
     */
    err = netdev_dpdkhw_init(dev, DPDKHW_VHOST_PORT);
    VLOG_INFO("Configured %s with device-id %"PRIu16" hw-port-id %"PRIu16,
                netdev->name, dev->dev_id, dev->port_id);
    ovs_mutex_unlock(&dpdkhw_mutex);
    return err;
}

static int
netdev_dpdkhw_send(struct netdev *netdev, int qid,
                     struct dp_packet_batch *batch, bool may_steal,
                     bool concurrent_txq)
{
    /*
     * XXX :: This function share lot of common code with dpdk netdev.
     * For now the code is duplicated. It is advised to refactor the code
     * in the future
     */

    uint32_t nb_tx = 0;
    uint16_t dpdk_portno;
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);

    if (!may_steal && batch->packets[0]->source != DPBUF_DPDK) {
        VLOG_WARN_RL(&rl, "Failed to steal packets, not sending out");
        return 0;
    }
    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_lock(&dev->tx_lock);
    }
    dp_packet_batch_apply_cutlen(batch);
    dpdk_portno = netdev_get_dpdk_portno(netdev);
    struct rte_mbuf **pkts = (struct rte_mbuf**)batch->packets;
    int cnt = batch->count;
    while (nb_tx != cnt) {
        uint32_t ret;
        ret = rte_eth_tx_burst(dpdk_portno, qid, pkts + nb_tx, cnt - nb_tx);
        if (!ret) {
            break;
        }
        nb_tx += ret;
    }

    VLOG_INFO("Sending %d packets on queue %d dpdk port %u",
              nb_tx, qid, dpdk_portno);
    if (OVS_UNLIKELY(nb_tx != cnt)) {
        int i;
        for (i = nb_tx; i < cnt; i++) {
            rte_pktmbuf_free(pkts[i]);
        }
    }

    rte_spinlock_lock(&dev->stats_lock);
    dev->stats.tx_packets += nb_tx;
    dev->stats.tx_dropped += (cnt - nb_tx);
    rte_spinlock_unlock(&dev->stats_lock);
    if (OVS_UNLIKELY(concurrent_txq)) {
        rte_spinlock_unlock(&dev->tx_lock);
    }
    return 0;
}

static int
netdev_dpdkhw_get_carrier(const struct netdev *netdev, bool *carrier)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_features(const struct netdev *netdev,
                         enum netdev_features *current,
                         enum netdev_features *advertised,
                         enum netdev_features *supported,
                         enum netdev_features *peer)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_status(const struct netdev *netdev, struct smap *args)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_reconfigure(struct netdev *netdev)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch)
{
    int nb_rx;
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(rxq->netdev);
    nb_rx = rte_eth_rx_burst(dev->dpdk_port_id, rxq->queue_id,
                             (struct rte_mbuf **) batch->packets,
                             NETDEV_MAX_BURST);
    if (!nb_rx) {
        return EAGAIN;
    }

    /*
     * XXX :: No policier for the exception path of hardware ports.
     */
    batch->count = nb_rx;
    VLOG_INFO_RL(&rl, "Receving packets from port %s and queue %d, num_pkts %d",
               dev->up.name, rxq->queue_id, nb_rx);
    rte_spinlock_lock(&dev->stats_lock);
    struct netdev_stats *stats = &dev->stats;
    stats->rx_packets += nb_rx;
    rte_spinlock_unlock(&dev->stats_lock);
    return 0;
}

static int
netdev_dpdkhw_get_config(const struct netdev *netdev, struct smap *args)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_numa_id(const struct netdev *netdev)
{
    /* Possibly it can return the socket that the FPGA resides thatn the numa,
     * XXX : By default it returns numa node 0 . Must read from rtl.
     */
     struct netdev_dpdkhw *dev;
     dev = netdev_dpdkhw_cast(netdev);
     return dev->numa_id;

}

static int
netdev_dpdkhw_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    /* XXX :: Is it possible to set mac address on the DPDK-DPGA ports */
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_mtu(const struct netdev *netdev, int *mtup)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_set_mtu(struct netdev *netdev, int mtu)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_ifindex(const struct netdev *netdev)
{
    return EOPNOTSUPP;
}

static long long int
netdev_dpdk_get_carrier_resets(const struct netdev *netdev)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_set_miimon(struct netdev *netdev OVS_UNUSED,
                       long long int interval OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_set_policing(struct netdev* netdev, uint32_t policer_rate,
                         uint32_t policer_burst)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                           struct sset *types)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_get_qos(const struct netdev *netdev,
                    const char **typep, struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_set_qos(struct netdev *netdev, const char *type,
                    const struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_dpdkhw_update_flags(struct netdev *netdev,
                         enum netdev_flags off, enum netdev_flags on,
                         enum netdev_flags *old_flagsp)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    *old_flagsp = dev->flags;
    /* XXX :: Only reading the flags, no flag update for now */
    return 0;
}

static const struct netdev_tunnel_config *
netdev_dpdkhw_get_tunnel_config(const struct netdev *dev)
{
    return NULL;
}

static int
netdev_dpdkhw_build_tunnel_config(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params)
{
    /*
     * XXX :  The existing vport tunnel build function are called here.
     * The OVS control path uses this function to craft the tunnel header for
     * the packets that received on the exception path.
     */
    return EOPNOTSUPP;
}

static void
netdev_dpdkhw_push_tunnel(struct dp_packet *packet,
                           const struct ovs_action_push_tnl *data)
{
    /*
     * XXX : No push operation happening here. Software simply call the hw_push
     * function on the tunnel port. The physical port to forward the tunnel
     * packets should add to the OVS for the learning.
     * The tunneling configuration should be the same way how the userspace
     * tunneling is configured,except the types of ports are hw based.
     * NOTE :: DPDK driver API is needed for tunnel push operation.
     */
    return;
}

static struct dp_packet *
netdev_dpdkhw_pop_tunnel(struct dp_packet *packet)
{
    /*
     * XXX : Pop operation is not happening in software. FOGA does it in the
     * hardware when OVS make tunnel pop request.
     * NOTE: DPDK APIs are needed for the pop operation.
     */
    return NULL;
}

static struct netdev_rxq *
netdev_dpdkhw_rxq_alloc(void)
{
    struct netdev_rxq *hw_rxq = dpdkhw_rte_mzalloc(sizeof *hw_rxq);
    VLOG_INFO("Allocate rxq port");
    return hw_rxq;
}

static int
netdev_dpdkhw_rxq_construct(struct netdev_rxq *rxq)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(rxq->netdev);
    ovs_mutex_lock(&dpdkhw_mutex);
    dev->hw_rxq = rxq;
    VLOG_INFO("Constructing rxq for port %s", dev->up.name);
    ovs_mutex_unlock(&dpdkhw_mutex);
    return 0;
}

static void
netdev_dpdkhw_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(rxq->netdev);
    ovs_mutex_lock(&dpdkhw_mutex);
    dev->hw_rxq = NULL;
    VLOG_INFO("Desstructing rxq for port %s", dev->up.name);
    ovs_mutex_unlock(&dpdkhw_mutex);
}

static void
netdev_dpdkhw_rxq_dealloc(struct netdev_rxq *rxq)
{
    VLOG_INFO("Deallocating the rxq");
    rte_free(rxq);
}

static int
netdev_dpdkhw_flow_flush(struct netdev *netdev OVS_UNUSED)
{
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return EOPNOTSUPP;

}

static void
netdev_dump_hwflow_start(struct dpdk_netdev_flow_dump *dpdk_dump) {
    dpdk_dump->hash_buf_idx = 0;
}

static int
netdev_dpdkhw_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    struct dpdk_netdev_flow_dump *dpdk_dump;
    struct netdev_flow_dump *dump;
    dpdk_dump = xzalloc(sizeof *dpdk_dump);
    dump = &dpdk_dump->dump;
    dump->netdev = netdev_ref(netdev);
    netdev_dump_hwflow_start(dpdk_dump);
    *dump_out = dump;
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return 0;
}

static int
netdev_dpdkhw_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    VLOG_INFO("Dump destroy");
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    netdev_close(dump->netdev);
    free(dump);
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return EOPNOTSUPP;
}

/* Add the hardware flow hash map entries into dump if its is not present.
 * On success return 0 and return false in case of error or entry already
 * present.
 */
static bool
netdev_flow_dump_add_once(struct ufid_to_rteflow *data,
                          struct dpdk_netdev_flow_dump *dpdk_dump)
{
    int i;
    size_t hash;
    hash = hash_bytes(&data->ufid, sizeof data->ufid, 0);
    for(i = 0; i < dpdk_dump->hash_buf_idx; i++) {
       if (hash == dpdk_dump->dump_flow_hash[i]) {
           /* Flow already dumped, do nothing */
           return false;
       }
    }
    /* Flow not found, insert into the dump */
    dpdk_dump->dump_flow_hash[i] = hash;
    dpdk_dump->hash_buf_idx++;
    return true;
}

static void
read_hwflow_stats(const struct ufid_to_rteflow *flow,
                  struct dpif_flow_stats *stats)
{
    /* XXX : Invoke DPDK hardware APIs to collect the stats */
    /* HACK :: HW doesnt support stat read now, so update stats statically */
    memset(stats, 0, sizeof *stats);
    static uint64_t temp_stats;
    stats->used = time_msec();
    temp_stats++;
    stats->n_packets = temp_stats;
    stats->n_bytes = (temp_stats << 1); /* Multiple by 2, 2 byte each pkt */
}

static bool
netdev_dpdkhw_flow_dump_next(struct netdev_flow_dump *dump,
                         struct match *match,
                         struct nlattr **actions,
                         size_t *action_len,
                         struct dpif_flow_stats *stats,
                         ovs_u128 *ufid,
                         struct ofpbuf *rbuffer,
                         struct ofpbuf *wbuffer)
{
    struct ufid_to_rteflow *data = NULL;
    int ret;
    struct dpdk_netdev_flow_dump *dpdk_dump;
    struct hmap *ufid_to_flow_map;
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(dump->netdev);
    dpdk_dump = netdev_flow_dump_cast(dump);

    ovs_mutex_lock(&dpdkhw_flow_mutex);
    ufid_to_flow_map = &dev->ufid_to_flow_map;
    HMAP_FOR_EACH(data, node, ufid_to_flow_map) {
        ret = netdev_flow_dump_add_once(data, dpdk_dump);
        if (ret) {
            /* Successfully added the flow into the dump */
            /* Update the flow fields accordingly */
            memcpy(match, &data->match, sizeof *match);
            *ufid = data->ufid;
            /* Read the stat from the hardware, and update the stat*/
            read_hwflow_stats(data, stats);
            *actions = data->actions;
            *action_len = data->action_len;
            ovs_mutex_unlock(&dpdkhw_flow_mutex);
            return true;
        }
    }

    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return false;
}

inline int
netdev_dpdkhw_switch_flow_del(struct netdev *netdev,
                              struct dpdkhw_switch *hw_switch,
                              const ovs_u128 *ufid)
{
    int ret = -ENOENT;
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    ret = hw_switch->hw_fns->del_ovs_op(netdev, hw_switch, ufid);
    if (ret) {
        VLOG_ERR_RL(&rl, "Failed to destroy flow in hardware device %d",
                         hw_switch->dev_id);
    }
    else {
        VLOG_INFO_RL(&rl, "Deleting the hardware flow");
        del_ufid_to_rteflow_mapping(ufid, netdev);
    }
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return ret;
}

static int
netdev_dpdkhw_flow_del(struct netdev *netdev,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   const ovs_u128 *ufid)
{
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    struct dpdkhw_switch *hw_switch = get_hw_switch(dev->dev_id);
    return netdev_dpdkhw_switch_flow_del(netdev, hw_switch, ufid);
}

static int
netdev_dpdkhw_flow_put(struct netdev *netdev,
                   struct match *match,
                   const struct nlattr *actions,
                   size_t actions_len,
                   struct dpif_flow_stats *stats,
                   const ovs_u128 *ufid,
                   struct offload_info *info)
{
    struct rte_flow_attr hw_flow_attr = {0};
    struct rte_flow_item hw_flow_batch[MAX_DPDKHW_RTE_FLOW_SIZE] = {{0}};
    struct rte_flow_action hw_action_batch[MAX_DPDKHW_RTE_ACTION_SIZE] = {{0}};
    struct rte_flow_error hw_err = {0};
    struct rte_flow *hw_flow = NULL;
    struct rte_flow_batch batch;
    int res = 0;

    struct dpdkhw_switch *hw_switch = NULL;
    struct netdev_dpdkhw *dev = netdev_dpdkhw_cast(netdev);
    hw_switch = get_hw_switch(dev->dev_id);

    if (!hw_switch->hw_fns->is_ovs_op_avial_in_hw(netdev, hw_switch, match,
                            actions, actions_len, ufid, info)) {
        VLOG_ERR("Hardware switch doesnt support flow offload");
        return -EINVAL;
    }
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    init_rte_flow_batch(&batch, hw_flow_batch, MAX_DPDKHW_RTE_FLOW_SIZE);
    res = hw_switch->hw_fns->ovs_flow_xlate(match, &hw_flow_attr, &batch,
                                            info);
    if(res) {
        VLOG_INFO("Failed to translate the flow, cannot insert flow in hw");
        goto out;
    }
    res = hw_switch->hw_fns->ovs_actions_xlate(hw_action_batch, actions,
                                       actions_len, info);
    if(res) {
        VLOG_INFO("Failed to translate the actions, Cannot insert flow in hw");
        goto out;
    }

    res = -EINVAL;
    hw_flow = hw_switch->hw_fns->install_ovs_op(netdev, hw_switch,
                          &hw_flow_attr, hw_flow_batch, hw_action_batch,
                          &hw_err);
    if (hw_flow) {
        add_ufid_to_rteflow_mapping(ufid, netdev, hw_flow, match, actions,
                                    actions_len);
        res = 0;
    }

out:
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return res;
}

static int
netdev_dpdkhw_flow_get(struct netdev *netdev,
                   struct match *match,
                   struct nlattr **actions,
                   size_t *action_len,
                   struct dpif_flow_stats *stats,
                   const ovs_u128 *ufid,
                   struct ofpbuf *buf)
{
    int ret = ENOENT;
    struct ufid_to_rteflow *entry;
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    entry = get_ufid_to_rteflow_mapping(ufid, netdev);
    if (entry) {
        /* Flow is present in the hardware */
        memcpy(match, &entry->match, sizeof *match);
        read_hwflow_stats(entry, stats);
        *actions = entry->actions;
        *action_len = entry->action_len;
        ret = 0;
    }
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return ret;
}

static int
netdev_dpdkhw_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    ovs_mutex_lock(&dpdkhw_flow_mutex);
    ovs_mutex_unlock(&dpdkhw_flow_mutex);
    return 0;
}

#define NETDEV_DPDKHW_CLASS(NAME, INIT, CONSTRUCT, DESTRUCT, \
                          GET_CONFIG, SET_CONFIG,             \
                          GET_TUNNEL_CONFIG, BUILD_HEADER,    \
                          PUSH_HEADER, POP_HEADER, SEND,      \
                          GET_CARRIER, GET_STATS,             \
                          GET_FEATURES, GET_STATUS,           \
                          RECONFIGURE, RXQ_RECV)              \
{                                                             \
    NAME,                                                     \
    true,                       /* is_pmd */                  \
    INIT,                       /* init */                    \
    NULL,                       /* netdev_dpdk_run */         \
    NULL,                       /* netdev_dpdk_wait */        \
                                                              \
    netdev_dpdkhw_alloc,        /* netdev_alloc */            \
    CONSTRUCT,                                                \
    DESTRUCT,                                                 \
    netdev_dpdkhw_dealloc,      /*netdev_dealloc*/            \
    GET_CONFIG,                                               \
    SET_CONFIG,                                               \
    GET_TUNNEL_CONFIG,          /* get_tunnel_config */       \
    BUILD_HEADER,               /* build header */            \
    PUSH_HEADER,                       /* push header */      \
    POP_HEADER,                       /* pop header */        \
    netdev_dpdkhw_get_numa_id,    /* get_numa_id */          \
    NULL,                                                     \
                                                              \
    SEND,                       /* send */                    \
    NULL,                       /* send_wait */               \
                                                              \
    netdev_dpdkhw_set_etheraddr,                              \
    netdev_dpdkhw_get_etheraddr,                              \
    netdev_dpdkhw_get_mtu,                                    \
    netdev_dpdkhw_set_mtu,                                    \
    netdev_dpdkhw_get_ifindex,                                \
    GET_CARRIER,                                              \
    netdev_dpdk_get_carrier_resets,                           \
    netdev_dpdkhw_set_miimon,                                 \
    GET_STATS,                                                \
    GET_FEATURES,                                             \
    NULL,                       /* set_advertisements */      \
                                                              \
    netdev_dpdkhw_set_policing,                               \
    netdev_dpdkhw_get_qos_types,                              \
    NULL,                       /* get_qos_capabilities */    \
    netdev_dpdkhw_get_qos,                                    \
    netdev_dpdkhw_set_qos,                                    \
    NULL,                       /* get_queue */               \
    NULL,                       /* set_queue */               \
    NULL,                       /* delete_queue */            \
    NULL,                       /* get_queue_stats */         \
    NULL,                       /* queue_dump_start */        \
    NULL,                       /* queue_dump_next */         \
    NULL,                       /* queue_dump_done */         \
    NULL,                       /* dump_queue_stats */        \
                                                              \
    NULL,                       /* set_in4 */                 \
    NULL,                       /* get_addr_list */           \
    NULL,                       /* add_router */              \
    NULL,                       /* get_next_hop */            \
    GET_STATUS,                                               \
    NULL,                       /* arp_lookup */              \
                                                              \
    netdev_dpdkhw_update_flags,                               \
    RECONFIGURE,                                              \
                                                              \
    netdev_dpdkhw_rxq_alloc,    /* netdev_rxq_alloc */        \
    netdev_dpdkhw_rxq_construct,/* netdev_rxq_construct */    \
    netdev_dpdkhw_rxq_destruct,/* netdev_rxq_destruct */      \
    netdev_dpdkhw_rxq_dealloc, /*netdev_rxq_dealloc */        \
    RXQ_RECV,                                                 \
    NULL,                      /* rx_wait */                  \
    NULL,                      /* rxq_drain */                \
    netdev_dpdkhw_flow_flush,   /* flow_flush */              \
    netdev_dpdkhw_flow_dump_create,   /*flow_dump_create */   \
    netdev_dpdkhw_flow_dump_destroy, /* flow_dump_destroy */  \
    netdev_dpdkhw_flow_dump_next,    /* flow_dump_destroy */  \
    netdev_dpdkhw_flow_put,          /* flow_put */           \
    netdev_dpdkhw_flow_get,          /* flow_get */           \
    netdev_dpdkhw_flow_del,          /* flow_del */           \
    netdev_dpdkhw_init_flow_api      /* init_flow_api */      \
}

/*
 * XXX :: The netdev functions are same for all type of hardware netdevs,
 * will change in the future on need basis.
 */
static const struct netdev_class dpdkhw_class =
        NETDEV_DPDKHW_CLASS(
                "dpdkhw",
                netdev_dpdkhw_class_init,
                netdev_dpdkhw_construct,
                netdev_dpdkhw_destruct,
                netdev_dpdkhw_get_config,
                netdev_dpdkhw_set_config,
                NULL, NULL, NULL, NULL, /* tunnel config */
                netdev_dpdkhw_send,
                netdev_dpdkhw_get_carrier,
                netdev_dpdkhw_get_stats,
                netdev_dpdkhw_get_features,
                netdev_dpdkhw_get_status,
                netdev_dpdkhw_reconfigure,
                netdev_dpdkhw_rxq_recv);

static const struct netdev_class dpdkhw_vhost_class =
        NETDEV_DPDKHW_CLASS(
                "dpdkhwvhost",
                netdev_dpdkhw_class_init,
                netdev_dpdkhw_construct,
                netdev_dpdkhw_destruct,
                netdev_dpdkhw_get_config,
                netdev_dpdkhw_set_config,
                NULL, NULL, NULL, NULL, /* tunnel config */
                netdev_dpdkhw_send,
                netdev_dpdkhw_get_carrier,
                netdev_dpdkhw_get_stats,
                netdev_dpdkhw_get_features,
                netdev_dpdkhw_get_status,
                netdev_dpdkhw_reconfigure,
                netdev_dpdkhw_rxq_recv);

static const struct netdev_class dpdkhw_tunnel_class =
        NETDEV_DPDKHW_CLASS(
                "dpdkhwtunnel",
                netdev_dpdkhw_class_init,
                netdev_dpdkhw_construct,
                netdev_dpdkhw_destruct,
                netdev_dpdkhw_get_config,
                netdev_dpdkhw_set_config,
                netdev_dpdkhw_get_tunnel_config,
                netdev_dpdkhw_build_tunnel_config,
                netdev_dpdkhw_push_tunnel,
                netdev_dpdkhw_pop_tunnel,/* tunnel config */
                netdev_dpdkhw_send,
                netdev_dpdkhw_get_carrier,
                netdev_dpdkhw_get_stats,
                netdev_dpdkhw_get_features,
                netdev_dpdkhw_get_status,
                netdev_dpdkhw_reconfigure,
                netdev_dpdkhw_rxq_recv);
void
netdev_dpdkhw_register(void)
{
    netdev_register_provider(&dpdkhw_class);
    netdev_register_provider(&dpdkhw_vhost_class);
    netdev_register_provider(&dpdkhw_tunnel_class);
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

static int
get_unsigned_long(const char *str, int base)
{
    unsigned long num;
    char *end = NULL;

    errno = 0;

    num = strtoul(str, &end, base);
    if ((str[0] == '\0') || (end == NULL) || (*end != '\0') || (errno != 0))
        return -1;

    return num;

}

static void
set_switch_proto_bitmap(struct dpdkhw_switch *hw_switch)
{

    /* Set the protocol bitmap for the switch based on the hw support
     * TODO :: Must need to use a API from DPDK to get the protocol
     * support. For now use constant values
     */

    /* First byte
    L2_ETHERNET, 1<<0
    L2_VLAN, 1<<1

    L3_IP, 1<<2
    L3_IPV6, 1<<3
    L3_MPLS, 1<<4
    L3_ARP, 1<<5
    L3_RARP, 1<<6

    L4_TCP, 1<<7
    */
    hw_switch->avail_ptypes[0] = 0xFF;

    /* Second Byte
    L4_ICMP, 1<<0
    L4_SCTP, 1<<1
    L4_ICMPV6, 1<<2
    */
    hw_switch->avail_ptypes[1] = 0x07;

}
static void
add_hw_switch_device(char *pci_id)
{
    int i,j;
    struct dpdkhw_switch *hw_switch;
    char tmp_pci_no[MAX_HW_DEV_NAME_LEN];
    strncpy(tmp_pci_no, pci_id, MAX_HW_DEV_NAME_LEN-1);
    int num[4] = { 0, 0, 0, 0};
    if( hw_switches.num_devs >= MAX_HW_OFFLOAD_SWITCH_DEVICES) {
        VLOG_WARN("Cannot add more switch devices, max limit reached");
    }
    i = strlen(tmp_pci_no) - 1;
    j = 3;
    while (i > 0 && j >= 0) {
        while ((tmp_pci_no[i - 1] != ':' && tmp_pci_no[i - 1] != '.')
                && i > 0) {
            i--;
        }
        num[j--] = get_unsigned_long(&tmp_pci_no[i], 16);
        i--;
        if (i >= 0) {
            tmp_pci_no[i] = '\0';
        }
    }
    /* Cache the device information */
    hw_switch = &hw_switches.dpdkhw_switch[hw_switches.num_devs];
    hw_switch->dev_id = hw_switches.num_devs;
    strncpy(hw_switch->dev_name, pci_id, (sizeof hw_switch->dev_name) -1);
    hw_switch->pci_addr.domain = num[0];
    hw_switch->pci_addr.bus = num[1];
    hw_switch->pci_addr.devid = num[2];
    hw_switch->pci_addr.function = num[3];

    /* XXX : HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK HACK
     * Statically setting all the hardware switch features now.
     * Need to read from hardware via DPDK.
     */
    hw_switch->n_vhost_ports = 32;
    hw_switch->n_phy_ports = 2;
    hw_switch->switch_mode = FULL_ACCEL_EM_SWITCH;
    hw_switch->total_flow_cnt = 2000000;
    atomic_count_init(&hw_switch->n_flow_cnt, 0);
    hw_switch->hw_fns = &dpdkhw_full_em_switch_fns;
    set_switch_proto_bitmap(hw_switch);
    hw_switches.num_devs++;
    /* XXX :: Read hardware switch information from DPDK to populate
     * switch feature set.
     */
}

/*
 * Read PCI-ID and initilize the switch device..
 * Returns false if failed to add the switch device.
 */
static bool
dpdkhw_get_switch_devices(const char *pci_ids)
{
   char *pci_dev;
   uint32_t len;
   int i;
   if (!pci_ids) {
        return false;
   }
   len = strlen(pci_ids);
   do {
       i = strcspn(pci_ids, ",");
       pci_dev = xmemdup0(pci_ids, i);
       if (!strlen(pci_dev)) {
           goto out;
       }
       add_hw_switch_device(pci_dev);
       i++;
       pci_ids += i; /* Read next PCI-ID */
       len -= i;
       free(pci_dev);
   } while(pci_ids && len);
out:
    return true;
}

/*
 * Setting the socket and numa node information for a dpdk hw port.
 * XXX :: The socket information is blindly decide based on the pci-id.
 * In future DPDK might offer APIs to know which socket the device(PF)
 * is belongs to.
 * Most cases pci_bus 00: is CPU1/socket0 and 80+ is CPU2/socket1
 */
static void
dpdkhw_switch_set_numa_node(struct dpdkhw_switch *hw_switch)
{
    if (hw_switch->pci_addr.bus >= 0x80) {
       hw_switch->socket_id = SOCKET1;
       hw_switch->numa_id = NUMA_NODE_1;
       return;
    }
    hw_switch->socket_id = SOCKET0;
    hw_switch->numa_id = NUMA_NODE_0;
}

static int
dpdkhw_switch_mp_configure(struct dpdkhw_switch *hw_switch)
{
    int mtu = ETHER_MTU; /* XXX :: Read from hw to change MTU if needed */
    uint32_t buf_size = dpdk_buf_size(mtu);
    struct dpdk_mp *mp;
    dpdkhw_switch_set_numa_node(hw_switch);
    mp = dpdk_mp_get_ext(hw_switch->socket_id, dpdk_framelen_to_mtu(buf_size));
    if (!mp) {
        VLOG_ERR("Insufficient memory to create memory pool for switchdev "
                 "%s, with MTU %d on socket %d\n",
                 hw_switch->dev_name, mtu, hw_switch->socket_id);
        return -ENOMEM;
    }
    else {
        dpdk_mp_put_ext(hw_switch->dpdk_mp);
        hw_switch->dpdk_mp = mp;
    }
    return 0;
}

/* Register VDPA engine for the switch device. */
static int
register_switch_engine(void)
{
    /* XXX ::switch engine APIs are not supposed to use/keep track of any
     * hardware information such as engid. this must be abstracted in DPDK.
     *
     * The engine need to be registered for each device.
     * This function loop on 'hw_switches' and init engine for each
     * switch device.
     */
    {
        int ret = 0;
        int engid = 0;
        struct dpdkhw_switch *hw_switch;
        int i;
        for (i = 0; i < hw_switches.num_devs; i++) {
            hw_switch = &hw_switches.dpdkhw_switch[i]; /*Only one device ??*/

            /* Configure the mempool for the switch device */
            ret = dpdkhw_switch_mp_configure(hw_switch);
            if (ret < 0) {
                return ret;
            }
            engid = rte_register_engine(&hw_switch->pci_addr,
                                        hw_switch->dpdk_mp->mp);
            if (engid >= 0) {
                /* valid engine id */
                hw_switch->hw_engid = engid;
            }
            else {
                /* Return if one of afu init is failed */
                return -EINVAL;
            }
        }
        return ret;
    }
}

/* Initilize OVS-DPDK to use hardware/FPGA pmd ports.
 * Any global OVS/DPDK/FPGA initialization can be done
 * here.
 */
void
dpdkhw_init(const struct smap *ovs_other_config)
{
    int ret;
    const char *pci_ids;
    pci_ids = smap_get(ovs_other_config, "dpdk-hw-offload-ids");
    hw_switches.num_devs = 0;
    if(!dpdkhw_get_switch_devices(pci_ids)) {
        VLOG_INFO("Failed to retrieve device info/No devices are provided");
        return;
    }
    VLOG_INFO("Initializing the hardware/FPGA ports.");
    netdev_dpdkhw_register();
    /* Initilize the hardware vhost socket directory */
    setup_vhost_dir("hw-vhost-sock-dir", ovs_other_config,
                    &hw_vhost_sock_dir);
    if (hw_vhost_sock_dir[strlen(hw_vhost_sock_dir) - 1] == '/' ) {
        hw_vhost_sock_dir[strlen(hw_vhost_sock_dir) - 1] = '\0';
    }
    ret = register_switch_engine();
    if (ret < 0) {
        VLOG_ERR("Failed to initialize the HW switch engine");
    }

    /*
     * XXX : Validate the hardware device init and set the flag
     * accordingly
     */
     rte_dpdkhw_init = DPDKHW_INIT_SUCCESS;
}
