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

#ifndef LIB_NETDEV_DPDK_HW_H_
#define LIB_NETDEV_DPDK_HW_H_

#include <rte_flow.h>
#include <rte_pci.h>
#include "odp-util.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "ovs-atomic.h"

#define NETDEV_DPDKHW

#define MAX_DPDKHW_PORTS                255 /* Maximum number of dpdk ports */
#define MAX_DPDKHW_RTE_FLOW_SIZE        6 /*6 flow elements */
#define MAX_DPDKHW_RTE_ACTION_SIZE      10 /* Maximum number of actions */


#define FOR_EACH_HWITEM(BATCH, ITEM, MAX_SIZE, END_TYPE, IDX)                  \
    for(IDX = 0 , ITEM = &BATCH[IDX];                                          \
        ITEM->type != END_TYPE && IDX < MAX_SIZE;                              \
        ITEM = &BATCH[++IDX])

#define FLOW_DUMP_MAX_BATCH 50
struct dpdk_netdev_flow_dump {
    struct netdev_flow_dump dump;
    /* List of hash that dumped already */
    size_t dump_flow_hash[FLOW_DUMP_MAX_BATCH];
    int hash_buf_idx;
};

#define MAX_HW_DEV_NAME_LEN    128
#define MAX_HW_OFFLOAD_SWITCH_DEVICES 8
struct dpdk_mp;

/* The acceleration mode of a device. A device can support one more modes */
enum hw_switch_mode {
    /* Partial acceleration mode, hardware can do exact match and report id */
    PARTIAL_ACCEL_SWITCH_EM_REPORT_ID = 1,
    /* Partial acceleration mode, hardware can do WC match and report id */
    PARTIAL_ACCEL_SWITCH_WC_REPORT_ID,
    /* Partial acceleration mode, hardware does zery copy to the VM */
    PARTIAL_ACCEL_SWITCH_ZERO_Q_COPY,
    /* Full acceleration mode, hardware does full EM classification + action */
    FULL_ACCEL_EM_SWITCH,
    /* Full acceleration mode, device can do full WC flows + actions. */
    FULL_ACCEL_WC_SWITCH
};

/*
 * Available switch protocols that can be programmed in the hardware. This
 * information is being used to determine whether a flow to be offloaded/not.
 *
 * XXX :: When adding a new protocol to the list, make sure to increase the
 * size of avail_ptype bitmap to accomodate the new entry. Current bitmap
 * can represent upto 32 entries.
 *
 * Each bit in hardware switch 'avail_ptypes' represent if a protocol is
 * supported or not. For eg: bit-0 for L2_ETHERNET, bit-1 for VLAN and so on.
 * The bit is set to '1' if its supported in the hardware and '0' otherwise.
 */
enum hw_switch_proto {
    /* L2 protocols*/
    L2_ETH,

    /* L3 protocols */
    L3_VLAN,
    L3_IP,
    L3_IPV6,
    L3_MPLS,
    L3_ARP,
    L3_RARP,

    /* L4 protocols */
    L4_TCP,
    L4_UDP,
    L4_ICMP,
    L4_SCTP,
    L4_ICMPV6,

    /*Tunnel protocols */
    L5_VXLAN,
    L5_NVGRE,

    /* Last protocol, Do not add any protocol after this */
    LAST_PROTO_INVALID
};

/*
 * Error codes when flow programming is not supported in hardware.
 * The validation function return this error code when its not possible to
 * install a flow in hw.
 * Updating this enum must need change in 'hw_switch_flow_install_err_str'.
 */
enum hw_switch_flow_install_err {
    /* The flow is supported in hw and can be installed */
    FLOW_INSTALL_SUPPORTED = 0,
    /* The same flow already installed in hw before, */
    FLOW_PRESENT_IN_HW,
    /* The protocol support is not available for this feature */
    FLOW_PROTO_UNSUPPORTED,
    /* Max flow limit of the device reached */
    FLOW_MAX_LIMIT_REACHED,
    /* Flow span across multiple hw switch devices. */
    FLOW_IN_MULTI_HW,
    /* Flow is using non-hw-accelerated ports */
    FLOW_WITH_NON_HW_PORTS
};

#define FLOW_INSTALL_ERR_STR_LEN 500
#define HW_PROTO_TYPE_NUM_BYTES  2

BUILD_ASSERT_DECL(LAST_PROTO_INVALID < HW_PROTO_TYPE_NUM_BYTES<<3);

/* The array of rte_flow_item to program a flow with different header fields
 * into the hardware
 */
struct dpdk_flow_batch {
    /* Array of rte_flow_item */
    struct rte_flow_item *flow_batch;
    uint32_t used;
    uint32_t max_size;
};

struct ufid_to_rteflow {
    struct hmap_node node;
    ovs_u128 ufid;
    const struct netdev *netdev;
    /* Based on the hardware capabilities, it is possible to have 1 or many
     * rte_flow for every ufid. Usually it happen when hardware can only
     * offload exact match flows and not wc. It is necessary to track them
     * as well.
     */
    const struct rte_flow **hw_flows;
    uint32_t hw_flow_size_allocated;
    uint32_t hw_flow_size_used;
    struct match match; /* The OVS flow entry used to install hw flow */
    struct nlattr *actions;
    size_t action_len;
};

struct dpdkhw_switch;
/* hardware switch functions. These functions are intended to interact with
 * hardware device.
 */
struct dpdkhw_switch_fns {
    /* OVS validation function to check if an operation/flow can be offloaded to a
     * hardware device. Return 'FLOW_INSTALL_SUPPORTED' when hardware can do
     * the operation . Error code otherwise./
     */
    enum hw_switch_flow_install_err (*is_ovs_op_avial_in_hw)(
                                      struct netdev *, struct dpdkhw_switch *,
                                      struct match *, const struct nlattr *,
                                      size_t, const ovs_u128 *,
                                      struct offload_info *);
    /* Function to translate the OVS flow into hardware flow format.
     * Most hardware can understand the rte_flow format, hence this function
     * translate the OVS flow to rte_flow.
     */
    int (*ovs_flow_xlate)(struct match *, struct rte_flow_attr *,
                          struct dpdk_flow_batch *,
                          const struct offload_info *);
    /* Translate the OVS actions to hardware actions. Hardware can understand
     * rte_action,hence this function translate into the actions that hardware
     * can do */
    int (*ovs_actions_xlate)(struct rte_flow_action *, const struct nlattr *,
                             size_t, const struct offload_info *);
    /* Install a flow or operation into a hardware using DPDK rte_flow
     * and rte_action.
     */
    struct rte_flow *(*install_ovs_op)(struct netdev *, struct dpdkhw_switch *,
                                       const struct rte_flow_attr *,
                                       struct rte_flow_item *,
                                       struct rte_flow_action *,
                                       struct rte_flow_error *);
   /* Delete the installed op/flow from a hardware from OVS */
   int (*del_ovs_op)(struct netdev *, struct dpdkhw_switch *,
                     const ovs_u128 *);
};

/* hardware accelerated device/hardware switch */
struct dpdkhw_switch {
    uint16_t dev_id;
    uint16_t hw_engid;
    int socket_id;
    int numa_id; /* Numa-id of the PF/hw-switch */
    char dev_name[MAX_HW_DEV_NAME_LEN];
    void *dev_info; /* Generic pointer to hold dpdk driver specific hw info */
    struct rte_pci_addr pci_addr;
    struct dpdk_mp *dpdk_mp; /* Mempool to use for default exception path */
    /** hardware switch properties populated based on DPDK get APIs **/
    enum hw_switch_mode switch_mode;
    /* Number of flows the switch can support */
    uint32_t total_flow_cnt;
    /* Number of flows installed in the hardware */
    atomic_count n_flow_cnt;
    /* Available protocol support in the hardware switch */
    uint8_t avail_ptypes[HW_PROTO_TYPE_NUM_BYTES];
    uint16_t n_vhost_ports;
    uint16_t n_phy_ports;
    const struct dpdkhw_switch_fns *hw_fns;
    /*TODO :: Extend more hardware properties */

};

void init_dpdk_flow_batch(struct dpdk_flow_batch *batch,
                    struct rte_flow_item rte_flow_start[],
                    uint32_t batch_size);
struct dpdkhw_switch *get_hw_switch(uint16_t dev_id);

bool is_dpdkhw_port(const struct netdev *netdev);
uint16_t netdev_get_dpdk_portno(struct netdev *netdev);
struct netdev *get_hw_netdev(odp_port_t port_no,
                             const struct dpif_class *dpif_class);

extern const struct dpdkhw_switch_fns dpdkhw_full_em_switch_fns;
bool is_netdev_on_switch(const struct netdev *netdev,
                         const uint16_t switch_id);

struct ufid_to_rteflow;
struct ufid_to_rteflow *get_ufid_to_rteflow_mapping(const ovs_u128 *ufid,
                            const struct netdev *netdev);
extern char hw_switch_flow_install_err_str[][FLOW_INSTALL_ERR_STR_LEN];

#endif /* LIB_NETDEV_DPDK_HW_H_ */
