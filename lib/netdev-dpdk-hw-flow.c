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

#include "netdev-dpdk-hw-flow.h"
#include "dpif-netdev.h"
#include "netdev-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_dpdkhw_flow);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* status of flow translation in each layer */
enum xlate_status {
    FLOW_XLATE_SUCCESS = 1<<0,
    FLOW_XLATE_NOT_NEEDED = 1<<1, /* Protocol layer can be skipped */
    FLOW_XLATE_LAST = 1<<2, /* Last protocol layer, No more translation */
    FLOW_XLATE_FAILED = 1<<3
};

/*
 * flow install error strings based on the enum set
 * 'hw_switch_flow_install_err'. Updating the enum must update this string
 * array as well.
 */
char hw_switch_flow_install_err_str[][FLOW_INSTALL_ERR_STR_LEN] =
{
    /* FLOW_INSTALL_SUPPORTED */
    "hardware flow install is supported in the device",
    /* FLOW_PRESENT_IN_HW */
    "Flow already present in hardware",
    /* FLOW_PROTO_UNSUPPORTED */
    "Flow protocol is unsupported in the hardware",
    /* FLOW_MAX_LIMIT_REACHED */
    "Flow max limit for the device is reached",
    /* FLOW_IN_MULTI_HW */
    "Flow is span across more than one accelerated device",
    /* FLOW_WITH_NON_HW_PORTS */
    "Flow need non hardware accelerated ports"
};

/* Dictionary entry to translate ovs flow element to rte_flow. */
struct flow_xlate_dic {
    enum rte_flow_item_type rte_flow_type;
    /*
     * Flow xlate function to translate specific header match into rtl format.
     * Each rte_flow_item_type, it is necessary to define a corresponding
     * xlate function in this structure. Return 0 if the flow is being translated
     * successfully and error code otherwise.
     */
    enum xlate_status (*flow_xlate)(struct match *match,
                       struct dpdk_flow_batch *batch,
                       const void *md);
};

static inline bool
is_dpdk_flow_batch_full(struct dpdk_flow_batch *flow_batch)
{
    if (flow_batch->used >= flow_batch->max_size) {
        return true;
    }
    return false;
}

/*
 * rte_flow_start must have the size
 * MAX_DPDKHW_RTE_FLOW_SIZE * sizeof(rte_flow_item)
 */
void
init_dpdk_flow_batch(struct dpdk_flow_batch *batch,
                    struct rte_flow_item rte_flow_start[],
                    uint32_t batch_size)
{
    batch->used = 0;
    batch->max_size = batch_size;
    /* rte_flow_start is an array of rte_flow_item */
    batch->flow_batch = rte_flow_start;
}

static inline bool
rte_flow_item_push(struct dpdk_flow_batch *batch, void *flow,
                   void *mask, enum rte_flow_item_type type)
{
    struct rte_flow_item *flow_item;
    if (is_dpdk_flow_batch_full(batch)) {
        VLOG_ERR("Failed to install flow entry, the flow batch set is full");
        return false;
    }
    flow_item = batch->flow_batch + batch->used;
    flow_item->spec = flow;
    flow_item->mask = mask;
    flow_item->type = type;
    flow_item->last = NULL;
    batch->used++;
    return true;

}

static enum xlate_status do_inport_flow_xlate(struct match *match,
                           struct dpdk_flow_batch *batch, const void *md);
static enum xlate_status do_l2_flow_xlate(struct match *match,
                        struct dpdk_flow_batch *batch, const void *md);
static enum xlate_status do_l2_vlan_flow_xlate(struct match *match,
                      struct dpdk_flow_batch *batch, const void *md);
static enum xlate_status do_l3_flow_xlate(struct match *match,
                          struct dpdk_flow_batch *batch, const void *md);
static enum xlate_status do_l4_flow_xlate(struct match *match,
                           struct dpdk_flow_batch *batch, const void *md);
static enum xlate_status do_end_flow_xlate(struct match *match,
                           struct dpdk_flow_batch *batch, const void *md);

/* xlate function definitions for translating OVS flow to rte_flow */
struct flow_xlate_dic PORT_FLOW_XLATE = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        do_inport_flow_xlate
};

struct flow_xlate_dic L2_FLOW_XLATE = {
        RTE_FLOW_ITEM_TYPE_ETH,
        do_l2_flow_xlate
};

struct flow_xlate_dic L2_VLAN_FLOW_XLATE = {
        RTE_FLOW_ITEM_TYPE_VLAN,
        do_l2_vlan_flow_xlate
};

struct flow_xlate_dic L3_FLOW_XLATE = {
            RTE_FLOW_ITEM_TYPE_VOID, /* L3 flow item can be different */
                    do_l3_flow_xlate
};

struct flow_xlate_dic L4_FLOW_XLATE = {
            RTE_FLOW_ITEM_TYPE_VOID, /* Can be UDP/TCP */
                    do_l4_flow_xlate
};

struct flow_xlate_dic END_FLOW_XLATE = {
        RTE_FLOW_ITEM_TYPE_END,
        do_end_flow_xlate
};

/* Function to go through each actions to see if it can handle with in the
 * same device. Also look at the actions to see if its supported in the hw.
 */
static enum hw_switch_flow_install_err
is_action_hanlded_in_one_device(struct dpdkhw_switch *hw_switch,
                                const struct nlattr *actions,
                                size_t actions_len,
                                struct offload_info *ofld_info)
{
    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            odp_port_t out_port = nl_attr_get_odp_port(a);
            /* Output port should be hardware port number. */
            struct netdev *netdev = get_hw_netdev(out_port,
                                                  ofld_info->dpif_class);
            if (!netdev) {
                VLOG_WARN("Cannot find the output port in hw-accel list"
                          " port %u", odp_to_u32(out_port));
                return FLOW_WITH_NON_HW_PORTS;
            }
            if (!is_netdev_on_switch(netdev, hw_switch->dev_id)) {
                VLOG_DBG("Output action is not on same device."
                         "inport device %u ", hw_switch->dev_id);
                return FLOW_IN_MULTI_HW;
            }
            break;
            }
        case OVS_ACTION_ATTR_PUSH_VLAN:
        case OVS_ACTION_ATTR_POP_VLAN:
        case OVS_ACTION_ATTR_SET:
        case OVS_ACTION_ATTR_PUSH_MPLS:
        case OVS_ACTION_ATTR_POP_MPLS:
        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_SET_MASKED:
        case OVS_ACTION_ATTR_SAMPLE:
        case OVS_ACTION_ATTR_HASH:
        case OVS_ACTION_ATTR_UNSPEC:
        case OVS_ACTION_ATTR_TRUNC:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_CT_CLEAR:
        case OVS_ACTION_ATTR_PUSH_ETH:
        case OVS_ACTION_ATTR_POP_ETH:
        case OVS_ACTION_ATTR_PUSH_NSH:
        case OVS_ACTION_ATTR_POP_NSH:
        case OVS_ACTION_ATTR_METER:
        case OVS_ACTION_ATTR_CLONE:
        case __OVS_ACTION_ATTR_MAX: {
            break;
            }
        default: {
            break;
            }
        }
        /* TODO :: Validate each actions */
    }
    return FLOW_INSTALL_SUPPORTED;
}

static bool
is_hw_switch_support_proto(struct dpdkhw_switch *hw_switch,
                           enum hw_switch_proto switch_proto)
{
    if (switch_proto >= LAST_PROTO_INVALID) {
        VLOG_DBG("Invalid protocol, cannot find in hardware capabilities");
        return false;
    }
    uint8_t flag = 1 << (switch_proto % 8);
    if (hw_switch->avail_ptypes[switch_proto/8] & flag) {
        return true;
    }
    return false;
}

static bool
is_protocol_supported_in_hw(struct dpdkhw_switch *hw_switch,
                            struct match *match)
{
    struct flow *flow = &match->flow;
    /* Start from the upper layer protocols, L4 layer protocols*/
    switch(flow->nw_proto) {
    case IPPROTO_TCP: {
        return is_hw_switch_support_proto(hw_switch, L4_TCP);
        break;
        }
    case IPPROTO_UDP: {
        return is_hw_switch_support_proto(hw_switch, L4_UDP);
        break;
        }
    case IPPROTO_ICMP: {
        return is_hw_switch_support_proto(hw_switch, L4_ICMP);
        break;
        }
    case IPPROTO_SCTP: {
        return is_hw_switch_support_proto(hw_switch, L4_SCTP);
        break;
        }
    case IPPROTO_ICMPV6: {
        return is_hw_switch_support_proto(hw_switch, L4_ICMPV6);
        break;
        }
    }

    /* Look for L3 only layer protocols */
    switch(ntohs(flow->dl_type)) {
    case ETH_TYPE_ARP: {
        return is_hw_switch_support_proto(hw_switch, L3_ARP);
        break;
        }
    case ETH_TYPE_RARP: {
        return is_hw_switch_support_proto(hw_switch, L3_RARP);
        break;
        }
    case ETH_TYPE_IP: {
        return is_hw_switch_support_proto(hw_switch, L3_IP);
        break;
        }
    case ETH_TYPE_IPV6: {
        return is_hw_switch_support_proto(hw_switch, L3_IPV6);
        break;
        }
    case ETH_TYPE_VLAN: {
        return is_hw_switch_support_proto(hw_switch, L3_VLAN);
        break;
        }
    }

    if (!eth_addr_is_zero(flow->dl_dst) && !eth_addr_is_zero(flow->dl_src)) {
        /* Just a L2 rule */
        return is_hw_switch_support_proto(hw_switch, L2_ETH);
    }

    /* TODO :: Add protocols to check support */
    return false;
}

/*
 * Function to check if a flow is already present in the hw before installing
 */
static inline bool
is_flow_present_in_hw(struct netdev *netdev, const ovs_u128 *ufid,
                      const struct nlattr *actions,
                      size_t actions_len)
{
    struct ufid_to_rteflow *entry;
    entry = get_ufid_to_rteflow_mapping(ufid, netdev);
    if (entry) {
        if (entry->action_len != actions_len) {
            /* Drop action can have zero len, so
             * check action_len to see if a flow need to be modified
             * in hw
             */
            return false;
        }
        if (!memcmp(entry->actions, actions, actions_len)) {
            return true;
        }
    }
    return false;
}

static enum hw_switch_flow_install_err
is_flow_ofld_on_full_em_switch_supported(struct netdev *netdev,
                                         struct dpdkhw_switch *hw_switch,
                                         struct match *match,
                                         const struct nlattr *actions,
                                         size_t actions_len,
                                         const ovs_u128 *ufid,
                                         struct offload_info *info)
{
    /* hardware doesnt have flow modify support, hence first delete the flow
     * before trying the flow install.
     * Modify with drop action is used as a delete function by revalidator.
     */
    if (info->flow_flags & DPIF_FP_MODIFY) {
        if (is_flow_present_in_hw(netdev, ufid, actions, actions_len)) {
            /*
             * No need to modify the flow in hw as its same as in sw.
             */
            return FLOW_PRESENT_IN_HW;
        }
        VLOG_DBG("Deleteing flows when modifying existing flows.");
        netdev_dpdkhw_switch_flow_del(netdev, hw_switch, ufid);
    }

    /* Check if the flow count before the install */
    if (atomic_count_get(&hw_switch->n_flow_cnt) >=
        hw_switch->total_flow_cnt) {
        return FLOW_MAX_LIMIT_REACHED;
    }

    /* Check if flow types are supported in the switch */
    if (!is_protocol_supported_in_hw(hw_switch, match)) {
        return FLOW_PROTO_UNSUPPORTED;
    }

    /* Check if the actions has port output, make sure its in same device */
    return is_action_hanlded_in_one_device(hw_switch, actions,
                                           actions_len, info);
}

static enum xlate_status
do_inport_flow_xlate(struct match *match, struct dpdk_flow_batch *batch,
                                          const void *md)
{
    struct flow *flow;
    struct rte_flow_item_port_id *port_flow_item;
    struct rte_flow_item_port_id *port_flow_item_mask;
    struct netdev *netdev;
    uint16_t dpdk_portno;
    struct offload_info *ofld_info = (struct offload_info *)md;

    flow = &match->flow;
    port_flow_item = xzalloc (sizeof *port_flow_item);
    port_flow_item_mask = xzalloc (sizeof *port_flow_item_mask);
    if(!port_flow_item) {
        VLOG_ERR("Failed to allocate the memory for hardware flow item");
        return FLOW_XLATE_FAILED;
    }

    netdev = get_hw_netdev(flow->in_port.odp_port, ofld_info->dpif_class);
    if (!netdev) {
        VLOG_WARN("Inport %u is not a valid hardware accelerated port.",
                    odp_to_u32(flow->in_port.odp_port));
        return FLOW_XLATE_FAILED;
    }
    /* The inport should be the dpdk port number, not the ovs portno */
    dpdk_portno = netdev_get_dpdk_portno(netdev);
    port_flow_item->id = dpdk_portno;
    port_flow_item_mask->id = 0xFFFFFFFF;

    /* Set the mask for the rte port flow */
    rte_flow_item_push(batch, port_flow_item, port_flow_item_mask,
                              PORT_FLOW_XLATE.rte_flow_type);
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_l2_flow_xlate(struct match *match, struct dpdk_flow_batch *batch,
                                      const void *md OVS_UNUSED)
{
    struct flow *flow, *mask;
    struct rte_flow_item_eth *eth_flow_item;
    struct rte_flow_item_eth *eth_flow_mask;
    flow = &match->flow;
    mask = &match->wc.masks;
    bool is_l2_zero  = 0;
    is_l2_zero = eth_addr_is_zero(flow->dl_dst);
    is_l2_zero &= eth_addr_is_zero(flow->dl_src);
    if(is_l2_zero) {
        VLOG_ERR("Cannot install flow with zero eth addr");
        return FLOW_XLATE_FAILED;
    }
    eth_flow_item = xzalloc(sizeof *eth_flow_item);
    eth_flow_mask = xzalloc(sizeof *eth_flow_mask);
    if(!eth_flow_item || !eth_flow_mask) {
        VLOG_ERR("Failed to allocate the memory for flow item");
        return FLOW_XLATE_FAILED;
    }


    memcpy(&eth_flow_item->dst, &flow->dl_dst, sizeof(eth_flow_item->dst));
    memcpy(&eth_flow_item->src, &flow->dl_src, sizeof(eth_flow_item->src));
    eth_flow_item->type = flow->dl_type;

    /* Copy the address mask too */

    memcpy(&eth_flow_mask->dst, &mask->dl_dst, sizeof(eth_flow_mask->dst));
    memcpy(&eth_flow_mask->src, &mask->dl_src, sizeof(eth_flow_mask->src));
    eth_flow_mask->type = mask->dl_type;

    rte_flow_item_push(batch, eth_flow_item, eth_flow_mask,
                       L2_FLOW_XLATE.rte_flow_type);
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_l2_vlan_flow_xlate(struct match *match, struct dpdk_flow_batch *batch,
                      const void *md OVS_UNUSED)
{
    int i;
    enum xlate_status ret = FLOW_XLATE_NOT_NEEDED;
    struct flow *flow, *mask;
    flow = &match->flow;
    mask = &match->wc.masks;
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        /* Push all VLAN flows to hardware */
        if (flow->vlans[i].tci & htons(VLAN_CFI)) {
            VLOG_DBG("Installing a flow with VLAN in hw.");
            /* VLAN tag is present in packet */
            struct rte_flow_item_vlan *vlan_flow_item;
            struct rte_flow_item_vlan *vlan_flow_mask;
            vlan_flow_item = xzalloc(sizeof *vlan_flow_item);
            vlan_flow_mask = xzalloc(sizeof *vlan_flow_mask);
            vlan_flow_item->inner_type = ETH_TYPE_VLAN;
            vlan_flow_item->tci = flow->vlans[i].tci;
            vlan_flow_mask->inner_type = 0xFFFF;
            vlan_flow_mask->tci = mask->vlans[i].tci;
            rte_flow_item_push(batch, vlan_flow_item, vlan_flow_mask,
                           L2_VLAN_FLOW_XLATE.rte_flow_type);
            ret = FLOW_XLATE_SUCCESS;
        }
        else {
            break;
        }
    }
    return ret;
}

static enum xlate_status
do_l3_flow_xlate(struct match *match, struct dpdk_flow_batch *batch,
                 const void *md OVS_UNUSED)
{
    struct flow *flow, *mask;

    flow = &match->flow;
    mask = &match->wc.masks;

    if(flow->dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *ipv4_flow_item, *ipv4_flow_mask;

        VLOG_DBG("Installing flow with IP header src: "IP_FMT ", dst: "
                 IP_FMT, IP_ARGS(flow->nw_src), IP_ARGS(flow->nw_dst));
        ipv4_flow_item = xzalloc(sizeof *ipv4_flow_item);
        ipv4_flow_mask = xzalloc(sizeof *ipv4_flow_mask);

        /* Xlate the ip flow entries */
        ipv4_flow_item->hdr.src_addr = flow->nw_src;
        ipv4_flow_item->hdr.dst_addr = flow->nw_dst;
        ipv4_flow_item->hdr.next_proto_id = flow->nw_proto;
        ipv4_flow_item->hdr.type_of_service = flow->nw_tos;
        ipv4_flow_item->hdr.version_ihl = 4;

        /* Xlate ipv4 mask entries */
        ipv4_flow_mask->hdr.src_addr = mask->nw_src;
        ipv4_flow_mask->hdr.dst_addr = mask->nw_dst;
        ipv4_flow_mask->hdr.next_proto_id = mask->nw_proto;
        ipv4_flow_mask->hdr.type_of_service = mask->nw_tos;
        ipv4_flow_mask->hdr.version_ihl = 0xFF;
        rte_flow_item_push(batch, ipv4_flow_item, ipv4_flow_mask,
                           RTE_FLOW_ITEM_TYPE_IPV4);
    }
    else if (flow->dl_type == htons(ETH_TYPE_MPLS)) {
            int i, n;
            n = flow_count_mpls_labels(flow, NULL);
            if (!n) {
                return FLOW_XLATE_NOT_NEEDED;
            }
            VLOG_DBG("Installing flow with MPLS");
            for (i = 0; i < n; i++) {
                struct rte_flow_item_mpls *mpls_lbl, *mpls_mask;
                mpls_lbl = xzalloc(sizeof *mpls_lbl);
                mpls_mask = xzalloc(sizeof *mpls_mask);
                /* MPLS label(32bit) are in the following format,
                 *  <label(20 bit)> <TC(3 bit)> <BS(1 bit)> <ttl(8 bit)>
                 */
                *(ovs_be32 *)mpls_lbl = flow->mpls_lse[i];
                *(ovs_be32 *)mpls_mask = mask->mpls_lse[i];
                rte_flow_item_push(batch, mpls_lbl, mpls_mask,
                                   RTE_FLOW_ITEM_TYPE_MPLS);
            }
            return FLOW_XLATE_LAST;
    }
    else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        VLOG_DBG("Installing flow with Ipv6");
        uint32_t ipv6_label;
        struct rte_flow_item_ipv6 *ipv6_flow_item, *ipv6_flow_mask;
        ipv6_flow_item = xzalloc(sizeof *ipv6_flow_item);
        ipv6_flow_mask = xzalloc(sizeof *ipv6_flow_mask);
        memcpy(&ipv6_flow_item->hdr.src_addr, &flow->ipv6_src,
               sizeof ipv6_flow_item->hdr.src_addr);
        memcpy(&ipv6_flow_item->hdr.dst_addr, &flow->ipv6_dst,
               sizeof ipv6_flow_item->hdr.dst_addr);
        ipv6_flow_item->hdr.proto = flow->nw_proto;
        /*ipv6 label need to be 20 bits packed in network order */
        /* Get the first 16 bits of flow_label */
        ipv6_label = (flow->ipv6_label & 0xFFFF0000);
        /* Get next four bits and move it to MSB */
        ipv6_label = ipv6_label |((flow->ipv6_label & 0x00000F00) <<4);
        ipv6_flow_item->hdr.vtc_flow = 6 |
                                   (flow->nw_tos << 4) | ipv6_label;
        memcpy(&ipv6_flow_mask->hdr.src_addr, &mask->ipv6_src,
               sizeof ipv6_flow_mask->hdr.src_addr);
        memcpy(&ipv6_flow_mask->hdr.dst_addr, &mask->ipv6_dst,
               sizeof ipv6_flow_mask->hdr.dst_addr);
        ipv6_flow_mask->hdr.proto =mask->nw_proto;
        ipv6_label = (mask->ipv6_label & 0xFFFF0000);
        ipv6_label = ipv6_label |((mask->ipv6_label & 0x00000F00) <<4);
        ipv6_flow_mask->hdr.vtc_flow = 6 |
                                   (mask->nw_tos << 4) | ipv6_label;
        rte_flow_item_push(batch, ipv6_flow_item, ipv6_flow_mask,
                           RTE_FLOW_ITEM_TYPE_IPV6);
    }
    else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
             flow->dl_type == htons(ETH_TYPE_RARP))
    {
        struct rte_flow_item_arp_eth_ipv4 *arp_flow, *arp_mask;
        arp_flow  = xzalloc(sizeof *arp_flow);
        arp_mask = xzalloc(sizeof *arp_mask);
        arp_flow->hrd = 1;
        arp_flow->pro =  ETH_TYPE_IP;
        arp_flow->hln = ETH_ADDR_LEN;
        arp_flow->pln = 4;
        /* arp op is 16 bit in network order */
        arp_flow->op = (flow->nw_proto << 8);
        /* Masks for ARP */
        arp_mask->hrd = 0xFF;
        arp_mask->pro = 0xFF;
        arp_mask->hln = 0xF;
        arp_mask->pln = 0xF;
        arp_mask->op = 0xFF;
        if (flow->nw_proto == ARP_OP_REQUEST ||
            flow->nw_proto == ARP_OP_REPLY) {
            arp_flow->spa = flow->nw_src;
            arp_flow->tpa = flow->nw_dst;
            memcpy(&arp_flow->sha, &flow->arp_sha,
                   sizeof arp_flow->sha);
            memcpy(&arp_flow->tha, &flow->arp_tha,
                   sizeof arp_flow->tha);
            /*Mask for arp header fields */
            arp_mask->spa = mask->nw_src;
            arp_mask->tpa = mask->nw_dst;
            memcpy(&arp_mask->sha, &mask->arp_sha,
                   sizeof arp_mask->sha);
            memcpy(&arp_mask->tha, &mask->arp_tha,
                   sizeof arp_mask->tha);
        }
        rte_flow_item_push(batch, arp_flow, arp_mask,
                           RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4);
        return FLOW_XLATE_LAST;
    }
    else {
      VLOG_DBG("Not a ARP/IP/IPv6/MPLS flow, %d, "
                "could be a L2 only flow ", ntohs(flow->dl_type));
      return FLOW_XLATE_FAILED;
    }
    return FLOW_XLATE_SUCCESS;

}

static enum xlate_status
do_l4_flow_xlate(struct match *match, struct dpdk_flow_batch *batch,
                 const void *md OVS_UNUSED)
{
    struct flow *flow, *mask;

    flow = &match->flow;
    mask = &match->wc.masks;

    if(flow->nw_proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *tcp_flow_item, *tcp_flow_mask;
        tcp_flow_item = xzalloc(sizeof *tcp_flow_item);
        tcp_flow_mask = xzalloc(sizeof *tcp_flow_mask);

        /* Xlate tcp flow entries */
        tcp_flow_item->hdr.src_port = flow->tp_src;
        tcp_flow_item->hdr.dst_port = flow->tp_dst;

        /* Xlate tcp flow mask entries */
        tcp_flow_mask->hdr.src_port = mask->tp_src;
        tcp_flow_mask->hdr.dst_port = mask->tp_dst;
        rte_flow_item_push(batch, tcp_flow_item, tcp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_TCP);
    }
    else if (flow->nw_proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *udp_flow_item, *udp_flow_mask;
        udp_flow_item = xzalloc(sizeof *udp_flow_item);
        udp_flow_mask = xzalloc(sizeof *udp_flow_mask);

        /* xlate UDP flow entries */
        udp_flow_item->hdr.src_port = flow->tp_src;
        udp_flow_item->hdr.dst_port = flow->tp_dst;

        /* Xlate UDP mask entries */
        udp_flow_mask->hdr.src_port = mask->tp_src;
        udp_flow_mask->hdr.dst_port = mask->tp_dst;
        rte_flow_item_push(batch, udp_flow_item, udp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_UDP);
    }
    else if (flow->nw_proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *icmp_flow_item, *icmp_flow_mask;
        icmp_flow_item = xzalloc(sizeof *icmp_flow_item);
        icmp_flow_mask = xzalloc(sizeof *icmp_flow_mask);
        /* icmp type is 8 bit, LSB of 16 bit tp_src */
        icmp_flow_item->hdr.icmp_type = htons(flow->tp_src) & 0xFF;
        /* icmp code is 8 bit, LSB of 16 bit tp_dst */
        icmp_flow_item->hdr.icmp_code = htons(flow->tp_dst) & 0xFF;
        icmp_flow_mask->hdr.icmp_type = htons(mask->tp_src) & 0xFF;
        icmp_flow_mask->hdr.icmp_code = htons(mask->tp_dst) & 0xFF;
        rte_flow_item_push(batch, icmp_flow_item, icmp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_ICMP);
    }
    else if(flow->nw_proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *sctp_flow_item, *sctp_flow_mask;
        sctp_flow_item = xzalloc(sizeof *sctp_flow_item);
        sctp_flow_mask = xzalloc(sizeof *sctp_flow_mask);
        sctp_flow_item->hdr.src_port = flow->tp_src;
        sctp_flow_item->hdr.dst_port = flow->tp_dst;
        sctp_flow_mask->hdr.src_port = mask->tp_src;
        sctp_flow_mask->hdr.dst_port = mask->tp_dst;
        rte_flow_item_push(batch, sctp_flow_item, sctp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_SCTP);
    }
    else if(flow->nw_proto == IPPROTO_ICMPV6) {
        /* icmp type is 8 bit, LSB of 16 bit tp_src */
        uint8_t type = htons(flow->tp_src) & 0xFF;
        /* icmp code is 8 bit, LSB of 16 bit tp_dst */
        uint8_t code = htons(flow->tp_dst) & 0xFF;
        uint8_t type_mask = htons(mask->tp_src) & 0xFF;
        uint8_t code_mask = htons(mask->tp_dst) & 0xFF;
        if (type == ND_NEIGHBOR_SOLICIT ||
            type == ND_NEIGHBOR_ADVERT) {
            /* ND_NA and ND_NS share same fields, hence allocate struct once.*/
            struct rte_flow_item_icmp6_nd_na *icmpv6_flow_item,
                                             *icmpv6_flow_mask;
            icmpv6_flow_item = xzalloc(sizeof *icmpv6_flow_item);
            icmpv6_flow_mask = xzalloc(sizeof *icmpv6_flow_mask);

            icmpv6_flow_item->type = type;
            /* icmp code is 8 bit, LSB of 16 bit tp_dst */
            icmpv6_flow_item->code = code;
            icmpv6_flow_mask->type = type_mask;
            icmpv6_flow_mask->code = code_mask;

            /* Need to populate ND entries if present. */
            memcpy(&icmpv6_flow_item->target_addr, &flow->nd_target,
                                      sizeof icmpv6_flow_item->target_addr);
            memcpy(&icmpv6_flow_mask->target_addr, &mask->nd_target,
                                      sizeof icmpv6_flow_mask->target_addr);
           rte_flow_item_push(batch, icmpv6_flow_item, icmpv6_flow_mask,
                                      (type == ND_NEIGHBOR_SOLICIT ?
                                      RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS :
                                      RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA));

            if (!eth_addr_is_zero(flow->arp_sha)) {
                /* ICMPV6 SLA */
                struct rte_flow_item_icmp6_nd_opt_sla_eth *icmpv6_flow_sla,
                                                      *icmpv6_flow_mask_sla;
                icmpv6_flow_sla = xzalloc(sizeof *icmpv6_flow_item);
                icmpv6_flow_mask_sla = xzalloc(sizeof *icmpv6_flow_mask);

                icmpv6_flow_sla->type = 1;
                icmpv6_flow_sla->length = 1;
                icmpv6_flow_mask_sla->type = 0xF;
                icmpv6_flow_mask_sla->length = 0xF;
                memcpy(&icmpv6_flow_sla->sla, &flow->arp_sha,
                       sizeof icmpv6_flow_sla->sla);
                memcpy(&icmpv6_flow_mask_sla->sla, &mask->arp_sha,
                       sizeof icmpv6_flow_mask_sla->sla);
                rte_flow_item_push(batch, icmpv6_flow_sla,
                                   icmpv6_flow_mask_sla,
                                   RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH);
            }
            else if (!eth_addr_is_zero(flow->arp_tha)) {
                /* ICMPV6 TLA */
                struct rte_flow_item_icmp6_nd_opt_tla_eth *icmpv6_flow_tla,
                                                      *icmpv6_flow_mask_tla;
                icmpv6_flow_tla = xzalloc(sizeof *icmpv6_flow_tla);
                icmpv6_flow_mask_tla = xzalloc(sizeof *icmpv6_flow_mask_tla);
                icmpv6_flow_tla->type = 2;
                icmpv6_flow_tla->length = 1;
                icmpv6_flow_mask_tla->type = 0xF;
                icmpv6_flow_mask_tla->length = 0xF;
                memcpy(&icmpv6_flow_tla->tla, &flow->arp_tha,
                                             sizeof icmpv6_flow_tla->tla);
                memcpy(&icmpv6_flow_mask_tla->tla, &mask->arp_tha,
                                           sizeof icmpv6_flow_mask_tla->tla);
                rte_flow_item_push(batch, icmpv6_flow_tla,
                                   icmpv6_flow_mask_tla,
                                   RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH);
            }
        }
        else {
            struct rte_flow_item_icmp6 *icmpv6_flow_item, *icmpv6_flow_mask;
            icmpv6_flow_item = xzalloc(sizeof *icmpv6_flow_item);
            icmpv6_flow_mask = xzalloc(sizeof *icmpv6_flow_mask);
            icmpv6_flow_item->type = type;
            icmpv6_flow_item->code = code;
            icmpv6_flow_mask->type = type_mask;
            icmpv6_flow_mask->code = code_mask;
            rte_flow_item_push(batch, icmpv6_flow_item, icmpv6_flow_mask,
                                    RTE_FLOW_ITEM_TYPE_ICMP6);
        }
    }
    else {
        VLOG_DBG("Not a TCP/UDP/ICMP/SCTP/ICMPv6 flow, Can be a L3 only"
                  " flow");
        return FLOW_XLATE_FAILED;
    }
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_end_flow_xlate(struct match *match OVS_UNUSED, struct dpdk_flow_batch *batch,
                                       const void *md OVS_UNUSED)
{
    rte_flow_item_push(batch, NULL, NULL, RTE_FLOW_ITEM_TYPE_END);
    return FLOW_XLATE_SUCCESS;
}

static int
do_flow_xlate_helper(struct flow_xlate_dic xlate_dic_entry,
                      struct match *match,
                      struct dpdk_flow_batch *batch,
                      const void *md)
{
    return xlate_dic_entry.flow_xlate(match, batch, md);

}

#define DO_FLOW_XLATE(XLATE_DIC_ENTRY, MATCH_ENTRY, FLOW_BATCH, MD_PTR) \
    do_flow_xlate_helper(XLATE_DIC_ENTRY, MATCH_ENTRY, FLOW_BATCH, \
                                                       MD_PTR)

/* The inport and L2 based flows are only populated in the hardware.
 * i,e Only the mac addresses and inport are matching in the hardware.
 */
static int
dpdkhw_rte_flow_xlate(struct match *match,
                          struct rte_flow_attr *hw_flow_attr,
                          struct dpdk_flow_batch *batch,
                          const struct offload_info *ofld_info)
{
    hw_flow_attr->group = 0;
    hw_flow_attr->priority = 0;
    hw_flow_attr->ingress = 1; /* Supports only ingress flow rules now */
    int ret = 0;
    int res = 0;

    /*
     * List of supported rte flow entries are populated below. Each header
     * has its own xlate function to generate the corresponding rte_flow entry.
     * The translate functions operate on each header fields independently in
     * the stack. It is possible that the flow can have match entry for port and
     * ip address when the mac flow translation is failed to do.
     */
    res = DO_FLOW_XLATE(PORT_FLOW_XLATE, match, batch, ofld_info);
    if (res == FLOW_XLATE_LAST) {
        goto out;
    }
    ret |= res;
    res = DO_FLOW_XLATE(L2_FLOW_XLATE, match, batch, NULL);
    if (res == FLOW_XLATE_LAST) {
        goto out;
    }
    ret |= res;
    res = DO_FLOW_XLATE(L2_VLAN_FLOW_XLATE, match, batch, NULL);
    if (res == FLOW_XLATE_LAST) {
        goto out;
    }
    ret |= res;
    res = DO_FLOW_XLATE(L3_FLOW_XLATE, match, batch, NULL);
    if (res == FLOW_XLATE_LAST) {
        goto out;
    }
    ret |= res;
    res = DO_FLOW_XLATE(L4_FLOW_XLATE, match, batch, NULL);
    if (res == FLOW_XLATE_LAST) {
        goto out;
    }
    ret |= res;
    /* Always the END function is called as a last function,
     * DO NOT ADD ANY TRANSLATE FUNCTION POST END XLATE.
     */
out:
    DO_FLOW_XLATE(END_FLOW_XLATE, match, batch, NULL);
    /* Return only the error if any */
    return (ret & FLOW_XLATE_FAILED);
}

static void
dpdkhw_rte_eth_set_action(const struct ovs_key_ethernet *key,
                          struct rte_flow_action hw_action_batch[],
                          int *const idx)
{
/*    if (!eth_addr_is_zero(key->eth_src)) {
        struct rte_flow_action_eth_set *eth_action_src =
                                       xmalloc(sizeof *eth_action_src);
        memcpy(&eth_action_src->addr, &key->eth_src,
                                      sizeof eth_action_src->addr);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ETH_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = eth_action_src;
        (*idx)++;
    }
    if (!eth_addr_is_zero(key->eth_dst)) {
        struct rte_flow_action_eth_set *eth_action_dst =
                                      xmalloc(sizeof *eth_action_dst);
        memcpy(&eth_action_dst->addr, &key->eth_dst,
                                      sizeof eth_action_dst->addr);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ETH_DST_ADDR_SET;
        hw_action_batch[*idx].conf = eth_action_dst;
        (*idx)++;
    }*/
}

/*
 * Set ttl for ipv4 and ipv6
 */
static void
dpdkhw_rte_ip_ttl_set_action(uint8_t ttl,
                             struct rte_flow_action hw_action_batch[],
                             int *const idx)
{
/*    struct rte_flow_action_ttl_set *ip_ttl_action =
                       xmalloc(sizeof *ip_ttl_action);
    ip_ttl_action->ttl = ttl;
    ip_ttl_action->layer = 0;
    hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_TTL_SET;
    hw_action_batch[*idx].conf = ip_ttl_action;
    (*idx)++;*/
}

/*
 * Set tos(dscp,ecn) for ipv4 and ipv6
 */
static void
dpdkhw_rte_ip_tos_set_action(uint8_t tos,
                             struct rte_flow_action hw_action_batch[],
                             int *const idx)
{
/*    struct rte_flow_action_dscp_ecn_set *ip_tos_action =
                         xmalloc(sizeof *ip_tos_action);
    ip_tos_action->dscp_ecn = tos;
    ip_tos_action->mask = 0xFF;
    ip_tos_action->layer = 0;
    hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DSCP_ECN_SET;
    hw_action_batch[*idx].conf = ip_tos_action;
    (*idx)++;*/
}

static void
dpdkhw_rte_ipv4_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv4 *ipv4_key;
    ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
/*    if (ipv4_key->ipv4_src) {
        struct rte_flow_action_ipv4_addr_set *ipv4_src_addr_action =
                            xmalloc(sizeof *ipv4_src_addr_action);
        ipv4_src_addr_action->addr = ipv4_key->ipv4_src;
        ipv4_src_addr_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_src_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_dst) {
        struct rte_flow_action_ipv4_addr_set *ipv4_dst_addr_action =
                            xmalloc(sizeof *ipv4_dst_addr_action);
        ipv4_dst_addr_action->layer = 0;
        ipv4_dst_addr_action->addr = ipv4_key->ipv4_dst;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_DST_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_dst_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_ttl) {
        dpdkhw_rte_ip_ttl_set_action(ipv4_key->ipv4_ttl, hw_action_batch,
                                     idx);
    }
    if (ipv4_key->ipv4_tos) {
        dpdkhw_rte_ip_tos_set_action(ipv4_key->ipv4_tos, hw_action_batch,
                                     idx);
    }*/
}

static void
dpdkhw_rte_ipv6_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv6 *ipv6_key;
    ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
    /* rte flow can only set src and dst ipv6 address */
/*    if (ipv6_addr_is_set(&ipv6_key->ipv6_src)) {
        struct rte_flow_action_ipv6_addr_set *ipv6_src_action =
                       xmalloc(sizeof *ipv6_src_action);
        memcpy(&ipv6_src_action->addr, &ipv6_key->ipv6_src,
                            sizeof ipv6_src_action->addr);
        ipv6_src_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = ipv6_src_action;
        (*idx)++;
    }
    if (ipv6_addr_is_set(&ipv6_key->ipv6_dst)) {
        struct rte_flow_action_ipv6_addr_set *ipv6_dst_action =
                       xmalloc(sizeof *ipv6_dst_action);
        memcpy(&ipv6_dst_action->addr, &ipv6_key->ipv6_dst,
                            sizeof ipv6_dst_action->addr);
        ipv6_dst_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_DST_ADDR_SET;
        hw_action_batch[*idx].conf = ipv6_dst_action;
        (*idx)++;
    }
    if (ipv6_key->ipv6_label) {*/
        /* ipv6 label is set for the ipv6 header */
/*        struct rte_flow_action_ipv6_label_set *ipv6_label_action =
                                 xmalloc(sizeof *ipv6_label_action);*/
        /* ipv6 label mask is 0xFFFFF000, Shift last 4 bits to the left
         * for the 20 bit packing.
         */
/*        ipv6_label_action->label = (ipv6_key->ipv6_label & 0xFFFF0000);
        ipv6_label_action->label |= (ipv6_key->ipv6_label & 0x00000F00) << 4;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV6_LABEL_SET;
        hw_action_batch[*idx].conf = ipv6_label_action;
        (*idx)++;
    }
    if (ipv6_key->ipv6_hlimit) {
        dpdkhw_rte_ip_ttl_set_action(ipv6_key->ipv6_hlimit, hw_action_batch,
                                     idx);
    }
    if (ipv6_key->ipv6_tclass) {
        dpdkhw_rte_ip_tos_set_action(ipv6_key->ipv6_tclass, hw_action_batch,
                                     idx);
    }*/
}

static void
dpdkhw_rte_l4_set_action(ovs_be16 src_port, ovs_be16 dst_port,
                         struct rte_flow_action hw_action_batch[],
                         int *const idx)
{
/*    if (src_port) {
        struct rte_flow_action_pt_num_set *l4_src_action =
                            xmalloc(sizeof *l4_src_action);
        l4_src_action->pt_num = src_port;
        l4_src_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_SRC_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_src_action;
        (*idx)++;
    }
    if (dst_port) {
        struct rte_flow_action_pt_num_set *l4_dst_action =
                             xmalloc(sizeof *l4_dst_action);
        l4_dst_action->pt_num = dst_port;
        l4_dst_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DST_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_dst_action;
        (*idx)++;
    }*/
}

static int
dpdkhw_rte_set_action(const struct nlattr *a,
                      struct rte_flow_action hw_action_batch[],
                      int *idx)
{
    enum ovs_key_attr type = nl_attr_type(a);
    int ret = 0;
    switch (type) {
    case OVS_KEY_ATTR_ETHERNET: {
        dpdkhw_rte_eth_set_action(nl_attr_get(a), hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_IPV4: {
        dpdkhw_rte_ipv4_set_action(a, hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_IPV6: {
        dpdkhw_rte_ipv6_set_action(a, hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6: {
        /* TODO ::ICMP set operations are not supported in DPDK rte-actions */
        /*const struct ovs_key_icmp *icmp_key =
                        nl_attr_get_unspec(a, sizeof(struct ovs_key_icmp));
        if (icmp_key->icmp_type) {
            struct rte_flow_action_icmp_type_set *icmp_type_action =
                                    xmalloc(sizeof *icmp_type_action);
            icmp_type_action->type = icmp_key->icmp_type;
            icmp_type_action->layer = 0;
            hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ICMP_TYPE_SET;
            hw_action_batch[*idx].conf = icmp_type_action;
            (*idx)++;
        }
        if (icmp_key->icmp_code) {
            struct rte_flow_action_icmp_code_set *icmp_code_action =
                                    xmalloc(sizeof *icmp_code_action);
            icmp_code_action->code = icmp_key->icmp_code;
            icmp_code_action->layer = 0;
            hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_ICMP_CODE_SET;
            hw_action_batch[*idx].conf = icmp_code_action;
            (*idx)++;
        }*/
        break;
    }

    case OVS_KEY_ATTR_TCP: {
        const struct ovs_key_tcp *tcp_key =
                nl_attr_get_unspec(a, sizeof(struct ovs_key_tcp));
        dpdkhw_rte_l4_set_action(tcp_key->tcp_src, tcp_key->tcp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_UDP: {
        const struct ovs_key_udp *udp_key =
               nl_attr_get_unspec(a, sizeof(struct ovs_key_udp));
        dpdkhw_rte_l4_set_action(udp_key->udp_src, udp_key->udp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_SCTP: {
        const struct ovs_key_sctp *sctp_key =
               nl_attr_get_unspec(a, sizeof(struct ovs_key_sctp));
        dpdkhw_rte_l4_set_action(sctp_key->sctp_src, sctp_key->sctp_dst,
                                 hw_action_batch, idx);
        break;
    }

    case OVS_KEY_ATTR_VLAN: {

        struct rte_flow_action_of_set_vlan_vid *vid_action =
                              xzalloc(sizeof *vid_action);
        uint16_t tci = nl_attr_get_u16(a);
        /* Set VID on outermost vlan tag. */
        vid_action->vlan_vid = htons(vlan_tci_to_vid(tci));
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID;
        hw_action_batch[*idx].conf = vid_action;
        (*idx)++;

        /* Set PCP bits on new VLAN tag */
        struct rte_flow_action_of_set_vlan_pcp *pcp_action =
                               xzalloc(sizeof *pcp_action);
        pcp_action->vlan_pcp = (uint8_t)vlan_tci_to_pcp(tci);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP;
        hw_action_batch[*idx].conf = pcp_action;
        (*idx)++;
        break;
    }

    case OVS_KEY_ATTR_ARP:
    case OVS_KEY_ATTR_ND:
    case OVS_KEY_ATTR_MPLS:
    case OVS_KEY_ATTR_RECIRC_ID:
    case OVS_KEY_ATTR_DP_HASH:
    case OVS_KEY_ATTR_SKB_MARK:
    case OVS_KEY_ATTR_TUNNEL:
    case OVS_KEY_ATTR_PRIORITY:
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_TCP_FLAGS:
    case OVS_KEY_ATTR_CT_STATE:
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
    case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
    case OVS_KEY_ATTR_NSH:
    case OVS_KEY_ATTR_PACKET_TYPE:
    case __OVS_KEY_ATTR_MAX:
    default:
        VLOG_ERR_RL(&rl, "Set action is not implemented");
        ret = -EINVAL;
    }
    return ret;
}

static int
dpdkhw_em_action_xlate(struct rte_flow_action hw_action_batch[],
                        const struct nlattr *actions,
                        size_t actions_len,
                        const struct offload_info *ofld_info)
{
    const struct nlattr *a;
    unsigned int left;
    int ret = 0;
    int i = 0;
    int max_action_entry = MAX_DPDKHW_RTE_ACTION_SIZE - 1;

    if (!actions_len || !actions) {
        VLOG_DBG_RL(&rl, "No actions to offload, Install drop action");
        hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_DROP;
        hw_action_batch[i].conf = NULL;
        return ret;
    }
    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        if(i >= max_action_entry) {
            VLOG_WARN("Max action entry limit reached,"
                      " cannot add more actions");
            return EPERM;
        }
        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            struct rte_flow_action_port_id *rte_action_port =
                    xmalloc(sizeof *rte_action_port);
            odp_port_t out_port = nl_attr_get_odp_port(a);
            /* Output port should be hardware port number. */
            struct netdev *netdev = get_hw_netdev(out_port,
                                                  ofld_info->dpif_class);
            if (!netdev) {
                VLOG_WARN("Cannot offload a flow with non accelerated output"
                          " port %u", odp_to_u32(out_port));
                return EPERM;
            }

            uint16_t dpdk_portno = netdev_get_dpdk_portno(netdev);
            rte_action_port->id = dpdk_portno;
            rte_action_port->original = 1;

            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
            hw_action_batch[i].conf = rte_action_port;
            i++;
            break;
        }
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
            /* Push a new vlan tag as defined in openflow */
            struct rte_flow_action_of_push_vlan *vlan_push =
                            xzalloc(sizeof *vlan_push);
            vlan_push->ethertype = vlan->vlan_tpid;
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN;
            hw_action_batch[i].conf = vlan_push;
            i++;

            struct rte_flow_action_of_set_vlan_vid *vid_action =
                              xzalloc(sizeof *vid_action);
            /* Set VID on newely pushed vlan. */
            vid_action->vlan_vid = htons(vlan_tci_to_vid(vlan->vlan_tci));
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID;
            hw_action_batch[i].conf = vid_action;
            i++;

            /* Set PCP bits on new VLAN tag */
            struct rte_flow_action_of_set_vlan_pcp *pcp_action =
                               xzalloc(sizeof *pcp_action);
            pcp_action->vlan_pcp = (uint8_t)vlan_tci_to_pcp(vlan->vlan_tci);
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP;
            hw_action_batch[i].conf = pcp_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN: {
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_POP_VLAN;
            hw_action_batch[i].conf = NULL;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_SET_MASKED:
        case OVS_ACTION_ATTR_SET: {
            ret = dpdkhw_rte_set_action(nl_attr_get(a), hw_action_batch, &i);
            break;
        }

        case OVS_ACTION_ATTR_PUSH_MPLS: {
            /* MPLS push is combination of PUSH + SET actions */
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
            struct rte_flow_action_of_push_mpls *mpls_push_action =
                        xmalloc(sizeof *mpls_push_action);
            mpls_push_action->ethertype = mpls->mpls_ethertype;
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS;
            hw_action_batch[i].conf = mpls_push_action;
            i++;

            /* TODO :: No DPDK rte actions present to set the MPLS label */
            /*struct rte_flow_action_mpls_set *mpls_set_action =
                        xmalloc(sizeof *mpls_set_action);
            mpls_set_action->hdr = mpls->mpls_lse;
            mpls_set_action->mask = 0xFFFFFFFF;

            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_SET;
            hw_action_batch[i].conf = mpls_set_action;
            i++;*/
            break;
        }

        case OVS_ACTION_ATTR_POP_MPLS: {
            struct rte_flow_action_of_pop_mpls *mpls_pop_action =
                        xmalloc(sizeof *mpls_pop_action);
            mpls_pop_action->ethertype = nl_attr_get_be16(a);
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_OF_POP_MPLS;
            hw_action_batch[i].conf = mpls_pop_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_TUNNEL_PUSH:
        case OVS_ACTION_ATTR_TUNNEL_POP:
        case OVS_ACTION_ATTR_SAMPLE:
        case OVS_ACTION_ATTR_HASH:
        case OVS_ACTION_ATTR_UNSPEC:
        case OVS_ACTION_ATTR_TRUNC:
        case __OVS_ACTION_ATTR_MAX:
        case OVS_ACTION_ATTR_USERSPACE:
        case OVS_ACTION_ATTR_RECIRC:
        case OVS_ACTION_ATTR_CT:
        case OVS_ACTION_ATTR_CT_CLEAR:
        case OVS_ACTION_ATTR_PUSH_NSH:
        case OVS_ACTION_ATTR_POP_NSH:
        case OVS_ACTION_ATTR_PUSH_ETH:
        case OVS_ACTION_ATTR_POP_ETH:
        case OVS_ACTION_ATTR_METER:
        case OVS_ACTION_ATTR_CLONE:
            VLOG_DBG_RL(&rl, "TODO actions %u", type);
            ret = -EINVAL;
            break;
        default:
            VLOG_DBG_RL(&rl, "Unsupported action to offload %u", type);
            ret = -EINVAL;
            break;
        }
    }
    /* Add end action as a last action */
    hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_END;
    hw_action_batch[i].conf =  NULL;
    return ret;
}

/*
 * Cleanup the rte flow allocated resource after the flow getting installed in hw
 */
static int
dpdkhw_rte_flow_action_cleanup(struct rte_flow_item hw_flow_batch[],
                               struct rte_flow_action hw_action_batch[])
{
    struct rte_flow_item *flow_item;
    struct rte_flow_action *action_item;
    int idx;

    FOR_EACH_HWITEM(hw_flow_batch, flow_item, MAX_DPDKHW_RTE_FLOW_SIZE,
                    RTE_FLOW_ITEM_TYPE_END, idx) {
        if(flow_item->spec) {
            free((void *)flow_item->spec);
        }
        if(flow_item->mask) {
            free((void *)flow_item->mask);
        }
        if(flow_item->last) {
            free((void *)flow_item->last);
        }
    }

    FOR_EACH_HWITEM(hw_action_batch, action_item, MAX_DPDKHW_RTE_ACTION_SIZE,
                    RTE_FLOW_ACTION_TYPE_END, idx) {
        if(action_item->conf) {
            free((void *)action_item->conf);
        }
    }
    return 0;
}

static void
update_hw_switch_on_flowadd(struct dpdkhw_switch *hw_switch)
{
    atomic_count_inc(&hw_switch->n_flow_cnt);
}

static void
update_hw_switch_on_flowdel(struct dpdkhw_switch *hw_switch)
{
    atomic_count_dec(&hw_switch->n_flow_cnt);
}

static struct rte_flow *
install_ovs_flow_in_hw(struct netdev *netdev, struct dpdkhw_switch *hw_switch,
                       const struct rte_flow_attr *hw_flow_attr,
                       struct rte_flow_item *hw_flow_batch,
                       struct rte_flow_action *hw_action_batch,
                       struct rte_flow_error *hw_err)
{

    uint16_t dpdk_portno = netdev_get_dpdk_portno(netdev);
    struct rte_flow *hw_flow = rte_flow_create(dpdk_portno, hw_flow_attr,
                                               hw_flow_batch, hw_action_batch,
                                               hw_err);
    dpdkhw_rte_flow_action_cleanup(hw_flow_batch, hw_action_batch);
    if (hw_err->type != RTE_FLOW_ERROR_TYPE_NONE) {
        /* Error while installing the flow */
        VLOG_ERR("Failed to install a flow(error : %u)", hw_err->type);
        hw_flow = NULL;
    }
    if (hw_flow) {
        /* update the hardware switch only when flow is installed */
        update_hw_switch_on_flowadd(hw_switch);
    }
    return hw_flow;
}

/* Delete all the flows that are corresponds to single ufid. */
static int
netdev_del_rte_flow(struct ufid_to_rteflow *entry, uint16_t dpdk_portno,
                    struct dpdkhw_switch *hw_switch)
{

    int i;
    int ret = 0;
    for (i = 0; i < entry->hw_flow_size_used; i++) {
        struct rte_flow_error rte_flow_err;
        int res;
        res = rte_flow_destroy(dpdk_portno,
                               (struct rte_flow *)entry->hw_flows[i],
                                &rte_flow_err);
        if (!res) {
            update_hw_switch_on_flowdel(hw_switch);
        }
        ret |= res;
    }
    return ret;
}

static int
delete_ovs_flow_in_hw(struct netdev *netdev, struct dpdkhw_switch *hw_switch,
                      const ovs_u128 *ufid)
{
    struct ufid_to_rteflow *entry;
    int ret = -ENOENT;
    entry = get_ufid_to_rteflow_mapping(ufid, netdev);
    if (entry) {
        uint16_t dpdk_portno = netdev_get_dpdk_portno(netdev);
        ret = netdev_del_rte_flow(entry, dpdk_portno, hw_switch);
    }
    return ret;
}
