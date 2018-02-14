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

#include "netdev-dpdk-hw.h"
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

struct flow_xlate_dic {
    enum rte_flow_item_type rte_flow_type;
    /*
     * Flow xlate function to translate specific header match into rtl format.
     * Each rte_flow_item_type, it is necessary to define a corresponding
     * xlate function in this structure. Return 0 if the flow is being translated
     * successfully and error code otherwise.
     */
    enum xlate_status (*flow_xlate)(struct match *match,
                       struct rte_flow_batch *batch,
                       const void *md);
};

static inline bool
is_rte_flow_batch_full(struct rte_flow_batch *flow_batch)
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
init_rte_flow_batch(struct rte_flow_batch *batch,
                    struct rte_flow_item rte_flow_start[],
                    uint32_t batch_size)
{
    batch->used = 0;
    batch->max_size = batch_size;
    /* rte_flow_start is an array of rte_flow_item */
    batch->flow_batch = rte_flow_start;
}

static inline bool
rte_flow_item_push(struct rte_flow_batch *batch, void *flow,
                   void *mask, enum rte_flow_item_type type)
{
    struct rte_flow_item *flow_item;
    if (is_rte_flow_batch_full(batch)) {
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
                           struct rte_flow_batch *batch, const void *md);
static enum xlate_status do_l2_flow_xlate(struct match *match,
                        struct rte_flow_batch *batch, const void *md);
static enum xlate_status do_l2_vlan_flow_xlate(struct match *match,
                      struct rte_flow_batch *batch, const void *md);
static enum xlate_status do_l3_flow_xlate(struct match *match,
                          struct rte_flow_batch *batch, const void *md);
static enum xlate_status do_l4_flow_xlate(struct match *match,
                           struct rte_flow_batch *batch, const void *md);
static enum xlate_status do_end_flow_xlate(struct match *match,
                           struct rte_flow_batch *batch, const void *md);

struct flow_xlate_dic PORT_FLOW_XLATE = {
        RTE_FLOW_ITEM_TYPE_SWITCH_PORT,
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


/*
 * Convert the mac address to little endian for flow programming
 */
static void
ntoh_mac(struct eth_addr *src, struct eth_addr *dst)
{
    int i;
    for (i = 0; i < 6; i++) {
        dst->ea[6 - i - 1] = src->ea[i];
    }
}

static enum xlate_status
do_inport_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                                          const void *md)
{
    struct flow *flow;
    struct rte_flow_item_port *port_flow_item;
    struct rte_flow_item_port *port_flow_item_mask;
    struct netdev *netdev;
    uint16_t dpdk_portno;
    struct offload_info *ofld_info = (struct offload_info *)md;

    flow = &match->flow;
    port_flow_item = xzalloc (sizeof *port_flow_item);
    port_flow_item_mask = xzalloc(sizeof *port_flow_item_mask);
    if(!port_flow_item) {
        VLOG_ERR("Failed to allocate the memory for hardware flow item");
        return FLOW_XLATE_FAILED;
    }

    netdev = get_hw_netdev(flow->in_port.odp_port, ofld_info->port_hmap_obj);
    if (!netdev) {
        VLOG_WARN("Inport %u is not a valid hardware accelerated port.",
                    odp_to_u32(flow->in_port.odp_port));
        return FLOW_XLATE_FAILED;
    }
    /* The inport should be the dpdk port number, not the ovs portno */
    dpdk_portno = netdev_get_dpdk_portno(netdev);
    port_flow_item->index = dpdk_portno;


    /* Set the mask for the rte port flow */
    port_flow_item_mask->index = 0xFFFFFFFF;
    rte_flow_item_push(batch, port_flow_item, port_flow_item_mask,
                              PORT_FLOW_XLATE.rte_flow_type);
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_l2_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                                      const void *md)
{
    struct flow *flow, *mask;
    struct rte_flow_item_eth *eth_flow_item;
    struct rte_flow_item_eth *eth_flow_mask;
    struct eth_addr mac_le;
    flow = &match->flow;
    mask = &match->wc.masks;
    bool is_l2_zero  = 0;
    is_l2_zero = eth_addr_is_zero(flow->dl_dst);
    is_l2_zero &= eth_addr_is_zero(flow->dl_src);
    if(is_l2_zero) {
        VLOG_INFO("Cannot install flow with zero eth addr");
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
    eth_flow_item->type = ntohs(flow->dl_type);

    /* Copy the address mask too */
    memcpy(&eth_flow_mask->dst, &mask->dl_dst, sizeof(eth_flow_mask->dst));
    memcpy(&eth_flow_mask->src, &mask->dl_src, sizeof(eth_flow_mask->src));
    eth_flow_mask->type = ntohs(mask->dl_type);

    rte_flow_item_push(batch, eth_flow_item, eth_flow_mask,
                       L2_FLOW_XLATE.rte_flow_type);
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_l2_vlan_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                      const void *md)
{
    struct flow *flow, *mask;
    flow = &match->flow;
    mask = &match->wc.masks;
    if (flow->vlan_tci & htons(VLAN_CFI)) {
        VLOG_INFO("Adding the VLAN flow");
        /* VLAN tag is present in packet */
        struct rte_flow_item_vlan *vlan_flow_item;
        struct rte_flow_item_vlan *vlan_flow_mask;
        vlan_flow_item = xzalloc(sizeof *vlan_flow_item);
        vlan_flow_mask = xzalloc(sizeof *vlan_flow_mask);
        vlan_flow_item->tpid = ETH_TYPE_VLAN;
        vlan_flow_item->tci = ntohs(flow->vlan_tci);
        vlan_flow_mask->tpid = 0xFFFF;
        vlan_flow_mask->tci = ntohs(mask->vlan_tci);
        rte_flow_item_push(batch, vlan_flow_item, vlan_flow_mask,
                           L2_VLAN_FLOW_XLATE.rte_flow_type);
        return FLOW_XLATE_SUCCESS;
    }
    else {
        return FLOW_XLATE_NOT_NEEDED;
    }
}

static enum xlate_status
do_l3_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                 const void *md)
{
    struct flow *flow, *mask;

    flow = &match->flow;
    mask = &match->wc.masks;

    if(flow->dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *ipv4_flow_item, *ipv4_flow_mask;

        VLOG_INFO("IP header flow.");
        ipv4_flow_item = xzalloc(sizeof *ipv4_flow_item);
        ipv4_flow_mask = xzalloc(sizeof *ipv4_flow_mask);

        /* Xlate the ip flow entries */
        ipv4_flow_item->hdr.src_addr = ntohl(flow->nw_src);
        ipv4_flow_item->hdr.dst_addr = ntohl(flow->nw_dst);
        ipv4_flow_item->hdr.next_proto_id = flow->nw_proto;
        ipv4_flow_item->hdr.type_of_service = flow->nw_tos;
        ipv4_flow_item->hdr.version_ihl = 4;

        /* Xlate ipv4 mask entries */
        ipv4_flow_mask->hdr.src_addr = ntohl(mask->nw_src);
        ipv4_flow_mask->hdr.dst_addr = ntohl(mask->nw_dst);
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
            VLOG_INFO("MPLS flow");
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
    }
    else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        VLOG_INFO("Ipv6 flow");
        struct rte_flow_item_ipv6 *ipv6_flow_item, *ipv6_flow_mask;
        ipv6_flow_item = xzalloc(sizeof *ipv6_flow_item);
        ipv6_flow_mask = xzalloc(sizeof *ipv6_flow_mask);
        memcpy(&ipv6_flow_item->hdr.src_addr, &flow->ipv6_src,
               sizeof ipv6_flow_item->hdr.src_addr);
        memcpy(&ipv6_flow_item->hdr.dst_addr, &flow->ipv6_dst,
               sizeof ipv6_flow_item->hdr.dst_addr);
        ipv6_flow_item->hdr.proto = flow->nw_proto;
        ipv6_flow_item->hdr.vtc_flow = htonl(6 << 28) |
                                   htonl(flow->nw_tos << 20) |
                                   flow->ipv6_label;
        ipv6_flow_item->hdr.vtc_flow = ntohl(ipv6_flow_item->hdr.vtc_flow);
        memcpy(&ipv6_flow_mask->hdr.src_addr, &mask->ipv6_src,
               sizeof ipv6_flow_mask->hdr.src_addr);
        memcpy(&ipv6_flow_mask->hdr.dst_addr, &mask->ipv6_dst,
               sizeof ipv6_flow_mask->hdr.dst_addr);
        ipv6_flow_mask->hdr.proto =mask->nw_proto;
        ipv6_flow_mask->hdr.vtc_flow = htonl(6 << 28) |
                                   htonl(flow->nw_tos << 20) |
                                   mask->ipv6_label;
        ipv6_flow_mask->hdr.vtc_flow = ntohl(ipv6_flow_mask->hdr.vtc_flow);
        rte_flow_item_push(batch, ipv6_flow_item, ipv6_flow_mask,
                           RTE_FLOW_ITEM_TYPE_IPV6);
    }
    else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
             flow->dl_type == htons(ETH_TYPE_RARP))
    {
        struct rte_flow_item_arp_ipv4 *arp_flow, *arp_mask;
        arp_flow  = xzalloc(sizeof *arp_flow);
        arp_mask = xzalloc(sizeof *arp_mask);
        arp_flow->hdr.arp_hrd = 1;
        arp_flow->hdr.arp_pro =  ETH_TYPE_IP;
        arp_flow->hdr.arp_hln = ETH_ADDR_LEN;
        arp_flow->hdr.arp_pln = 4;
        arp_flow->hdr.arp_op = flow->nw_proto;
        /* Masks for ARP */
        arp_mask->hdr.arp_hrd = 0xFF;
        arp_mask->hdr.arp_pro = 0xFF;
        arp_mask->hdr.arp_hln = 0xF;
        arp_mask->hdr.arp_pln = 0xF;
        arp_mask->hdr.arp_op = 0xFF;
        if (flow->nw_proto == ARP_OP_REQUEST ||
            flow->nw_proto == ARP_OP_REPLY) {
            arp_flow->hdr.arp_data.arp_sip = ntohl(flow->nw_src);
            arp_flow->hdr.arp_data.arp_tip = ntohl(flow->nw_dst);
            memcpy(&arp_flow->hdr.arp_data.arp_sha, &flow->arp_sha,
                   sizeof arp_flow->hdr.arp_data.arp_sha);
            memcpy(&arp_flow->hdr.arp_data.arp_tha, &flow->arp_tha,
                   sizeof arp_flow->hdr.arp_data.arp_tha);
            /*Mask for arp header fields */
            arp_mask->hdr.arp_data.arp_sip = ntohl(mask->nw_src);
            arp_mask->hdr.arp_data.arp_tip = ntohl(mask->nw_dst);
            memcpy(&arp_mask->hdr.arp_data.arp_sha, &mask->arp_sha,
                   sizeof arp_mask->hdr.arp_data.arp_sha);
            memcpy(&arp_mask->hdr.arp_data.arp_tha, &mask->arp_tha,
                   sizeof arp_mask->hdr.arp_data.arp_tha);
        }
        rte_flow_item_push(batch, arp_flow, arp_mask,
                           RTE_FLOW_ITEM_TYPE_ARP_IPV4);
        return FLOW_XLATE_LAST;
    }
    else {
      VLOG_INFO("Not a ARP/IP/IPv6/MPLS flow, %d, "
                "could be a L2 only flow ", ntohs(flow->dl_type));
      return FLOW_XLATE_FAILED;
    }
    return FLOW_XLATE_SUCCESS;

}

static enum xlate_status
do_l4_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                 const void *md)
{
    struct flow *flow, *mask;

    flow = &match->flow;
    mask = &match->wc.masks;

    if(flow->nw_proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *tcp_flow_item, *tcp_flow_mask;
        tcp_flow_item = xzalloc(sizeof *tcp_flow_item);
        tcp_flow_mask = xzalloc(sizeof *tcp_flow_mask);

        /* Xlate tcp flow entries */
        tcp_flow_item->hdr.src_port = ntohs(flow->tp_src);
        tcp_flow_item->hdr.dst_port = ntohs(flow->tp_dst);

        /* Xlate tcp flow mask entries */
        tcp_flow_mask->hdr.src_port = ntohs(mask->tp_src);
        tcp_flow_mask->hdr.dst_port = ntohs(mask->tp_dst);
        rte_flow_item_push(batch, tcp_flow_item, tcp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_TCP);
    }
    else if (flow->nw_proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *udp_flow_item, *udp_flow_mask;
        udp_flow_item = xzalloc(sizeof *udp_flow_item);
        udp_flow_mask = xzalloc(sizeof *udp_flow_mask);

        /* xlate UDP flow entries */
        udp_flow_item->hdr.src_port = ntohs(flow->tp_src);
        udp_flow_item->hdr.dst_port = ntohs(flow->tp_dst);

        /* Xlate UDP mask entries */
        udp_flow_mask->hdr.src_port = ntohs(mask->tp_src);
        udp_flow_mask->hdr.dst_port = ntohs(mask->tp_dst);
        rte_flow_item_push(batch, udp_flow_item, udp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_UDP);
    }
    else if (flow->nw_proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *icmp_flow_item, *icmp_flow_mask;
        icmp_flow_item = xzalloc(sizeof *icmp_flow_item);
        icmp_flow_mask = xzalloc(sizeof *icmp_flow_mask);
        icmp_flow_item->hdr.icmp_type = ntohs(flow->tp_src);
        icmp_flow_item->hdr.icmp_code = ntohs(flow->tp_dst);
        icmp_flow_mask->hdr.icmp_type = ntohs(mask->tp_src);
        icmp_flow_mask->hdr.icmp_code = ntohs(mask->tp_dst);
        rte_flow_item_push(batch, icmp_flow_item, icmp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_ICMP);
    }
    else if(flow->nw_proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *sctp_flow_item, *sctp_flow_mask;
        sctp_flow_item = xzalloc(sizeof *sctp_flow_item);
        sctp_flow_mask = xzalloc(sizeof *sctp_flow_mask);
        sctp_flow_item->hdr.src_port = ntohs(flow->tp_src);
        sctp_flow_item->hdr.dst_port = ntohs(flow->tp_dst);
        sctp_flow_mask->hdr.src_port = ntohs(mask->tp_src);
        sctp_flow_mask->hdr.dst_port = ntohs(mask->tp_dst);
        rte_flow_item_push(batch, sctp_flow_item, sctp_flow_mask,
                           RTE_FLOW_ITEM_TYPE_SCTP);
    }
    else if(flow->nw_proto == IPPROTO_ICMPV6) {
        struct rte_flow_item_icmpv6 *icmpv6_flow_item, *icmpv6_flow_mask;
        icmpv6_flow_item = xzalloc(sizeof *icmpv6_flow_item);
        icmpv6_flow_mask = xzalloc(sizeof *icmpv6_flow_mask);
        icmpv6_flow_item->type = ntohs(flow->tp_src);
        icmpv6_flow_item->code = ntohs(flow->tp_dst);
        icmpv6_flow_mask->type = ntohs(mask->tp_src);
        icmpv6_flow_mask->code = ntohs(mask->tp_dst);
        rte_flow_item_push(batch, icmpv6_flow_item, icmpv6_flow_mask,
                           RTE_FLOW_ITEM_TYPE_ICMPV6);
        if (icmpv6_flow_item->type == ND_NEIGHBOR_SOLICIT ||
            icmpv6_flow_item->type == ND_NEIGHBOR_ADVERT) {
            /* Need to populate ND entries if present. */
            struct rte_flow_item_icmpv6_tgt_addr *icmpv6_tgt, *icmpv6_tgt_mask;
            icmpv6_tgt =  xzalloc(sizeof *icmpv6_tgt);
            icmpv6_tgt_mask = xzalloc(sizeof *icmpv6_tgt_mask);
            memcpy(&icmpv6_tgt->addr, &flow->nd_target,
                                      sizeof icmpv6_tgt->addr);
            memcpy(&icmpv6_tgt_mask->addr, &mask->nd_target,
                                      sizeof icmpv6_tgt_mask->addr);
            rte_flow_item_push(batch, icmpv6_tgt, icmpv6_tgt_mask,
                               RTE_FLOW_ITEM_TYPE_ICMPV6_TGT_ADDR);
            if (!eth_addr_is_zero(flow->arp_sha)) {
                struct rte_flow_item_icmpv6_sll *icmpv6_sll_flow,
                                                *icmpv6_sll_mask;
                icmpv6_sll_flow = xzalloc(sizeof *icmpv6_sll_flow);
                icmpv6_sll_mask = xzalloc(sizeof *icmpv6_sll_mask);
                memcpy(&icmpv6_sll_flow->addr, &flow->arp_sha,
                       sizeof icmpv6_sll_flow->addr);
                memcpy(&icmpv6_sll_mask->addr, &mask->arp_sha,
                       sizeof icmpv6_sll_mask->addr);
                rte_flow_item_push(batch, &icmpv6_sll_flow, icmpv6_sll_mask,
                                   RTE_FLOW_ITEM_TYPE_ICMPV6_SLL);
            }
            if (!eth_addr_is_zero(flow->arp_tha)) {
                struct rte_flow_item_icmpv6_tll *icmpv6_tll_flow,
                                                *icmpv6_tll_mask;
                icmpv6_tll_flow = xzalloc(sizeof *icmpv6_tll_flow);
                icmpv6_tll_mask = xzalloc(sizeof *icmpv6_tll_mask);
                memcpy(&icmpv6_tll_flow->addr, &flow->arp_tha,
                       sizeof icmpv6_tll_flow->addr);
                mempcpy(&icmpv6_tll_mask->addr, &mask->arp_tha,
                        sizeof icmpv6_tll_mask->addr);
                rte_flow_item_push(batch, icmpv6_tll_flow, icmpv6_tll_mask,
                                   RTE_FLOW_ITEM_TYPE_ICMPV6_TLL);
            }
        }
    }
    else {
        VLOG_INFO("Not a TCP/UDP/ICMP/SCTP/ICMPv6 flow, Can be a L3 only"
                  " flow");
        return FLOW_XLATE_FAILED;
    }
    return FLOW_XLATE_SUCCESS;
}

static enum xlate_status
do_end_flow_xlate(struct match *match, struct rte_flow_batch *batch,
                                       const void *md)
{
    rte_flow_item_push(batch, NULL, NULL, RTE_FLOW_ITEM_TYPE_END);
    return FLOW_XLATE_SUCCESS;
}

static int
do_flow_xlate_helper(struct flow_xlate_dic xlate_dic_entry,
                      struct match *match,
                      struct rte_flow_batch *batch,
                      const void *md)
{
    return xlate_dic_entry.flow_xlate(match, batch, md);

}

#define DO_FLOW_XLATE(XLATE_DIC_ENTRY, MATCH_ENTRY, FLOW_BATCH, MD_PTR) \
    do_flow_xlate_helper(XLATE_DIC_ENTRY, MATCH_ENTRY, FLOW_BATCH, \
                                                       MD_PTR)

static int
dpdkhw_rte_flow_xlate(struct match *match,
                          struct rte_flow_attr *hw_flow_attr,
                          struct rte_flow_batch *batch,
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
    if (!eth_addr_is_zero(key->eth_src)) {
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
    }
}

static void
dpdkhw_rte_ipv4_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv4 *ipv4_key;
    ipv4_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv4));
    if (ipv4_key->ipv4_src) {
        struct rte_flow_action_ipv4_addr_set *ipv4_src_addr_action =
                            xmalloc(sizeof *ipv4_src_addr_action);
        ipv4_src_addr_action->addr = ntohl(ipv4_key->ipv4_src);
        ipv4_src_addr_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_SRC_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_src_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_dst) {
        struct rte_flow_action_ipv4_addr_set *ipv4_dst_addr_action =
                            xmalloc(sizeof *ipv4_dst_addr_action);
        ipv4_dst_addr_action->layer = 0;
        ipv4_dst_addr_action->addr = ntohl(ipv4_key->ipv4_dst);
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_IPV4_DST_ADDR_SET;
        hw_action_batch[*idx].conf = ipv4_dst_addr_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_ttl) {
        struct rte_flow_action_ttl_set *ipv4_ttl_action =
                         xmalloc(sizeof *ipv4_ttl_action);
        ipv4_ttl_action->ttl = ipv4_key->ipv4_ttl;
        ipv4_ttl_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_TTL_SET;
        hw_action_batch[*idx].conf = ipv4_ttl_action;
        (*idx)++;
    }
    if (ipv4_key->ipv4_tos) {
        struct rte_flow_action_dscp_ecn_set *ipv4_tos_action =
                         xmalloc(sizeof *ipv4_tos_action);
        ipv4_tos_action->dscp_ecn = ipv4_key->ipv4_tos;
        ipv4_tos_action->mask = 0xFF;
        ipv4_tos_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DSCP_ECN_SET;
        hw_action_batch[*idx].conf = ipv4_tos_action;
        (*idx)++;
    }
}

static void
dpdkhw_rte_ipv6_set_action(const struct nlattr *a,
                           struct rte_flow_action hw_action_batch[],
                           int *const idx)
{
    const struct ovs_key_ipv6 *ipv6_key;
    ipv6_key = nl_attr_get_unspec(a, sizeof(struct ovs_key_ipv6));
    /* rte flow can only set src and dst ipv6 address */
    if (ipv6_addr_is_set(&ipv6_key->ipv6_src)) {
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
}

static void
dpdkhw_rte_l4_set_action(ovs_be16 src_port, ovs_be16 dst_port,
                         struct rte_flow_action hw_action_batch[],
                         int *const idx)
{
    if (src_port) {
        struct rte_flow_action_pt_num_set *l4_src_action =
                            xmalloc(sizeof *l4_src_action);
        l4_src_action->pt_num = ntohs(src_port);
        l4_src_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_SRC_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_src_action;
        (*idx)++;
    }
    if (dst_port) {
        struct rte_flow_action_pt_num_set *l4_dst_action =
                             xmalloc(sizeof *l4_dst_action);
        l4_dst_action->pt_num = ntohs(dst_port);
        l4_dst_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_DST_PT_NUM_SET;
        hw_action_batch[*idx].conf = l4_dst_action;
        (*idx)++;
    }
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
        const struct ovs_key_icmp *icmp_key =
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
        }
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
        /* Set the 12 bit VID */
        struct rte_flow_action_vlan_set *vlan_action =
                xmalloc(sizeof *vlan_action);
        vlan_action->tag = nl_attr_get_u16(a);
        vlan_action->mask = RTE_FLOW_ACTION_MASK_VLAN_VID;
        vlan_action->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_VLAN_SET;
        hw_action_batch[*idx].conf = vlan_action;
        (*idx)++;
        /* Set the User priority */
        struct rte_flow_action_vlan_set *vlan_action_pri =
                xmalloc(sizeof *vlan_action_pri);
        vlan_action_pri->tag = vlan_action->tag;
        vlan_action_pri->mask = RTE_FLOW_ACTION_MASK_VLAN_PRI;
        vlan_action_pri->layer = 0;
        hw_action_batch[*idx].type = RTE_FLOW_ACTION_TYPE_VLAN_SET;
        hw_action_batch[*idx].conf = vlan_action_pri;
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
        VLOG_INFO_RL(&rl, "No actions to offload, Install drop action");
        hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_DROP;
        hw_action_batch[i].conf = NULL;
        return ret;
    }
    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        if(i >= max_action_entry) {
            VLOG_ERR("Max action entry limit reached, cannot add more actions");
            return EPERM;
        }
        switch ((enum ovs_action_attr) type) {
        case OVS_ACTION_ATTR_OUTPUT: {
            /*
             * Current POC only supports the output action to a port.
             */
            struct rte_flow_action_switch_port *rte_action_port =
                    xmalloc(sizeof *rte_action_port);
            odp_port_t out_port = nl_attr_get_odp_port(a);
            /* Output port should be hardware port number. */
            struct netdev *netdev = get_hw_netdev(out_port,
                                                  ofld_info->port_hmap_obj);
            if (!netdev) {
                VLOG_WARN("Cannot offload a flow with non accelerated output"
                          " port %u", odp_to_u32(out_port));
                return EPERM;
            }

            uint16_t dpdk_portno = netdev_get_dpdk_portno(netdev);
            rte_action_port->index = dpdk_portno;

            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_SWITCH_PORT;
            hw_action_batch[i].conf = rte_action_port;
            i++;
            break;
        }
        case OVS_ACTION_ATTR_PUSH_VLAN: {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
            struct rte_flow_action_vlan_push *vlan_action =
                            xmalloc(sizeof *vlan_action);
            vlan_action->tpid = ntohs(vlan->vlan_tpid);
            vlan_action->tag = ntohs(vlan->vlan_tci) & ~VLAN_CFI;
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_VLAN_PUSH;
            hw_action_batch[i].conf = vlan_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN: {
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_VLAN_POP;
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
            const struct ovs_action_push_mpls *mpls = nl_attr_get(a);
            struct rte_flow_action_mpls_push *mpls_push_action =
                        xmalloc(sizeof *mpls_push_action);
            mpls_push_action->tpid = mpls->mpls_ethertype;
            mpls_push_action->hdr = mpls->mpls_lse;
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_PUSH;
            hw_action_batch[i].conf = mpls_push_action;
            i++;
            break;
        }

        case OVS_ACTION_ATTR_POP_MPLS: {
            hw_action_batch[i].type = RTE_FLOW_ACTION_TYPE_MPLS_POP;
            hw_action_batch[i].conf = NULL;
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
            VLOG_INFO_RL(&rl, "TODO actions %u", type);
            ret = -EINVAL;
            break;
        default:
            VLOG_INFO_RL(&rl, "Unsupported action to offload");
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

const struct dpdkhw_switch_fns dpdkhw_full_em_switch_fns = {
    is_flow_ofld_on_full_em_switch_supported,
    dpdkhw_rte_flow_xlate,
    dpdkhw_em_action_xlate,
    install_ovs_flow_in_hw,
    delete_ovs_flow_in_hw
};
