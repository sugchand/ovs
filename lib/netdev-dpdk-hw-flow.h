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

/* The array of rte_flow_item to program a flow with different header fields
 * into the hardware
 */
struct dpdk_flow_batch {
    /* Array of rte_flow_item */
    struct rte_flow_item *flow_batch;
    uint32_t used;
    uint32_t max_size;
};

void init_dpdk_flow_batch(struct dpdk_flow_batch *batch,
                    struct rte_flow_item rte_flow_start[],
                    uint32_t batch_size);
struct dpdkhw_switch *get_hw_switch(uint16_t dev_id);

bool is_dpdkhw_port(const struct netdev *netdev);
uint16_t netdev_get_dpdk_portno(struct netdev *netdev);
struct netdev *get_hw_netdev(odp_port_t port_no,
                             const struct dpif_class *dpif_class);

#endif /* LIB_NETDEV_DPDK_HW_H_ */
