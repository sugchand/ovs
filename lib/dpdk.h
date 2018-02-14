/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef DPDK_H
#define DPDK_H

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_lcore.h>
#include "openvswitch/list.h"

#define NON_PMD_CORE_ID LCORE_ID_ANY
#define NUMA_NODE_0     0
#define NUMA_NODE_1     1
#define SOCKET0         0
#define SOCKET1         1
#define NIC_PORT_RX_Q_SIZE 2048  /* Size of Physical NIC RX Queue, Max (n+32<=4096)*/
#define NIC_PORT_TX_Q_SIZE 2048  /* Size of Physical NIC TX Queue, Max (n+32<=4096)*/

struct dpdk_mp {
    struct rte_mempool *mp;
    int mtu;
    int socket_id;
    int refcount;
    struct ovs_list list_node OVS_GUARDED_BY(dpdk_mutex);
};

struct dpdk_mp *dpdk_mp_get_ext(int socket_id, int mtu);
void dpdk_mp_put_ext(struct dpdk_mp *dmp);

uint32_t dpdk_buf_size(int mtu);
uint32_t dpdk_framelen_to_mtu(uint32_t buf_size);

struct smap;
void setup_vhost_dir(char *input, const struct smap *ovs_other_config,
                     char **new_dir);

#else

#define NON_PMD_CORE_ID UINT32_MAX

#endif /* DPDK_NETDEV */

struct smap;

void dpdk_init(const struct smap *ovs_other_config);
void dpdk_set_lcore_id(unsigned cpu);
const char *dpdk_get_vhost_sock_dir(void);

#endif /* dpdk.h */
