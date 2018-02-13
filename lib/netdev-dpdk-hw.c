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
