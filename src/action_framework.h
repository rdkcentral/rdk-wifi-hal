/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _ACTION_FRAMEWORK_H_
#define _ACTION_FRAMEWORK_H_

#if VAP_REINDEX
#define MIN_AP_INDEX 1
#define MAX_AP_INDEX 16
#else
#define MIN_AP_INDEX 0
#define MAX_AP_INDEX 15
#endif

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "collection.h"
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "wifi_hal.h"

struct rtnl_handle
{
    int         fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    __u32           seq;
    __u32           dump;
};

struct rtnl_kvr_handle
{
    int         fd;
    int         fd_ctrl;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    __u32           seq;
    __u32           dump;
};

#define MAX_REGISTERED_CB_NUM   4
#define MAX_DPP_ATTRIBS_SIZE       2048
#ifndef IFLA_WIRELESS
#define IFLA_WIRELESS   (IFLA_MASTER + 1)
#endif /* IFLA_WIRELESS */
#define IWEVTXDROP  0x8C00      /* Packet dropped to excessive retry */
#define IWEVQUAL    0x8C01      /* Quality part of statistics (scan) */
#define IWEVCUSTOM  0x8C02      /* Driver specific ascii string */
#define IWEVREGISTERED  0x8C03      /* Discovered a new node (AP mode) */
#define IWEVEXPIRED 0x8C04      /* Expired a node (AP mode) */
#define IWEVGENIE   0x8C05      /* Generic IE (WPA, RSN, WMM, ..) */

typedef enum {
    action_type_radio_measurement_request,
    action_type_radio_measurement_report,
    action_type_neighbor_report_request,
    action_type_neighbor_report_response,
    action_type_bss_transition_query,
    action_type_bss_transition_request,
    action_type_bss_transition_response,
    action_type_public_action_dpp_session,
} wifi_80211ActionType_t;

typedef enum {
    beacon,
    lci,
    sta_stats,
    channel_load
} wifi_MeasurementType_t;

typedef struct {
    wifi_BTMQueryRequest_callback   query_callback;
    wifi_BTMResponse_callback       response_callback;
} wifi_BTM_callbacks_t;

typedef struct {
    struct rtnl_handle  rtnl;
    struct rtnl_kvr_handle  rtnl_kvr;
    wifi_newApAssociatedDevice_callback assoc_cb[MAX_REGISTERED_CB_NUM];
    unsigned int    num_assoc_cbs;
    wifi_device_disassociated_callback disassoc_cb[MAX_REGISTERED_CB_NUM];
    unsigned int    num_disassoc_cbs;
    queue_t             *queue;
    wifi_RMBeaconReport_callback          bcnrpt_callback[MAX_AP_INDEX];
    wifi_BTM_callbacks_t    btm_callback[MAX_AP_INDEX];
    wifi_dppAuthResponse_callback_t     dpp_auth_rsp_callback;
    wifi_dppConfigRequest_callback_t    dpp_config_req_callback;
	wifi_dppConfigResult_callback_t		dpp_config_result_callback;
	wifi_dppReconfigAnnounce_callback_t	dpp_reconfig_announce_callback;
	wifi_dppReconfigAuthResponse_callback_t	dpp_reconfig_auth_rsp_callback;
    wifi_anqp_request_callback_t        anqp_req_callback;
    wifi_dppConfigResult_callback_t		dpp_config_result_callback;
    wifi_dppReconfigAnnounce_callback_t	dpp_reconfig_announce_callback;
    wifi_dppReconfigAuthResponse_callback_t	dpp_reconfig_auth_rsp_callback;
    pthread_mutex_t     lock;
    pthread_t notification_thread_id;
    bool            notification_framework_initialized;
    wifi_device_deauthenticated_callback      apDeAuthEvent_cb[MAX_REGISTERED_CB_NUM];
    unsigned int    num_apDeAuthEvent_cbs;
    wifi_receivedMgmtFrame_callback     mgmt_frame_rx_callback;
       wifi_received8021xFrame_callback        eapol_frame_rx_callback;
} wifi_device_callbacks_t;
#if 0
typedef struct {
    unsigned int    vap_sys_index;
    unsigned int    ap_index;
    wifi_80211ActionType_t  type;
    unsigned int    sub_type;
    unsigned char   token;
    struct timeval      create_time;
    mac_address_t       peer;
    unsigned int    num_results;
    unsigned int    num_repetitions;
    union {
        wifi_BeaconReport_t     bcnrpt[32];
        wifi_BTMResponse_t      btmrsp;
    } data;
} wifi_80211ActionRequestData_t;
#endif
typedef struct {
    unsigned int    vap_sys_index;
    unsigned int    ap_index;
    wifi_80211ActionType_t  type;
    unsigned int    sub_type;
    unsigned char   token;
    struct timeval      create_time;
    mac_address_t       peer;
    unsigned int    num_results;
    unsigned int    num_repetitions;
    union {
        wifi_BeaconReport_t     bcnrpt[32];
        wifi_BTMResponse_t      btmrsp;
    } result;
} wifi_80211ActionRequestData_t;
#endif //_ACTION_FRAMEWORK_H_


