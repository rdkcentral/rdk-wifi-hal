/***************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef SERVER_HAL_IPC_H
#define SERVER_HAL_IPC_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "hal_ipc_wifi_wrappers.h"

#define MAX_IPC_BUFF            10240
#define	MAX_HAL_IPC_PROTO_BUFF  50*MAX_IPC_BUFF

typedef enum {
    processor_type_ipc_client_input,
    processor_type_ipc_client_output,
    processor_type_ipc_server_output,
    processor_type_ipc_client_notification_input,
    processor_type_ipc_server_notification_output,
    processor_type_ipc_max
} hal_ipc_processor_type_t;

struct hal_ipc_processor_desc;

typedef int (*hal_ipc_processor_t)(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);

typedef enum {
    hal_ipc_node_type_notification_server,
    hal_ipc_node_type_notification_client,
    hal_ipc_node_type_sync_call_server,
    hal_ipc_node_type_sync_call_sm_client,
    hal_ipc_node_type_sync_call_bm_client,
    hal_ipc_node_type_max
} hal_ipc_node_type_t;

typedef enum {
    hal_ipc_desc_type_set_radio_stats_enable,               // INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enabled);
    hal_ipc_desc_type_get_ssid_num_of_entries,              // INT wifi_getSSIDNumberOfEntries(ULONG *numEntries);
    hal_ipc_desc_type_get_ap_assoc_dev_stats,               // INT wifi_getApAssociatedDeviceStats(INT apIndex, mac_address_t *clientMacAddress, wifi_associated_dev_stats_t *associated_dev_stats, ULLONG *handle);
    hal_ipc_desc_type_get_radio_chan_stats,                 // INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array, INT array_size);
    hal_ipc_desc_type_start_neighbor_scan,                  // INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list);
    hal_ipc_desc_type_get_neighbor_wifi_status,             // INT wifi_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
    hal_ipc_desc_type_get_ssid_traffic_stats2,              // INT wifi_getSSIDTrafficStats2(INT ssidIndex, wifi_ssidTrafficStats2_t *output_struct);
    hal_ipc_desc_type_get_ap_assoc_dev_rx_stats_result,     // INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle);
    hal_ipc_desc_type_get_ssid_enable,                      // INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool);
    hal_ipc_desc_type_get_ssid_radio_index,                 // INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex);
    hal_ipc_desc_type_get_ssid_name_status,                 // INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string);
    hal_ipc_desc_type_get_ap_name,                          // INT wifi_getApName(INT apIndex, CHAR *output_string);
    hal_ipc_desc_type_get_neighbor_report_activation,       // INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate);
    hal_ipc_desc_type_get_bss_transition_activation,        // INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate);
    hal_ipc_desc_type_get_ap_assoc_dev_diag_result3,        // INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size);
    hal_ipc_desc_type_get_ap_assoc_client_diag_result,      // INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn);
    hal_ipc_desc_type_get_radio_operating_freq_band,        // INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string);
    hal_ipc_desc_type_get_radio_num_of_entries,             // INT wifi_getRadioNumberOfEntries(ULONG *output);
    hal_ipc_desc_type_get_ap_assoc_dev_tx_stats_result,     // INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle);
    hal_ipc_desc_type_steering_set_group,                   // INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5);
    hal_ipc_desc_type_steering_client_set,                  // INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config);
    hal_ipc_desc_type_steering_client_remove,               // INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac);
    hal_ipc_desc_type_steering_client_disconnect,           // INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason);
    hal_ipc_desc_type_set_btm_request,                      // INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request);
    hal_ipc_desc_type_get_ssid_name,                        // INT wifi_getSSIDName(INT apIndex, CHAR *output_string);
    hal_ipc_desc_type_set_rm_beacon_request,                // INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken);
    hal_ipc_desc_type_get_association_req_ies,              // INT wifi_getAssociationReqIEs(UINT apIndex, const mac_address_t *clientMacAddress, CHAR *req_ies, UINT req_ies_size, UINT *req_ies_len);
    hal_ipc_desc_type_set_neighbor_reports,                 // INT wifi_setNeighborReports(UINT apIndex, UINT numNeighborReports, wifi_NeighborReport_t *neighborReports);
    hal_ipc_desc_type_set_neighbor_report_activation,       // INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate);
    hal_ipc_desc_type_get_radio_if_name,                    // INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string);
    hal_ipc_desc_type_get_ap_num_assoc_devs,                // INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong);

    hal_ipc_desc_type_steering_unregister,                  // INT wifi_steering_eventUnregister(void);
    hal_ipc_desc_type_steering_register,                    // INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb);
    hal_ipc_desc_type_steering_event,                       // notify about steering event
    hal_ipc_desc_type_mgmt_frame_callback_register,         // INT wifi_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback mgmtRxCallback);
    hal_ipc_desc_type_mgmt_frame_event,                     // notify about mgmt frame event
    hal_ipc_rm_beacon_request_register,                     // INT wifi_RMBeaconRequestCallbackRegister(unsigned int apIndex, wifi_RMBeaconReport_callback cb_fn)
    hal_ipc_rm_beacon_report_event,                         // notify about RM beacon report event
    hal_ipc_btm_query_request_register,                     // INT wifi_BTMQueryRequest_callback_register(unsigned int apIndex, wifi_BTMQueryRequest_callback btmQueryCallback, wifi_BTMResponse_callback btmResponseCallback)
    hal_ipc_btm_query_request_event,                        // notify about BTM query request event
    hal_ipc_btm_response_event,                             // notify about BTM response event
    hal_ipc_desc_type_max
} hal_ipc_desc_type_t;

#define HAL_IPC_RADIO_CHANNELS_MAX          64
#define HAL_IPC_MAX_STA_SUPPORT_NUM         16  //64  // OneWifi monitor.h #define MAX_ASSOCIATED_WIFI_DEVS    64

#define HAL_IPC_MAX_NEIGHBOR_AP_COUNT       16
#define HAL_IPC_MAX_STATS_ARRAY_NUM         HAL_IPC_MAX_STA_SUPPORT_NUM
#define HAL_IPC_MAX_STRING_LEN              64

#define HAL_IPC_MAC_ADDR_SIZE_BYTES         6
#define HAL_IPC_ASSOC_REQ_IES_BUF_SIZE      1024 // Magic number hardcoded in bsal.c function target_bsal_client_info
#define HAL_IPC_ACL_DEVS_LIST_STRING_LEN    512

#define HAL_IPC_DESCRIPTOR_NAME_LEN 128

#pragma pack(1)
typedef struct hal_ipc_processor_desc {
    hal_ipc_desc_type_t type;
    char                name[HAL_IPC_DESCRIPTOR_NAME_LEN];
    hal_ipc_processor_t ipc_processor[processor_type_ipc_max];
    unsigned int        len;
    int                 ret;
    union {
        int init_data;
        //----------------------------------------------------------------------
        // wifi_setRadioStatsEnable
        struct {
            INT radio_index;
            BOOL enabled;
        } set_radio_stats_enable;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceStats
        struct {
            INT ap_index;
            mac_address_t client_mac_addr;
        } get_ap_assoc_dev_stats;
        //----------------------------------------------------------------------
        // wifi_getRadioChannelStats
        struct {
            INT radio_index;
            wifi_channelStats_t input_output_channel_stats_array[0];            // HAL_IPC_RADIO_CHANNELS_MAX
            INT array_size;
        } get_radio_channel_stats;
        //----------------------------------------------------------------------
        // wifi_startNeighborScan
        struct {
            INT ap_index;
            wifi_neighborScanMode_t scan_mode;
            INT dwell_time;
            UINT chan_num;
        } start_neighbor_scan;
        //----------------------------------------------------------------------
        // wifi_getNeighboringWiFiStatus
        struct {
            INT radio_index;
        } get_neighbor_wifi_status;
        //----------------------------------------------------------------------
        // wifi_getSSIDTrafficStats2
        struct {
            INT ssid_index;
        } get_ssid_traffic_stats2;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceRxStatsResult
        struct {
            INT radio_index;
            mac_address_t client_mac_addr;
        } get_ap_assoc_dev_rx_stats_result;
        //----------------------------------------------------------------------
        // wifi_getSSIDEnable
        struct {
            INT ssid_index;
        } get_ssid_enable;
        //----------------------------------------------------------------------
        // wifi_getSSIDRadioIndex
        struct {
            INT ssid_index;
        } get_ssid_radio_index;
        //----------------------------------------------------------------------
        // wifi_getSSIDNameStatus
        struct {
            INT ap_index;
        } get_ssid_name_status;
        //----------------------------------------------------------------------
        // wifi_getApName
        struct {
            INT ap_index;
        } get_ap_name;
        //----------------------------------------------------------------------
        // wifi_getNeighborReportActivation
        struct {
            UINT ap_index;
        } get_neighbor_report_activation;
        //----------------------------------------------------------------------
        // wifi_getBSSTransitionActivation
        struct {
            UINT ap_index;
        } get_bss_transition_activation;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceDiagnosticResult3
        struct {
            UINT ap_index;
        } get_ap_assoc_dev_diag_result3;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedClientDiagnosticResult
        struct {
            INT ap_index;
            char mac_addr[HAL_IPC_MAC_ADDR_SIZE_BYTES];
        } get_ap_assoc_client_diag_result;
        //----------------------------------------------------------------------
        // wifi_getRadioOperatingFrequencyBand
        struct {
                INT radio_index;
        } get_radio_operating_freq_band;
        //----------------------------------------------------------------------
        // steering event data
        struct {
            unsigned int steering_group_index;
            wifi_steering_event_t evt;
        } steering_event_data;
        //----------------------------------------------------------------------
        // mgmt frame event data
        struct {
            INT apIndex;
            UCHAR sta_mac[HAL_IPC_MAC_ADDR_SIZE_BYTES];
            UCHAR frame[0];
            UINT len;
            wifi_mgmtFrameType_t type;
            wifi_direction_t dir;
        } mgmt_frame_event_data;
        //----------------------------------------------------------------------
        // RM beacon report event data
        // wifi_RMBeaconReport_callback parameters
        struct {
            UINT                apIndex;
            wifi_BeaconReport_t out_struct[0];
            UINT                out_array_size;
            UCHAR               out_DialogToken;
        } rm_beacon_report_event_data;
        //----------------------------------------------------------------------
        // BTM query request event data
        struct {
            UINT                apIndex;
            mac_address_t       peerMac;
            wifi_BTMQuery_t     query[0];
            UINT                inMemSize;
            wifi_BTMRequest_t   request[0];
        } btm_query_request_event_data;
        //----------------------------------------------------------------------
        // BTM response event data
        struct {
            UINT                apIndex;
            mac_address_t       peerMac;
            wifi_BTMResponse_t  response;
        } btm_response_event_data;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceTxStatsResult
        struct {
            INT radio_index;
            mac_address_t client_mac_addr;
        } get_ap_assoc_dev_tx_stats_result;
        //----------------------------------------------------------------------
        // wifi_steering_setGroup
        struct {
            UINT steering_group_index;
            wifi_steering_apConfig_t cfg_2;
            wifi_steering_apConfig_t cfg_5;
        } set_steering_group;
        //----------------------------------------------------------------------
        // wifi_steering_clientSet
        struct {
            UINT steering_group_index;
            INT ap_index;
            mac_address_t client_mac;
            wifi_steering_clientConfig_t config;
        } set_steering_client;
        //----------------------------------------------------------------------
        // wifi_steering_clientRemove
        struct {
            UINT steering_group_index;
            INT ap_index;
            mac_address_t client_mac;
        } remove_steering_client;
        //----------------------------------------------------------------------
        // wifi_steering_clientDisconnect
        struct {
            UINT steering_group_index;
            INT ap_index;
            mac_address_t client_mac;
            wifi_disconnectType_t type;
            UINT reason;
        } disconnect_steering_client;
        //----------------------------------------------------------------------
        // wifi_setBTMRequest
        struct {
            UINT ap_index;
            mac_address_t peer_mac;
            wifi_BTMRequest_t request;
        } set_btm_request;
        //----------------------------------------------------------------------
        // wifi_getSSIDName
        struct {
            INT ap_index;
        } get_ssid_name;
        //----------------------------------------------------------------------
        // wifi_setRMBeaconRequest
        struct {
            UINT ap_index;
            mac_address_t peer_mac;
            wifi_BeaconRequest_t in_request;
        } set_rm_beacon_request;
        //----------------------------------------------------------------------
        // wifi_getAssociationReqIEs
        struct {
            UINT ap_index;
            mac_address_t client_mac_addr;
            UINT req_ies_size;
        } get_association_req_ies;
        //----------------------------------------------------------------------
        // wifi_setNeighborReports
        struct {
            UINT ap_index;
            UINT num_neighbor_reports;
            wifi_NeighborReport_t neighbor_reports[0];                          // HAL_IPC_MAX_NEIGHBOR_AP_COUNT
        } set_neighbor_reports;
        //----------------------------------------------------------------------
        // wifi_setNeighborReportActivation
        struct {
            UINT ap_index;
            BOOL activate;
        } set_neighbor_report_activation;
        //----------------------------------------------------------------------
        // wifi_getRadioIfName
        struct {
            INT radio_index;
        } get_radio_if_name;
        //----------------------------------------------------------------------
        // wifi_getApNumDevicesAssociated
        struct {
            INT ap_index;
        } get_ap_num_assoc_devs;
        //----------------------------------------------------------------------
        // ****** end of "in" union ******
    } in;

    union {
        int init_data;
        //----------------------------------------------------------------------
        // wifi_getSSIDNumberOfEntries
        struct {
            ULONG numEntries;
        } get_ssid_num_entries;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceStats
        struct {
            wifi_associated_dev_stats_t associated_dev_stats;
            ULLONG handle;                                                      // assoc_count
        } get_ap_assoc_dev_stats;
        //----------------------------------------------------------------------
        // wifi_getRadioChannelStats
        struct {
            wifi_channelStats_t input_output_channel_stats_array[0];            // HAL_IPC_RADIO_CHANNELS_MAX
        } get_radio_channel_stats;
        //----------------------------------------------------------------------
        // wifi_startNeighborScan
        struct {
            UINT chan_list;
        } start_neighbor_scan;
        //----------------------------------------------------------------------
        // wifi_getNeighboringWiFiStatus
        struct {
            wifi_neighbor_ap2_t neighbor_ap_array[0];                           // HAL_IPC_MAX_NEIGHBOR_AP_COUNT
            UINT output_array_size;
        } get_neighbor_wifi_status;
        //----------------------------------------------------------------------
        // wifi_getSSIDTrafficStats2
        struct {
            wifi_ssidTrafficStats2_t output_struct;
        } get_ssid_traffic_stats2;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceRxStatsResult
        struct {
            wifi_associated_dev_rate_info_rx_stats_t stats_array[0];            // HAL_IPC_MAX_STATS_ARRAY_NUM
            UINT output_array_size;
            ULLONG handle;
        } get_ap_assoc_dev_rx_stats_result;
        //----------------------------------------------------------------------
        // wifi_getSSIDEnable
        struct {
            BOOL output_bool;
        } get_ssid_enable;
        //----------------------------------------------------------------------
        // wifi_getSSIDRadioIndex
        struct {
            INT radio_index;
        } get_ssid_radio_index;
        //----------------------------------------------------------------------
        // wifi_getSSIDNameStatus
        struct {
            CHAR output_string[HAL_IPC_MAX_STRING_LEN];
        } get_ssid_name_status;
        //----------------------------------------------------------------------
        // wifi_getApName
        struct {
            CHAR output_string[HAL_IPC_MAX_STRING_LEN];
        } get_ap_name;
        //----------------------------------------------------------------------
        // wifi_getNeighborReportActivation
        struct {
            BOOL activate;
        } get_neighbor_report_activation;
        //----------------------------------------------------------------------
        // wifi_getBSSTransitionActivation
        struct {
            BOOL activate;
        } get_bss_transition_activation;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceDiagnosticResult3
        struct {
            wifi_associated_dev3_t  dev[0];                                     // HAL_IPC_MAX_STA_SUPPORT_NUM
            unsigned int num;
        } get_ap_assoc_dev_diag_result3;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedClientDiagnosticResult
        struct {
            wifi_associated_dev3_t dev_conn;
        } get_ap_assoc_client_diag_result;
        //----------------------------------------------------------------------
        // wifi_getRadioOperatingFrequencyBand
        struct {
                CHAR output_string[HAL_IPC_MAX_STRING_LEN];
        } get_radio_operating_freq_band;
        //----------------------------------------------------------------------
        // wifi_getRadioNumberOfEntries
        struct {
            ULONG output;
        } get_radio_number_of_entries;
        //----------------------------------------------------------------------
        // wifi_getApAssociatedDeviceTxStatsResult
        struct {
            wifi_associated_dev_rate_info_tx_stats_t stats_array[0];            // HAL_IPC_MAX_STATS_ARRAY_NUM
            UINT output_array_size;
            ULLONG handle;
        } get_ap_assoc_dev_tx_stats_result;
        //----------------------------------------------------------------------
        // wifi_steering_setGroup
        struct {
            wifi_steering_apConfig_t cfg_2;
            wifi_steering_apConfig_t cfg_5;
        } set_steering_group;
        //----------------------------------------------------------------------
        // wifi_steering_clientSet
        struct {
            wifi_steering_clientConfig_t config;
        } set_steering_client;
        //----------------------------------------------------------------------
        // wifi_steering_clientRemove
        //struct {
        //          *** no return data except return code is expected ***
        //} remove_steering_client;
        //----------------------------------------------------------------------
        // wifi_steering_clientDisconnect
        //struct {
        //          *** no return data except return code is expected ***
        //} disconnect_steering_client;
        //----------------------------------------------------------------------
        // wifi_setBTMRequest
        //struct {
        //          *** no return data except return code is expected ***
        //} set_btm_request;
        //----------------------------------------------------------------------
        // wifi_getSSIDName
        struct {
            CHAR output_string[HAL_IPC_MAX_STRING_LEN];
        } get_ssid_name;
        //----------------------------------------------------------------------
        // wifi_setRMBeaconRequest
        struct {
            UCHAR dialog_token;
        } set_rm_beacon_request;
        //----------------------------------------------------------------------
        // wifi_getAssociationReqIEs
        struct {
            CHAR req_ies[HAL_IPC_ASSOC_REQ_IES_BUF_SIZE];
            UINT req_ies_len;
        } get_association_req_ies;
        //----------------------------------------------------------------------
        // wifi_setNeighborReports
        //struct {
        //          *** no return data except return code is expected ***
        //} set_neighbor_reports;
        //----------------------------------------------------------------------
        // wifi_setNeighborReportActivation
        //struct {
        //          *** no return data except return code is expected ***
        //} set_neighbor_report_activation;
        //----------------------------------------------------------------------
        // wifi_getRadioIfName
        struct {
            CHAR output_string[HAL_IPC_MAX_STRING_LEN];
        } get_radio_if_name;
        //----------------------------------------------------------------------
        // wifi_getApNumDevicesAssociated
        struct {
            ULONG output;
        } get_ap_num_assoc_devs;
        //----------------------------------------------------------------------
        // ****** end of "out" union ******
    } out;
    // internal use of descriptor to allocate big buffers
    unsigned char *scratch_buf;
    unsigned int scratch_buf_size;
} __attribute__((packed, aligned(1))) hal_ipc_processor_desc_t;

typedef struct {
    char                node_path[64];
    pthread_t           listener_tid;
    int                 srv_sock;
    struct sockaddr_un  srv_sockaddr;
    hal_ipc_node_type_t type;
} hal_ipc_node_t;

hal_ipc_node_t              *rdk_create_hal_ipc_node(hal_ipc_node_type_t type);
hal_ipc_processor_desc_t    *get_processor_desc(hal_ipc_desc_type_t type);
int                         rdk_hal_ipc_exec(hal_ipc_node_t *p_ipc_node, hal_ipc_processor_desc_t *arg);

int	ipc_server_output(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);
int ipc_client_notification_input(struct hal_ipc_processor_desc *desc, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);

void hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(app_get_ap_assoc_dev_diag_res3_t callback_get_ap_assoc_dev_diag_res3);
void hal_ipc_server_set_neighbor_ap2_callback(app_get_neighbor_ap2_t callback_get_neighbor_ap2);
void hal_ipc_server_set_radio_channel_stats_callback(app_get_radio_channel_stats_t callback_get_radio_channel_stats);
void hal_ipc_server_set_radio_traffic_stats_callback(app_get_radio_channel_stats_t callback_get_radio_traffic_stats);
app_get_ap_assoc_dev_diag_res3_t hal_ipc_server_get_ap_assoc_dev_diag_res3_callback(void);
app_get_neighbor_ap2_t           hal_ipc_server_get_neighbor_ap2_callback(void);
app_get_radio_channel_stats_t    hal_ipc_server_get_radio_channel_stats_callback(void);
app_get_radio_traffic_stats_t    hal_ipc_server_get_radio_traffic_stats_callback(void);

#ifdef __cplusplus
}
#endif

#endif // SERVER_HAL_IPC_H
