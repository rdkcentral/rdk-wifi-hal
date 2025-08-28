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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "hal_ipc.h"

#include "server_hal_ipc.h"

static INT hal_ipc_BTMQueryRequestEvent(UINT apIndex,
                                        CHAR *peerMac,
                                        wifi_BTMQuery_t *query,
                                        UINT inMemSize,
                                        wifi_BTMRequest_t *request)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_btm_query_request_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &apIndex, peerMac, query, &inMemSize, request) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

static INT hal_ipc_BTMResponseEvent(UINT apIndex,
                                    CHAR *peerMac,
                                    wifi_BTMResponse_t *response)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_btm_response_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &apIndex, peerMac, response, NULL, NULL) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return -1;
    }
    return 0;
}

static INT hal_ipc_RMBeaconReportEvent( UINT                apIndex,
                                        wifi_BeaconReport_t *out_struct,
                                        UINT                *out_array_size,
                                        UCHAR               *out_DialogToken)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_rm_beacon_report_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &apIndex, out_struct, out_array_size, out_DialogToken, NULL) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return -1;
    }

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}


// This function is used as argument for wifi_steering_eventRegister.
// Therefore when steering event occurs this function will be called and
// here we pass steering event data to BM via IPC mechanism
static void hal_ipc_send_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event)
{
    hal_ipc_node_t *node;
    hal_ipc_processor_t notification_input_func;
    hal_ipc_processor_desc_t *desc;

    desc  = get_processor_desc(hal_ipc_desc_type_steering_event);

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return;
    }

    notification_input_func = desc->ipc_processor[processor_type_ipc_client_notification_input];

    if ((notification_input_func != NULL) && (notification_input_func(desc, &steeringgroupIndex, event, NULL, NULL, NULL) != 0)) {
        wifi_hal_error_print("%s:%d: Client input processor failed\n", __func__, __LINE__);
        return;
    }
    wifi_hal_dbg_print("%s:%d: Steering event for apindex: %d and event type: %d for desc name %s: \n", __func__, __LINE__, event->apIndex, event->type, desc->name);

    if (rdk_hal_ipc_exec(node, desc) != 0) {
        wifi_hal_error_print("%s:%d: ipc  processor failed\n", __func__, __LINE__);
        return;
    }
}

int hal_ipc_init(void)
{
    hal_ipc_node_t *node;

    // Register HAL IPC function as steering event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
    wifi_hal_steering_eventRegister(hal_ipc_send_steering_event);

    // Register HAL IPC function as RM Beacon Report event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
    for (int ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++) {
        wifi_hal_RMBeaconRequestCallbackRegister(ap_index, hal_ipc_RMBeaconReportEvent);
    }

    // Register HAL IPC function as BTM Query/Request event callback
    // in rdk-wifi-hal callbacks struct g_wifi_hal.device_callbacks
    for (int ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++) {
        wifi_hal_BTMQueryRequest_callback_register( ap_index, 
                                                    hal_ipc_BTMQueryRequestEvent,
                                                    hal_ipc_BTMResponseEvent);
    }

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_notification_client)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create notification client node\n", __func__, __LINE__);
        return -1;
    }

    if ((node = rdk_create_hal_ipc_node(hal_ipc_node_type_sync_call_server)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create sync call server node\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}


