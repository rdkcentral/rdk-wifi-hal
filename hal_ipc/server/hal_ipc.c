#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "hal_ipc.h"

hal_ipc_node_t  g_ipc_node[hal_ipc_node_type_max];

// HAL-IPC Server
#define ipc_client_input                NULL
#define ipc_client_output               NULL
#define ipc_server_notification_output  NULL


hal_ipc_processor_desc_t    processor_desc[hal_ipc_desc_type_max] = {
    {
        hal_ipc_desc_type_set_radio_stats_enable,
        "wifi_setRadioStatsEnable",
        {                                         // ipc_processor
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,                                        // len
        0,                                        // ret
        {0},                                      // union in
        {0},                                      // union out
        NULL,                                     // scratch_buf pointer
        0                                         // scratch_buf_size
    },
    {
        hal_ipc_desc_type_get_ssid_num_of_entries,
        "wifi_getSSIDNumberOfEntries",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_assoc_dev_stats,
        "wifi_getApAssociatedDeviceStats",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_radio_chan_stats,
        "wifi_getRadioChannelStats",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_start_neighbor_scan,
        "wifi_startNeighborScan",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_neighbor_wifi_status,
        "wifi_getNeighboringWiFiStatus",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ssid_traffic_stats2,
        "wifi_getSSIDTrafficStats2",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_assoc_dev_rx_stats_result,
        "wifi_getApAssociatedDeviceRxStatsResult",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ssid_enable,
        "wifi_getSSIDEnable",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ssid_radio_index,
        "wifi_getSSIDRadioIndex",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ssid_name_status,
        "wifi_getSSIDNameStatus",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_name,
        "wifi_getApName",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_neighbor_report_activation,
        "wifi_getNeighborReportActivation",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_bss_transition_activation,
        "wifi_getBSSTransitionActivation",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_assoc_dev_diag_result3,
        "wifi_getApAssociatedDeviceDiagnosticResult3",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_assoc_client_diag_result,
        "wifi_getApAssociatedClientDiagnosticResult",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_radio_operating_freq_band,
        "wifi_getRadioOperatingFrequencyBand",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_radio_num_of_entries,
        "wifi_getRadioNumberOfEntries",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_assoc_dev_tx_stats_result,
        "wifi_getApAssociatedDeviceTxStatsResult",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_set_group,
        "wifi_steering_setGroup",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_client_set,
        "wifi_steering_clientSet",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_client_remove,
        "wifi_steering_clientRemove",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_client_disconnect,
        "wifi_steering_clientDisconnect",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_set_btm_request,
        "wifi_setBTMRequest",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ssid_name,
        "wifi_getSSIDName",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_set_rm_beacon_request,
        "wifi_setRMBeaconRequest",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_association_req_ies,
        "wifi_getAssociationReqIEs",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_set_neighbor_reports,
        "wifi_setNeighborReports",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_set_neighbor_report_activation,
        "wifi_setNeighborReportActivation",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_radio_if_name,
        "wifi_getRadioIfName",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_get_ap_num_assoc_devs,
        "wifi_getApNumDevicesAssociated",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_unregister,
        "wifi_steering_eventUnregister",
        {
            NULL,
            NULL,
            NULL,
            ipc_client_notification_input,
            NULL
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_register,
        "wifi_steering_eventRegister",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_steering_event,
        "steering event notification",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_mgmt_frame_callback_register,
        "wifi_mgmt_frame_callbacks_register",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_desc_type_mgmt_frame_event,
        "mgmt frame event notification",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_rm_beacon_request_register,
        "wifi_RMBeaconRequestCallbackRegister",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_rm_beacon_report_event,
        "RM beacon report event notification",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_btm_query_request_register,
        "wifi_BTMQueryRequest_callback_register",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_btm_query_request_event,
        "BTM query request event notification",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    },
    {
        hal_ipc_btm_response_event,
        "BTM response event notification",
        {
            ipc_client_input,
            ipc_client_output,
            ipc_server_output,
            ipc_client_notification_input,
            ipc_server_notification_output
        },
        0,
        0,
        {0},
        {0},
        NULL,
        0
    }
};

//**************************************************************************************************
// Function pointer to store client's callback for steering event
//wifi_steering_eventCB_t client_registered_steering_callback = NULL;

//--------------------------------------------------------------------------------------------------
//void hal_ipc_set_client_steering_callback(wifi_steering_eventCB_t client_steering_event_callback)
//{
//    // Don't check for NULL pointer here for the purpose of Unregistering clients callback
//    client_registered_steering_callback = client_steering_event_callback;
//}

//--------------------------------------------------------------------------------------------------
//wifi_steering_eventCB_t hal_ipc_get_client_steering_callback(void)
//{
//    return client_registered_steering_callback;
//}

//**************************************************************************************************
// Function to store callback function to get AP associated device diagnostic result3
app_get_ap_assoc_dev_diag_res3_t hal_ipc_server_callback_get_ap_assoc_dev_diag_res3;
app_get_neighbor_ap2_t hal_ipc_server_callback_get_neighbor_ap2;
app_get_radio_channel_stats_t hal_ipc_server_callback_get_radio_channel_stats;
// app_get_radio_traffic_stats_t hal_ipc_server_callback_get_radio_traffic_stats;

//--------------------------------------------------------------------------------------------------
void hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(app_get_ap_assoc_dev_diag_res3_t callback_get_ap_assoc_dev_diag_res3)
{
    // check for NULL pointer here?
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    hal_ipc_server_callback_get_ap_assoc_dev_diag_res3 = callback_get_ap_assoc_dev_diag_res3;
}

void hal_ipc_server_set_neighbor_ap2_callback(app_get_neighbor_ap2_t callback_get_neighbor_ap2)
{
    // check for NULL pointer here?
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    hal_ipc_server_callback_get_neighbor_ap2 = callback_get_neighbor_ap2;
}

void hal_ipc_server_set_radio_channel_stats_callback(app_get_radio_channel_stats_t callback_get_radio_channel_stats)
{
    // check for NULL pointer here?
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    hal_ipc_server_callback_get_radio_channel_stats = callback_get_radio_channel_stats;
}

// void hal_ipc_server_set_radio_traffic_stats_callback(app_get_radio_channel_stats_t callback_get_radio_traffic_stats)
// {
//     // check for NULL pointer here?
//     wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
//     hal_ipc_server_callback_get_radio_traffic_stats = callback_get_radio_traffic_stats;
// }

//--------------------------------------------------------------------------------------------------
app_get_ap_assoc_dev_diag_res3_t hal_ipc_server_get_ap_assoc_dev_diag_res3_callback(void)
{
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    return hal_ipc_server_callback_get_ap_assoc_dev_diag_res3;
}

app_get_neighbor_ap2_t hal_ipc_server_get_neighbor_ap2_callback(void)
{
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    return hal_ipc_server_callback_get_neighbor_ap2;
}

app_get_radio_channel_stats_t hal_ipc_server_get_radio_channel_stats_callback(void)
{
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    return hal_ipc_server_callback_get_radio_channel_stats;
}

// app_get_radio_traffic_stats_t hal_ipc_server_get_radio_traffic_stats_callback(void)
// {
//     wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
//     return hal_ipc_server_callback_get_radio_traffic_stats;
// }



//**************************************************************************************************
//                      HAL IPC core functions
//**************************************************************************************************
//--------------------------------------------------------------------------------------------------
hal_ipc_processor_desc_t *get_processor_desc(hal_ipc_desc_type_t type)
{
    return &processor_desc[type];
}

//--------------------------------------------------------------------------------------------------
int rdk_hal_ipc_exec(hal_ipc_node_t *p_ipc_node, hal_ipc_processor_desc_t *desc)
{
    socklen_t len;
    int cli_sock;
    int nbytes, target_bytes;
    unsigned int max_size = MAX_IPC_BUFF;
    struct sockaddr_un cli_sockaddr, srv_sockaddr;
    unsigned char *tmp;

    if ((cli_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        wifi_hal_error_print("%s:%d:server socket create failed err: %d\n", __func__, __LINE__, errno);
        return -1;
    }

    cli_sockaddr.sun_family = AF_UNIX;
    strcpy(cli_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(cli_sockaddr);

    unlink(p_ipc_node->node_path);
    if (bind(cli_sock, (struct sockaddr *)&cli_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:client socket bind failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        return -1;
    }

    srv_sockaddr.sun_family = AF_UNIX;

    switch (p_ipc_node->type) {
        case hal_ipc_node_type_sync_call_sm_client:
        case hal_ipc_node_type_sync_call_bm_client:
            strcpy(srv_sockaddr.sun_path, "/tmp/hal_sync_server");
            break;

        case hal_ipc_node_type_notification_client:
            strcpy(srv_sockaddr.sun_path, "/tmp/hal_notification_server");
            break;

        default:
            wifi_hal_error_print("%s:%d: Assert!!!.\n", __func__, __LINE__);
            assert(1);
            break;
    }

    if ((setsockopt(cli_sock, SOL_SOCKET, SO_RCVBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:clientr socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        return -1;
    }

    if ((setsockopt(cli_sock, SOL_SOCKET, SO_SNDBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:clientr socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        return -1;
    }

    if (connect(cli_sock, (struct sockaddr *)&srv_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:connect failed err: %d\n", __func__, __LINE__, errno);
        close(cli_sock);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: sending desc %s struct of size bytes %d\n",
            __func__, __LINE__, desc->name, desc->len);

    ///************************************************************************///
    ///     SEND DATA TO SERVER FOR PROCESSING                                 ///
    ///************************************************************************///
    tmp = (unsigned char *)desc;
    if (sizeof(hal_ipc_processor_desc_t) > max_size) {
        nbytes = 0;
        target_bytes = 0;

        while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
            if ((nbytes = send(cli_sock, tmp, ((sizeof(hal_ipc_processor_desc_t) - target_bytes) > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) {
                wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                close(cli_sock);
                return -1;
            }
            tmp += nbytes;
            target_bytes += nbytes;
        }
        nbytes = target_bytes;
    }
    else {
        if ((nbytes = send(cli_sock, tmp, sizeof(hal_ipc_processor_desc_t), 0)) == -1) {
            wifi_hal_error_print("%s:%d:sending desc failed err: %d\n", __func__, __LINE__, errno);
            close(cli_sock);
            return -1;
        }
    }

    target_bytes = 0;
    nbytes = 0;

    if (desc->len > sizeof(hal_ipc_processor_desc_t)) {
        tmp = desc->scratch_buf;
        while (target_bytes < desc->scratch_buf_size) {
            if ((nbytes = send(cli_sock, tmp, ((desc->scratch_buf_size - target_bytes) > max_size) ? max_size : desc->scratch_buf_size - target_bytes, 0)) == -1) {
                wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                close(cli_sock);
                free(desc->scratch_buf);
                return -1;
            }
            tmp += nbytes;
            target_bytes += nbytes;
        }
        free(desc->scratch_buf);
    }

    wifi_hal_dbg_print("%s:%d: sent %d bytes\n", __func__, __LINE__, desc->len);

    close(cli_sock);

    return 0;
}

//--------------------------------------------------------------------------------------------------
static void *rdk_hal_server_func(void *arg)
{
    int cli_sock;
    ssize_t nbytes, target_bytes, max_size = MAX_IPC_BUFF;
    socklen_t len;
    struct sockaddr_un cli_sockaddr;
    hal_ipc_processor_desc_t desc;
    hal_ipc_processor_t	serv_processor;
    hal_ipc_node_t *p_ipc_node = (hal_ipc_node_t *)arg;
    unsigned char *tmp;
    unsigned char break_cycle = 0;

    unsigned char *ptr;

    if (((p_ipc_node->type != hal_ipc_node_type_notification_server) ||
            (p_ipc_node->type != hal_ipc_node_type_sync_call_server)) == false) {
        wifi_hal_error_print("%s:%d: Invalid node type: %d\n", __func__, __LINE__, p_ipc_node->type);
        return NULL;
    }

    if ((p_ipc_node->srv_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        wifi_hal_error_print("%s:%d:server socket create failed err: %d\n", __func__, __LINE__, errno);
        return NULL;
    }

    p_ipc_node->srv_sockaddr.sun_family = AF_UNIX;
    strcpy(p_ipc_node->srv_sockaddr.sun_path, p_ipc_node->node_path);
    len = sizeof(p_ipc_node->srv_sockaddr);

    unlink(p_ipc_node->node_path);
    if (bind(p_ipc_node->srv_sock, (struct sockaddr *)&p_ipc_node->srv_sockaddr, len) == -1) {
        wifi_hal_error_print("%s:%d:server socket bind failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if ((setsockopt(p_ipc_node->srv_sock, SOL_SOCKET, SO_RCVBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:server socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if ((setsockopt(p_ipc_node->srv_sock, SOL_SOCKET, SO_SNDBUF, &max_size ,sizeof(int))) < 0) {
        wifi_hal_error_print("%s:%d:server socket size set failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    if (listen(p_ipc_node->srv_sock, 32) == -1) {
        wifi_hal_error_print("%s:%d:server socket listen failed err: %d\n", __func__, __LINE__, errno);
        close(p_ipc_node->srv_sock);
        return NULL;
    }

    wifi_hal_dbg_print("%s:%d: Enter loop.\n", __func__, __LINE__);

    while ((cli_sock = accept(p_ipc_node->srv_sock, (struct sockaddr *)&cli_sockaddr, &len)) != -1) {
        ///**************************************************************************************///
        ///                 RECEIVE SYNC DATA FROM CLIENT                                        ///
        ///**************************************************************************************///
        break_cycle = 0;
        nbytes = 0;
        target_bytes = 0;
        desc.scratch_buf = NULL;
        desc.scratch_buf_size = 0;
        ptr = (unsigned char *) &desc;
        if (sizeof(hal_ipc_processor_desc_t) > max_size) {
            while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
                if (((nbytes = recv(cli_sock, ptr, (sizeof(hal_ipc_processor_desc_t) - target_bytes > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) || (nbytes == 0)) {
                    wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                ptr += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
        } else {
            if (((nbytes = recv(cli_sock, (unsigned char *) &desc, sizeof(hal_ipc_processor_desc_t), 0)) == -1) || (nbytes == 0)) {
                wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                close(cli_sock);
                continue;
            }
        }

        target_bytes = 0;
        nbytes = 0;

        // check if there is more data to be received
        if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
            assert(desc.scratch_buf_size == (desc.len - sizeof(hal_ipc_processor_desc_t)));
            wifi_hal_dbg_print("%s:%d: Receiving scratch buf of size %d bytes ...\n", __func__, __LINE__, desc.scratch_buf_size);

            // allocate memory for client's data
            // free in serv_proc function
            desc.scratch_buf = malloc(desc.scratch_buf_size);

            if (!desc.scratch_buf) {
                wifi_hal_error_print("%s:%d: failed to allocate memory of %d bytes for scratch buffer\n", __func__, __LINE__, desc.scratch_buf_size);
                close(cli_sock);
                continue;
            }

            memset(desc.scratch_buf, 0, desc.scratch_buf_size);
            tmp = desc.scratch_buf;

            if (desc.scratch_buf_size > max_size) {
                while (target_bytes < desc.scratch_buf_size) {
                    if (((nbytes = recv(cli_sock, (unsigned char *)tmp, (desc.scratch_buf_size - target_bytes) > max_size ? max_size : (desc.scratch_buf_size - target_bytes), 0)) == -1) || (nbytes == 0)) {
                        wifi_hal_error_print("%s:%d:receiving desc scratch buf in chunks failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                        free(desc.scratch_buf);
                        close(cli_sock);
                        break_cycle = 1;
                        break;
                    }
                    target_bytes += nbytes;
                }
                if (break_cycle) {
                    continue;
                }
                nbytes = target_bytes;
            } else {
                if (((nbytes = recv(cli_sock, (unsigned char *)tmp, desc.scratch_buf_size, 0)) == -1) || (nbytes == 0)) {
                    wifi_hal_error_print("%s:%d:receiving command response failed err: %d data len:%zu\n", __func__, __LINE__, errno, nbytes);
                    free(desc.scratch_buf);
                    close(cli_sock);
                    continue;
                }
            }
        } else {
            // client's data fit into descriptor struct
            desc.scratch_buf = NULL;
            desc.scratch_buf_size = 0;
        }

        wifi_hal_dbg_print("%s:%d: Received command to execute: %s, bytes: %zu, expected: %d\n", __func__, __LINE__, desc.name, sizeof(hal_ipc_processor_desc_t) + nbytes, desc.len);

        assert((sizeof(hal_ipc_processor_desc_t) + nbytes) == desc.len);
        ///**************************************************************************************///
        ///                 call the associated descriptor processor                             ///
        ///**************************************************************************************///
        serv_processor = processor_desc[desc.type].ipc_processor[processor_type_ipc_server_output];

        if ((serv_processor != NULL) && (serv_processor(&desc, NULL, NULL, NULL, NULL, NULL) != 0)) {
            wifi_hal_error_print("%s:%d: Execution failed: %s\n", __func__, __LINE__, desc.name);
            // indicate ipc failure
            desc.ret = -1;
            desc.len = sizeof(hal_ipc_processor_desc_t);
            desc.scratch_buf_size = 0;
        }

        ///**************************************************************************************///
        ///                     SEND DATA TO CLIENT                                              ///
        ///**************************************************************************************///

        wifi_hal_dbg_print("%s:%d: Send data to client.\n", __func__, __LINE__);

        // At first send the descriptor structure
        // Next send the descriptor scratch buffer (optional)
        if (sizeof(hal_ipc_processor_desc_t) > max_size) {
            nbytes = 0;
            target_bytes = 0;
            ptr = (unsigned char *) &desc;
            while (target_bytes < sizeof(hal_ipc_processor_desc_t)) {
                if ((nbytes = send(cli_sock, ptr, ((sizeof(hal_ipc_processor_desc_t) - target_bytes) > max_size) ? max_size : (sizeof(hal_ipc_processor_desc_t) - target_bytes), 0)) == -1) {
                    wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                    // serv_processor function depending on descriptor type
                    // might allocate memory for client's response
                    // to desc.scratch_buf pointer and therefore desc.len (data length of descriptor)
                    // will be more than size of desc structure.
                    // if send failed - decide to free memory based on desc data length
                    if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
                        free(desc.scratch_buf);
                    }
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                ptr += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
            nbytes = target_bytes;
        } else if ((nbytes = send(cli_sock, (unsigned char *)&desc, sizeof(hal_ipc_processor_desc_t), 0)) == -1) {
            wifi_hal_error_print("%s:%d:sending desc failed err: %d\n", __func__, __LINE__, errno);
            if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
                free(desc.scratch_buf);
            }
            close(cli_sock);
            continue;
        }

        // now check if there is a data in descriptor scratch buffer
        if (desc.len > sizeof(hal_ipc_processor_desc_t)) {
            nbytes = 0;
            target_bytes = 0;
            tmp = desc.scratch_buf;
            while(target_bytes < desc.scratch_buf_size) {
                if ((nbytes = send(cli_sock, (unsigned char *) tmp, ((desc.scratch_buf_size - target_bytes) > max_size) ? max_size : (desc.scratch_buf_size - target_bytes), 0)) == -1) {
                    wifi_hal_error_print("%s:%d:sending desc in chunks failed err: %d\n", __func__, __LINE__, errno);
                    // condition if (desc.len > sizeof(hal_ipc_processor_desc_t)) means that
                    // we allocated memory in server_proc function
                    free(desc.scratch_buf);
                    close(cli_sock);
                    break_cycle = 1;
                    break;
                }
                tmp += nbytes;
                target_bytes += nbytes;
            }
            if (break_cycle) {
                continue;
            }
            nbytes = target_bytes;

            wifi_hal_dbg_print("%s:%d: Response sent to client for api: %s bytes: %zu\n", __func__, __LINE__, desc.name, sizeof(hal_ipc_processor_desc_t) + nbytes);

            free(desc.scratch_buf);
            close(cli_sock);
        } else {
            wifi_hal_dbg_print("%s:%d: Response sent to client for api: %s bytes: %zu\n", __func__, __LINE__, desc.name, nbytes);
            close(cli_sock);
        }

    } // end of while (accept)

    close(p_ipc_node->srv_sock);

    wifi_hal_dbg_print("%s:%d: Exit.\n", __func__, __LINE__);

    return NULL;
}

//--------------------------------------------------------------------------------------------------
hal_ipc_node_t *rdk_create_hal_ipc_node(hal_ipc_node_type_t type)
{
    hal_ipc_node_t *node;

    // always return the node based on enumeration of node type which is also the index of the array
    node = &g_ipc_node[type];

    node->type = type;

    switch (type) {
        case hal_ipc_node_type_sync_call_server:
            strcpy(node->node_path, "/tmp/hal_sync_server");
            break;

        case hal_ipc_node_type_notification_client:
            strcpy(node->node_path, "/tmp/hal_notification_client");
            break;

        case hal_ipc_node_type_sync_call_bm_client:
        case hal_ipc_node_type_sync_call_sm_client:
        case hal_ipc_node_type_notification_server:
        default:
            wifi_hal_dbg_print("%s:%d: Invalid node type for server.\n", __func__, __LINE__);
            return NULL;
    }

    if ((type == hal_ipc_node_type_sync_call_server) && (pthread_create(&node->listener_tid, NULL, rdk_hal_server_func, node) != 0)) {
        wifi_hal_dbg_print("%s:%d: Failed to create HAL server ipc node and start server.\n", __func__, __LINE__);
        return NULL;
    }

    return node;
}
