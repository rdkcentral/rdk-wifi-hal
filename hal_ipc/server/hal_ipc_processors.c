#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "hal_ipc.h"

//--------------------------------------------------------------------------------------------------
static void cleanup_client_data(unsigned char **client_scratch_buf, int client_data_len)
{
    if (client_data_len > sizeof(hal_ipc_processor_desc_t)) {
        if (*client_scratch_buf != NULL) {
            free(*client_scratch_buf);
            *client_scratch_buf = NULL;
        }
    }
}

//--------------------------------------------------------------------------------------------------
static void cleanup_desc_scratch_buf(struct hal_ipc_processor_desc *desc)
{
    desc->scratch_buf_size = 0;
    desc->scratch_buf = NULL;
}

int sync_hostapd_freq_param(unsigned int apIndex)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    int freq;
    char country[8] = { 0 };

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface for ap index:%u not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;

    get_coutry_str_from_code(radio_param->countryCode, country);

    freq = ieee80211_chan_to_freq(country, radio_param->op_class, radio_param->channel);
    if (interface->u.ap.hapd.iface->freq != freq) {
        wifi_hal_info_print("%s:%d: ap index:%u existing freq:%d curr freq:%d\n", __func__, __LINE__, apIndex, interface->u.ap.hapd.iface->freq, freq);
        interface->u.ap.hapd.iface->freq = freq;
    } else {
        wifi_hal_dbg_print("%s:%d: ap index:%u existing freq:%d curr freq:%d\n", __func__, __LINE__, apIndex, interface->u.ap.hapd.iface->freq, freq);
    }
    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
int ipc_server_output(struct hal_ipc_processor_desc *desc,
                      void *arg1,
                      void *arg2,
                      void *arg3,
                      void *arg4,
                      void *arg5)
{
    int index = 0;
    unsigned long num_entries;
    unsigned long long handle;
    int array_size;
    wifi_neighborScanMode_t scan_mode;
    int dwell_time;
    unsigned int chan_num;
    unsigned int *chan_list;
    unsigned int output_array_size;
    wifi_ssidTrafficStats2_t *output_struct;
    wifi_associated_dev_rate_info_rx_stats_t *assoc_dev_rx_stats_array;
    wifi_associated_dev_rate_info_tx_stats_t *assoc_dev_tx_stats_array;
    BOOL output_bool;
    int got_radio_index = 0;
    CHAR* output_string;
    wifi_associated_dev3_t *associated_dev_array;
    UINT req_ies_size_out = 0;

    wifi_hal_dbg_print("%s:%d Enter: executing %s api in server\n", __func__, __LINE__, desc->name);

    int client_data_len = desc->len;
    unsigned char *client_scratch_buf = desc->scratch_buf;

    desc->len = sizeof(hal_ipc_processor_desc_t);

    desc->ret = 0;

    switch (desc->type) {
        case hal_ipc_desc_type_set_radio_stats_enable:
            index = desc->in.set_radio_stats_enable.radio_index;
            BOOL enable = desc->in.set_radio_stats_enable.enabled;
            desc->ret = wifi_hal_setRadioStatsEnable(index, enable);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }
            break;

        case hal_ipc_desc_type_get_ssid_num_of_entries:
            num_entries = 0;
            desc->ret = wifi_hal_getSSIDNumberOfEntries(&num_entries);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_ssid_num_entries.numEntries = num_entries;
            break;

        case hal_ipc_desc_type_get_ap_assoc_dev_stats:
            index = desc->in.get_ap_assoc_dev_stats.ap_index;

            wifi_associated_dev_stats_t associated_dev_stats;
            mac_address_t *client_mac_address = (mac_address_t*) malloc(sizeof(mac_address_t));

            if (!client_mac_address) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory client_mac_addr\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) client_mac_address,
                       (unsigned char*) &desc->in.get_ap_assoc_dev_stats.client_mac_addr[0],
                       sizeof(mac_address_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s client_mac_addr\n", __func__, __LINE__, desc->name);
                free(client_mac_address);
                goto error_happened;
            }

            desc->ret = wifi_hal_getApAssociatedDeviceStats(index, client_mac_address, &associated_dev_stats, &handle);

            free(client_mac_address);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_ap_assoc_dev_stats.handle = handle;

            if (!memcpy((unsigned char*) &desc->out.get_ap_assoc_dev_stats.associated_dev_stats,
                       (unsigned char*) &associated_dev_stats,
                       sizeof(wifi_associated_dev_stats_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s associated_dev_stats\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }
            break;

        case hal_ipc_desc_type_get_radio_chan_stats:
            index = desc->in.get_radio_channel_stats.radio_index;
            array_size = desc->in.get_radio_channel_stats.array_size;

            wifi_channelStats_t *input_output_channelStats_array, *chan_stats_tmp;

            if (array_size > HAL_IPC_RADIO_CHANNELS_MAX) {
                array_size = HAL_IPC_RADIO_CHANNELS_MAX;
            }

            input_output_channelStats_array = (wifi_channelStats_t *) malloc(array_size * sizeof(wifi_channelStats_t));

            if (!input_output_channelStats_array) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d wifi_channelStats_t array\n", __func__, __LINE__, desc->name, HAL_IPC_RADIO_CHANNELS_MAX);
                goto error_happened;
            }
            memset((unsigned char*)&input_output_channelStats_array[0], 0, array_size * sizeof(wifi_channelStats_t));

            if (desc->scratch_buf_size != array_size*sizeof(wifi_channelStats_t)) {
                free(input_output_channelStats_array);
                wifi_hal_error_print("%s:%d FAIL %s incorrect data size received.\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &input_output_channelStats_array[0],
                       (unsigned char*) desc->scratch_buf,
                       array_size*sizeof(wifi_channelStats_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s input_output_channel_stats_array\n", __func__, __LINE__, desc->name);
                free(input_output_channelStats_array);
                goto error_happened;
            }
            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);

            wifi_hal_dbg_print("%s:%d Channel number[%d] array_size:%d\n",__func__,__LINE__, input_output_channelStats_array[0].ch_number, array_size);
            desc->ret = wifi_hal_getRadioChannelStats(index, input_output_channelStats_array, array_size);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(input_output_channelStats_array);
                goto error_happened;
            }

            for (int index = 0; index < array_size; index++) {
                chan_stats_tmp = &input_output_channelStats_array[index];
                wifi_hal_dbg_print(
                    "%s:%d array_size:%d,index:%d,Channel number :%d busyTx:%llu busyrx:%llu, "
                    "ch_in_pool:%d ch_noise:%d ch_utilization:%d ch_utilization_total:%llu\n",
                    __func__, __LINE__, array_size, index, chan_stats_tmp->ch_number,
                    chan_stats_tmp->ch_utilization_busy_tx, chan_stats_tmp->ch_utilization_busy_rx,
                    chan_stats_tmp->ch_in_pool, chan_stats_tmp->ch_noise,
                    chan_stats_tmp->ch_utilization, chan_stats_tmp->ch_utilization_total);
            }

            // allocate new memory for server's output data
            // will be free'd in calling function on successful send to client or send failure
            // if failure happens in this function - free here
            desc->scratch_buf = malloc(array_size * sizeof(wifi_channelStats_t));
            if (!desc->scratch_buf) {
                wifi_hal_error_print("%s:%d FAIL %s allocate desc scratch buf memory for %d wifi_channelStats_t output array\n", __func__, __LINE__, desc->name, array_size);
                free(input_output_channelStats_array);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }

            memset(desc->scratch_buf, 0, array_size * sizeof(wifi_channelStats_t));

            desc->scratch_buf_size = 0;

            chan_stats_tmp = (wifi_channelStats_t *)desc->scratch_buf;

            for (unsigned int i = 0; i < array_size; i++) {
                if (!memcpy( (unsigned char*) chan_stats_tmp,
                            (unsigned char*) &input_output_channelStats_array[i],
                            sizeof(wifi_channelStats_t))) {
                    wifi_hal_error_print("%s:%d FAIL memcpy %s input_output_channel_stats_array\n", __func__, __LINE__, desc->name);
                    free(desc->scratch_buf);
                    cleanup_desc_scratch_buf(desc);
                    free(input_output_channelStats_array);
                    goto error_happened;
                }
                desc->scratch_buf_size += sizeof(wifi_channelStats_t);
                chan_stats_tmp++;
            }

            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            free(input_output_channelStats_array);
            break;

        case hal_ipc_desc_type_start_neighbor_scan:
            index = desc->in.start_neighbor_scan.ap_index;
            scan_mode = desc->in.start_neighbor_scan.scan_mode;
            dwell_time = desc->in.start_neighbor_scan.dwell_time;
            chan_num = desc->in.start_neighbor_scan.chan_num;
            chan_list = (unsigned int*) malloc(sizeof(unsigned int));

            if (dwell_time == 0) {
                    dwell_time = 5;
            }
            desc->ret = wifi_hal_startNeighborScan(index, scan_mode, dwell_time, chan_num, chan_list);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(chan_list);
                goto error_happened;
            }
            desc->out.start_neighbor_scan.chan_list = *chan_list;
            free(chan_list);
            break;

        case hal_ipc_desc_type_get_neighbor_wifi_status:
            index = desc->in.get_neighbor_wifi_status.radio_index;
            output_array_size = 0;
            wifi_neighbor_ap2_t *tmp_neighbr_ap;

            wifi_neighbor_ap2_t *neighbor_ap_array;

            desc->ret = wifi_hal_getNeighboringWiFiStatus(index, &neighbor_ap_array, &output_array_size);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                cleanup_desc_scratch_buf(desc);
                free(neighbor_ap_array);
                goto error_happened;
            }

            desc->out.get_neighbor_wifi_status.output_array_size = output_array_size;
            if (!neighbor_ap_array) {
                wifi_hal_error_print("%s:%d %s returned empty neighbor_ap_array.\n", __func__, __LINE__, desc->name);
                desc->len = sizeof(hal_ipc_processor_desc_t);
                cleanup_desc_scratch_buf(desc);
                cleanup_client_data(&client_scratch_buf, client_data_len);
                return 0;
            }
            if (!output_array_size) {
                wifi_hal_error_print("%s:%d %s returned empty neighbor_ap_array.\n", __func__, __LINE__, desc->name);
                desc->len = sizeof(hal_ipc_processor_desc_t);
                cleanup_desc_scratch_buf(desc);
                cleanup_client_data(&client_scratch_buf, client_data_len);
                free(neighbor_ap_array);
                return 0;
            }

            if (output_array_size > HAL_IPC_MAX_NEIGHBOR_AP_COUNT) {
                wifi_hal_dbg_print("%s:%d %s returned too big array. Truncate to %d elements.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_NEIGHBOR_AP_COUNT);
                output_array_size = HAL_IPC_MAX_NEIGHBOR_AP_COUNT;
            }

            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);

            // will be free'd in calling function on successful send to client or send failure
            // if failure happens in this function - free here
            desc->scratch_buf = malloc(output_array_size*sizeof(wifi_neighbor_ap2_t));

            if (!desc->scratch_buf) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d wifi_neighbor_ap2_t structs\n", __func__, __LINE__, desc->name, output_array_size);
                cleanup_desc_scratch_buf(desc);
                free(neighbor_ap_array);
                goto error_happened;
            }
            memset(desc->scratch_buf, 0, output_array_size*sizeof(wifi_neighbor_ap2_t));

            desc->scratch_buf_size = 0;

            tmp_neighbr_ap = (wifi_neighbor_ap2_t*) desc->scratch_buf;

            for (unsigned int i = 0; i < output_array_size; i++) {
                if(!memcpy((unsigned char*) tmp_neighbr_ap,
                       (unsigned char*) &neighbor_ap_array[i],
                       sizeof(wifi_neighbor_ap2_t))) {
                    wifi_hal_error_print("%s:%d FAIL memcpy %s neighbor_ap_array\n", __func__, __LINE__, desc->name);
                    free(desc->scratch_buf);
                    cleanup_desc_scratch_buf(desc);
                    free(neighbor_ap_array);
                    goto error_happened;
                }
                tmp_neighbr_ap++;
                desc->scratch_buf_size += sizeof(wifi_neighbor_ap2_t);
            }

            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            free(neighbor_ap_array);
            break;

        case hal_ipc_desc_type_get_ssid_traffic_stats2:
            index = desc->in.get_ssid_traffic_stats2.ssid_index;
            output_struct = (wifi_ssidTrafficStats2_t*) malloc(sizeof(wifi_ssidTrafficStats2_t));

            if (!output_struct) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_ssidTrafficStats2_t output_struct\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            desc->ret = wifi_hal_getSSIDTrafficStats2(index, output_struct);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_struct);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &desc->out.get_ssid_traffic_stats2.output_struct,
                       (unsigned char*) output_struct,
                       sizeof(wifi_ssidTrafficStats2_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s wifi_ssidTrafficStats2_t output_struct\n", __func__, __LINE__, desc->name);
                free(output_struct);
                goto error_happened;
            }
            free(output_struct);
            break;

        case hal_ipc_desc_type_get_ap_assoc_dev_rx_stats_result:
            index = desc->in.get_ap_assoc_dev_rx_stats_result.radio_index;
            wifi_associated_dev_rate_info_rx_stats_t *tmp_rx_stats;
            assoc_dev_rx_stats_array = (wifi_associated_dev_rate_info_rx_stats_t*) malloc(HAL_IPC_MAX_STATS_ARRAY_NUM*sizeof(wifi_associated_dev_rate_info_rx_stats_t));

            if (!assoc_dev_rx_stats_array) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_associated_dev_rate_info_rx_stats_t assoc_dev_rx_stats_array\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            desc->ret = wifi_hal_getApAssociatedDeviceRxStatsResult(index,
                                                                &desc->in.get_ap_assoc_dev_rx_stats_result.client_mac_addr,
                                                                &assoc_dev_rx_stats_array,
                                                                &output_array_size,
                                                                &handle);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                cleanup_desc_scratch_buf(desc);
                free(assoc_dev_rx_stats_array);
                goto error_happened;
            }

            desc->out.get_ap_assoc_dev_rx_stats_result.handle = handle;

            desc->out.get_ap_assoc_dev_rx_stats_result.output_array_size = output_array_size;

            if (!output_array_size) {
                wifi_hal_error_print("%s:%d %s returned empty assoc_dev_rx_stats_array.\n", __func__, __LINE__, desc->name);
                free(assoc_dev_rx_stats_array);
                cleanup_desc_scratch_buf(desc);
                cleanup_client_data(&client_scratch_buf, client_data_len);
                desc->len = sizeof(hal_ipc_processor_desc_t);
                return 0;
            }

            if (output_array_size > HAL_IPC_MAX_STATS_ARRAY_NUM) {
                wifi_hal_dbg_print("%s:%d %s returned too big array. Truncate to %d elements\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STATS_ARRAY_NUM);
                output_array_size = HAL_IPC_MAX_STATS_ARRAY_NUM;
            }

            desc->out.get_ap_assoc_dev_rx_stats_result.output_array_size = output_array_size;
            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);

            // will be free'd in calling function on successful send to client or send failure
            // if failure happens in this function - free here
            desc->scratch_buf = malloc(output_array_size*sizeof(wifi_associated_dev_rate_info_rx_stats_t));

            if (!desc->scratch_buf) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d wifi_associated_dev_rate_info_rx_stats_t structs\n", __func__, __LINE__, desc->name, output_array_size);
                cleanup_desc_scratch_buf(desc);
                free(assoc_dev_rx_stats_array);
                goto error_happened;
            }
            memset(desc->scratch_buf, 0, output_array_size*sizeof(wifi_associated_dev_rate_info_rx_stats_t));

            desc->scratch_buf_size = 0;

            tmp_rx_stats = (wifi_associated_dev_rate_info_rx_stats_t*) desc->scratch_buf;

            for (unsigned int i = 0; i < output_array_size; i++) {
                if (!memcpy((unsigned char*) tmp_rx_stats,
                       (unsigned char*) &assoc_dev_rx_stats_array[i],
                       sizeof(wifi_associated_dev_rate_info_rx_stats_t))) {
                    wifi_hal_error_print("%s:%d FAIL memcpy %s wifi_associated_dev_rate_info_rx_stats_t struct\n", __func__, __LINE__, desc->name);
                    free(assoc_dev_rx_stats_array);
                    free(desc->scratch_buf);
                    cleanup_desc_scratch_buf(desc);
                    goto error_happened;
                }
                tmp_rx_stats++;
                desc->scratch_buf_size += sizeof(wifi_associated_dev_rate_info_rx_stats_t);

            }
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            free(assoc_dev_rx_stats_array);
            break;

        case hal_ipc_desc_type_get_ssid_enable:
            index = desc->in.get_ssid_enable.ssid_index;

            desc->ret = wifi_hal_getSSIDEnable(index, &output_bool);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_ssid_enable.output_bool = output_bool;
            break;

        case hal_ipc_desc_type_get_ssid_radio_index:
            index = desc->in.get_ssid_radio_index.ssid_index;

            desc->ret = wifi_hal_getSSIDRadioIndex(index, &got_radio_index);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_ssid_radio_index.radio_index = got_radio_index;
            break;

        case hal_ipc_desc_type_get_ssid_name_status:
            index = desc->in.get_ssid_name_status.ap_index;

            output_string = (CHAR*) malloc(HAL_IPC_MAX_STRING_LEN*sizeof(CHAR));

            if (!output_string) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for SSID status string.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STRING_LEN);
                goto error_happened;
            }
            memset(output_string, 0, HAL_IPC_MAX_STRING_LEN);

            desc->ret = wifi_hal_getSSIDNameStatus(index, output_string);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_string);
                goto error_happened;
            }

            if (!strlen(output_string)) {
                wifi_hal_error_print("%s:%d %s returned empty SSID status string for AP index %d.\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }

            if (!memcpy(desc->out.get_ssid_name_status.output_string, output_string, strlen(output_string) + 1)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s SSID output string of AP index %d\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }
            free(output_string);
            break;

        case hal_ipc_desc_type_get_ap_name:
            index = desc->in.get_ap_name.ap_index;

            output_string = (CHAR*) malloc(HAL_IPC_MAX_STRING_LEN*sizeof(CHAR));

            if (!output_string) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for AP name string.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STRING_LEN);
                goto error_happened;
            }
            memset(output_string, 0, HAL_IPC_MAX_STRING_LEN);

            desc->ret = wifi_hal_getApName(index, output_string);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_string);
                goto error_happened;
            }

            if (!strlen(output_string)) {
                wifi_hal_error_print("%s:%d %s returned empty AP name string for AP index %d.\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }

            memset(desc->out.get_ap_name.output_string, 0, sizeof(desc->out.get_ap_name.output_string));

            if (!memcpy(desc->out.get_ap_name.output_string, output_string, strlen(output_string) + 1)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s SSID output string of AP index %d\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }
            free(output_string);
            break;

        case hal_ipc_desc_type_get_neighbor_report_activation:
            index = desc->in.get_neighbor_report_activation.ap_index;

            desc->ret = wifi_hal_getNeighborReportActivation(index, &output_bool);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_neighbor_report_activation.activate = output_bool;
            break;

        case hal_ipc_desc_type_get_bss_transition_activation:
            index = desc->in.get_bss_transition_activation.ap_index;

            desc->ret = wifi_hal_getBSSTransitionActivation(index, &output_bool);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_bss_transition_activation.activate = output_bool;
            break;

        case hal_ipc_desc_type_get_ap_assoc_dev_diag_result3:;
            wifi_associated_dev3_t *dev;
            output_array_size = 0;
            index = desc->in.get_ap_assoc_dev_diag_result3.ap_index;
            associated_dev_array = (wifi_associated_dev3_t*) malloc(HAL_IPC_MAX_STA_SUPPORT_NUM*sizeof(wifi_associated_dev3_t));

            if (!associated_dev_array) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d objects of associated_dev_array.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STA_SUPPORT_NUM);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }

            memset(associated_dev_array, 0, HAL_IPC_MAX_STA_SUPPORT_NUM * sizeof(wifi_associated_dev3_t));

            // call OneWifi monitor functions to collect associated device diagnostic results3
            app_get_ap_assoc_dev_diag_res3_t callback_fn_diag = hal_ipc_server_get_ap_assoc_dev_diag_res3_callback();
            if (!callback_fn_diag) {
                wifi_hal_error_print("%s:%d FAIL %s callback is NULL.\n", __func__, __LINE__, desc->name);
                free(associated_dev_array);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }

            desc->ret = callback_fn_diag(index, associated_dev_array, &output_array_size);

            if (!output_array_size) {
                wifi_hal_dbg_print("%s:%d %s returned empty array.\n", __func__, __LINE__, desc->name);
                desc->out.get_ap_assoc_dev_diag_result3.num = 0;
                cleanup_desc_scratch_buf(desc);
                free(associated_dev_array);
                cleanup_client_data(&client_scratch_buf, client_data_len);
                return 0;
            }

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(associated_dev_array);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }

            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);

            desc->out.get_ap_assoc_dev_diag_result3.num = output_array_size;

            desc->scratch_buf = malloc(output_array_size*sizeof(wifi_associated_dev3_t));   // will be free()'ed after send to client
            if (!desc->scratch_buf) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d wifi_associated_dev3_t structs\n", __func__, __LINE__, desc->name, output_array_size); 
                free(associated_dev_array);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }
            memset(desc->scratch_buf, 0, output_array_size*sizeof(wifi_associated_dev3_t));

            desc->scratch_buf_size = 0;

            dev = (wifi_associated_dev3_t*) desc->scratch_buf;
            mac_addr_str_t assoc_mac, dev_mac;
            for (unsigned int i = 0; i < output_array_size; i++) {
                if (!memcpy((unsigned char*) dev, (unsigned char*) &associated_dev_array[i], sizeof(wifi_associated_dev3_t))) {
                    wifi_hal_error_print("%s:%d FAIL memcpy %s %d of %d diagnostic results \n", __func__, __LINE__, desc->name, i, output_array_size);
                    free(associated_dev_array);
                    free(desc->scratch_buf);
                    cleanup_desc_scratch_buf(desc);
                    goto error_happened;
                }
                desc->scratch_buf_size += sizeof(wifi_associated_dev3_t);
                to_mac_str(associated_dev_array[i].cli_MACAddress, assoc_mac);
                to_mac_str(dev->cli_MACAddress, dev_mac);
                wifi_hal_info_print("%s:%d assoc_mac:%s,dev_mac:%s,value of i:%d \n", __func__, __LINE__,assoc_mac,dev_mac,i);
                dev++;
            }
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            free(associated_dev_array);
            break;

        case hal_ipc_desc_type_get_ap_assoc_client_diag_result:
            ;
            wifi_associated_dev3_t *dev_conn = (wifi_associated_dev3_t*) malloc(sizeof(wifi_associated_dev3_t));

            if (!dev_conn) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_associated_dev3_t struct.\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            desc->ret = wifi_hal_getApAssociatedClientDiagnosticResult( desc->in.get_ap_assoc_client_diag_result.ap_index,
                                                                        &desc->in.get_ap_assoc_client_diag_result.mac_addr[0],
                                                                        dev_conn);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(dev_conn);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &desc->out.get_ap_assoc_client_diag_result.dev_conn,
                       (unsigned char*) dev_conn,
                       sizeof(wifi_associated_dev3_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s client diagnostic results\n", __func__, __LINE__, desc->name);
                free(dev_conn);
                goto error_happened;
            }
            free(dev_conn);
            break;

        case hal_ipc_desc_type_get_radio_operating_freq_band:
            index = desc->in.get_radio_operating_freq_band.radio_index;

            output_string = (CHAR*) malloc(HAL_IPC_MAX_STRING_LEN*sizeof(CHAR));

            if (!output_string) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for operating frequency band string.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STRING_LEN);
                goto error_happened;
            }
            memset(output_string, 0, HAL_IPC_MAX_STRING_LEN);

            desc->ret = wifi_hal_getRadioOperatingFrequencyBand(index, output_string);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_string);
                goto error_happened;
            }

            if (!strlen(output_string)) {
                wifi_hal_error_print("%s:%d %s returned empty operating frequency band string for radio index %d.\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }

            if (!memcpy(desc->out.get_radio_operating_freq_band.output_string, output_string, strlen(output_string) + 1)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s SSID output string of AP index %d\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }
            free(output_string);
            break;

        case hal_ipc_desc_type_get_radio_num_of_entries:
            desc->ret = wifi_hal_getRadioNumberOfEntries(&num_entries);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_radio_number_of_entries.output = num_entries;
            break;

        case hal_ipc_desc_type_get_ap_assoc_dev_tx_stats_result:
            index = desc->in.get_ap_assoc_dev_tx_stats_result.radio_index;
            wifi_associated_dev_rate_info_tx_stats_t *tmp_tx_stats;
            assoc_dev_tx_stats_array = (wifi_associated_dev_rate_info_tx_stats_t*) malloc(HAL_IPC_MAX_STATS_ARRAY_NUM*sizeof(wifi_associated_dev_rate_info_tx_stats_t));

            if (!assoc_dev_tx_stats_array) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_associated_dev_rate_info_tx_stats_t assoc_dev_tx_stats_array\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            desc->ret = wifi_hal_getApAssociatedDeviceTxStatsResult(index,
                                                                    &desc->in.get_ap_assoc_dev_tx_stats_result.client_mac_addr,
                                                                    &assoc_dev_tx_stats_array,
                                                                    &output_array_size,
                                                                    &handle);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(assoc_dev_tx_stats_array);
                cleanup_desc_scratch_buf(desc);
                goto error_happened;
            }

            desc->out.get_ap_assoc_dev_tx_stats_result.handle = handle;

            desc->out.get_ap_assoc_dev_tx_stats_result.output_array_size = output_array_size;

            if (!output_array_size) {
                wifi_hal_dbg_print("%s:%d %s returned empty assoc_dev_tx_stats_array.\n", __func__, __LINE__, desc->name);
                cleanup_desc_scratch_buf(desc);
                cleanup_client_data(&client_scratch_buf, client_data_len);
                free(assoc_dev_tx_stats_array);
                desc->len = sizeof(hal_ipc_processor_desc_t);
                return 0;
            }

            if (output_array_size > HAL_IPC_MAX_STATS_ARRAY_NUM) {
                wifi_hal_dbg_print("%s:%d %s returned too big array. Truncate to %d elements\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STATS_ARRAY_NUM);
                output_array_size = HAL_IPC_MAX_STATS_ARRAY_NUM;
            }

            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);

            desc->scratch_buf = malloc(output_array_size*sizeof(wifi_associated_dev_rate_info_tx_stats_t));
            memset(desc->scratch_buf, 0, output_array_size*sizeof(wifi_associated_dev_rate_info_tx_stats_t));

            desc->out.get_ap_assoc_dev_tx_stats_result.output_array_size = output_array_size;
            desc->scratch_buf_size = 0;

            tmp_tx_stats = (wifi_associated_dev_rate_info_tx_stats_t*) desc->scratch_buf;

            for (unsigned int i = 0; i < output_array_size; i++) {
                if (!memcpy((unsigned char*) tmp_tx_stats,
                       (unsigned char*) &assoc_dev_tx_stats_array[i],
                       sizeof(wifi_associated_dev_rate_info_tx_stats_t))) {
                    wifi_hal_error_print("%s:%d FAIL memcpy %s wifi_associated_dev_rate_info_tx_stats_t struct\n", __func__, __LINE__, desc->name);
                    free(assoc_dev_tx_stats_array);
                    free(desc->scratch_buf);
                    cleanup_desc_scratch_buf(desc);
                    goto error_happened;
                }
                tmp_tx_stats++;
                desc->scratch_buf_size += sizeof(wifi_associated_dev_rate_info_tx_stats_t);

            }
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            free(assoc_dev_tx_stats_array);
            break;

        case hal_ipc_desc_type_steering_set_group:
            ;
            wifi_steering_apConfig_t *cfg_2 = (wifi_steering_apConfig_t*) malloc(sizeof(wifi_steering_apConfig_t));
            wifi_steering_apConfig_t *cfg_5 = (wifi_steering_apConfig_t*) malloc(sizeof(wifi_steering_apConfig_t));
            if (!cfg_2 || !cfg_5) {
                wifi_hal_dbg_print("%s:%d FAIL %s allocate memory for wifi_steering_apConfig_t structs:cfg_2 or cfg_5 .\n", __func__, __LINE__, desc->name);
                if (cfg_2) {
                    free(cfg_2);
                }
                if (cfg_5) {
                    free(cfg_5);
                }
                goto error_happened;
            }
            if (!memcpy((unsigned char*) cfg_2,
                        (unsigned char*) &desc->in.set_steering_group.cfg_2,
                        sizeof(wifi_steering_apConfig_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s steering client config 2.4GHz\n", __func__, __LINE__, desc->name);
                free(cfg_2);
                free(cfg_5);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) cfg_5,
                        (unsigned char*) &desc->in.set_steering_group.cfg_5,
                        sizeof(wifi_steering_apConfig_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s steering client config 5GHz\n", __func__, __LINE__, desc->name);
                free(cfg_2);
                free(cfg_5);
                goto error_happened;
            }

            desc->ret = wifi_hal_steering_setGroup( desc->in.set_steering_group.steering_group_index,
                                                    cfg_2,
                                                    cfg_5);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(cfg_2);
                free(cfg_5);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &desc->out.set_steering_group.cfg_2,
                        (unsigned char*) cfg_2,
                        sizeof(wifi_steering_apConfig_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s output steering client config 2.4GHz\n", __func__, __LINE__, desc->name);
                free(cfg_2);
                free(cfg_5);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &desc->out.set_steering_group.cfg_5,
                        (unsigned char*) cfg_5,
                        sizeof(wifi_steering_apConfig_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s output steering client config 5GHz\n", __func__, __LINE__, desc->name);
                free(cfg_2);
                free(cfg_5);
                goto error_happened;
            }

            free(cfg_2);
            free(cfg_5);
            break;

        case hal_ipc_desc_type_steering_client_set:

            desc->ret = wifi_hal_steering_clientSet(desc->in.set_steering_client.steering_group_index,
                                                    desc->in.set_steering_client.ap_index,
                                                    desc->in.set_steering_client.client_mac,
                                                    &desc->in.set_steering_client.config);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) &desc->out.set_steering_client.config,
                       (unsigned char*) &desc->in.set_steering_client.config,
                       sizeof(wifi_steering_clientConfig_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s steering client set config for AP index %d\n", __func__, __LINE__, desc->name, desc->in.set_steering_client.ap_index);
                goto error_happened;
            }
            break;

        case hal_ipc_desc_type_steering_client_remove:
            desc->ret = wifi_hal_steering_clientRemove( desc->in.remove_steering_client.steering_group_index,
                                                        desc->in.remove_steering_client.ap_index,
                                                        desc->in.remove_steering_client.client_mac);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }
            break;

        case hal_ipc_desc_type_steering_client_disconnect:
            desc->ret = wifi_hal_steering_clientDisconnect( desc->in.disconnect_steering_client.steering_group_index,
                                                            desc->in.disconnect_steering_client.ap_index,
                                                            desc->in.disconnect_steering_client.client_mac,
                                                            desc->in.disconnect_steering_client.type,
                                                            desc->in.disconnect_steering_client.reason);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }
            break;

        case hal_ipc_desc_type_set_btm_request:
            ;
            wifi_BTMRequest_t *btm_request = (wifi_BTMRequest_t*) malloc(sizeof(wifi_BTMRequest_t));

            if (!btm_request) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_BTMRequest_t.\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }
    
            if (!memcpy((unsigned char*) btm_request,
                        (unsigned char*) &desc->in.set_btm_request.request,
                        sizeof(wifi_BTMRequest_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s of wifi_BTMRequest_t\n", __func__, __LINE__, desc->name);
                free(btm_request);
                goto error_happened;
            }

            wifi_hal_info_print("%s:%d name:%s ap_index:%d peer mac::%02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__, desc->name,
                            desc->in.set_btm_request.ap_index, desc->in.set_btm_request.peer_mac[0], desc->in.set_btm_request.peer_mac[1],
                            desc->in.set_btm_request.peer_mac[2], desc->in.set_btm_request.peer_mac[3],
                            desc->in.set_btm_request.peer_mac[4], desc->in.set_btm_request.peer_mac[5]);
            desc->ret = wifi_hal_setBTMRequest( desc->in.set_btm_request.ap_index,
                                                desc->in.set_btm_request.peer_mac,
                                                btm_request);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(btm_request);
                goto error_happened;
            }
            free(btm_request);
            break;

        case hal_ipc_desc_type_get_ssid_name:
            output_string = (CHAR*) malloc(HAL_IPC_MAX_STRING_LEN*sizeof(CHAR));

            if (!output_string) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for SSID name string.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STRING_LEN);
                goto error_happened;
            }
            memset(output_string, 0, HAL_IPC_MAX_STRING_LEN);

            desc->ret = wifi_hal_getSSIDName(desc->in.get_ssid_name.ap_index,
                                             output_string);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_string);
                goto error_happened;
            }

            if (!strlen(output_string)) {
                wifi_hal_error_print("%s:%d %s returned empty SSID name string for AP index %d.\n", __func__, __LINE__, desc->name, desc->in.get_ssid_name.ap_index);
                free(output_string);
                goto error_happened;
            }

            if (!memcpy(desc->out.get_ssid_name.output_string, output_string, strlen(output_string) + 1)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s SSID output string of AP index %d\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }
            free(output_string);
            break;

        case hal_ipc_desc_type_set_rm_beacon_request:
            ;
            UCHAR dialog_token_output = 0;

            wifi_BeaconRequest_t *beacon_request = (wifi_BeaconRequest_t*) malloc(sizeof(wifi_BeaconRequest_t));

            if (!beacon_request) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for wifi_BeaconRequest_t.\n", __func__, __LINE__, desc->name);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) beacon_request,
                        (unsigned char*) &desc->in.set_rm_beacon_request.in_request,
                        sizeof(wifi_BeaconRequest_t))) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s of wifi_BeaconRequest_t\n", __func__, __LINE__, desc->name);
                free(beacon_request);
                goto error_happened;
            }

            sync_hostapd_freq_param(desc->in.set_rm_beacon_request.ap_index);
            wifi_hal_info_print("%s:%d name:%s ap_index:%d peer mac::%02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__,
                            desc->name, desc->in.set_rm_beacon_request.ap_index,
                            desc->in.set_rm_beacon_request.peer_mac[0], desc->in.set_rm_beacon_request.peer_mac[1],
                            desc->in.set_rm_beacon_request.peer_mac[2], desc->in.set_rm_beacon_request.peer_mac[3],
                            desc->in.set_rm_beacon_request.peer_mac[4], desc->in.set_rm_beacon_request.peer_mac[5]);
            desc->ret = wifi_hal_setRMBeaconRequest(desc->in.set_rm_beacon_request.ap_index,
                                                    desc->in.set_rm_beacon_request.peer_mac,
                                                    beacon_request,
                                                    &dialog_token_output);
            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(beacon_request);
                goto error_happened;
            }
            desc->out.set_rm_beacon_request.dialog_token = dialog_token_output;
            free(beacon_request);
            break;

        case hal_ipc_desc_type_get_association_req_ies:
            ;
            CHAR *req_ies_out = (CHAR*) malloc(HAL_IPC_ASSOC_REQ_IES_BUF_SIZE*sizeof(CHAR));

            if (!req_ies_out) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for req_ies_out array.\n", __func__, __LINE__, desc->name, HAL_IPC_ASSOC_REQ_IES_BUF_SIZE);
                goto error_happened;
            }

            desc->ret = wifi_hal_getAssociationReqIEs(  desc->in.get_association_req_ies.ap_index,
                                                        &desc->in.get_association_req_ies.client_mac_addr,
                                                        req_ies_out,
                                                        desc->in.get_association_req_ies.req_ies_size,
                                                        &req_ies_size_out);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(req_ies_out);
                goto error_happened;
            }

            if (req_ies_size_out > HAL_IPC_ASSOC_REQ_IES_BUF_SIZE) {
                wifi_hal_error_print("%s:%d call to %s returned too big array size. MAX %d, got %d\n", __func__, __LINE__, desc->name, HAL_IPC_ASSOC_REQ_IES_BUF_SIZE, req_ies_size_out);
                free(req_ies_out);
                goto error_happened;
            }

            desc->out.get_association_req_ies.req_ies_len = req_ies_size_out;

            if (!memcpy((unsigned char*) desc->out.get_association_req_ies.req_ies,
                       (unsigned char*) req_ies_out,
                       req_ies_size_out)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s req_ies_out array %d bytes. AP index %d\n", __func__, __LINE__, desc->name, req_ies_size_out, desc->in.get_association_req_ies.ap_index);
                free(req_ies_out);
                goto error_happened;
            }
            free(req_ies_out);
            break;

        case hal_ipc_desc_type_set_neighbor_reports:
            ;
            wifi_NeighborReport_t *reports = (wifi_NeighborReport_t*) malloc(HAL_IPC_MAX_NEIGHBOR_AP_COUNT*sizeof(wifi_NeighborReport_t));

            if (!reports) {
                wifi_hal_error_print("%s:%d FAIL %s allocate memory for %d wifi_NeighborReport_t array.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_NEIGHBOR_AP_COUNT);
                goto error_happened;
            }

            if (!memcpy((unsigned char*) reports, (unsigned char*) desc->scratch_buf, desc->scratch_buf_size)) {
                wifi_hal_error_print("%s:%d FAIL memcpy %s of %d wifi_NeighborReport_t structs\n", __func__, __LINE__, desc->name, desc->in.set_neighbor_reports.num_neighbor_reports);
                free(reports);
                goto error_happened;
            }

            wifi_hal_info_print("%s:%d name:%s ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.set_neighbor_reports.ap_index);
            desc->ret = wifi_hal_setNeighborReports(desc->in.set_neighbor_reports.ap_index,
                                                    desc->in.set_neighbor_reports.num_neighbor_reports,
                                                    reports);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(reports);
                goto error_happened;
            }
            // free memory allocated for client's input data in calling function
            cleanup_client_data(&client_scratch_buf, client_data_len);
            free(reports);
            break;

        case hal_ipc_desc_type_set_neighbor_report_activation:
            desc->ret = wifi_hal_setNeighborReportActivation(desc->in.set_neighbor_report_activation.ap_index, desc->in.set_neighbor_report_activation.activate);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            break;

        case hal_ipc_desc_type_get_radio_if_name:
            index = desc->in.get_radio_if_name.radio_index;

            output_string = (CHAR*) malloc(HAL_IPC_MAX_STRING_LEN*sizeof(CHAR));

            if (!output_string) {
                wifi_hal_error_print("%s:%d FAIL %s allocate %d bytes of memory for SSID status string.\n", __func__, __LINE__, desc->name, HAL_IPC_MAX_STRING_LEN);
                goto error_happened;
            }
            memset(output_string, 0, HAL_IPC_MAX_STRING_LEN);

            desc->ret = wifi_hal_getRadioIfName(index, output_string);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                free(output_string);
                goto error_happened;
            }

            if (!strlen(output_string)) {
                wifi_hal_error_print("%s:%d %s returned empty radio interface name string for radio index %d.\n", __func__, __LINE__, desc->name, desc->in.get_radio_if_name.radio_index);
                free(output_string);
                goto error_happened;
            }

            memset(desc->out.get_radio_if_name.output_string, 0, HAL_IPC_MAX_STRING_LEN);

            if(!memcpy(desc->out.get_radio_if_name.output_string, output_string, strlen(output_string) + 1)){
                wifi_hal_error_print("%s:%d FAIL memcpy %s SSID output string of AP index %d\n", __func__, __LINE__, desc->name, index);
                free(output_string);
                goto error_happened;
            }
            free(output_string);
            break;

        case hal_ipc_desc_type_get_ap_num_assoc_devs:;
            ULONG num_devs_associated = 0;
            index = desc->in.get_ap_num_assoc_devs.ap_index;

            desc->ret = wifi_hal_getApNumDevicesAssociated(index, &num_devs_associated);

            if (desc->ret) {
                wifi_hal_error_print("%s:%d FAIL call to %s returned %d code\n", __func__, __LINE__, desc->name, desc->ret);
                goto error_happened;
            }

            desc->out.get_ap_num_assoc_devs.output = num_devs_associated;
            break;

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default. Unknown descriptor.\n", __func__, __LINE__, desc->name);
            goto error_happened;
            break;
    }

    return 0;

error_happened:
    cleanup_client_data(&client_scratch_buf, client_data_len);
    return -1;
}

//--------------------------------------------------------------------------------------------------
int ipc_client_notification_input(struct hal_ipc_processor_desc *desc,
                                  void *arg1,
                                  void *arg2,
                                  void *arg3,
                                  void *arg4,
                                  void *arg5)
{
    wifi_hal_dbg_print("%s:%d Enter: client notification input %s\n", __func__, __LINE__, desc->name);
    switch (desc->type) {
        case hal_ipc_desc_type_steering_event:
            if (!arg1 || !arg2) {
                wifi_hal_dbg_print("%s:%d function %s require 2 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.steering_event_data.steering_group_index = *(unsigned int*) arg1;
            if (!memcpy((unsigned char*) &desc->in.steering_event_data.evt,
                       (unsigned char*) arg2,
                       sizeof(wifi_steering_event_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_steering_event_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->len = sizeof(hal_ipc_processor_desc_t);
            break;

        case hal_ipc_desc_type_mgmt_frame_event:

            break;

        case hal_ipc_rm_beacon_report_event:
            if (!arg1 || !arg2 || !arg3 || !arg4) {
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            
            desc->in.rm_beacon_report_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.rm_beacon_report_event_data.apIndex);

            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BeaconReport_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg2,
                        sizeof(wifi_BeaconReport_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BeaconReport_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            desc->in.rm_beacon_report_event_data.out_array_size = *(unsigned int*) arg3;
            desc->in.rm_beacon_report_event_data.out_DialogToken = *(unsigned char*) arg4;

            desc->scratch_buf_size = sizeof(wifi_BeaconReport_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;
            break;

        case hal_ipc_btm_query_request_event:
            if (!arg1 || !arg2 || !arg3 || !arg4) {
                wifi_hal_dbg_print("%s:%d function %s require 4 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.btm_query_request_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d\n", __func__, __LINE__, desc->name, desc->in.btm_query_request_event_data.apIndex);
            if (!memcpy((unsigned char*) &desc->in.btm_query_request_event_data.peerMac,
                        (unsigned char*) arg2,
                        sizeof(mac_address_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s mac_address_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            desc->in.btm_query_request_event_data.inMemSize = *(unsigned int*) arg4;
            
            desc->scratch_buf = (unsigned char*) malloc(sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t));
            if (!desc->scratch_buf) {
                wifi_hal_dbg_print("%s:%d FAIL desc->scratch_buf malloc %s for wifi_BTMQuery_t and wifi_BTMRequest_t\n", __func__, __LINE__, desc->name);
                return -1;
            }

            if (!memcpy((unsigned char*) desc->scratch_buf,
                        (unsigned char*) arg3,
                        sizeof(wifi_BTMQuery_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }

            if (!memcpy((unsigned char*) (desc->scratch_buf + sizeof(wifi_BTMQuery_t)),
                        (unsigned char*) arg5,
                        sizeof(wifi_BTMRequest_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                free(desc->scratch_buf); 
                return -1;
            }
            desc->scratch_buf_size = sizeof(wifi_BTMQuery_t) + sizeof(wifi_BTMRequest_t);
            desc->len = sizeof(hal_ipc_processor_desc_t) + desc->scratch_buf_size;

            break;

        case hal_ipc_btm_response_event:
            if (!arg1 || !arg2 || !arg3) {
                wifi_hal_dbg_print("%s:%d function %s require 3 arguments.\n", __func__, __LINE__, desc->name);
                return -1;
            }
            mac_address_t sta_mac;
            memset(sta_mac, 0, sizeof(mac_address_t));

            desc->in.btm_response_event_data.apIndex = *(unsigned int*) arg1;
            wifi_hal_info_print("%s:%d:: %s() ap_index:%d peer_mac:%s\n", __func__, __LINE__, desc->name,
                                    desc->in.btm_response_event_data.apIndex, (char *)arg2);
            sscanf((char *)arg2, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &sta_mac[0], &sta_mac[1], &sta_mac[2],&sta_mac[3], &sta_mac[4], &sta_mac[5]);

            if (!memcpy((unsigned char*) &desc->in.btm_response_event_data.peerMac,
                        (unsigned char*) sta_mac,
                        sizeof(mac_address_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s mac_address_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            if (!memcpy((unsigned char*) &desc->in.btm_response_event_data.response,
                        (unsigned char*) arg3,
                        sizeof(wifi_BTMResponse_t))) {
                wifi_hal_dbg_print("%s:%d FAIL memcpy %s wifi_BTMResponse_t\n", __func__, __LINE__, desc->name);
                return -1;
            }
            break;

        default:
            wifi_hal_dbg_print("%s:%d RFC API %s reached default.\n", __func__, __LINE__, desc->name);
            return -1;
            break;
    }
    return 0;
}
