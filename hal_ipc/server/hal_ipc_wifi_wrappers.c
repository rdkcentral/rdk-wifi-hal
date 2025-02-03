#include "hal_ipc_wifi_wrappers.h"
#include "wifi_hal_priv.h"
#include "hal_ipc.h"

//--------------------------------------------------------------------------------------------------
INT wifi_hal_setRadioStatsEnable(   INT radioIndex,
                                    BOOL enabled)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_dbg_print("%s:%d: \tNOTICE: EMTPY FUNCTION.\n", __func__, __LINE__);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDNumberOfEntries(ULONG *numEntries)
{
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio = NULL;
    ULONG ssid_num = 0;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    // iterate through num radios over all interfaces
    for (int i = 0; i < g_wifi_hal.num_radios; i ++)
    {
      radio = get_radio_by_rdk_index(i);
      if (radio) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL)
        {
          if (((int)interface->vap_info.vap_index >= 0) && (interface->vap_info.vap_mode == wifi_vap_mode_ap)) {
            ssid_num++;
          }
          interface = hash_map_get_next(radio->interface_map, interface);
        }
      }
    }
    *numEntries = ssid_num;

    wifi_hal_dbg_print("%s:%d: Num of SSIDs: %lu.\n", __func__, __LINE__, *numEntries);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceStats(INT apIndex,
                                        mac_address_t *clientMacAddress,
                                        wifi_associated_dev_stats_t *associated_dev_stats,
                                        ULLONG *handle)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_getApAssociatedDeviceStats(apIndex, clientMacAddress, associated_dev_stats, handle);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioChannelStats(INT radioIndex,
                                  wifi_channelStats_t *input_output_channelStats_array,
                                  INT array_size)
{
    wifi_hal_dbg_print("%s:%d: Enter. Array size %d\n", __func__, __LINE__, array_size);

    if (array_size > HAL_IPC_RADIO_CHANNELS_MAX){
        wifi_hal_dbg_print("%s:%d: array_size %d is too big. Truncate.\n", __func__, __LINE__, array_size);
        array_size = HAL_IPC_RADIO_CHANNELS_MAX;
    }

    return wifi_getRadioChannelStats(radioIndex, input_output_channelStats_array, array_size);
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDTrafficStats2(  INT ssidIndex,
                                    wifi_ssidTrafficStats2_t *output_struct)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_getSSIDTrafficStats2(ssidIndex, output_struct);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceRxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_rx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_getApAssociatedDeviceRxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size, handle);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDEnable( INT ssidIndex,
                            BOOL *output_bool)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(ssidIndex);
    if(!interface){
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ssidIndex);
      return RETURN_ERR;
    }
    *output_bool = interface->vap_info.u.bss_info.enabled;

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDRadioIndex( INT ssidIndex,
                                INT *radioIndex)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(ssidIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, ssidIndex);
      return RETURN_ERR;
    }
    *radioIndex = interface->vap_info.radio_index;

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDNameStatus( INT apIndex,
                                CHAR *output_string)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }
    strcpy(output_string, interface->vap_info.u.bss_info.ssid);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApName( INT apIndex,
                        CHAR *output_string)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    if (apIndex >= get_total_num_of_vaps()) {
        wifi_hal_dbg_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    if(get_interface_name_from_vap_index(apIndex, output_string) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:Failed to get ap name for ap index:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: Requested index %d cloud name is %s.\n", __func__, __LINE__, apIndex, output_string);

    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getNeighborReportActivation(   UINT apIndex,
                                            BOOL *activate)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    *activate = interface->vap_info.u.bss_info.nbrReportActivated;

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getBSSTransitionActivation(UINT apIndex,
                                        BOOL *activate)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    *activate = interface->vap_info.u.bss_info.bssTransitionActivated;

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedClientDiagnosticResult( INT apIndex,
                                                    char *mac_addr,
                                                    wifi_associated_dev3_t *dev_conn)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_getApAssociatedClientDiagnosticResult(apIndex, mac_addr, dev_conn);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioOperatingFrequencyBand(INT radioIndex,
                                            CHAR *output_string)
{
    wifi_radio_info_t *radio = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
      wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
      return RETURN_ERR;
    }

    if (radio->oper_param.band == WIFI_FREQUENCY_5_BAND) {
        snprintf(output_string, 64, "5GHz");
    } else if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        snprintf(output_string, 64, "6GHz");
    } else {
        snprintf(output_string, 64, "2.4GHz");
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioNumberOfEntries(ULONG *output)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    *output = g_wifi_hal.num_radios;
    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceTxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_tx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle)
{
    int ret;

    wifi_hal_info_print("%s:%d: Enter...radio_index:%d\n", __func__, __LINE__, radioIndex);

    ret = wifi_getApAssociatedDeviceTxStatsResult(radioIndex, clientMacAddress, stats_array, output_array_size, handle);
    if (ret == RETURN_OK) {
        wifi_associated_dev_rate_info_tx_stats_t *stats_tx = *stats_array;
        int index = 0;
        for (index = 0; index < (int)*output_array_size; index++) {
            wifi_hal_info_print("%s:%d index:%d Radio_Index:%d num of statistics tx array:%d nss:%d mcs:%d bw:%d flags:%lld bytes:%lld msdus:%lld mpdus:%lld ppdus:%lld retries:%lld attempts:%lld\r\n", __func__, __LINE__, index, radioIndex,
                   *output_array_size, stats_tx->nss, stats_tx->mcs, stats_tx->bw, stats_tx->flags,
                   stats_tx->bytes, stats_tx->msdus, stats_tx->mpdus, stats_tx->ppdus, stats_tx->retries, stats_tx->attempts);
            stats_tx++;
        }
    }
    return ret;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getMultiPskClientKey(  INT apIndex,
                                    mac_address_t mac,
                                    wifi_key_multi_psk_t *key)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_dbg_print("%s:%d: \tNOTICE: EMTPY FUNCTION.\n", __func__, __LINE__);
    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_setGroup( UINT steeringgroupIndex,
                                wifi_steering_apConfig_t *cfg_2,
                                wifi_steering_apConfig_t *cfg_5)
{
    if (steeringgroupIndex >= MAX_STEERING_GROUP_NUM) {
        wifi_hal_error_print("%s:%d: Wrong steering group Index:%d\n", __func__, __LINE__, steeringgroupIndex);
        return RETURN_ERR;
    } else if (cfg_2 == NULL || cfg_5 == NULL) {
        wifi_hal_error_print("%s:%d: Wrong steering group Index:%d config\n", __func__, __LINE__, steeringgroupIndex);
        return RETURN_ERR;
    }

    wifi_bm_steering_group_t *p_steer_group;
    p_steer_group = &g_wifi_hal.bm_steer_groups[steeringgroupIndex];

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    p_steer_group->group_index = steeringgroupIndex;
    p_steer_group->group_enable = true;
    memset(p_steer_group->bm_group_info, 0, (MAX_NUM_RADIOS * sizeof(wifi_bm_steering_group_info_t)));
    memcpy(&p_steer_group->bm_group_info[0].config, cfg_2, sizeof(wifi_steering_apConfig_t));
    memcpy(&p_steer_group->bm_group_info[1].config, cfg_5, sizeof(wifi_steering_apConfig_t));

    /* Macfilter deny mode set */
    steering_set_acl_mode(cfg_2->apIndex, wifi_mac_filter_mode_black_list);
    steering_set_acl_mode(cfg_5->apIndex, wifi_mac_filter_mode_black_list);
    wifi_hal_info_print("Wi-Fi steering ApGroup %d CFG: apidx=%d, %d, %d, %d, %d\n",
                            steeringgroupIndex, cfg_2->apIndex,
                            cfg_2->utilCheckIntervalSec, cfg_2->utilAvgCount,
                            cfg_2->inactCheckIntervalSec, cfg_2->inactCheckThresholdSec);
    wifi_hal_info_print("Wi-Fi steering ApGroup %d CFG: apidx=%d, %d, %d, %d, %d\n",
                            steeringgroupIndex, cfg_5->apIndex,
                            cfg_5->utilCheckIntervalSec, cfg_5->utilAvgCount,
                            cfg_5->inactCheckIntervalSec, cfg_5->inactCheckThresholdSec);
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientSet(UINT steeringgroupIndex,
                                INT apIndex, mac_address_t client_mac,
                                wifi_steering_clientConfig_t *config)
{
    wifi_interface_info_t *interface = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    bm_sta_list_t *bm_client_info = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: WiFi interface not found:%d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    bm_client_info = steering_add_stalist(interface, NULL, client_mac, BM_STA_TYPE_CLIENT_SET);
    if (bm_client_info == NULL) {
        wifi_hal_error_print("%s:%d: bm sta_list create failure for ap index %d\n", __func__, __LINE__, apIndex);
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
        return RETURN_ERR;
    } else {
        key = to_mac_str(client_mac, sta_mac_str);
        memcpy(&bm_client_info->bm_client_cfg, config, sizeof(wifi_steering_clientConfig_t));
        if (!config->rssiProbeLWM && !config->rssiProbeHWM) {
            if (wifi_steering_del_mac_list(apIndex, bm_client_info) == RETURN_OK) {
                wifi_hal_info_print("Remove MAC=%s from maclist for vap:%d\n", key, apIndex);
            }
        }
        wifi_hal_info_print("%s:%d: Wi-Fi steering group:%d for vap:%d and client:%s\n", __func__, __LINE__,
                                steeringgroupIndex, apIndex, key);
        wifi_hal_info_print("rssiProbe HWM:%d-LWM:%d rssiAuthHWM:%d-LWM:%d rssiInactXing:%d"
                                "rssiHighXing:%d-Low:%d authRejectReason:%d\n",
                                config->rssiProbeHWM, config->rssiProbeLWM, config->rssiAuthHWM, config->rssiAuthLWM,
                                config->rssiInactXing, config->rssiHighXing, config->rssiLowXing, config->authRejectReason);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);

    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientRemove( UINT steeringgroupIndex,
                                    INT apIndex,
                                    mac_address_t client_mac)
{
    wifi_interface_info_t *interface = NULL;
    bm_sta_list_t *bm_client_info = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    key = to_mac_str(client_mac, sta_mac_str);
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    bm_client_info = hash_map_get(interface->bm_sta_map, key);
    if (bm_client_info != NULL) {
        wifi_hal_info_print("%s:%d: remove client info:%s vap:%d\n", __func__, __LINE__, key, apIndex);
        /* remove from the deny list */
        wifi_steering_del_mac_list(apIndex, bm_client_info);
        steering_del_stalist(interface, bm_client_info->mac_addr, BM_STA_TYPE_CLIENT_SET);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    return nl80211_kick_device(interface, client_mac);
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientDisconnect( UINT steeringgroupIndex,
                                        INT apIndex,
                                        mac_address_t client_mac,
                                        wifi_disconnectType_t type,
                                        UINT reason)
{
    wifi_interface_info_t *interface;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    wifi_hal_info_print("%s:%d: apIndex:%d steeringgroupIndex:%d type:%d reason:%d\n", __func__, __LINE__, apIndex, steeringgroupIndex, type, reason);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    if ((type == DISCONNECT_TYPE_DEAUTH) || (type == DISCONNECT_TYPE_DISASSOC)) {
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        ap_sta_disconnect(&interface->u.ap.hapd, NULL, client_mac, reason);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    } else {
        wifi_hal_info_print("%s:%d: apIndex:%d unknown event type:%d\n", __func__, __LINE__, apIndex, type);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDName(   INT apIndex,
                            CHAR *output_string)
{
    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }

    strcpy(output_string, interface->vap_info.u.bss_info.ssid);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getAssociationReqIEs(  UINT apIndex,
                                    const mac_address_t *clientMacAddress,
                                    CHAR *req_ies,
                                    UINT req_ies_size,
                                    UINT *req_ies_len)
{

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_interface_info_t *interface = NULL;
    struct sta_info *station = NULL;

    interface = get_interface_by_vap_index(apIndex);
    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    station = ap_get_sta(&interface->u.ap.hapd, (const u8 *) clientMacAddress);
    if (req_ies_size < station->assoc_req_len) {
      wifi_hal_error_print("%s:%d: req_ies_size %u is too small (should be at least %zu)\n", __func__, __LINE__, req_ies_size, station->assoc_req_len);
      pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
      return RETURN_ERR;
    }

    memcpy(req_ies, station->assoc_req, station->assoc_req_len);
    *req_ies_len = station->assoc_req_len;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioCountryCode(   INT radioIndex,
                                    CHAR *output_string)
{
    wifi_radio_info_t *radio;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
        wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
        return -1;
    }

    get_coutry_str_from_code(radio->oper_param.countryCode, output_string);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioOperatingChannelBandwidth( INT radioIndex,
                                                CHAR *output_string)
{
    wifi_radio_info_t *radio = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    radio = get_radio_by_rdk_index(radioIndex);

    if(!radio){
      wifi_hal_error_print("%s:%d: radio pointer is NULL!.\n", __func__, __LINE__);
      return RETURN_ERR;
    }

    switch (radio->oper_param.channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            snprintf(output_string, 6, "20MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            snprintf(output_string, 6, "40MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            snprintf(output_string, 6, "80MHz");
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            snprintf(output_string, 7, "160MHz");
            break;

        default:
            snprintf(output_string, 6, "20MHz");
            break;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioTransmitPower( INT radioIndex,
                                    ULONG *output_ulong)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    /*
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(radioIndex);

    if (!radio){
        wifi_hal_dbg_print("%s:%d: radio info for index %d is NULL.\n", __func__, __LINE__, radioIndex);
        return -1;
    }

    *output_ulong = radio->oper_param.transmitPower;
    */

    wifi_getRadioTransmitPower(radioIndex, output_ulong);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    wifi_interface_info_t *interface = NULL;
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);
    interface = get_interface_by_vap_index(apIndex);

    if(!interface) {
      wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
      return RETURN_ERR;
    }
    interface->vap_info.u.bss_info.nbrReportActivated = activate;

    return 0;
}

struct ovs_radioname_cloudradioname_map {
    unsigned int radio_index;
    char cloudradioname[64];
    char gw_radio_name[64];
};

struct ovs_radioname_cloudradioname_map cloud_radio_map[] = {
    {0, "wl0", "wlan0"},
    {1, "wl1", "wlan2"}
};

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioIfName(INT radioIndex, CHAR *output_string)
{
    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    if (radioIndex > g_wifi_hal.num_radios){
        wifi_hal_dbg_print("%s:%d: radio index %d out of range.\n", __func__, __LINE__, radioIndex);
        return -1;
    }

    if (!output_string){
        wifi_hal_error_print("%s:%d: NULL pointer string passed.\n", __func__, __LINE__);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Requested radio index %d GW name %s translated to cloud name %s .\n", __func__, __LINE__,
                                radioIndex, cloud_radio_map[radioIndex].gw_radio_name, cloud_radio_map[radioIndex].cloudradioname);

    strcpy(output_string, cloud_radio_map[radioIndex].cloudradioname);

    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
    wifi_interface_info_t *interface = NULL;

    wifi_hal_dbg_print("%s:%d: Enter.\n", __func__, __LINE__);

    interface = get_interface_by_vap_index(apIndex);
    if (!interface)
    {
        wifi_hal_error_print("%s:%d: ERROR Interface for vap index %d doesn't exist.\n", __func__, __LINE__, apIndex);
        return -1;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *output_ulong = interface->u.ap.hapd.num_sta;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_dbg_print("%s:%d: AP index %d, num assoc devs: %lu.\n", __func__, __LINE__, apIndex, *output_ulong);

    return 0;
}
