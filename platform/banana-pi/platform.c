/************************************************************************
* If not stated otherwise in this file or this component's Licenses.txt
* file the following copyright and licenses apply:
*
* Copyright 2024 RDK Management
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
*
* Some material is:
* Copyright (c) 2002-2015, Jouni Malinen j@w1.fi
* Copyright (c) 2003-2004, Instant802 Networks, Inc.
* Copyright (c) 2005-2006, Devicescape Software, Inc.
* Copyright (c) 2007, Johannes Berg johannes@sipsolutions.net
* Copyright (c) 2009-2010, Atheros Communications
* Licensed under the BSD-3 License
**************************************************************************/

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"
#include "platform.h"

#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define BPI_LEN_32 32
#define BPI_LEN_16 16
#define MAX_KEYPASSPHRASE_LEN 129
#define MAX_SSID_LEN 33
#define INVALID_KEY  "12345678"

int wifi_nvram_defaultRead(char *in,char *out);
int _syscmd(char *cmd, char *retBuf, int retBufSize);

typedef struct {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

csi_info_map_t csi_radio_info[MAX_NUM_RADIOS];

int wifi_nvram_defaultRead(char *in,char *out)
{
    char buf[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *position;

    snprintf(cmd,MAX_CMD_SIZE,"grep '%s=' /nvram/wifi_defaults.txt",in);
    if(_syscmd(cmd,buf,sizeof(buf)) == -1)
    {
        wifi_hal_dbg_print("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return -1;
    }

    if (buf[0] == NULL_CHAR)
        return -1;
    position = buf;
    while(*position != NULL_CHAR)
    {
        if (*position == NEW_LINE)
        {
            *position = NULL_CHAR;
            break;
        }
        position++;
    }
    position = strchr(buf, '=');
    if (position == NULL)
    {
        wifi_hal_dbg_print("Line %d: invalid line '%s'",__LINE__, buf);
        return -1;
    }
    *position = NULL_CHAR;
    position++;
    strncpy(out,position,strlen(position)+1);
    return 0; 
}

static int json_parse_backhaul_keypassphrase(char *backhaul_keypassphrase)
{
    return json_parse_string(EM_CFG_FILE, "Backhaul_KeyPassphrase", backhaul_keypassphrase,
        MAX_KEYPASSPHRASE_LEN);
}

static int json_parse_backhaul_ssid(char *backhaul_ssid)
{
    return json_parse_string(EM_CFG_FILE, "Backhaul_SSID", backhaul_ssid, MAX_SSID_LEN);
}

int platform_pre_init()
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    system("brctl addif brlan0 wifi0");
    system("brctl addif brlan0 wifi1");
    system("brctl addif brlan0 wifi2");
    return 0;
}


int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    /* if the vap_index is that of mesh STA then try to obtain the ssid from
       /nvram/EasymeshCfg.json file */
    if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        if (!json_parse_backhaul_keypassphrase(password)) {
            wifi_hal_dbg_print("%s:%d, read password from jSON file\n", __func__, __LINE__);
            return 0;
        }
    }
    /*password is not sensitive,won't grant access to real devices*/ 
    wifi_nvram_defaultRead("bpi_wifi_password",password);
    if (strlen(password) == 0) {
        wifi_hal_error_print("%s:%d nvram default password not found, "
                             "enforced alternative default password\n",
            __func__, __LINE__);
        strncpy(password, INVALID_KEY, strlen(INVALID_KEY) + 1);
    }
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n", __func__, __LINE__);
    /* if the vap_index is that of mesh STA or mesh backhaul then try to obtain the ssid from
       /nvram/EasymeshCfg.json file */
    if (is_wifi_hal_vap_mesh_sta(vap_index)) {
        if (!json_parse_backhaul_ssid(ssid)) {
            wifi_hal_dbg_print("%s:%d, read SSID:%s from jSON file\n", __func__, __LINE__, ssid);
            return 0;
        }
    }
    snprintf(ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    wifi_nvram_defaultRead("wps_pin",pin);
    return 0;
}

int platform_wps_event(wifi_wps_event_t data)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    return 0;
}

int platform_get_country_code_default(char *code)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);  
    strcpy(code,"US");
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    /*password is not sensitive,won't grant access to real devices*/ 
    wifi_nvram_defaultRead("bpi_wifi_password",l_password);
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__); 
    snprintf(l_ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char output_val[BPI_LEN_32];
    int i;
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);

    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
    }
    for (i = 0; i < map->num_vaps; i++)
    {
      if (map->vap_array[i].vap_mode == wifi_vap_mode_ap)
      {
	    if ((get_security_mode_support_radius(map->vap_array[i].u.bss_info.security.mode)) || is_wifi_hal_vap_lnf_radius(map->vap_array[i].vap_index) || is_wifi_hal_vap_hotspot_secure(map->vap_array[i].vap_index)) {
	//   Assigning default radius values
	    wifi_nvram_defaultRead("radius_s_port",output_val);
	    map->vap_array[i].u.bss_info.security.u.radius.s_port = atoi(output_val);
	    map->vap_array[i].u.bss_info.security.u.radius.port = atoi(output_val);
	    wifi_nvram_defaultRead("radius_s_ip",map->vap_array[i].u.bss_info.security.u.radius.s_ip);
	    wifi_nvram_defaultRead("radius_s_ip",map->vap_array[i].u.bss_info.security.u.radius.ip);
	    wifi_nvram_defaultRead("radius_key",map->vap_array[i].u.bss_info.security.u.radius.s_key);
	    wifi_nvram_defaultRead("radius_key",map->vap_array[i].u.bss_info.security.u.radius.key);
	    }
      }
    }
    return 0;
}

int platform_flags_init(int *flags)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    *flags = PLATFORM_FLAGS_STA_INACTIVITY_TIMER;
    return 0;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_free_aid(void* priv, u16* aid)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_sync_done(void* priv)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_get_chanspec_list(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, wifi_channels_list_t channels, char *buff)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_set_acs_exclusion_list(wifi_radio_index_t index,char *buff)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_update_radio_presence(void)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_set_txpower(void* priv, uint txpower)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_set_offload_mode(void* priv, uint offload_mode)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return RETURN_OK;
}

int platform_get_radius_key_default(char *radius_key)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    wifi_nvram_defaultRead("radius_key",radius_key);
    return 0;	
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    return 0;
}

int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    return -1;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    return 0;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    return 0;
}

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    return wifi_hal_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list);
}

int wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return wifi_hal_getNeighboringWiFiStatus(radio_index, neighbor_ap_array, output_array_size);
}

int wifi_setQamPlus(void *priv)
{
    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    return 0;
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
#ifdef CONFIG_IEEE80211BE
#if HOSTAPD_VERSION >= 211
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d failed to get radio for index\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    for (interface = hash_map_get_first(radio->interface_map); interface != NULL;
        interface = hash_map_get_next(radio->interface_map, interface)) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            continue;
        }

	struct hostapd_iface *iface = &interface->u.ap.iface;
        if (strstr(interface->vap_info.vap_name, "private_ssid_5g")) {
	    for (int i = 0; i < iface->num_hw_features; i++) {
                iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].eht_supported = true;
	    }
        } else if (strstr(interface->vap_info.vap_name, "private_ssid_6g")) {
	    for (int i = 0; i < iface->num_hw_features; i++) {
                iface->hw_features[i].eht_capab[IEEE80211_MODE_AP].eht_supported = true;
	    }
        }
    }
#endif /* HOSTAPD_VERSION >= 211 */
#endif /* CONFIG_IEEE80211BE */
    return RETURN_OK;
}

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    int res = wifi_hal_send_mgmt_frame(apIndex, MacAddr, frame, len, frequency, wait);
    return (res == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_ERROR;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, MacAddr, frequency, 0, frame, len);
}

INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
    return 0;
}

INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    return RETURN_OK;
}

static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    sta_list_t *sta_list = (sta_list_t *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_MAC]) {
        sta_list->macs = realloc(sta_list->macs, (sta_list->num + 1) * sizeof(mac_address_t));
        if (sta_list->macs) {
            memcpy(sta_list->macs[sta_list->num], nla_data(tb[NL80211_ATTR_MAC]), sizeof(mac_address_t));
            sta_list->num++;
        }
    }

    return NL_OK;
}

static int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret;
    struct nl_msg *msg = NULL;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, get_sta_list_handler, sta_list, NULL, NULL);
    if (ret < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to execute NL command\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

static int get_sta_stats_handler(struct nl_msg *msg, void *arg)
{
    wifi_associated_dev3_t *dev = (wifi_associated_dev3_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
                [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
                [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
                [NL80211_STA_INFO_CONNECTED_TIME] = { .type = NLA_U32 },
    };
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
                [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
    };
    struct nl80211_sta_flag_update *sta_flags;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_error_print("%s:%d Failed to get sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_MAC]) {
        memcpy(dev->cli_MACAddress, nla_data(tb[NL80211_ATTR_MAC]), sizeof(mac_address_t));
    }

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
	wifi_hal_error_print("%s:%d Failed to parse nested attributes\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (stats[NL80211_STA_INFO_RX_BYTES]) {
        dev->cli_BytesReceived = nla_get_u32(stats[NL80211_STA_INFO_RX_BYTES]);
    }
    if (stats[NL80211_STA_INFO_TX_BYTES]) {
        dev->cli_BytesSent = nla_get_u32(stats[NL80211_STA_INFO_TX_BYTES]);
    }
    if (stats[NL80211_STA_INFO_RX_PACKETS]) {
        dev->cli_PacketsReceived = nla_get_u32(stats[NL80211_STA_INFO_RX_PACKETS]);
    }
    if (stats[NL80211_STA_INFO_TX_PACKETS]) {
        dev->cli_PacketsSent = nla_get_u32(stats[NL80211_STA_INFO_TX_PACKETS]);
    }
    if (stats[NL80211_STA_INFO_TX_FAILED]) {
        dev->cli_ErrorsSent = nla_get_u32(stats[NL80211_STA_INFO_TX_FAILED]);
    }

    if (stats[NL80211_STA_INFO_TX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_TX_BITRATE], rate_policy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32]){
            dev->cli_LastDataDownlinkRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
    }
    if (stats[NL80211_STA_INFO_RX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_RX_BITRATE], rate_policy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32]) {
                dev->cli_LastDataUplinkRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
    }

    if (stats[NL80211_STA_INFO_STA_FLAGS]) {
        sta_flags = nla_data(stats[NL80211_STA_INFO_STA_FLAGS]);
        dev->cli_AuthenticationState = sta_flags->mask & (1 << NL80211_STA_FLAG_AUTHORIZED) &&
            sta_flags->set & (1 << NL80211_STA_FLAG_AUTHORIZED);
    }

    return NL_OK;
}

static int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac, wifi_associated_dev3_t *dev)
{
    int ret;
    struct nl_msg *msg = NULL;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), mac);

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, dev, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to execute NL command\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex,
    wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    int ret;
    unsigned int i;
    sta_list_t sta_list = {};
    wifi_interface_info_t *interface;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__, apIndex);
        return -1;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    *associated_dev_array = sta_list.num ?
        calloc(sta_list.num, sizeof(wifi_associated_dev3_t)) : NULL;
    *output_array_size = sta_list.num;

    for (i = 0; i < sta_list.num; i++) {
        ret = get_sta_stats(interface, sta_list.macs[i], &(*associated_dev_array)[i]);
        if (ret < 0) {
            wifi_hal_stats_error_print("%s:%d Failed to get sta stats\n", __func__, __LINE__);
            free(*associated_dev_array);
            *associated_dev_array = NULL;
            *output_array_size = 0;
            goto exit;
        }
    }

exit:
    free(sta_list.macs);
    return ret;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    return RETURN_ERR;
}

UINT wifi_freq_to_op_class(UINT freq)
{
    u8 op_class, channel;

    if (ieee80211_freq_to_channel_ext(freq, 0, 0, &op_class, &channel) == NUM_HOSTAPD_MODES){
        wifi_hal_error_print("%s:%d Failed to get op class for freq : %d\n", __func__, __LINE__, freq);
        return RETURN_ERR;
    }

    return op_class;
}

INT wifi_setProxyArp(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_setCountryIe(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled)
{
    return 0;
}

INT wifi_getCountryIe(INT apIndex, BOOL *enabled)
{
    return 0;
}

INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled)
{
    return 0;
}

INT wifi_getProxyArp(INT apIndex, BOOL *enabled)
{
    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getBssLoad(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled)
{
    return 0;
}

INT wifi_setBssLoad(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_getApAssociatedClientDiagnosticResult(INT ap_index, char *key,wifi_associated_dev3_t *assoc)
{
    return RETURN_ERR;
}

INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled)
{
    return 0;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}

INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
    return 0;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    return 0;
}

#ifdef CONFIG_IEEE80211BE
int nl80211_drv_mlo_msg(struct nl_msg *msg, struct nl_msg **msg_mlo, void *priv,
    struct wpa_driver_ap_params *params)
{
    (void)msg;
    (void)msg_mlo;
    (void)priv;
    (void)params;

    return 0;
}

int nl80211_send_mlo_msg(struct nl_msg *msg)
{
    (void)msg;

    return 0;
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
    (void)eht_capab;
    (void)tb;
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
    (void)interface;

    return 0;
}
#endif /* CONFIG_IEEE80211BE */

csi_info_map_t *get_csi_radio_info_map(uint8_t radio_index)
{
    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_hal_error_print("%s:%d: wrong radio index:%d\n", __func__, __LINE__, radio_index);
        return NULL;
    }

    return &csi_radio_info[radio_index];
}

int add_link_elem_info(link_element_t **head, void *data, uint32_t data_len)
{
    link_element_t *temp = malloc(sizeof(link_element_t));
    if (temp == NULL) {
        wifi_hal_error_print("%s:%d: memory alloc is falied\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    temp->data = malloc(data_len);
    if (temp->data == NULL) {
        wifi_hal_error_print("%s:%d: memory alloc is falied for data:%d\n",
            __func__, __LINE__, data_len);
        return RETURN_ERR;
    }

    memcpy(temp->data, data, data_len);

    temp->next = *head;
    *head = temp;

    return RETURN_OK;
}

void *pick_link_elem_info(link_element_t *head, void *data, uint32_t data_len)
{
    while(head) {
        if (memcmp(head->data, data, data_len) == 0) {
            return head->data;
        }
        head = head->next;
    }

    return NULL;
}

int del_link_elem_info(link_element_t **head, void *data, uint32_t data_len)
{
    link_element_t *cur = *head, *pre;

    if (cur == NULL) {
        return RETURN_ERR;
    }

    if (cur->data && (memcmp(cur->data, data, data_len) == 0)) {
        free(cur->data);
        *head = cur->next;
    } else {
        pre = cur;
        cur = cur->next;
        while(cur) {
            if (cur->data && (memcmp(cur->data, data, data_len) == 0)) {
                free(cur->data);
                pre->next = cur->next;
                free(cur);
                return RETURN_OK;
            }
            pre = cur;
            cur = cur->next;
        }
    }

    return RETURN_ERR;
}

bool is_link_elem_data_present(link_element_t *head, void *data, uint32_t data_len)
{
    while(head) {
        if (memcmp(head->data, data, data_len) == 0) {
            return true;
        }
        head = head->next;
    }

    return false;
}

int set_csi_radio_info_map(uint8_t radio_index, bool status, uint8_t *sta_mac)
{
    csi_info_map_t *csi_map = get_csi_radio_info_map(radio_index);

    if (csi_map == NULL) {
        return RETURN_ERR;
    }

    csi_map->csi_active_radio = status;
    if (status) {
        return add_link_elem_info(&csi_map->sta_info, sta_mac, ETH_ALEN);
    } else {
        return del_link_elem_info(&csi_map->sta_info, sta_mac, ETH_ALEN);
    }
}

int nl80211_csi_set(uint8_t radio_index, uint8_t mode, uint8_t cfg, uint8_t value1, uint32_t value2, uint8_t *mac)
{
    struct nl_msg *msg;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio = NULL;
    struct nlattr *nlattr_vendor = NULL;
    struct nlattr *tb1 = NULL, *tb2 = NULL;
    int ret = RETURN_ERR;

    wifi_hal_dbg_print("%s:%d: set csi for radio index:%d mode:%d cfg:%d value1:%d value2:%d\n", __func__,
        __LINE__, radio_index, mode, cfg, value1, value2);
    radio = get_radio_by_rdk_index(radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index:%d\n", __func__, __LINE__,
            radio_index);
        return ret;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for radio index:%d\n", __func__,
            __LINE__, radio_index);
        return ret;
    }

    // Create the vendor-specific command message
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, RDKB_OUI_MTK,
        NL80211_MTK_VENDOR_SUB_CMD_CSI);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
        return ret;
    }

    nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
    if (!nlattr_vendor) {
        wifi_hal_error_print("%s:%d: Failed to set nest vendor data\n", __func__, __LINE__);
        goto fail;
    }

    tb1 = nla_nest_start(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG | NLA_F_NESTED);
    if (!tb1) {
        wifi_hal_error_print("%s:%d: Failed to set nl attr csi cfg for radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }

    if (nla_put_u8(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_MODE, mode) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set mode attr for radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }
    if (nla_put_u8(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_TYPE, cfg) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set type attr for radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }
    if (nla_put_u8(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL1, value1) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set val1 attr for radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }
    if (nla_put_u32(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL2, value2) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set val2 attr for radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }

    nla_nest_end(msg, tb1);

    if (mac) {
        tb2 = nla_nest_start(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR | NLA_F_NESTED);
        if (!tb2) {
            wifi_hal_error_print("%s:%d: Failed to set nl attr csi mac for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            goto fail;
        }

        wifi_hal_info_print("%s:%d: csi set mac for radio_index:%d\n",
                __func__, __LINE__, radio_index);
        for (uint32_t i = 0; i < ETH_ALEN; i++) {
            wifi_hal_info_print("%x\n", mac[i]);
            nla_put_u8(msg, i, mac[i]);
        }

        nla_nest_end(msg, tb2);
    }

    if (nla_put_u8(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_BAND_IDX, radio_index) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set nl radio_index:%d\n", __func__, __LINE__, radio_index);
        goto fail;
    }

    nla_nest_end(msg, nlattr_vendor);

    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d:Failed to set csi. ret=%d (%s)",
                        __func__, __LINE__, ret, strerror(-ret));
    }

    wifi_hal_info_print("%s:%d: set csi success for radio_index:%d\n", __func__, __LINE__, radio_index);
    return ret;
fail:
    nlmsg_free(msg);
    return ret;
}

#ifdef DEBUG_LOGS
void wifi_hexdump(const char *title, const uint8_t *buf, size_t len)
{
    size_t i;
    static FILE *fpg = NULL;

    if ((access("/nvram/wifiHexDump", R_OK)) == 0) {
        if (fpg == NULL) {
            fpg = fopen("/tmp/wifiCsiHex", "a+");
            if (fpg == NULL) {
                return;
            }
        }

        fprintf(fpg, "%s - hexdump(len=%lu):", title, (unsigned long) len);

        if (buf == NULL) {
            fprintf(fpg, " [NULL]");
        } else {
            for (i = 0; i < len; i++) {
                fprintf(fpg, " %02x", buf[i]);
                if ((i != 0) && (i % 16 == 0)) {
                    fprintf(fpg, "\n");
                }
            }
        }

        fprintf(fpg, "\n");
        fflush(fpg);
    }
}
#endif

static int mt76_csi_dump_cb(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb1[NL_NUM_MTK_VENDOR_ATTRS_CSI_CTRL];
    struct nlattr *tb2[NL_NUM_MTK_VENDOR_ATTRS_CSI_DATA];
    struct nlattr *attr, *cur, *data;
    int len = 0, rem, idx;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct csi_resp_data *csi_resp = (struct csi_resp_data *)arg;
    struct csi_data *csi_data_info = csi_resp->csi_buf;
    mac_address_t sta_mac = { 0 };
    mac_address_t null_mac = { 0 };
    mac_address_t broadcast_mac;

    memset(broadcast_mac, 0xff, ETH_ALEN);

    struct nla_policy csi_ctrl_policy[NL_NUM_MTK_VENDOR_ATTRS_CSI_CTRL] = {
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_BAND_IDX] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG] = { .type = NLA_NESTED },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_MODE] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_TYPE] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL1] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL2] = { .type = NLA_U32 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR] = { .type = NLA_NESTED },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM] = { .type = NLA_U16 },
        [NL_MTK_VENDOR_ATTR_CSI_CTRL_DATA] = { .type = NLA_NESTED },
    };

    struct nla_policy csi_data_policy[NL_NUM_MTK_VENDOR_ATTRS_CSI_DATA] = {
        [NL_MTK_VENDOR_ATTR_CSI_DATA_VER] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_TS] = { .type = NLA_U32 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_RSSI] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_SNR] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_BW] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_CH_IDX] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_TA] = { .type = NLA_NESTED },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_NUM] = { .type = NLA_U32 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_I] = { .type = NLA_NESTED },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_Q] = { .type = NLA_NESTED },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_INFO] = { .type = NLA_U32 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_TX_ANT] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_RX_ANT] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_MODE] = { .type = NLA_U8 },
        [NL_MTK_VENDOR_ATTR_CSI_DATA_CHAIN_INFO] = { .type = NLA_U32 },
    };

    if (csi_resp->usr_need_cnt <= csi_resp->buf_cnt) {
        wifi_hal_error_print("%s:%d: csi data buffer overflow: max:%d cur:%d\n",
            __func__, __LINE__, csi_resp->usr_need_cnt, csi_resp->buf_cnt);
        return NL_SKIP;
    }

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);

    attr = tb[NL80211_ATTR_VENDOR_DATA];
    if (!attr) {
        wifi_hal_error_print("%s:%d: csi data attr is NULL\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nla_parse_nested(tb1, NL_MTK_VENDOR_ATTR_CSI_CTRL_MAX, attr, csi_ctrl_policy);

    if (!tb1[NL_MTK_VENDOR_ATTR_CSI_CTRL_DATA]) {
        wifi_hal_error_print("%s:%d: csi data tb1 attr is NULL\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nla_parse_nested(tb2, NL_MTK_VENDOR_ATTR_CSI_DATA_MAX,
        tb1[NL_MTK_VENDOR_ATTR_CSI_CTRL_DATA], csi_data_policy);

    if (!(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_VER] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_TS] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_RSSI] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_SNR] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_BW] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_CH_IDX] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_TA] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_I] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_Q] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_INFO] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_MODE] &&
        tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_CHAIN_INFO])) {
        wifi_hal_error_print("%s:%d:Attributes error for CSI data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    idx = 0;
    nla_for_each_nested(cur, tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_TA], rem) {
    if (idx < ETH_ALEN)
        sta_mac[idx++] = nla_get_u8(cur);
    }

    if ((memcmp(sta_mac, null_mac, ETH_ALEN) == 0) ||
        (memcmp(sta_mac, broadcast_mac, ETH_ALEN) == 0)) {
        wifi_hal_dbg_print("%s:%d null/broadcast:" MACSTR " packet is skip\n",
            __func__, __LINE__, MAC2STR(sta_mac));
        return NL_SKIP;
    }

    csi_data_info += csi_resp->buf_cnt;

    memcpy(csi_data_info->ta, sta_mac, ETH_ALEN);

    csi_data_info->rssi = nla_get_u8(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_RSSI]);
    csi_data_info->snr = nla_get_u8(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_SNR]);
    csi_data_info->data_bw = nla_get_u8(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_BW]);
    csi_data_info->pri_ch_idx = nla_get_u8(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_CH_IDX]);
    csi_data_info->rx_mode = nla_get_u8(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_MODE]);

    csi_data_info->tx_idx = nla_get_u16(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_TX_ANT]);
    csi_data_info->rx_idx = nla_get_u16(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_RX_ANT]);

    csi_data_info->ext_info = nla_get_u32(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_INFO]);
    csi_data_info->chain_info = nla_get_u32(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_CHAIN_INFO]);

    csi_data_info->ts = nla_get_u32(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_TS]);

    csi_data_info->data_num = nla_get_u32(tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_NUM]);

    idx = 0;
    nla_for_each_nested(cur, tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_I], rem) {
    if (idx < csi_data_info->data_num)
        csi_data_info->data_i[idx++] = nla_get_u16(cur);
    }

    idx = 0;
    nla_for_each_nested(cur, tb2[NL_MTK_VENDOR_ATTR_CSI_DATA_Q], rem) {
    if (idx < csi_data_info->data_num)
        csi_data_info->data_q[idx++] = nla_get_u16(cur);
    }

    csi_resp->buf_cnt++;

    return NL_SKIP;
}

int nl80211_csi_dump(uint8_t radio_index, void *dump_buf)
{
    struct nl_msg *msg;
    struct nlattr *data;
    int ret = RETURN_ERR;
    struct csi_resp_data *csi_resp;
    uint16_t pkt_num, i;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio = NULL;

    if (dump_buf == NULL) {
        wifi_hal_error_print("%s:%d: wrong nl csi resp buffer data\n", __func__, __LINE__);
        return ret;
    }

    csi_resp = (csi_resp_data_t *)dump_buf;
    pkt_num =  csi_resp->usr_need_cnt / 2;

    if (pkt_num > MAX_CSI_DUMP_PKT_CNT) {
        wifi_hal_error_print("%s:%d: wrong nl csi dump packet num:%d\n", __func__, __LINE__, pkt_num);
        return ret;
    }

    wifi_hal_dbg_print("%s:%d: dump csi data for radio index:%d packet num:%d\n", __func__,
        __LINE__, radio_index, pkt_num);
    radio = get_radio_by_rdk_index(radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index:%d\n", __func__, __LINE__,
            radio_index);
        return ret;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for radio index:%d\n", __func__,
            __LINE__, radio_index);
        return ret;
    }

    for (i = 0; i < pkt_num / CSI_DUMP_PER_NUM; i++) {
        // Create the vendor-specific command message
        msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, RDKB_OUI_MTK,
            NL80211_MTK_VENDOR_SUB_CMD_CSI);
        //msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, RDKB_OUI_MTK,
            //NL80211_MTK_VENDOR_SUB_CMD_CSI);
        if (msg == NULL) {
            wifi_hal_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
            return ret;
        }

        data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA | NLA_F_NESTED);
        if (!data) {
            goto fail;
        }

        if (nla_put_u16(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM, CSI_DUMP_PER_NUM) < 0) {
            wifi_hal_error_print("%s:%d: Failed to set csi cnt attr for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            goto fail;
        }
        if (nla_put_u8(msg, NL_MTK_VENDOR_ATTR_CSI_CTRL_BAND_IDX, radio_index) < 0) {
            wifi_hal_error_print("%s:%d: Failed to set csi band attr for radio_index:%d\n",
                __func__, __LINE__, radio_index);
            goto fail;
        }

        nla_nest_end(msg, data);

        if (nl80211_send_and_recv(msg, mt76_csi_dump_cb, dump_buf, NULL, NULL)) {
            wifi_hal_error_print("%s:%d: Error getting sta info\n", __func__, __LINE__);
            goto fail;
        }
        //usleep(10 * 1000);//10 ms
    }

    wifi_hal_info_print("%s:%d: csi data dump is success for radio_index:%d\n", __func__,
        __LINE__, radio_index);
    return RETURN_OK;
fail:
    nlmsg_free(msg);
    return ret;
}

void wlan_wifi_parse_csi_matrix_data(csi_data_t *drv_csi_data, wifi_csi_data_t *hal_csi_data)
{
    uint32_t index;

#ifdef DEBUG_LOGS
    wifi_hexdump("rx_idex", &drv_csi_data->rx_idx, sizeof(drv_csi_data->rx_idx));
    wifi_hexdump("higher data_i", drv_csi_data->data_i, drv_csi_data->data_num);
    wifi_hexdump("lower data_q", drv_csi_data->data_q, drv_csi_data->data_num);
#endif
    for (index = 0; index < drv_csi_data->data_num; index++) {
        hal_csi_data->csi_matrix[index][drv_csi_data->rx_idx][0] =
            COMBINE_SHORTS_TO_UINT(drv_csi_data->data_i[index], drv_csi_data->data_q[index]);
    }
    hal_csi_data->frame_info.Nr = drv_csi_data->rx_idx;
    hal_csi_data->frame_info.Nc = drv_csi_data->tx_idx;
    hal_csi_data->frame_info.num_sc = drv_csi_data->data_num;
}

void append_second_stream_data(csi_data_t *drv_csi_data, wifi_csi_data_t *hal_csi_data)
{
    uint32_t index;

#ifdef DEBUG_LOGS
    wifi_hexdump("append rx_idex", &drv_csi_data->rx_idx, sizeof(drv_csi_data->rx_idx));
    wifi_hexdump("append higher data_i", drv_csi_data->data_i, drv_csi_data->data_num);
    wifi_hexdump("append lower data_q", drv_csi_data->data_q, drv_csi_data->data_num);
#endif
    for (index = 0; index < drv_csi_data->data_num; index++) {
        hal_csi_data->csi_matrix[index][drv_csi_data->rx_idx][0] =
            COMBINE_SHORTS_TO_UINT(drv_csi_data->data_i[index], drv_csi_data->data_q[index]);
    }
    if (drv_csi_data->rx_idx > hal_csi_data->frame_info.Nr) {
        hal_csi_data->frame_info.Nr = drv_csi_data->rx_idx;
    }
    if (drv_csi_data->tx_idx > hal_csi_data->frame_info.Nc) {
        hal_csi_data->frame_info.Nc = drv_csi_data->tx_idx;
    }
    hal_csi_data->frame_info.num_sc = drv_csi_data->data_num;
}

int convert_wifi_drv_to_hal_csi_data(csi_data_t *drv_csi_data, wifi_csi_data_t *hal_csi_data,
    uint8_t *sta_mac)
{
    mac_addr_str_t sta_mac_str;

    memcpy(sta_mac, drv_csi_data->ta, ETH_ALEN);

    hal_csi_data->frame_info.time_stamp = drv_csi_data->ts;
    hal_csi_data->frame_info.channel = drv_csi_data->chain_info;

    wlan_wifi_parse_csi_matrix_data(drv_csi_data, hal_csi_data);

    //Remaining params I will do it later
#ifdef DEBUG_LOGS
    wifi_hal_info_print("%s:%d CSI data for sta:%s time:%llu ch:%d\r\n",
        __func__, __LINE__, to_mac_str(sta_mac, sta_mac_str),
        hal_csi_data->frame_info.time_stamp, hal_csi_data->frame_info.channel);
    wifi_hal_info_print("%s:%d CSI data size:%u time:%llu\r\n",
        __func__, __LINE__, drv_csi_data->data_num, drv_csi_data->ts);
#endif
}

void send_user_csi_data(csi_resp_data_t *csi_rsp_data)
{
    uint16_t index;
    wifi_csi_data_t hal_csi = { 0 };
    wifi_device_callbacks_t *callbacks;
    mac_address_t sta_mac = { 0 };
    uint8_t *mac;
    csi_data_t pre_csi_data;
    bool is_trigger_data_set = false;
    mac_addr_str_t sta_mac_str;

    memset(&pre_csi_data, 0, sizeof(pre_csi_data));
    //memset(broadcast_mac, 0xff, ETH_ALEN);

    callbacks = get_hal_device_callbacks();

    for (index = 0; index < csi_rsp_data->buf_cnt; index++) {
        mac = csi_rsp_data->csi_buf[index].ta;
        csi_data_t *drv_csi_data = &csi_rsp_data->csi_buf[index];
        wifi_hal_dbg_print("frame:[%s] rx_idx:%d tx_idx:%d sc:%d time:%llu, pre_time:%llu\r\n", to_mac_str(mac, sta_mac_str),
            drv_csi_data->rx_idx, drv_csi_data->tx_idx, drv_csi_data->data_num, drv_csi_data->ts, pre_csi_data.ts);
        //convert driver to Onewifi frame packet.
        if (pre_csi_data.ts != csi_rsp_data->csi_buf[index].ts) {
            if ((is_trigger_data_set == true) && callbacks && callbacks->csi_callback) {
                callbacks->csi_callback(sta_mac, &hal_csi);
                is_trigger_data_set = false;
            } else if (is_trigger_data_set == false) {
                wifi_hal_info_print("%s:%d is_trigger_data_set is false\n", __func__, __LINE__);
            } else {
                wifi_hal_info_print("%s:%d wifi csi callback is NULL\n", __func__, __LINE__);
            }
            convert_wifi_drv_to_hal_csi_data(&csi_rsp_data->csi_buf[index],
                &hal_csi, (uint8_t *)sta_mac);
            memcpy(&pre_csi_data, &csi_rsp_data->csi_buf[index], sizeof(csi_data_t));
        } else {
            append_second_stream_data(&csi_rsp_data->csi_buf[index], &hal_csi);
            is_trigger_data_set = true;
        }
    }

    if ((is_trigger_data_set == true) && callbacks && callbacks->csi_callback) {
        callbacks->csi_callback(sta_mac, &hal_csi);
        is_trigger_data_set = false;
    } else if (is_trigger_data_set == false) {
        wifi_hal_info_print("%s:%d is_trigger_data_set is false\n", __func__, __LINE__);
    } else {
        wifi_hal_info_print("%s:%d wifi csi callback is NULL\n", __func__, __LINE__);
    }
}

unsigned long long int get_cur_ms_time(void)
{
    struct timeval tv_now = { 0 };
    unsigned long long int milliseconds = 0;
    gettimeofday(&tv_now, NULL);
    milliseconds = (tv_now.tv_sec*1000LL + tv_now.tv_usec/1000);
    return milliseconds;
}

uint32_t dump_total_csi_packets(unsigned long long int curr_time_ms,
    unsigned long long int old_time_ms)
{
    uint32_t diff_time_ms;
    uint32_t pkt_num = 0;

    curr_time_ms = get_cur_ms_time();
    diff_time_ms = curr_time_ms - old_time_ms;

    pkt_num = (diff_time_ms / MAX_READ_CSI_PKT_INTERVAL) * 4;
    if (pkt_num > MAX_CSI_DUMP_PKT_CNT) {
        wifi_hal_info_print("%s:%d:wrong packet size:%d, time diff:%d, new time:%llu old:%llu\n",
            __func__, __LINE__, pkt_num, diff_time_ms, curr_time_ms, old_time_ms);
        pkt_num = MAX_CSI_DUMP_PKT_CNT;
    }

    return pkt_num;
}

void *csi_data_get_from_driver(void *data)
{
    uint32_t radio_index = 0, csi_rsp_buff_len = 0;
    csi_resp_data_t csi_rsp_data = { 0 };
    wifi_device_callbacks_t *callbacks;
    csi_info_map_t *csi_map;
    bool all_radio_disable = true;
    unsigned long long int old_time_ms = get_cur_ms_time();
    unsigned long long int curr_time_ms = get_cur_ms_time();
    callbacks = get_hal_device_callbacks();

    csi_rsp_data.usr_need_cnt = 70;
    csi_rsp_data.buf_cnt = 0;

    csi_rsp_buff_len = sizeof(struct csi_data) * csi_rsp_data.usr_need_cnt;

    csi_rsp_data.csi_buf = (struct csi_data *)malloc(csi_rsp_buff_len);
    if (csi_rsp_data.csi_buf == NULL) {
        wifi_hal_error_print("%s:%d:Error in memory allocation\n", __func__, __LINE__);
        return NULL;
    }

    while(1) {
        all_radio_disable = true;
        curr_time_ms = get_cur_ms_time();

        for (radio_index = 0; radio_index < g_wifi_hal.num_radios; radio_index++) {
            csi_info_map_t *csi_map = get_csi_radio_info_map(radio_index);
            if (csi_map && csi_map->csi_active_radio) {
                memset(csi_rsp_data.csi_buf, 0, csi_rsp_buff_len);
                csi_rsp_data.buf_cnt = 0;
                nl80211_csi_dump(radio_index, &csi_rsp_data);
                //Send data to OneWifi CB
                send_user_csi_data(&csi_rsp_data);
                usleep(100 * 1000);//100 ms
                all_radio_disable = false;
            }
        }
        if (all_radio_disable) {
            sleep(1);//1s
        } else {
            usleep(MAX_CSI_DATA_POLLING_PERIOD_MS * 1000);//500 ms
        }
        old_time_ms = curr_time_ms;
    }

    free(csi_rsp_data.csi_buf);
    return NULL;
}

void process_csi_data_thread_start(void)
{
    static bool is_thread_started = false;
    if (is_thread_started == false) {
        static pthread_t csi_data_thread_id;
        pthread_attr_t attr;
        pthread_attr_t *attrp = NULL;
        ssize_t stack_size = 0x800000; /* 8MB */

        attrp = &attr;
        pthread_attr_init(&attr);
        int ret = pthread_attr_setstacksize(&attr, stack_size);
        if (ret != 0) {
            wifi_hal_error_print("%s:%d pthread_attr_setstacksize failed for size:%d ret:%d\n",
                __func__, __LINE__, stack_size, ret);
        }
        pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
        if (pthread_create(&csi_data_thread_id, attrp, csi_data_get_from_driver, NULL) != 0) {
            if(attrp != NULL) {
                pthread_attr_destroy(attrp);
            }
            wifi_hal_error_print( "CSI data process thread create error\n");
            return RETURN_ERR;
        }

        wifi_hal_info_print("%s:%d CSI data process thread is started successfully\n", __func__, __LINE__);

        if (attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        is_thread_started = true;
    } else {
        wifi_hal_info_print("%s:%d CSI data process thread is already started\n", __func__, __LINE__);
    }

    return RETURN_OK;
}

INT wifi_enableCSIEngine(INT ap_index, mac_address_t sta_mac, BOOL enable)
{
    uint8_t radio_index = 0;
    mac_addr_str_t sta_mac_str;
    int ret;
    mac_address_t empty_sta_mac = { 0 };

    ret = get_rdk_radio_index_from_vap_index(ap_index);
    if (ret != RETURN_ERR) {
        radio_index = (uint8_t)ret;
    }

    if (enable) {
        csi_param_cfg_t csi_cfg[] = {
            //Active CSI
            { 1, 0, 0, 0, 0 },
            //Configure CSI
            // { 2, 8, 1, 1, 1 },
            { 2, 9, 0, 1, 1 },
            { 2, 9, 2, 100, 0 }
	};
        uint8_t *p_str_mac = NULL;
        csi_param_cfg_t *ptr;

        for (uint32_t index = 0; index < ARRAY_SIZE(csi_cfg); index++) {
            if (csi_cfg[index].is_mac_addr_used) {
                p_str_mac = (uint8_t *)sta_mac;
	    } else {
                p_str_mac = (uint8_t *)empty_sta_mac;
                //p_str_mac = NULL;
            }
            ptr = &csi_cfg[index];
            if (nl80211_csi_set(radio_index, ptr->mode, ptr->cfg,
                ptr->param_value1, ptr->param_value2, p_str_mac) != RETURN_OK) {
                wifi_hal_error_print("%s:%d CSI set nl command is"
                    " failed\r\n", __func__, __LINE__);
                return RETURN_ERR;
            }
        }
        set_csi_radio_info_map(radio_index, true, sta_mac);
        wifi_hal_info_print( "%s:%d Radio:%d CSI is actived for sta:%s\r\n",
            __func__, __LINE__, radio_index, to_mac_str(sta_mac, sta_mac_str));
    } else {
        //Disable CSI
        if (nl80211_csi_set(radio_index, 0, 0, 0, 0, (uint8_t *)empty_sta_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d CSI set nl command is failed\r\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        if (nl80211_csi_set(radio_index, 2, 9, 0, 0, (uint8_t *)sta_mac) != RETURN_OK) {
            wifi_hal_error_print("%s:%d CSI set nl command is failed\r\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        set_csi_radio_info_map(radio_index, false, sta_mac);
        wifi_hal_info_print("%s:%d Radio:%d CSI is disabled for sta:%s\r\n",
            __func__, __LINE__, radio_index, to_mac_str(sta_mac, sta_mac_str));
    }
    return RETURN_OK;
}

void wifi_csi_callback_register(wifi_csi_callback callback_proc)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return;
    }

    callbacks->csi_callback = callback_proc;
    process_csi_data_thread_start();
}
