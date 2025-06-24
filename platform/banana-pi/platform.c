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

    // Cannot use this function to create interfaces here.
    // nl80211_id is not initialized, yet.
    // g_wifi_hal.nl80211_id is initialized in init_nl80211()

    return 0;
}

int platform_create_interfaces(void)
{
    struct nl_msg *msg;
    int ret;
    /* FIXME(ldk): Read from JSON/use static map? */
    const int wiphy = 0;
    const char ifname[] = "mld-ap0";

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_NEW_INTERFACE);
    if (msg == NULL) {
        return -1;
    }

    /* TODO(ldk): ? */
    /* if (nla_put_u32(msg, NL80211_ATTR_VIF_RADIO_MASK, 0x6) < 0) {
        nlmsg_free(msg);
        return -1;
    } */

    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, wiphy) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_string(msg, NL80211_ATTR_IFNAME, ifname) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if ((ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error creating %s interface on dev:%d error: %d (%s)\n", __func__, __LINE__,
            ifname, wiphy, ret, strerror(-ret));
        return -1;
    }

    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    // system("brctl addif brlan0 wifi0");
    // system("brctl addif brlan0 wifi1");
    // system("brctl addif brlan0 wifi2");
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
    //snprintf(ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
    //snprintf(ssid,BPI_LEN_16,"2-LDK-1-VAP%d",vap_index);
    snprintf(ssid,BPI_LEN_16,"2-LDK-MLD-VAP%1d",vap_index);
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
    wifi_hal_dbg_print("%s:%d: Called update_hostap_mlo\n", __func__, __LINE__);

    wifi_hal_dbg_print("%s:%d: MLO: interface name: %s, index: %d, phy_index: %d, rdk_radio_index: %d\n",
	__func__, __LINE__, interface->name, interface->index, interface->phy_index,
	interface->rdk_radio_index);

    wifi_vap_info_t *vap = &interface->vap_info;
    wifi_hal_dbg_print("%s:%d: MLO: vap name: %s\n", __func__, __LINE__,
	vap->vap_name);


    char mld_interface[20];
    unsigned int mld_link_id;

    int rc = get_mld_interface_name_from_vap_index(vap->vap_index,
        mld_interface, sizeof(mld_interface) - 1, &mld_link_id);
    if (rc == RETURN_ERR) {
        return RETURN_ERR;
    }

    if (mld_link_id == 0) {
        wifi_hal_dbg_print("%s:%d: MLO: Configure Link 0\n", __func__, __LINE__);
        struct hostapd_data *hapd = &interface->u.ap.hapd;
        struct hostapd_bss_config *conf = hapd->conf;

        conf->mld_ap = 1;
        conf->okc = 1;

        wifi_hal_dbg_print("%s:%d: MLO: conf iface: \"%s\"\n",
            __func__, __LINE__, conf->iface);

        // TOOD(ldk): replace with hostapd_bss_setup_multi_link?
        struct hostapd_mld *mld = os_zalloc(sizeof(struct hostapd_mld));
        strcpy(mld->name, conf->iface);
        dl_list_init(&mld->links);
        //mld->mld_addr[0] = 0xde;
        //mld->mld_addr[1] = 0xad;
        //mld->mld_addr[2] = 0xbe;
        //mld->mld_addr[3] = 0xef;
        //mld->mld_addr[4] = 0x01;
        //mld->mld_addr[5] = 0x02;
        os_memcpy(mld->mld_addr, hapd->own_addr, ETH_ALEN);
        mld->mld_addr[5] += 1;

        hapd->mld = mld;
        hapd->ctrl_sock = -1;
        wifi_hal_dbg_print("%s:%d: MLO: drv_priv: %p\n",
            __func__, __LINE__, hapd->drv_priv);

        mld->refcount++;
        hapd->mld_link_id = mld->next_link_id++;

        wifi_hal_dbg_print("%s:%d: MLO: Setup of first link (%d) BSS of MLD %s\n",
                           __func__, __LINE__,
                           hapd->mld_link_id, hapd->conf->iface);
        if (hostapd_mld_add_link(hapd) != 0) {
            wifi_hal_dbg_print("%s:%d: MLO: Failed to add MLO link\n", __func__, __LINE__);
        }

        if (hapd->drv_priv == NULL)
            wifi_hal_dbg_print("%s:%d: MLO: hapd->drv_priv NULL\n", __func__, __LINE__);
        if (hapd->driver == NULL)
            wifi_hal_dbg_print("%s:%d: MLO: hapd->driver NULL\n", __func__, __LINE__);
        else if (hapd->driver->link_add == NULL)
            wifi_hal_dbg_print("%s:%d: MLO: hapd->driver->link_add NULL\n", __func__, __LINE__);

        wifi_hal_dbg_print("%s:%d: MLO: Set link_id=%u, mld_addr=" MACSTR
                           ", own_addr=" MACSTR "\n", __func__, __LINE__,
                           hapd->mld_link_id,
                           MAC2STR(hapd->mld->mld_addr),
                           MAC2STR(hapd->own_addr));
        if (hostapd_drv_link_add(hapd, hapd->mld_link_id, hapd->own_addr) != 0) {
        //if (hostapd_drv_link_add(hapd, hapd->mld_link_id, mld->mld_addr) != 0) {
            wifi_hal_dbg_print("%s:%d: MLO: Failed to add hostapd_drv_link_add\n", __func__, __LINE__);
        }

        wifi_hal_dbg_print("%s:%d: MLO: done\n", __func__, __LINE__);
    }

    return 0;
}
#endif /* CONFIG_IEEE80211BE */

