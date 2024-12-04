/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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


/* Adapted code from hostap, which is:
Copyright (c) 2002-2015, Jouni Malinen j@w1.fi
Copyright (c) 2003-2004, Instant802 Networks, Inc.
Copyright (c) 2005-2006, Devicescape Software, Inc.
Copyright (c) 2007, Johannes Berg johannes@sipsolutions.net
Copyright (c) 2009-2010, Atheros Communications
Licensed under the BSD-3 License
*/

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"

#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define RPI_LEN_32 32
#define INVALID_KEY                      "12345678"

int wifi_nvram_defaultRead(char *in,char *out);
int _syscmd(char *cmd, char *retBuf, int retBufSize);

typedef struct {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

/* FIXME: VIKAS/PRAMOD:
 * If wifi_nvram_defaultRead fail, handle appropriately in callers.
 */
int wifi_nvram_defaultRead(char *in,char *out)
{
    char buf[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *position;

    sprintf(cmd,"grep '%s=' /nvram/wifi_defaults.txt",in);
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

int platform_pre_init()
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    system("brctl addif brlan0 wlan0");
    system("brctl addif brlan0 wlan1");
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
    char output_val[RPI_LEN_32];
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);

    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
    }
    for (index = 0; index < map->num_vaps; index++)
    {
      if (map->vap_array[index].vap_mode == wifi_vap_mode_ap)
      {
	//   Assigning default radius values 
	    wifi_nvram_defaultRead("radius_s_port",output_val);
	    map->vap_array[index].u.bss_info.security.u.radius.s_port = atoi(output_val);
	    wifi_nvram_defaultRead("radius_s_ip",map->vap_array[index].u.bss_info.security.u.radius.s_ip);
	    wifi_nvram_defaultRead("radius_key",map->vap_array[index].u.bss_info.security.u.radius.s_key);
      }
    } 
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
    /*password is not sensitive,won't grant access to real devices*/ 
    wifi_nvram_defaultRead("rpi_wifi_password",password);
    if (strlen(password) == 0) {
       wifi_hal_error_print("%s:%d nvram default password not found, "
           "enforced alternative default password\n", __func__, __LINE__);
       strncpy(password, INVALID_KEY, strlen(INVALID_KEY) + 1);
    }
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);   
    sprintf(ssid,"RPI_RDKB-AP%d",vap_index);
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
    wifi_nvram_defaultRead("rpi_wifi_password",l_password);
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__); 
    sprintf(l_ssid,"RPI_RDKB-AP%d",vap_index);
    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
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


INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    return RETURN_OK;
}
//--------------------------------------------------------------------------------------------------
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
    return RETURN_OK;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    return RETURN_OK;
}


//--------------------------------------------------------------------------------------------------
INT wifi_getBssLoad(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}
//--------------------------------------------------------------------------------------------------
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    return RETURN_ERR;
}

int platform_get_radio_caps(wifi_radio_index_t index)
{ 
    return 0;
}

INT wifi_getApDeviceRSSI(INT ap_index, CHAR *MAC, INT *output_RSSI)
{
    return 0;
}


static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    sta_list_t *sta_list = (sta_list_t *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
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

int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret, family_id;
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    struct nl_cb *cb = NULL;

    sta_list->num = 0;

    sock = nl_socket_alloc();
    if (!sock) {
        wifi_hal_error_print("%s:%d Failed to allocate netlink socket\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = genl_connect(sock);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to connect to netlink socket: %s\n", __func__, __LINE__, nl_geterror(ret));
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    family_id = genl_ctrl_resolve(sock, "nl80211");
    if (family_id < 0) {
        wifi_hal_error_print("%s:%d Failed to resolve nl80211 family\n", __func__, __LINE__);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d Failed to allocate nlmsg\n", __func__, __LINE__);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    genlmsg_put(msg, 0, 0, family_id, 0, NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        wifi_hal_error_print("%s:%d Failed to allocate callback\n", __func__, __LINE__);
        nlmsg_free(msg);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_sta_list_handler, sta_list);

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to send nlmsg: %s\n",  __func__, __LINE__, nl_geterror(ret));
        nl_cb_put(cb);
        nlmsg_free(msg);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    ret = nl_recvmsgs(sock, cb);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to receive netlink messages: %s\n", __func__, __LINE__, nl_geterror(ret));
        return RETURN_ERR;
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    nl_socket_free(sock);

    return RETURN_OK;
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

int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac, wifi_associated_dev3_t *dev)
{
    int family_id, ret;
    struct nl_sock *sock = NULL;
    struct nl_msg *msg = NULL;
    struct nl_cb *cb = NULL;

    sock = nl_socket_alloc();
    if (!sock) {
        wifi_hal_error_print("%s:%d Failed to allocate netlink socket\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = genl_connect(sock);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to connect to netlink socket: %s\n", __func__, __LINE__, nl_geterror(ret));
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    family_id = genl_ctrl_resolve(sock, "nl80211");
    if (family_id < 0) {
        wifi_hal_error_print("%s:%d Failed to resolve nl80211 family\n", __func__, __LINE__);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d Failed to allocate nlmsg\n", __func__, __LINE__);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    genlmsg_put(msg, 0, 0, family_id, 0, 0, NL80211_CMD_GET_STATION, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), mac);

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        wifi_hal_error_print("%s:%d Failed to allocate callback\n", __func__, __LINE__);
        nlmsg_free(msg);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_sta_stats_handler, dev);

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to send nlmsg: %s\n", __func__, __LINE__, nl_geterror(ret));
        nl_cb_put(cb);
        nlmsg_free(msg);
        nl_socket_free(sock);
        return RETURN_ERR;
    }

    ret = nl_recvmsgs(sock, cb);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to receive netlink messages: %s\n", __func__, __LINE__, nl_geterror(ret));
        return RETURN_ERR;
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    nl_socket_free(sock);

    return RETURN_OK;
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
        wifi_hal_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    *associated_dev_array = sta_list.num ?
        calloc(sta_list.num, sizeof(wifi_associated_dev3_t)) : NULL;
    *output_array_size = sta_list.num;

    for (i = 0; i < sta_list.num; i++) {
        ret = get_sta_stats(interface, sta_list.macs[i], &(*associated_dev_array)[i]);
        if (ret != RETURN_OK) {
            wifi_hal_error_print("%s:%d Failed to get sta stats\n", __func__, __LINE__);
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

INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable) // Tr181
{
    return 0;
}

INT wifi_getRadioChannel(INT radioIndex, ULONG *output_ulong)
{
    return 0;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    return RETURN_OK;
}

int wifi_rrm_send_beacon_req(struct wifi_interface_info_t *interface, const u8 *addr,
    u16 num_of_repetitions, u8 measurement_request_mode, u8 oper_class, u8 channel,
    u16 random_interval, u16 measurement_duration, u8 mode, const u8 *bssid,
    struct wpa_ssid_value *ssid, u8 *rep_cond, u8 *rep_cond_threshold, u8 *rep_detail,
    const u8 *ap_ch_rep, unsigned int ap_ch_rep_len, const u8 *req_elem, unsigned int req_elem_len,
    u8 *ch_width, u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication)
{
    return 0;
}

/* called by BTM API */
int wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta,
    u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int, const u8 *bss_term_dur,
    const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len)
{
    return 0;
}

int handle_wnm_action_frame(struct wifi_interface_info_t *interface, const mac_address_t sta,
    struct ieee80211_mgmt *mgmt, size_t len)
{
    return 0;
}

int handle_rrm_action_frame(struct wifi_interface_info_t *interface, const mac_address_t sta,
    const struct ieee80211_mgmt *mgmt, size_t len, int ssi_signal)
{
    return 0;
}

INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    return 0;
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
    return 0;
}

int wifi_drv_set_ap_mlo(struct nl_msg *msg, void *priv, struct wpa_driver_ap_params *params)
{
    return 0;
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb)
{
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac,
    wifi_disconnectType_t type, UINT reason)
{
    return 0;
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

INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled)
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

INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
    return 0;
}

INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_setBssLoad(INT apIndex, BOOL enabled)
{
    return 0;
}

INT wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool)
{
    return 0;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return 0;
}

INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled)
{
    return 0;
}
INT wifi_getApAssociatedClientDiagnosticResult(INT ap_index, char *key,wifi_associated_dev3_t *assoc)
{
    return RETURN_ERR;
}