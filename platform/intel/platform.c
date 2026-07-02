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

#include <fcntl.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include <uci_wrapper.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "arris_rpc.h"
#include "platform_hal.h"

#if HAL_IPC
#include "hal_ipc.h"
#include "server_hal_ipc.h"
#endif

#define COUNTRY_LENGTH 10
#define MAX_KEYPASSPHRASE_LEN 128
#define MAX_SSID_LEN 33

#define WIFI5_2G "g,n"
#define WIFI6_2G "g,n,ax"
#define WIFI5_5G "a,n,ac"
#define WIFI6_5G "a,n,ac,ax"
#define WIFI5_2G_UCI "11bgn"
#define WIFI6_2G_UCI "11bgnax"
#define WIFI5_5G_UCI "11anac"
#define WIFI6_5G_UCI "11anacax"

#define RADIO_VAP_STATUS_SHM_OBJ_SIZE 1024
#define RADIO_VAP_STATUS_SHM_OBJ_NAME "radio_vap_status_info"
typedef enum {
    LED_SOLID_STATE,
    LED_BLINK_STATE,
} led_states_t;

int platform_pre_init()
{

    char region[COUNTRY_LENGTH] = {0};
    char cmd[128] = {0};
    int ret = 0;

    ret = ARM_RPC(region, COUNTRY_LENGTH, "default_region");
    if (ret != 0)
    {
        strcpy(region, "US");
    }
    sprintf(cmd, "iw reg set %s", region);
    system(cmd);

    return 0;
}

#ifdef MXL_WIFI
/**
 * opclass_channel_to_center_freq - Compute center frequency from operating class,
 *                                  primary channel and bandwidth.
 * @op_class: Global operating class (IEEE 802.11 Table E-4).
 * @channel:  Primary channel number within the operating class.
 * @bw:       Bandwidth in MHz (from op_class_to_bandwidth).
 *
 * Returns the center frequency in MHz, or -1 on error.
 */
static int opclass_channel_to_center_freq(UINT op_class, UINT channel, int bw)
{
    static const unsigned int centers_80_5g[]  = {42, 58, 106, 122, 138, 155};
    static const unsigned int centers_80_6g[]  = {7, 23, 39, 55, 71, 87, 103, 119,
                                                  135, 151, 167, 183, 199, 215};
    static const unsigned int centers_160_5g[] = {50, 114, 163};
    static const unsigned int centers_160_6g[] = {15, 47, 79, 111, 143, 175, 207};
    const unsigned int *centers;
    int freq, n, i;
    bool is_6g = (op_class >= 131 && op_class <= 137);

    freq = ieee80211_chan_to_freq(NULL, op_class, channel);
    if (freq < 0)
        return -1;

    switch (bw) {
    case 20:
        return freq;

    case 40:
        /* 40 MHz: center = primary ± 10 MHz, direction determined by operating class */
        switch (op_class) {
        case 83:   /* 2.4 GHz HT40+ */
        case 116:  /* 5 GHz 36,44 */
        case 119:  /* 5 GHz 52,60 */
        case 122:  /* 5 GHz 100-140 */
        case 126:  /* 5 GHz 149-173 */
            return freq + 10;
        case 84:   /* 2.4 GHz HT40- */
        case 117:  /* 5 GHz 40,48 */
        case 120:  /* 5 GHz 56,64 */
        case 123:  /* 5 GHz 104-144 */
        case 127:  /* 5 GHz 153-177 */
            return freq - 10;
        case 132:  /* 6 GHz 40 MHz */
            /* Pairs: (1,5), (9,13), (17,21), ...
             * Lower primary ch % 8 == 1: secondary above
             * Upper primary ch % 8 == 5: secondary below */
            if (channel % 8 == 1)
                return freq + 10;
            else if (channel % 8 == 5)
                return freq - 10;
            else
                return -1;
        default:
            return -1;
        }

    case 80:
        /* 80 MHz: find center channel whose block contains primary (center ± 6) */
        if (is_6g) {
            centers = centers_80_6g;
            n = ARRAY_SZ(centers_80_6g);
        } else {
            centers = centers_80_5g;
            n = ARRAY_SZ(centers_80_5g);
        }
        for (i = 0; i < n; i++) {
            if (channel >= centers[i] - 6 && channel <= centers[i] + 6)
                return is_6g ? (int)(5950 + centers[i] * 5)
                             : (int)(5000 + centers[i] * 5);
        }
        return -1;

    case 160:
        /* 160 MHz: find center channel whose block contains primary (center ± 14) */
        if (is_6g) {
            centers = centers_160_6g;
            n = ARRAY_SZ(centers_160_6g);
        } else {
            centers = centers_160_5g;
            n = ARRAY_SZ(centers_160_5g);
        }
        for (i = 0; i < n; i++) {
            if (channel >= centers[i] - 14 && channel <= centers[i] + 14)
                return is_6g ? (int)(5950 + centers[i] * 5)
                             : (int)(5000 + centers[i] * 5);
        }
        return -1;

    default:
        return -1;
    }
}

int platform_get_nasta(INT apIndex, const wifi_na_sta_req_params_t *params, wifi_na_sta_info_t *sta_info)
{
    struct intel_vendor_unconnected_sta_req_cfg req = { 0 };
    struct intel_vendor_unconnected_sta nasta_info = { 0 };
    wifi_radio_info_t *radio;
    wifi_interface_info_t *ap_iface, *primary_iface;
    struct hostapd_iface *bss, *master;
    struct sta_info *sta;
    struct wpabuf *rsp;
    int cca_in_progress, cac_started;
    int freq, c_freq, bw, rcpi, i, ret;

    if (!params || !sta_info) {
        wifi_hal_error_print("%s:%d: Invalid parameters\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    memset(sta_info, 0, sizeof(*sta_info));

    ap_iface = get_interface_by_vap_index(apIndex);
    if (!ap_iface) {
        wifi_hal_error_print("%s:%d: WiFi AP not found for index:%d\n",
            __func__, __LINE__, apIndex);
        return WIFI_HAL_ERROR;
    }

    radio = get_radio_by_rdk_index(ap_iface->rdk_radio_index);
    if (!radio) {
        wifi_hal_error_print("%s:%d: WiFi radio not found for index:%d\n",
            __func__, __LINE__, ap_iface->rdk_radio_index);
        return WIFI_HAL_ERROR;
    }

    primary_iface = get_primary_interface(radio);
    if (!primary_iface) {
        wifi_hal_error_print("%s:%d: WiFi primary interface not found\n",
            __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (!ap_iface->vap_configured) {
        wifi_hal_error_print("%s:%d: WiFi interface is not configured\n",
            __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    master = &primary_iface->u.ap.iface;
    bss = &ap_iface->u.ap.iface;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    cac_started = master->cac_started;
    cca_in_progress = bss->bss[0]->cca_in_progress;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (WAVE_FREQ_IS_5G(bss->freq) && cac_started) {
        wifi_hal_error_print("%s:%d: CAC is in progress, can't schedule scan\n",
            __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    if (cca_in_progress) {
        wifi_hal_error_print("%s:%d: CCA is in progress, can't schedule scan\n",
            __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    sta = ap_get_sta(bss->bss[0], params->sta_mac);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    if (sta) {
        wifi_hal_error_print("%s:%d: STA " MACSTR " is connected to current AP index %d\n",
            __func__, __LINE__, MAC2STR(params->sta_mac), apIndex);
        return WIFI_HAL_ERROR;
    }


    /* Get bandwidth from operating class */
    bw = op_class_to_bandwidth(params->op_class);
    if (bw > 320) {
        bw = 20;
        wifi_hal_error_print("%s:%d: op_class %u is not supported, forcing bandwidth to %d\n",
            __func__, __LINE__, params->op_class, bw);
    }

    /* Convert operating class + channel to center frequency */
    c_freq = opclass_channel_to_center_freq(params->op_class, params->channel, bw);
    if (c_freq < 0) {
        wifi_hal_error_print("%s:%d: Invalid opclass/channel: %u/%u\n",
            __func__, __LINE__, params->op_class, params->channel);
        return WIFI_HAL_ERROR;
    }

    /* Get the primary channel frequency */
    freq = ieee80211_chan_to_freq(NULL, params->op_class, params->channel);
    if (freq < 0) {
        wifi_hal_error_print("%s:%d: invalid channel: freq for opclass %u channel %u not found\n",
            __func__, __LINE__, params->op_class, params->channel);
        return WIFI_HAL_ERROR;
    }

    /* Validate channel definition for primary frequency */
    if (!hostapd_is_chandef_valid(bss, freq, 20)) {
        wifi_hal_error_print("%s:%d: invalid channel definition: primary freq %d (opclass=%u, channel=%u)\n",
            __func__, __LINE__, freq, params->op_class, params->channel);
        return WIFI_HAL_ERROR;
    }

    /* Validate channel definition for central frequency */
    if (!hostapd_is_chandef_valid(bss, c_freq, bw)) {
        wifi_hal_error_print("%s:%d: invalid channel definition: central freq %d bandwidth %d (opclass=%u, channel=%u)\n",
            __func__, __LINE__, c_freq, bw, params->op_class, params->channel);
        return WIFI_HAL_ERROR;
    }

    /* compose request */
    ret = bw_to_nl80211_chan_width(bw, 0);
    if (ret == -1) {
        wifi_hal_error_print("%s:%d: invalid bandwidth %d for opclass %u\n",
            __func__, __LINE__, bw, params->op_class);
        return WIFI_HAL_ERROR;
    }
    req.bandwidth =  ret;

    req.freq = freq;
    req.center_freq1 = c_freq;
    req.center_freq2 = 0;

    req.req_type = NASTA_STATS_REQ_SYNC;
    memcpy(&req.addr, params->sta_mac, ETH_ALEN);

    wifi_hal_dbg_print("%s:%d: NaSta vendor req: freq=%d center_freq1=%d center_freq2=%d "
        "bw=%d req_type=%d addr=" MACSTR "\n",
        __func__, __LINE__, req.freq, req.center_freq1, req.center_freq2,
        req.bandwidth, req.req_type, MAC2STR(req.addr));

    rsp = wpabuf_alloc(sizeof(nasta_info));
    if (!rsp) {
        wifi_hal_error_print("%s:%d: alloc failed\n", __func__, __LINE__);
        return WIFI_HAL_ERROR;
    }

    ret = wifi_drv_vendor_cmd(ap_iface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_UNCONNECTED_STA,
                                (u8 *)&req, sizeof(req), NESTED_ATTR_NOT_USED, rsp);
    if (ret) {
        wifi_hal_error_print("%s:%d: nl80211: sending/receiving GET_UNCONNECTED_STA "
            "failed: %i (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        goto err;
    }

    if (rsp->used != sizeof(nasta_info)) {
        wifi_hal_error_print("%s:%d: nl80211: driver returned %zu bytes instead of %zu\n",
            __func__, __LINE__, rsp->used, sizeof(nasta_info));
        goto err;
    }
    memcpy(&nasta_info, rsp->buf, sizeof(nasta_info));

    wifi_hal_dbg_print("%s:%d: NaSta RSSI per antenna: [0]=%d [1]=%d [2]=%d [3]=%d\n",
        __func__, __LINE__,
        (int)nasta_info.rssi[0], (int)nasta_info.rssi[1],
        (int)nasta_info.rssi[2], (int)nasta_info.rssi[3]);

    /* Convert max antenna RSSI to RCPI: (RSSI + 110) * 2, clamped to [0, 220] */
    for (i = 1; i < WAVE_STAT_MAX_ANTENNAS; i++) {
        if (nasta_info.rssi[i] && (nasta_info.rssi[i] > nasta_info.rssi[0])) {
            nasta_info.rssi[0] = nasta_info.rssi[i];
        }
    }
    rcpi = ((int)nasta_info.rssi[0] + 110) << 1;
    rcpi = MXL_CLAMP(rcpi, 0, 220);

    wifi_hal_dbg_print("%s:%d: NaSta RCPI=%d (best RSSI=%d)\n",
        __func__, __LINE__, rcpi, (int)nasta_info.rssi[0]);

    memcpy(sta_info->sta_mac, params->sta_mac, ETH_ALEN);
    sta_info->channel = params->channel;
    sta_info->op_class = params->op_class;
    sta_info->rcpi = (UINT)rcpi;

    wpabuf_free(rsp);
    return WIFI_HAL_SUCCESS;

err:
    wpabuf_free(rsp);
    return WIFI_HAL_ERROR;
}
#endif /* MXL_WIFI */

#if HAL_IPC
int platform_post_init(wifi_hal_post_init_t *post_init_struct)
{
    app_get_ap_assoc_dev_diag_res3_t get_diag_res3_fn           = NULL;
    app_get_neighbor_ap2_t           get_neighbor_ap2_fn        = NULL;
    app_get_radio_channel_stats_t    get_radio_channel_stats_fn = NULL;
    //app_get_radio_traffic_stats_t    get_radio_traffic_stats_fn = NULL;
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);

    if (post_init_struct->app_info->app_get_ap_assoc_dev_diag_res3_fn) {
        get_diag_res3_fn = post_init_struct->app_info->app_get_ap_assoc_dev_diag_res3_fn;
        hal_ipc_server_set_ap_assoc_dev_diag_res3_callback(get_diag_res3_fn);
    } else {
        wifi_hal_dbg_print("%s: HAL IPC unable to get AP associated device diagnostic result3 due to callback not provided.\n", __FUNCTION__);
    }

    if (post_init_struct->app_info->app_get_neighbor_ap2_fn) {
        get_neighbor_ap2_fn = post_init_struct->app_info->app_get_neighbor_ap2_fn;
        hal_ipc_server_set_neighbor_ap2_callback(get_neighbor_ap2_fn);
    } else {
        wifi_hal_dbg_print("%s: HAL IPC unable to get neighbor results due to callback not provided.\n", __FUNCTION__);
    }

    if (post_init_struct->app_info->app_get_radio_channel_stats_fn) {
        get_radio_channel_stats_fn = post_init_struct->app_info->app_get_radio_channel_stats_fn;
        hal_ipc_server_set_radio_channel_stats_callback(get_radio_channel_stats_fn);
    } else {
        wifi_hal_dbg_print("%s: HAL IPC unable to get radio channel stats due to callback not provided.\n", __FUNCTION__);
    }

    // if (post_init_struct->app_info->app_get_radio_traffic_stats_fn) {
    //     get_radio_traffic_stats_fn = post_init_struct->app_info->app_get_radio_traffic_stats_fn;
    //     hal_ipc_server_set_radio_traffic_stats_callback(get_radio_traffic_stats_fn);
    // } else {
    //     wifi_hal_dbg_print("%s: HAL IPC unable to get radio traffic stats due to callback not provided.\n", __FUNCTION__);
    // }

    wifi_hal_dbg_print("%s: HAL IPC init.\n", __FUNCTION__);

    if(hal_ipc_init() != 0){
        wifi_hal_dbg_print("%s:%d: failed to start HAL IPC sync call server.\n",__func__, __LINE__);
    } else {
        wifi_hal_dbg_print("%s: HAL IPC sync call server started.\n", __FUNCTION__);
    }
    wifi_hal_dbg_print("%s: Exit.\n", __FUNCTION__);
    return 0;
}
#else
int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s: Enter.\n", __FUNCTION__);
    return 0;
}
#endif

int nvram_get_current_password(char *l_password, int vap_index)
{
    if (l_password == NULL)
    {
        return -1;
    }
    uci_converter_get_optional_str(TYPE_VAP, vap_index, "key", l_password, MAX_KEYPASSPHRASE_LEN, "");
    wifi_hal_dbg_print("nvram_get_current_password vap_index:%d \n",vap_index);
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    if (l_ssid == NULL)
    {
        return -1;
    }
    wifi_hal_dbg_print("nvram_get_current_password vap_index:%d \n",vap_index);
    return uci_converter_get_str_ext(TYPE_VAP, vap_index, "ssid", l_ssid, MAX_SSID_LEN - 1);
}

void hwmode_format_uci(char *output_str, const char *input_str)
{
    if(output_str == NULL) {
        wifi_hal_error_print("%s: output_str is NULL", __func__);
        return;
    }

    memset(output_str, 0, MAX_UCI_BUF_LEN);

    if (!strncmp(WIFI5_2G, input_str, sizeof(WIFI5_2G)))
        strncpy(output_str, WIFI5_2G_UCI, strlen(WIFI5_2G_UCI) + 1);
    else if (!strncmp(WIFI6_2G, input_str, sizeof(WIFI6_2G)))
        strncpy(output_str, WIFI6_2G_UCI, strlen(WIFI6_2G_UCI) + 1);
    else if (!strncmp(WIFI5_5G, input_str, sizeof(WIFI5_5G)))
        strncpy(output_str, WIFI5_5G_UCI, strlen(WIFI5_5G_UCI) + 1);
    else if (!strncmp(WIFI6_5G, input_str, sizeof(WIFI6_5G)))
        strncpy(output_str, WIFI6_5G_UCI, strlen(WIFI6_5G_UCI) + 1);
    else {
        wifi_hal_error_print("%s: incorrect input_str=%s", __func__, input_str);
    }
    wifi_hal_dbg_print("%s: output_str=%s\n", __func__, output_str);
}

/* Stub for wave_api function, should be removed after implementation*/
int wifi_allow2G80211ax(bool enable)
{
    return 0;
}   

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    int ret = 0;
    char key[MAX_KEYPASSPHRASE_LEN] = {0};
    FILE *fp = NULL;

    if (password == NULL)
    {
        return -1;
    }

    if ( is_wifi_hal_vap_private(vap_index) ) {
        /* Return default passphrase for private SSID */
        ret = ARM_RPC(password, MAX_KEYPASSPHRASE_LEN,"nvm_get", "psk");
        if (ret == 0)
        {
           wifi_hal_dbg_print("platform_get_keypassphrase_default pvt - returning success index=%d\n",vap_index);
            return 0;
        }
    }
    else if ( is_wifi_hal_vap_xhs(vap_index)) {
         //Default passphrase for XHS vaps
         wifi_hal_dbg_print("platform_get_keypassphrase_default - XHS %d\n",vap_index);
         fp = popen ("/lib/rdk/xhsScript.sh", "r");
         if(fp != NULL)
         {
           if (fgets (key, sizeof (key), fp) == NULL)
           {
             wifi_hal_dbg_print("platform_get_keypassphrase_default: failed to get default for XHS\n");
             pclose(fp);
             return -1;
           }
           if(key[0] != '\0')
           {
             if( key[strlen(key) - 1] == '\n')
             {
                key[strlen(key) - 1] = '\0';
             }
             strcpy(password,key);
             wifi_hal_dbg_print("platform_get_keypassphrase_default - XHS done.\n");
             pclose(fp);
             memset(key,0,sizeof(key));
             return 0;
           }
           else
           {
             wifi_hal_dbg_print("platform_get_keypassphrase_default - Key NULL\n");
             pclose(fp);
             return -1;
           }
         }
         else
         {
           wifi_hal_dbg_print("platform_get_keypassphrase_default - popen xhsScript.sh failed \n");
           return -1;
         }

    }
    else if (is_wifi_hal_vap_lnf_psk(vap_index)){
        //Default credential for LnF vaps.
        wifi_hal_dbg_print("platform_get_keypassphrase_default - lnf  %d\n",vap_index);
        fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_auth", "r");
        if(fp != NULL)
        {
            if (fgets (key, sizeof (key), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_keypassphrase_default: failed to get default LNF passphrase\n");
                pclose(fp);
                return -1;
            }
            if(key[0] != '\0')
            {
                if( key[strlen(key) - 1] == '\n')
                {
                    key[strlen(key) - 1] = '\0';
                }

                strcpy(password,key);
                wifi_hal_dbg_print("platform_get_keypassphrase_default - LNF done.\n");
                pclose(fp);
                memset(key,0,sizeof(key));
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_keypassphrase_default - Key NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_keypassphrase_default - popen lnfScript.sh get_default_lnf_auth failed \n");
            return -1;
        }
    }
    else if (is_wifi_hal_vap_lnf_radius(vap_index)){
        //Default passphrase for LnF vaps
        wifi_hal_dbg_print("platform_get_keypassphrase_default - lnf radius %d\n",vap_index);
        fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_radius_auth", "r");
        if(fp != NULL)
        {
            if (fgets (key, sizeof (key), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_keypassphrase_default: failed to get default LNF passphrase\n");
                pclose(fp);
                return -1;
            }
            if(key[0] != '\0')
            {
                if( key[strlen(key) - 1] == '\n')
                {
                    key[strlen(key) - 1] = '\0';
                }

                strcpy(password,key);
                wifi_hal_dbg_print("platform_get_keypassphrase_default - LNF done.\n");
                pclose(fp);
                memset(key,0,sizeof(key));
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_keypassphrase_default - Key NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_keypassphrase_default - popen lnfScript.sh get_default_lnf_radius_auth failed \n");
            return -1;
        }
    }
    else {
        wifi_hal_dbg_print("platform_get_keypassphrase_default else case - vap %d\n",vap_index);
        return nvram_get_current_password(password,vap_index);
    }
    wifi_hal_dbg_print("platform_get_keypassphrase_default - LnF common Fail\n");
    return -1;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    int ret = 0;
    char name[MAX_SSID_LEN] = {0};
    FILE *fp = NULL;
    if (ssid == NULL)
    {
        return -1;
    }

    if ( is_wifi_hal_vap_private(vap_index) ) {
        /* Return default SSID for private SSID */
        ret = ARM_RPC(ssid,MAX_SSID_LEN,"default_ssid");
        if (ret == 0)
        {
            wifi_hal_dbg_print("platform_get_ssid_default  private vap: %d succcess\n",vap_index);
            return 0;
        }
    }
    else if (is_wifi_hal_vap_xhs(vap_index)){
        /* Return default SSID of XHS vap */
        ret = ARM_RPC(ssid,MAX_SSID_LEN,"default_xhs_ssid");
        if(ret==0)
        {
            wifi_hal_dbg_print("platform_get_ssid_default xhs vap: %d, succcess\n",vap_index);
          return 0;
        }
    }
    else if(is_wifi_hal_vap_lnf_psk(vap_index)){
        // Default SSID of PSK LnF vaps
        wifi_hal_dbg_print("platform_get_ssid_default lnf psk vap : %d\n",vap_index);
        fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_ssid", "r");
        if(fp != NULL)
        {
            if (fgets (name, sizeof (name), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_ssid_default: failed to get default LNF ssid\n");
                pclose(fp);
                return -1;
            }
            if(name[0] != '\0')
            {
                if( name[strlen(name) - 1] == '\n')
                {
                    name[strlen(name) - 1] = '\0';
                }
                strcpy(ssid,name);
                wifi_hal_dbg_print("platform_get_ssid_default - LNF done.\n");
                pclose(fp);
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_ssid_default - ssid NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_ssid_default - popen lnfScript.sh get_default_lnf_ssid failed \n");
            return -1;
        }
    }
    else if(is_wifi_hal_vap_lnf_radius(vap_index)){
        // Default SSID of radius LnF vaps
        wifi_hal_dbg_print("platform_get_ssid_default lnf radius vap : %d\n",vap_index);
                fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_radius_ssid", "r");
        if(fp != NULL)
        {
            if (fgets (name, sizeof (name), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_ssid_default: failed to get default LNF ssid\n");
                pclose(fp);
                return -1;
            }
            if(name[0] != '\0')
            {
                if( name[strlen(name) - 1] == '\n')
                {
                    name[strlen(name) - 1] = '\0';
                }
                strcpy(ssid,name);
                wifi_hal_dbg_print("platform_get_ssid_default - LNF done.\n");
                pclose(fp);
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_ssid_default - ssid NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_ssid_default - popen lnfScript.sh get_default_lnf_radius_ssid failed \n");
            return -1;
        }
    }
    else if (is_wifi_hal_vap_xhs(vap_index)){
        /* Return default SSID of XHS vap */
        ret = ARM_RPC(ssid,MAX_SSID_LEN,"default_xhs_ssid");
        if(ret==0)
        {
            wifi_hal_dbg_print("platform_get_ssid_default xhs vap: %d, succcess\n",vap_index);
          return 0;
        }
    }
    else if(is_wifi_hal_vap_lnf_psk(vap_index)){
        // Default SSID of PSK LnF vaps
        wifi_hal_dbg_print("platform_get_ssid_default lnf psk vap : %d\n",vap_index);
        fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_ssid", "r");
        if(fp != NULL)
        {
            if (fgets (name, sizeof (name), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_ssid_default: failed to get default LNF ssid\n");
                pclose(fp);
                return -1;
            }
            if(name[0] != '\0')
            {
                if( name[strlen(name) - 1] == '\n')
                {
                    name[strlen(name) - 1] = '\0';
                }
                strcpy(ssid,name);
                wifi_hal_dbg_print("platform_get_ssid_default - LNF done.\n");
                pclose(fp);
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_ssid_default - ssid NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_ssid_default - popen lnfScript.sh get_default_lnf_ssid failed \n");
            return -1;
        }
    }
    else if(is_wifi_hal_vap_lnf_radius(vap_index)){
        // Default SSID of radius LnF vaps
        wifi_hal_dbg_print("platform_get_ssid_default lnf radius vap : %d\n",vap_index);
                fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_radius_ssid", "r");
        if(fp != NULL)
        {
            if (fgets (name, sizeof (name), fp) == NULL)
            {
                wifi_hal_dbg_print("platform_get_ssid_default: failed to get default LNF ssid\n");
                pclose(fp);
                return -1;
            }
            if(name[0] != '\0')
            {
                if( name[strlen(name) - 1] == '\n')
                {
                    name[strlen(name) - 1] = '\0';
                }
                strcpy(ssid,name);
                wifi_hal_dbg_print("platform_get_ssid_default - LNF done.\n");
                pclose(fp);
                return 0;
            }
            else
            {
                wifi_hal_dbg_print("platform_get_ssid_default - ssid NULL\n");
                pclose(fp);
                return -1;
            }
        }
        else
        {
            wifi_hal_dbg_print("platform_get_ssid_default - popen lnfScript.sh get_default_lnf_radius_ssid failed \n");
            return -1;
        }
    }
    else{
         wifi_hal_dbg_print("platform_get_ssid_default  vap: %d,succcess\n",vap_index);
         return nvram_get_current_ssid(ssid, vap_index); 
    }
    return -1;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
  char htmode_str1[MAX_UCI_BUF_LEN];
  wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, index);
  if (uci_converter_alloc_local_uci_context()) {
      wifi_hal_dbg_print("%s:%d: alloc local context returned err!\n",__func__, __LINE__);
      return RETURN_ERR;
  }
  if(channelWidth == NULL) {
      wifi_hal_dbg_print("%s:%d: wifi_radio_operationParam_t *operationParam is NULL \n", __func__, __LINE__);
      return RETURN_ERR;
  }
  wifi_hal_dbg_print("%s:%d: Entering uci****************:\n", __func__, __LINE__);
  uci_converter_get_str_ext(TYPE_RADIO, index, "htmode", htmode_str1, sizeof(htmode_str1));
  wifi_hal_dbg_print("%s:%d: Enter radio index:%d htmode_value=%s\n", __func__, __LINE__, index,htmode_str1);
  if (!strncmp(htmode_str1, "HT20", MAX_UCI_BUF_LEN) || !strncmp(htmode_str1, "VHT20", MAX_UCI_BUF_LEN))
      *channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
  else if (!strncmp(htmode_str1, "HT40+", MAX_UCI_BUF_LEN) || !strncmp(htmode_str1, "HT40-", MAX_UCI_BUF_LEN) || !strncmp(htmode_str1, "VHT40+", MAX_UCI_BUF_LEN) ||
      !strncmp(htmode_str1, "VHT40-", MAX_UCI_BUF_LEN) || !strncmp(htmode_str1, "VHT40", MAX_UCI_BUF_LEN))
      *channelWidth = WIFI_CHANNELBANDWIDTH_40MHZ;
  else if (!strncmp(htmode_str1, "VHT80", MAX_UCI_BUF_LEN))
      *channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
  else if (!strncmp(htmode_str1, "VHT160", MAX_UCI_BUF_LEN))
      *channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
  else {
      wifi_hal_dbg_print("%s:%d: htmode_str1 error value:%s \n", __func__, __LINE__,htmode_str1);
      return RETURN_ERR;
  }
  wifi_hal_dbg_print("%s:%d: %u *****successful***********\n", __func__, __LINE__,*channelWidth);
  uci_converter_free_local_uci_context();
  return 0;
}

int platform_get_country_code_default(char *code)
{
    if (code == NULL)
    {
        return -1;
    }
    if( ARM_RPC(code, COUNTRY_LENGTH,"default_region") == -1) {

        wifi_hal_dbg_print("%s:%d:Error value of default_code= %s\n", __func__, __LINE__,code);

        return -1;
    }
    wifi_hal_info_print("%s:%d:Actual value of default_code= %s\n", __func__, __LINE__,code);
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}


int platform_get_wps_pin_default(char *pin)
{
    return -1;
}

static int update_radio_vap_status_shm(void)
{
    int shm_fd;
    void* ptr;
    FILE *out;

    shm_fd = shm_open(RADIO_VAP_STATUS_SHM_OBJ_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        wifi_hal_error_print("%s:%d: shm_open failed, errno %d\n", __func__, __LINE__, errno);
        return RETURN_ERR;
    }
    if (ftruncate(shm_fd, RADIO_VAP_STATUS_SHM_OBJ_SIZE) == -1) {
        wifi_hal_error_print("%s:%d: ftruncate failed, errno %d\n", __func__, __LINE__, errno);
        close(shm_fd);
        return RETURN_ERR;
    }
    ptr = mmap(0, RADIO_VAP_STATUS_SHM_OBJ_SIZE, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        wifi_hal_error_print("%s:%d: mmap failed, errno %d\n", __func__, __LINE__, errno);
        close(shm_fd);
        return RETURN_ERR;
    }
    close(shm_fd);

    memset(ptr, 0, RADIO_VAP_STATUS_SHM_OBJ_SIZE);
    out = fmemopen(ptr, RADIO_VAP_STATUS_SHM_OBJ_SIZE, "a");
    if (out == NULL) {
        wifi_hal_error_print("%s:%d: fmemopen failed, errno %d\n", __func__, __LINE__, errno);
        munmap(ptr, RADIO_VAP_STATUS_SHM_OBJ_SIZE);
        return RETURN_ERR;
    }

    for(unsigned int index = 0; index < g_wifi_hal.num_radios; index++) {
        wifi_interface_info_t *interface;
        wifi_radio_info_t *radio;

        radio = get_radio_by_rdk_index(index);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: Could not find radio index:%d\n", __func__, __LINE__, index);
            continue;
        }

        fprintf(out, "radio:%d, status:%d\n", radio->rdk_radio_index, radio->oper_param.enable);

        if (radio->interface_map == NULL) {
            wifi_hal_error_print("%s:%d: Interface map is NULL for radio index:%d\n", __func__, __LINE__, index);
            continue;
        }

        interface = hash_map_get_first(radio->interface_map);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: Interface map is empty for radio index:%d\n", __func__, __LINE__, index);
            continue;
        }

        while (interface != NULL) {
            // on CMXB7 platform radio interfaces have vap_index -1
            // therefore check for interface vap_index
            // and don't add radio interfaces to vap map
            if ((int)interface->vap_info.vap_index >= 0) {
                fprintf(out, "vap:%.2d, status:%d, mac:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X, interface:%s\n",
                        interface->vap_info.vap_index, interface->interface_status,
                        interface->mac[0], interface->mac[1], interface->mac[2],
                        interface->mac[3], interface->mac[4], interface->mac[5],
                        interface->name);
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    fclose(out);
    munmap(ptr, RADIO_VAP_STATUS_SHM_OBJ_SIZE);
    return RETURN_OK;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char temp_buff[MAX_UCI_BUF_LEN];
    memset(temp_buff, 0 ,sizeof(temp_buff));
    char temp_buff1[MAX_UCI_BUF_LEN];
    memset(temp_buff1, 0 ,sizeof(temp_buff1));
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, index);

    if (uci_converter_alloc_local_uci_context()) {
        wifi_hal_dbg_print("%s:%d: alloc local context returned err!\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    get_coutry_str_from_code(operationParam->countryCode, temp_buff);
    // Canada 'CA' uses high power mode set as "CB" in the driver
    if( temp_buff[0] == 'C' && temp_buff[1] == 'A') {
        temp_buff[1] = 'B';
        wifi_hal_dbg_print("%s:%d: Forcing to CA High Power\n", __func__, __LINE__);
    }

    wifi_hal_dbg_print("%s:%d:setting UCI country_str %s\n", __func__, __LINE__, temp_buff);

    uci_converter_set_str(TYPE_RADIO, index, "country", temp_buff);

    memset(temp_buff, 0 ,sizeof(temp_buff));

    switch (operationParam->band)
    {
        case WIFI_FREQUENCY_2_4_BAND:
            strcpy(temp_buff, "2.4GHz");
            break;
        case WIFI_FREQUENCY_5_BAND:
            strcpy(temp_buff, "5GHz");
            break;
        case WIFI_FREQUENCY_5L_BAND:
            strcpy(temp_buff, "Low 5GHz");
            break;
        case WIFI_FREQUENCY_5H_BAND:
            strcpy(temp_buff, "High 5Ghz");
            break;
        case WIFI_FREQUENCY_6_BAND:
            strcpy(temp_buff, "6GHz");
            break;
        case WIFI_FREQUENCY_60_BAND:
            strcpy(temp_buff, "60GHz");
            break;
        default:
            strcpy(temp_buff, "");
            break;
    }

    uci_converter_set_str(TYPE_RADIO, index, "band", temp_buff);
    uci_converter_set_uint(TYPE_RADIO, index, "beacon_int",
        operationParam->beaconInterval);
    memset(temp_buff, 0 ,sizeof(temp_buff));
    get_radio_variant_str_from_int(operationParam->variant, temp_buff);
    hwmode_format_uci(temp_buff1, temp_buff);
    uci_converter_set_str(TYPE_RADIO, index, "hwmode", temp_buff1);

    if (operationParam->autoChannelEnabled) {
        uci_converter_set_str(TYPE_RADIO, index, "channel", "auto");
    } else {
        uci_converter_set_ulong(TYPE_RADIO, index, "channel",
            operationParam->channel);
    }

    uci_converter_commit_wireless();
    uci_converter_free_local_uci_context();

    if(update_radio_vap_status_shm() == -1) {
        wifi_hal_error_print("%s:%d: update_radio_vap_status_shm failed\n", __func__, __LINE__);
    }

    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *vap;
    unsigned int i;

    wifi_hal_dbg_print("%s:%d: \n", __func__, __LINE__);

    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
    }

    for (i = 0; i < map->num_vaps; i++)
    {
        mac_address_t dummy_mac;
        char interface_name[8];
        char bssid[18] = { 0 };
        vap = &map->vap_array[i];
        get_interface_name_from_vap_index(map->vap_array[i].vap_index,
            interface_name);
        char cmd[128] = {};
        snprintf(cmd, sizeof(cmd), "atom_util macdb vap %s", interface_name);
        FILE *fp = popen(cmd, "r");

        fscanf(fp, "%s", bssid);
        pclose(fp);

        to_mac_bytes(bssid, dummy_mac);

        memcpy(vap->u.bss_info.bssid, dummy_mac, sizeof(dummy_mac));
    }

    return 0;
}

static void set_led_status(int led_color, led_states_t led_state, int led_interval)
{
    LEDMGMT_PARAMS ledMgmt = {0};
    int ret;

    ledMgmt.LedColor = led_color;
    ledMgmt.State    = led_state;// 0 for Solid, 1 for Blink.
    ledMgmt.Interval = led_interval;
    if ((ret = platform_hal_setLed(&ledMgmt)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: LED status set failure %i\n", __func__, __LINE__, ret);
    }
}

int platform_wps_event(wifi_wps_event_t data)
{
    static LEDMGMT_PARAMS curr_led_value;
    static uint8_t wps_active = 0;

    switch(data.event) {
        case WPS_EV_PBC_ACTIVE:
        case WPS_EV_PIN_ACTIVE:
            if (!wps_active) {
                if(platform_hal_getLed(&curr_led_value) != RETURN_OK) {
                    wifi_hal_error_print("%s:%d led status get failure:led color:%d led_state:%d led_interval:%d\r\n", __func__,
                            __LINE__, curr_led_value.LedColor, curr_led_value.State, curr_led_value.Interval);
                } else {
                    wifi_hal_dbg_print("%s:%d current led color:%d led_state:%d led_interval:%d\r\n", __func__, __LINE__,
                            curr_led_value.LedColor, curr_led_value.State, curr_led_value.Interval);
                }

                // set wps led color to blue
                set_led_status(LED_BLUE, LED_BLINK_STATE, 0);
                wifi_hal_dbg_print("%s:%d set wps led color to blue\r\n", __func__, __LINE__);
                wps_active = 1;
            }
            break;
        case WPS_EV_SUCCESS:
        case WPS_EV_PBC_TIMEOUT:
        case WPS_EV_PBC_DISABLE:
        case WPS_EV_PIN_TIMEOUT:
        case WPS_EV_PIN_DISABLE:
            if (wps_active) {
                // set wps led color to white
                set_led_status(curr_led_value.LedColor, curr_led_value.State, curr_led_value.Interval);
                wifi_hal_dbg_print("%s:%d set led color:%d led_state:%d led_interval:%d\r\n", __func__, __LINE__,
                                curr_led_value.LedColor, curr_led_value.State, curr_led_value.Interval);
                wps_active = 0;
            }
            break;

        default:
            wifi_hal_info_print("%s:%d wps event[%d] not handle\r\n", __func__, __LINE__, data.event);
            break;
    }

    return 0;
}

/* XXX: should be refactored, using uci set */
int platform_create_vap(wifi_radio_index_t r_index, wifi_vap_info_map_t *map)
{
    char temp_buff[MAX_UCI_BUF_LEN];
    int index =0;
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, r_index);

    if (uci_converter_alloc_local_uci_context())
    {
        wifi_hal_dbg_print("%s:%d: alloc local context returned err!\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }
    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
    }
    for (index = 0; index < map->num_vaps; index++)
    {
      if (map->vap_array[index].vap_mode == wifi_vap_mode_ap)
      {
        memset(temp_buff, 0 ,sizeof(temp_buff));
        if (get_security_mode_str_from_int(map->vap_array[index].u.bss_info.security.mode, map->vap_array[index].vap_index, temp_buff) == RETURN_OK)
        {
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "encryption", temp_buff))
            wifi_hal_dbg_print("%s:%d: Failed to set the encryption type:%s for apIndex:%d\n", __func__, __LINE__,temp_buff,map->vap_array[index].vap_index);
        }
        if  (strlen(map->vap_array[index].repurposed_vap_name) == 0) {
            if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "ssid", map->vap_array[index].u.bss_info.ssid))
                wifi_hal_dbg_print("%s:%d:Failed to set the SSID:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.ssid,map->vap_array[index].vap_index);
        } else {
            wifi_hal_info_print("%s is repurposed to %s hence not setting ssid in uci \n",map->vap_array[index].vap_name,map->vap_array[index].repurposed_vap_name);
        }
        if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index,"wps_pin",map->vap_array[index].u.bss_info.wps.pin))
          wifi_hal_dbg_print("%s:%d: Failed to set the wps:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.wps.pin,map->vap_array[index].vap_index);
        if ((get_security_mode_support_radius(map->vap_array[index].u.bss_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index))
        {
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "auth_server", map->vap_array[index].u.bss_info.security.u.radius.ip))
            wifi_hal_dbg_print("%s:%d:  Failed to set the auth server:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.ip,map->vap_array[index].vap_index);
          if(map->vap_array[index].u.bss_info.security.u.radius.port != 0 )
          {
            if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "auth_port", map->vap_array[index].u.bss_info.security.u.radius.port))
              wifi_hal_dbg_print("%s:%d: Failed to set the auth port:%d for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.port,map->vap_array[index].vap_index);
          }
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "auth_secret", map->vap_array[index].u.bss_info.security.u.radius.key))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth secret:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.key,map->vap_array[index].vap_index);
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_server", map->vap_array[index].u.bss_info.security.u.radius.ip))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth server:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.ip,map->vap_array[index].vap_index);
          if(map->vap_array[index].u.bss_info.security.u.radius.port != 0 )
          {
            if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_port", map->vap_array[index].u.bss_info.security.u.radius.port))
             wifi_hal_dbg_print("%s:%d: Failed to set the auth port:%d for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.port,map->vap_array[index].vap_index);
          }
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_secret", map->vap_array[index].u.bss_info.security.u.radius.key))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth secret:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.key,map->vap_array[index].vap_index);
        }
        else
        {
            if  (strlen(map->vap_array[index].repurposed_vap_name) == 0) {
                if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "key", map->vap_array[index].u.bss_info.security.u.key.key))
                 wifi_hal_dbg_print("%s:%d: Failed to set the KeyPassPhrase:%s for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.key.key,map->vap_array[index].vap_index);
             } else {
                wifi_hal_info_print("%s is repurposed to %s hence not setting key in uci \n",map->vap_array[index].vap_name,map->vap_array[index].repurposed_vap_name);
             }
        }
        if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "hessid" ,map->vap_array[index].u.bss_info.interworking.interworking.hessid))
          wifi_hal_dbg_print("%s:%d: Failed to set the hessid:%s for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.hessid,map->vap_array[index].vap_index);
        if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "venue_group" , map->vap_array[index].u.bss_info.interworking.interworking.venueGroup))
          wifi_hal_dbg_print("%s:%d: Failed to set the venuegroup:%d for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.venueGroup,map->vap_array[index].vap_index);
        if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "venue_type" , map->vap_array[index].u.bss_info.interworking.interworking.venueType))
          wifi_hal_dbg_print("%s:%d: Failed to set the venuetype:%d for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.venueType,map->vap_array[index].vap_index);
      }
      else if (map->vap_array[index].vap_mode == wifi_vap_mode_sta)
      {
        memset(temp_buff, 0 ,sizeof(temp_buff));
        if (get_security_mode_str_from_int(map->vap_array[index].u.bss_info.security.mode, map->vap_array[index].vap_index, temp_buff) == RETURN_OK)
        {
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "encryption", temp_buff))
            wifi_hal_dbg_print("%s:%d: Failed to set the encryption type:%s for apIndex:%d\n", __func__, __LINE__,temp_buff,map->vap_array[index].vap_index);
        }
        if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "ssid", map->vap_array[index].u.bss_info.ssid))
          wifi_hal_dbg_print("%s:%d:Failed to set the SSID:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.ssid,map->vap_array[index].vap_index);
        if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index,"wps_pin",map->vap_array[index].u.bss_info.wps.pin))
          wifi_hal_dbg_print("%s:%d: Failed to set the wps:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.wps.pin,map->vap_array[index].vap_index);
        if ((get_security_mode_support_radius(map->vap_array[index].u.bss_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index))
        {
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "auth_server", map->vap_array[index].u.bss_info.security.u.radius.ip))
            wifi_hal_dbg_print("%s:%d:  Failed to set the auth server:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.ip,map->vap_array[index].vap_index);
          if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "auth_port", map->vap_array[index].u.bss_info.security.u.radius.port))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth port:%d for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.port,map->vap_array[index].vap_index);
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "auth_secret", map->vap_array[index].u.bss_info.security.u.radius.key))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth secret:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.key,map->vap_array[index].vap_index);
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_server", map->vap_array[index].u.bss_info.security.u.radius.ip))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth server:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.ip,map->vap_array[index].vap_index);
          if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_port", map->vap_array[index].u.bss_info.security.u.radius.port))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth port:%d for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.port,map->vap_array[index].vap_index);
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "sec_auth_secret", map->vap_array[index].u.bss_info.security.u.radius.key))
            wifi_hal_dbg_print("%s:%d: Failed to set the auth secret:%s for apIndex:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.radius.key,map->vap_array[index].vap_index);
        }
        else
        {
          if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "key", map->vap_array[index].u.bss_info.security.u.key.key))
            wifi_hal_dbg_print("%s:%d: Failed to set the KeyPassPhrase:%s for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.security.u.key.key,map->vap_array[index].vap_index);
        }
        if(uci_converter_set_str(TYPE_VAP, map->vap_array[index].vap_index, "hessid" ,map->vap_array[index].u.bss_info.interworking.interworking.hessid))
          wifi_hal_dbg_print("%s:%d: Failed to set the hessid:%s for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.hessid,map->vap_array[index].vap_index);
        if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "venue_group" , map->vap_array[index].u.bss_info.interworking.interworking.venueGroup))
          wifi_hal_dbg_print("%s:%d: Failed to set the venuegroup:%d for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.venueGroup,map->vap_array[index].vap_index);
        if(uci_converter_set_uint(TYPE_VAP, map->vap_array[index].vap_index, "venue_type" , map->vap_array[index].u.bss_info.interworking.interworking.venueType))
          wifi_hal_dbg_print("%s:%d: Failed to set the venuetype:%d for index:%d\n", __func__, __LINE__,map->vap_array[index].u.bss_info.interworking.interworking.venueType,map->vap_array[index].vap_index);
      }
    }
    uci_converter_commit_wireless();
    uci_converter_free_local_uci_context();

    if(update_radio_vap_status_shm() == -1) {
        wifi_hal_error_print("%s:%d: update_radio_vap_status_shm failed\n", __func__, __LINE__);
    }

    return 0;
}

int platform_flags_init(int *flags)
{
    *flags = PLATFORM_FLAGS_SET_BSS | PLATFORM_FLAGS_CONTROL_PORT_FRAME |
             PLATFORM_FLAGS_PROBE_RESP_OFFLOAD |
             PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY;

    return 0;
}

int wifi_setQamPlus(void* priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    int res = 0;
    int sQAMplus = 0;
#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_QAMPLUS_MODE,
                                (u8*)&sQAMplus, sizeof(sQAMplus), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_QAMPLUS_MODE,
                               (u8*)&sQAMplus, sizeof(sQAMplus), NULL);
#endif
    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending _QAMPLUS_MODE failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }
    return res;
}

int wifi_setApRetrylimit(void* priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    int res = 0;
    int RL[2]; // RL means RetryLimit
    RL[0]=4;
    RL[1]=7;
#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT,
                                (u8*)RL, sizeof(RL), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_AP_RETRY_LIMIT,
                               (u8*)RL, sizeof(RL), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending _AP_RETRY_LIMIT failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }

    return res;
}


/* Set Broadcast probe request offload mode:
    0 - offload ON (default)             | only necessary frames are forwared to user space
    1 - turn of wildcard SSID offload    | only necessary frames + wildcards SSID's are forwared to user space
    2 - offload OFF                      | all frames are forwarded to user space (may degrade performance in a busy environment)

    The default mode (0) is preferable,
    but in certain cases is is necessary to forward to the user space more broadcast probe requests for analysis
    The desired mode (1) or (2) depends on customer's requirements.
*/
int platform_set_offload_mode(void* priv, uint offload_mode)
{
    int res = -1;
    wifi_hal_dbg_print("%s:%d: send SET_PROBEREQ_OFFLOAD_MODE request\n", __func__, __LINE__);

    if (!priv){
        return res;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_PROBEREQ_OFFLOAD_MODE,
                                (u8*) &offload_mode, sizeof(offload_mode), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_PROBEREQ_OFFLOAD_MODE,
                                (u8*) &offload_mode, sizeof(offload_mode), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending SET_PROBEREQ_OFFLOAD_MODE failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }

    return res;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
    int res = -1;
    struct wpabuf *rsp_aid;
    int aid_size = sizeof(u16);

    if (!addr){
        return res;
    }

    if (*aid) {
        wifi_hal_dbg_print("Reusing old AID %hu\n", *aid);
        return 0;
    }

    rsp_aid = wpabuf_alloc(aid_size);
    if (!rsp_aid) {
        return -ENOBUFS;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_AID,
                                addr, ETH_ALEN, NESTED_ATTR_NOT_USED, rsp_aid);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_AID,
                                addr, ETH_ALEN, rsp_aid);
#endif

    if (res) {
        wifi_hal_dbg_print("nl80211: sending/receiving GET_AID failed: %i "
            "(%s)\n", res, strerror(res));
        *aid = 0;
    } else {
        memcpy(aid, rsp_aid->buf, aid_size);
        wifi_hal_dbg_print("Received a new AID %hu\n", *aid);
    }

    wpabuf_free(rsp_aid);

    return res;
}

int platform_free_aid(void* priv, u16* aid)
{
    int res = -1;

    if (!aid){
        return res;
    }

    if (0 == *aid) {
        return 0;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_FREE_AID,
                                (u8*) aid, sizeof(*aid), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_FREE_AID,
                                (u8*) aid, sizeof(*aid), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("nl80211: sending FREE_AID failed: %i "
            "(%s)\n", res, strerror(res));
    } else {
        wifi_hal_dbg_print("AID %hu released\n", *aid);
        *aid = 0;
    }

    return res;
}

int platform_sync_done(void* priv)
{
    int res = -1;

    if (!priv){
        return res;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SYNC_DONE,
                                NULL, 0, NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SYNC_DONE,
                                NULL, 0, NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("nl80211: sending SYNC_DONE failed: %i "
            "(%s)\n", res, strerror(res));
    }

    return res;
}

int platform_get_vap_measurements(void *priv, struct intel_vendor_vap_info *vap_info)
{
    int ret;
    struct wpabuf *rsp;

    rsp = wpabuf_alloc(sizeof(*vap_info));
    if (!rsp) {
        return -ENOBUFS;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_VAP_MEASUREMENTS,
                                NULL, 0, NESTED_ATTR_NOT_USED, rsp);
#else
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_VAP_MEASUREMENTS,
                                NULL, 0, rsp);
#endif

    if (ret) {
        wifi_hal_error_print("%s: nl80211: sending/receiving GET_VAP_MEASUREMENTS "
            "failed: %i (%s)\n", __func__, ret, strerror(-ret));
        goto out;
    }

    if (rsp->used != sizeof(*vap_info)) {
        ret = -EMSGSIZE;
        wifi_hal_error_print("%s: nl80211: driver returned %zu bytes instead of %zu",
            __func__, rsp->used, sizeof(*vap_info));
        goto out;
    }

    memcpy(vap_info, rsp->buf, sizeof(*vap_info));

out:
    wpabuf_free(rsp);
    return ret;
}

int platform_get_radio_info(void *priv, struct intel_vendor_radio_info *radio_info)
{
    int ret;
    struct wpabuf *rsp;

    rsp = wpabuf_alloc(sizeof(*radio_info));
    if (!rsp) {
        return -ENOBUFS;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_RADIO_INFO,
                                NULL, 0, NESTED_ATTR_NOT_USED, rsp);
#else
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_RADIO_INFO,
                                NULL, 0, rsp);
#endif

    if (ret) {
        wifi_hal_error_print("%s: nl80211: sending/receiving GET_RADIO_INFO "
            "failed: %i (%s)\n", __func__, ret, strerror(-ret));
        goto out;
    }

    if (rsp->used != sizeof(*radio_info)) {
        ret = -EMSGSIZE;
        wifi_hal_error_print("%s: nl80211: driver returned %zu bytes instead of %zu",
            __func__, rsp->used, sizeof(*radio_info));
        goto out;
    }

    memcpy(radio_info, rsp->buf, sizeof(*radio_info));

out:
    wpabuf_free(rsp);
    return ret;
}

int platform_get_sta_measurements(void *priv, const u8 *sta_addr, struct intel_vendor_sta_info *sta_info)
{
    int ret;
    struct wpabuf *rsp;

    rsp = wpabuf_alloc(sizeof(*sta_info));
    if (!rsp) {
        return -ENOBUFS;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_STA_MEASUREMENTS,
                                NULL, 0, NESTED_ATTR_NOT_USED, rsp);
#else
    ret = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_STA_MEASUREMENTS,
                                NULL, 0, rsp);
#endif

    if (ret) {
        wifi_hal_error_print("%s: nl80211: sending/receiving GET_STA_MEASUREMENTS "
            "failed: %i (%s)\n", __func__, ret, strerror(-ret));
        goto out;
    }

    if (rsp->used != sizeof(*sta_info)) {
        ret = -EMSGSIZE;
        wifi_hal_error_print("%s: nl80211: driver returned %zu bytes instead of %zu",
            __func__, rsp->used, sizeof(*sta_info));
        goto out;
    }

    memcpy(sta_info, rsp->buf, sizeof(*sta_info));
    wifi_hal_dbg_print("%s: nl80211: Received station measurements for station " MACSTR, __func__, MAC2STR(sta_addr));

out:
    wpabuf_free(rsp);
    return ret;
}

int platform_set_txpower(void* priv, uint txpower)
{
    int res = -1;
    int sPowerSelection = 0;

    wifi_hal_dbg_print("%s:%d: send SET_TX_POWER_LIMIT_OFFSET request\n", __func__, __LINE__);

    if (!priv){
        return res;
    }

    switch (txpower) {
        case 12: sPowerSelection=9; break;
        case 25: sPowerSelection=6; break;
        case 50: sPowerSelection=3; break;
        case 75: sPowerSelection=1; break;
        case 100: sPowerSelection=0; break;
        default:
            wifi_hal_error_print("%s:%d: unsupported transmit power (%u%%)\n", __func__, __LINE__, txpower);
            return res;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_TX_POWER_LIMIT_OFFSET,
                                (u8*) &sPowerSelection, sizeof(sPowerSelection), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(priv, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_TX_POWER_LIMIT_OFFSET,
                                (u8*) &sPowerSelection, sizeof(sPowerSelection), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending SET_TX_POWER_LIMIT_OFFSET failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }

    return res;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    FILE *fp;
    char c;
    char interface_name[8];
    get_interface_name_from_vap_index(vap_index, interface_name);
    char acl_path[50] = {};
    snprintf(acl_path, sizeof(acl_path), "/proc/net/mtlk/%s/acl_list", interface_name);

    fp = fopen(acl_path, "r");

	if (fp == NULL) {
		wifi_hal_dbg_print("%s:%d: acl_list failed to open hal acl count:%d\r\n", __func__, __LINE__, *acl_count);
        return -1;
	} else {
        for (c = getc(fp); c != EOF; c = getc(fp)) {
            if (c == '\n')
                *acl_count = *acl_count + 1;
        }
        *acl_count = *acl_count - 2;
        fclose(fp);
    }
    return 0;
}

int platform_get_radius_key_default(char *radius_key)
{
    char key[MAX_KEYPASSPHRASE_LEN] = {0};
    FILE *fp = NULL;

    //Default passphrase for LnF vaps
    wifi_hal_dbg_print("platform_get_radius_key_default - lnf radius\n");
    fp = popen ("/lib/rdk/lnfScript.sh get_default_lnf_radius_auth", "r");
    if(fp != NULL)
    {
        if (fgets (key, sizeof (key), fp) == NULL)
        {
            wifi_hal_dbg_print("platform_get_radius_key_default: failed to get default LNF passphrase\n");
            pclose(fp);
            return -1;
        }
        if(key[0] != '\0')
        {
            if( key[strlen(key) - 1] == '\n')
            {
                key[strlen(key) - 1] = '\0';
            }

            strncpy(radius_key, key, strlen(key));
            wifi_hal_dbg_print("platform_get_radius_key_default - LNF done.\n");
            pclose(fp);
            memset(key,0,sizeof(key));
            return 0;
        }
        else
        {
            wifi_hal_dbg_print("platform_get_radius_key_default - Key NULL\n");
            pclose(fp);
            return -1;
        }
    }
    return 0;
}

int platform_update_radio_presence(void)
{
    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    return 0;
}

/* Stub for MXL platform to resolve build issue. */
int platform_get_chanspec_list(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, const wifi_channels_list_t *channels, char *buff)
{
    //wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__); 
    return 0;
}

/* Stub for MXL platform to resolve build issue. */
int platform_set_acs_exclusion_list(wifi_radio_index_t index,char *buff)
{
    //wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__); 
    return 0;
}

int platform_get_vendor_oui (char *vendor_oui, int vendor_oui_len)
{
    return -1;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    struct wpabuf *resp;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    int res, resp_size = sizeof(u32);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get primary interface for index: %d\n", __func__,
            __LINE__, index);
        return RETURN_ERR;
    }

    resp = wpabuf_alloc(resp_size);
    if (resp == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate buffer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_TEMPERATURE_SENSOR,
        NULL, 0, NESTED_ATTR_NOT_USED, resp);
#else
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_GET_TEMPERATURE_SENSOR,
        NULL, 0, resp);
#endif

    if (res < 0) {
        wifi_hal_error_print("%s:%d: Failed to get temperature, err: %d (%s)\n", __func__,
            __LINE__, res, strerror(res));
    } else {
        memcpy(&radioPhyTemperature->radio_Temperature, resp->buf, resp_size);
    }

    wpabuf_free(resp);

    return res;
}

#if HAL_IPC
//==================================================================================================
// HAL API stubs
// because for HAL-IPC feature usage hal-wifi-generic(HAL-IPC client) was unlinked from rdk-wifihal(HAL-IPC server) and OneWifi(target user)
// we need to provide definitions of some functions used by rdk-wifi-hal and/or OneWifi

//--------------------------------------------------------------------------------------------------
// NOTE: to be removed after MxL provide implementation
INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    return wifi_hal_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list);
}

//--------------------------------------------------------------------------------------------------
// NOTE: to be removed after MxL provide implementation
INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    return wifi_hal_getNeighboringWiFiStatus(radio_index, neighbor_ap_array, output_array_size);
}

//--------------------------------------------------------------------------------------------------
INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_pushApRoamingConsortiumElement(INT apIndex, wifi_roamingConsortiumElement_t *infoElement)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setApManagementFramePowerControl(INT apIndex, INT dBm)
{
    wifi_interface_info_t *interface = NULL;
    int res = 0;

    if ((interface = get_interface_by_vap_index(apIndex)) == NULL) {
        wifi_hal_error_print("%s:%d:interface for ap index:%d not found\n", __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#if HOSTAPD_VERSION >= 210 //2.10
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL,
                                (u8*) &dBm, sizeof(dBm), NESTED_ATTR_NOT_USED, NULL);
#else
    res = wifi_drv_vendor_cmd(interface, OUI_LTQ, LTQ_NL80211_VENDOR_SUBCMD_SET_MGMT_FRAME_PWR_CTRL,
                               (u8*) &dBm, sizeof(dBm), NULL);
#endif

    if (res) {
        wifi_hal_dbg_print("%s:%d: nl80211: sending _MGMT_FRAME_PWR_CTRL failed: %i "
            "(%s)\n",  __func__, __LINE__, res, strerror(res));
    }
    return res;
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
INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)
{
    wifi_radio_info_t *radio;

    radio = get_radio_by_rdk_index(radioIndex);

    if (!radio)
    {
        return RETURN_ERR;
    }

    if (radio->configured && radio->oper_param.enable){
        *output_ulong = radio->oper_param.channel;
        return RETURN_OK;
    } else {
        return RETURN_ERR;
    }
}

//--------------------------------------------------------------------------------------------------
INT wifi_setProxyArp(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setCountryIe(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getLayer2TrafficInspectionFiltering(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getCountryIe(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setP2PCrossConnect(INT apIndex, BOOL disabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getDownStreamGroupAddress(INT apIndex, BOOL *disabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getProxyArp(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_applyGASConfiguration(wifi_GASConfiguration_t *input_struct)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getBssLoad(INT apIndex, BOOL *enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_pushApHotspotElement(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setBssLoad(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_getApInterworkingServiceEnable(INT apIndex, BOOL *output_bool)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, MacAddr, frequency, 0, frame, len);
}

//--------------------------------------------------------------------------------------------------
INT wifi_setDownStreamGroupAddress(INT apIndex, BOOL disabled)
{
    return RETURN_ERR;
}

//--------------------------------------------------------------------------------------------------
INT wifi_setLayer2TrafficInspectionFiltering(INT apIndex, BOOL enabled)
{
    return RETURN_ERR;
}
int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    return 0;
}
#endif // HAL_IPC

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return 0;
}

int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    return RETURN_OK;
}

int platform_set_beacon_prot(uint apIndex, bool isEnabled)
{
    return RETURN_OK;
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
    wifi_hal_error_print("%s:%d: not implemented\n", __func__, __LINE__);
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
#ifdef CONFIG_MLO
    wifi_hal_error_print("%s:%d: not implemented\n", __func__, __LINE__);
    return RETURN_ERR;
#else
    wifi_hal_error_print("%s:%d: CONFIG_MLO is not set\n", __func__, __LINE__);
    return RETURN_OK;
#endif /* CONFIG_MLO */
}

#endif /* CONFIG_IEEE80211BE */
