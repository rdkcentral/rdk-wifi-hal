/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
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

/**********************************************************************************************
   Changes from Qualcomm Innovation Center, Inc. are provided under the following license:
   Copyright (c) 2022, 2024 Qualcomm Innovation Center, Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

**********************************************************************************************/

#include <string.h>
#include <stdbool.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>
#include "qcconfig_utils.h"
#include <ctype.h>
#include "driver_nl80211.h"
#include "ieee802_11.h"
#include "ap/rrm.h"

/* Use the QCA vendor header for ATF NL80211 vendor command attributes.
 * We implement the ATF NL80211 commands directly using rdk-wifi-hal's
 * nl80211_send_and_recv() because hapd->drv_priv uses struct i802_bss *
 * (hostapd nl80211 priv) which is incompatible with rdk-wifi-hal's
 * wifi_interface_info_t * priv. */
#include "common/qca-vendor.h"
/* ATF airtime scale factor: firmware expects percentage * 10 */
#ifdef CONFIG_ATF_OFFLOAD
#define ATF_AIRTIME_SCALE(pct)  ((u16)((pct) * 10))
/* Max size for ATF stats string buffer */
#define ATF_STATS_BUF_MAX 4096

/*
 * WMM AC config TLV format (matches hostapd atf_offload.h):
 *   TAG_ARRAY_STRUCT = 0x12
 *   TAG_ATF_GROUP_WMM_AC_INFO = 841
 *   PREP(tag, len) = (len & 0xFFFF) | ((tag & 0xFFFF) << 16)
 *   HDR_SIZE = sizeof(uint32_t) = 4
 *
 * struct atf_group_wmm_ac_info {
 *     __le32 header;        // PREP(TAG_ATF_GROUP_WMM_AC_INFO, sizeof-HDR_SIZE)
 *     __le32 atf_group_id;
 *     __le32 atf_units_be;
 *     __le32 atf_units_bk;
 *     __le32 atf_units_vi;
 *     __le32 atf_units_vo;
 * };  // 24 bytes
 */
#define ATF_WMM_TAG_ARRAY_STRUCT        0x12
#define ATF_WMM_TAG_GROUP_INFO          841
#define ATF_WMM_HDR_SIZE                4   /* sizeof(__le32 header) */
#define ATF_WMM_GROUP_INFO_SIZE         24  /* sizeof(atf_group_wmm_ac_info) */
#define ATF_WMM_PREP(tag, len)          (((len) & 0xFFFF) | (((tag) & 0xFFFF) << 16))
#endif /* CONFIG_ATF_OFFLOAD */

#if HAL_IPC
#include "hal_ipc.h"
#include "server_hal_ipc.h"
#endif

#define WIFI_AP_MAX_PASSPHRASE_LEN 300
#define WIFI_MAX_RADIUS_KEY 128
#define COUNTRY_LENGTH 10
#define MAX_KEYPASSPHRASE_LEN 128
#define MAX_SSID_LEN 33
#define DEFAULT_SSID_SIZE 128
#define DEFAULT_CMD_SIZE 256
#define MAX_BUF_SIZE 300
#define VAP_PREFIX "ath"
#define RADIO_PREFIX "wifi"
#define IPQ_UD_MAX_NUM_RADIOS 3
#define RETRY_LIMIT 7

#define WIFI_24G_MAC_ADDR_KEY "WiFi 2.4GHz MAC address"
#define WIFI_50G_MAC_ADDR_KEY "WiFi 5.0GHz MAC address"
#define DEFAULT_24G_SSID_KEY "Default 2.4 GHz SSID"
#define DEFAULT_50G_SSID_KEY "Default 5.0 GHz SSID"
#define DEFAULT_60G_SSID_KEY "Default 6.0 GHz SSID"
#define DEFAULT_MESH_BACKHAUL_SSID_KEY "Default Mesh Backhaul SSID"
#define DEFAULT_WIFI_PASSWORD_KEY "Default WIFI Password"
#define DEFAULT_XHS_SSID_KEY "Default XHS SSID for 2.4GHZ and 5.0GHZ"
#define DEFAULT_XHS_PASSWORD_KEY "Default XHS Password"
#define MAX_DEFAULT_VALUE_SIZE 128
#define FACTORY_DEFAULTS_FILE "/etc/factory_nvram.data"

#define QCA_MAX_CMD_SZ 128
#define MLD_PREFIX "mld"
#define OUI_QCA_ "001374"

/* QCA vendor OUI and config attribute definitions (from qca-vendor.h) */
#ifndef OUI_QCA
#define OUI_QCA 0x001374
#endif

#ifndef QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND
#define QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND  17
#define QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE    18
#define QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA     19
#endif

#ifndef QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID
#define QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID      99
#endif

#define QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS              200
/* Outer subcmds for vdev (VAP-level) and wiphy (radio-level) vendor commands */
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION   74
#define QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION   75
#define QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION  505
#define QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION  506
/* Attribute ID for radio index in vendor data (from ath12k/vendor.h) */
#ifndef QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX
#define QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX             150
#endif
/* Generic command value for radio-level wifi params (used by DFS vendor cmds) */
#define QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS_VAL               200
/*
 * ath12k returns GET_WIPHY_CONFIGURATION responses using a private enum
 * (qca_wlan_genric_data) rather than QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA:
 *   QCA_WLAN_VENDOR_ATTR_PARAM_DATA   (= 1) — u32 value
 *   QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH (= 2) — u32 sizeof(value)
 *   QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS  (= 3) — u32 0
 */
#define QCA_WLAN_VENDOR_ATTR_PARAM_DATA    1
#define QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH  2
#define QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS   3

/* Maximum file path length for NOL dump/restore */
#define DFS_NOL_FILEPATH_MAX_LEN           256
/* WIFI_PARAMS command ID */
#define WIFI_PARAMS 200

/* Vdev parameter IDs for REG_PARAMS */
#define VDEV_PARAM_REG_PARAMS   72  /* disable_opclass_chans */

#ifndef QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS
#define QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS   518
#endif

/* qca_wlan_vendor_attr_reg_params numeric values */
#define REG_PARAMS_ATTR_CMD      1   /* QCA_WLAN_VENDOR_ATTR_REG_PARAMS_CMD      */
#define REG_PARAMS_ATTR_LINKID   3   /* QCA_WLAN_VENDOR_ATTR_REG_PARAMS_LINKID   */
#define REG_PARAMS_ATTR_DISABLE  4   /* QCA_WLAN_VENDOR_ATTR_REG_PARAMS_DISABLE  */
#define REG_PARAMS_ATTR_OPCLASS  5   /* QCA_WLAN_VENDOR_ATTR_REG_PARAMS_OPCLASS  */
#define REG_PARAMS_ATTR_CHAN_LIST 6   /* QCA_WLAN_VENDOR_ATTR_REG_PARAMS_CHAN_LIST (nested) */

/* qca_wlan_vendor_reg_params cmd value for disable_opclass_chans */
#define REG_PARAMS_CMD_DISABLE_OPCLASS_CHANS 4

/* Radio/Vdev Parameter IDs */
#define RADIO_PARAM_COUNTRY         84  /* set_country / get_country */
#define RADIO_PARAM_COUNTRY_ID      85  /* set_country_id / get_country_id */
#define RADIO_PARAM_REGDOMAIN       86  /* set_regdomain / get_regdomain */
#define RADIO_PARAM_BANDINFO        81  /* get_bandinfo */
#define RADIO_PARAM_BAND_CHANS      82  /* display_band_chans */
#define RADIO_PARAM_SUPER_CHAN_LIST 83  /* display_super_chan_list */
#define VDEV_PARAM_LIST_CHAN        71  /* list_chan */
#define VDEV_PARAM_LIST_BAND        70  /* list_band */


#ifndef NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE
#define NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE 68
#endif

/* nl80211_6ghz_reg_rule_attr nested attribute IDs */
#define SCL_6GHZ_RULE_FLAGS       1   /* NL80211_6GHZ_REG_RULE_ATTR_FLAGS      */
#define SCL_6GHZ_RULE_POWER_RULE  2   /* NL80211_6GHZ_REG_RULE_ATTR_POWER_RULE */
#define SCL_6GHZ_RULE_MAX         2

/* nl80211_6ghz_reg_rule_flags */
#define SCL_6GHZ_LPI  (1 << 0)   /* Low Power Indoor  → PowerMode 1 */
#define SCL_6GHZ_VLP  (1 << 1)   /* Very Low Power    → PowerMode 3 */
/* SP (Standard Power) = neither LPI nor VLP → PowerMode 2 */

/* nl80211_reg_rule_attr IDs inside the nested power rule */
#define SCL_POWER_RULE_MAX_EIRP  6   /* NL80211_ATTR_POWER_RULE_MAX_EIRP (mBm) */
#define SCL_POWER_RULE_PSD       8   /* NL80211_ATTR_POWER_RULE_PSD (0.25 dBm) */
#define SCL_POWER_RULE_MAX       8

struct super_chan_ctx {
    char   *buf;
    size_t  buf_len;
    size_t  written;
    bool    got_data;
    bool    header_printed;
};

#define SCL_W(fmt, ...) \
    do { \
        if (ctx->written < ctx->buf_len) \
            ctx->written += snprintf(ctx->buf + ctx->written, \
                                     ctx->buf_len - ctx->written, \
                                     fmt, ##__VA_ARGS__); \
    } while (0)
/* Response context for NL80211 callbacks */
typedef struct {
    void   *data;
    size_t  data_len;
    size_t  data_received;
    int     error;
} nl80211_vendor_response_t;

extern int qca_getRadiosIndex();
extern int qca_nl_cfg80211_init();
extern int isValidAPIndex(int apIndex);

typedef enum radio_band {
    radio_2g = 0,
    radio_5g,
    radio_6g
} radio_band_t;

struct wifiChannelWidthMap
{
    wifi_channelBandwidth_t halWifiChanWidth;
    char wifiChanWidthName[16];
};

struct wifiVariantBitMap
{
    wifi_ieee80211Variant_t halWifiRadioMode;
    char halWifiRadioModename[5];
};

typedef struct
{
    radio_band_t halWifiBand;
    char wifiBandName[10];
}wifiBandMap;

wifiBandMap wifiRadioBandMap[] = 
{
    {radio_2g, "2GHz"},
    {radio_5g, "5GHz"},
    {radio_6g, "6GHz"},
};
    
struct wifiChannelWidthMap wifiChannelBandWidthMap[] =
{
    {WIFI_CHANNELBANDWIDTH_20MHZ,     "20MHz"},
    {WIFI_CHANNELBANDWIDTH_40MHZ,     "40MHz"},
    {WIFI_CHANNELBANDWIDTH_80MHZ,     "80MHz"},
    {WIFI_CHANNELBANDWIDTH_160MHZ,    "160MHz"},
    {WIFI_CHANNELBANDWIDTH_80_80MHZ,  "80+80MHz"},
};

struct wifiVariantBitMap wifiRadioModeBitMap[] = 
{
    {WIFI_80211_VARIANT_A,     "a"}, 
    {WIFI_80211_VARIANT_B,     "b"},
    {WIFI_80211_VARIANT_G,     "g"},
    {WIFI_80211_VARIANT_N,     "n"},
    {WIFI_80211_VARIANT_H,     "h"},
    {WIFI_80211_VARIANT_AC,   "ac"},
    {WIFI_80211_VARIANT_AD,   "ad"},
    {WIFI_80211_VARIANT_AX,   "ax"},
    {WIFI_80211_VARIANT_BE,   "be"},
};

/* write event explanations */
static const uint8_t *WPS_enum_to_str[] = {
    [WPS_EV_M2D]                       = (uint8_t*) "WPS_EV_M2D",
    [WPS_EV_FAIL]                      = (uint8_t*) "WPS_EV_FAIL",
    [WPS_EV_SUCCESS]                   = (uint8_t*) "WPS_EV_SUCCESS",
    [WPS_EV_PWD_AUTH_FAIL]             = (uint8_t*) "WPS_EV_PWD_AUTH_FAIL",
    [WPS_EV_PBC_OVERLAP]               = (uint8_t*) "WPS_EV_PBC_OVERLAP",
    [WPS_EV_PBC_TIMEOUT]               = (uint8_t*) "WPS_EV_PBC_TIMEOUT",
    [WPS_EV_PBC_ACTIVE]                = (uint8_t*) "WPS_EV_PBC_ACTIVE",
    [WPS_EV_PBC_DISABLE]               = (uint8_t*) "WPS_EV_PBC_DISABLE",
    [WPS_EV_PIN_TIMEOUT]               = (uint8_t*) "WPS_EV_PIN_TIMEOUT",
    [WPS_EV_PIN_DISABLE]               = (uint8_t*) "WPS_EV_PIN_DISABLE",
    [WPS_EV_PIN_ACTIVE]                = (uint8_t*) "WPS_EV_PIN_ACTIVE",
    [WPS_EV_ER_AP_ADD]                 = (uint8_t*) "WPS_EV_ER_AP_ADD",
    [WPS_EV_ER_AP_REMOVE]              = (uint8_t*) "WPS_EV_ER_AP_REMOVE",
    [WPS_EV_ER_ENROLLEE_ADD]           = (uint8_t*) "WPS_EV_ER_ENROLLEE_ADD",
    [WPS_EV_ER_ENROLLEE_REMOVE]        = (uint8_t*) "WPS_EV_ER_ENROLLEE_REMOVE",
    [WPS_EV_ER_AP_SETTINGS]            = (uint8_t*) "WPS_EV_ER_AP_SETTINGS",
    [WPS_EV_ER_SET_SELECTED_REGISTRAR] = (uint8_t*) "WPS_EV_ER_SET_SELECTED_REGISTRAR",
    [WPS_EV_AP_PIN_SUCCESS]            = (uint8_t*) "WPS_EV_AP_PIN_SUCCESS",
};
#ifdef QCA_UD_HOSTAPD
static const uint8_t *WPS_ei_to_str[] = {
    [WPS_EI_NO_ERROR]                      = (uint8_t*) "No Error",
    [WPS_EI_SECURITY_TKIP_ONLY_PROHIBITED] = (uint8_t*) "TKIP Only Prohibited",
    [WPS_EI_SECURITY_WEP_PROHIBITED]       = (uint8_t*) "WEP Prohibited",
    [WPS_EI_AUTH_FAILURE]                  = (uint8_t*) "Authentication Failure",
};
static const uint8_t *pbc_status_str[] = {
    [WPS_PBC_STATUS_DISABLE]         = (uint8_t*) "Disabled",
    [WPS_PBC_STATUS_ACTIVE]          = (uint8_t*) "Active",
    [WPS_PBC_STATUS_TIMEOUT]         = (uint8_t*) "Timed-out",
    [WPS_PBC_STATUS_OVERLAP]         = (uint8_t*) "Overlap",
};
#endif
enum vap_enum_type {
    vap_private = 0,
    vap_xhs,
    hotspot_open,
    vap_lnf_psk,
    vap_hotspot_secure,
    vap_lnf_radius,
    vap_mesh_backhaul,
    vap_mesh_sta,
    vap_invalid
};
typedef BOOL (*vap_type) (unsigned int ap_index);

vap_type vap_type_arr[10] = {

    is_wifi_hal_vap_private,
    is_wifi_hal_vap_xhs,
    is_wifi_hal_vap_hotspot_open,
    is_wifi_hal_vap_lnf_psk,
    is_wifi_hal_vap_hotspot_secure,
    is_wifi_hal_vap_lnf_radius,
    is_wifi_hal_vap_mesh_backhaul,
    is_wifi_hal_vap_mesh_sta
};

typedef struct {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

/**
 * struct sta_data_ctx - Context for NL80211 STA data callback
 * @data: Output structure to populate with STA statistics
 * @mac: MAC address of the STA being queried
 * @found: Flag indicating if the STA was found
 */
struct sta_data_ctx {
    struct hostap_sta_driver_data *data;
    const u8 *mac;
    bool found;
};

enum qca_vendor_vdev_param {
    QCA_WLAN_VENDOR_VDEV_PARAM_DIS_LPI_ANT_OPTIMIZE   = 62,
    QCA_WLAN_VENDOR_VDEV_PARAM_GET_MINTXPOWER         = 63,
    QCA_WLAN_VENDOR_VDEV_PARAM_GET_MAXTXPOWER         = 64,
    QCA_WLAN_VENDOR_VDEV_PARAM_REGTXPOWER             = 65,
    QCA_WLAN_VENDOR_VDEV_PARAM_GET_TXPOWER_RESOLUTION = 66,
    QCA_WLAN_VENDOR_VDEV_PARAM_GET_MAXRATE            = 72,
};
enum qca_vendor_radio_param {
    QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT2G            = 38,
    QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT5G            = 39,
    QCA_WLAN_VENDOR_RADIO_PARAM_ANTENNA_GAIN_2G            = 40,
    QCA_WLAN_VENDOR_RADIO_PARAM_ANTENNA_GAIN_5G            = 41,
    QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_SCALE              = 43,
    QCA_WLAN_VENDOR_RADIO_PARAM_DFS_NOL_SUBCHANNEL_MARKING = 74,
    QCA_WLAN_VENDOR_RADIO_PARAM_RADAR_DETECT_COUNT         = 75,
    QCA_WLAN_VENDOR_RADIO_PARAM_CTLPWRSCALE                = 76,
    QCA_WLAN_VENDOR_RADIO_PARAM_EN_CHAN_144                 = 77,
    QCA_WLAN_VENDOR_RADIO_PARAM_NOL_CHAN_LIST               = 79,
};

static int read_from_factory_defaults(char *filename, char *key, char *value, int val_len)
{
    FILE *fp = NULL;
    char buf[1024] = {0};
    char *ptr = NULL;
    int len;

    memset(value, '\0', val_len);
    if(access(filename, F_OK) == 0)
    {
        fp = fopen(filename, "r");
    }
    else
    {
        wifi_hal_error_print("%s:%d Factory file not found\n", __func__, __LINE__);
        return -1;
    }
    while(!feof(fp))
    {
        memset(buf, '\0', sizeof(buf));
        fgets(buf, sizeof(buf), fp);
        if((ptr = strstr(buf, key)) != NULL)
        {
            break;
        }
    }
    if(ptr == NULL)
    {
        fclose(fp);
        wifi_hal_error_print("%s:%d Key %s not found in factory file\n", __func__, __LINE__, key);
        return -1;
    }
    ptr += strlen(key);
    while(*ptr != '\0' && (*ptr == ' ' || *ptr == ':' ))
    {
        ++ptr;
    }
    strncpy(value, ptr, val_len);
    len = strlen(value)-1;
    if(value[len] == '\n')
    {
        value[len] = '\0';
    }
    fclose(fp);

    return 0;
}

struct qca_vendor_param_result { int32_t value; bool found; };

/*
 * qca_vendor_param_get_handler: parse vendor response.
 *
 * The driver returns the value at nested attribute ID=1 (per XML VendorRsp
 * ATTR_MAX="2", Attribute ID="1"). The previous code incorrectly looked for
 * QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA (=19) which is never set in the
 * response — that is why all GET commands returned empty/zero.
 */
static int qca_vendor_param_get_handler(struct nl_msg *msg, void *arg)
{
    struct qca_vendor_param_result *r = (struct qca_vendor_param_result *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *vd[4]; /* ATTR_MAX=2 per XML, use 4 for safety */
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA]) {
        wifi_hal_error_print("%s:%d UFR10: no NL80211_ATTR_VENDOR_DATA in response\n",
                             __func__, __LINE__);
        return NL_SKIP;
    }
    if (nla_parse_nested(vd, 3, tb[NL80211_ATTR_VENDOR_DATA], NULL) < 0) {
        wifi_hal_error_print("%s:%d UFR10: nla_parse_nested failed\n",
                             __func__, __LINE__);
        return NL_SKIP;
    }
    /* Driver returns value at attribute ID=1 (not GENERIC_DATA=19) */
    if (vd[1]) {
        r->value = nla_get_s32(vd[1]);
        r->found = true;
        wifi_hal_dbg_print("%s:%d UFR10 GET response: value=%d\n",
                           __func__, __LINE__, r->value);
    } else {
        wifi_hal_error_print("%s:%d UFR10 GET response: vd[1] not present\n",
                             __func__, __LINE__);
    }
    return NL_SKIP;
}

/*
 * qca_vendor_param_get: send a GET vendor command.
 *
 * outer_subcmd: QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION (75) for
 *               VAP-level (vdev) params, or
 *               QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION (506) for
 *               radio-level (wiphy) params.
 * param: the QCA_WLAN_VENDOR_VDEV_PARAM_* or QCA_WLAN_VENDOR_RADIO_PARAM_*
 *        value to query.
 */
static int qca_vendor_param_get(wifi_interface_info_t *iface, uint32_t outer_subcmd,
                        uint32_t param, int32_t *val, int radio_idx)
{
    struct nl_msg *msg;
    struct nlattr *p;
    struct qca_vendor_param_result r = {0, false};
    int ret;

    wifi_hal_dbg_print("%s:%d UFR10 GET: outer_subcmd=%u param=%u iface=%s radio_idx=%d\n",
                       __func__, __LINE__, outer_subcmd, param,
                       iface ? iface->name : "NULL", radio_idx);

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, iface, 0, OUI_QCA,
                                     outer_subcmd);
    if (!msg) {
        wifi_hal_error_print("%s:%d UFR10: nl80211_drv_vendor_cmd_msg failed\n",
                             __func__, __LINE__);
        return RETURN_ERR;
    }
    p = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!p) { nlmsg_free(msg); return RETURN_ERR; }
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, param);

    /* For wiphy (radio-level) commands (subcmd 505/506): add RADIO_INDEX.
     * The driver (ath12k_vendor_set/get_wiphy_params_extn) uses
     * QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX (=150) to select the radio.
     * Without it, radio_idx defaults to INVALID_RADIO_INDEX (0xFF=255)
     * and the driver returns -ENODATA ("Invalid radio index 255").
     */
    if (outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION ||
        outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION) {
        if (radio_idx >= 0) {
            uint8_t ridx = (uint8_t)radio_idx;
            nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX,
                    sizeof(uint8_t), &ridx);
            wifi_hal_dbg_print("%s:%d UFR10 GET: radio_idx=%d\n",
                               __func__, __LINE__, radio_idx);
        }
    }

    /* MLO: add link ID so the driver queries the correct per-link value.
     * Matches cfg80211tool.1 (ven_cmd_tool.c):
     *   if (link_id != MLO_INVALID_LINK_ID &&
     *       (subcmd == SET_WIFI_CONFIGURATION || subcmd == GET_WIFI_CONFIGURATION))
     *       nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID, sizeof(u8), &link_id)
     * Without this the driver returns the default link (2.4 GHz) value for all VAPs.
     */
    if (iface && iface->mld_name[0] != '\0' &&
        (outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION ||
         outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION)) {
        int link_id = wifi_hal_get_mld_link_id(iface);
        if (link_id >= 0) {
            uint8_t lid = (uint8_t)link_id;
            nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID,
                    sizeof(uint8_t), &lid);
            wifi_hal_dbg_print("%s:%d UFR10 GET: MLO link_id=%d iface=%s\n",
                               __func__, __LINE__, link_id, iface->name);
        }
    }

    nla_nest_end(msg, p);

    ret = nl80211_send_and_recv(msg, qca_vendor_param_get_handler, &r, NULL, NULL);
    wifi_hal_dbg_print("%s:%d UFR10 GET: send_and_recv ret=%d found=%d val=%d\n",
                       __func__, __LINE__, ret, (int)r.found, r.value);
    if (ret || !r.found) return RETURN_ERR;
    *val = r.value;
    return RETURN_OK;
}

/*
 * qca_vendor_param_set: send a SET vendor command.
 *
 * outer_subcmd: QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION (74) for
 *               VAP-level (vdev) params, or
 *               QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION (505) for
 *               radio-level (wiphy) params.
 */
static int qca_vendor_param_set(wifi_interface_info_t *iface, uint32_t outer_subcmd,
                        uint32_t param, int32_t val, int radio_idx)
{
    struct nl_msg *msg;
    struct nlattr *p;
    int ret;

    wifi_hal_dbg_print("%s:%d UFR10 SET: outer_subcmd=%u param=%u val=%d iface=%s radio_idx=%d\n",
                       __func__, __LINE__, outer_subcmd, param, val,
                       iface ? iface->name : "NULL", radio_idx);

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, iface, 0, OUI_QCA,
                                     outer_subcmd);
    if (!msg) {
        wifi_hal_error_print("%s:%d UFR10: nl80211_drv_vendor_cmd_msg failed\n",
                             __func__, __LINE__);
        return RETURN_ERR;
    }
    p = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!p) { nlmsg_free(msg); return RETURN_ERR; }
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
                QCA_NL80211_VENDOR_SUBCMD_WIFI_PARAMS);
    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, param);
    nla_put_s32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA, val);

    /* For wiphy (radio-level) commands (subcmd 505/506): add RADIO_INDEX.
     * The driver (ath12k_vendor_set_wiphy_params_extn) uses
     * QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX (=150) to select the radio.
     * Without it, radio_idx defaults to INVALID_RADIO_INDEX (0xFF=255)
     * and the driver returns -ENODATA ("Invalid radio index 255").
     */
    if (outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION ||
        outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION) {
        if (radio_idx >= 0) {
            uint8_t ridx = (uint8_t)radio_idx;
            nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX,
                    sizeof(uint8_t), &ridx);
            wifi_hal_dbg_print("%s:%d UFR10 SET: radio_idx=%d\n",
                               __func__, __LINE__, radio_idx);
        }
    }

    /* MLO: add link ID so the driver sets the correct per-link value.
     * Matches cfg80211tool.1 behavior for SET_WIFI_CONFIGURATION commands.
     */
    if (iface && iface->mld_name[0] != '\0' &&
        (outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION ||
         outer_subcmd == QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION)) {
        int link_id = wifi_hal_get_mld_link_id(iface);
        if (link_id >= 0) {
            uint8_t lid = (uint8_t)link_id;
            nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID,
                    sizeof(uint8_t), &lid);
            wifi_hal_dbg_print("%s:%d UFR10 SET: MLO link_id=%d iface=%s\n",
                               __func__, __LINE__, link_id, iface->name);
        }
    }

    nla_nest_end(msg, p);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    wifi_hal_dbg_print("%s:%d UFR10 SET: send_and_recv ret=%d\n",
                       __func__, __LINE__, ret);
    return (ret == 0) ? RETURN_OK : RETURN_ERR;
}

static wifi_interface_info_t *qca_vendor_radio_iface(wifi_radio_index_t idx)
{
    wifi_radio_info_t *r = get_radio_by_rdk_index((unsigned int)idx);
    return r ? get_primary_interface(r) : NULL;
}

/*
 * qca_vendor_get_hw_idx - Get the driver hardware radio index for a radio.
 *
 * The driver uses QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX to select the radio
 * via ah->radio[radio_id] (ath12k_get_radio_by_id).  This index is the
 * hardware radio index (hw_idx) as reported by the driver in the multi-hw
 * capabilities, NOT the RDK radio index (0=2.4GHz, 1=5GHz, 2=6GHz).
 *
 * On IPQ54xx the driver's radio array order differs from the RDK order:
 *   hw_idx=0 → 2.4GHz (freq_range=2402-2472 MHz)
 *   hw_idx=1 → 6GHz   (freq_range=5945-7125 MHz)
 *   hw_idx=2 → 5GHz   (freq_range=5170-5835 MHz)
 *
 * Resolution priority:
 *   1. current_hw_info->hw_idx  — set after hostapd_get_hw_features() runs
 *   2. multi_hw_info[] search   — available earlier (after wifi_drv_get_multi_hw_info)
 *   3. radioIndex fallback      — last resort (may be wrong for 5GHz/6GHz)
 */
static int qca_vendor_get_hw_idx(wifi_radio_index_t radioIndex)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *iface;
    struct hostapd_iface *hapd_iface;
    unsigned int i;
    int band_freq;

    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio)
        return (int)radioIndex;

    iface = get_primary_interface(radio);
    if (!iface)
        return (int)radioIndex;

    hapd_iface = iface->u.ap.hapd.iface;
    if (!hapd_iface)
        return (int)radioIndex;

    /* Priority 1: current_hw_info — most accurate, set after hw features query */
    if (hapd_iface->current_hw_info)
        return (int)hapd_iface->current_hw_info->hw_idx;

    /* Priority 2: search multi_hw_info[] by band frequency.
     * multi_hw_info is populated by wifi_drv_get_multi_hw_info() which runs
     * before platform_set_radio() is called, so this is available at startup. */
    if (hapd_iface->multi_hw_info && hapd_iface->num_multi_hws > 0) {
        /* Pick a representative frequency for the radio's operating band */
        switch (radio->oper_param.band) {
        case WIFI_FREQUENCY_2_4_BAND:
            band_freq = 2437;
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            band_freq = 5500;
            break;
        case WIFI_FREQUENCY_6_BAND:
            band_freq = 6000;
            break;
        default:
            band_freq = 0;
            break;
        }

        if (band_freq > 0) {
            for (i = 0; i < hapd_iface->num_multi_hws; i++) {
                struct hostapd_multi_hw_info *hw = &hapd_iface->multi_hw_info[i];
                if (band_freq >= hw->start_freq && band_freq <= hw->end_freq) {
                    wifi_hal_dbg_print("%s:%d: radio %d band_freq=%d matched"
                                       " hw_idx=%d (freq=%d-%d MHz)\n",
                                       __func__, __LINE__, (int)radioIndex,
                                       band_freq, hw->hw_idx,
                                       hw->start_freq, hw->end_freq);
                    return (int)hw->hw_idx;
                }
            }
        }
    }

    /* Priority 3: fallback to RDK radio index — may be wrong for 5GHz/6GHz */
    wifi_hal_dbg_print("%s:%d: current_hw_info not set for radio %d (%s), using radioIndex\n",
                       __func__, __LINE__, (int)radioIndex, iface->name);
    return (int)radioIndex;
}


/* Check if radio is present in the platform radio map. */
int check_radio_index(uint8_t radio_index)
{
    radio_interface_mapping_t platform_map_t[IPQ_UD_MAX_NUM_RADIOS];
    uint8_t i = 0;

    memset(platform_map_t, 0, sizeof(platform_map_t));
    get_radio_interface_info_map(platform_map_t);

    for (i = 0; i < IPQ_UD_MAX_NUM_RADIOS ; i++) {
	if (platform_map_t[i].interface_name[0] == '\0') {
		wifi_hal_error_print("%s: break at loop:%d\n", __func__, i);
		break;
	}
        if (platform_map_t[i].radio_index == radio_index) {

            return 0;
        }
    }

    wifi_hal_dbg_print("%s: radio not found\n", __FUNCTION__);
    return -1;
}

int is_interface_exists(const char *fname)
{
    FILE *file = fopen(fname, "r");
    if (file)
    {
      fclose(file);
      return 1;
    }
    return 0;
}

int platform_get_chanspec_list(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, const wifi_channels_list_t *channels, char *buff)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

int platform_set_acs_exclusion_list(wifi_radio_index_t index,char *buff)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

/* UD platform private VAP indices (from QCOM_ATH12K_PORT interface map):
*   private_ssid_2g -> vap_index  0  (wlan0)
*   private_ssid_5g -> vap_index  1  (wlan1)
*   private_ssid_6g -> vap_index 16  (wlan6)
*/
#define UD_PRIVATE_VAP_2G_INDEX   0
#define UD_PRIVATE_VAP_5G_INDEX   1
#define UD_PRIVATE_VAP_6G_INDEX  16

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

void getprivatevap2G(unsigned int *index)
{
    unsigned int idx = 0;
    wifi_interface_name_idex_map_t interface_map[(IPQ_UD_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
    if (index == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return;
    }

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {

        if (strncmp(interface_map[idx].vap_name, "private_ssid_2g", strlen("private_ssid_2g")) == 0) {
            *index = interface_map[idx].index;

        }
    }
}

void getprivatevap5G(unsigned int *index)
{
    unsigned int idx = 0;
    wifi_interface_name_idex_map_t interface_map[(IPQ_UD_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
    if (index == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return;
    }

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {

        if (strncmp(interface_map[idx].vap_name, "private_ssid_5g", strlen("private_ssid_5g")) == 0) {
            *index = interface_map[idx].index;
        }
    }
}

void getprivatevap6G(unsigned int *index)
{
    unsigned int idx = 0;
    wifi_interface_name_idex_map_t interface_map[(IPQ_UD_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
    if (index == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return;
    }

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {
        if (strncmp(interface_map[idx].vap_name, "private_ssid_6g", strlen("private_ssid_6g")) == 0) {
            *index = interface_map[idx].index;
        }
    }
}


int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    uint32_t primary_vap_index = 0;
    wifi_radio_info_t *radio = NULL;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (operationParam == NULL || check_radio_index(index) != 0 ) {
        wifi_hal_error_print("%s:%d returning error param:%p index:%d\n",__func__,__LINE__, operationParam, index);
        return -1;
    }
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, index);
    switch (operationParam->band) {
        case WIFI_FREQUENCY_2_4_BAND:
            getprivatevap2G(&primary_vap_index);
            break;
        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            getprivatevap5G(&primary_vap_index);
            break;
        case WIFI_FREQUENCY_6_BAND:
        case WIFI_FREQUENCY_60_BAND:
            getprivatevap6G(&primary_vap_index);
            break;
        default:
            wifi_hal_error_print("%s:%d: Unknown band:%d radio_index:%d\n", __func__, __LINE__, operationParam->band, index);
            break;
    }

    /* Apply TX power via nl80211 using the transmitPower percentage from operationParam */
    {
        wifi_radio_info_t *radio = get_radio_by_rdk_index(index);
        wifi_interface_info_t *interface = NULL;

        if (radio != NULL) {
            interface = get_primary_interface(radio);
            if (interface != NULL) {
                if (platform_set_txpower(interface, operationParam->transmitPower) != RETURN_OK) {
                    wifi_hal_error_print(
                        "%s:%d: Failed to set TX power for radio index:%d (transmitPower=%u%%)\n",
                        __func__, __LINE__, index, operationParam->transmitPower);
                    /* Non-fatal: log and continue */
                }
            } else {
                wifi_hal_error_print("%s:%d: No primary interface for radio index:%d\n",
                    __func__, __LINE__, index);
            }
        } else {
            wifi_hal_error_print("%s:%d: Could not find radio index:%d\n",
                __func__, __LINE__, index);
        }
    }

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

#ifdef CONFIG_ATF_OFFLOAD
/**
 * platform_atf_nl80211_vendor_msg - Helper to build a QCA ATF vendor NL80211 message.
 *
 * Creates a NL80211_CMD_VENDOR message for QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS
 * using the rdk-wifi-hal nl80211 socket (g_wifi_hal.nl80211_id + interface->index).
 * The caller must add the vendor data attributes and call nl80211_send_and_recv().
 *
 * Returns the allocated nl_msg on success, NULL on failure.
 * The caller is responsible for calling nlmsg_free() on failure.
 */
static struct nl_msg *platform_atf_nl80211_vendor_msg(wifi_interface_info_t *interface,
                                                       u8 radio_index,
                                                       struct nlattr **data_out)
{
    struct nl_msg *msg;
    struct nlattr *data;

    msg = nlmsg_alloc();
    if (!msg)
        return NULL;

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                     NL80211_CMD_VENDOR, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)interface->index) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                    QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS)) {
        nlmsg_free(msg);
        return NULL;
    }

    data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!data ||
        nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_INDEX, radio_index)) {
        nlmsg_free(msg);
        return NULL;
    }

    *data_out = data;
    return msg;
}

/**
 * platform_atf_nl80211_enable - Enable ATF offload via NL80211 vendor command.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS with
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_ENABLED = 1 using the rdk-wifi-hal
 * nl80211 socket (not hapd->drv_priv which uses struct i802_bss *).
 */
static int platform_atf_nl80211_enable(wifi_interface_info_t *interface,
                                        u8 radio_index)
{
    struct nl_msg  *msg;
    struct nlattr  *data;
    int             ret;

    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_ENABLED, 1)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF enable failed ret=%d\n",
                             __func__, __LINE__, ret);
    else
        wifi_hal_info_print("%s:%d: ATF enabled radio_index=%u\n",
                            __func__, __LINE__, radio_index);
    return ret;
}

/* ── ATF VAP sorting helper ─────────────────────────────────────────────── */

/* Maximum number of ATF-configured VAPs per radio for sorting */
#define ATF_MAX_VAPS_PER_RADIO  32

/*
 * atf_vap_entry - Compact descriptor for one ATF-configured AP VAP.
 * Used by atf_collect_sorted_vaps() to build a deterministically-ordered
 * list that is shared between platform_atf_nl80211_ssid_groups(),
 * platform_atf_nl80211_peers(), and platform_atf_get_stats().
 */
struct atf_vap_entry {
    UINT                   vap_index;
    UINT                   atm_airtime_percent;
    UINT                   atm_num_stas;
    wifi_interface_info_t *iface;   /* back-pointer for STA list access */
};

/*
 * atf_collect_sorted_vaps - Collect all ATF-configured AP VAPs from
 * radio->interface_map and sort them by vap_index (ascending).
 *
 * This ensures that platform_atf_nl80211_ssid_groups() and
 * platform_atf_get_stats() assign the same group index to the same VAP
 * regardless of hash_map iteration order.
 *
 * Returns the number of ATF-configured VAPs found (0 if none).
 */
static unsigned int atf_collect_sorted_vaps(wifi_radio_info_t *radio,
                                             struct atf_vap_entry *vaps,
                                             unsigned int max_vaps)
{
    wifi_interface_info_t *iface_iter;
    unsigned int count = 0;
    unsigned int i, j;

    hash_map_foreach(radio->interface_map, iface_iter) {
        if (iface_iter->vap_info.vap_mode != wifi_vap_mode_ap)
            continue;
        if (iface_iter->vap_info.u.bss_info.atm_airtime_percent == 0)
            continue;
        if (count >= max_vaps)
            break;
        vaps[count].vap_index           = iface_iter->vap_info.vap_index;
        vaps[count].atm_airtime_percent = iface_iter->vap_info.u.bss_info.atm_airtime_percent;
        vaps[count].atm_num_stas        = iface_iter->vap_info.u.bss_info.atm_num_stas;
        vaps[count].iface               = iface_iter;
        count++;
    }

    /* Insertion sort by vap_index — N is small (< 16 per radio) */
    for (i = 1; i < count; i++) {
        struct atf_vap_entry key = vaps[i];
        j = i;
        while (j > 0 && vaps[j - 1].vap_index > key.vap_index) {
            vaps[j] = vaps[j - 1];
            j--;
        }
        vaps[j] = key;
    }

    return count;
}

/**
 * platform_atf_nl80211_ssid_groups - Push SSID group config for all ATF-configured VAPs.
 *
 * Sends a single QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS message with
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_CONFIG containing one group
 * per configured VAP.  Group indices are assigned in ascending vap_index order
 * using atf_collect_sorted_vaps() so that every call for the same radio
 * produces the same group-index-to-VAP mapping regardless of which VAPs were
 * in the triggering wifi_hal_createVAP() map.
 *
 * Bug fix (Bug 1): previously iterated map->vap_array[] (partial map) which
 * caused stale group accumulation in the firmware when VAPs were pushed one
 * at a time by the webconfig flow.  Now iterates radio->interface_map to
 * always include ALL ATF-configured VAPs on the radio.
 */
static int platform_atf_nl80211_ssid_groups(wifi_interface_info_t *interface,
                                             u8 radio_index,
                                             u8 *group_index_map)
{
    struct nl_msg         *msg;
    struct nlattr         *data, *groups, *grp;
    u8                     grp_idx = 0;
    int                    ret;
    wifi_radio_info_t     *radio;
    struct atf_vap_entry   sorted_vaps[ATF_MAX_VAPS_PER_RADIO];
    unsigned int           num_vaps, i;

    radio = get_radio_by_rdk_index(radio_index);
    if (!radio)
        return -ENODEV;

    num_vaps = atf_collect_sorted_vaps(radio, sorted_vaps, ATF_MAX_VAPS_PER_RADIO);
    if (num_vaps == 0)
        return 0;

    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    groups = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_CONFIG);
    if (!groups) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    for (i = 0; i < num_vaps; i++) {
        u16 scaled = ATF_AIRTIME_SCALE(sorted_vaps[i].atm_airtime_percent);

        grp = nla_nest_start(msg, grp_idx);
        if (!grp) {
            nlmsg_free(msg);
            return -EINVAL;
        }

        if (nla_put_u8(msg,  QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_INDEX,
                       grp_idx) ||
            nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_AIRTIME_CONFIGURED,
                        scaled) ||
            nla_put_u8(msg,  QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_POLICY,
                       0 /* ATF_FAIR_SCHEDULING */) ||
            nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_UNCONFIGURED_PEERS,
                        0) ||
            nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_CONFIGURED_PEERS,
                        (u16)sorted_vaps[i].atm_num_stas) ||
            nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_SSID_GROUP_UNCONFIGURED_PEERS_AIRTIME,
                        0)) {
            nlmsg_free(msg);
            return -EINVAL;
        }
        nla_nest_end(msg, grp);

        /* Record which group index this VAP got */
        if (group_index_map)
            group_index_map[sorted_vaps[i].vap_index] = grp_idx;

        wifi_hal_info_print("%s:%d: ATF SSID group[%u] ssid='%s' airtime=%u%%"
                            " (scaled=%u)\n",
                            __func__, __LINE__, grp_idx,
                            sorted_vaps[i].iface->vap_info.u.bss_info.ssid,
                            sorted_vaps[i].atm_airtime_percent, scaled);
        grp_idx++;
    }

    nla_nest_end(msg, groups);
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF SSID group config failed ret=%d\n",
                             __func__, __LINE__, ret);
    return ret;
}

/**
 * platform_atf_nl80211_peers - Push per-STA explicit airtime config.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS with
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_CONFIG for all STAs across all VAPs.
 * group_index_map[vap_index] gives the SSID group index for each VAP.
 *
 * Bug fix (Bug 1): previously iterated map->vap_array[] (partial map); now
 * uses atf_collect_sorted_vaps() to include ALL ATF-configured VAPs on the
 * radio so that explicit STA entries are not missed when only one VAP was
 * in the triggering wifi_hal_createVAP() map.
 */
static int platform_atf_nl80211_peers(wifi_interface_info_t *interface,
                                       u8 radio_index,
                                       const u8 *group_index_map)
{
    struct nl_msg         *msg;
    struct nlattr         *data, *peers_cfg, *peers, *peer;
    unsigned int           s;
    unsigned int           peer_idx = 0;
    bool                   has_peers = false;
    int                    ret;
    wifi_radio_info_t     *radio;
    struct atf_vap_entry   sorted_vaps[ATF_MAX_VAPS_PER_RADIO];
    unsigned int           num_vaps, i;

    radio = get_radio_by_rdk_index(radio_index);
    if (!radio)
        return 0;

    num_vaps = atf_collect_sorted_vaps(radio, sorted_vaps, ATF_MAX_VAPS_PER_RADIO);

    /* Check if any STA entries exist */
    for (i = 0; i < num_vaps; i++) {
        if (sorted_vaps[i].atm_num_stas > 0) {
            has_peers = true;
            break;
        }
    }
    if (!has_peers)
        return 0;

    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    peers_cfg = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_CONFIG);
    if (!peers_cfg ||
        nla_put_flag(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_CONFIG_FULL_UPDATE)) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    peers = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_CONFIG_PAYLOAD);
    if (!peers) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    for (i = 0; i < num_vaps; i++) {
        wifi_vap_info_t *vap = &sorted_vaps[i].iface->vap_info;
        u8 grp_idx = group_index_map ? group_index_map[sorted_vaps[i].vap_index] : 0;

        for (s = 0; s < vap->u.bss_info.atm_num_stas &&
                    s < WIFI_ATM_MAX_STAS_PER_BSS; s++) {
            const unsigned char *m = vap->u.bss_info.atm_stas[s].mac_addr;
            UINT sta_airtime = vap->u.bss_info.atm_stas[s].airtime_percent;
            u16 scaled;

            if (sta_airtime == 0)
                continue;

            scaled = ATF_AIRTIME_SCALE(sta_airtime);

            peer = nla_nest_start(msg, peer_idx);
            if (!peer ||
                nla_put(msg,   QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_MAC,
                        ETH_ALEN, m) ||
                nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_AIRTIME,
                            scaled) ||
                nla_put_u8(msg,  QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_GROUP_INDEX,
                           grp_idx) ||
                nla_put_flag(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_CONFIGURED)) {
                nlmsg_free(msg);
                return -EINVAL;
            }
            nla_nest_end(msg, peer);

            wifi_hal_info_print("%s:%d: ATF peer[%u]"
                                " %02x:%02x:%02x:%02x:%02x:%02x"
                                " airtime=%u%% group=%u\n",
                                __func__, __LINE__, peer_idx,
                                m[0], m[1], m[2], m[3], m[4], m[5],
                                sta_airtime, grp_idx);
            peer_idx++;
        }
    }

    nla_nest_end(msg, peers);
    nla_nest_end(msg, peers_cfg);
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF peer config failed ret=%d\n",
                             __func__, __LINE__, ret);
    return ret;
}

/**
 * platform_atf_nl80211_disable - Disable ATF offload in the firmware.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS with
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_ENABLED = 0 and
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_ENABLED = 0.
 *
 * Called when all VAPs on a radio have atm_airtime_percent = 0 (ATF
 * has been turned off via dmcli).  Without this the firmware would
 * continue enforcing the previously-configured airtime limits even
 * after the operator removes the ATF configuration.
 */
static int platform_atf_nl80211_disable(wifi_interface_info_t *interface,
                                         u8 radio_index)
{
    struct nl_msg  *msg;
    struct nlattr  *data;
    int             ret;

    /* Step 1: disable stats collection first */
    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_ENABLED, 0)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF stats disable failed ret=%d (non-fatal)\n",
                             __func__, __LINE__, ret);

    /* Step 2: disable ATF enforcement */
    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_ENABLED, 0)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF disable failed ret=%d\n",
                             __func__, __LINE__, ret);
    else
        wifi_hal_info_print("%s:%d: ATF disabled for radio_index=%u\n",
                            __func__, __LINE__, radio_index);
    return ret;
}

/**
 * platform_atf_nl80211_stats_enable - Enable ATF stats collection.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS with
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_ENABLED = 1 and
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_TIMEOUT = timeout_sec.
 *
 * Must be called after platform_atf_nl80211_enable() so that the firmware
 * has ATF active before stats collection is requested.
 *
 * @interface:    primary AP interface for this radio
 * @radio_index:  QCA radio index (same as RDK radio index)
 * @timeout_sec:  stats polling interval in seconds (10–50 recommended)
 * Returns 0 on success, negative errno on failure (non-fatal).
 */
static int platform_atf_nl80211_stats_enable(wifi_interface_info_t *interface,
                                              u8 radio_index,
                                              u8 timeout_sec)
{
    struct nl_msg  *msg;
    struct nlattr  *data;
    int             ret;

    /* Step A: enable stats */
    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_ENABLED, 1)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d: ATF stats enable failed ret=%d\n",
                             __func__, __LINE__, ret);
        return ret;
    }

    /* Step B: set stats timeout */
    msg = platform_atf_nl80211_vendor_msg(interface, radio_index, &data);
    if (!msg)
        return -ENOMEM;

    if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_TIMEOUT, timeout_sec)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF stats timeout set failed ret=%d\n",
                             __func__, __LINE__, ret);
    else
        wifi_hal_info_print("%s:%d: ATF stats enabled radio_index=%u timeout=%us\n",
                            __func__, __LINE__, radio_index, timeout_sec);
    return ret;
}

/**
 * platform_set_atf_config - Configure ATF offload per-SSID/STA airtime.
 *
 * Called from platform_create_vap() after all VAPs have been created.
 * Implements ATF configuration directly using NL80211 vendor commands via
 * rdk-wifi-hal's nl80211_send_and_recv() — bypasses hapd->drv_priv which
 * uses struct i802_bss * (hostapd nl80211 priv) incompatible with
 * rdk-wifi-hal's wifi_interface_info_t * priv.
 *
 * Steps:
 *   1. Push SSID group config (one group per configured VAP)
 *   2. Push per-STA explicit airtime config (if any)
 *   3. Enable ATF enforcement
 */
static void platform_set_atf_config(wifi_radio_index_t index,
                                    wifi_vap_info_map_t *map)
{
    wifi_interface_info_t  *interface = NULL;
    u8                      radio_index;
    /* group_index_map[vap_index] = SSID group index assigned to that VAP */
    u8                      group_index_map[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    memset(group_index_map, 0, sizeof(group_index_map));

    /* Check if ATM master enable flag is false on the radio.
     * When ATM.Enable=false is set via dmcli, atm_enabled is stored in
     * the radio oper_param.  Even if VAPs still have atm_airtime_percent > 0
     * (the operator may have disabled ATM without clearing the APGroup config),
     * we must send ENABLED=0 to the firmware. */
    {
        wifi_radio_info_t *radio = get_radio_by_rdk_index(index);
        if (radio != NULL && !radio->oper_param.atm_enabled) {
            /* ATM master switch is off — find any AP interface and disable */
            wifi_interface_info_t *any_iface = NULL;
            wifi_interface_info_t *iface_iter;
            hash_map_foreach(radio->interface_map, iface_iter) {
                if (iface_iter->vap_info.vap_mode == wifi_vap_mode_ap) {
                    any_iface = iface_iter;
                    break;
                }
            }
            if (any_iface != NULL) {
                wifi_hal_info_print("%s:%d: ATM master enable=false on radio %d"
                                    " — sending ENABLED=0 to firmware\n",
                                    __func__, __LINE__, index);
                platform_atf_nl80211_disable(any_iface, (u8)index);
            }
            return;
        }
    }

    /* Find the first AP interface with ATF configured (from radio->interface_map).
     * Bug fix: previously iterated map->vap_array[] (partial map) which missed
     * VAPs not in the current push.  Now uses radio->interface_map to find any
     * ATF-configured AP interface on the radio. */
    {
        wifi_radio_info_t *radio = get_radio_by_rdk_index(index);
        if (radio != NULL) {
            wifi_interface_info_t *iface_iter;
            hash_map_foreach(radio->interface_map, iface_iter) {
                if (iface_iter->vap_info.vap_mode == wifi_vap_mode_ap &&
                    iface_iter->vap_info.u.bss_info.atm_airtime_percent > 0) {
                    interface = iface_iter;
                    break;
                }
            }
        }
    }

    if (interface == NULL) {
        /* No ATF-configured VAPs on this radio — ATF has been disabled.
         * We must send ENABLED=0 to the firmware so it stops enforcing
         * the previously-configured airtime limits.  Find any AP interface
         * on this radio to use as the NL80211 socket handle. */
        wifi_radio_info_t *radio = get_radio_by_rdk_index(index);
        wifi_interface_info_t *any_iface = NULL;

        if (radio != NULL) {
            wifi_interface_info_t *iface_iter;
            hash_map_foreach(radio->interface_map, iface_iter) {
                if (iface_iter->vap_info.vap_mode == wifi_vap_mode_ap) {
                    any_iface = iface_iter;
                    break;
                }
            }
        }

        if (any_iface != NULL) {
            wifi_hal_info_print("%s:%d: no ATF-configured VAPs on radio %d"
                                " — sending ENABLED=0 to firmware\n",
                                __func__, __LINE__, index);
            platform_atf_nl80211_disable(any_iface, (u8)index);
        } else {
            wifi_hal_dbg_print("%s:%d: no ATF-configured VAPs and no AP"
                               " interface found on radio %d, skipping disable\n",
                               __func__, __LINE__, index);
        }
        return;
    }

    radio_index = (u8)index;

    /* Step 1: Push SSID group config
     * Matches hostapd nl80211_atf_offload_send_group_config().
     * GROUP_POLICY is hardcoded to 0 (ATF_FAIR_SCHEDULING) because:
     *   - iconf->atf_strict_sched = false (set in update_hostap_config_params)
     *   - No TR-181 parameter for per-group scheduling policy
     * hostapd also sends STRICT_SCHEDULING_ENABLED and SSID_SCHED_POLICY
     * but only when the respective flags are non-zero (strict mode).
     * Since we always use fair scheduling, those commands are not needed.
     */
    if (platform_atf_nl80211_ssid_groups(interface, radio_index,
                                          group_index_map) != 0) {
        wifi_hal_error_print("%s:%d: ATF SSID group config failed\n",
                             __func__, __LINE__);
        return;
    }

    /* Step 2: Push WMM AC config (required by firmware on every config push).
     * Matches hostapd nl80211_atf_offload_send_wmm_ac_config() which sends
     * a binary TLV blob with all-zero WMM AC airtime values (Phase 2 placeholder).
     * The firmware expects this message even though all values are zero.
     * Format: TAG_ARRAY_STRUCT header + one atf_group_wmm_ac_info per group.
     */
    {
        unsigned int num_groups = 0;
        /* Count ATF-configured VAPs (= number of groups) using radio->interface_map
         * so the WMM blob size matches the SSID_GROUP_CONFIG sent above. */
        {
            wifi_radio_info_t *radio = get_radio_by_rdk_index(index);
            if (radio != NULL) {
                struct atf_vap_entry sorted_vaps[ATF_MAX_VAPS_PER_RADIO];
                num_groups = atf_collect_sorted_vaps(radio, sorted_vaps,
                                                     ATF_MAX_VAPS_PER_RADIO);
            }
        }

        if (num_groups > 0) {
            /* Build binary TLV blob:
             *   [0..3]   = PREP(TAG_ARRAY_STRUCT, num_groups * ATF_WMM_GROUP_INFO_SIZE)
             *   [4..27]  = group 0: PREP(TAG_GROUP_INFO, 20), group_id=0, be=0, bk=0, vi=0, vo=0
             *   [28..51] = group 1: ...
             */
            size_t total_len = ATF_WMM_HDR_SIZE +
                               (num_groups * ATF_WMM_GROUP_INFO_SIZE);
            u8 *buf = calloc(1, total_len);
            if (buf) {
                struct nl_msg  *wmm_msg;
                struct nlattr  *wmm_data;
                int             wmm_ret;
                u32 *hdr = (u32 *)buf;
                u32 *grp = (u32 *)(buf + ATF_WMM_HDR_SIZE);
                unsigned int g;

                /* Array header */
                *hdr = ATF_WMM_PREP(ATF_WMM_TAG_ARRAY_STRUCT,
                                    num_groups * ATF_WMM_GROUP_INFO_SIZE);

                /* Per-group entries (all-zero airtime = Phase 2 placeholder) */
                for (g = 0; g < num_groups; g++) {
                    grp[0] = ATF_WMM_PREP(ATF_WMM_TAG_GROUP_INFO,
                                          ATF_WMM_GROUP_INFO_SIZE - ATF_WMM_HDR_SIZE);
                    grp[1] = g;   /* atf_group_id */
                    grp[2] = 0;   /* atf_units_be */
                    grp[3] = 0;   /* atf_units_bk */
                    grp[4] = 0;   /* atf_units_vi */
                    grp[5] = 0;   /* atf_units_vo */
                    grp += (ATF_WMM_GROUP_INFO_SIZE / sizeof(u32));
                }

                wmm_msg = platform_atf_nl80211_vendor_msg(interface, radio_index,
                                                           &wmm_data);
                if (wmm_msg) {
                    if (nla_put(wmm_msg,
                                QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_WMM_AC_CONFIG,
                                (int)total_len, buf) == 0) {
                        nla_nest_end(wmm_msg, wmm_data);
                        wmm_ret = nl80211_send_and_recv(wmm_msg, NULL, NULL,
                                                        NULL, NULL);
                        if (wmm_ret)
                            wifi_hal_error_print(
                                "%s:%d: ATF WMM AC config failed ret=%d"
                                " (non-fatal)\n",
                                __func__, __LINE__, wmm_ret);
                        else
                            wifi_hal_info_print(
                                "%s:%d: ATF WMM AC config sent"
                                " (%zu bytes, %u groups)\n",
                                __func__, __LINE__, total_len, num_groups);
                    } else {
                        nlmsg_free(wmm_msg);
                    }
                }
                free(buf);
            }
        }
    }

    /* Step 3: Push per-STA config (optional, no-op if no STAs configured) */
    platform_atf_nl80211_peers(interface, radio_index, group_index_map);

    /* Step 4: Enable ATF */
    if (platform_atf_nl80211_enable(interface, radio_index) != 0) {
        wifi_hal_error_print("%s:%d: ATF enable failed\n",
                             __func__, __LINE__);
        return;
    }

    /* Step 5: Enable ATF stats collection so that
     * Device.WiFi.X_RDKCENTRAL-COM_ATM.Stats returns real data.
     * Use a 30-second polling interval (valid range: 10–50 s).
     * Non-fatal: ATF enforcement still works if this fails.
     */
    if (platform_atf_nl80211_stats_enable(interface, radio_index, 30) != 0) {
        wifi_hal_error_print("%s:%d: ATF stats enable failed (non-fatal)\n",
                             __func__, __LINE__);
    }

    wifi_hal_info_print("%s:%d: ATF config pushed for radio %d\n",
                        __func__, __LINE__, index);
}

/* ── ATF Stats ─────────────────────────────────────────────────────────── */

struct atf_stats_ctx {
    char   *buf;
    size_t  buf_len;
    size_t  written;
    /* group_to_vap[group_index] = RDK VAP index for that SSID group.
     * Populated by platform_atf_get_stats() before the NL80211 dump. */
    u8      group_to_vap[32];
    /* group_airtime[group_index] = configured airtime % (0-100) for that group.
     * Populated by platform_atf_get_stats() from atm_airtime_percent. */
    u8      group_airtime[32];
    u8      num_groups;
    /* vap_to_group[vap_index] = group index for that VAP.
     * Reverse map of group_to_vap[].  Used to look up which group a peer
     * belongs to when displaying per-peer stats. */
    u8      vap_to_group[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    /* radio pointer — used in the peer filter to look up associated STAs
     * and explicit ATF STA configs, matching hostapd's atf_stats_cb logic:
     *   atf_find_peer_config_by_mac() → explicit ATF peer
     *   atf_implicit_peer_cfg()       → associated STA (implicit peer)
     * Only MACs that are known peers (explicit or implicit) are printed. */
    wifi_radio_info_t *radio;
};

/**
 * atf_stats_nl80211_cb - NL80211 response callback for ATF stats dump.
 *
 * Parses QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS (radio-level) and
 * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS (per-STA) attributes and
 * formats them into a tabulated string matching the kernel log output:
 *
 *   ***** ATF STATS For SSID Groups *****
 *   GroupID  Configured  Actual(Relative)  Borrowed  Unused  Duration(us) ...
 *   ...
 *   ***** ATF STATS For PEERs *****
 *   PeerMAC  GroupId  Configured  Actual(Relative)  Borrowed  Unused ...
 *   ...
 *   Total radio duration(us): X
 *   Total Airtime(us)     X
 *   Total UL Airtime(us)  X
 */
static int atf_stats_nl80211_cb(struct nl_msg *msg, void *arg)
{
    struct atf_stats_ctx *ctx = (struct atf_stats_ctx *)arg;
    struct nlattr        *tb[NL80211_ATTR_MAX + 1];
    /* Top-level vendor data attributes (QCA_WLAN_VENDOR_ATTR_*) */
    struct nlattr        *vdata[QCA_WLAN_VENDOR_ATTR_MAX + 1];
    /* Radio/peer stats nested inside QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS */
    struct nlattr        *radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_MAX + 1];
    struct genlmsghdr    *gnlh = nlmsg_data(nlmsg_hdr(msg));

    /* Radio-level stats from the response */
    u32 tx_be = 0, tx_bk = 0, tx_vi = 0, tx_vo = 0;
    u32 rx_be = 0, rx_bk = 0, rx_vi = 0, rx_vo = 0;
    u32 total_airtime = 0, total_ul_airtime = 0, total_duration = 0;

#define W(fmt, ...) \
    do { \
        if (ctx->written < ctx->buf_len) \
            ctx->written += snprintf(ctx->buf + ctx->written, \
                                     ctx->buf_len - ctx->written, \
                                     fmt, ##__VA_ARGS__); \
    } while (0)

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA])
        return NL_SKIP;

    /*
     * Step 1: Parse the top-level vendor data.
     * The firmware response has TWO levels of nesting (matching hostapd
     * atf_stats_cb):
     *   NL80211_ATTR_VENDOR_DATA
     *     └─ QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS  (nested)
     *           ├─ QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BE_AIRTIME
     *           ├─ QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BK_AIRTIME
     *           ├─ ...
     *           └─ QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS  (nested array)
     *                 └─ per-peer: MAC + TX/RX per-AC airtime
     *
     * platform_ud.c previously parsed VENDOR_DATA directly with
     * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_MAX, missing the outer
     * QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS nesting level and getting
     * all-zero stats.
     */
    nla_parse_nested(vdata, QCA_WLAN_VENDOR_ATTR_MAX,
                     tb[NL80211_ATTR_VENDOR_DATA], NULL);

    /* Step 2: Descend into QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS */
    if (!vdata[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS]) {
        wifi_hal_error_print("%s:%d: ATF stats nested attr not present in NL response\n",
                             __func__, __LINE__);
        return NL_SKIP;
    }

    nla_parse_nested(radio_stats, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS_MAX,
                     vdata[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_STATS], NULL);

    /* Step 3: Extract radio-level TX/RX airtime per AC from radio_stats[] */
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BE_AIRTIME])
        tx_be = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BE_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BK_AIRTIME])
        tx_bk = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_BK_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_VI_AIRTIME])
        tx_vi = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_VI_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_VO_AIRTIME])
        tx_vo = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_TX_VO_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_BE_AIRTIME])
        rx_be = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_BE_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_BK_AIRTIME])
        rx_bk = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_BK_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_VI_AIRTIME])
        rx_vi = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_VI_AIRTIME]);
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_VO_AIRTIME])
        rx_vo = nla_get_u32(radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_RX_VO_AIRTIME]);

    total_airtime    = tx_be + tx_bk + tx_vi + tx_vo;
    total_ul_airtime = rx_be + rx_bk + rx_vi + rx_vo;
    total_duration   = total_airtime + total_ul_airtime;

    /* ── Per-group airtime accumulators ──
     * The firmware does not return per-group airtime directly.  We calculate
     * it by summing the per-peer TX/RX airtime for all peers in each group.
     * This requires a single pass over the peer stats before displaying the
     * group stats table.
     *
     * Per-peer display data is stored in a fixed-size array so we can display
     * it after the group stats table without a second NL parse pass.
     */
#define ATF_MAX_PEERS_DISPLAY 64
    struct {
        u8  mac[ETH_ALEN];
        u8  group;
        u32 tx_total;
        u32 rx_total;
        u32 actual_rel;
    } peer_disp[ATF_MAX_PEERS_DISPLAY];
    unsigned int num_peer_disp = 0;

    u32 group_tx[32];
    u32 group_rx[32];
    memset(group_tx, 0, sizeof(group_tx));
    memset(group_rx, 0, sizeof(group_rx));

    /* Single pass: parse peer stats, accumulate per-group airtime, store for display */
    if (radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS]) {
        struct nlattr *peer;
        int rem;

        nla_for_each_nested(peer, radio_stats[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS], rem) {
            struct nlattr *ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS_MAX + 1];
            u32 p_tx_be = 0, p_tx_bk = 0, p_tx_vi = 0, p_tx_vo = 0;
            u32 p_rx_be = 0, p_rx_bk = 0, p_rx_vi = 0, p_rx_vo = 0;
            u32 p_tx_total, p_rx_total, p_actual_rel;
            u8  peer_group = 0;
            bool is_known_peer = false;
            wifi_interface_info_t *iface_iter2;

            nla_parse(ptb, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS_MAX,
                      nla_data(peer), nla_len(peer), NULL);

            if (!ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS_MAC])
                continue;

            const u8 *m = nla_data(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_STATS_MAC]);

            /* Filter known peers and determine group in a single loop */
            if (ctx->radio != NULL) {
                hash_map_foreach(ctx->radio->interface_map, iface_iter2) {
                    if (iface_iter2->vap_info.vap_mode != wifi_vap_mode_ap)
                        continue;

                    /* Check 1: explicit ATF peer */
                    {
                        unsigned int s;
                        for (s = 0; s < iface_iter2->vap_info.u.bss_info.atm_num_stas &&
                                    s < WIFI_ATM_MAX_STAS_PER_BSS; s++) {
                            if (memcmp(m,
                                       iface_iter2->vap_info.u.bss_info.atm_stas[s].mac_addr,
                                       ETH_ALEN) == 0) {
                                is_known_peer = true;
                                break;
                            }
                        }
                    }

                    /* Check 2: implicit peer (associated STA) */
                    if (!is_known_peer) {
                        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                        if (ap_get_sta(&iface_iter2->u.ap.hapd, m) != NULL)
                            is_known_peer = true;
                        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
                    }

                    if (is_known_peer) {
                        /* Determine group from vap_to_group[] */
                        UINT vi = iface_iter2->vap_info.vap_index;
                        if (vi < (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) &&
                            ctx->vap_to_group[vi] != 0xff)
                            peer_group = ctx->vap_to_group[vi];
                        break;
                    }
                }
            }

            if (!is_known_peer) {
                wifi_hal_dbg_print("%s:%d: ATF stats: peer %02x:%02x:%02x:%02x:%02x:%02x"
                                   " filtered (not in sta_list)\n",
                                   __func__, __LINE__,
                                   m[0], m[1], m[2], m[3], m[4], m[5]);
                continue;
            }

            wifi_hal_info_print("%s:%d: ATF stats: peer %02x:%02x:%02x:%02x:%02x:%02x"
                                " found in group %u\n",
                                __func__, __LINE__,
                                m[0], m[1], m[2], m[3], m[4], m[5], peer_group);

            /* Parse peer TX/RX airtime */
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_BE_AIRTIME])
                p_tx_be = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_BE_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_BK_AIRTIME])
                p_tx_bk = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_BK_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_VI_AIRTIME])
                p_tx_vi = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_VI_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_VO_AIRTIME])
                p_tx_vo = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_TX_VO_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_BE_AIRTIME])
                p_rx_be = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_BE_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_BK_AIRTIME])
                p_rx_bk = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_BK_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_VI_AIRTIME])
                p_rx_vi = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_VI_AIRTIME]);
            if (ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_VO_AIRTIME])
                p_rx_vo = nla_get_u32(ptb[QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_PEER_RX_VO_AIRTIME]);

            p_tx_total = p_tx_be + p_tx_bk + p_tx_vi + p_tx_vo;
            p_rx_total = p_rx_be + p_rx_bk + p_rx_vi + p_rx_vo;
            p_actual_rel = (total_airtime > 0) ?
                           (u32)((u64)p_tx_total * 100 / total_airtime) : 0;

            /* Accumulate per-group airtime */
            if (peer_group < 32) {
                group_tx[peer_group] += p_tx_total;
                group_rx[peer_group] += p_rx_total;
            }

            /* Store for display */
            if (num_peer_disp < ATF_MAX_PEERS_DISPLAY) {
                memcpy(peer_disp[num_peer_disp].mac, m, ETH_ALEN);
                peer_disp[num_peer_disp].group      = peer_group;
                peer_disp[num_peer_disp].tx_total   = p_tx_total;
                peer_disp[num_peer_disp].rx_total   = p_rx_total;
                peer_disp[num_peer_disp].actual_rel = p_actual_rel;
                num_peer_disp++;
            }
        }
    }

    /* ── SSID Group Stats Table ──
     * Matches hostapd's atf_offload_update_peer_airtime() + atf_offload_print_stats():
     *   group->actual_airtime = sum of (peer_tx * 100 / radio_tx) for all peers in group
     *   group->actual_duration = sum of peer TX airtime (us)
     *
     * Key: denominator is radio TX airtime only (not TX+RX), matching hostapd.
     * Borrowed = actual > configured ? actual - configured : 0
     * Unused   = actual < configured ? configured - actual : 0
     */
    W("***** ATF STATS For SSID Groups *****\n");
    W("%-9s %-10s %-12s %-18s %-10s %-8s %-14s %-10s %-8s %s\n",
      "GroupID", "VapIndex", "Configured", "Actual(Relative)", "Borrowed",
      "Unused", "Duration(us)", "ActualUL", "UL(us)", "Actual");

    if (ctx->num_groups > 0) {
        u8 grp;
        for (grp = 0; grp < ctx->num_groups; grp++) {
            u32 grp_tx       = group_tx[grp];
            u32 grp_rx       = group_rx[grp];
            u32 grp_duration = grp_tx + grp_rx;
            /* Actual(Relative) = group TX as % of total radio TX airtime.
             * Matches hostapd: peer_actual = (peer_tx * 100) / radio_tx_airtime
             *                  group_actual = sum(peer_actual) = (group_tx * 100) / radio_tx */
            u32 grp_actual_rel = (total_airtime > 0) ?
                                 (u32)((u64)grp_tx * 100 / total_airtime) : 0;
            u8  cfg_pct = ctx->group_airtime[grp];
            u32 borrowed = (grp_actual_rel > cfg_pct) ? (grp_actual_rel - cfg_pct) : 0;
            u32 unused   = (grp_actual_rel < cfg_pct) ? (cfg_pct - grp_actual_rel) : 0;
            W("  %-7u %-10u %-12u %-18u %-10u %-8u %-14u %-10u %-8u %u\n",
              grp,                    /* GroupID */
              ctx->group_to_vap[grp], /* RDK VAP index */
              cfg_pct,               /* Configured airtime % */
              grp_actual_rel,        /* Actual(Relative) % of radio TX airtime */
              borrowed,              /* Borrowed (actual > configured) */
              unused,                /* Unused (actual < configured) */
              grp_tx,                /* Duration(us) TX for this group */
              0,                     /* ActualUL % */
              grp_rx,                /* UL(us) RX for this group */
              grp_duration);         /* Actual TX+RX for this group */
        }
    } else {
        u32 actual_rel = (total_airtime > 0) ?
                         (u32)((u64)total_airtime * 100 / total_airtime) : 0;
        W("  %-7u %-10s %-12s %-18u %-10u %-8u %-14u %-10u %-8u %u\n",
          0, "N/A", "N/A (no ATF)", actual_rel, 0,
          100 - actual_rel, total_airtime, 0, total_ul_airtime, total_duration);
    }

    /* ── Peer Stats Table ── */
    W("***** ATF STATS For PEERs *****\n");
    W("%-19s %-8s %-11s %-19s %-11s %-9s %-14s %-9s %-7s %s\n",
      "PeerMAC", "GroupId", "Configured", "Actual(Relative)",
      "Borrowed", "Unused", "Duration(us)", "ActualUL", "UL(us)", "Actual");

    {
        unsigned int p;
        for (p = 0; p < num_peer_disp; p++) {
            u32 p_duration = peer_disp[p].tx_total + peer_disp[p].rx_total;
            W("%02x:%02x:%02x:%02x:%02x:%02x  %-8u %-11u %-19u %-11u %-9u %-14u %-9u %-7u %u\n",
              peer_disp[p].mac[0], peer_disp[p].mac[1],
              peer_disp[p].mac[2], peer_disp[p].mac[3],
              peer_disp[p].mac[4], peer_disp[p].mac[5],
              peer_disp[p].group,      /* GroupId */
              0,                       /* Configured */
              peer_disp[p].actual_rel, /* Actual(Relative) % of radio TX */
              0,                       /* Borrowed (per-peer not tracked) */
              0,                       /* Unused */
              peer_disp[p].tx_total,   /* Duration(us) TX */
              0,                       /* ActualUL % */
              peer_disp[p].rx_total,   /* UL(us) */
              p_duration);             /* Actual combined */
        }
    }

    /* Summary */
    W("Total radio duration(us): %u\n", total_duration);
    W("Total Airtime(us)     %u\n",     total_airtime);
    W("Total UL Airtime(us)  %u\n",     total_ul_airtime);

#undef W
    return NL_SKIP;
}

/**
 * platform_atf_get_stats - Fetch ATF stats via NL80211 vendor DUMP command.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS with NLM_F_DUMP flag
 * using rdk-wifi-hal's nl80211_send_and_recv().  The response is parsed by
 * atf_stats_nl80211_cb() and formatted into a tabulated string.
 *
 * @radio_index: RDK radio index (0, 1, 2)
 * @buf:         output buffer for the stats string
 * @buf_len:     size of buf (recommend ATF_STATS_BUF_MAX = 4096)
 * Returns 0 on success, negative errno on failure.
 */
int platform_atf_get_stats(wifi_radio_index_t radio_index, char *buf, size_t buf_len)
{
    wifi_radio_info_t     *radio;
    wifi_interface_info_t *interface;
    struct nl_msg         *msg;
    struct nlattr         *data;
    struct atf_stats_ctx   ctx;
    int                    ret;

    if (!buf || buf_len == 0)
        return -EINVAL;

    memset(&ctx, 0, sizeof(ctx));
    ctx.buf     = buf;
    ctx.buf_len = buf_len;
    buf[0] = '\0';

    radio = get_radio_by_rdk_index(radio_index);
    if (!radio) {
        snprintf(buf, buf_len, "radio %u not found\n", radio_index);
        return -ENODEV;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        snprintf(buf, buf_len, "no primary interface for radio %u\n", radio_index);
        return -ENODEV;
    }

    /* Build group_to_vap[] and group_airtime[] mappings using the same
     * sorted order as platform_atf_nl80211_ssid_groups() (Bug 2 fix).
     * Previously used hash_map_foreach() which has non-deterministic order,
     * causing VapIndex display to be wrong when a radio has multiple
     * ATF-configured VAPs.  Now uses atf_collect_sorted_vaps() which sorts
     * by vap_index ascending — the same order used when assigning group
     * indices in platform_atf_nl80211_ssid_groups(). */
    ctx.radio = radio;
    memset(ctx.vap_to_group, 0xff, sizeof(ctx.vap_to_group)); /* 0xff = not configured */
    {
        struct atf_vap_entry sorted_vaps[ATF_MAX_VAPS_PER_RADIO];
        unsigned int num_vaps, vi;

        num_vaps = atf_collect_sorted_vaps(radio, sorted_vaps, ATF_MAX_VAPS_PER_RADIO);
        for (vi = 0; vi < num_vaps && vi < 32; vi++) {
            ctx.group_to_vap[vi]  = (u8)sorted_vaps[vi].vap_index;
            ctx.group_airtime[vi] = (u8)sorted_vaps[vi].atm_airtime_percent;
            /* Build reverse map: vap_index → group_index */
            if (sorted_vaps[vi].vap_index < (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO))
                ctx.vap_to_group[sorted_vaps[vi].vap_index] = (u8)vi;
        }
        ctx.num_groups = (u8)num_vaps;

        /* Log the group mapping for debugging */
        wifi_hal_info_print("%s:%d: ATF stats group map for radio %u (%u groups):\n",
                            __func__, __LINE__, radio_index, num_vaps);
        for (vi = 0; vi < num_vaps; vi++) {
            wifi_hal_info_print("%s:%d:   group[%u] = VAP %u (%s) airtime=%u%%\n",
                                __func__, __LINE__, vi,
                                sorted_vaps[vi].vap_index,
                                sorted_vaps[vi].iface->vap_info.u.bss_info.ssid,
                                sorted_vaps[vi].atm_airtime_percent);
        }
    }

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    /* NLM_F_DUMP requests the firmware to return stats */
    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, NLM_F_DUMP,
                     NL80211_CMD_VENDOR, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)interface->index) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                    QCA_NL80211_VENDOR_SUBCMD_ATF_OFFLOAD_OPS)) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!data ||
        nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_ATF_OFFLOAD_RADIO_INDEX,
                   (u8)radio_index)) {
        nlmsg_free(msg);
        return -EINVAL;
    }
    nla_nest_end(msg, data);

    ret = nl80211_send_and_recv(msg, atf_stats_nl80211_cb, &ctx, NULL, NULL);
    if (ret)
        wifi_hal_error_print("%s:%d: ATF stats NL80211 failed ret=%d radio=%u\n",
                             __func__, __LINE__, ret, radio_index);
    else
        wifi_hal_info_print("%s:%d: ATF stats fetched for radio %u (%zu bytes)\n",
                            __func__, __LINE__, radio_index, ctx.written);
    return ret;
}
#endif /* CONFIG_ATF_OFFLOAD */



int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
#if (HOSTAPD_VERSION >= 211)
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface;

    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wpa_printf(MSG_DEBUG,"%s:%d: failed to get interface for vap_index %d\n", __func__,
                    __LINE__, vap->vap_index);
            continue;
        }

        if (interface->u.ap.conf.disable_11be) {
            continue;
        }

        if (!wifi_hal_is_mld_enabled(interface)) {
            continue;
        }

        /* beacon has to be set twice to make it broadcast */
    }
#endif

#ifdef CONFIG_ATF_OFFLOAD
    /* Push per-SSID ATF airtime configuration to the firmware via the
     * hostapd ATF offload algorithm.  This must be called after the BSS
     * instances are started so that the ATF algo (atf_algo) has been
     * initialised by atf_init_algo() inside hostapd_setup_interface_complete().
     */
    platform_set_atf_config(index, map);
#endif /* CONFIG_ATF_OFFLOAD */

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

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    int ret = 0;
    char value[MAX_DEFAULT_VALUE_SIZE] = {0};

    if(is_wifi_hal_vap_private(vap_index))
    {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, DEFAULT_WIFI_PASSWORD_KEY,
                                value, sizeof(value));
    }

    else if(is_wifi_hal_vap_xhs(vap_index))
    {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, DEFAULT_XHS_PASSWORD_KEY,
                                 value, sizeof(value));
    }
    else
    {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, DEFAULT_WIFI_PASSWORD_KEY,
                                value, sizeof(value));
    }
    if(ret == -1)
    {
        wifi_hal_error_print("%s:%d Reading default password for vap %d from factory defaults failed\n",
                                                           __func__, __LINE__, vap_index);
        return 0;
    }

    strncpy(password, value, MAX_DEFAULT_VALUE_SIZE - 1);
    password[MAX_DEFAULT_VALUE_SIZE - 1] = '\0';
    wifi_hal_info_print("%s:%d: Default Password for vap %d: %s\n",
        __func__, __LINE__, vap_index, password);
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    const char *factory_key = NULL;
    char value[MAX_DEFAULT_VALUE_SIZE] = {0};
    int ret;

    if (ssid == NULL) {
        wifi_hal_error_print("%s:%d: NULL ssid param\n", __func__, __LINE__);
        return -1;
    }

    if (is_wifi_hal_vap_mesh_backhaul(vap_index)) {
        factory_key = DEFAULT_MESH_BACKHAUL_SSID_KEY;
    } else if (is_wifi_hal_vap_private(vap_index)) {
        wifi_interface_name_idex_map_t imap[IPQ_UD_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
        unsigned int i;
        get_wifi_interface_info_map(imap);
        for (i = 0; i < ARRAY_SZ(imap); i++) {
            if (imap[i].index != (unsigned int)vap_index)
                continue;
            if (strcmp(imap[i].vap_name, "private_ssid_2g") == 0)
                factory_key = DEFAULT_24G_SSID_KEY;
            else if (strcmp(imap[i].vap_name, "private_ssid_5g") == 0)
                factory_key = DEFAULT_50G_SSID_KEY;
            else if (strcmp(imap[i].vap_name, "private_ssid_6g") == 0)
                factory_key = DEFAULT_60G_SSID_KEY;
            break;
        }
    }

    if (factory_key == NULL) {
        wifi_hal_dbg_print("%s:%d: no factory key for vap_index=%d\n",
            __func__, __LINE__, vap_index);
        return -1;
    }

    ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, (char *)factory_key,
                                     value, sizeof(value));
    if (ret != 0 || value[0] == '\0') {
        if (is_wifi_hal_vap_mesh_backhaul(vap_index)) {
            strncpy(ssid, "Mesh_Backhaul", MAX_DEFAULT_VALUE_SIZE - 1);
            ssid[MAX_DEFAULT_VALUE_SIZE - 1] = '\0';
            wifi_hal_info_print("%s:%d: vap_index=%d key '%s' not in factory file"
                " — using fallback SSID='Mesh_Backhaul'\n",
                __func__, __LINE__, vap_index, factory_key);
            return 0;
        }
        wifi_hal_error_print("%s:%d: factory read failed for key=%s vap_index=%d ret=%d\n",
            __func__, __LINE__, factory_key, vap_index, ret);
        return -1;
    }

    strncpy(ssid, value, MAX_DEFAULT_VALUE_SIZE - 1);
    ssid[MAX_DEFAULT_VALUE_SIZE - 1] = '\0';
    wifi_hal_dbg_print("%s:%d: vap_index=%d ssid=%s (from factory)\n",
        __func__, __LINE__, vap_index, ssid);
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    int ret = 0;

    if (pin == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return -1;
    }

    ret = qcconfig_get_param("default_wps_pin", pin, MAX_DEFAULT_VALUE_SIZE);

    if (ret != 0) {
        wifi_hal_error_print("%s: Failed to get default_wps_pin\n", __FUNCTION__);
        return -1;
    }
    wifi_hal_dbg_print("%s:%d: wps_pin:%s \n", __func__, __LINE__, pin);

    return 0;
}

void mac_print (u_int8_t *context, u_int8_t *mac)
{
    wifi_hal_info_print("%s %02x:%02x:%02x:%02x:%02x:%02x\n",context, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return;
}
int platform_wps_event(wifi_wps_event_t data)
{
    union wps_event_data *wps = (union wps_event_data *) data.wps_data;
    unsigned int event = data.event;

    struct wps_event_success *success = NULL;
    struct wps_event_pwd_auth_fail *auth_fail = NULL;
    struct wps_event_fail *fail = NULL;

    wifi_hal_info_print("%s:%d WPS EVENT vap_index=%d event=%u wps_data=%p\n",
        __func__, __LINE__, data.vap_index, event,
        (void *)wps);

     switch (event) {
         case WPS_EV_M2D:
            /* data->m2d may be populated but hostapd does not use it; just log */
            wifi_hal_info_print("%s:%d WPS M2D received (Registrar did not know us) vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_FAIL:
            if (wps == NULL) {
                wifi_hal_error_print("%s:%d WPS_EV_FAIL: NULL wps_data\n", __func__, __LINE__);
                break;
            }
             fail = &wps->fail;
            mac_print((uint8_t *)"WPS Registration Fail", fail->peer_macaddr);
             if (fail->error_indication > 0 && fail->error_indication < NUM_WPS_EI_VALUES) {
#ifdef QCA_UD_HOSTAPD
                wifi_hal_info_print("%s:%d WPS-FAIL msg=%d config_error=%d reason=%d (%s)\n",
                    __func__, __LINE__, fail->msg, fail->config_error,
                    fail->error_indication, WPS_ei_to_str[fail->error_indication]);
#else
                wifi_hal_info_print("%s:%d WPS-FAIL msg=%d config_error=%d reason=%d\n",
                    __func__, __LINE__, fail->msg, fail->config_error,
                    fail->error_indication);
#endif /* QCA_UD_HOSTAPD */
             } else {
                wifi_hal_info_print("%s:%d WPS-FAIL msg=%d config_error=%d reason=%d\n",
                    __func__, __LINE__, fail->msg, fail->config_error,
                    fail->error_indication);
             }
             break;
        case WPS_EV_SUCCESS:
            if (wps == NULL) {
                wifi_hal_error_print("%s:%d WPS_EV_SUCCESS: NULL wps_data\n", __func__, __LINE__);
                break;
            }
            success = &wps->success;
            mac_print((uint8_t *)"WPS Registration Success", success->peer_macaddr);
            wifi_hal_info_print("%s:%d WPS Registration Success vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_PWD_AUTH_FAIL:
            if (wps == NULL) {
                wifi_hal_error_print("%s:%d WPS_EV_PWD_AUTH_FAIL: NULL wps_data\n", __func__, __LINE__);
                break;
            }
            auth_fail = &wps->pwd_auth_fail;
            mac_print((uint8_t *)"WPS: Authentication failure update", auth_fail->peer_macaddr);
            wifi_hal_info_print("%s:%d WPS PWD_AUTH_FAIL enrollee=%d part=%d vap_index=%d\n",
                __func__, __LINE__, auth_fail->enrollee,
                auth_fail->part, data.vap_index);
            break;

        case WPS_EV_PBC_OVERLAP:
            wifi_hal_info_print("%s:%d PBC Status: %s vap_index=%d\n",
                __func__, __LINE__, "PBC Overlap", data.vap_index);
            break;

        case WPS_EV_PBC_TIMEOUT:
            wifi_hal_info_print("%s:%d PBC Status: %s vap_index=%d\n",
                __func__, __LINE__, "PBC Timeout", data.vap_index);
            break;

        case WPS_EV_PBC_DISABLE:
            wifi_hal_info_print("%s:%d PBC Status: %s vap_index=%d\n",
                __func__, __LINE__, "PBC Disabled", data.vap_index);
            break;

        case WPS_EV_PBC_ACTIVE:
            wifi_hal_info_print("%s:%d PBC Status: %s vap_index=%d\n",
                __func__, __LINE__, "PBC Active", data.vap_index);
            break;

        case WPS_EV_PIN_TIMEOUT:
            wifi_hal_info_print("%s:%d PIN Status: %s vap_index=%d\n",
                __func__, __LINE__, WPS_enum_to_str[WPS_EV_PIN_TIMEOUT], data.vap_index);
            break;

        case WPS_EV_PIN_DISABLE:
            wifi_hal_info_print("%s:%d PIN Status: %s vap_index=%d\n",
                __func__, __LINE__, WPS_enum_to_str[WPS_EV_PIN_DISABLE], data.vap_index);
            break;

        case WPS_EV_PIN_ACTIVE:
            wifi_hal_info_print("%s:%d PIN Status: %s vap_index=%d\n",
                __func__, __LINE__, WPS_enum_to_str[WPS_EV_PIN_ACTIVE], data.vap_index);
            break;

        case WPS_EV_ER_AP_ADD:
            wifi_hal_info_print("%s:%d WPS ER: AP added vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_ER_AP_REMOVE:
            wifi_hal_info_print("%s:%d WPS ER: AP removed vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_ER_ENROLLEE_ADD:
            wifi_hal_info_print("%s:%d WPS ER: Enrollee added vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_ER_ENROLLEE_REMOVE:
            wifi_hal_info_print("%s:%d WPS ER: Enrollee removed vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_ER_AP_SETTINGS:
            wifi_hal_info_print("%s:%d WPS ER: AP Settings learned vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_ER_SET_SELECTED_REGISTRAR:
            wifi_hal_info_print("%s:%d WPS ER: SetSelectedRegistrar vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        case WPS_EV_AP_PIN_SUCCESS:
            wifi_hal_info_print("%s:%d WPS External Registrar used correct AP PIN vap_index=%d\n",
                __func__, __LINE__, data.vap_index);
            break;

        default:
            wifi_hal_info_print("%s:%d WPS unknown event=%u vap_index=%d\n",
                __func__, __LINE__, event, data.vap_index);
             break;
    }
    return 0;
}

int platform_get_country_code_default(char *code)
{
    strcpy(code,"US");
    return 0;
}


#define OUI_QCA_VENDOR_IE "dd088cfdf00101020100"
int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    if (NULL == vendor_oui) {
        wifi_hal_error_print("%s:%d  Invalid parameter \n", __func__, __LINE__);
        return -1;
    }
    strncpy(vendor_oui, OUI_QCA_VENDOR_IE, vendor_oui_len - 1);
    vendor_oui[vendor_oui_len - 1] = '\0';
    return 0;
}


static int generate_vap_mac_addr(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
                                  uint8_t *out_mac)
{
    char path[128];
    char line[64];
    FILE *f;
    uint8_t base_mac[ETH_ALEN] = {0};   /* macaddress (phy permanent addr) */
    uint8_t addr_mask[ETH_ALEN] = {0};
    uint8_t addrs[32][ETH_ALEN];
    int num_addrs = 0;
    int idx;
    static const uint8_t zero_mask[ETH_ALEN] = {0};
    uint8_t radio_base_mac[ETH_ALEN] = {0};
    /* For 6GHz, MBSSID is enabled → use "b5" algorithm (last-octet rotation). */
    bool use_mbssid = (radio->oper_param.band == WIFI_FREQUENCY_6_BAND);
    int  mbssid_group_size = 4;
    uint8_t mbssid_base_mac[ETH_ALEN] = {0};

    /* Read phy permanent MAC address */
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/macaddress", radio->name);
    f = fopen(path, "r");
    if (!f) {
        wifi_hal_error_print("%s:%d: cannot open %s\n", __func__, __LINE__, path);
        return RETURN_ERR;
    }
    if (fscanf(f, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &base_mac[0], &base_mac[1], &base_mac[2],
               &base_mac[3], &base_mac[4], &base_mac[5]) != 6) {
        fclose(f);
        return RETURN_ERR;
    }
    fclose(f);

    /* Read address mask */
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/address_mask", radio->name);
    f = fopen(path, "r");
    if (f) {
        fscanf(f, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &addr_mask[0], &addr_mask[1], &addr_mask[2],
               &addr_mask[3], &addr_mask[4], &addr_mask[5]);
        fclose(f);
    }

    /* Read pre-allocated per-band addresses.
     * The file has one entry per band: addrs[0]=2.4GHz, addrs[1]=5GHz, addrs[2]=6GHz.
     * This mirrors OpenWRT's addrs[radio_idx] selection. */
    snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/addresses", radio->name);
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f) && num_addrs < 32) {
            if (sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &addrs[num_addrs][0], &addrs[num_addrs][1],
                       &addrs[num_addrs][2], &addrs[num_addrs][3],
                       &addrs[num_addrs][4], &addrs[num_addrs][5]) == 6) {
                num_addrs++;
            }
        }
        fclose(f);
    }

    /* Select per-radio base MAC: addrs[rdk_radio_index] if available.
     * This is the OpenWRT radio_idx concept: each radio gets its own base MAC
     * from the addresses file so VAPs on different radios don't collide. */
    if (radio->rdk_radio_index < num_addrs) {
        memcpy(radio_base_mac, addrs[radio->rdk_radio_index], ETH_ALEN);
        wifi_hal_dbg_print("%s:%d: radio[%d] base MAC = "
            "%02x:%02x:%02x:%02x:%02x:%02x (addrs[%d])\n",
            __func__, __LINE__, radio->rdk_radio_index,
            radio_base_mac[0], radio_base_mac[1], radio_base_mac[2],
            radio_base_mac[3], radio_base_mac[4], radio_base_mac[5],
            radio->rdk_radio_index);
    } else {
        /* Fallback: use phy permanent MAC */
        memcpy(radio_base_mac, base_mac, ETH_ALEN);
    }

    /* For MBSSID (6GHz): find the "transmitted BSSID" — the MAC of the first
     * existing VAP on this radio.  All non-transmitted BSSIDs must differ from
     * it only in the lower mbssid_group_size bits of the last octet. */
    if (use_mbssid && radio->interface_map) {
        wifi_interface_info_t *intf = hash_map_get_first(radio->interface_map);
        while (intf) {
            if (memcmp(intf->mac, zero_mask, ETH_ALEN) != 0 &&
                !(intf->mac[0] & 0x01)) {
                memcpy(mbssid_base_mac, intf->mac, ETH_ALEN);
                wifi_hal_dbg_print("%s:%d: MBSSID tx-BSSID = "
                    "%02x:%02x:%02x:%02x:%02x:%02x\n",
                    __func__, __LINE__,
                    mbssid_base_mac[0], mbssid_base_mac[1], mbssid_base_mac[2],
                    mbssid_base_mac[3], mbssid_base_mac[4], mbssid_base_mac[5]);
                break;
            }
            intf = hash_map_get_next(radio->interface_map, intf);
        }
        if (memcmp(mbssid_base_mac, zero_mask, ETH_ALEN) == 0)
            memcpy(mbssid_base_mac, radio_base_mac, ETH_ALEN);
    }

    /* Iterate idx 0..31, generate candidate, skip if already in use */
    for (idx = 0; idx < 32; idx++) {
        uint8_t candidate[ETH_ALEN];
        bool in_use = false;
        int ri;

        if (memcmp(addr_mask, zero_mask, ETH_ALEN) == 0) {
            /* address_mask is all-zeros */
            if (idx == 0) {
                /* idx 0: per-radio base MAC (addrs[rdk_radio_index]) */
                memcpy(candidate, radio_base_mac, ETH_ALEN);
            } else if (use_mbssid) {
                /* "b5" algorithm for MBSSID (6GHz):
                 * Rotate the last octet within the MBSSID group so that all
                 * BSSIDs share the same upper (8 - log2(group_size)) bits.
                 * Satisfies the IEEE 802.11ax MBSSID constraint. */
                int size = mbssid_group_size;
                int B    = mbssid_base_mac[5] % size;
                int loct = mbssid_base_mac[5];
                memcpy(candidate, mbssid_base_mac, ETH_ALEN);
                candidate[5] = (uint8_t)((loct - B + ((B + idx) % size)) & 0xff);
            } else {
                /* "b1" algorithm for non-MBSSID bands:
                 * Set the Locally Administered bit and XOR bits 2-7 of the
                 * first octet with the slot index. */
                int b1_idx = idx;
                memcpy(candidate, radio_base_mac, ETH_ALEN);
                if (!(candidate[0] & 2))
                    b1_idx--;
                candidate[0] |= 2;
                candidate[0] ^= (uint8_t)(b1_idx << 2);
            }
        } else {
            /* Non-zero address_mask: use the mask to select the algorithm,
             * mirroring OpenWRT's type selection logic:
             *   mask[0] > 0          -> "b1": XOR first octet (LA bit + idx)
             *   mask[5] < 0xff       -> "b5": XOR last octet with idx
             *   otherwise            -> "add": increment last octets
             * For idx==0 always return the per-radio base MAC directly. */
            if (idx == 0) {
                memcpy(candidate, radio_base_mac, ETH_ALEN);
            } else if (addr_mask[0] > 0) {
                /* "b1": set LA bit, XOR bits 2-7 of first octet */
                int b1_idx = idx;
                memcpy(candidate, radio_base_mac, ETH_ALEN);
                if (!(candidate[0] & 2))
                    b1_idx--;
                candidate[0] |= 2;
                candidate[0] ^= (uint8_t)(b1_idx << 2);
            } else if (addr_mask[5] < 0xff) {
                /* "b5": XOR last octet with idx (non-MBSSID variant) */
                memcpy(candidate, radio_base_mac, ETH_ALEN);
                candidate[5] ^= (uint8_t)idx;
                candidate[5] &= 0xff;
            } else {
                /* "add": increment last octets with carry propagation */
                int i;
                memcpy(candidate, radio_base_mac, ETH_ALEN);
                for (i = 5; i > 0; i--) {
                    candidate[i] = (uint8_t)(candidate[i] + idx);
                    if ((int)radio_base_mac[i] + idx < 256)
                        break;
                }
            }
        }

        /* Skip multicast / all-zero addresses */
        if (candidate[0] & 0x01)
            continue;
        if (memcmp(candidate, zero_mask, ETH_ALEN) == 0)
            continue;

        /* Check if already assigned to an existing interface */
        for (ri = 0; ri < g_wifi_hal.num_radios && !in_use; ri++) {
            wifi_radio_info_t *r = get_radio_by_rdk_index(ri);
            wifi_interface_info_t *intf;
            if (!r || !r->interface_map)
                continue;
            intf = hash_map_get_first(r->interface_map);
            while (intf) {
                if (memcmp(intf->mac, candidate, ETH_ALEN) == 0) {
                    in_use = true;
                    break;
                }
                intf = hash_map_get_next(r->interface_map, intf);
            }
        }

        if (!in_use) {
            memcpy(out_mac, candidate, ETH_ALEN);
            wifi_hal_info_print("%s:%d: vap_index=%d radio[%d] assigned MAC "
                "%02x:%02x:%02x:%02x:%02x:%02x (idx=%d %s)\n",
                __func__, __LINE__, vap->vap_index, radio->rdk_radio_index,
                out_mac[0], out_mac[1], out_mac[2],
                out_mac[3], out_mac[4], out_mac[5], idx,
                use_mbssid ? "b5/MBSSID" : "b1");
            return RETURN_OK;
        }
    }

    wifi_hal_error_print("%s:%d: no unique MAC found for vap_index=%d\n",
        __func__, __LINE__, vap->vap_index);
    return RETURN_ERR;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface;
    wifi_radio_info_t *radio = NULL;
    static const uint8_t null_bssid[ETH_ALEN] = {0};
    uint8_t generated_mac[ETH_ALEN];

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
            __func__, __LINE__, index);
        return -1;
    }

    if (map == NULL)
    {
        wifi_hal_dbg_print("%s:%d: wifi_vap_info_map_t *map is NULL \n", __func__, __LINE__);
    }
    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        if (memcmp(vap->u.bss_info.bssid, null_bssid, ETH_ALEN) == 0) {
            if (generate_vap_mac_addr(radio, vap, generated_mac) == RETURN_OK) {
                memcpy(vap->u.bss_info.bssid, generated_mac, ETH_ALEN);
            } else {
                wifi_hal_error_print("%s:%d: MAC generation failed for vap_index=%d\n",
                        __func__, __LINE__, vap->vap_index);
            }
        }

#if HOSTAPD_VERSION >= 210
        /* R-RMM-02: Validate MAC prefix for MBSSID group BEFORE interface creation.
         * Reject early so that nl80211_create_interface() is never called with a
         * bad MAC — avoids wasting kernel resources on an interface that would be
         * torn down immediately.
         *
         * Guard: only for 6G (MBSSID enabled), only when a TX VAP is already
         * started, never compare against itself, skip zero MAC.
         * Skip for disabled VAPs (disable path does not recreate the interface).
         *
         * Uses hostapd_max_bssid_indicator() which correctly returns n=4 for MLO
         * (num_multi_hws=3, mbssid_max_interfaces=48, per-radio limit=16).
         */
        if (vap->u.bss_info.enabled &&
            radio->oper_param.band == WIFI_FREQUENCY_6_BAND &&
            !is_zero_ether_addr(vap->u.bss_info.bssid)) {
            wifi_interface_info_t *_tx_intf = NULL;
            wifi_interface_info_t *_intf = hash_map_get_first(radio->interface_map);
            while (_intf != NULL) {
                if (_intf->vap_info.vap_mode == wifi_vap_mode_ap &&
                    _intf->u.ap.hapd.iconf != NULL &&
                    _intf->u.ap.hapd.iconf->mbssid != MBSSID_DISABLED &&
                    _intf->u.ap.hapd.started &&
                    !is_zero_ether_addr(_intf->u.ap.hapd.own_addr)) {
                    _tx_intf = _intf;
                    break;
                }
                _intf = hash_map_get_next(radio->interface_map, _intf);
            }
            if (_tx_intf != NULL) {
#ifdef QCA_UD_HOSTAPD
                u8  _n    = hostapd_max_bssid_indicator(&_tx_intf->u.ap.hapd);
                u64 _mask = (u64)UINT64_MAX << _n;
                u64 _new  = ((u64)vap->u.bss_info.bssid[0] << 40) |
                            ((u64)vap->u.bss_info.bssid[1] << 32) |
                            ((u64)vap->u.bss_info.bssid[2] << 24) |
                            ((u64)vap->u.bss_info.bssid[3] << 16) |
                            ((u64)vap->u.bss_info.bssid[4] << 8)  |
                            ((u64)vap->u.bss_info.bssid[5]);
                u64 _tx   = ((u64)_tx_intf->u.ap.hapd.own_addr[0] << 40) |
                            ((u64)_tx_intf->u.ap.hapd.own_addr[1] << 32) |
                            ((u64)_tx_intf->u.ap.hapd.own_addr[2] << 24) |
                            ((u64)_tx_intf->u.ap.hapd.own_addr[3] << 16) |
                            ((u64)_tx_intf->u.ap.hapd.own_addr[4] << 8)  |
                            ((u64)_tx_intf->u.ap.hapd.own_addr[5]);
                if ((_new & _mask) != (_tx & _mask)) {
                    wifi_hal_error_print(
                        "%s:%d: [R-RMM-02] vap_index=%d MAC " MACSTR
                        " fails MBSSID prefix requirement"
                        " (TX VAP %s: " MACSTR ", n=%u)"
                        " -- rejecting VAP creation\n",
                        __func__, __LINE__, vap->vap_index,
                        MAC2STR(vap->u.bss_info.bssid),
                        _tx_intf->name,
                        MAC2STR(_tx_intf->u.ap.hapd.own_addr),
                        (unsigned)_n);
                    return RETURN_ERR;
                }
                wifi_hal_info_print(
                    "%s:%d: [R-RMM-02] vap_index=%d MAC " MACSTR
                    " satisfies MBSSID prefix (TX VAP %s: " MACSTR ", n=%u)\n",
                    __func__, __LINE__, vap->vap_index,
                    MAC2STR(vap->u.bss_info.bssid),
                    _tx_intf->name,
                    MAC2STR(_tx_intf->u.ap.hapd.own_addr),
                    (unsigned)_n);
#endif /* QCA_UD_HOSTAPD */
            }
        }
#endif /* HOSTAPD_VERSION >= 210 */

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: failed to get interface for vap_index %d\n", __func__,
                    __LINE__, vap->vap_index);

            /* For mesh_backhaul VAPs the link interface (e.g. mld3) has not been
             * created yet because the MLD parent (e.g. phy00-mld1) is missing.
             * Create the MLD parent now so that the subsequent
             * nl80211_create_interface() call in wifi_hal_createVAP() succeeds
             * when it tries to look up the MLD parent via if_nametoindex(). */
            if (is_wifi_hal_vap_mesh_backhaul(vap->vap_index)) {
                char ifname[32] = {0};
                if (get_interface_name_from_vap_index(vap->vap_index, ifname) == RETURN_OK
                        && ifname[0] != '\0') {
                    char *mld_parent = wifi_hal_get_mld_name_by_interface_name(ifname);
                    if (mld_parent != NULL && mld_parent[0] != '\0') {
                        if (if_nametoindex(mld_parent) == 0) {
                            /* Derive phy name from MLD parent name.
                             * e.g. "phy00-mld1" → phy_name = "phy00" */
                            char phy_name[32] = {0};
                            char *sep = strstr(mld_parent, "-mld");
                            if (sep != NULL) {
                                size_t phy_len = (size_t)(sep - mld_parent);
                                if (phy_len < sizeof(phy_name) - 1)
                                    strncpy(phy_name, mld_parent, phy_len);
                            } else {
                                snprintf(phy_name, sizeof(phy_name), "phy%02d", radio->index);
                            }
                            /* Generate a unique MAC for the MLD parent using
                             * generate_vap_mac_addr() so it does not collide
                             * with any existing kernel interface MAC.
                             * Without an explicit addr the kernel assigns the
                             * phy base MAC, which duplicates phy00-mld0. */
                            uint8_t mld_mac[ETH_ALEN] = {0};
                            if (generate_vap_mac_addr(radio, vap, mld_mac) != RETURN_OK) {
                                wifi_hal_error_print(
                                        "%s:%d: MAC generation failed for MLD"
                                        " parent %s — will use phy base MAC\n",
                                        __func__, __LINE__, mld_parent);
                            }
                            char cmd[160];
                            static const uint8_t zero_mac[ETH_ALEN] = {0};
                            if (memcmp(mld_mac, zero_mac, ETH_ALEN) != 0) {
                                snprintf(cmd, sizeof(cmd),
                                         "iw phy %s interface add %s type __ap"
                                         " addr %02x:%02x:%02x:%02x:%02x:%02x",
                                         phy_name, mld_parent,
                                         mld_mac[0], mld_mac[1], mld_mac[2],
                                         mld_mac[3], mld_mac[4], mld_mac[5]);
                            } else {
                                snprintf(cmd, sizeof(cmd),
                                         "iw phy %s interface add %s type __ap",
                                         phy_name, mld_parent);
                            }
                            wifi_hal_info_print(
                                    "%s:%d: MLD parent %s missing — creating: %s\n",
                                    __func__, __LINE__, mld_parent, cmd);
                            if (system(cmd) != 0) {
                                wifi_hal_error_print(
                                        "%s:%d: failed to create MLD parent %s"
                                        " for vap_index %d\n",
                                        __func__, __LINE__, mld_parent, vap->vap_index);
                            } else {
                                wifi_hal_info_print(
                                        "%s:%d: created MLD parent %s"
                                        " for vap_index %d\n",
                                        __func__, __LINE__, mld_parent, vap->vap_index);
                                /* Bring up the MLD parent NOW — before
                                 * nl80211_create_interface() creates and
                                 * brings up the link interface (e.g. mld2)
                                 * with the same MAC address.  If the link
                                 * interface is up first, bringing up the MLD
                                 * parent later fails with ENOTUNIQ because
                                 * both share the same MAC. */
                                if (nl80211_interface_enable(mld_parent, true) < 0) {
                                    wifi_hal_error_print(
                                            "%s:%d: failed to bring up MLD"
                                            " parent %s\n",
                                            __func__, __LINE__, mld_parent);
                                } else {
                                    wifi_hal_info_print(
                                            "%s:%d: brought up MLD parent %s"
                                            " before link interface creation\n",
                                            __func__, __LINE__, mld_parent);
                                }
                            }
                        } else {
                            wifi_hal_info_print(
                                    "%s:%d: MLD parent %s already exists"
                                    " for vap_index %d\n",
                                    __func__, __LINE__, mld_parent, vap->vap_index);
                        }
                    }
                }
                /* Skip the MLD config-override block below — the link interface
                 * does not exist yet and will be created by nl80211_create_interface()
                 * inside wifi_hal_createVAP() now that the MLD parent is present. */
                continue;
            }
            return -1;
        }
        /* Override MLO configuration because MLD is enabled on boot. */
        vap->u.bss_info.mld_info.common_info.mld_enable =
            interface->vap_info.u.bss_info.mld_info.common_info.mld_enable;
        memcpy(vap->u.bss_info.mld_info.common_info.mld_addr,
                interface->vap_info.u.bss_info.mld_info.common_info.mld_addr,
                sizeof(vap->u.bss_info.mld_info.common_info.mld_addr));
        vap->u.bss_info.mld_info.common_info.mld_link_id =
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id;
        vap->u.bss_info.mld_info.common_info.mld_id =
            interface->vap_info.u.bss_info.mld_info.common_info.mld_id;

        wifi_hal_info_print("%s:%d: %s mld_id:%d link_id:%d mld_enable:%d \n",
              __func__, __LINE__, interface->name, vap->u.bss_info.mld_info.common_info.mld_id, vap->u.bss_info.mld_info.common_info.mld_link_id, vap->u.bss_info.mld_info.common_info.mld_enable);
        /* Disable non-MLD interface so its MAC can be reused for the MLD link. */
        if (vap->u.bss_info.mld_info.common_info.mld_enable &&
                nl80211_interface_enable(interface->name, false) < 0) {
            wifi_hal_error_print("%s:%d: failed to disable interface %s\n", __func__, __LINE__,
                    interface->name);
            return -1;
        }
        wifi_hal_error_print("%s:%d: precreate VAP END\n", __func__, __LINE__);
    }

    return 0;
}


int platform_flags_init(int *flags)
{  
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    *flags |= PLATFORM_FLAGS_CONTROL_PORT_FRAME;
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

UINT wifi_freq_to_op_class(UINT freq)
{
    u8 op_class, channel;

    if (ieee80211_freq_to_channel_ext(freq, 0, 0, &op_class, &channel) == NUM_HOSTAPD_MODES){
        wifi_hal_error_print("%s:%d Failed to get op class for freq : %d\n", __func__, __LINE__, freq);
        return RETURN_ERR;
    }

    return op_class;
}


int platform_update_radio_presence(void)
{
    unsigned int index = 0;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    wifi_radio_info_t *radio = NULL;
    radio_interface_mapping_t platform_map_t[IPQ_UD_MAX_NUM_RADIOS];

    get_radio_interface_info_map(platform_map_t);

    wifi_hal_info_print("%s:%d: g_wifi_hal.num_radios %d\n", __func__, __LINE__, g_wifi_hal.num_radios);
    for (index = 0; index < g_wifi_hal.num_radios; index++)
    {
        radio = get_radio_by_rdk_index(index);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d: radio NULL for index %d\n", __func__, __LINE__, index);
            continue;
        }
        snprintf(cmd, sizeof(cmd), "/sys/class/net/%s", platform_map_t[index].interface_name);
        if (is_interface_exists(cmd)) {
            radio->radio_presence = true;
        } else {
            radio->radio_presence = false;
        }
        wifi_hal_info_print("%s:%d: Index %d iface %s presence %d\n", __func__, __LINE__, index, platform_map_t[index].interface_name, radio->radio_presence);
    }

    return 0;
}

/*
 * Callback used by nl80211_send_and_recv() to extract the TX power level
 * reported by the kernel after a SET or GET_INTERFACE command.
 */
struct txpwr_query_result {
    int  tx_power_mbm;
    bool found;
};

static int txpower_get_handler(struct nl_msg *msg, void *arg)
{
    struct txpwr_query_result *result = (struct txpwr_query_result *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]) {
        result->tx_power_mbm = (int)nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]);
        result->found = true;
    }
    return NL_SKIP;
}

/*
 * Send NL80211_CMD_SET_WIPHY with NL80211_TX_POWER_LIMITED and the given
 * mBm value.  Returns 0 on success, negative on error.
 */
static int nl80211_set_txpower_mbm(wifi_interface_info_t *interface, int mbm)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (msg == NULL)
        return -ENOMEM;

    if (genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                    NL80211_CMD_SET_WIPHY, 0) == NULL ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (uint32_t)interface->index) < 0 ||
        nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING,
                    NL80211_TX_POWER_LIMITED) < 0 ||
        nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
                    (uint32_t)mbm) < 0) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    /* msg ownership transferred to nl80211_send_and_recv / execute_send_and_recv,
     * which always calls nlmsg_free(msg) internally — do NOT free here. */
    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    return ret;
}

/*
 * Query the kernel for the current TX power on the interface.
 * Returns the TX power in mBm, or a negative value on error.
 */
static int nl80211_get_txpower_mbm(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    struct txpwr_query_result result = { .tx_power_mbm = -1, .found = false };
    int ret;

    msg = nlmsg_alloc();
    if (msg == NULL)
        return -ENOMEM;

    if (genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                    NL80211_CMD_GET_INTERFACE, 0) == NULL ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (uint32_t)interface->index) < 0) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    /* msg ownership transferred to nl80211_send_and_recv / execute_send_and_recv,
     * which always calls nlmsg_free(msg) internally — do NOT free here. */
    ret = nl80211_send_and_recv(msg, txpower_get_handler, &result, NULL, NULL);

    if (ret != 0 || !result.found)
        return -1;

    return result.tx_power_mbm;
}

int platform_set_txpower(void* priv, uint txpower)
{
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;
    int g_max_pwr_mbm = 0;
    int g_max_pwr = 0;   /* dBm */
    int tx_pwr = 0;      /* dBm */
    int target_mbm = 0;
    int ret;

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: NULL interface pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /*
     * Set 3000 mBm (30 dBm) — well above any regulatory limit.
     * The driver/kernel will cap it at the regulatory maximum, so the
     * value read back is the true maximum for this interface.
     */
    ret = nl80211_set_txpower_mbm(interface, 3000);
    if (ret != 0) {
        wifi_hal_error_print(
            "%s:%d: Failed to set probe TX power on %s: %d\n",
            __func__, __LINE__, interface->name, ret);
        return RETURN_ERR;
    }

    /*
     * Read back the actual (capped) TX power — this is the max.
     */
    g_max_pwr_mbm = nl80211_get_txpower_mbm(interface);
    if (g_max_pwr_mbm <= 0) {
        wifi_hal_error_print(
            "%s:%d: Failed to read max TX power on %s (got %d mBm)\n",
            __func__, __LINE__, interface->name, g_max_pwr_mbm);
        return RETURN_ERR;
    }

    /* Convert mBm → dBm (round to nearest integer) */
    g_max_pwr = (g_max_pwr_mbm + 50) / 100;

    wifi_hal_dbg_print(
        "%s:%d: Max TX power on %s: %d mBm (%d dBm), requested: %u%%\n",
        __func__, __LINE__, interface->name, g_max_pwr_mbm, g_max_pwr, txpower);

    /*
     * Map the OneWiFi percentage to a dBm offset from the maximum.
     * These offsets match the standard 3 dB per halving-of-power convention.
     */
    if (txpower == 100) {
        tx_pwr = g_max_pwr - 0;
    } else if (txpower == 75) {
        tx_pwr = g_max_pwr - 1;
    } else if (txpower == 50) {
        tx_pwr = g_max_pwr - 3;
    } else if (txpower == 25) {
        tx_pwr = g_max_pwr - 6;
    } else if (txpower == 12) {
        tx_pwr = g_max_pwr - 9;
    } else if (txpower == 6) {
        tx_pwr = g_max_pwr - 12;
    } else if (txpower == 0) {
        tx_pwr = 0;
    } else {
        /* Unknown percentage — use maximum */
        tx_pwr = g_max_pwr;
    }

    /* Clamp to a sane minimum (1 dBm) unless explicitly set to 0 */
    if (txpower != 0 && tx_pwr < 1)
        tx_pwr = 1;

    target_mbm = tx_pwr * 100;

    wifi_hal_dbg_print(
        "%s:%d: Setting TX power on %s to %d dBm (%d mBm)\n",
        __func__, __LINE__, interface->name, tx_pwr, target_mbm);

    /*
     * Apply the computed TX power.
     */
    ret = nl80211_set_txpower_mbm(interface, target_mbm);
    if (ret != 0) {
        wifi_hal_error_print(
            "%s:%d: Failed to set TX power %d mBm on %s: %d\n",
            __func__, __LINE__, target_mbm, interface->name, ret);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: TX power set to %d dBm (%d mBm) on %s\n",
        __func__, __LINE__, tx_pwr, target_mbm, interface->name);
    return RETURN_OK;
}

int platform_set_offload_mode(void* priv, uint offload_mode)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return RETURN_OK;
}

int platform_get_radius_key_default(char *radius_key)
{
    int ret = 0;

    if (radius_key == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return -1;
    }

    ret = qcconfig_get_param("default_radius_key", radius_key, WIFI_MAX_RADIUS_KEY);
    if (ret != 0) {
        wifi_hal_error_print("%s: Failed to get default_radius_key\n", __FUNCTION__);
        return -1;
    }
    wifi_hal_dbg_print("%s:%d: default radious key:%s \n", __func__, __LINE__,radius_key);

    return 0;
}

INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *txpower)
{
    wifi_radio_info_t    *radio     = NULL;
    wifi_interface_info_t *interface = NULL;
    int mbm;

    if (txpower == NULL) {
        wifi_hal_error_print("%s:%d: NULL txpower pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get primary interface for radio %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    mbm = nl80211_get_txpower_mbm(interface);
    if (mbm <= 0) {
        wifi_hal_error_print("%s:%d: Failed to get TX power for radio %d (got %d mBm)\n",
                __func__, __LINE__, radioIndex, mbm);
        return RETURN_ERR;
    }

    /* Convert mBm → dBm (round to nearest integer) */
    *txpower = (ULONG)((mbm + 50) / 100);

    wifi_hal_info_print("%s:%d: Radio %d TX power: %d mBm = %lu dBm\n",
            __func__, __LINE__, radioIndex, mbm, *txpower);

    return RETURN_OK;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{

     radioPhyTemperature->radio_Temperature =  0;

     return RETURN_OK;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    wifi_interface_info_t *interface;

    if (acl_count == NULL) {
        wifi_hal_error_print("%s:%d: NULL acl_count pointer for vap_index:%d\n",
            __func__, __LINE__, vap_index);
        return -1;
    }

    interface = get_interface_by_vap_index(vap_index);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for vap_index:%d\n",
            __func__, __LINE__, vap_index);
        *acl_count = 0;
        return -1;
    }

    *acl_count = (interface->acl_map != NULL) ? hash_map_count(interface->acl_map) : 0;

    wifi_hal_dbg_print("%s:%d: vap_index:%d acl_count:%u\n",
        __func__, __LINE__, vap_index, *acl_count);
    return 0;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    wifi_hal_info_print("%s:%d Enter %d\n", __func__, __LINE__,index);

    (void)add;
    (void)mac;

    return 0;
}

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
     int nol_timeout_secs = 0;
     FILE *fp;

     if (operationParam == NULL) {
         wifi_hal_error_print("%s:%d: NULL operationParam\n", __func__, __LINE__);
         return -1;
     }

     /* Convert DFSTimer (minutes) to seconds for cfg80211 NOL timeout.
      * This synchronizes the kernel-level NOL timeout with the OneWifi
      * DFSTimer so both layers expire at the same time.
      * Only applicable for test builds where dfs_nol_timeout param exists.
      */
     nol_timeout_secs = operationParam->DFSTimer * 60;

     fp = fopen("/sys/module/cfg80211/parameters/dfs_nol_timeout", "w");
     if (fp == NULL) {
         wifi_hal_dbg_print("%s:%d: dfs_nol_timeout not available (non-test build)\n",
                            __func__, __LINE__);
         return 0;
     }

     fprintf(fp, "%d\n", nol_timeout_secs);
     fclose(fp);

     wifi_hal_info_print("%s:%d: Set cfg80211 dfs_nol_timeout=%d sec (DFSTimer=%d min) for radio %d\n",
                         __func__, __LINE__, nol_timeout_secs, operationParam->DFSTimer, index);

    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    wifi_vap_index_t retry_vap_index = interface->vap_info.vap_index;
    int res = -1;

    wifi_hal_info_print("%s:%d: Setting AP retry limit for vap_index:%d retry_limit:%d\n",
        __func__, __LINE__, retry_vap_index, RETRY_LIMIT);

    res = wifi_setApRetryLimit(retry_vap_index, RETRY_LIMIT);

    if (res) {
        wifi_hal_error_print("%s:%d: AP_RETRY_LIMIT failed for vap_index:%d res:%d\n",
            __func__, __LINE__, retry_vap_index, res);
    } else {
        wifi_hal_info_print("%s:%d: AP_RETRY_LIMIT set successfully vap_index:%d value:%d\n",
            __func__, __LINE__, retry_vap_index, RETRY_LIMIT);
    }

    return 0;
}
int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}

int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
    return RETURN_OK;
}

static int qca_add_intf_to_bridge(wifi_interface_info_t *interface, bool is_mld)
{
    return RETURN_OK;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    #define MAX_INTERFACE_IDX 30
    wifi_radio_info_t *radio = NULL;
    wifi_interface_info_t *interface = NULL;
    int existing_vap_indices = 0;
    int i;

    wifi_hal_dbg_print("%s:%d Enter\n",__func__,__LINE__);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if(!radio->configured)
    {
        wifi_hal_info_print("%s:%d: Radio is getting configured for the first time.\n", __func__, __LINE__);
        return RETURN_OK;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_OK;
    }

    while (interface != NULL) {
        if(interface->vap_info.vap_index >= 0) {
            existing_vap_indices |= 1<<interface->vap_info.vap_index;
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    for(i=0; i < MAX_INTERFACE_IDX; i++)
    {
        if(!(existing_vap_indices & 1<<i))
        {
            continue;
        }
        if ((interface = get_interface_by_vap_index(i)) == NULL)
        {
            wifi_hal_error_print("%s:%d: vap index:%d Interface should be created first to get the MLD addr\n",
                                __func__, __LINE__, i);
            continue;
        }
        if (radio->oper_param.variant & WIFI_80211_VARIANT_BE && !(operationParam->variant & WIFI_80211_VARIANT_BE)) {
            // Moving from 11BE to non 11BE mode
            wifi_hal_info_print("%s:%d: 11BE mode is disabled. Remove mld from the bridge. [%d -> %d]\n",
                __func__, __LINE__, radio->oper_param.variant, operationParam->variant);
            if (qca_add_intf_to_bridge(interface, false) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: Failed to add vap idx %d to bridge.\n",
                    __func__, __LINE__, i);
                continue;
            }
        } else if (operationParam->variant & WIFI_80211_VARIANT_BE && !(radio->oper_param.variant & WIFI_80211_VARIANT_BE)) {
            // Moving from non 11BE to 11BE mode
            wifi_hal_info_print("%s:%d: 11BE mode is enabled. Add mld to the bridge. [%d -> %d]\n",
                __func__, __LINE__, radio->oper_param.variant, operationParam->variant);
            if (qca_add_intf_to_bridge(interface, true) != RETURN_OK) {
                wifi_hal_error_print("%s:%d: Failed to add vap idx %d to bridge.\n",
                    __func__, __LINE__, i);
                continue;
            }
        } else {
            wifi_hal_dbg_print("%s:%d: Vap addition to bridge is not required!\n", __func__, __LINE__);
            return 0;
        }
    }
    wifi_hal_dbg_print("%s:%d Exit\n",__func__,__LINE__);
    return 0;
}


INT platform_set_intf_mld_bonding(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    return RETURN_OK;
}

INT platform_set_radio_mld_bonding(wifi_radio_info_t *radio)
{
    return RETURN_OK;
}

INT platform_create_interface_attributes(struct nl_msg **msg_ptr, wifi_radio_info_t *radio, wifi_vap_info_t *vap)
{

    return RETURN_OK;
}

/**
 * @brief Platform-specific stub functions for QCA IPQ platform
 * 
 * These are dummy implementations that return success (0) for compilation.
 * Replace with actual platform-specific implementations as needed.
 */

int platform_pre_init()
 {
     wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
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

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) {
        size_t len;
        const u8 *pos;

        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);

        if (len > sizeof(eht_capab->mac_cap)) {
            len = sizeof(eht_capab->mac_cap);
        }
        pos = (nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]));
        eht_capab->mac_cap = WPA_GET_LE16(pos);
    }
}
static struct hostapd_mld *find_mld(wifi_interface_info_t *interface)
{
    wifi_mld_unit_t *mld_it = NULL;

    dl_list_for_each(mld_it, &g_wifi_hal.mld_array.mld_unit, wifi_mld_unit_t, mld_unit) {
        if (strncmp(interface->mld_name, mld_it->mld->name, sizeof(mld_it->mld->name)) == 0) {
            return mld_it->mld;
        }
    }
    return NULL;
}

static bool wifi_hal_is_mld_link_exists(struct hostapd_data *hapd)
{
    struct hostapd_data *link_bss;

    if (hapd->mld == NULL) {
        return false;
    }

    wpa_printf(MSG_DEBUG,"%s:%d link %d in MLD %s\n", __func__, __LINE__, hapd->mld_link_id,
            hapd->conf->iface);
    dl_list_for_each(link_bss, &hapd->mld->links, struct hostapd_data, link) {
        if (link_bss == hapd) {
            wpa_printf(MSG_DEBUG,"%s:%d TRUE link %d in MLD %s\n", __func__, __LINE__, hapd->mld_link_id,
                    hapd->conf->iface);
            return true;
        }
    }
    wpa_printf(MSG_DEBUG,"%s:%d FALSE  link %d in MLD %s\n", __func__, __LINE__, hapd->mld_link_id,
            hapd->conf->iface);
    return false;
}

static int alloc_mld(wifi_interface_info_t *interface)
{
    struct hostapd_mld *mld;
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    wifi_mld_unit_t *mld_unit = NULL;

    if (g_wifi_hal.mld_array.mld_count == 0) {
        dl_list_init(&g_wifi_hal.mld_array.mld_unit);
    } else {
        mld = find_mld(interface);
        if (mld) {
            wpa_printf(MSG_DEBUG, "%s:%d hapd->mld was found for interface %s\n",
                __func__, __LINE__, interface->name);
            hapd->mld = mld;
            mld->refcount++;
            return 0;
        }
    }

    mld_unit = calloc(1, sizeof(wifi_mld_unit_t));
    if (mld_unit == NULL) {
        wpa_printf(MSG_DEBUG, "%s:%d: Failed to allocate memory for wifi_mld_unit_t\n",
            __func__, __LINE__);
        return -1;
    }
    dl_list_init(&mld_unit->mld_unit);

    mld = calloc(1, sizeof(struct hostapd_mld));
    if (mld == NULL) {
        wpa_printf(MSG_DEBUG, "%s:%d: Failed to allocate memory for hostapd_mld %s\n",
            __func__, __LINE__, interface->mld_name);
        free(mld_unit);
        return -1;
    }

    mld_unit->mld = mld;
    dl_list_add_tail(&g_wifi_hal.mld_array.mld_unit, &mld_unit->mld_unit);

    strlcpy(mld->name, interface->mld_name, sizeof(mld->name) - 1);
    dl_list_init(&mld->links);
#ifdef QCA_UD_HOSTAPD
    dl_list_init(&mld->ft_ds_ml_stas);
#endif /* QCA_UD_HOSTAPD */
    mld->ctrl_sock = -1;
    memcpy(mld->mld_addr, wifi_hal_get_mld_mac_address(interface), ETH_ALEN);
    mld->refcount++;

    hapd->mld = mld;
    g_wifi_hal.mld_array.mld_count++;

    return 0;
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
    wpa_printf(MSG_DEBUG,"%s:%d \n",  __func__, __LINE__);
#if (HOSTAPD_VERSION >= 211)
    struct hostapd_bss_config *conf;
    struct hostapd_data *hapd, *first_link;
    struct hostapd_data *links_to_add[2];
    int num_links = 0, i;

    if (interface->u.ap.conf.disable_11be) {
        return 0;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return 0;
    }

    hapd = &interface->u.ap.hapd;
    conf = hapd->conf;

    conf->mld_ap = 1;
    conf->okc = 1;
    hapd->mld_link_id = wifi_hal_get_mld_link_id(interface);

    wpa_printf(MSG_DEBUG,"%s:%d hapd->mld_link_id:%d \n",  __func__, __LINE__,hapd->mld_link_id);

    if (hapd->mld == NULL) {
        if (alloc_mld(interface) < 0) {
            wpa_printf(MSG_DEBUG,"%s:%d Failed to obtain hostapd_mld for MLD interface %s\n",
                __func__, __LINE__, interface->mld_name);
            return -1;
        }
    }

    wpa_printf(MSG_DEBUG,"%s:%d add link %d in MLD %s\n", __func__, __LINE__, hapd->mld_link_id,
            hapd->conf->iface);
    if (!wifi_hal_is_mld_link_exists(hapd) && hostapd_mld_add_link(hapd) != 0) {
        wpa_printf(MSG_DEBUG,"%s:%d Failed to add link %d in MLD %s\n", __func__, __LINE__, hapd->mld_link_id,
            hapd->conf->iface);
        return -1;
    }
    /* Always add the first link; if hapd is a different link, add it too */
    first_link = hostapd_mld_is_first_bss(hapd) ? hapd : hostapd_mld_get_first_bss(hapd);
    links_to_add[num_links++] = first_link;
    if (first_link != hapd)
        links_to_add[num_links++] = hapd;

    for (i = 0; i < num_links; i++) {
        struct hostapd_data *h = links_to_add[i];

        wpa_printf(MSG_DEBUG,
                   "%s:%d mld_link_id:%d ADD Link\n",
                   __func__, __LINE__, h->mld_link_id);

        if (hostapd_drv_link_add(h, h->mld_link_id, h->own_addr)) {
            wpa_printf(MSG_DEBUG,
                       "%s:%d Failed to add link %d in MLD %s\n",
                       __func__, __LINE__,
                       h->mld_link_id, h->conf->iface);
            return -1;
        }
    }
#endif
    return 0;
}
#endif /* CONFIG_IEEE80211BE */


int wifi_getApInterworkingElement(int apIndex, wifi_InterworkingElement_t *output_struct)
{
        return RETURN_ERR;
}

int wifi_enableCSIEngine(int apIndex, mac_address_t sta, BOOL enable)
{
        return RETURN_ERR;
}

int wifi_setRadioDfsAtBootUpEnable(int radioIndex, unsigned char enabled)
{
        return RETURN_ERR;
}

int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}

int wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode, int vap_index)
{
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index, wifi_channelBandwidth_t *channelWidth)
{
    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    return 0;
}

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    return 0;
}

int wifi_wnm_send_bss_tm_req(struct wifi_interface_info_t *interface, struct sta_info *sta,
     u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int, const u8 *bss_term_dur,
     const char *url, const u8 *nei_rep, size_t nei_rep_len, const u8 *mbo_attrs, size_t mbo_len)
{
        return 0;
}


/* Helper: dump hostapd's internal accept_mac / deny_mac list */
static void dump_acl_list(const char *caller, int apIndex,
                           struct hostapd_bss_config *conf)
{
    int i;
    char mac_str[18];

    wifi_hal_dbg_print("%s: apIndex=%d macaddr_acl=%d"
        " (0=ACCEPT_UNLESS_DENIED 1=DENY_UNLESS_ACCEPTED)"
        " accept_mac_count=%d deny_mac_count=%d\n",
        caller, apIndex, conf->macaddr_acl,
        conf->num_accept_mac, conf->num_deny_mac);

    for (i = 0; i < conf->num_accept_mac; i++) {
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            conf->accept_mac[i].addr[0], conf->accept_mac[i].addr[1],
            conf->accept_mac[i].addr[2], conf->accept_mac[i].addr[3],
            conf->accept_mac[i].addr[4], conf->accept_mac[i].addr[5]);
        wifi_hal_dbg_print("%s:   accept_mac[%d] = %s\n", caller, i, mac_str);
    }
    for (i = 0; i < conf->num_deny_mac; i++) {
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            conf->deny_mac[i].addr[0], conf->deny_mac[i].addr[1],
            conf->deny_mac[i].addr[2], conf->deny_mac[i].addr[3],
            conf->deny_mac[i].addr[4], conf->deny_mac[i].addr[5]);
        wifi_hal_dbg_print("%s:   deny_mac[%d]   = %s\n", caller, i, mac_str);
    }
}

INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map;
    struct hostapd_bss_config *conf;
    mac_address_t mac_addr;

    if (DeviceMacAddress == NULL) {
        wifi_hal_error_print("%s:%d: NULL DeviceMacAddress for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Interface:%s MAC:%s\n",
        __func__, __LINE__, interface->name, DeviceMacAddress);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to add MAC ACL for STA device\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    /* --- Update interface->acl_map --- */
    if (interface->acl_map == NULL) {
        interface->acl_map = hash_map_create();
        if (interface->acl_map == NULL) {
            wifi_hal_error_print("%s:%d: ACL map create failure for apIndex:%d\n",
                __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
    }

    acl_map = hash_map_get(interface->acl_map, DeviceMacAddress);
    if (acl_map != NULL) {
        wifi_hal_dbg_print("%s:%d: MAC %s already present in acl_map for apIndex:%d\n",
            __func__, __LINE__, DeviceMacAddress, apIndex);
        /* Still sync to hostapd in case it was lost */
    } else {
        acl_map = (acl_map_t *)malloc(sizeof(acl_map_t));
        if (acl_map == NULL) {
            wifi_hal_error_print("%s:%d: malloc failed for apIndex:%d\n",
                __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
        memcpy(acl_map->mac_addr_str, DeviceMacAddress, sizeof(mac_addr_str_t));
        to_mac_bytes(acl_map->mac_addr_str, acl_map->mac_addr);
        hash_map_put(interface->acl_map, strdup(DeviceMacAddress), acl_map);
    }

    /* --- Sync to hostapd's internal ACL list ---
     * hostapd_add_acl_maclist() does NOT check for duplicates — guard with
     * hostapd_maclist_found() first. */
    to_mac_bytes(DeviceMacAddress, mac_addr);
    conf = interface->u.ap.hapd.conf;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
        if (!hostapd_maclist_found(conf->accept_mac, conf->num_accept_mac, mac_addr, NULL)) {
            hostapd_add_acl_maclist(&conf->accept_mac, &conf->num_accept_mac, 0, mac_addr);
            /* Keep list sorted so hostapd_maclist_found() binary search works */
            if (conf->accept_mac)
                qsort(conf->accept_mac, conf->num_accept_mac,
                      sizeof(*conf->accept_mac), hostapd_acl_comp);
        } else {
            wifi_hal_dbg_print("%s:%d: MAC %s already in accept_mac for apIndex:%d\n",
                __func__, __LINE__, DeviceMacAddress, apIndex);
        }
    } else {
        if (!hostapd_maclist_found(conf->deny_mac, conf->num_deny_mac, mac_addr, NULL)) {
            hostapd_add_acl_maclist(&conf->deny_mac, &conf->num_deny_mac, 0, mac_addr);
            /* Keep list sorted so hostapd_maclist_found() binary search works */
            if (conf->deny_mac)
                qsort(conf->deny_mac, conf->num_deny_mac,
                      sizeof(*conf->deny_mac), hostapd_acl_comp);
        } else {
            wifi_hal_dbg_print("%s:%d: MAC %s already in deny_mac for apIndex:%d\n",
                __func__, __LINE__, DeviceMacAddress, apIndex);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    /* For blacklist mode: if the STA is currently connected, tear it down
     * through hostapd's ap_free_sta() so that WDS STA interfaces (wlanX.staY)
     * are also removed via wifi_drv_set_wds_sta(val=0).
     * nl80211_kick_device() only sends NL80211_CMD_DEL_STATION to the kernel
     * and bypasses the hostapd cleanup path, leaving stale WDS interfaces. */
    if (vap->u.bss_info.mac_filter_enable &&
        vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
        struct sta_info *sta;
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        sta = ap_get_sta(&interface->u.ap.hapd, mac_addr);
        if (sta != NULL) {
            wifi_hal_info_print("%s:%d: blacklisted STA %s still connected on %s"
                " — freeing via ap_free_sta() to clean up WDS interface\n",
                __func__, __LINE__, DeviceMacAddress, interface->name);
            ap_free_sta(&interface->u.ap.hapd, sta);
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        /* Also send a deauth so the STA knows it has been disconnected */
        if (nl80211_kick_device(interface, mac_addr) != 0) {
            wifi_hal_dbg_print("%s:%d: nl80211_kick_device failed for %s on apIndex:%d"
                " (STA may not be connected)\n",
                __func__, __LINE__, DeviceMacAddress, apIndex);
        }
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    dump_acl_list(__func__, apIndex, interface->u.ap.hapd.conf);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}

INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map;
    mac_address_t mac_addr;

    if (DeviceMacAddress == NULL) {
        wifi_hal_error_print("%s:%d: NULL DeviceMacAddress for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Interface:%s MAC:%s\n",
        __func__, __LINE__, interface->name, DeviceMacAddress);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: Not possible to del MAC ACL for STA device\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL map is NULL for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    acl_map = hash_map_get(interface->acl_map, DeviceMacAddress);
    if (acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: MAC %s not present in acl_map for apIndex:%d\n",
            __func__, __LINE__, DeviceMacAddress, apIndex);
        return RETURN_OK;
    }

    /* Sync removal from hostapd BEFORE freeing the acl_map entry */
    to_mac_bytes(DeviceMacAddress, mac_addr);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
        hostapd_remove_acl_mac(&interface->u.ap.hapd.conf->accept_mac,
                               &interface->u.ap.hapd.conf->num_accept_mac,
                               mac_addr);
    } else {
        hostapd_remove_acl_mac(&interface->u.ap.hapd.conf->deny_mac,
                               &interface->u.ap.hapd.conf->num_deny_mac,
                               mac_addr);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    /* Remove from acl_map and free */
    hash_map_remove(interface->acl_map, DeviceMacAddress);
    free(acl_map);

    /* For whitelist mode: if the STA is currently connected, kick it since
     * it has been removed from the whitelist and is no longer allowed. */
    if (vap->u.bss_info.mac_filter_enable &&
        vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
        struct sta_info *sta;
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        sta = ap_get_sta(&interface->u.ap.hapd, mac_addr);
        if (sta != NULL) {
            wifi_hal_info_print("%s:%d: removed-from-whitelist STA %s still connected on %s"
                " — freeing via ap_free_sta()\n",
                __func__, __LINE__, DeviceMacAddress, interface->name);
            ap_free_sta(&interface->u.ap.hapd, sta);
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        if (nl80211_kick_device(interface, mac_addr) != 0) {
            wifi_hal_dbg_print("%s:%d: nl80211_kick_device failed for %s on apIndex:%d"
                " (STA may not be connected)\n",
                __func__, __LINE__, DeviceMacAddress, apIndex);
        }
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    dump_acl_list(__func__, apIndex, interface->u.ap.hapd.conf);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}

INT wifi_delApAclDevices(INT apIndex)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    acl_map_t *acl_map, *temp_acl_map;
    mac_addr_str_t mac_str;
    mac_address_t mac_addr;
    /* For whitelist kick: pre-collect MAC addresses before the removal loop */
    mac_address_t *kick_macs = NULL;
    int kick_count = 0;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    wifi_hal_dbg_print("%s:%d: Interface:%s\n", __func__, __LINE__, interface->name);

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_dbg_print("%s:%d: Not possible to del MAC ACL for STA device\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    if (interface->acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL map is NULL for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    acl_map = hash_map_get_first(interface->acl_map);
    if (acl_map == NULL) {
        wifi_hal_dbg_print("%s:%d: ACL list is empty for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_OK;
    }

    /* For whitelist mode: pre-collect all MAC addresses so we can kick
     * connected STAs after the removal loop (acl_map entries are freed
     * inside the loop so we cannot iterate them again afterwards). */
    if (vap->u.bss_info.mac_filter_enable &&
        vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
        int total = hash_map_count(interface->acl_map);
        if (total > 0) {
            kick_macs = malloc(total * sizeof(mac_address_t));
            if (kick_macs) {
                acl_map_t *tmp = hash_map_get_first(interface->acl_map);
                while (tmp != NULL) {
                    memcpy(kick_macs[kick_count], tmp->mac_addr, sizeof(mac_address_t));
                    kick_count++;
                    tmp = hash_map_get_next(interface->acl_map, tmp);
                }
            }
        }
    }

    /* Sync removal from hostapd and clear acl_map */
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    while (acl_map != NULL) {
        memcpy(&mac_str, &acl_map->mac_addr_str, sizeof(mac_addr_str_t));
        memcpy(mac_addr, acl_map->mac_addr, sizeof(mac_address_t));
        acl_map = hash_map_get_next(interface->acl_map, acl_map);

        if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
            hostapd_remove_acl_mac(&interface->u.ap.hapd.conf->accept_mac,
                                   &interface->u.ap.hapd.conf->num_accept_mac,
                                   mac_addr);
        } else {
            hostapd_remove_acl_mac(&interface->u.ap.hapd.conf->deny_mac,
                                   &interface->u.ap.hapd.conf->num_deny_mac,
                                   mac_addr);
        }

        temp_acl_map = hash_map_remove(interface->acl_map, mac_str);
        if (temp_acl_map != NULL)
            free(temp_acl_map);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    /* For whitelist mode: kick all STAs that were in the whitelist and are
     * still connected, since they are no longer allowed. */
    if (kick_macs) {
        int i;
        for (i = 0; i < kick_count; i++) {
            struct sta_info *sta;
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            sta = ap_get_sta(&interface->u.ap.hapd, kick_macs[i]);
            if (sta != NULL) {
                wifi_hal_info_print("%s:%d: removed-from-whitelist STA still connected on %s"
                    " — freeing via ap_free_sta()\n",
                    __func__, __LINE__, interface->name);
                ap_free_sta(&interface->u.ap.hapd, sta);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
            if (nl80211_kick_device(interface, kick_macs[i]) != 0) {
                wifi_hal_dbg_print("%s:%d: nl80211_kick_device failed for entry %d on apIndex:%d"
                    " (STA may not be connected)\n",
                    __func__, __LINE__, i, apIndex);
            }
        }
        free(kick_macs);
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    dump_acl_list(__func__, apIndex, interface->u.ap.hapd.conf);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}

INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    struct hostapd_bss_config *conf;
    acl_map_t *entry;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    vap = &interface->vap_info;

    if (vap->vap_mode != wifi_vap_mode_ap) {
        wifi_hal_error_print("%s:%d: not AP mode for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    if (vap->u.bss_info.enabled != true) {
        /*
         * Return success to prevent early exit of wifi_hal_createVAP */
        wifi_hal_error_print("%s:%d: bss not enabled:%d for apIndex:%d\n",
            __func__, __LINE__, vap->u.bss_info.enabled, apIndex);
        return RETURN_OK;
    }

    /* Update vap filter mode */
    switch (filterMode) {
    case 2:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;
        break;
    case 1:
        vap->u.bss_info.mac_filter_enable = true;
        vap->u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        break;
    case 0:
        vap->u.bss_info.mac_filter_enable = false;
        break;
    default:
        wifi_hal_error_print("%s:%d: Wrong Mac mode %d for apIndex:%d\n",
            __func__, __LINE__, filterMode, apIndex);
        return RETURN_ERR;
    }

    /* Sync macaddr_acl policy and rebuild hostapd's internal MAC lists
     * from interface->acl_map so hostapd_check_acl() returns the correct
     * result in process_frame_mgmt(). */
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    conf = interface->u.ap.hapd.conf;

    /* Clear both lists */
    while (conf->num_accept_mac > 0)
        hostapd_remove_acl_mac(&conf->accept_mac, &conf->num_accept_mac,
                               conf->accept_mac[0].addr);
    while (conf->num_deny_mac > 0)
        hostapd_remove_acl_mac(&conf->deny_mac, &conf->num_deny_mac,
                               conf->deny_mac[0].addr);

    /* Set macaddr_acl policy */
    if (vap->u.bss_info.mac_filter_enable) {
        conf->macaddr_acl =
            (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list)
            ? DENY_UNLESS_ACCEPTED : ACCEPT_UNLESS_DENIED;
    } else {
        conf->macaddr_acl = ACCEPT_UNLESS_DENIED;
    }

    /* Rebuild the appropriate list from interface->acl_map */
    if (vap->u.bss_info.mac_filter_enable && interface->acl_map != NULL) {
        entry = hash_map_get_first(interface->acl_map);
        while (entry != NULL) {
            if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                hostapd_add_acl_maclist(&conf->accept_mac, &conf->num_accept_mac,
                                       0, entry->mac_addr);
            } else {
                hostapd_add_acl_maclist(&conf->deny_mac, &conf->num_deny_mac,
                                       0, entry->mac_addr);
            }
            entry = hash_map_get_next(interface->acl_map, entry);
        }
        /* Sort once after all entries are added */
        if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
            if (conf->accept_mac)
                qsort(conf->accept_mac, conf->num_accept_mac,
                      sizeof(*conf->accept_mac), hostapd_acl_comp);
        } else {
            if (conf->deny_mac)
                qsort(conf->deny_mac, conf->num_deny_mac,
                      sizeof(*conf->deny_mac), hostapd_acl_comp);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    dump_acl_list(__func__, apIndex, interface->u.ap.hapd.conf);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return RETURN_OK;
}

INT wifi_getApAclDeviceNum(INT apIndex, UINT *aclCount)
{
    wifi_interface_info_t *interface;

    if (aclCount == NULL) {
        wifi_hal_error_print("%s:%d: NULL aclCount for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
            __func__, __LINE__, apIndex);
        *aclCount = 0;
        return RETURN_ERR;
    }

    *aclCount = (interface->acl_map != NULL) ? hash_map_count(interface->acl_map) : 0;

    wifi_hal_dbg_print("%s:%d: apIndex:%d acl_count:%u\n",
        __func__, __LINE__, apIndex, *aclCount);
    return RETURN_OK;
}

INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode,
    INT dwell_time, UINT chan_num, UINT *chan_list)
{
    int   ret                        = 0;

    wifi_hal_dbg_print("%s:%d: apIndex=%d scan_mode=%d dwell_time=%d chan_num=%u\n",
        __func__, __LINE__, apIndex, scan_mode, dwell_time, chan_num);

    if (chan_list == NULL && chan_num > 0) {
        wifi_hal_error_print("%s:%d: chan_list is NULL but chan_num=%u\n",
            __func__, __LINE__, chan_num);
        return RETURN_ERR;
    }

    ret = wifi_hal_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list);
    if (ret != RETURN_OK) {
        wifi_hal_error_print("%s:%d: wifi_hal_startNeighborScan failed for AP %d (ret=%d)\n",
            __func__, __LINE__, apIndex, ret);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: Neighbor scan started on AP %d\n",
        __func__, __LINE__, apIndex);
    return RETURN_OK;
}

INT wifi_getNeighboringWiFiStatus(INT radioIndex,
    wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size)
{
    int ret = 0;

    wifi_hal_dbg_print("%s:%d: radioIndex=%d\n", __func__, __LINE__, radioIndex);

    if (!neighbor_ap_array || !output_array_size) {
        wifi_hal_error_print("%s:%d: Invalid NULL arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    *neighbor_ap_array  = NULL;
    *output_array_size  = 0;

    ret = wifi_hal_getNeighboringWiFiStatus(radioIndex, neighbor_ap_array, output_array_size);
    if (ret != RETURN_OK) {
        wifi_hal_error_print("%s:%d: wifi_hal_getNeighboringWiFiStatus failed for radio %d (ret=%d)\n",
            __func__, __LINE__, radioIndex, ret);
        return ret;
    }

    wifi_hal_dbg_print("%s:%d: Found %u neighboring APs for radio %d\n",
        __func__, __LINE__, *output_array_size, radioIndex);

    return RETURN_OK;
}

#define MCUC_CMD_MAX_LEN 256

static INT mcuc_exec_wlanconfig(INT apIndex, const char *list_cmd,
        const char *op_cmd, const char *ip_addr,
        const char *mask)
{
    char cmd[MCUC_CMD_MAX_LEN];
    char interface_name[32];
    int ret;
    wifi_interface_info_t *interface;
    int link_id = -1;
    bool is_mlo = false;

    if (get_interface_name_from_vap_index(apIndex, interface_name) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Failed to get interface name for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface != NULL && interface->mld_name[0] != '\0') {
        is_mlo = true;
        link_id = wifi_hal_get_mld_link_id(interface);
        wifi_hal_info_print("%s:%d: MLO interface: mld_name=%s link_id=%d apIndex=%d\n",
            __func__, __LINE__, interface->mld_name, link_id, apIndex);
    }

    if (strcmp(op_cmd, "dump") == 0) {
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "wlanconfig %s link_id %d %s dump",
                    interface->mld_name, link_id, list_cmd);
        } else {
            snprintf(cmd, sizeof(cmd), "wlanconfig %s %s dump",
                    interface_name, list_cmd);
        }
    } else {
        if (ip_addr == NULL || mask == NULL) {
            wifi_hal_error_print("%s:%d: ip_addr or mask is NULL for apIndex:%d\n",
                    __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "wlanconfig %s link_id %d %s %s %s %s",
                    interface->mld_name, link_id, list_cmd, op_cmd, ip_addr, mask);
        } else {
            snprintf(cmd, sizeof(cmd), "wlanconfig %s %s %s %s %s",
                    interface_name, list_cmd, op_cmd, ip_addr, mask);
        }
    }

    wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);

    ret = system(cmd);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Command failed (ret=%d): %s\n",
                __func__, __LINE__, ret, cmd);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_addMulticastHMMCIPv4Entry(INT apIndex, const char *ip_addr, const char *mask)
{
    if (ip_addr == NULL || mask == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s mask:%s\n",
            __func__, __LINE__, apIndex, ip_addr, mask);
    return mcuc_exec_wlanconfig(apIndex, "hmmc", "add", ip_addr, mask);
}

INT wifi_delMulticastHMMCIPv4Entry(INT apIndex, const char *ip_addr, const char *mask)
{
    if (ip_addr == NULL || mask == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s mask:%s\n",
            __func__, __LINE__, apIndex, ip_addr, mask);
    return mcuc_exec_wlanconfig(apIndex, "hmmc", "del", ip_addr, mask);
}

INT wifi_dumpMulticastHMMCIPv4Entries(INT apIndex)
{
    wifi_hal_info_print("%s:%d: apIndex:%d\n", __func__, __LINE__, apIndex);
    return mcuc_exec_wlanconfig(apIndex, "hmmc", "dump", NULL, NULL);
}

INT wifi_addMulticastHMMCIPv6Entry(INT apIndex, const char *ip_addr, const char *prefix_len)
{
    if (ip_addr == NULL || prefix_len == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s prefix:%s\n",
            __func__, __LINE__, apIndex, ip_addr, prefix_len);
    return mcuc_exec_wlanconfig(apIndex, "hmmc_v6", "add", ip_addr, prefix_len);
}

INT wifi_delMulticastHMMCIPv6Entry(INT apIndex, const char *ip_addr, const char *prefix_len)
{
    if (ip_addr == NULL || prefix_len == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s prefix:%s\n",
            __func__, __LINE__, apIndex, ip_addr, prefix_len);
    return mcuc_exec_wlanconfig(apIndex, "hmmc_v6", "del", ip_addr, prefix_len);
}

INT wifi_dumpMulticastHMMCIPv6Entries(INT apIndex)
{
    wifi_hal_info_print("%s:%d: apIndex:%d\n", __func__, __LINE__, apIndex);
    return mcuc_exec_wlanconfig(apIndex, "hmmc_v6", "dump", NULL, NULL);
}

INT wifi_addMulticastDenyListIPv4Entry(INT apIndex, const char *ip_addr, const char *mask)
{
    if (ip_addr == NULL || mask == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s mask:%s\n",
            __func__, __LINE__, apIndex, ip_addr, mask);
    return mcuc_exec_wlanconfig(apIndex, "deny_list", "add", ip_addr, mask);
}

INT wifi_delMulticastDenyListIPv4Entry(INT apIndex, const char *ip_addr, const char *mask)
{
    if (ip_addr == NULL || mask == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s mask:%s\n",
            __func__, __LINE__, apIndex, ip_addr, mask);
    return mcuc_exec_wlanconfig(apIndex, "deny_list", "del", ip_addr, mask);
}

INT wifi_dumpMulticastDenyListIPv4Entries(INT apIndex)
{
    wifi_hal_info_print("%s:%d: apIndex:%d\n", __func__, __LINE__, apIndex);
    return mcuc_exec_wlanconfig(apIndex, "deny_list", "dump", NULL, NULL);
}

INT wifi_addMulticastDenyListIPv6Entry(INT apIndex, const char *ip_addr, const char *prefix_len)
{
    if (ip_addr == NULL || prefix_len == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s prefix:%s\n",
            __func__, __LINE__, apIndex, ip_addr, prefix_len);
    return mcuc_exec_wlanconfig(apIndex, "deny_list_v6", "add", ip_addr, prefix_len);
}

INT wifi_delMulticastDenyListIPv6Entry(INT apIndex, const char *ip_addr, const char *prefix_len)
{
    if (ip_addr == NULL || prefix_len == NULL) {
        wifi_hal_error_print("%s:%d: NULL parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d: apIndex:%d ip:%s prefix:%s\n",
            __func__, __LINE__, apIndex, ip_addr, prefix_len);
    return mcuc_exec_wlanconfig(apIndex, "deny_list_v6", "del", ip_addr, prefix_len);
}

INT wifi_dumpMulticastDenyListIPv6Entries(INT apIndex)
{
    wifi_hal_info_print("%s:%d: apIndex:%d\n", __func__, __LINE__, apIndex);
    return mcuc_exec_wlanconfig(apIndex, "deny_list_v6", "dump", NULL, NULL);
}

INT wifi_setMulticastEnhanceMode(INT apIndex, INT mode)
{
    char cmd[MCUC_CMD_MAX_LEN];
    char interface_name[32];
    int ret;
    wifi_interface_info_t *interface;
    int link_id = -1;
    bool is_mlo = false;

    if (mode != 0 && mode != 5 && mode != 6) {
        wifi_hal_error_print("%s:%d: Invalid mcastenhance mode:%d (valid: 0, 5, 6)\n",
                __func__, __LINE__, mode);
        return RETURN_ERR;
    }

    if (get_interface_name_from_vap_index(apIndex, interface_name) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Failed to get interface name for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface != NULL && interface->mld_name[0] != '\0') {
        is_mlo = true;
        link_id = wifi_hal_get_mld_link_id(interface);
        wifi_hal_info_print("%s:%d: MLO mcastenhance: mld_name=%s link_id=%d mode=%d\n",
                __func__, __LINE__, interface->mld_name, link_id, mode);
    }

    if (is_mlo) {
        snprintf(cmd, sizeof(cmd), "wlanconfig %s link_id %d mcastenhance %d",
                interface->mld_name, link_id, mode);
    } else {
        snprintf(cmd, sizeof(cmd), "wlanconfig %s mcastenhance %d",
                interface_name, mode);
    }

    wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
    ret = system(cmd);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Command failed (ret=%d): %s\n",
                __func__, __LINE__, ret, cmd);
        return RETURN_ERR;
    }

    if (mode != 0) {
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload on",
                    interface->mld_name);
        } else {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload on",
                    interface_name);
        }
        wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
        ret = system(cmd);
        if (ret != 0) {
            wifi_hal_error_print("%s:%d: bridge mcast_mcuc_hw_offload on failed (ret=%d): %s\n",
                    __func__, __LINE__, ret, cmd);
        }
    } else {
        /* Disabling ME: restore bridge-level mcast_to_unicast and disable hw offload */
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload off",
                    interface->mld_name);
        } else {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload off",
                    interface_name);
        }
        wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
        ret = system(cmd);
        if (ret != 0) {
            wifi_hal_error_print("%s:%d: bridge mcast_mcuc_hw_offload off failed (ret=%d): %s\n",
                    __func__, __LINE__, ret, cmd);
        }
    }

    return RETURN_OK;
}

INT wifi_setIGMPMulticastEnable(INT apIndex, INT enable)
{
    char cmd[MCUC_CMD_MAX_LEN];
    char interface_name[32];
    int ret;
    wifi_interface_info_t *interface;
    int link_id = -1;
    bool is_mlo = false;

    if (enable != 0 && enable != 1) {
        wifi_hal_error_print("%s:%d: Invalid igmpmcasten value:%d (valid: 0 or 1)\n",
                __func__, __LINE__, enable);
        return RETURN_ERR;
    }

    if (get_interface_name_from_vap_index(apIndex, interface_name) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Failed to get interface name for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index(apIndex);
    if (interface != NULL && interface->mld_name[0] != '\0') {
        is_mlo = true;
        link_id = wifi_hal_get_mld_link_id(interface);
        wifi_hal_info_print("%s:%d: MLO igmpmcasten: mld_name=%s link_id=%d enable=%d\n",
            __func__, __LINE__, interface->mld_name, link_id, enable);
    }

    if (is_mlo) {
        snprintf(cmd, sizeof(cmd), "wlanconfig %s link_id %d igmpmcasten %d",
            interface->mld_name, link_id, enable);
    } else {
        snprintf(cmd, sizeof(cmd), "wlanconfig %s igmpmcasten %d",
             interface_name, enable);
    }
    wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
    ret = system(cmd);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Command failed (ret=%d): %s\n",
                __func__, __LINE__, ret, cmd);
        return RETURN_ERR;
    }

    if (enable) {
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload on",
                    interface->mld_name);
        } else {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload on",
                    interface_name);
        }
        wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
        ret = system(cmd);
        if (ret != 0) {
            wifi_hal_error_print("%s:%d: bridge mcast_mcuc_hw_offload on failed (ret=%d): %s\n",
                    __func__, __LINE__, ret, cmd);
        }
    } else {
        /* Disabling IGMP MCUC: restore bridge settings */
        if (is_mlo) {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload off",
                    interface->mld_name);
        } else {
            snprintf(cmd, sizeof(cmd), "bridge link set dev %s mcast_mcuc_hw_offload off",
                    interface_name);
        }

        wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);
        ret = system(cmd);
        if (ret != 0) {
            wifi_hal_error_print("%s:%d: bridge mcast_mcuc_hw_offload off failed (ret=%d): %s\n",
                    __func__, __LINE__, ret, cmd);
        }
    }

    return RETURN_OK;
}


static int get_ip_from_dnsmasq_leases(const mac_address_t mac, char *ip_str, size_t ip_str_len)
{
    FILE *fp;
    char line[512];
    char mac_str[18];
    char lease_mac[18];
    char lease_ip[46];  /* IPv4 or IPv6 */
    int found = 0;

    if (ip_str == NULL || ip_str_len == 0) {
        return -1;
    }

    /* Format MAC address for comparison (lowercase with colons) */
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    fp = fopen("/nvram/dnsmasq.leases", "r");
    if (fp == NULL) {
        wifi_hal_dbg_print("%s:%d Failed to open /nvram/dnsmasq.leases\n", __func__, __LINE__);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Parse: <expiry> <mac> <ip> <hostname> ... */
        if (sscanf(line, "%*s %17s %45s", lease_mac, lease_ip) == 2) {
            /* Compare MAC addresses (case-insensitive) */
            if (strcasecmp(lease_mac, mac_str) == 0) {
                strlcpy(ip_str, lease_ip, ip_str_len - 1);
                ip_str[ip_str_len - 1] = '\0';
                found = 1;
                wifi_hal_dbg_print("%s:%d Found IP %s for MAC %s in dnsmasq.leases\n",
                        __func__, __LINE__, ip_str, mac_str);
                break;
            }
        }
    }

    fclose(fp);

    if (!found) {
        wifi_hal_dbg_print("%s:%d MAC %s not found in dnsmasq.leases\n",
                __func__, __LINE__, mac_str);
        return -1;
    }

    return 0;
}

/**
 * nl80211_sta_data_handler - NL80211 callback for GET_STATION response
 * 
 * Parses NL80211_CMD_GET_STATION response to extract:
 * - signal: Current RSSI (NL80211_STA_INFO_SIGNAL)
 * - mgmt_signal: Management frame RSSI (NL80211_STA_INFO_SIGNAL_AVG)
 */
static int nl80211_sta_data_handler(struct nl_msg *msg, void *arg)
{
    struct sta_data_ctx *ctx = (struct sta_data_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_SIGNAL]      = { .type = NLA_U8 },
        [NL80211_STA_INFO_SIGNAL_AVG]  = { .type = NLA_U8 },
    };

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_MAC]) {
        const u8 *mac = nla_data(tb[NL80211_ATTR_MAC]);
        if (memcmp(mac, ctx->mac, ETH_ALEN) != 0) {
            return NL_SKIP;
        }
    }

    if (!tb[NL80211_ATTR_STA_INFO]) {
        return NL_SKIP;
    }

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX,
                        tb[NL80211_ATTR_STA_INFO], stats_policy) < 0) {
        return NL_SKIP;
    }

    if (stats[NL80211_STA_INFO_SIGNAL]) {
        ctx->data->signal = (int)(int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL]);
    }

    if (stats[NL80211_STA_INFO_SIGNAL_AVG]) {
#ifdef QCA_UD_HOSTAPD
        ctx->data->mgmt_signal = (int)(int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL_AVG]);
#endif /* QCA_UD_HOSTAPD */
    }

    ctx->found = true;
    return NL_SKIP;
}

/**
 * nl80211_vendor_sta_info_handler - QCA vendor command callback for extended STA info
 * 
 * Parses QCA_NL80211_VENDOR_SUBCMD_GET_STA_INFO response to extract:
 * - min_rssi: Minimum RSSI observed (QCA vendor-specific)
 * - max_rssi: Maximum RSSI observed (QCA vendor-specific)
 */
static int nl80211_vendor_sta_info_handler(struct nl_msg *msg, void *arg)
{
    struct sta_data_ctx *ctx = (struct sta_data_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *vendor[QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_VENDOR_DATA]) {
        return NL_SKIP;
    }

    if (nla_parse_nested(vendor, QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MAX,
                        tb[NL80211_ATTR_VENDOR_DATA], NULL) < 0) {
        return NL_SKIP;
    }

    if (vendor[QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MIN_RSSI]) {
        ctx->data->min_rssi = (int)(int8_t)nla_get_u8(
            vendor[QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MIN_RSSI]);
    }

    if (vendor[QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MAX_RSSI]) {
        ctx->data->max_rssi = (int)(int8_t)nla_get_u8(
            vendor[QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MAX_RSSI]);
    }

    return NL_SKIP;
}

/**
 * get_sta_data_from_driver - Retrieve per-STA statistics from the driver
 * 
 * This function implements the driver-level STA data retrieval using two
 * NL80211 commands:
 * 
 * 1. NL80211_CMD_GET_STATION: Retrieves standard STA info including:
 *    - signal: Current RSSI (dBm)
 *    - mgmt_signal: Management frame RSSI (dBm)
 * 
 * 2. QCA_NL80211_VENDOR_SUBCMD_GET_STA_INFO: Retrieves QCA vendor-specific info:
 *    - min_rssi: Minimum RSSI observed (dBm)
 *    - max_rssi: Maximum RSSI observed (dBm)
 * 
 * @interface: WiFi interface information structure
 * @data: Output structure to populate with STA statistics
 * @addr: MAC address of the STA to query
 * 
 * Returns: 0 on success, -1 on failure
 */
int get_sta_data_from_driver(wifi_interface_info_t *interface,
                           struct hostap_sta_driver_data *data,
                           const u8 *addr)
{
    struct nl_msg *msg = NULL;
    struct nlattr *vendor_data;
    struct sta_data_ctx ctx;
    int ret;
    unsigned int vendor_ifindex = 0;
    int link_id = -1;

    if (!data || !addr) {
        wifi_hal_error_print("%s:%d: Invalid parameters\n", __func__, __LINE__);
        return -1;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.data = data;
    ctx.mac = addr;
    ctx.found = false;

    memset(data, 0, sizeof(*data));

    wifi_hal_dbg_print("%s:%d: Querying STA " MACSTR " on interface %s\n",
                      __func__, __LINE__, MAC2STR(addr), interface->name);

    /* Step 1: Send NL80211_CMD_GET_STATION to get standard STA info */
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                              NL80211_CMD_GET_STATION);
    if (!msg) {
        wifi_hal_error_print("%s:%d: Failed to allocate NL message\n",
                           __func__, __LINE__);
        return -1;
    }

    if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) < 0) {
        wifi_hal_error_print("%s:%d: Failed to add MAC attribute\n",
                           __func__, __LINE__);
        nlmsg_free(msg);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, nl80211_sta_data_handler, &ctx, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: NL80211_CMD_GET_STATION failed: %d\n",
                           __func__, __LINE__, ret);
        return -1;
    }

    if (!ctx.found) {
        wifi_hal_error_print("%s:%d: STA " MACSTR " not found\n",
                           __func__, __LINE__, MAC2STR(addr));
        return -1;
    }

    vendor_ifindex = interface->index;

    /*
     * In MLO mode, the station is owned by the MLD netdev (for example
     * phy00-mld0), while this function may be called for a per-link logical
     * interface (mld0/mld1/mld6).  ath12k's GET_STA_INFO dumpit checks
     * wdev->valid_links and expects QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_LINK_ID
     * when the request is sent to the MLD netdev.  Send the vendor query on
     * interface->mld_name when available, and include the link id so the driver
     * reads RSSI from the correct link instead of the default link.
     */
    if (interface->mld_name[0] != '\0') {
        unsigned int mld_ifindex = if_nametoindex(interface->mld_name);

        if (mld_ifindex != 0) {
            vendor_ifindex = mld_ifindex;
            link_id = wifi_hal_get_mld_link_id(interface);
            wifi_hal_dbg_print("%s:%d: MLO STA info query: link_if=%s(%u) "
                               "mld_if=%s(%u) link_id=%d\n",
                               __func__, __LINE__, interface->name,
                               interface->index, interface->mld_name,
                               vendor_ifindex, link_id);
        } else {
            wifi_hal_dbg_print("%s:%d: MLD interface %s not found, using %s(%u)\n",
                               __func__, __LINE__, interface->mld_name,
                               interface->name, interface->index);
        }
    }

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: Failed to allocate vendor message\n",
                           __func__, __LINE__);
        return -1;
    }

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, NLM_F_DUMP,
                     NL80211_CMD_VENDOR, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)vendor_ifindex) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                    QCA_NL80211_VENDOR_SUBCMD_GET_STA_INFO)) {
        wifi_hal_error_print("%s:%d: Failed to build vendor command\n",
                           __func__, __LINE__);
        nlmsg_free(msg);
        return -1;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data ||
        nla_put(msg, QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_MAC, ETH_ALEN, addr) < 0) {
        wifi_hal_error_print("%s:%d: Failed to add vendor attributes\n",
                           __func__, __LINE__);
        nlmsg_free(msg);
        return -1;
    }

    if (link_id >= 0 &&
        nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_GET_STA_INFO_LINK_ID, (u8)link_id) < 0) {
        wifi_hal_error_print("%s:%d: Failed to add STA info link_id=%d\n",
                           __func__, __LINE__, link_id);
        nlmsg_free(msg);
        return -1;
    }

    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg, nl80211_vendor_sta_info_handler, &ctx,
                                NULL, NULL);
    if (ret < 0) {
        wifi_hal_dbg_print("%s:%d: QCA vendor command failed: %d "
                          "ifindex=%u link_id=%d (non-fatal)\n",
                          __func__, __LINE__, ret, vendor_ifindex, link_id);
    } else {
        wifi_hal_dbg_print("%s:%d: QCA vendor command returned ret=%d "
                          "ifindex=%u link_id=%d min_rssi=%d max_rssi=%d\n",
                          __func__, __LINE__, ret, vendor_ifindex, link_id,
                          data->min_rssi, data->max_rssi);
    }

    if (data->min_rssi == 0 && data->max_rssi == 0 && data->signal != 0) {
        data->min_rssi = data->signal - 5;  /* Estimate: signal - 5 dBm */
        data->max_rssi = data->signal + 5;  /* Estimate: signal + 5 dBm */
        
        wifi_hal_info_print("%s:%d: STA " MACSTR " using fallback min/max RSSI: "
                           "signal=%d min=%d max=%d (vendor cmd returned no valid min/max)\n",
                           __func__, __LINE__, MAC2STR(addr),
                           data->signal, data->min_rssi, data->max_rssi);
    } else {
        wifi_hal_info_print("%s:%d: STA " MACSTR " data: signal=%d mgmt_signal=%d "
                           "min_rssi=%d max_rssi=%d\n",
                           __func__, __LINE__, MAC2STR(addr),
                           data->signal, data->mgmt_signal,
                           data->min_rssi, data->max_rssi);
    }

    return 0;
}

/*
 * get_sta_rssi_from_driver() - Wrapper to call wifi_drv_read_sta_data()
 * 
 * This function provides a compatibility layer for the existing code that
 * expects to call hostapd_drv_read_sta_data(). Instead, it calls our
 * platform-specific wifi_drv_read_sta_data() implementation.
 */
static int get_sta_rssi_from_driver(struct hostapd_data *hapd,
                                     const u8 *mac,
                                     INT *out_signal,
                                     INT *out_mgmt_signal,
                                     INT *out_min_rssi,
                                     INT *out_max_rssi, INT apIndex)
{
    struct hostap_sta_driver_data sta_data;
    wifi_interface_info_t *interface;

    if (!hapd || !mac || !out_signal || !out_mgmt_signal ||
        !out_min_rssi || !out_max_rssi)
        return -1;

    *out_signal      = 0;
    *out_mgmt_signal = 0;
    *out_min_rssi    = 0;
    *out_max_rssi    = 0;

    interface = get_interface_by_vap_index(apIndex);

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for apIndex:%d\n",
                __func__, __LINE__, apIndex);
    }

    memset(&sta_data, 0, sizeof(sta_data));

    /* Call our platform-specific implementation */
    if (get_sta_data_from_driver(interface, &sta_data, mac) != 0) {
        wifi_hal_info_print("%s:%d wifi_drv_read_sta_data failed\n",
                           __func__, __LINE__);
        return -1;
    }

    *out_signal      = (INT)sta_data.signal;
    *out_mgmt_signal = (INT)sta_data.mgmt_signal;
    *out_min_rssi    = (INT)sta_data.min_rssi;
    *out_max_rssi    = (INT)sta_data.max_rssi;

    wifi_hal_info_print(
        "%s:%d wifi_drv_read_sta_data: signal=%d mgmt_signal=%d "
        "min_rssi=%d max_rssi=%d\n",
        __func__, __LINE__,
        *out_signal, *out_mgmt_signal, *out_min_rssi, *out_max_rssi);

    return 0;
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
        [NL80211_STA_INFO_RX_RETRIES] = { .type = NLA_U32 },
    };
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
        [NL80211_RATE_INFO_MCS]       = { .type = NLA_U8  },
        [NL80211_RATE_INFO_VHT_NSS]   = { .type = NLA_U8  },
        [NL80211_RATE_INFO_HE_NSS]    = { .type = NLA_U8  },
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

    if (stats[NL80211_STA_INFO_RX_RETRIES]) {
        dev->cli_RxRetries = nla_get_u32(stats[NL80211_STA_INFO_RX_RETRIES]);
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

    if (rate[NL80211_RATE_INFO_EHT_NSS])
        dev->cli_activeNumSpatialStreams = nla_get_u8(rate[NL80211_RATE_INFO_EHT_NSS]);
    else if (rate[NL80211_RATE_INFO_HE_NSS])
        dev->cli_activeNumSpatialStreams = nla_get_u8(rate[NL80211_RATE_INFO_HE_NSS]);
    else if (rate[NL80211_RATE_INFO_VHT_NSS])
        dev->cli_activeNumSpatialStreams = nla_get_u8(rate[NL80211_RATE_INFO_VHT_NSS]);
    else if (rate[NL80211_RATE_INFO_MCS])
        dev->cli_activeNumSpatialStreams = (nla_get_u8(rate[NL80211_RATE_INFO_MCS]) / 8) + 1;
    else
        dev->cli_activeNumSpatialStreams = 1; /* legacy */

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

static int get_sta_stats_ext_handler(struct nl_msg *msg, void *arg)
{
    wifi_associated_dev3_t *dev = (wifi_associated_dev3_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_SIGNAL]       = { .type = NLA_U8  },
        [NL80211_STA_INFO_SIGNAL_AVG]   = { .type = NLA_U8  },
        [NL80211_STA_INFO_TX_RETRIES]   = { .type = NLA_U32 },
        [NL80211_STA_INFO_RX_DROP_MISC] = { .type = NLA_U64 },
        [NL80211_STA_INFO_TX_BITRATE]   = { .type = NLA_NESTED },
        [NL80211_STA_INFO_RX_BITRATE]   = { .type = NLA_NESTED },
    };
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
        [NL80211_RATE_INFO_BITRATE32]       = { .type = NLA_U32  },
        [NL80211_RATE_INFO_MCS]             = { .type = NLA_U8   },
        [NL80211_RATE_INFO_VHT_MCS]         = { .type = NLA_U8   },
        [NL80211_RATE_INFO_HE_MCS]          = { .type = NLA_U8   },
        [NL80211_RATE_INFO_VHT_NSS]         = { .type = NLA_U8   },
        [NL80211_RATE_INFO_HE_NSS]          = { .type = NLA_U8   },
        [NL80211_RATE_INFO_40_MHZ_WIDTH]    = { .type = NLA_FLAG },
        [NL80211_RATE_INFO_80_MHZ_WIDTH]    = { .type = NLA_FLAG },
        [NL80211_RATE_INFO_160_MHZ_WIDTH]   = { .type = NLA_FLAG },
        [NL80211_RATE_INFO_80P80_MHZ_WIDTH] = { .type = NLA_FLAG },
    };

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse sta data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_error_print("%s:%d Failed to get sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX,
                         tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        wifi_hal_error_print("%s:%d Failed to parse nested attributes\n", __func__, __LINE__);
        return NL_SKIP;
    }

    /* RSSI — NL80211 reports as u8 but the value is a signed dBm */
    if (stats[NL80211_STA_INFO_SIGNAL]) {
        INT signal = (INT)(int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL]);
        dev->cli_RSSI    = signal;
    }

    /* Average signal strength */
    if (stats[NL80211_STA_INFO_SIGNAL_AVG]) {
        dev->cli_SignalStrength =
            (INT)(int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL_AVG]);
    }

    /* TX retries */
    if (stats[NL80211_STA_INFO_TX_RETRIES]) {
        ULLONG retries = (ULLONG)nla_get_u32(stats[NL80211_STA_INFO_TX_RETRIES]);
        dev->cli_Retransmissions    = (UINT)retries;
        dev->cli_RetransCount       = retries;
        dev->cli_RetryCount         = retries;
        dev->cli_MultipleRetryCount = retries;
    }

    /* RX drop misc → RX errors */
    if (stats[NL80211_STA_INFO_RX_DROP_MISC]) {
        dev->cli_RxErrors = nla_get_u64(stats[NL80211_STA_INFO_RX_DROP_MISC]);
    }

    /* TX bitrate — operating standard, channel bandwidth, max downlink rate */
    if (stats[NL80211_STA_INFO_TX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX,
                         stats[NL80211_STA_INFO_TX_BITRATE], rate_policy) == 0) {

        /* Operating standard from MCS type */
        if (rate[NL80211_RATE_INFO_HE_MCS]) {
            strlcpy(dev->cli_OperatingStandard, "ax",
                    sizeof(dev->cli_OperatingStandard) - 1);
        } else if (rate[NL80211_RATE_INFO_VHT_MCS]) {
            strlcpy(dev->cli_OperatingStandard, "ac",
                    sizeof(dev->cli_OperatingStandard) - 1);
        } else if (rate[NL80211_RATE_INFO_MCS]) {
            strlcpy(dev->cli_OperatingStandard, "n",
                    sizeof(dev->cli_OperatingStandard) - 1);
        }


        /* Channel bandwidth from rate flags */
        if (rate[NL80211_RATE_INFO_320_MHZ_WIDTH]) {
            strlcpy(dev->cli_OperatingChannelBandwidth, "320MHz",
                    sizeof(dev->cli_OperatingChannelBandwidth) - 1);
        } else if (rate[NL80211_RATE_INFO_160_MHZ_WIDTH] ||
                rate[NL80211_RATE_INFO_80P80_MHZ_WIDTH]) {
            strlcpy(dev->cli_OperatingChannelBandwidth, "160MHz",
                    sizeof(dev->cli_OperatingChannelBandwidth) - 1);
        } else if (rate[NL80211_RATE_INFO_80_MHZ_WIDTH]) {
            strlcpy(dev->cli_OperatingChannelBandwidth, "80MHz",
                    sizeof(dev->cli_OperatingChannelBandwidth) - 1);
        } else if (rate[NL80211_RATE_INFO_40_MHZ_WIDTH]) {
            strlcpy(dev->cli_OperatingChannelBandwidth, "40MHz",
                    sizeof(dev->cli_OperatingChannelBandwidth) - 1);
        } else {
            strlcpy(dev->cli_OperatingChannelBandwidth, "20MHz",
                    sizeof(dev->cli_OperatingChannelBandwidth) - 1);
        }

        /* Max downlink rate (kbps — same unit as cli_LastDataDownlinkRate) */
        if (rate[NL80211_RATE_INFO_BITRATE32]) {
            dev->cli_MaxDownlinkRate =
                nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
    }

    /* RX bitrate — max uplink rate */
    if (stats[NL80211_STA_INFO_RX_BITRATE] &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX,
                         stats[NL80211_STA_INFO_RX_BITRATE], rate_policy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32]) {
            dev->cli_MaxUplinkRate =
                nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]) * 100;
        }
    }

    return NL_OK;
}

static int get_sta_stats_ext(wifi_interface_info_t *interface, mac_address_t mac,
                             wifi_associated_dev3_t *dev)
{
    int ret;
    struct nl_msg *msg = NULL;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), mac);

    ret = nl80211_send_and_recv(msg, get_sta_stats_ext_handler, dev, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to execute NL command\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

/**
 * wds_sta_entry_t - Tracks a WDS STA and the interface it lives on.
 *
 * For WDS (4-address) clients the kernel creates a per-STA interface named
 * "<mld_parent>.sta<aid>" (e.g. "phy00-mld0.sta1").  Because mld1->index is
 * set to phy00-mld0->index in platform_pre_create_vap(), get_sta_list() sends
 * NL80211_CMD_GET_STATION dump to phy00-mld0 which returns an empty list.
 * The actual STA list and stats are only available on the WDS STA interface.
 */
typedef struct {
    mac_address_t mac;
    char          wds_ifname[IFNAMSIZ]; /* e.g. "phy00-mld0.sta1" */
    unsigned int  wds_ifindex;
} wds_sta_entry_t;

/**
 * scan_wds_sta_interfaces - Scan all <mld_name>.sta<N> interfaces and
 * collect the STA MACs that are associated on them.
 *
 * @mld_name      : MLD parent interface name (e.g. "phy00-mld0")
 * @out_entries   : allocated array of wds_sta_entry_t (caller must free)
 * @out_count     : number of entries returned
 * Returns 0 on success (even if count==0), -1 on allocation failure.
 */
static int scan_wds_sta_interfaces(const char *mld_name,
                                    wds_sta_entry_t **out_entries,
                                    unsigned int *out_count)
{
    char wds_ifname[IFNAMSIZ];
    unsigned int ifindex;
    struct nl_msg *msg;
    int ret;

    *out_entries = NULL;
    *out_count   = 0;

    for (int aid = 1; aid <= 64; aid++) {
        snprintf(wds_ifname, sizeof(wds_ifname), "%s.sta%d", mld_name, aid);
        ifindex = if_nametoindex(wds_ifname);
        if (ifindex == 0)
            break;  /* No more WDS STA interfaces with sequential AIDs */

        /* Dump STA list on this WDS STA interface */
        sta_list_t tmp_list = {};
        msg = nlmsg_alloc();
        if (!msg)
            continue;

        if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, NLM_F_DUMP,
                         NL80211_CMD_GET_STATION, 0) ||
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) < 0) {
            nlmsg_free(msg);
            continue;
        }

        ret = nl80211_send_and_recv(msg, get_sta_list_handler, &tmp_list,
                                    NULL, NULL);
        if (ret != 0 || tmp_list.num == 0) {
            free(tmp_list.macs);
            continue;
        }

        /* Add each STA to the output list */
        for (unsigned int j = 0; j < tmp_list.num; j++) {
            wds_sta_entry_t *new_arr = realloc(*out_entries,
                (*out_count + 1) * sizeof(wds_sta_entry_t));
            if (!new_arr) {
                free(tmp_list.macs);
                return -1;
            }
            *out_entries = new_arr;
            memcpy((*out_entries)[*out_count].mac, tmp_list.macs[j],
                   sizeof(mac_address_t));
            strlcpy((*out_entries)[*out_count].wds_ifname, wds_ifname,
                    IFNAMSIZ);
            (*out_entries)[*out_count].wds_ifindex = ifindex;
            (*out_count)++;

            wifi_hal_info_print("%s:%d: WDS STA " MACSTR
                                " found on %s (ifindex=%u)\n",
                                __func__, __LINE__,
                                MAC2STR(tmp_list.macs[j]),
                                wds_ifname, ifindex);
        }
        free(tmp_list.macs);
    }
    return 0;
}

/**
 * get_sta_stats_by_ifindex - Get STA stats using a raw ifindex.
 * Used for WDS STA interfaces where we have the ifindex but no
 * wifi_interface_info_t.
 */
static int get_sta_stats_by_ifindex(unsigned int ifindex, mac_address_t mac,
                                     wifi_associated_dev3_t *dev)
{
    struct nl_msg *msg;
    int ret;

    msg = nlmsg_alloc();
    if (!msg) return -1;

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                     NL80211_CMD_GET_STATION, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) < 0 ||
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, dev, NULL, NULL);
    if (ret != 0) return -1;

    /* Also get ext stats (signal, rates) */
    msg = nlmsg_alloc();
    if (msg) {
        if (genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                        NL80211_CMD_GET_STATION, 0) &&
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) >= 0 &&
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, mac) >= 0) {
            nl80211_send_and_recv(msg, get_sta_stats_ext_handler, dev,
                                  NULL, NULL);
        } else {
            nlmsg_free(msg);
        }
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
    char ifname[32];

    if (associated_dev_array == NULL || output_array_size == NULL) {
        wifi_hal_error_print("%s:%d NULL parameter error\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    *associated_dev_array = NULL;
    *output_array_size = 0;

    interface = get_interface_by_vap_index(apIndex);
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d Failed to get interface for index %d\n",
                                   __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret < 0) {
        wifi_hal_stats_error_print("%s:%d Failed to get sta list\n", __func__, __LINE__);
        goto exit;
    }

    /* For MLO platforms, mld1->index = phy00-mld0->index, so get_sta_list()
     * sends NL80211_CMD_GET_STATION dump to phy00-mld0 which returns an empty
     * list for WDS (4-address) clients.  The actual STA list and stats for WDS
     * clients are only available on the per-STA WDS interface
     * "<mld_parent>.sta<aid>" (e.g. "phy00-mld0.sta1").
     * Scan those interfaces and append any WDS STAs to sta_list. */
    wds_sta_entry_t *wds_entries = NULL;
    unsigned int wds_count = 0;
    if (interface->mld_name[0] != '\0') {
        scan_wds_sta_interfaces(interface->mld_name, &wds_entries, &wds_count);
        if (wds_count > 0) {
            wifi_hal_info_print("%s:%d: Found %u WDS STA(s) on %s interfaces\n",
                                __func__, __LINE__, wds_count, interface->mld_name);
        }
    }

    unsigned int total_stas = sta_list.num + wds_count;
    *associated_dev_array = total_stas ?
        calloc(total_stas, sizeof(wifi_associated_dev3_t)) : NULL;
    *output_array_size = total_stas;

    /* Process regular STAs (from get_sta_list) */
    for (i = 0; i < sta_list.num; i++) {
        wifi_associated_dev3_t *dev = &(*associated_dev_array)[i];

        ret = get_sta_stats(interface, sta_list.macs[i], dev);
        if (ret < 0) {
            wifi_hal_stats_error_print("%s:%d Failed to get sta stats\n",
                                       __func__, __LINE__);
            free(*associated_dev_array);
            *associated_dev_array = NULL;
            *output_array_size = 0;
            free(wds_entries);
            goto exit;
        }

        get_sta_stats_ext(interface, sta_list.macs[i], dev);

        {
            struct hostapd_data *hapd = &interface->u.ap.hapd;
            INT drv_signal = 0, drv_mgmt = 0, drv_min = 0, drv_max = 0;

            if (hapd != NULL && hapd->drv_priv != NULL &&
                get_sta_rssi_from_driver(hapd, sta_list.macs[i],
                                         &drv_signal, &drv_mgmt,
                                         &drv_min, &drv_max, apIndex) == 0) {

                if (drv_signal != 0) {
                    dev->cli_RSSI = drv_signal;
                    dev->cli_SNR  = drv_signal;
                }
                if (drv_mgmt != 0 && dev->cli_RSSI == 0)
                    dev->cli_RSSI = drv_mgmt;

                if (drv_min != 0)
                    dev->cli_MinRSSI = drv_min;
                if (drv_max != 0)
                    dev->cli_MaxRSSI = drv_max;
            } else {
                if (dev->cli_RSSI != 0 && dev->cli_SNR == 0)
                    dev->cli_SNR = dev->cli_RSSI;
            }
        }

        if (get_interface_name_from_vap_index(apIndex, ifname) != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Failed to get interface name for apIndex:%d\n",
                    __func__, __LINE__, apIndex);
            return RETURN_ERR;
        }
        char mac_str[18];
        int link_id = 0;  /* Default link ID */

        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                sta_list.macs[i][0], sta_list.macs[i][1], sta_list.macs[i][2],
                sta_list.macs[i][3], sta_list.macs[i][4], sta_list.macs[i][5]);

        if (interface != NULL && interface->mld_name[0] != '\0') {
            link_id = wifi_hal_get_mld_link_id(interface);
            strlcpy(ifname, interface->mld_name, sizeof(ifname) - 1);
            ifname[sizeof(ifname) - 1] = '\0';
        }

#ifdef CONFIG_IEEE80211BE
        /* For MLO STAs, get the actual link ID from hostapd sta_info */
        {
            struct hostapd_data *hapd = &interface->u.ap.hapd;
            struct sta_info *sta;

            if (hapd != NULL) {
                sta = ap_get_sta(hapd, sta_list.macs[i]);
                if (sta != NULL && ap_sta_is_mld(hapd, sta)) {
                    /* Get the link ID for this specific link STA */
                    link_id = hapd->mld_link_id;
                    wifi_hal_info_print("%s:%d: MLD STA " MACSTR " on link_id=%d\n",
                            __func__, __LINE__, MAC2STR(sta_list.macs[i]), link_id);
                }
            }
        }
#endif

        dev->cli_Active = TRUE;
        strlcpy(dev->cli_InterferenceSources, "NULL",
                sizeof(dev->cli_InterferenceSources) - 1);
        dev->cli_Disassociations        = 0;
        dev->cli_AuthenticationFailures = 0;
        dev->cli_Associations           = 0;
        dev->cli_CsiData                = NULL;
        dev->cli_MLDEnable              = FALSE;
        memset(dev->cli_MLDAddr, 0, sizeof(mac_address_t));
        memset(&dev->cli_DownlinkMuStats, 0, sizeof(wifi_dl_mu_stats_t));
        memset(&dev->cli_UplinkMuStats,   0, sizeof(wifi_ul_mu_stats_t));
        memset(&dev->cli_TwtParams,       0, sizeof(wifi_twt_dev_info_t));

        dev->cli_TxFrames           = dev->cli_PacketsSent;
        dev->cli_FailedRetransCount = dev->cli_ErrorsSent;
        dev->cli_DataFramesSentNoAck = dev->cli_ErrorsSent;
        if (dev->cli_PacketsSent > dev->cli_ErrorsSent) {
            dev->cli_DataFramesSentAck =
                dev->cli_PacketsSent - dev->cli_ErrorsSent;
        }
        if (dev->cli_MaxDownlinkRate == 0)
            dev->cli_MaxDownlinkRate = dev->cli_LastDataDownlinkRate;
        if (dev->cli_MaxUplinkRate == 0)
            dev->cli_MaxUplinkRate = dev->cli_LastDataUplinkRate;

        if (get_ip_from_dnsmasq_leases(sta_list.macs[i], dev->cli_IPAddress,
                    sizeof(dev->cli_IPAddress)) == 0) {
            wifi_hal_info_print("%s:%d Got IP %s from dnsmasq.leases for MAC " MACSTR "\n",
                    __func__, __LINE__, dev->cli_IPAddress,
                    MAC2STR(sta_list.macs[i]));
        } else {
            wifi_hal_dbg_print("%s:%d No IP address found for MAC " MACSTR "\n",
                    __func__, __LINE__, MAC2STR(sta_list.macs[i]));
        }

#ifdef CONFIG_IEEE80211BE
            struct hostapd_data *hapd = &interface->u.ap.hapd;
            struct sta_info *sta;

            if (hapd != NULL) {
                sta = ap_get_sta(hapd, sta_list.macs[i]);
                if (sta != NULL && ap_sta_is_mld(hapd, sta)) {
                    dev->cli_MLDEnable = TRUE;
                    memcpy(dev->cli_MLDAddr,
                           sta->mld_info.common_info.mld_addr, ETH_ALEN);
                    wifi_hal_info_print(
                        "%s:%d Client " MACSTR " is MLD enabled\n",
                        __func__, __LINE__,
                        MAC2STR(sta_list.macs[i]));

                }
            }
#endif
    }

    /* Process WDS STAs (from scan_wds_sta_interfaces).
     * For each WDS STA, use get_sta_stats_by_ifindex() to query the WDS STA
     * interface directly — this returns the correct RSSI, bytes, and rates. */
    for (unsigned int w = 0; w < wds_count; w++) {
        wifi_associated_dev3_t *dev = &(*associated_dev_array)[sta_list.num + w];
        wds_sta_entry_t *wds = &wds_entries[w];

        memcpy(dev->cli_MACAddress, wds->mac, sizeof(mac_address_t));

        if (get_sta_stats_by_ifindex(wds->wds_ifindex, wds->mac, dev) == 0) {
            wifi_hal_info_print("%s:%d: WDS STA " MACSTR
                                " stats: RSSI=%d tx=%lu rx=%lu rate_dl=%u rate_ul=%u\n",
                                __func__, __LINE__, MAC2STR(wds->mac),
                                dev->cli_RSSI,
                                (unsigned long)dev->cli_BytesSent,
                                (unsigned long)dev->cli_BytesReceived,
                                dev->cli_LastDataDownlinkRate,
                                dev->cli_LastDataUplinkRate);
            if (dev->cli_RSSI != 0 && dev->cli_SNR == 0)
                dev->cli_SNR = dev->cli_RSSI;
        } else {
            wifi_hal_error_print("%s:%d: Failed to get stats for WDS STA " MACSTR
                                 " on %s\n",
                                 __func__, __LINE__, MAC2STR(wds->mac),
                                 wds->wds_ifname);
        }

        /* Common fields */
        if (get_interface_name_from_vap_index(apIndex, ifname) == RETURN_OK) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     wds->mac[0], wds->mac[1], wds->mac[2],
                     wds->mac[3], wds->mac[4], wds->mac[5]);
            if (interface->mld_name[0] != '\0') {
                strlcpy(ifname, interface->mld_name, sizeof(ifname) - 1);
            }
        }

        dev->cli_Active = TRUE;
        strlcpy(dev->cli_InterferenceSources, "NULL",
                sizeof(dev->cli_InterferenceSources) - 1);
        dev->cli_Disassociations        = 0;
        dev->cli_AuthenticationFailures = 0;
        dev->cli_Associations           = 0;
        dev->cli_CsiData                = NULL;
        dev->cli_MLDEnable              = FALSE;
        memset(dev->cli_MLDAddr, 0, sizeof(mac_address_t));
        memset(&dev->cli_DownlinkMuStats, 0, sizeof(wifi_dl_mu_stats_t));
        memset(&dev->cli_UplinkMuStats,   0, sizeof(wifi_ul_mu_stats_t));
        memset(&dev->cli_TwtParams,       0, sizeof(wifi_twt_dev_info_t));

        dev->cli_TxFrames            = dev->cli_PacketsSent;
        dev->cli_FailedRetransCount  = dev->cli_ErrorsSent;
        dev->cli_DataFramesSentNoAck = dev->cli_ErrorsSent;
        if (dev->cli_PacketsSent > dev->cli_ErrorsSent)
            dev->cli_DataFramesSentAck = dev->cli_PacketsSent - dev->cli_ErrorsSent;
        if (dev->cli_MaxDownlinkRate == 0)
            dev->cli_MaxDownlinkRate = dev->cli_LastDataDownlinkRate;
        if (dev->cli_MaxUplinkRate == 0)
            dev->cli_MaxUplinkRate = dev->cli_LastDataUplinkRate;

        get_ip_from_dnsmasq_leases(wds->mac, dev->cli_IPAddress,
                                   sizeof(dev->cli_IPAddress));
    }

    free(wds_entries);

exit:
    free(sta_list.macs);
    return ret;
}

/* =========================================================================
 * wifi_getRadioChannelStats
 *
 * Retrieves channel statistics for the given radio using the standard
 * NL80211_CMD_GET_SURVEY dump command.  For each entry in
 * input_output_channelStats_array the caller pre-fills ch_number (or
 * leaves it 0 to request the currently-in-use channel only).
 *
 * Filled fields:
 *   ch_number              - operating channel number
 *   ch_noise               - average noise floor (dBm)
 *   ch_utilization         - busy percentage  (0-100)
 *   ch_utilization_total   - NL80211_SURVEY_INFO_CHANNEL_TIME   (ms)
 *   ch_utilization_busy    - NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY (ms)
 *   ch_utilization_busy_tx - NL80211_SURVEY_INFO_CHANNEL_TIME_TX  (ms)
 *   ch_utilization_busy_rx - NL80211_SURVEY_INFO_CHANNEL_TIME_RX  (ms)
 *   ch_utilization_busy_self - NL80211_SURVEY_INFO_TIME_BSS_RX    (ms)
 *   ch_utilization_busy_ext  - NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY (ms)
 * ========================================================================= */

/* Context passed to the NL80211 survey dump callback */
typedef struct {
    wifi_channelStats_t *arr;   /* caller-supplied array                  */
    int                  size;  /* number of elements in arr              */
    int                  filled;/* number of elements actually populated  */
    /* Radio-specific frequency band filter.
     * Since phy00-mld0 is a single MLD parent covering ALL radios (2.4/5/6 GHz),
     * iw phy00-mld0 survey dump returns "in use" channels for ALL radios.
     * We must filter by the radio's operating band to avoid assigning the
     * wrong radio's channel stats (e.g. 2437 MHz) to a 5GHz or 6GHz radio.
     * freq_min/freq_max define the inclusive MHz range for this radio. */
    unsigned int         freq_min; /* lower bound of radio's band (MHz)  */
    unsigned int         freq_max; /* upper bound of radio's band (MHz)  */
} ud_chan_stats_ctx_t;

static int ud_survey_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY]          = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE]              = { .type = NLA_U8  },
        [NL80211_SURVEY_INFO_IN_USE]             = { .type = NLA_FLAG },
        [NL80211_SURVEY_INFO_CHANNEL_TIME]       = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]  = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_CHANNEL_TIME_TX]    = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_CHANNEL_TIME_RX]    = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_TIME_BSS_RX]        = { .type = NLA_U64 },
        [NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY] = { .type = NLA_U64 },
    };
    ud_chan_stats_ctx_t *ctx = (ud_chan_stats_ctx_t *)arg;
    unsigned int freq = 0;
    uint channel = 0;
    int i;
    ULLONG total, busy;

    nla_parse(tb, NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_SURVEY_INFO])
        return NL_SKIP;

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,
                         tb[NL80211_ATTR_SURVEY_INFO], survey_policy)) {
        wifi_hal_error_print("%s:%d: failed to parse survey nested attrs\n",
                             __func__, __LINE__);
        return NL_SKIP;
    }

    if (!sinfo[NL80211_SURVEY_INFO_FREQUENCY])
        return NL_SKIP;

    freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);

    /* Radio-specific band filter: skip frequencies outside this radio's band.
     * Required because phy00-mld0 covers all 3 radios and returns survey data
     * for all bands in a single dump. Without this filter, the 2.4GHz "in use"
     * channel (e.g. 2437 MHz) would be incorrectly assigned to the 5GHz or
     * 6GHz radio when ch_number == 0 (auto-detect in-use channel). */
    if (ctx->freq_min > 0 && ctx->freq_max > 0) {
        if (freq < ctx->freq_min || freq > ctx->freq_max)
            return NL_SKIP;
    }

    if (wifi_freq_to_channel((int)freq, &channel) != RETURN_OK) {
        wifi_hal_dbg_print("%s:%d: cannot convert freq %u to channel\n",
                           __func__, __LINE__, freq);
        return NL_SKIP;
    }

    /* Find the matching slot in the caller's array.
     * If ch_number == 0 we accept any in-use channel. */
    for (i = 0; i < ctx->size; i++) {
        if (ctx->arr[i].ch_number == 0) {
            /* Accept only the currently-in-use channel */
            if (!sinfo[NL80211_SURVEY_INFO_IN_USE])
                continue;
            ctx->arr[i].ch_number = (INT)channel;
        } else if (ctx->arr[i].ch_number != (INT)channel) {
            continue;
        }

        /* Noise floor */
        if (sinfo[NL80211_SURVEY_INFO_NOISE])
            ctx->arr[i].ch_noise =
                (INT)(int8_t)nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);

        /* Raw time counters (milliseconds) */
        total = sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME] ?
                nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME]) : 0;
        busy  = sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY] ?
                nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_BUSY]) : 0;

        ctx->arr[i].ch_utilization_total = total;
        ctx->arr[i].ch_utilization_busy  = busy;

        ctx->arr[i].ch_utilization_busy_tx =
            sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX] ?
            nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_TX]) : 0;

        ctx->arr[i].ch_utilization_busy_rx =
            sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX] ?
            nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_RX]) : 0;

        ctx->arr[i].ch_utilization_busy_self =
            sinfo[NL80211_SURVEY_INFO_TIME_BSS_RX] ?
            nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BSS_RX]) : 0;

        ctx->arr[i].ch_utilization_busy_ext =
            sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY] ?
            nla_get_u64(sinfo[NL80211_SURVEY_INFO_CHANNEL_TIME_EXT_BUSY]) : 0;

        /* Utilization percentage: (busy / total) * 100, clamped to 100 */
        if (total > 0)
            ctx->arr[i].ch_utilization =
                (INT)((busy * 100ULL) / total);
        else
            ctx->arr[i].ch_utilization = 0;

        ctx->filled++;
        break; /* one slot per survey entry */
    }

    return NL_SKIP;
}

INT wifi_getRadioChannelStats(INT radioIndex,
                              wifi_channelStats_t *input_output_channelStats_array,
                              INT array_size)
{
    wifi_radio_info_t   *radio;
    wifi_interface_info_t *interface;
    struct nl_msg       *msg;
    ud_chan_stats_ctx_t  ctx;
    int                  ret;
    unsigned int         ifindex;

    wifi_hal_dbg_print("%s:%d: radioIndex=%d array_size=%d\n",
                       __func__, __LINE__, radioIndex, array_size);

    if (!input_output_channelStats_array || array_size <= 0) {
        wifi_hal_error_print("%s:%d: invalid arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        wifi_hal_error_print("%s:%d: primary interface not found for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    /* For MLO interfaces (e.g. mld0), NL80211_CMD_GET_SURVEY must be sent
     * to the MLD parent interface (e.g. phy00-mld0), not the link interface.
     * This matches the pattern used in wifi_getApAssociatedDeviceDiagnosticResult3
     * where interface->mld_name holds the MLD parent interface name.
     * iw uses: iw dev phy00-mld0 survey dump  (CIB_NETDEV on the MLD parent). */
    ifindex = (unsigned int)interface->index;
    if (interface->mld_name[0] != '\0') {
        unsigned int mld_ifindex = if_nametoindex(interface->mld_name);
        if (mld_ifindex > 0) {
            ifindex = mld_ifindex;
            wifi_hal_dbg_print("%s:%d: MLO radio %d: using MLD parent %s (ifindex=%u)"
                               " instead of link iface %s (ifindex=%u)\n",
                               __func__, __LINE__, radioIndex,
                               interface->mld_name, ifindex,
                               interface->name, (unsigned int)interface->index);
        } else {
            wifi_hal_error_print("%s:%d: if_nametoindex(%s) failed, falling back to %s\n",
                                 __func__, __LINE__, interface->mld_name, interface->name);
        }
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.arr  = input_output_channelStats_array;
    ctx.size = array_size;

    /* Set frequency band filter based on radio->oper_param.band.
     * phy00-mld0 covers all 3 radios and returns survey data for ALL bands.
     * Without this filter, the first "in use" channel found (e.g. 2437 MHz
     * for 2.4GHz) would be incorrectly assigned to the 5GHz or 6GHz radio.
     *
     * Frequency ranges (IEEE 802.11 / regulatory):
     *   2.4GHz : 2412 – 2484 MHz
     *   5GHz   : 5180 – 5825 MHz  (includes 5L + 5H sub-bands)
     *   6GHz   : 5925 – 7125 MHz  (Wi-Fi 6E / 802.11ax 6GHz)
     */
    switch (radio->oper_param.band) {
    case WIFI_FREQUENCY_2_4_BAND:
        ctx.freq_min = 2412;
        ctx.freq_max = 2484;
        break;
    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        ctx.freq_min = 5180;
        ctx.freq_max = 5825;
        break;
    case WIFI_FREQUENCY_6_BAND:
        ctx.freq_min = 5925;
        ctx.freq_max = 7125;
        break;
    default:
        /* Unknown band — disable filter (accept all frequencies) */
        ctx.freq_min = 0;
        ctx.freq_max = 0;
        wifi_hal_dbg_print("%s:%d: unknown band %d for radio %d, no freq filter\n",
                           __func__, __LINE__, radio->oper_param.band, radioIndex);
        break;
    }

    wifi_hal_dbg_print("%s:%d: radio %d band=%d freq_filter=[%u-%u MHz]\n",
                       __func__, __LINE__, radioIndex,
                       radio->oper_param.band, ctx.freq_min, ctx.freq_max);

    /* Build NL80211_CMD_GET_SURVEY dump message targeting the resolved interface */
    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0,
                     NLM_F_DUMP, NL80211_CMD_GET_SURVEY, 0) ||
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)ifindex)) {
        wifi_hal_error_print("%s:%d: failed to build survey msg\n",
                             __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, ud_survey_handler, &ctx, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d: NL80211_CMD_GET_SURVEY failed ret=%d\n",
                             __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: survey done, filled=%d/%d\n",
                       __func__, __LINE__, ctx.filled, array_size);

    return RETURN_OK;
}

/* =========================================================================
 * UFR10: Tx Power and Dynamic IE Commands
 * =========================================================================
 *
 * For hostapd-based commands: we call ieee802_11_update_beacons() after
 * setting the config because:
 * - Hostapd builds beacon frame and sends to kernel via nl80211_set_ap()
 * - Kernel transmits beacon periodically with FIXED content
 * - Without ieee802_11_update_beacons(), beacon content won't change
 *
 */


/* R-UFR10-01: VAP-level vdev param → outer subcmd 75 (GET_WIFI_CONFIGURATION) */
INT wifi_hal_getRadioMinTxPower(wifi_radio_index_t radioIndex, INT *v)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!v || !i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_GET_MINTXPOWER, &val, -1) != RETURN_OK) return RETURN_ERR;
    *v = (INT)val; return RETURN_OK;
}

/* R-UFR10-02: VAP-level vdev param → outer subcmd 75 */
INT wifi_hal_getRadioMaxTxPower(wifi_radio_index_t radioIndex, INT *v)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!v || !i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_GET_MAXTXPOWER, &val, -1) != RETURN_OK) return RETURN_ERR;
    *v = (INT)val; return RETURN_OK;
}

/* R-UFR10-03: VAP-level vdev param → outer subcmd 75 */
INT wifi_hal_getRadioRegTxPower(wifi_radio_index_t radioIndex, INT *v)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!v || !i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_REGTXPOWER, &val, -1) != RETURN_OK) return RETURN_ERR;
    *v = (INT)val; return RETURN_OK;
}

/* R-UFR10-04: VAP-level vdev param → outer subcmd 75 */
INT wifi_hal_getApVapTxPower(INT apIndex, INT *v)
{
    int32_t val = 0;
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!v || !i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_GET_TXPOWER_RESOLUTION, &val, -1) != RETURN_OK) return RETURN_ERR;
    *v = (INT)val; return RETURN_OK;
}

/* R-UFR10-07: VAP-level vdev param → outer subcmd 75 */
INT wifi_hal_getApMaxRate(INT apIndex, UINT *v)
{
    int32_t val = 0;
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!v || !i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_GET_MAXRATE, &val, -1) != RETURN_OK) return RETURN_ERR;
    *v = (UINT)val; return RETURN_OK;
}

/* R-UFR10-06: CTL Power Scale — radio-level wiphy param → outer subcmd 505/506 */
INT wifi_hal_setRadioCtlPwrScale(wifi_radio_index_t radioIndex, UINT scale)
{
    int ret;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d scale=%u hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, scale,
                       qca_vendor_get_hw_idx(radioIndex));
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_CTLPWRSCALE, (int32_t)scale,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set ctlpwrscale=%u for radio %d\n",
                             __func__, __LINE__, scale, radioIndex);
    else
        wifi_hal_info_print("%s:%d: ctlpwrscale=%u set for radio %d\n",
                            __func__, __LINE__, scale, radioIndex);
    return ret;
}
INT wifi_hal_getRadioCtlPwrScale(wifi_radio_index_t radioIndex, UINT *scale)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!scale) {
        wifi_hal_error_print("%s:%d: NULL scale pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION,
                             QCA_WLAN_VENDOR_RADIO_PARAM_CTLPWRSCALE, &val,
                             qca_vendor_get_hw_idx(radioIndex)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get ctlpwrscale for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    *scale = (UINT)val;
    wifi_hal_dbg_print("%s:%d: radio=%d ctlpwrscale=%u\n",
                       __func__, __LINE__, radioIndex, *scale);
    return RETURN_OK;
}

/* R-UFR10-11: Channel 144 — radio-level wiphy param → outer subcmd 505/506 */
INT wifi_hal_setRadioChan144Enable(wifi_radio_index_t radioIndex, BOOL enable)
{
    int ret;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* Channel 144 (5720 MHz) only exists on 5 GHz — skip for 2.4G and 6G */
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio ||
        (radio->oper_param.band != WIFI_FREQUENCY_5_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5L_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5H_BAND)) {
        wifi_hal_info_print("%s:%d: chan144_enable not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__,
                            radio ? (int)radio->oper_param.band : -1, radioIndex);
        return RETURN_OK;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d chan144_enable=%d hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, enable,
                       qca_vendor_get_hw_idx(radioIndex));
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_EN_CHAN_144, enable ? 1 : 0,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set chan144_enable=%d for radio %d\n",
                             __func__, __LINE__, enable, radioIndex);
    else
        wifi_hal_info_print("%s:%d: chan144_enable=%d set for radio %d\n",
                            __func__, __LINE__, enable, radioIndex);
    return ret;
}
INT wifi_hal_getRadioChan144Enable(wifi_radio_index_t radioIndex, BOOL *enable)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!enable) {
        wifi_hal_error_print("%s:%d: NULL enable pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION,
                             QCA_WLAN_VENDOR_RADIO_PARAM_EN_CHAN_144, &val,
                             qca_vendor_get_hw_idx(radioIndex)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get chan144_enable for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    *enable = (val != 0) ? TRUE : FALSE;
    wifi_hal_dbg_print("%s:%d: radio=%d chan144_enable=%d\n",
                       __func__, __LINE__, radioIndex, *enable);
    return RETURN_OK;
}

/* R-UFR10-19: Antenna Gain 2.4GHz — radio-level wiphy param → outer subcmd 505 */
INT wifi_hal_setRadioAntennaGain2G(wifi_radio_index_t radioIndex, UINT gain)
{
    int ret;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* Antenna gain 2G param is only valid on 2.4 GHz radio */
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio || radio->oper_param.band != WIFI_FREQUENCY_2_4_BAND) {
        wifi_hal_info_print("%s:%d: antenna_gain_2g not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__,
                            radio ? (int)radio->oper_param.band : -1, radioIndex);
        return RETURN_OK;
    }
    if (gain > 30) {
        wifi_hal_error_print("%s:%d: antenna_gain_2g=%u out of range (max 30) for radio %d\n",
                             __func__, __LINE__, gain, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d antenna_gain_2g=%u hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, gain,
                       qca_vendor_get_hw_idx(radioIndex));
    /* Driver expects raw gain value (0-30). The param selector (param=40 vs
     * param=41) already distinguishes 2G from 5G — no mask needed. */
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_ANTENNA_GAIN_2G,
                               (int32_t)gain,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set antenna_gain_2g=%u for radio %d\n",
                             __func__, __LINE__, gain, radioIndex);
    else
        wifi_hal_info_print("%s:%d: antenna_gain_2g=%u set for radio %d\n",
                            __func__, __LINE__, gain, radioIndex);
    return ret;
}

/* R-UFR10-20: Antenna Gain 5GHz — radio-level wiphy param → outer subcmd 505 */
INT wifi_hal_setRadioAntennaGain5G(wifi_radio_index_t radioIndex, UINT gain)
{
    int ret;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* Antenna gain 5G param is only valid on 5 GHz radio */
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio ||
        (radio->oper_param.band != WIFI_FREQUENCY_5_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5L_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5H_BAND)) {
        wifi_hal_info_print("%s:%d: antenna_gain_5g not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__,
                            radio ? (int)radio->oper_param.band : -1, radioIndex);
        return RETURN_OK;
    }
    if (gain > 30) {
        wifi_hal_error_print("%s:%d: antenna_gain_5g=%u out of range (max 30) for radio %d\n",
                             __func__, __LINE__, gain, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d antenna_gain_5g=%u hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, gain,
                       qca_vendor_get_hw_idx(radioIndex));
    /* Driver expects raw gain value (0-30). The param selector (param=40 vs
     * param=41) already distinguishes 2G from 5G — no mask needed. */
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_ANTENNA_GAIN_5G,
                               (int32_t)gain,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set antenna_gain_5g=%u for radio %d\n",
                             __func__, __LINE__, gain, radioIndex);
    else
        wifi_hal_info_print("%s:%d: antenna_gain_5g=%u set for radio %d\n",
                            __func__, __LINE__, gain, radioIndex);
    return ret;
}

/* R-UFR10-21: Tx Power Scale — radio-level wiphy param → outer subcmd 505/506 */
INT wifi_hal_setRadioTxPowerScale(wifi_radio_index_t radioIndex, UINT scale)
{
    int ret;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (scale > 4) {
        wifi_hal_error_print("%s:%d: txpowerscale=%u out of range (0-4) for radio %d\n",
                             __func__, __LINE__, scale, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerscale=%u hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, scale,
                       qca_vendor_get_hw_idx(radioIndex));
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_SCALE, (int32_t)scale,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set txpowerscale=%u for radio %d\n",
                             __func__, __LINE__, scale, radioIndex);
    else
        wifi_hal_info_print("%s:%d: txpowerscale=%u set for radio %d\n",
                            __func__, __LINE__, scale, radioIndex);
    return ret;
}
INT wifi_hal_getRadioTxPowerScale(wifi_radio_index_t radioIndex, UINT *scale)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!scale) {
        wifi_hal_error_print("%s:%d: NULL scale pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION,
                             QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_SCALE, &val,
                             qca_vendor_get_hw_idx(radioIndex)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get txpowerscale for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    *scale = (UINT)val;
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerscale=%u\n",
                       __func__, __LINE__, radioIndex, *scale);
    return RETURN_OK;
}

/* R-UFR10-22: Tx Power Limit 2GHz — radio-level wiphy param → outer subcmd 505/506 */
INT wifi_hal_setRadioTxPowerLimit2G(wifi_radio_index_t radioIndex, INT limit)
{
    int ret;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* TX power limit 2G param is only valid on 2.4 GHz radio */
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio || radio->oper_param.band != WIFI_FREQUENCY_2_4_BAND) {
        wifi_hal_info_print("%s:%d: txpowerlimit2g not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__,
                            radio ? (int)radio->oper_param.band : -1, radioIndex);
        return RETURN_OK;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerlimit2g=%d hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, limit,
                       qca_vendor_get_hw_idx(radioIndex));
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT2G, (int32_t)limit,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set txpowerlimit2g=%d for radio %d\n",
                             __func__, __LINE__, limit, radioIndex);
    else
        wifi_hal_info_print("%s:%d: txpowerlimit2g=%d set for radio %d\n",
                            __func__, __LINE__, limit, radioIndex);
    return ret;
}
INT wifi_hal_getRadioTxPowerLimit2G(wifi_radio_index_t radioIndex, INT *limit)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!limit) {
        wifi_hal_error_print("%s:%d: NULL limit pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION,
                             QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT2G, &val,
                             qca_vendor_get_hw_idx(radioIndex)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get txpowerlimit2g for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    *limit = (INT)val;
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerlimit2g=%d\n",
                       __func__, __LINE__, radioIndex, *limit);
    return RETURN_OK;
}

/* R-UFR10-23: Tx Power Limit 5GHz — radio-level wiphy param → outer subcmd 505/506 */
INT wifi_hal_setRadioTxPowerLimit5G(wifi_radio_index_t radioIndex, INT limit)
{
    int ret;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* TX power limit 5G param is only valid on 5 GHz radio */
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio ||
        (radio->oper_param.band != WIFI_FREQUENCY_5_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5L_BAND &&
         radio->oper_param.band != WIFI_FREQUENCY_5H_BAND)) {
        wifi_hal_info_print("%s:%d: txpowerlimit5g not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__,
                            radio ? (int)radio->oper_param.band : -1, radioIndex);
        return RETURN_OK;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerlimit5g=%d hw_idx=%d\n",
                       __func__, __LINE__, radioIndex, limit,
                       qca_vendor_get_hw_idx(radioIndex));
    ret = qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
                               QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT5G, (int32_t)limit,
                               qca_vendor_get_hw_idx(radioIndex));
    if (ret != RETURN_OK)
        wifi_hal_error_print("%s:%d: failed to set txpowerlimit5g=%d for radio %d\n",
                             __func__, __LINE__, limit, radioIndex);
    else
        wifi_hal_info_print("%s:%d: txpowerlimit5g=%d set for radio %d\n",
                            __func__, __LINE__, limit, radioIndex);
    return ret;
}
INT wifi_hal_getRadioTxPowerLimit5G(wifi_radio_index_t radioIndex, INT *limit)
{
    int32_t val = 0;
    wifi_interface_info_t *i = qca_vendor_radio_iface(radioIndex);
    if (!limit) {
        wifi_hal_error_print("%s:%d: NULL limit pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (!i) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION,
                             QCA_WLAN_VENDOR_RADIO_PARAM_TXPOWER_LIMIT5G, &val,
                             qca_vendor_get_hw_idx(radioIndex)) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get txpowerlimit5g for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    *limit = (INT)val;
    wifi_hal_dbg_print("%s:%d: radio=%d txpowerlimit5g=%d\n",
                       __func__, __LINE__, radioIndex, *limit);
    return RETURN_OK;
}

/*
 * R-UFR10-08: PureG Mode
 * Sets pureg_bss + calls ieee802_11_update_beacons to push to kernel.
 * hostapd_cli SET_PUREG just sets struct (designed for test flow where
 * beacon update is triggered separately). RDK HAL calls it explicitly.
 */
INT wifi_hal_setRadioPureGMode(wifi_radio_index_t radioIndex, BOOL enable)
{
    wifi_radio_info_t *radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    wifi_interface_info_t *iface;
    int ret = RETURN_OK;
    if (!radio) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* Pure-G mode (802.11g only) is only applicable on 2.4 GHz */
    if (radio->oper_param.band != WIFI_FREQUENCY_2_4_BAND) {
        wifi_hal_info_print("%s:%d: pureg_mode not applicable for band %d (radio %d), skipping\n",
                            __func__, __LINE__, (int)radio->oper_param.band, radioIndex);
        return RETURN_OK;
    }
    iface = get_primary_interface(radio);
    if (!iface) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d pureg_mode=%d\n",
                       __func__, __LINE__, radioIndex, enable);
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    iface->u.ap.conf.bss_extn.pureg_bss = (bool)enable;
    if (iface->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(iface->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for radio %d\n",
                                 __func__, __LINE__, radioIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: pureg_mode=%d set for radio %d\n",
                                __func__, __LINE__, enable, radioIndex);
        }
    } else {
        wifi_hal_dbg_print("%s:%d: hapd not initialized for radio %d, pureg_mode=%d cached\n",
                           __func__, __LINE__, radioIndex, enable);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return ret;
}
INT wifi_hal_getRadioPureGMode(wifi_radio_index_t radioIndex, BOOL *enable)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *iface;
    if (!enable) {
        wifi_hal_error_print("%s:%d: NULL enable pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    iface = get_primary_interface(radio);
    if (!iface) {
        wifi_hal_error_print("%s:%d: no primary interface for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *enable = iface->u.ap.conf.bss_extn.pureg_bss ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: radio=%d pureg_mode=%d\n",
                       __func__, __LINE__, radioIndex, *enable);
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-09: HT40 Intolerance
 * Sets ht_capab + calls ieee802_11_update_beacons.
 * Matches hostapd_cli HT40INTOL behavior exactly.
 */
INT wifi_hal_setRadioHT40Intolerant(wifi_radio_index_t radioIndex, BOOL intol)
{
    wifi_radio_info_t *radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    wifi_interface_info_t *iface;
    int ret = RETURN_OK;
    if (!radio) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    /* HT (802.11n) does not exist on 6 GHz — ht40intolerant not applicable */
    if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        wifi_hal_info_print("%s:%d: ht40intolerant not applicable for 6 GHz (radio %d), skipping\n",
                            __func__, __LINE__, radioIndex);
        return RETURN_OK;
    }
    iface = get_primary_interface(radio);
    if (!iface || !iface->u.ap.iface.conf) {
        wifi_hal_error_print("%s:%d: no primary interface or iconf for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: radio=%d ht40intolerant=%d\n",
                       __func__, __LINE__, radioIndex, intol);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    if (intol)
        iface->u.ap.iface.conf->ht_capab |= HT_CAP_INFO_40MHZ_INTOLERANT;
    else
        iface->u.ap.iface.conf->ht_capab &= ~HT_CAP_INFO_40MHZ_INTOLERANT;
    if (iface->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(iface->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for radio %d\n",
                                 __func__, __LINE__, radioIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: ht40intolerant=%d set for radio %d\n",
                                __func__, __LINE__, intol, radioIndex);
        }
    } else {
        wifi_hal_dbg_print("%s:%d: hapd not initialized for radio %d, ht40intolerant=%d cached\n",
                           __func__, __LINE__, radioIndex, intol);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return ret;
}
INT wifi_hal_getRadioHT40Intolerant(wifi_radio_index_t radioIndex, BOOL *intol)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *iface;
    if (!intol) {
        wifi_hal_error_print("%s:%d: NULL intol pointer for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    radio = get_radio_by_rdk_index((unsigned int)radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: radio not found for index %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    iface = get_primary_interface(radio);
    if (!iface || !iface->u.ap.iface.conf) {
        wifi_hal_error_print("%s:%d: no primary interface or iconf for radio %d\n",
                             __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *intol = (iface->u.ap.iface.conf->ht_capab & HT_CAP_INFO_40MHZ_INTOLERANT) ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: radio=%d ht40intolerant=%d\n",
                       __func__, __LINE__, radioIndex, *intol);
    return RETURN_OK;
}

/*
 * R-UFR10-13: ECSA Opclass (WFA test)
 * Sets ecsa_opclass — used for CSA frames, NOT in beacon content.
 * No ieee802_11_update_beacons needed.
 */
INT wifi_hal_setApEcsaOpclass(INT apIndex, UCHAR opclass)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: apIndex=%d ecsa_opclass=%u\n",
                       __func__, __LINE__, apIndex, opclass);
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    i->u.ap.conf.bss_extn.ecsa_opclass = opclass;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_info_print("%s:%d: ecsa_opclass=%u set for apIndex %d\n",
                        __func__, __LINE__, opclass, apIndex);
#endif
    return RETURN_OK;
}
INT wifi_hal_getApEcsaOpclass(INT apIndex, UCHAR *opclass)
{
    wifi_interface_info_t *i;
    if (!opclass) {
        wifi_hal_error_print("%s:%d: NULL opclass pointer for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *opclass = i->u.ap.conf.bss_extn.ecsa_opclass;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: apIndex=%d ecsa_opclass=%u\n",
                       __func__, __LINE__, apIndex, *opclass);
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-14: EHT CCFS0 (WFA test)
 * Sets eht_config_ccfs0 + calls ieee802_11_update_beacons to push to kernel.
 */
INT wifi_hal_setApEhtConfigCcfs0(INT apIndex, BOOL enable)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    int ret = RETURN_OK;
    if (!i || !i->u.ap.iface.conf) {
        wifi_hal_error_print("%s:%d: interface or iconf not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: apIndex=%d eht_config_ccfs0=%d\n",
                       __func__, __LINE__, apIndex, enable);
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    i->u.ap.iface.conf->conf_extn.eht_config_ccfs0 = (bool)enable;
    if (i->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(i->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex %d\n",
                                 __func__, __LINE__, apIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: eht_config_ccfs0=%d set for apIndex %d\n",
                                __func__, __LINE__, enable, apIndex);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return ret;
}
INT wifi_hal_getApEhtConfigCcfs0(INT apIndex, BOOL *enable)
{
    wifi_interface_info_t *i;
    if (!enable) {
        wifi_hal_error_print("%s:%d: NULL enable pointer for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i || !i->u.ap.iface.conf) {
        wifi_hal_error_print("%s:%d: interface or iconf not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *enable = i->u.ap.iface.conf->conf_extn.eht_config_ccfs0 ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: apIndex=%d eht_config_ccfs0=%d\n",
                       __func__, __LINE__, apIndex, *enable);
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-16: TPE Common PSD (WFA test)
 * Sets tpe_common_psd + calls ieee802_11_update_beacons to push TPE IE to kernel.
 */
INT wifi_hal_setApTpeCommonPsd(INT apIndex, BOOL enable)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    int ret = RETURN_OK;
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_common_psd=%d\n",
                       __func__, __LINE__, apIndex, enable);
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    i->u.ap.conf.bss_extn.tpe_common_psd = (bool)enable;
    if (i->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(i->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex %d\n",
                                 __func__, __LINE__, apIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: tpe_common_psd=%d set for apIndex %d\n",
                                __func__, __LINE__, enable, apIndex);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return ret;
}
INT wifi_hal_getApTpeCommonPsd(INT apIndex, BOOL *enable)
{
    wifi_interface_info_t *i;
    if (!enable) {
        wifi_hal_error_print("%s:%d: NULL enable pointer for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *enable = i->u.ap.conf.bss_extn.tpe_common_psd ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_common_psd=%d\n",
                       __func__, __LINE__, apIndex, *enable);
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-17: TPE Power Unit (WFA test)
 * Sets tpe_tx_pwr_interp + calls ieee802_11_update_beacons to push TPE IE to kernel.
 */
INT wifi_hal_setApTpePwrUnit(INT apIndex, UCHAR unit)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    int ret = RETURN_OK;
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_pwr_unit=%u (%s)\n",
                       __func__, __LINE__, apIndex, unit,
                       unit == 1 ? "TPE_REG_EIRP" : "TPE_REG_EIRP_PSD");
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    i->u.ap.conf.bss_extn.tpe_tx_pwr_interp = (unit == 1) ? TPE_REG_EIRP : TPE_REG_EIRP_PSD;
    if (i->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(i->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex %d\n",
                                 __func__, __LINE__, apIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: tpe_pwr_unit=%u set for apIndex %d\n",
                                __func__, __LINE__, unit, apIndex);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return ret;
}
INT wifi_hal_getApTpePwrUnit(INT apIndex, UCHAR *unit)
{
    wifi_interface_info_t *i;
    if (!unit) {
        wifi_hal_error_print("%s:%d: NULL unit pointer for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *unit = (i->u.ap.conf.bss_extn.tpe_tx_pwr_interp == TPE_REG_EIRP) ? 1 : 0;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_pwr_unit=%u (%s)\n",
                       __func__, __LINE__, apIndex, *unit,
                       *unit == 1 ? "TPE_REG_EIRP" : "TPE_REG_EIRP_PSD");
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-18: TPE Puncture Channel Power (WFA test)
 * Sets tpe_punct_channel_tx_pwr + calls ieee802_11_update_beacons to push TPE IE to kernel.
 */
INT wifi_hal_setApTpePunctChanPwr(INT apIndex, BOOL enable)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    int ret = RETURN_OK;
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_punct_channel_tx_pwr=%d\n",
                       __func__, __LINE__, apIndex, enable);
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    i->u.ap.conf.bss_extn.tpe_punct_channel_tx_pwr = (bool)enable;
    if (i->u.ap.hapd_initialized) {
        if (ieee802_11_update_beacons(i->u.ap.hapd.iface) != 0) {
            wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex %d\n",
                                 __func__, __LINE__, apIndex);
            ret = RETURN_ERR;
        } else {
            wifi_hal_info_print("%s:%d: tpe_punct_channel_tx_pwr=%d set for apIndex %d\n",
                                __func__, __LINE__, enable, apIndex);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return ret;
}
INT wifi_hal_getApTpePunctChanPwr(INT apIndex, BOOL *enable)
{
    wifi_interface_info_t *i;
    if (!enable) {
        wifi_hal_error_print("%s:%d: NULL enable pointer for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex %d\n",
                             __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }
#ifdef QCA_UD_HOSTAPD
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    *enable = i->u.ap.conf.bss_extn.tpe_punct_channel_tx_pwr ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    wifi_hal_dbg_print("%s:%d: apIndex=%d tpe_punct_channel_tx_pwr=%d\n",
                       __func__, __LINE__, apIndex, *enable);
#endif
    return RETURN_OK;
}

/*
 * R-UFR10-12: Disable LPI Antenna Optimization (WFA test)
 * Sends QCA_WLAN_VENDOR_VDEV_PARAM_DIS_LPI_ANT_OPTIMIZE (62) via NL80211
 * subcmd SET_WIFI_CONFIGURATION (74) / GET_WIFI_CONFIGURATION (75).
 * Valid values: 0 = LPI ant optimization enabled (default)
 *               1 = LPI ant optimization disabled
 */
INT wifi_hal_setApDisLpiAntOptimize(INT apIndex, UINT enable)
{
    wifi_interface_info_t *i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) return RETURN_ERR;
    wifi_hal_dbg_print("%s:%d UFR10-12 SET DisLpiAntOptimize ap=%d val=%u\n",
                       __func__, __LINE__, apIndex, enable);
    return qca_vendor_param_set(i, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION,
                        QCA_WLAN_VENDOR_VDEV_PARAM_DIS_LPI_ANT_OPTIMIZE,
                        (int32_t)enable, -1);
}

INT wifi_hal_getApDisLpiAntOptimize(INT apIndex, UINT *enable)
{
    int32_t val = 0;
    wifi_interface_info_t *i;
    if (!enable) return RETURN_ERR;
    i = get_interface_by_vap_index((unsigned int)apIndex);
    if (!i) return RETURN_ERR;
    if (qca_vendor_param_get(i, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION,
                     QCA_WLAN_VENDOR_VDEV_PARAM_DIS_LPI_ANT_OPTIMIZE,
                     &val, -1) != RETURN_OK)
        return RETURN_ERR;
    *enable = (UINT)val;
    wifi_hal_dbg_print("%s:%d UFR10-12 GET DisLpiAntOptimize ap=%d val=%u\n",
                       __func__, __LINE__, apIndex, *enable);
    return RETURN_OK;
}

/*
 * wifi_getApRrmBeaconReport - retrieve the latest RRM beacon report data
 * for the given AP index via hostapd_cli show_rrm_beacon_report.
 * The output is copied into pValue (up to bufLen bytes).
 */

/* =========================================================================
 * WNM/RRM Beacon Report DMCLI HAL functions
 *
 * These functions provide runtime control of ieee80211k (RRM), ieee80211v
 * (WNM/BSS Transition), and RRM Beacon Report via the hostapd internal API.
 * They follow the same pattern as wifi_setApMbssidTx():
 *   - get_interface_by_vap_index()
 *   - pthread_mutex_lock(&g_wifi_hal.hapd_lock)
 *   - direct hapd->conf modification + ieee802_11_set_beacon()
 *   - pthread_mutex_unlock(&g_wifi_hal.hapd_lock)
 *
 * wifi_sendApRrmBeaconRequest() calls hostapd_send_beacon_req() which
 * clears hapd->bcn_report_db before sending the new request.
 * wifi_getApRrmBeaconReport() calls hostapd_show_rrm_bcn_report() which
 * reads from hapd->bcn_report_db populated when the STA responds.
 * ========================================================================= */

/* =========================================================================
 * IPQ beacon report callback storage
 * Stores parsed wifi_BeaconReport_t entries received via bcnrpt_callback.
 * wifi_getApRrmBeaconReport() reads from this buffer when populated.
 * ========================================================================= */
#define IPQ_BCNRPT_MAX_ENTRIES 64
#define IPQ_BCNRPT_BUF_LEN     8192
/* Storage must cover all possible apIndex values including 6GHz (apIndex=16).
 * MAX_AP_INDEX=15 with FEATURE_SINGLE_PHY, but 6GHz private VAP uses apIndex=16.
 * Use a fixed size of 24 to cover all current and future VAP indices. */
#define IPQ_BCNRPT_AP_MAX      24

/**
 * nl80211_vendor_response_handler - Callback for NL80211 vendor command responses
 */
static int nl80211_vendor_response_handler(struct nl_msg *msg, void *arg)
{
    nl80211_vendor_response_t *ctx = (nl80211_vendor_response_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *vendor_data;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA]) {
        wifi_hal_error_print("%s:%d: No vendor data in response\n",
                __func__, __LINE__);
        ctx->error = -ENODATA;
        return NL_SKIP;
    }

    vendor_data = tb[NL80211_ATTR_VENDOR_DATA];

    /* Parse nested vendor attributes up to CONFIG_MAX to cover all attrs
     * including QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA (19) and
     * QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX (150). */
    struct nlattr *vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    if (nla_parse_nested(vendor_tb, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX,
                vendor_data, NULL) < 0) {
        wifi_hal_error_print("%s:%d: Failed to parse vendor attributes\n",
                __func__, __LINE__);
        ctx->error = -EINVAL;
        return NL_SKIP;
    }

    /* Extract GENERIC_DATA attribute */
    if (vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]) {
        void *data = nla_data(vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]);
        size_t len = nla_len(vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]);

        if (ctx->data && len <= ctx->data_len) {
            memcpy(ctx->data, data, len);
            ctx->data_received = len;
        } else {
            wifi_hal_error_print("%s:%d: Response buffer too small (%zu > %zu)\n",
                    __func__, __LINE__, len, ctx->data_len);
            ctx->error = -ENOSPC;
            return NL_SKIP;
        }
    }

    return NL_OK;
}

/**
 * nl80211_get_reg_alpha2_handler - NL80211_CMD_GET_REG callback
 *
 * Extracts NL80211_ATTR_REG_ALPHA2 (2-char country code) from the kernel
 * regulatory domain response.  Used by wifi_getRadioRegdomain() as a
 * NL80211-only fallback when the QCA vendor command is not available.
 */
struct nl80211_reg_alpha2_ctx {
    char alpha2[3];   /* null-terminated 2-char country code */
    bool found;
};

static int nl80211_get_reg_alpha2_handler(struct nl_msg *msg, void *arg)
{
    struct nl80211_reg_alpha2_ctx *ctx = (struct nl80211_reg_alpha2_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_REG_ALPHA2]) {
        const char *a2 = (const char *)nla_data(tb[NL80211_ATTR_REG_ALPHA2]);
        ctx->alpha2[0] = a2[0];
        ctx->alpha2[1] = a2[1];
        ctx->alpha2[2] = '\0';
        ctx->found = true;
    }
    return NL_SKIP;
}

/**
 * nl80211_u32_response_ctx_t / nl80211_u32_response_handler
 *
 * Custom NL80211 response handler that extracts GENERIC_VALUE (u32).
 * The existing nl80211_vendor_response_handler only checks GENERIC_DATA;
 * band_info (RADIO_PARAM_BANDINFO) and list_band (VDEV_PARAM_LIST_BAND)
 * responses come back in GENERIC_VALUE instead.
 */
typedef struct {
    uint32_t value;
    bool     found;
    int      error;
} nl80211_u32_response_ctx_t;

static int nl80211_u32_response_handler(struct nl_msg *msg, void *arg)
{
    nl80211_u32_response_ctx_t *ctx = (nl80211_u32_response_ctx_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA]) {
        ctx->error = -ENODATA;
        return NL_SKIP;
    }

    if (nla_parse_nested(vendor_tb, QCA_WLAN_VENDOR_ATTR_CONFIG_MAX,
                tb[NL80211_ATTR_VENDOR_DATA], NULL) < 0) {
        ctx->error = -EINVAL;
        return NL_SKIP;
    }

    /* Kernel returns the value in GENERIC_VALUE (u32) for band_info / list_band */
    if (vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE]) {
        ctx->value = nla_get_u32(
                vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE]);
        ctx->found = true;
    } else if (vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]) {
        /* Fallback: some firmware versions use GENERIC_DATA */
        size_t len = nla_len(
                vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]);
        const uint8_t *d = nla_data(
                vendor_tb[QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA]);
        if (len >= 4)
            memcpy(&ctx->value, d, 4);
        else if (len >= 1)
            ctx->value = d[0];
        ctx->found = true;
    }

    return NL_OK;
}

/**
 * wifi_send_vendor_cmd_radio - Send NL80211 vendor command for per-radio operations
 */
static int wifi_send_vendor_cmd_radio(int wiphy_idx, int radio_idx,
        int subcmd, int param_id,
        const void *data, size_t data_len,
        void *response, size_t response_len)
{
    struct nl_msg *msg;
    struct nlattr *vendor_data;
    nl80211_vendor_response_t ctx = {
        .data = response,
        .data_len = response_len,
        .data_received = 0,
        .error = 0,
    };
    int ret;

    if (wiphy_idx < 0) {
        wifi_hal_error_print("%s:%d: Invalid wiphy_idx %d\n",
                __func__, __LINE__, wiphy_idx);
        return -EINVAL;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return -ENOMEM;
    }

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_WIPHY, (u32)wiphy_idx) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, (u32)subcmd)) {
        wifi_hal_error_print("%s:%d: Failed to build vendor command\n",
                __func__, __LINE__);
        nlmsg_free(msg);
        return -EINVAL;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    /* QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX (u8, attr=150) specifies which
     * hardware radio within the wiphy to target.  This is the correct attribute
     * for per-radio commands sent via NL80211_ATTR_WIPHY.
     * Previously QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_FLAGS (attr=21) was used
     * here, but that attribute is documented as "flags for GENERIC_DATA" and
     * is NOT a radio index selector — the kernel driver (ath12k) ignored it
     * and defaulted to radio index 255 (0xFF), causing:
     *   "ath12k: Invalid radio index 255 (valid range: 0..2)"
     */
    if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, WIFI_PARAMS) ||
            nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, (u32)param_id) ||
            nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX, (u8)radio_idx)) {
        nlmsg_free(msg);
        return -EINVAL;
    }

    if (data && data_len > 0) {
        if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA,
                    (int)data_len, data) < 0) {
            nlmsg_free(msg);
            return -EINVAL;
        }
    }
    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg,
            response ? nl80211_vendor_response_handler : NULL,
            response ? &ctx : NULL,
            NULL, NULL);

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: nl80211_send_and_recv failed: %d\n",
                __func__, __LINE__, ret);
        return ret;
    }

    if (ctx.error) {
        wifi_hal_error_print("%s:%d: Response handler error: %d\n",
                __func__, __LINE__, ctx.error);
        return ctx.error;
    }

    return 0;
}

/**
 * wifi_send_reg_params_cmd - Send NL80211 vendor command for REG_PARAMS operations
 *
 * Implements the disable_opclass_chans path using the correct vendor subcmd
 * QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS (518) with the REG_PARAMS attributes
 * defined in the OpenWrt patches (836c025.diff / a6c86aa.diff).
 *
 * This mirrors nl80211_disable_opclass_chans_extn() from
 * hostapd/src/driver_nl80211_extn.c which is the reference implementation
 * for OpenWrt.  In RDK, hostapd is a library so we build the NL80211 message
 * directly using rdk-wifi-hal's nl80211_send_and_recv() instead of the
 * hostapd nl80211_bss_msg() / send_and_recv_cmd() helpers.
 *
 * NL80211 message structure (from driver_nl80211_extn.c):
 *   NL80211_CMD_VENDOR
 *     NL80211_ATTR_IFINDEX = interface->index
 *     NL80211_ATTR_VENDOR_ID = OUI_QCA
 *     NL80211_ATTR_VENDOR_SUBCMD = 518 (QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS)
 *     NL80211_ATTR_VENDOR_DATA (nested):
 *       attr[1] = cmd  (u8) = 4 (DISABLE_OPCLASS_CHANS)
 *       attr[3] = link_id (u8)
 *       attr[4] = disable (u8, 0=enable 1=disable)
 *       attr[5] = opclass (u8)
 *       attr[6] (nested) = channel list:
 *           attr[1] = chan[0] (u8)
 *           attr[2] = chan[1] (u8)
 *           ...
 *
 * @interface:    WiFi interface info
 * @link_id:      MLO link ID (or -1 for non-MLO, uses 0)
 * @disable:      1 to disable channels, 0 to enable channels
 * @opclass:      Operating class number
 * @channels:     Array of channel numbers
 * @num_channels: Number of channels in the array
 *
 * Returns: 0 on success, negative errno on failure
 */
static int wifi_send_reg_params_cmd(wifi_interface_info_t *interface, int link_id,
        int disable, unsigned char opclass,
        unsigned char *channels, int num_channels)
{
    struct nl_msg *msg;
    struct nlattr *vendor_data;
    struct nlattr *chan_attr;
    int ret;
    size_t idx;

    if (!interface || !channels || num_channels <= 0) {
        wifi_hal_error_print("%s:%d: Invalid parameters\n", __func__, __LINE__);
        return -EINVAL;
    }

    if (num_channels > 256) {
        wifi_hal_error_print("%s:%d: Too many channels: %d (max 256)\n",
                __func__, __LINE__, num_channels);
        return -EINVAL;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return -ENOMEM;
    }

    /* Use QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS (518) — the dedicated subcmd
     * for regulatory parameter operations including disable_opclass_chans.
     * The previous approach used QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION
     * (74) with GENERIC_COMMAND/VALUE/DATA which is NOT the correct path for
     * this operation and caused:
     *   "ath12k: Failed to set wifi params" / kernel error -22
     */
    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)interface->index) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS)) {
        wifi_hal_error_print("%s:%d: Failed to build vendor command\n",
                __func__, __LINE__);
        nlmsg_free(msg);
        return -EINVAL;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    /* attr[1] = CMD = DISABLE_OPCLASS_CHANS (4) */
    if (nla_put_u8(msg, REG_PARAMS_ATTR_CMD,
                REG_PARAMS_CMD_DISABLE_OPCLASS_CHANS) ||
            /* attr[3] = LINKID */
            nla_put_u8(msg, REG_PARAMS_ATTR_LINKID,
                (u8)(link_id >= 0 ? link_id : 0)) ||
            /* attr[4] = DISABLE (0=enable, 1=disable) */
            nla_put_u8(msg, REG_PARAMS_ATTR_DISABLE, (u8)disable) ||
            /* attr[5] = OPCLASS */
            nla_put_u8(msg, REG_PARAMS_ATTR_OPCLASS, opclass)) {
        wifi_hal_error_print("%s:%d: Failed to put REG_PARAMS scalar attrs\n",
                __func__, __LINE__);
        nlmsg_free(msg);
        return -EINVAL;
    }

    /* attr[6] = CHAN_LIST (nested): each channel as u8 with index 1..N */
    chan_attr = nla_nest_start(msg, REG_PARAMS_ATTR_CHAN_LIST);
    if (!chan_attr) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    for (idx = 0; idx < (size_t)num_channels; idx++) {
        if (nla_put_u8(msg, (int)(idx + 1), channels[idx])) {
            wifi_hal_error_print("%s:%d: Failed to put channel[%zu]=%u\n",
                    __func__, __LINE__, idx, channels[idx]);
            nla_nest_end(msg, chan_attr);
            nlmsg_free(msg);
            return -ENOBUFS;
        }
    }

    nla_nest_end(msg, chan_attr);
    nla_nest_end(msg, vendor_data);

    wifi_hal_info_print("%s:%d: REG_PARAMS subcmd=518 disable=%d opclass=%u"
            " link_id=%d channels=%d\n",
            __func__, __LINE__, disable, opclass,
            link_id >= 0 ? link_id : 0, num_channels);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: nl80211_send_and_recv failed: %d\n",
                __func__, __LINE__, ret);
        return ret;
    }

    return 0;
}

/**
 * get_wiphy_radio_idx - Map RDK radio index to wiphy and radio_idx
 */
static int get_wiphy_radio_idx(INT radioIndex, int *wiphy_idx, int *radio_idx)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    if (!wiphy_idx || !radio_idx) {
        wifi_hal_error_print("%s:%d: NULL output parameters\n", __func__, __LINE__);
        return -1;
    }

    radio = get_radio_by_rdk_index(radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: Radio not found for index %d\n",
                __func__, __LINE__, radioIndex);
        return -1;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        wifi_hal_error_print("%s:%d: Primary interface not found for radio %d\n",
                __func__, __LINE__, radioIndex);
        return -1;
    }

    *wiphy_idx = interface->phy_index;
    *radio_idx = radioIndex;

    wifi_hal_dbg_print("%s:%d: radioIndex=%d → wiphy_idx=%d radio_idx=%d\n",
            __func__, __LINE__, radioIndex, *wiphy_idx, *radio_idx);

    return 0;
}

/**
 * wifi_setRadioCountryCode - Set regulatory country code for a radio
 *
 * Uses NL80211_CMD_REQ_SET_REG with NL80211_ATTR_REG_ALPHA2 — identical to
 * 'iw reg set <alpha2>'.  This is the standard kernel regulatory path and
 * works on ath12k without requiring QCA vendor commands.
 */
INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
    struct nl_msg *msg;
    char alpha2[3];
    int ret;

    if (!CountryCode || strlen(CountryCode) != 2) {
        wifi_hal_error_print("%s:%d: Invalid country code\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    alpha2[0] = CountryCode[0];
    alpha2[1] = CountryCode[1];
    alpha2[2] = '\0';

    wifi_hal_info_print("%s:%d: Setting country code '%s' for radio %d"
            " via NL80211_CMD_REQ_SET_REG\n",
            __func__, __LINE__, alpha2, radioIndex);

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* Build NL80211_CMD_REQ_SET_REG + NL80211_ATTR_REG_ALPHA2 — same as iw */
    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_REQ_SET_REG, 0) ||
            nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, alpha2) < 0) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: NL80211_CMD_REQ_SET_REG failed: %d\n",
                __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Country code '%s' set for radio %d\n",
            __func__, __LINE__, alpha2, radioIndex);
    usleep(100000);  /* 100ms — allow regulatory change to propagate */
    return RETURN_OK;
}

/**
 * wifi_getRadioCountryCode - Get regulatory country code for a radio
 *
 * Uses NL80211_CMD_GET_REG with NLM_F_DUMP and reads NL80211_ATTR_REG_ALPHA2
 * — identical to 'iw reg get'.  This is the standard kernel regulatory path
 * and works on ath12k without requiring QCA vendor commands.
 */
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
    struct nl80211_reg_alpha2_ctx reg_ctx;
    struct nl_msg *msg;
    int ret;

    if (!output_string) {
        wifi_hal_error_print("%s:%d: NULL output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(&reg_ctx, 0, sizeof(reg_ctx));

    /* Use NL80211_CMD_GET_REG with NLM_F_DUMP — same as 'iw reg get'.
     * The kernel returns NL80211_ATTR_REG_ALPHA2 with the current country. */
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP,
            NL80211_CMD_GET_REG);
    if (!msg) {
        wifi_hal_error_print("%s:%d: Failed to allocate NL message\n",
                __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, nl80211_get_reg_alpha2_handler,
            &reg_ctx, NULL, NULL);
    if (ret < 0 || !reg_ctx.found || reg_ctx.alpha2[0] == '\0') {
        wifi_hal_error_print(
                "%s:%d: NL80211_CMD_GET_REG failed for radio %d:"
                " ret=%d found=%d\n",
                __func__, __LINE__, radioIndex, ret, reg_ctx.found);
        return RETURN_ERR;
    }

    output_string[0] = reg_ctx.alpha2[0];
    output_string[1] = reg_ctx.alpha2[1];
    output_string[2] = '\0';

    wifi_hal_info_print("%s:%d: Radio %d country code: '%s'\n",
            __func__, __LINE__, radioIndex, output_string);

    return RETURN_OK;
}

/* Forward declaration: defined later in this file, after wifi_getRadioCountryID() */
static int param_data_u32_nl80211_handler(struct nl_msg *msg, void *arg);

INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string)
{
    int                         wiphy_idx, radio_idx;
    nl80211_u32_response_ctx_t  ctx = {0};
    struct nl_msg              *msg;
    struct nlattr              *vendor_data;
    int                         ret;

    if (!output_string) {
        wifi_hal_error_print("%s:%d: NULL output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (get_wiphy_radio_idx(radioIndex, &wiphy_idx, &radio_idx) < 0)
        return RETURN_ERR;

    /* Send QCA vendor command: GET_WIPHY_CONFIGURATION + RADIO_PARAM_BANDINFO (81)
     * targeting the specific hardware radio within the wiphy via
     * QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX.
     *
     * This is the NL80211 equivalent of:
     *   cfg80211tool <phy_name> radio_idx <N> get_bandinfo
     *
     * Band values returned in PARAM_DATA (u32):
     *   0: NO_BAND_INFORMATION_AVAILABLE
     *   1: HIGH_BAND_5G_RADIO   (5490-5835 MHz)
     *   2: FULL_BAND_5G_RADIO
     *   3: LOW_BAND_5G_RADIO    (5170-5330 MHz)
     *   4: NON_5G_RADIO         (2.4 GHz)
     *   5: FULL_BAND_6G_RADIO   (5945-7125 MHz)
     *   6: BAND_5G_6G_RADIO
     *   7: LOW_BAND_6G_RADIO
     *   8: HIGH_BAND_6G_RADIO
     */
    msg = nlmsg_alloc();
    if (!msg) return RETURN_ERR;

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_WIPHY, (u32)wiphy_idx) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) { nlmsg_free(msg); return RETURN_ERR; }

    if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND,
                WIFI_PARAMS) ||
            nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE,
                RADIO_PARAM_BANDINFO) ||
            nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX,
                (u8)radio_idx)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg, param_data_u32_nl80211_handler,
            &ctx, NULL, NULL);
    if (ret < 0 || !ctx.found) {
        wifi_hal_error_print(
                "%s:%d: Failed to get band info for radio %d:"
                " ret=%d found=%d\n",
                __func__, __LINE__, radioIndex, ret, ctx.found);
        return RETURN_ERR;
    }

    snprintf(output_string, 32, "%u", ctx.value);

    wifi_hal_info_print("%s:%d: Radio %d band info: %s\n",
            __func__, __LINE__, radioIndex, output_string);
    return RETURN_OK;
}

/* Context for list_chan NL80211 response handler */
struct list_chan_ctx {
    char   *buf;
    size_t  buf_len;
    bool    found;
};

/* =========================================================================
 * Center channel computation helpers
 *
 * These compute the 80/160/320 MHz center channel numbers matching the
 * output format of cfg80211tool list_chan / display_band_chans.
 * ========================================================================= */

/** chan_get_80mhz_center_5ghz - 80MHz center channel for 5GHz */
static int chan_get_80mhz_center_5ghz(int channel)
{
    if (channel >= 36  && channel <= 48)  return 42;
    if (channel >= 52  && channel <= 64)  return 58;
    if (channel >= 100 && channel <= 112) return 106;
    if (channel >= 116 && channel <= 128) return 122;
    if (channel >= 132 && channel <= 144) return 138;
    if (channel >= 149 && channel <= 161) return 155;
    return 0;
}

/** chan_get_160mhz_center_5ghz - 160MHz center channel for 5GHz */
static int chan_get_160mhz_center_5ghz(int channel)
{
    if (channel >= 36  && channel <= 64)  return 50;
    if (channel >= 100 && channel <= 128) return 114;
    if (channel >= 149 && channel <= 177) return 163;
    return 0;
}

/**
 * chan_get_80mhz_center_6ghz - 80MHz center channel for 6GHz
 * 6GHz channels: 1,5,9,13,17,21,25,29,33,...  (4-channel groups)
 * Formula: center = ((channel - 1) / 16) * 16 + 7
 */
static int chan_get_80mhz_center_6ghz(int channel)
{
    if (channel < 1 || channel > 233)
        return 0;
    return ((channel - 1) / 16) * 16 + 7;
}

/**
 * chan_get_160mhz_center_6ghz - 160MHz center channel for 6GHz
 * Formula: center = ((channel - 1) / 32) * 32 + 15
 */
static int chan_get_160mhz_center_6ghz(int channel)
{
    if (channel < 1 || channel > 233)
        return 0;
    return ((channel - 1) / 32) * 32 + 15;
}

/**
 * chan_get_320mhz_centers_6ghz - 320MHz center channels for 6GHz
 *
 * A channel can belong to up to two overlapping 320MHz groups.
 * Groups start at 1, 33, 65, 97, 129, 161 (every 32 channels).
 * Each group spans 64 channel numbers (channels start + 0..60).
 * Center = group_start + 30.
 *
 * Returns the number of valid centers (0, 1, or 2).
 */
static int chan_get_320mhz_centers_6ghz(int channel, int *center1, int *center2)
{
    int count = 0;
    int k;

    *center1 = 0;
    *center2 = 0;

    /* Groups: k=1..6, start = 1 + (k-1)*32, end = start+60, center = start+30 */
    for (k = 1; k <= 6; k++) {
        int gs = 1 + (k - 1) * 32;
        int ge = gs + 60;
        int gc = gs + 30;

        if (channel >= gs && channel <= ge) {
            if (count == 0)
                *center1 = gc;
            else
                *center2 = gc;
            count++;
            if (count == 2)
                break;
        }
    }
    return count;
}

/* =========================================================================
 * wiphy_chan_ctx / wiphy_chan_handler
 *
 * Fallback channel list extraction via NL80211_CMD_GET_WIPHY.
 * Used when the QCA vendor command VDEV_PARAM_LIST_CHAN returns empty.
 * Parses NL80211_ATTR_WIPHY_BANDS → NL80211_BAND_ATTR_FREQS and builds
 * a detailed per-channel string matching cfg80211tool list_chan format:
 *
 *   Channel  36 : 5180   Mhz 11na C CU V VU V80- 42 H HU H80- 42 H160- 50 E EU E80- 42 E160- 50
 *   Channel  52 : 5260 ~ Mhz 11na C CU V VU V80- 58 H HU H80- 58 H160- 50 E EU E80- 58 E160- 50
 *   Channel   1 : 5955   Mhz  H HU H80-  7 H160- 15 E EU E80-  7 E160- 15 E320- 31,   0
 *   Channel   1 : 2412   Mhz 11ng C CU H HU E EU
 *
 * Band mapping (NL80211 enum → iw phy "Band N"):
 *   NL80211_BAND_2GHZ (0) → Band 1  (2.4 GHz)
 *   NL80211_BAND_5GHZ (1) → Band 2  (5 GHz)
 *   NL80211_BAND_6GHZ (3) → Band 4  (6 GHz)
 * ========================================================================= */
struct wiphy_chan_ctx {
    char         *buf;
    size_t        buf_len;
    unsigned int  target_band; /* NL80211 band enum value */
    bool          found;
};

static int wiphy_chan_handler(struct nl_msg *msg, void *arg)
{
    struct wiphy_chan_ctx *ctx = (struct wiphy_chan_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_band;
    int rem_band;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
        struct nlattr *band_tb[NL80211_BAND_ATTR_MAX + 1];
        struct nlattr *nl_freq;
        int rem_freq;

        /* nl_band->nla_type is the NL80211 band enum value */
        if ((unsigned int)nl_band->nla_type != ctx->target_band)
            continue;

        nla_parse(band_tb, NL80211_BAND_ATTR_MAX,
                nla_data(nl_band), nla_len(nl_band), NULL);

        if (!band_tb[NL80211_BAND_ATTR_FREQS])
            continue;

        nla_for_each_nested(nl_freq, band_tb[NL80211_BAND_ATTR_FREQS], rem_freq) {
            struct nlattr *freq_tb[NL80211_FREQUENCY_ATTR_MAX + 1];
            uint32_t freq_mhz;
            uint channel = 0;
            size_t cur_len;
            /* Per-channel line buffer — large enough for the longest 6GHz line */
            char line[256];
            char flags[192];
            int flen = 0;
            int is_dfs, no_ht40plus, no_ht40minus, no_80mhz, no_160mhz;
            int is_cu, is_cl;
            int c80, c160, c320_1, c320_2;
            const char *mode_str;

            nla_parse(freq_tb, NL80211_FREQUENCY_ATTR_MAX,
                    nla_data(nl_freq), nla_len(nl_freq), NULL);

            if (!freq_tb[NL80211_FREQUENCY_ATTR_FREQ])
                continue;

            /* Skip disabled channels */
            if (freq_tb[NL80211_FREQUENCY_ATTR_DISABLED])
                continue;

            freq_mhz = nla_get_u32(freq_tb[NL80211_FREQUENCY_ATTR_FREQ]);

            if (wifi_freq_to_channel((int)freq_mhz, &channel) != RETURN_OK)
                continue;

            /* Parse NL80211 channel capability flags */
            is_dfs       = (freq_tb[NL80211_FREQUENCY_ATTR_RADAR]        != NULL);
            no_ht40plus  = (freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS] != NULL);
            no_ht40minus = (freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS]!= NULL);
            no_80mhz     = (freq_tb[NL80211_FREQUENCY_ATTR_NO_80MHZ]     != NULL);
            no_160mhz    = (freq_tb[NL80211_FREQUENCY_ATTR_NO_160MHZ]    != NULL);

            /* CU = upper primary (HT40-), CL = lower primary (HT40+)
             * NO_HT40_MINUS → cannot be upper primary → no CU
             * NO_HT40_PLUS  → cannot be lower primary → no CL */
            is_cu = !no_ht40minus;
            is_cl = !no_ht40plus;

            /* Mode string: 11na (5GHz), 11ng (2.4GHz), empty (6GHz) */
            if (ctx->target_band == NL80211_BAND_2GHZ)
                mode_str = "11ng";
            else if (ctx->target_band == NL80211_BAND_5GHZ)
                mode_str = "11na";
            else
                mode_str = "";

            /* Compute center channels for each bandwidth */
            c80 = c160 = c320_1 = c320_2 = 0;
            if (!no_80mhz) {
                if (ctx->target_band == NL80211_BAND_5GHZ)
                    c80 = chan_get_80mhz_center_5ghz((int)channel);
                else if (ctx->target_band == NL80211_BAND_6GHZ)
                    c80 = chan_get_80mhz_center_6ghz((int)channel);
            }
            if (!no_160mhz) {
                if (ctx->target_band == NL80211_BAND_5GHZ)
                    c160 = chan_get_160mhz_center_5ghz((int)channel);
                else if (ctx->target_band == NL80211_BAND_6GHZ)
                    c160 = chan_get_160mhz_center_6ghz((int)channel);
            }
            if (ctx->target_band == NL80211_BAND_6GHZ)
                chan_get_320mhz_centers_6ghz((int)channel, &c320_1, &c320_2);

            /* ── Build the flags string ──────────────────────────────── */
            flags[0] = '\0';
            flen = 0;

            /* 5GHz / 2.4GHz: C CU/CL (HT20 / 40MHz) */
            if (ctx->target_band == NL80211_BAND_5GHZ ||
                    ctx->target_band == NL80211_BAND_2GHZ) {
                flen += snprintf(flags + flen, sizeof(flags) - flen, " C");
                if (is_cu)
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " CU");
                if (is_cl)
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " CL");
            }

            /* 5GHz only: V VU/VL V80-<center> (VHT 80MHz) */
            if (ctx->target_band == NL80211_BAND_5GHZ && c80 > 0) {
                flen += snprintf(flags + flen, sizeof(flags) - flen, " V");
                if (is_cu)
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " VU");
                if (is_cl)
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " VL");
                flen += snprintf(flags + flen, sizeof(flags) - flen, " V80-%3d", c80);
            }

            /* H HU/HL H80-<center> H160-<center> (HE) */
            {
                int has_h = (ctx->target_band == NL80211_BAND_2GHZ)
                    ? (is_cu || is_cl) : 1;
                if (has_h) {
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " H");
                    if (is_cu)
                        flen += snprintf(flags + flen, sizeof(flags) - flen, " HU");
                    if (is_cl)
                        flen += snprintf(flags + flen, sizeof(flags) - flen, " HL");
                    if (c80 > 0)
                        flen += snprintf(flags + flen, sizeof(flags) - flen,
                                " H80-%3d", c80);
                    if (c160 > 0)
                        flen += snprintf(flags + flen, sizeof(flags) - flen,
                                " H160-%3d", c160);
                }
            }

            /* E EU/EL E80-<center> E160-<center> E320-<c1>,<c2> (EHT) */
            {
                int has_e = (ctx->target_band == NL80211_BAND_2GHZ)
                    ? (is_cu || is_cl) : 1;
                if (has_e) {
                    flen += snprintf(flags + flen, sizeof(flags) - flen, " E");
                    if (is_cu)
                        flen += snprintf(flags + flen, sizeof(flags) - flen, " EU");
                    if (is_cl)
                        flen += snprintf(flags + flen, sizeof(flags) - flen, " EL");
                    if (c80 > 0)
                        flen += snprintf(flags + flen, sizeof(flags) - flen,
                                " E80-%3d", c80);
                    if (c160 > 0)
                        flen += snprintf(flags + flen, sizeof(flags) - flen,
                                " E160-%3d", c160);
                    if (ctx->target_band == NL80211_BAND_6GHZ && c320_1 > 0)
                        flen += snprintf(flags + flen, sizeof(flags) - flen,
                                " E320-%3d,%4d", c320_1, c320_2);
                }
            }

            /* ── Assemble the full line ───────────────────────────────
             * Format (matches cfg80211tool list_chan / display_band_chans):
             *   Channel  36 : 5180   Mhz 11na C CU V VU V80- 42 ...
             *   Channel  52 : 5260 ~ Mhz 11na C CU V VU V80- 58 ...
             *   Channel   1 : 5955   Mhz  H HU H80-  7 ...
             *   Channel   1 : 2412   Mhz 11ng C CU H HU E EU
             *
             * DFS marker: "~ " replaces "  " (2 chars) after the frequency.
             * Mode string: "11na"/"11ng" for 5/2.4 GHz, " " (space) for 6GHz
             * so the total width before the flags is always the same.
             */
            snprintf(line, sizeof(line),
                    "Channel %3u : %4u %s Mhz %s%s\n",
                    channel,
                    freq_mhz,
                    is_dfs ? "~" : " ",   /* 1 char: ~ or space */
                    mode_str[0] ? mode_str : " ", /* 4 chars: 11na/11ng or space */
                    flags);

            cur_len = strlen(ctx->buf);
            if (cur_len + strlen(line) < ctx->buf_len - 1) {
                strlcat(ctx->buf, line, sizeof(ctx->buf));
                ctx->found = true;
            }
        }
        break; /* Found the target band — stop iterating */
    }

    return NL_SKIP;
}

/**
 * list_chan_nl80211_handler - NL80211 response handler for VDEV_PARAM_LIST_CHAN.
 *
 * Root cause of the previous failure:
 *   The driver returns the channel list as a comma-separated string in
 *   QCA_WLAN_VENDOR_ATTR_PARAM_DATA (attr=1) from enum qca_wlan_genric_data
 *   (defined in cfg80211_nlwrapper_pvt.h):
 *
 *     QCA_WLAN_VENDOR_ATTR_PARAM_INVALID = 0
 *     QCA_WLAN_VENDOR_ATTR_PARAM_DATA    = 1  ← channel list string here
 *     QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH  = 2
 *     QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS   = 3
 *
 *   The previous nl80211_vendor_response_handler only checked
 *   QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA (attr=19), which is a completely
 *   different attribute — so the response always appeared empty.
 */
static int list_chan_nl80211_handler(struct nl_msg *msg, void *arg)
{
    struct list_chan_ctx *ctx = (struct list_chan_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    /* QCA_WLAN_VENDOR_ATTR_PARAM_MAX = 3, so we need 4 slots */
    struct nlattr *vendor_tb[4];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    const char *data;
    size_t data_len;
    size_t copy_len;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA])
        return NL_SKIP;

    /* Parse vendor data with QCA_WLAN_VENDOR_ATTR_PARAM_MAX = 3 */
    if (nla_parse_nested(vendor_tb, 3,
                tb[NL80211_ATTR_VENDOR_DATA], NULL) < 0)
        return NL_SKIP;

    /* QCA_WLAN_VENDOR_ATTR_PARAM_DATA = 1 */
    if (!vendor_tb[1])
        return NL_SKIP;

    data     = (const char *)nla_data(vendor_tb[1]);
    data_len = (size_t)nla_len(vendor_tb[1]);

    if (data && data_len > 0 && ctx->buf && ctx->buf_len > 1) {
        copy_len = (data_len < ctx->buf_len - 1) ? data_len : ctx->buf_len - 1;
        memcpy(ctx->buf, data, copy_len);
        ctx->buf[copy_len] = '\0';
        ctx->found = true;
    }

    return NL_OK;
}

/**
 * wifi_getRadioPossibleChannels - Get list of possible channels for a radio.
 *
 * Sends QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION with
 * VDEV_PARAM_LIST_CHAN (71) via the primary interface and parses the
 * response using list_chan_nl80211_handler which correctly reads
 * QCA_WLAN_VENDOR_ATTR_PARAM_DATA (attr=1).
 *
 * For MLO interfaces the link_id is included so the driver returns the
 * channel list for the correct per-link radio.
 */
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)
{
    wifi_radio_info_t     *radio;
    wifi_interface_info_t *interface;
    int                    link_id = -1;
    struct nl_msg         *msg;
    struct nlattr         *vendor_data;
    struct list_chan_ctx   ctx;
    int                    ret;

    if (!output_string) {
        wifi_hal_error_print("%s:%d: NULL output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: Radio not found for index %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        wifi_hal_error_print("%s:%d: Primary interface not found for radio %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    /* For MLO interfaces include the link_id so the driver returns the
     * channel list for the correct per-link radio (mld0/mld1/mld6). */
    if (interface->mld_name[0] != '\0') {
        link_id = wifi_hal_get_mld_link_id(interface);
    }

    wifi_hal_info_print("%s:%d: Getting channel list for radio %d"
            " (iface=%s link_id=%d)\n",
            __func__, __LINE__, radioIndex, interface->name, link_id);

    /* Buffer size for detailed channel list format (cfg80211tool list_chan style):
     * 6GHz has ~60 channels × ~90 chars/line = ~5400 bytes.
     * Use 8192 to be safe for all bands. The caller must provide a buffer
     * of at least this size (DML handlers use 8192-byte local buffers). */
    memset(&ctx, 0, sizeof(ctx));
    ctx.buf     = output_string;
    ctx.buf_len = 8192;
    output_string[0] = '\0';

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_IFINDEX, (u32)interface->index) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) { nlmsg_free(msg); return RETURN_ERR; }

    if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, WIFI_PARAMS) ||
            nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE, VDEV_PARAM_LIST_CHAN)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    if (link_id >= 0 &&
            nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_MLO_LINK_ID, (u8)link_id) < 0) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg, list_chan_nl80211_handler, &ctx, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Failed to get channel list for radio %d: %d\n",
                __func__, __LINE__, radioIndex, ret);
        return RETURN_ERR;
    }

    if (!ctx.found || output_string[0] == '\0') {
        /* QCA vendor command returned empty — fall back to NL80211_CMD_GET_WIPHY.
         * This outputs in the same detailed cfg80211tool list_chan format using
         * the wiphy_chan_handler which computes center channels from NL80211
         * frequency attributes.
         *
         * NL80211 band enum → radio band mapping:
         *   NL80211_BAND_2GHZ (0) = 2.4 GHz
         *   NL80211_BAND_5GHZ (1) = 5 GHz
         *   NL80211_BAND_6GHZ (3) = 6 GHz  (Band 4 in 'iw phy' output)
         */
        unsigned int target_band;
        struct wiphy_chan_ctx wiphy_ctx;
        struct nl_msg *wiphy_msg;

        wifi_hal_info_print("%s:%d: QCA vendor cmd returned empty for radio %d"
                " — falling back to NL80211_CMD_GET_WIPHY\n",
                __func__, __LINE__, radioIndex);

        switch (radio->oper_param.band) {
            case WIFI_FREQUENCY_2_4_BAND:
                target_band = NL80211_BAND_2GHZ;   /* 0 */
                break;
            case WIFI_FREQUENCY_5_BAND:
            case WIFI_FREQUENCY_5L_BAND:
            case WIFI_FREQUENCY_5H_BAND:
                target_band = NL80211_BAND_5GHZ;   /* 1 */
                break;
            case WIFI_FREQUENCY_6_BAND:
                target_band = NL80211_BAND_6GHZ;   /* 3 */
                break;
            default:
                wifi_hal_error_print("%s:%d: Unknown band %d for radio %d\n",
                        __func__, __LINE__, radio->oper_param.band, radioIndex);
                return RETURN_ERR;
        }

        memset(&wiphy_ctx, 0, sizeof(wiphy_ctx));
        wiphy_ctx.buf         = output_string;
        wiphy_ctx.buf_len     = 8192;  /* same as ctx.buf_len above */
        wiphy_ctx.target_band = target_band;
        wiphy_ctx.found       = false;
        output_string[0]      = '\0';

        wiphy_msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL,
                NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
        if (wiphy_msg) {
            if (nla_put_u32(wiphy_msg, NL80211_ATTR_WIPHY,
                        (u32)interface->phy_index) < 0 ||
                    nla_put_flag(wiphy_msg, NL80211_ATTR_SPLIT_WIPHY_DUMP) < 0) {
                nlmsg_free(wiphy_msg);
                wiphy_msg = NULL;
            } else {
                nl80211_send_and_recv(wiphy_msg, wiphy_chan_handler,
                        &wiphy_ctx, NULL, NULL);
            }
        }

        if (!wiphy_ctx.found || output_string[0] == '\0') {
            wifi_hal_error_print(
                    "%s:%d: Both QCA vendor cmd and NL80211_CMD_GET_WIPHY"
                    " failed to return channel list for radio %d\n",
                    __func__, __LINE__, radioIndex);
            return RETURN_ERR;
        }

        wifi_hal_info_print("%s:%d: Radio %d possible channels (wiphy fallback): %s\n",
                __func__, __LINE__, radioIndex, output_string);
        return RETURN_OK;
    }

    wifi_hal_info_print("%s:%d: Radio %d possible channels: %s\n",
            __func__, __LINE__, radioIndex, output_string);
    return RETURN_OK;
}

INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)
{
    wifi_radio_info_t     *radio;
    wifi_interface_info_t *interface;
    int                    link_id = -1;
    char                   cmd[128];
    char                   buf[64];
    FILE                  *fp;
    char                  *ptr;

    if (!output_string) {
        wifi_hal_error_print("%s:%d: NULL output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: Radio not found for index %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        wifi_hal_error_print("%s:%d: Primary interface not found for radio %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    /* Execute cfg80211tool <iface>:<link_id> list_band
     * For MLO interfaces use mld_name:<link_id> format.
     * For non-MLO interfaces use the interface name directly.
     *
     * Sample output:
     *   phy00-mld0      list_band:1   (2.4 GHz  → bit0)
     *   phy00-mld0      list_band:2   (5 GHz    → bit1)
     *   phy00-mld0      list_band:4   (6 GHz    → bit2)
     *
     * Band bitmap: bit0=2.4GHz, bit1=5GHz, bit2=6GHz
     */
    if (interface->mld_name[0] != '\0') {
        link_id = wifi_hal_get_mld_link_id(interface);
        snprintf(cmd, sizeof(cmd), "cfg80211tool %s:%d list_band",
                interface->mld_name, link_id);
    } else {
        snprintf(cmd, sizeof(cmd), "cfg80211tool %s list_band",
                interface->name);
    }

    wifi_hal_info_print("%s:%d: Executing: %s\n", __func__, __LINE__, cmd);

    fp = popen(cmd, "r");
    if (!fp) {
        wifi_hal_error_print("%s:%d: popen failed for cmd: %s\n",
                __func__, __LINE__, cmd);
        return RETURN_ERR;
    }

    memset(buf, 0, sizeof(buf));
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        pclose(fp);
        wifi_hal_error_print("%s:%d: No output from cmd: %s\n",
                __func__, __LINE__, cmd);
        return RETURN_ERR;
    }
    pclose(fp);

    /* Parse output: "<iface>      list_band:<value>" */
    ptr = strstr(buf, "list_band:");
    if (!ptr) {
        wifi_hal_error_print("%s:%d: Unexpected output format from '%s': %s\n",
                __func__, __LINE__, cmd, buf);
        return RETURN_ERR;
    }
    ptr += strlen("list_band:");

    /* Strip trailing whitespace/newline */
    {
        size_t len = strlen(ptr);
        while (len > 0 && (ptr[len - 1] == '\n' || ptr[len - 1] == '\r' ||
                    ptr[len - 1] == ' '))
            ptr[--len] = '\0';
    }

    /* Return the raw numeric value as a string.
     * The DM parameter X_IPQ_SupportedBands expects the raw band bitmap:
     *   1 = 2.4 GHz (bit0)
     *   2 = 5 GHz   (bit1)
     *   4 = 6 GHz   (bit2)
     * This matches the cfg80211tool list_band output directly. */
    snprintf(output_string, 32, "%u", (unsigned int)atoi(ptr));

    wifi_hal_info_print("%s:%d: Radio %d supported bands: %s\n",
            __func__, __LINE__, radioIndex, output_string);
    return RETURN_OK;
}


/**
 * wifi_setRadioCountryID - Set regulatory country code by numeric ID
 *
 * The ath12k kernel driver expects a u32 (4 bytes) for the country ID.
 * Previously uint16_t (2 bytes) was used, causing:
 *   "ath12k: Invalid country id data len: 2"
 */
INT wifi_setRadioCountryID(INT radioIndex, UINT CountryID)
{
    int wiphy_idx, radio_idx;
    uint32_t country_id = (uint32_t)CountryID;  /* kernel expects u32, not u16 */
    int ret;

    if (get_wiphy_radio_idx(radioIndex, &wiphy_idx, &radio_idx) < 0) {
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Setting country ID %u for radio %d\n",
            __func__, __LINE__, CountryID, radioIndex);

    ret = wifi_send_vendor_cmd_radio(wiphy_idx, radio_idx,
            QCA_NL80211_VENDOR_SUBCMD_SET_WIPHY_CONFIGURATION,
            RADIO_PARAM_COUNTRY_ID,
            &country_id, sizeof(country_id),
            NULL, 0);

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Failed to set country ID: %d\n",
                __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    usleep(100000);
    return RETURN_OK;
}

/**
 * param_data_u32_nl80211_handler - NL80211 response handler for PARAM_DATA u32.
 *
 * Root cause of wifi_getRadioCountryID failure (ret=0 found=0):
 *   The driver returns the country ID as a u32 in QCA_WLAN_VENDOR_ATTR_PARAM_DATA
 *   (attr=1) from enum qca_wlan_genric_data (cfg80211_nlwrapper_pvt.h):
 *
 *     QCA_WLAN_VENDOR_ATTR_PARAM_INVALID = 0
 *     QCA_WLAN_VENDOR_ATTR_PARAM_DATA    = 1  ← u32 value returned here
 *     QCA_WLAN_VENDOR_ATTR_PARAM_LENGTH  = 2  ← length (4 bytes for u32)
 *     QCA_WLAN_VENDOR_ATTR_PARAM_FLAGS   = 3
 *
 *   The previous nl80211_u32_response_handler only checked
 *   QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE (attr=18) and
 *   QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_DATA (attr=19) — completely
 *   different attributes — so ctx.found was always false.
 *
 * This handler is also used by wifi_getRadioRegdomain (same response format).
 */
static int param_data_u32_nl80211_handler(struct nl_msg *msg, void *arg)
{
    nl80211_u32_response_ctx_t *ctx = (nl80211_u32_response_ctx_t *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    /* QCA_WLAN_VENDOR_ATTR_PARAM_MAX = 3, so we need 4 slots */
    struct nlattr *vendor_tb[4];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    const uint8_t *data;
    size_t data_len;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_VENDOR_DATA])
        return NL_SKIP;

    /* Parse vendor data with QCA_WLAN_VENDOR_ATTR_PARAM_MAX = 3 */
    if (nla_parse_nested(vendor_tb, 3,
                tb[NL80211_ATTR_VENDOR_DATA], NULL) < 0)
        return NL_SKIP;

    /* QCA_WLAN_VENDOR_ATTR_PARAM_DATA = 1 */
    if (!vendor_tb[1])
        return NL_SKIP;

    data     = (const uint8_t *)nla_data(vendor_tb[1]);
    data_len = (size_t)nla_len(vendor_tb[1]);

    if (data && data_len >= 4) {
        memcpy(&ctx->value, data, 4);
        ctx->found = true;
    } else if (data && data_len > 0) {
        ctx->value = (uint32_t)data[0];
        ctx->found = true;
    }

    return NL_OK;
}

/**
 * wifi_getRadioCountryID - Get regulatory country code by numeric ID
 *
 * The ath12k kernel driver returns the country ID as a u32 in
 * QCA_WLAN_VENDOR_ATTR_PARAM_DATA (attr=1), not in
 * QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE (attr=18).
 * Uses param_data_u32_nl80211_handler to correctly parse the response.
 */
INT wifi_getRadioCountryID(INT radioIndex, UINT *CountryID)
{
    int                         wiphy_idx, radio_idx;
    nl80211_u32_response_ctx_t  ctx = {0};
    struct nl_msg              *msg;
    struct nlattr              *vendor_data;
    int                         ret;

    if (!CountryID) {
        wifi_hal_error_print("%s:%d: NULL CountryID pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (get_wiphy_radio_idx(radioIndex, &wiphy_idx, &radio_idx) < 0)
        return RETURN_ERR;

    msg = nlmsg_alloc();
    if (!msg) return RETURN_ERR;

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_WIPHY, (u32)wiphy_idx) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) { nlmsg_free(msg); return RETURN_ERR; }

    if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, WIFI_PARAMS) ||
            nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE,
                RADIO_PARAM_COUNTRY_ID) ||
            nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX, (u8)radio_idx)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg, param_data_u32_nl80211_handler, &ctx, NULL, NULL);
    if (ret < 0 || !ctx.found) {
        wifi_hal_error_print("%s:%d: Failed to get country ID for radio %d:"
                " ret=%d found=%d\n",
                __func__, __LINE__, radioIndex, ret, ctx.found);
        return RETURN_ERR;
    }

    *CountryID = (UINT)ctx.value;

    wifi_hal_info_print("%s:%d: Radio %d country ID: %u (0x%08x)\n",
            __func__, __LINE__, radioIndex, *CountryID, ctx.value);

    return RETURN_OK;
}

/**
 * wifi_setRadioRegdomain - Set regulatory domain code
 *
 * Uses NL80211_CMD_REQ_SET_REG (same as 'iw reg set') instead of the QCA
 * vendor command path.  The QCA vendor command fails with -95 (EOPNOTSUPP)
 * when the target country does not support 6GHz because the firmware tries
 * to update ALL pdevs (0=2.4GHz, 1=5GHz, 2=6GHz) and pdev 2 rejects the
 * country:
 *   ath12k: pdev is not supported for this country
 *   ath12k: failed to update chan list for pdev 2, ret -95
 *
 * The standard kernel regulatory path handles per-band constraints
 * internally — unsupported bands are marked disabled, not failed.
 * This is identical to how wifi_setRadioCountryCode works.
 */
INT wifi_setRadioRegdomain(INT radioIndex, UINT regdomain)
{
    struct nl_msg *msg;
    char alpha2[3] = {0};
    int ret;
    unsigned int k;

    /* Map QCA regdomain code to ISO 3166-1 alpha-2 country code.
     * QCA regdomain codes are defined in the QCA driver regulatory database.
     * Multiple countries may share the same regdomain code (e.g. FCC=0x60
     * covers US, CA, MX).  We use the most representative country for each
     * regdomain code range. */
    static const struct { UINT rd; const char *cc; } rd_to_cc[] = {
        /* FCC (0x60-0x6F) — United States and territories */
        { 0x60, "US" }, { 0x61, "US" }, { 0x62, "US" }, { 0x63, "US" },
        { 0x64, "US" }, { 0x65, "US" }, { 0x66, "US" }, { 0x67, "US" },
        { 0x68, "US" }, { 0x69, "US" }, { 0x6A, "US" }, { 0x6B, "US" },
        { 0x6C, "US" }, { 0x6D, "US" }, { 0x6E, "US" }, { 0x6F, "US" },
        /* ETSI (0x30-0x3F) — Europe */
        { 0x30, "DE" }, { 0x31, "DE" }, { 0x32, "DE" }, { 0x33, "DE" },
        { 0x34, "DE" }, { 0x35, "DE" }, { 0x36, "DE" }, { 0x37, "DE" },
        { 0x38, "DE" }, { 0x39, "DE" }, { 0x3A, "DE" }, { 0x3B, "DE" },
        { 0x3C, "DE" }, { 0x3D, "DE" }, { 0x3E, "DE" }, { 0x3F, "DE" },
        /* MKK (0x40-0x4F) — Japan */
        { 0x40, "JP" }, { 0x41, "JP" }, { 0x42, "JP" }, { 0x43, "JP" },
        { 0x44, "JP" }, { 0x45, "JP" }, { 0x46, "JP" }, { 0x47, "JP" },
        { 0x48, "JP" }, { 0x49, "JP" }, { 0x4A, "JP" }, { 0x4B, "JP" },
        { 0x4C, "JP" }, { 0x4D, "JP" }, { 0x4E, "JP" }, { 0x4F, "JP" },
        /* China (0x50-0x5F) */
        { 0x50, "CN" }, { 0x51, "CN" }, { 0x52, "CN" }, { 0x53, "CN" },
        { 0x54, "CN" }, { 0x55, "CN" }, { 0x56, "CN" }, { 0x57, "CN" },
        { 0x58, "CN" }, { 0x59, "CN" }, { 0x5A, "CN" }, { 0x5B, "CN" },
        { 0x5C, "CN" }, { 0x5D, "CN" }, { 0x5E, "CN" }, { 0x5F, "CN" },
        /* APAC / Other (0x70-0x7F) */
        { 0x70, "AU" }, { 0x71, "AU" }, { 0x72, "AU" },
        { 0x73, "LK" }, /* Sri Lanka — 115 decimal, no 6GHz support */
        { 0x74, "IN" }, { 0x75, "IN" }, { 0x76, "IN" },
        { 0x77, "SG" }, { 0x78, "SG" },
        { 0x79, "KR" }, { 0x7A, "KR" },
        { 0x7B, "TW" }, { 0x7C, "TW" },
        { 0x7D, "BR" }, { 0x7E, "BR" },
        { 0x7F, "MX" },
        /* World regulatory domain */
        { 0x00, "00" },
    };

    for (k = 0; k < ARRAY_SZ(rd_to_cc); k++) {
        if (rd_to_cc[k].rd == regdomain) {
            alpha2[0] = rd_to_cc[k].cc[0];
            alpha2[1] = rd_to_cc[k].cc[1];
            alpha2[2] = '\0';
            break;
        }
    }

    if (alpha2[0] == '\0') {
        wifi_hal_error_print("%s:%d: Unknown regdomain 0x%08x for radio %d\n",
                __func__, __LINE__, regdomain, radioIndex);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Setting regdomain 0x%08x (%s) for radio %d"
            " via NL80211_CMD_REQ_SET_REG\n",
            __func__, __LINE__, regdomain, alpha2, radioIndex);

    msg = nlmsg_alloc();
    if (!msg) {
        wifi_hal_error_print("%s:%d: nlmsg_alloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /* Build NL80211_CMD_REQ_SET_REG + NL80211_ATTR_REG_ALPHA2 — same as
     * wifi_setRadioCountryCode and 'iw reg set <alpha2>'.
     * The kernel regulatory framework handles per-band constraints internally:
     * if 6GHz is not supported for the country, those channels are marked
     * disabled without failing the overall regulatory set operation. */
    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_REQ_SET_REG, 0) ||
            nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, alpha2) < 0) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: NL80211_CMD_REQ_SET_REG failed: %d\n",
                __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Regdomain 0x%08x (%s) set for radio %d\n",
            __func__, __LINE__, regdomain, alpha2, radioIndex);
    usleep(100000);  /* 100ms — allow regulatory change to propagate */
    return RETURN_OK;
}

/**
 * wifi_getRadioRegdomain - Get regulatory domain code
 *
 * The ath12k kernel driver returns the regdomain in GENERIC_VALUE (u32),
 * not GENERIC_DATA.  wifi_send_vendor_cmd_radio uses nl80211_vendor_response_handler
 * which only checks GENERIC_DATA and therefore always returns 0.
 */
INT wifi_getRadioRegdomain(INT radioIndex, UINT *regdomain)
{
    int                         wiphy_idx, radio_idx;
    nl80211_u32_response_ctx_t  ctx = {0};
    struct nl_msg              *msg;
    struct nlattr              *vendor_data;
    int                         ret;

    if (!regdomain) {
        wifi_hal_error_print("%s:%d: NULL regdomain pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (get_wiphy_radio_idx(radioIndex, &wiphy_idx, &radio_idx) < 0)
        return RETURN_ERR;

    msg = nlmsg_alloc();
    if (!msg) return RETURN_ERR;

    if (!genlmsg_put(msg, 0, 0, g_wifi_hal.nl80211_id, 0, 0,
                NL80211_CMD_VENDOR, 0) ||
            nla_put_u32(msg, NL80211_ATTR_WIPHY, (u32)wiphy_idx) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
            nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                QCA_NL80211_VENDOR_SUBCMD_GET_WIPHY_CONFIGURATION)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    vendor_data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data) { nlmsg_free(msg); return RETURN_ERR; }

    if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, WIFI_PARAMS) ||
            nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_VALUE,
                RADIO_PARAM_REGDOMAIN) ||
            nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_CONFIG_RADIO_INDEX, (u8)radio_idx)) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    nla_nest_end(msg, vendor_data);

    ret = nl80211_send_and_recv(msg, nl80211_u32_response_handler, &ctx, NULL, NULL);
    if (ret < 0 || !ctx.found) {
        /* QCA vendor command not available — fall back to NL80211_CMD_GET_REG.
         * NL80211_CMD_GET_REG returns NL80211_ATTR_REG_ALPHA2 (2-char country
         * code) which we map to a numeric regdomain value.
         * This is the standard NL80211-only path used when the QCA vendor
         * command is not supported by the firmware. */
        struct nl80211_reg_alpha2_ctx reg_ctx;
        struct nl_msg *reg_msg;

        memset(&reg_ctx, 0, sizeof(reg_ctx));

        reg_msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0,
                NL80211_CMD_GET_REG);
        if (reg_msg != NULL) {
            nl80211_send_and_recv(reg_msg, nl80211_get_reg_alpha2_handler,
                    &reg_ctx, NULL, NULL);
        }

        if (reg_ctx.found && reg_ctx.alpha2[0] != '\0') {
            /* Map 2-char country code to a numeric regdomain.
             * These values match the QCA regdomain encoding used by
             * cfg80211tool get_regdomain / RADIO_PARAM_REGDOMAIN:
             *   0x60 = FCC (US, CA, ...)
             *   0x30 = ETSI (EU countries)
             *   0x40 = MKK (Japan)
             *   0x00 = World / unknown
             */
            static const struct { const char *cc; UINT rd; } cc_map[] = {
                /* FCC countries */
                { "US", 0x60 }, { "CA", 0x60 }, { "MX", 0x60 },
                /* ETSI countries */
                { "DE", 0x30 }, { "FR", 0x30 }, { "GB", 0x30 },
                { "IT", 0x30 }, { "ES", 0x30 }, { "NL", 0x30 },
                { "BE", 0x30 }, { "AT", 0x30 }, { "CH", 0x30 },
                { "SE", 0x30 }, { "NO", 0x30 }, { "DK", 0x30 },
                { "FI", 0x30 }, { "PL", 0x30 }, { "PT", 0x30 },
                { "IE", 0x30 }, { "AU", 0x30 }, { "NZ", 0x30 },
                { "SG", 0x30 }, { "IN", 0x30 }, { "BR", 0x30 },
                /* MKK (Japan) */
                { "JP", 0x40 },
                /* China */
                { "CN", 0x50 },
                /* APAC */
                { "LK", 0x73 }, /* Sri Lanka */
                { "KR", 0x79 }, /* South Korea */
                { "TW", 0x7B }, /* Taiwan */
            };
            unsigned int k;
            UINT rd = 0x00; /* default: World */

            for (k = 0; k < ARRAY_SZ(cc_map); k++) {
                if (strncmp(reg_ctx.alpha2, cc_map[k].cc, 2) == 0) {
                    rd = cc_map[k].rd;
                    break;
                }
            }

            *regdomain = rd;
            wifi_hal_info_print(
                    "%s:%d: Radio %d regdomain via NL80211_CMD_GET_REG:"
                    " country=%s regdomain=0x%02x\n",
                    __func__, __LINE__, radioIndex, reg_ctx.alpha2, rd);
            return RETURN_OK;
        }

        /* NL80211_CMD_GET_REG also unavailable — return 0 (unknown) */
        wifi_hal_dbg_print(
                "%s:%d: NL80211 regdomain not available for radio %d"
                " (vendor ret=%d found=%d, GET_REG found=%d) — returning 0\n",
                __func__, __LINE__, radioIndex, ret, ctx.found, reg_ctx.found);
        *regdomain = 0;
        return RETURN_OK;
    }

    *regdomain = (UINT)ctx.value;

    wifi_hal_info_print("%s:%d: Radio %d regdomain: 0x%08x\n",
            __func__, __LINE__, radioIndex, *regdomain);

    return RETURN_OK;
}

/* ============================================================
 * Per-VAP / Per-Link APIs using hostapd library directly
 *
 * Since hostapd is a library in onewifi (not a daemon), we
 * access the hostapd_data struct directly via:
 *   interface = get_interface_by_vap_index(apIndex)
 *   hapd = &interface->u.ap.hapd
 *
 * All hapd accesses are protected by g_wifi_hal.hapd_lock.
 * ============================================================ */

/**
 * wifi_setApBeaconCountryIE - Enable/disable Country IE in beacons
 *
 * Replaces: hostapd_cli -i wlanX -l Y countryie <0|1>
 * Backend:  hostapd_ctrl_iface_country_ie_extn() which sets
 *           hapd->iconf->ieee80211d = enabled
 *           and calls ieee802_11_update_beacons(hapd->iface)
 *
 * @apIndex: AP/VAP index
 * @enable:  TRUE to include Country IE in beacons, FALSE to omit
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
/**
 * wifi_setApBeaconCountryIE - Enable/disable Country IE in beacons
 *
 * Replaces: hostapd_cli -i wlanX -l Y countryie <0|1>
 * Backend:  hostapd_ctrl_iface_country_ie_extn() which sets
 *           hapd->iconf->ieee80211d = enabled
 *           and calls ieee802_11_update_beacons(hapd->iface)
 *
 * @apIndex: AP/VAP index
 * @enable:  TRUE to include Country IE in beacons, FALSE to omit
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */

INT wifi_setApBeaconCountryIE(INT apIndex, BOOL enable)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;
    int old_enabled;

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Setting Country IE %s for apIndex:%d\n",
            __func__, __LINE__, enable ? "enabled" : "disabled", apIndex);

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->iconf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL iconf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    old_enabled = hapd->iconf->ieee80211d;
    if ((int)enable == old_enabled) {
        /* No change needed */
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_dbg_print("%s:%d: Country IE already %s for apIndex:%d\n",
                __func__, __LINE__, enable ? "enabled" : "disabled", apIndex);
        return RETURN_OK;
    }

    hapd->iconf->ieee80211d = enable ? 1 : 0;

    /* Update beacons to reflect the new Country IE setting */
    if (ieee802_11_update_beacons(hapd->iface) < 0) {
        /* Revert on failure */
        hapd->iconf->ieee80211d = old_enabled;
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: Country IE %s for apIndex:%d\n",
            __func__, __LINE__, enable ? "enabled" : "disabled", apIndex);
    return RETURN_OK;
}

/**
 * wifi_getApBeaconCountryIE - Get Country IE beacon status
 *
 * Replaces: hostapd_cli -i wlanX -l Y get_countryie
 * Backend:  reads hapd->iconf->ieee80211d
 *
 * @apIndex:     AP/VAP index
 * @output_bool: Pointer to receive enable status
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_getApBeaconCountryIE(INT apIndex, BOOL *output_bool)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;

    if (!output_bool) {
        wifi_hal_error_print("%s:%d: NULL output_bool\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->iconf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL iconf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    *output_bool = (hapd->iconf->ieee80211d != 0) ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: apIndex:%d Country IE: %s\n",
            __func__, __LINE__, apIndex,
            *output_bool ? "enabled" : "disabled");
    return RETURN_OK;
}

/**
 * wifi_setApPureNMode - Enable/disable 802.11n-only (HT-only) mode
 *
 * Replaces: hostapd_cli -i wlanX -l Y set_puren <0|1>
 * Backend:  hostapd_ctrl_iface_set_puren_extn() which sets
 *           hapd->iconf->require_ht = value
 *
 * @apIndex: AP/VAP index
 * @enable:  TRUE to reject non-HT clients, FALSE to allow all
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_setApPureNMode(INT apIndex, BOOL enable)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Setting Pure N mode %s for apIndex:%d\n",
            __func__, __LINE__, enable ? "enabled" : "disabled", apIndex);

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->conf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL hapd.conf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#ifdef QCA_UD_HOSTAPD
    /*
     * Per-BSS pure-N override: set puren_bss.is_overridden = true and
     * puren_bss.value = enable.  This takes precedence over the per-radio
     * iconf->require_ht setting in hostapd_deny_non_ht_assoc().
     * Applicable to 2.4GHz and 5GHz only (not 6GHz).
     */
    hapd->conf->bss_extn.puren_bss.is_overridden = true;
    hapd->conf->bss_extn.puren_bss.value = (enable != FALSE);
#endif
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: Pure N mode %s for apIndex:%d\n",
            __func__, __LINE__, enable ? "enabled" : "disabled", apIndex);
    return RETURN_OK;
}

/**
 * wifi_getApPureNMode - Get PureN mode status
 *
 * Replaces: hostapd_cli -i wlanX -l Y get_puren
 * Backend:  reads hapd->iconf->require_ht
 *
 * @apIndex:     AP/VAP index
 * @output_bool: Pointer to receive enable status
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_getApPureNMode(INT apIndex, BOOL *output_bool)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;
    bool puren;

    if (!output_bool) {
        wifi_hal_error_print("%s:%d: NULL output_bool\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->conf == NULL || hapd->iconf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL hapd.conf/iconf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#ifdef QCA_UD_HOSTAPD
    /* Per-BSS override takes precedence over per-radio require_ht */
    if (hapd->conf->bss_extn.puren_bss.is_overridden)
        puren = hapd->conf->bss_extn.puren_bss.value;
    else
#endif
        puren = (hapd->iconf->require_ht != 0);

    *output_bool = puren ? TRUE : FALSE;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: apIndex:%d Pure N mode: %s\n",
            __func__, __LINE__, apIndex,
            *output_bool ? "enabled" : "disabled");
    return RETURN_OK;
}

/**
 * wifi_setApOperatingClassTable - Set operating class table index
 *
 * Replaces: hostapd_cli -i wlanX -l Y set_opclass_tbl <index>
 * Backend:  sets hapd->iconf->conf_extn.opclass_tbl_idx = (u8) idx
 *           Triggers beacon update to reflect new opclass advertisement.
 *           Valid range: 0-6.
 *
 * @apIndex: AP/VAP index
 * @index:   Operating class table index (0-6)
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_setApOperatingClassTable(INT apIndex, UINT index)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;

    if (index > 6) {
        wifi_hal_error_print("%s:%d: Invalid opclass table index %u (max 6)\n",
                __func__, __LINE__, index);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Setting opclass table index %u for apIndex:%d\n",
            __func__, __LINE__, index, apIndex);

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->iconf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL iconf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#ifdef QCA_UD_HOSTAPD
    hapd->iconf->conf_extn.opclass_tbl_idx = (u8)index;
#endif
    /* Update beacons to advertise the new operating class table */
    if (ieee802_11_update_beacons(hapd->iface) < 0) {
        wifi_hal_error_print("%s:%d: ieee802_11_update_beacons failed for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        /* Non-fatal: config is updated, beacon update failed */
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: Opclass table index set to %u for apIndex:%d\n",
            __func__, __LINE__, index, apIndex);
    return RETURN_OK;
}

/**
 * wifi_getApOperatingClassTable - Get operating class table index
 *
 * Replaces: hostapd_cli -i wlanX -l Y get_opclass_tbl
 * Backend:  reads hapd->iconf->conf_extn.opclass_tbl_idx
 *
 * @apIndex: AP/VAP index
 * @index:   Pointer to receive table index
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_getApOperatingClassTable(INT apIndex, UINT *index)
{
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd;

    if (!index) {
        wifi_hal_error_print("%s:%d: NULL index pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hapd = &interface->u.ap.hapd;

    if (hapd->iconf == NULL) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d: NULL iconf for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

#ifdef QCA_UD_HOSTAPD
    *index = (UINT)hapd->iconf->conf_extn.opclass_tbl_idx;
#endif
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d: apIndex:%d opclass table index: %u\n",
            __func__, __LINE__, apIndex, *index);
    return RETURN_OK;
}

/**
 * wifi_setApOperatingClassChannels - Core helper: disable or enable channels
 *
 * Implements the NL80211 vendor command path for:
 *   hostapd_cli –i wlanX –l y disable_opclass_chans [0|1] opclass ch1 ch2…chN
 *
 * The first parameter of that command maps to the REG_PARAMS_ATTR_DISABLE
 * attribute in QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS (subcmd 518):
 *   disable = 1  →  disable channels (mark unavailable for use)
 *   disable = 0  →  enable  channels (re-enable previously disabled channels)
 *
 * @apIndex:      AP/VAP index
 * @opclass:      Operating class number (e.g. 81=2.4GHz 20MHz, 115=5GHz 40MHz)
 * @channel_list: Space/comma-separated channel numbers, e.g. "36 40 44"
 * @disable:      1 = disable channels, 0 = re-enable channels
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
static INT wifi_setApOperatingClassChannels(INT apIndex, UINT opclass,
        CHAR *channel_list, int disable)
{
    wifi_interface_info_t *interface;
    int link_id = -1;
    unsigned char channels[64];
    int num_channels = 0;
    char *list_copy;
    char *token;
    char *saveptr;
    int ret;

    if (!channel_list) {
        wifi_hal_error_print("%s:%d: NULL channel_list\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    interface = get_interface_by_vap_index((unsigned int)apIndex);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: interface not found for apIndex:%d\n",
                __func__, __LINE__, apIndex);
        return RETURN_ERR;
    }

    /* Get MLO link ID if applicable */
    if (interface->mld_name[0] != '\0')
        link_id = wifi_hal_get_mld_link_id(interface);

    /* Parse the space/comma-separated channel list */
    list_copy = strdup(channel_list);
    if (!list_copy) {
        wifi_hal_error_print("%s:%d: strdup failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    token = strtok_r(list_copy, " ,", &saveptr);
    while (token != NULL && num_channels < (int)(sizeof(channels))) {
        int ch = atoi(token);
        if (ch > 0 && ch <= 255)
            channels[num_channels++] = (unsigned char)ch;
        token = strtok_r(NULL, " ,", &saveptr);
    }
    free(list_copy);

    if (num_channels == 0) {
        wifi_hal_error_print("%s:%d: No valid channels in list '%s'\n",
                __func__, __LINE__, channel_list);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: %s %d channels in opclass %u for apIndex:%d"
            " (REG_PARAMS_DISABLE=%d)\n",
            __func__, __LINE__,
            disable ? "Disabling" : "Enabling",
            num_channels, opclass, apIndex, disable);

    ret = wifi_send_reg_params_cmd(interface, link_id, disable,
            (unsigned char)opclass, channels, num_channels);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Failed to %s channels in opclass %u: %d\n",
                __func__, __LINE__,
                disable ? "disable" : "enable", opclass, ret);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Successfully %s %d channels in opclass %u "
            "for apIndex:%d\n",
            __func__, __LINE__,
            disable ? "disabled" : "enabled",
            num_channels, opclass, apIndex);
    return RETURN_OK;
}

/**
 * wifi_disableApOperatingClassChannels - Disable channels in an opclass
 *
 * Equivalent to:
 *   hostapd_cli –i wlanX –l y disable_opclass_chans 1 <opclass> <ch1> [chN…]
 *
 * Sends REG_PARAMS_ATTR_DISABLE = 1 to the firmware via
 * QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS (subcmd 518).
 * The firmware marks the listed channels as unavailable; if the AP is
 * currently operating on one of them it automatically falls back to the
 * next available channel.
 *
 * To re-enable the same channels call wifi_enableApOperatingClassChannels()
 * with the same opclass and channel_list.
 *
 * @apIndex:      AP/VAP index
 * @opclass:      Operating class number
 * @channel_list: Space/comma-separated channel numbers, e.g. "36 40 44"
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_disableApOperatingClassChannels(INT apIndex, UINT opclass, CHAR *channel_list)
{
    return wifi_setApOperatingClassChannels(apIndex, opclass, channel_list, 1 /* disable */);
}

/**
 * wifi_enableApOperatingClassChannels - Re-enable previously disabled channels
 *
 * Equivalent to:
 *   hostapd_cli –i wlanX –l y disable_opclass_chans 0 <opclass> <ch1> [chN…]
 *
 * Sends REG_PARAMS_ATTR_DISABLE = 0 to the firmware via
 * QCA_NL80211_VENDOR_SUBCMD_REG_PARAMS (subcmd 518).
 * The firmware marks the listed channels as available again.
 *
 * This is the inverse of wifi_disableApOperatingClassChannels().
 * Use the same opclass and channel_list that were passed to the disable call.
 *
 * @apIndex:      AP/VAP index
 * @opclass:      Operating class number
 * @channel_list: Space/comma-separated channel numbers, e.g. "36 40 44"
 * Returns: RETURN_OK on success, RETURN_ERR on failure
 */
INT wifi_enableApOperatingClassChannels(INT apIndex, UINT opclass, CHAR *channel_list)
{
    return wifi_setApOperatingClassChannels(apIndex, opclass, channel_list, 0 /* enable */);
}

/**
 * wifi_getRadioBandChannels - Get channel list for a specific band (diagnostic)
 *
 * Uses wifi_getRadioPossibleChannels() to get the actual channel list for
 * the radio.  The previous NL80211 vendor command approach returned a
 * hardcoded placeholder (always 5GHz channels 36,40,44) regardless of the
 * radio or band parameter.
 *
 * @radioIndex: RDK radio index (0=2.4GHz, 1=5GHz, 2=6GHz on this platform)
 * @band:       Band selector (0=2.4GHz, 1=5GHz, 2=6GHz) — matches radioIndex
 * @output_string: Buffer to receive the channel list
 * @output_len: Size of output_string buffer
 */
INT wifi_getRadioBandChannels(INT radioIndex, UINT band,
        CHAR *output_string, UINT output_len)
{
    /* 8192 bytes: enough for 6GHz (~60 channels × ~90 chars/line = ~5400 bytes) */
    char chanList[8192] = {0};

    if (!output_string || output_len == 0) {
        wifi_hal_error_print("%s:%d: NULL/zero output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_hal_info_print("%s:%d: Getting band %u channels for radio %d\n",
            __func__, __LINE__, band, radioIndex);

    /* Use wifi_getRadioPossibleChannels which correctly reads from the
     * radio capabilities populated during HAL init. */
    if (wifi_getRadioPossibleChannels(radioIndex, chanList) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Failed to get channel list for radio %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    snprintf(output_string, output_len, "%s", chanList);

    wifi_hal_info_print("%s:%d: Radio %d band %u channels: %s\n",
            __func__, __LINE__, radioIndex, band, output_string);

    return RETURN_OK;
}

/* =========================================================================
 * super_chan_ctx / super_chan_handler
 *
 * NL80211_CMD_GET_WIPHY callback that parses the 6GHz band frequency
 * attributes and formats them into a human-readable super channel list.
 *
 * Per-frequency attributes extracted:
 *   NL80211_FREQUENCY_ATTR_FREQ       - frequency in MHz
 *   NL80211_FREQUENCY_ATTR_DISABLED   - channel disabled
 *   NL80211_FREQUENCY_ATTR_NO_IR      - no initiating radiation (passive only)
 *   NL80211_FREQUENCY_ATTR_RADAR      - DFS required
 *   NL80211_FREQUENCY_ATTR_NO_HT40_PLUS/MINUS - no 40MHz
 *   NL80211_FREQUENCY_ATTR_NO_80MHZ   - no 80MHz
 *   NL80211_FREQUENCY_ATTR_NO_160MHZ  - no 160MHz
 *   NL80211_FREQUENCY_ATTR_DFS_STATE  - DFS channel state
 *   NL80211_FREQUENCY_ATTR_PSD        - Power Spectral Density (0.25 dBm units)
 * ========================================================================= */
/* =========================================================================
 * NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE support
 * (kernel 5.15+ — same kernel that shows "Supported power modes: LPI SP VLP")
 * ========================================================================= */

static int super_chan_handler(struct nl_msg *msg, void *arg)
{
    struct super_chan_ctx *ctx = (struct super_chan_ctx *)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_band;
    int rem_band;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
        struct nlattr *band_tb[NL80211_BAND_ATTR_MAX + 1];
        struct nlattr *nl_freq;
        int rem_freq;

        /* Only 6GHz band (NL80211_BAND_6GHZ = 3) */
        if ((unsigned int)nl_band->nla_type != NL80211_BAND_6GHZ)
            continue;

        nla_parse(band_tb, NL80211_BAND_ATTR_MAX,
                nla_data(nl_band), nla_len(nl_band), NULL);

        if (!band_tb[NL80211_BAND_ATTR_FREQS])
            continue;

        if (!ctx->header_printed) {
            SCL_W("%-10s %-12s %-14s %-10s %-10s %-10s %-10s %-8s %-12s\n",
                    "Freq(MHz)", "PowerMode", "EIRPpower(dBm)",
                    "PSDflag", "PSDpower", "ChanFlags",
                    "ChanState", "MinBW", "MaxBW");
            ctx->header_printed = true;
        }

        nla_for_each_nested(nl_freq, band_tb[NL80211_BAND_ATTR_FREQS], rem_freq) {
            struct nlattr *freq_tb[NL80211_FREQUENCY_ATTR_MAX + 1];
            uint32_t freq;
            bool     disabled;
            uint32_t chan_flags;
            int      chan_state;
            uint32_t max_bw;
            int32_t  eirp_dbm;
            int      psd_flag;
            int32_t  psd_power;

            nla_parse(freq_tb, NL80211_FREQUENCY_ATTR_MAX,
                    nla_data(nl_freq), nla_len(nl_freq), NULL);

            if (!freq_tb[NL80211_FREQUENCY_ATTR_FREQ])
                continue;

            freq     = nla_get_u32(freq_tb[NL80211_FREQUENCY_ATTR_FREQ]);
            disabled = (freq_tb[NL80211_FREQUENCY_ATTR_DISABLED] != NULL);

            /* ── Chan flags (IEEE80211_CHAN_* bitmask) ── */
            chan_flags = 0;
            if (disabled)
                chan_flags |= 0x001;
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_IR])
                chan_flags |= 0x002;
            if (freq_tb[NL80211_FREQUENCY_ATTR_RADAR])
                chan_flags |= 0x008;
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS])
                chan_flags |= 0x010;
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS])
                chan_flags |= 0x020;
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_80MHZ])
                chan_flags |= 0x080;
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_160MHZ])
                chan_flags |= 0x100;
            if (freq_tb[NL80211_FREQUENCY_ATTR_INDOOR_ONLY])
                chan_flags |= 0x200;

            /* ── Channel state: 0=disabled 1=passive 2=DFS 3=active ── */
            if (disabled)
                chan_state = 0;
            else if (freq_tb[NL80211_FREQUENCY_ATTR_NO_IR])
                chan_state = 1;
            else if (freq_tb[NL80211_FREQUENCY_ATTR_RADAR])
                chan_state = 2;
            else
                chan_state = 3;

            /* ── Max BW from NO_* flags ── */
            if (freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS] &&
                    freq_tb[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS])
                max_bw = 20;
            else if (freq_tb[NL80211_FREQUENCY_ATTR_NO_80MHZ])
                max_bw = 40;
            else if (freq_tb[NL80211_FREQUENCY_ATTR_NO_160MHZ])
                max_bw = 80;
            else
                max_bw = 320;   /* 6GHz EHT */

            /* ── EIRP power (mBm ÷ 100 = dBm) ── */
            eirp_dbm = 0;
            if (freq_tb[NL80211_FREQUENCY_ATTR_MAX_TX_POWER])
                eirp_dbm = (int32_t)nla_get_u32(
                        freq_tb[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) / 100;

            /* ── PSD power (0.25 dBm units ÷ 4 = dBm) ── */
            psd_flag  = 0;
            psd_power = 0;
            if (freq_tb[NL80211_FREQUENCY_ATTR_PSD]) {
                psd_power = (int32_t)nla_get_u32(
                        freq_tb[NL80211_FREQUENCY_ATTR_PSD]) / 4;
                psd_flag  = (psd_power != 0) ? 1 : 0;
            }

            /* ── Per-power-mode breakdown ──
             * NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE (kernel 5.15+)
             * Each nested entry: FLAGS (LPI/VLP/SP) + POWER_RULE (EIRP+PSD)
             * Matches cfg80211tool display_super_chan_list output:
             *   PowerMode=1(LPI), PowerMode=2(SP), PowerMode=3(VLP)
             */
            {
                /* NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE = 68 exceeds
                 * NL80211_FREQUENCY_ATTR_MAX in the SDK nl80211.h (max=54).
                 * Use nla_find() on the raw nested data to locate it by
                 * numeric ID, bypassing the fixed-size freq_tb[] array and
                 * avoiding the -Werror=array-bounds build error. */
                struct nlattr *pwr_rules =
                    nla_find(nla_data(nl_freq),
                            nla_len(nl_freq),
                            NL80211_FREQUENCY_ATTR_6GHZ_REG_POWER_RULE);
                bool printed_any = false;

                if (pwr_rules) {
                    struct nlattr *rule;
                    int rem_rule;
                    uint32_t power_types = 0;
                    uint32_t best_mode   = 0;
                    int32_t  best_eirp   = -999;

                    /* Pass 1: compute power_types bitmask and best_power_mode */
                    nla_for_each_nested(rule, pwr_rules, rem_rule) {
                        struct nlattr *rtb[SCL_6GHZ_RULE_MAX + 1];
                        uint32_t rflags = 0;
                        int32_t  r_eirp = 0;

                        if (nla_parse_nested(rtb, SCL_6GHZ_RULE_MAX,
                                    rule, NULL) < 0)
                            continue;

                        if (rtb[SCL_6GHZ_RULE_FLAGS])
                            rflags = nla_get_u32(rtb[SCL_6GHZ_RULE_FLAGS]);

                        if (rtb[SCL_6GHZ_RULE_POWER_RULE]) {
                            struct nlattr *ptb[SCL_POWER_RULE_MAX + 1];
                            if (nla_parse_nested(ptb, SCL_POWER_RULE_MAX,
                                        rtb[SCL_6GHZ_RULE_POWER_RULE],
                                        NULL) == 0 &&
                                    ptb[SCL_POWER_RULE_MAX_EIRP])
                                r_eirp = (int32_t)nla_get_u32(
                                        ptb[SCL_POWER_RULE_MAX_EIRP]) / 100;
                        }

                        /* power_types: bit1=LPI, bit2=SP, bit3=VLP */
                        if (rflags & SCL_6GHZ_LPI) {
                            power_types |= 0x2;
                            if (r_eirp > best_eirp) { best_eirp = r_eirp; best_mode = 1; }
                        } else if (rflags & SCL_6GHZ_VLP) {
                            power_types |= 0x8;
                            if (r_eirp > best_eirp) { best_eirp = r_eirp; best_mode = 3; }
                        } else {
                            /* SP = neither LPI nor VLP */
                            power_types |= 0x4;
                            if (r_eirp > best_eirp) { best_eirp = r_eirp; best_mode = 2; }
                        }
                    }

                    SCL_W("Freq=%-6u PowerTypes=0x%x BestPowerMode=0x%x\n",
                            freq, power_types, best_mode);

                    /* Pass 2: print per-power-mode rows */
                    nla_for_each_nested(rule, pwr_rules, rem_rule) {
                        struct nlattr *rtb[SCL_6GHZ_RULE_MAX + 1];
                        uint32_t rflags    = 0;
                        int32_t  r_eirp    = eirp_dbm;
                        int32_t  r_psd     = psd_power;
                        int      r_psd_flg = psd_flag;
                        uint32_t pmode;
                        const char *pmode_str;

                        if (nla_parse_nested(rtb, SCL_6GHZ_RULE_MAX,
                                    rule, NULL) < 0)
                            continue;

                        if (rtb[SCL_6GHZ_RULE_FLAGS])
                            rflags = nla_get_u32(rtb[SCL_6GHZ_RULE_FLAGS]);

                        if (rtb[SCL_6GHZ_RULE_POWER_RULE]) {
                            struct nlattr *ptb[SCL_POWER_RULE_MAX + 1];
                            if (nla_parse_nested(ptb, SCL_POWER_RULE_MAX,
                                        rtb[SCL_6GHZ_RULE_POWER_RULE],
                                        NULL) == 0) {
                                if (ptb[SCL_POWER_RULE_MAX_EIRP])
                                    r_eirp = (int32_t)nla_get_u32(
                                            ptb[SCL_POWER_RULE_MAX_EIRP]) / 100;
                                if (ptb[SCL_POWER_RULE_PSD]) {
                                    r_psd     = (int32_t)nla_get_u32(
                                            ptb[SCL_POWER_RULE_PSD]) / 4;
                                    r_psd_flg = (r_psd != 0) ? 1 : 0;
                                }
                            }
                        }

                        if (rflags & SCL_6GHZ_LPI) {
                            pmode = 1; pmode_str = "LPI";
                        } else if (rflags & SCL_6GHZ_VLP) {
                            pmode = 3; pmode_str = "VLP";
                        } else {
                            pmode = 2; pmode_str = "SP";
                        }

                        SCL_W("  PowerMode=%u(%s) PSDflag=%d PSDpower=%d"
                                " EIRPpower=%d ChanFlags=0x%x ChanState=%d"
                                " MinBW=20 MaxBW=%u AFC_NOT_DONE=0\n",
                                pmode, pmode_str, r_psd_flg, r_psd,
                                r_eirp, chan_flags, chan_state, max_bw);
                        printed_any = true;
                    }
                }

                /* Fallback: 6GHZ_REG_POWER_RULE not available */
                if (!printed_any) {
                    SCL_W("Freq=%-6u PowerTypes=N/A BestPowerMode=N/A\n", freq);
                    SCL_W("  PowerMode=0(ALL) PSDflag=%d PSDpower=%d"
                            " EIRPpower=%d ChanFlags=0x%x ChanState=%d"
                            " MinBW=20 MaxBW=%u AFC_NOT_DONE=0\n",
                            psd_flag, psd_power, eirp_dbm,
                            chan_flags, chan_state, max_bw);
                }
            }

            ctx->got_data = true;
        }
    }

#undef SCL_W
    return NL_SKIP;
}

/**
 * wifi_getRadioSuperChannelList - Get 6GHz super channel list via NL80211
 *
 * Uses NL80211_CMD_GET_WIPHY with NL80211_ATTR_SPLIT_WIPHY_DUMP to fetch
 * the 6GHz band frequency attributes from the kernel.  For each 6GHz
 * frequency the following NL80211 attributes are extracted and formatted:
 *   - NL80211_FREQUENCY_ATTR_FREQ       : frequency in MHz
 *   - NL80211_FREQUENCY_ATTR_DISABLED   : channel disabled flag
 *   - NL80211_FREQUENCY_ATTR_NO_IR      : no initiating radiation
 *   - NL80211_FREQUENCY_ATTR_RADAR      : DFS required
 *   - NL80211_FREQUENCY_ATTR_NO_80MHZ / NO_160MHZ : max bandwidth
 *   - NL80211_FREQUENCY_ATTR_DFS_STATE  : DFS channel state
 *   - NL80211_FREQUENCY_ATTR_PSD        : Power Spectral Density (0.25 dBm)
 *
 * This is the NL80211-only equivalent of:
 *   cfg80211tool phyXX radio_idx N display_super_chan_list
 */
INT wifi_getRadioSuperChannelList(INT radioIndex, CHAR *output_string, UINT output_len)
{
    wifi_radio_info_t     *radio;
    wifi_interface_info_t *interface;
    struct nl_msg         *msg;
    struct super_chan_ctx   ctx;
    int                    ret;

    if (!output_string || output_len == 0) {
        wifi_hal_error_print("%s:%d: NULL/zero output_string\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(radioIndex);
    if (!radio) {
        wifi_hal_error_print("%s:%d: Radio not found for index %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    /* Super channel list is only meaningful for 6GHz radios */
    if (radio->oper_param.band != WIFI_FREQUENCY_6_BAND) {
        snprintf(output_string, output_len,
                "Super channel list not applicable for non-6GHz radio %d\n",
                radioIndex);
        return RETURN_OK;
    }

    interface = get_primary_interface(radio);
    if (!interface) {
        wifi_hal_error_print("%s:%d: Primary interface not found for radio %d\n",
                __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.buf     = output_string;
    ctx.buf_len = output_len;
    output_string[0] = '\0';

    wifi_hal_info_print("%s:%d: Getting 6GHz super channel list for radio %d"
            " (wiphy=%d iface=%s)\n",
            __func__, __LINE__, radioIndex, interface->phy_index, interface->name);

    /* Build NL80211_CMD_GET_WIPHY dump targeting this radio's wiphy.
     * NL80211_ATTR_SPLIT_WIPHY_DUMP is required to get per-channel data
     * for all 6GHz frequencies (the kernel sends one message per channel). */
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP,
            NL80211_CMD_GET_WIPHY);
    if (!msg) {
        wifi_hal_error_print("%s:%d: Failed to allocate NL message\n",
                __func__, __LINE__);
        return RETURN_ERR;
    }

    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, (u32)interface->phy_index) < 0 ||
            nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP) < 0) {
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, super_chan_handler, &ctx, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: NL80211_CMD_GET_WIPHY failed ret=%d\n",
                __func__, __LINE__, ret);
        return RETURN_ERR;
    }

    if (!ctx.got_data) {
        snprintf(output_string, output_len,
                "No 6GHz super channel data available for radio %d\n", radioIndex);
        wifi_hal_dbg_print("%s:%d: No 6GHz band data in wiphy dump for radio %d\n",
                __func__, __LINE__, radioIndex);
    } else {
        wifi_hal_info_print("%s:%d: Radio %d 6GHz super channel list: %zu bytes\n",
                __func__, __LINE__, radioIndex, ctx.written);
    }

    return RETURN_OK;
}

int platform_set_beacon_prot(uint apIndex, bool isEnabled)
{
    return RETURN_OK;
}
