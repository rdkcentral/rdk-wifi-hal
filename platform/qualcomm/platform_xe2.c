/*
 * Copyright (c) 2024 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * platform_xe2.c — XE2 Dakota Qualcomm (IPQ4019) platform for rdk-wifi-hal
 *
 * Driver invocation: NL80211 (libnl 3.2.x) + legacy cfg80211tool calls
 * Flow: OVSM → OneWifi → rdk-wifi-hal → QCA driver
 *
 * Adapted from platform_xer5.c for the 3-radio IPQ Dakota (XE2) superpod.
 */

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include <unistd.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"
/* NOTE: qca_wifi_hal.h is an external QCA product (hal-qcawifi) header that is
 * not part of the XE2 workspace, and the generic libhal_wifi does not export
 * the QCA "extender" HAL ops. The QCA helpers used below (qca_getRadiosIndex,
 * qca_nl_cfg80211_init, isValidAPIndex) plus the wifi_hal action-frame /
 * neighbor-report / DFS / CSI ops are therefore defined locally at the bottom
 * of this file (see "XE2 QCA HAL op supplement"), ported/stubbed from the XER5
 * QCA HAL. They are XE2_PORT-gated (this file compiles only when XE2_PORT is
 * enabled). */

#if HAL_IPC
#include "hal_ipc.h"
#include "server_hal_ipc.h"
#endif

/* ───────────────────────── compile-time constants ───────────────────────── */

#define WIFI_AP_MAX_PASSPHRASE_LEN  300
#define WIFI_MAX_RADIUS_KEY         128
#define COUNTRY_LENGTH              10
#define MAX_KEYPASSPHRASE_LEN       128
#define MAX_SSID_LEN                33
#define DEFAULT_SSID_SIZE           128
#define DEFAULT_CMD_SIZE            256
#define MAX_BUF_SIZE                300
#define VAP_PREFIX                  "ath"
#define RADIO_PREFIX                "wifi"
#define NVRAM_NAME_SIZE             128

/* XE2 Dakota superpod has 3 radios: 2.4 GHz, 5 GHz-low and 5 GHz-high */
#define IPQ_XE2_MAX_NUM_RADIOS      3

#define OUI_QCA         "0x001374"
#define RETRY_LIMIT     7

#define WIFI_24G_MAC_ADDR_KEY       "WiFi 2.4GHz MAC address"
#define WIFI_50G_MAC_ADDR_KEY       "WiFi 5.0GHz MAC address"
#define DEFAULT_24G_SSID_KEY        "Default 2.4 GHz SSID"
#define DEFAULT_50G_SSID_KEY        "Default 5.0 GHz SSID"
#define DEFAULT_WIFI_PASSWORD_KEY   "Default WIFI Password"
#define DEFAULT_XHS_SSID_KEY        "Default XHS SSID for 2.4GHZ and 5.0GHZ"
#define DEFAULT_XHS_PASSWORD_KEY    "Default XHS Password"
#define MAX_DEFAULT_VALUE_SIZE      128
#define FACTORY_DEFAULTS_FILE       "/tmp/factory_nvram.data"

#define QCA_MAX_CMD_SZ              128

/* ────────────────────────── extern QCA helpers ──────────────────────────── */

extern int qca_getRadiosIndex(void);
extern int qca_nl_cfg80211_init(void);
extern int isValidAPIndex(int apIndex);

/* ──────────────────────── static look-up tables ─────────────────────────── */

static const char *getRadiusCfgFile = "radius.cfg";

typedef enum radio_band {
    radio_2g = 0,
    radio_5g
} radio_band_t;

struct wifiChannelWidthMap {
    wifi_channelBandwidth_t halWifiChanWidth;
    char wifiChanWidthName[16];
};

struct wifiVariantBitMap {
    wifi_ieee80211Variant_t halWifiRadioMode;
    char halWifiRadioModename[5];
};

typedef struct {
    radio_band_t halWifiBand;
    char wifiBandName[10];
} wifiBandMap;

static wifiBandMap wifiRadioBandMap[] = {
    { radio_2g, "2GHz" },
    { radio_5g, "5GHz" },
};

static struct wifiChannelWidthMap wifiChannelBandWidthMap[] = {
    { WIFI_CHANNELBANDWIDTH_20MHZ,    "20MHz"    },
    { WIFI_CHANNELBANDWIDTH_40MHZ,    "40MHz"    },
    { WIFI_CHANNELBANDWIDTH_80MHZ,    "80MHz"    },
    { WIFI_CHANNELBANDWIDTH_160MHZ,   "160MHz"   },
    { WIFI_CHANNELBANDWIDTH_80_80MHZ, "80+80MHz" },
};

static struct wifiVariantBitMap wifiRadioModeBitMap[] = {
    { WIFI_80211_VARIANT_A,  "a"  },
    { WIFI_80211_VARIANT_B,  "b"  },
    { WIFI_80211_VARIANT_G,  "g"  },
    { WIFI_80211_VARIANT_N,  "n"  },
    { WIFI_80211_VARIANT_H,  "h"  },
    { WIFI_80211_VARIANT_AC, "ac" },
    { WIFI_80211_VARIANT_AD, "ad" },
    { WIFI_80211_VARIANT_AX, "ax" },
};

enum qca_phymode {
    QCA_HAL_IEEE80211_PHYMODE_AUTO             = 0,
    QCA_HAL_IEEE80211_PHYMODE_11A              = 1,
    QCA_HAL_IEEE80211_PHYMODE_11B              = 2,
    QCA_HAL_IEEE80211_PHYMODE_11G              = 3,
    QCA_HAL_IEEE80211_PHYMODE_FH               = 4,
    QCA_HAL_IEEE80211_PHYMODE_TURBO_A          = 5,
    QCA_HAL_IEEE80211_PHYMODE_TURBO_G          = 6,
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT20        = 7,
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT20        = 8,
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS    = 9,
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS   = 10,
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS    = 11,
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS   = 12,
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40        = 13,
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40        = 14,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20       = 15,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS   = 16,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS  = 17,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40       = 18,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80       = 19,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160      = 20,
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80    = 21,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20       = 22,
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20       = 23,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS   = 24,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS  = 25,
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS   = 26,
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS  = 27,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40       = 28,
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40       = 29,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80       = 30,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160      = 31,
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80    = 32,
    QCA_HAL_IEEE80211_PHYMODE_INVALID
};

static const uint8_t *phymode_strings[] = {
    [QCA_HAL_IEEE80211_PHYMODE_AUTO]            = (uint8_t *)"AUTO",
    [QCA_HAL_IEEE80211_PHYMODE_11A]             = (uint8_t *)"11A",
    [QCA_HAL_IEEE80211_PHYMODE_11B]             = (uint8_t *)"11B",
    [QCA_HAL_IEEE80211_PHYMODE_11G]             = (uint8_t *)"11G",
    [QCA_HAL_IEEE80211_PHYMODE_FH]              = (uint8_t *)"FH",
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_A]         = (uint8_t *)"TA",
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_G]         = (uint8_t *)"TG",
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT20]       = (uint8_t *)"11NAHT20",
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT20]       = (uint8_t *)"11NGHT20",
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS]   = (uint8_t *)"11NAHT40PLUS",
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS]  = (uint8_t *)"11NAHT40MINUS",
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS]   = (uint8_t *)"11NGHT40PLUS",
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS]  = (uint8_t *)"11NGHT40MINUS",
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40]       = (uint8_t *)"11NGHT40",
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40]       = (uint8_t *)"11NAHT40",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20]      = (uint8_t *)"11ACVHT20",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS]  = (uint8_t *)"11ACVHT40PLUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS] = (uint8_t *)"11ACVHT40MINUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40]      = (uint8_t *)"11ACVHT40",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80]      = (uint8_t *)"11ACVHT80",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160]     = (uint8_t *)"11ACVHT160",
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80]   = (uint8_t *)"11ACVHT80_80",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20]      = (uint8_t *)"11AHE20",
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20]      = (uint8_t *)"11GHE20",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS]  = (uint8_t *)"11AHE40PLUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS] = (uint8_t *)"11AHE40MINUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS]  = (uint8_t *)"11GHE40PLUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS] = (uint8_t *)"11GHE40MINUS",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40]      = (uint8_t *)"11AHE40",
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40]      = (uint8_t *)"11GHE40",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80]      = (uint8_t *)"11AHE80",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160]     = (uint8_t *)"11AHE160",
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80]   = (uint8_t *)"11AHE80_80",
    [QCA_HAL_IEEE80211_PHYMODE_INVALID]          = NULL,
};

/* WPS event strings */
static const uint8_t *WPS_enum_to_str[] = {
    [WPS_EV_M2D]                       = (uint8_t *)"WPS_EV_M2D",
    [WPS_EV_FAIL]                      = (uint8_t *)"WPS_EV_FAIL",
    [WPS_EV_SUCCESS]                   = (uint8_t *)"WPS_EV_SUCCESS",
    [WPS_EV_PWD_AUTH_FAIL]             = (uint8_t *)"WPS_EV_PWD_AUTH_FAIL",
    [WPS_EV_PBC_OVERLAP]               = (uint8_t *)"WPS_EV_PBC_OVERLAP",
    [WPS_EV_PBC_TIMEOUT]               = (uint8_t *)"WPS_EV_PBC_TIMEOUT",
    [WPS_EV_PBC_ACTIVE]                = (uint8_t *)"WPS_EV_PBC_ACTIVE",
    [WPS_EV_PBC_DISABLE]               = (uint8_t *)"WPS_EV_PBC_DISABLE",
    [WPS_EV_ER_AP_ADD]                 = (uint8_t *)"WPS_EV_ER_AP_ADD",
    [WPS_EV_ER_AP_REMOVE]              = (uint8_t *)"WPS_EV_ER_AP_REMOVE",
    [WPS_EV_ER_ENROLLEE_ADD]           = (uint8_t *)"WPS_EV_ER_ENROLLEE_ADD",
    [WPS_EV_ER_ENROLLEE_REMOVE]        = (uint8_t *)"WPS_EV_ER_ENROLLEE_REMOVE",
    [WPS_EV_ER_AP_SETTINGS]            = (uint8_t *)"WPS_EV_ER_AP_SETTINGS",
    [WPS_EV_ER_SET_SELECTED_REGISTRAR] = (uint8_t *)"WPS_EV_ER_SET_SELECTED_REGISTRAR",
    [WPS_EV_AP_PIN_SUCCESS]            = (uint8_t *)"WPS_EV_AP_PIN_SUCCESS",
};

static const uint8_t *WPS_ei_to_str[] = {
    [WPS_EI_NO_ERROR]                      = (uint8_t *)"No Error",
    [WPS_EI_SECURITY_TKIP_ONLY_PROHIBITED] = (uint8_t *)"TKIP Only Prohibited",
    [WPS_EI_SECURITY_WEP_PROHIBITED]       = (uint8_t *)"WEP Prohibited",
    [WPS_EI_AUTH_FAILURE]                   = (uint8_t *)"Authentication Failure",
};

static const uint8_t *pbc_status_str[] = {
    [WPS_PBC_STATUS_DISABLE]  = (uint8_t *)"Disabled",
    [WPS_PBC_STATUS_ACTIVE]   = (uint8_t *)"Active",
    [WPS_PBC_STATUS_TIMEOUT]  = (uint8_t *)"Timed-out",
    [WPS_PBC_STATUS_OVERLAP]  = (uint8_t *)"Overlap",
};

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

typedef BOOL (*vap_type)(unsigned int ap_index);

static vap_type vap_type_arr[10] = {
    is_wifi_hal_vap_private,
    is_wifi_hal_vap_xhs,
    is_wifi_hal_vap_hotspot_open,
    is_wifi_hal_vap_lnf_psk,
    is_wifi_hal_vap_hotspot_secure,
    is_wifi_hal_vap_lnf_radius,
    is_wifi_hal_vap_mesh_backhaul,
    is_wifi_hal_vap_mesh_sta
};

/* ────────────────────── factory-defaults helpers ────────────────────────── */

static int read_from_factory_defaults(char *filename, char *key, char *value, int val_len)
{
    FILE *fp = NULL;
    char buf[1024] = {0};
    char *ptr = NULL;
    int len;

    memset(value, '\0', val_len);

    if (access(filename, F_OK) != 0) {
        wifi_hal_error_print("%s:%d Factory file not found\n", __func__, __LINE__);
        return -1;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d Cannot open factory file\n", __func__, __LINE__);
        return -1;
    }

    while (!feof(fp)) {
        memset(buf, '\0', sizeof(buf));
        if (fgets(buf, sizeof(buf), fp) == NULL)
            break;
        if ((ptr = strstr(buf, key)) != NULL)
            break;
    }

    if (ptr == NULL) {
        fclose(fp);
        wifi_hal_error_print("%s:%d Key %s not found in factory file\n",
                             __func__, __LINE__, key);
        return -1;
    }

    ptr += strlen(key);
    while (*ptr != '\0' && (*ptr == ' ' || *ptr == ':'))
        ++ptr;

    strncpy(value, ptr, val_len - 1);
    value[val_len - 1] = '\0';
    len = strlen(value) - 1;
    if (len >= 0 && value[len] == '\n')
        value[len] = '\0';

    fclose(fp);
    return 0;
}

/* ───────────────── QCA NVRAM helpers (legacy cfg80211tool) ─────────────── */

void qcacfg_nvram_set_str(const char *param, const char *val)
{
    char cmd[DEFAULT_CMD_SIZE] = {0};

    if (param == NULL || val == NULL || strlen(param) == 0 || strlen(val) == 0)
        return;

    snprintf(cmd, sizeof(cmd), "qc-config update %s %s", param, val);
    system(cmd);
}

void qcacfg_nvram_set_int(const char *param, const int val)
{
    char cmd[DEFAULT_CMD_SIZE] = {0};

    if (param == NULL || strlen(param) == 0)
        return;

    snprintf(cmd, sizeof(cmd), "qc-config update %s %d", param, val);
    system(cmd);
}

int qcacfg_nvram_get(const char *param, const char *val, const unsigned int size)
{
    char cmd[DEFAULT_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    FILE *fptr = NULL;

    if (param == NULL || val == NULL || strlen(param) == 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "qc-config get %s", param);
    fptr = popen(cmd, "r");
    if (fptr == NULL) {
        wifi_hal_error_print("%s:%d popen error\n", __func__, __LINE__);
        return -1;
    }

    if (fgets(buf, sizeof(buf), fptr) != NULL) {
        char *nl = strchr(buf, '\n');
        if (nl)
            *nl = '\0';
        strncpy((char *)val, buf, size - 1);
    }

    pclose(fptr);
    return 0;
}

static int qcacfg_nvram_get_bool(const char *param, bool *val)
{
    char buf[16] = {0};
    int ret;

    ret = qcacfg_nvram_get(param, buf, sizeof(buf));
    if (ret == 0 && buf[0] != '\0') {
        *val = (atoi(buf) != 0);
    }
    return ret;
}

/* ─────────────────── radio-index validation (XE2: 3 radios) ─────────────── */

int check_radio_index(uint8_t radio_index)
{
    if (radio_index < IPQ_XE2_MAX_NUM_RADIOS)
        return 0;

    wifi_hal_dbg_print("%s: radio index %d out of range (max %d)\n",
                       __FUNCTION__, radio_index, IPQ_XE2_MAX_NUM_RADIOS);
    return -1;
}

/* ──────────────────────── platform API functions ─────────────────────────── */

int platform_pre_init(void)
{
    qca_getRadiosIndex();
    qca_nl_cfg80211_init();
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    char cmd[DEFAULT_CMD_SIZE];
    unsigned int idx;
    int ret = -1;
    wifi_interface_name_idex_map_t interface_map[IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);

    get_wifi_interface_info_map(interface_map);

    /* Set ACS min/max dwell for every valid AP VAP across all 3 radios
     * (2.4G / 5GL / 5GH) via the QCA driver (legacy cfg80211tool). */
    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {
        int ap_index = interface_map[idx].index;

        if (!isValidAPIndex(ap_index))
            continue;

        snprintf(cmd, sizeof(cmd),
                 "cfg80211tool %s acsmindwell 51", interface_map[idx].interface_name);
        ret = system(cmd);
        if (ret == -1)
            wifi_hal_error_print("Unable to set min ACS dwell %s:%d\n",
                                 __func__, __LINE__);

        snprintf(cmd, sizeof(cmd),
                 "cfg80211tool %s acsmaxdwell 51", interface_map[idx].interface_name);
        ret = system(cmd);
        if (ret == -1)
            wifi_hal_error_print("Unable to set max ACS dwell %s:%d\n",
                                 __func__, __LINE__);
    }

    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

/* ──────────── VAP private-index helpers (NL80211 interface map) ─────────── */

void getprivatevap2G(unsigned int *index)
{
    unsigned int idx;
    wifi_interface_name_idex_map_t interface_map[IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    if (index == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return;
    }

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {
        if (strncmp(interface_map[idx].vap_name, "private_ssid_2g",
                    strlen("private_ssid_2g")) == 0) {
            *index = interface_map[idx].index;
        }
    }
}

void getprivatevap5G(unsigned int *index)
{
    unsigned int idx;
    wifi_interface_name_idex_map_t interface_map[IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    if (index == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return;
    }

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {
        if (strncmp(interface_map[idx].vap_name, "private_ssid_5g",
                    strlen("private_ssid_5g")) == 0) {
            *index = interface_map[idx].index;
        }
    }
}

/* Resolve the private-SSID AP VAP index that belongs to a given RDK radio
 * index. Works for all 3 XE2 radios (2.4G / 5GL / 5GH) because it keys off
 * the interface map's rdk_radio_index rather than the band. */
static void get_private_vap_for_radio(wifi_radio_index_t radio_index,
                                      unsigned int *vap_index)
{
    unsigned int idx;
    wifi_interface_name_idex_map_t interface_map[IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    if (vap_index == NULL)
        return;

    get_wifi_interface_info_map(interface_map);

    for (idx = 0; idx < ARRAY_SZ(interface_map); idx++) {
        if (interface_map[idx].rdk_radio_index == radio_index &&
            strncmp(interface_map[idx].vap_name, "private_ssid_",
                    strlen("private_ssid_")) == 0) {
            *vap_index = interface_map[idx].index;
            return;
        }
    }
}

/* ──────── Radio mode / phymode helper (cfg80211tool → QCA driver) ──── */

void qca_setRadioMode(wifi_radio_index_t index,
                       wifi_radio_operationParam_t *operationParam)
{
    unsigned int apindex = 0;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    char tmp[DEFAULT_CMD_SIZE] = {0};
    char command[DEFAULT_CMD_SIZE] = {0};
    char buffer[DEFAULT_CMD_SIZE] = {0};
    char output[DEFAULT_CMD_SIZE] = {0};
    FILE *fp = NULL;
    wifi_ieee80211Variant_t variant;
    wifi_channelBandwidth_t channelWidth;
    wifi_interface_name_idex_map_t interface_map[IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    variant      = operationParam->variant;
    channelWidth = operationParam->channelWidth;

    get_wifi_interface_info_map(interface_map);
    get_private_vap_for_radio(index, &apindex);

    switch (operationParam->band) {
    case WIFI_FREQUENCY_2_4_BAND:
        if (variant == WIFI_80211_VARIANT_B) {
            strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11B],
                    DEFAULT_CMD_SIZE);
        } else if (variant == WIFI_80211_VARIANT_G) {
            strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11G],
                    DEFAULT_CMD_SIZE);
        } else if (variant & WIFI_80211_VARIANT_AX) {
            if (channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40],
                        DEFAULT_CMD_SIZE);
            else
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20],
                        DEFAULT_CMD_SIZE);
        } else if (variant & WIFI_80211_VARIANT_N) {
            if (channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT40],
                        DEFAULT_CMD_SIZE);
            else
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT20],
                        DEFAULT_CMD_SIZE);
        } else {
            strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_AUTO],
                    DEFAULT_CMD_SIZE);
        }
        break;

    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        if (variant & WIFI_80211_VARIANT_AX) {
            if (channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160],
                        DEFAULT_CMD_SIZE);
            else if (channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80],
                        DEFAULT_CMD_SIZE);
            else if (channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40],
                        DEFAULT_CMD_SIZE);
            else
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20],
                        DEFAULT_CMD_SIZE);
        } else if (variant & WIFI_80211_VARIANT_AC) {
            if (channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80],
                        DEFAULT_CMD_SIZE);
            else if (channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40],
                        DEFAULT_CMD_SIZE);
            else
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20],
                        DEFAULT_CMD_SIZE);
        } else if (variant & WIFI_80211_VARIANT_N) {
            if (channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT40],
                        DEFAULT_CMD_SIZE);
            else
                strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT20],
                        DEFAULT_CMD_SIZE);
        } else if (variant == WIFI_80211_VARIANT_A) {
            strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11A],
                    DEFAULT_CMD_SIZE);
        } else {
            strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_AUTO],
                    DEFAULT_CMD_SIZE);
        }
        break;

    default:
        strncpy(cmd, (char *)phymode_strings[QCA_HAL_IEEE80211_PHYMODE_AUTO],
                DEFAULT_CMD_SIZE);
        break;
    }

    /* Push the computed phymode to the QCA driver via cfg80211tool, but only
     * when it differs from the current mode (avoids a needless radio bounce).
     * This is the rdk-wifi-hal → driver hop for the radio's PHY mode. */
    snprintf(command, sizeof(command),
             "cfg80211tool %s%d get_mode | cut -d':' -f2", VAP_PREFIX, apindex);
    fp = popen(command, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d Failed to query current phymode\n",
                             __func__, __LINE__);
        return;
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
        strncpy(output, buffer, sizeof(output) - 1);
    pclose(fp);

    if (strncmp(output, cmd, strlen(cmd)) != 0) {
        wifi_hal_dbg_print("%s:%d Setting phymode %s for radio %d vap %d\n",
                           __func__, __LINE__, cmd, index, apindex);
        snprintf(tmp, sizeof(tmp), "cfg80211tool %s%d mode %s",
                 VAP_PREFIX, apindex, cmd);
        system(tmp);
    }
}

/* ─────── radio-parameter setter (NL80211 + legacy cfg80211tool hybrid) ──── */

int platform_set_radio(wifi_radio_index_t index,
                       wifi_radio_operationParam_t *operationParam)
{
    wifi_radio_info_t *radio = NULL;
    unsigned int primary_vap_index = 0;
    int apIndex, ret;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    char param[DEFAULT_CMD_SIZE] = {0};
    char temp_buff[MAX_BUF_SIZE] = {0};
    const char *guard_int = NULL;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n",
                             __func__, __LINE__, index);
        return RETURN_ERR;
    }

    /* Resolve the private VAP that belongs to this radio (2.4G / 5GL / 5GH) */
    get_private_vap_for_radio(index, &primary_vap_index);

    /* Push radio mode to the QCA driver via cfg80211tool */
    qca_setRadioMode(index, operationParam);

    /* Persist radio parameters to NVRAM */
    snprintf(param, sizeof(param), "%s%d.channel", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->channel);

    snprintf(param, sizeof(param), "%s%d.channelWidth", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->channelWidth);

    snprintf(param, sizeof(param), "%s%d.autoChannelEnabled", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->autoChannelEnabled);

    snprintf(param, sizeof(param), "%s%d.band", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->band);

    snprintf(param, sizeof(param), "%s%d.beaconInterval", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->beaconInterval);

    /* Guard interval */
    snprintf(param, sizeof(param), "%s.%d.guardInterval", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->guardInterval);

    switch (operationParam->guardInterval) {
    case wifi_guard_interval_400:  guard_int = "400nsec";  break;
    case wifi_guard_interval_800:  guard_int = "800nsec";  break;
    case wifi_guard_interval_1600: guard_int = "1600nsec"; break;
    case wifi_guard_interval_3200: guard_int = "3200nsec"; break;
    default: break;
    }

    if (guard_int != NULL) {
        ret = wifi_setRadioGuardInterval(index, (char *)guard_int);
        if (ret != RETURN_OK)
            wifi_hal_dbg_print("%s:%d Failed to set Guard Interval\n",
                               __func__, __LINE__);
    }

    /* ACS at boot */
    if (operationParam->autoChannelEnabled) {
        if (!radio->configured) {
            snprintf(cmd, sizeof(cmd), "iwconfig %s%d channel 0",
                     VAP_PREFIX, primary_vap_index);
            ret = system(cmd);
            if (ret == -1)
                wifi_hal_error_print("ACS set command failed %s:%d\n",
                                     __func__, __LINE__);
        }
    }

    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

/* ───────────── VAP create / bridge helper (NL80211 netlink) ─────────────── */

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *vap;
    int vap_itr;
    char interface_name[32];
    char cmd[DEFAULT_CMD_SIZE];

    for (vap_itr = 0; vap_itr < map->num_vaps; vap_itr++) {
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            /* Enable ap_bridge for intra-BSS packet transfer */
            snprintf(cmd, sizeof(cmd), "cfg80211tool %s ap_bridge 1", interface_name);
            wifi_hal_dbg_print("%s:%d Executing %s\n", __func__, __LINE__, cmd);
            system(cmd);
        }
    }

    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

/* ── XE2 platform hooks required by the wifi-hal core (ported from platform_xer5.c) ── */

int platform_get_chanspec_list(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth,
                               const wifi_channels_list_t *channels, char *buff)
{
    wifi_hal_dbg_print("%s:%d \n", __func__, __LINE__);
    return 0;
}

int platform_set_acs_exclusion_list(wifi_radio_index_t index, char *buff)
{
    wifi_hal_dbg_print("%s:%d \n", __func__, __LINE__);
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

/* ────────────── radio pre-init (NL80211 bridge & VAP teardown) ──────────── */

int platform_set_radio_pre_init(wifi_radio_index_t index,
                                wifi_radio_operationParam_t *operationParam)
{
    wifi_radio_info_t *radio = NULL;

    wifi_hal_dbg_print("%s:%d Enter\n", __func__, __LINE__);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n",
                             __func__, __LINE__, index);
        return RETURN_ERR;
    }

    if (!radio->configured) {
        wifi_hal_info_print("%s:%d: Radio first-time configuration.\n",
                            __func__, __LINE__);
    }

    wifi_hal_dbg_print("%s:%d Exit\n", __func__, __LINE__);
    return RETURN_OK;
}

/* ──────────────────── NVRAM / default-value accessors ───────────────────── */

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    char param[DEFAULT_CMD_SIZE] = {0};

    snprintf(param, sizeof(param), "%s%d.vap_enabled", VAP_PREFIX, vap_index);
    qcacfg_nvram_get_bool(param, vap_enable);
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode, int vap_index)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    int ret;
    char param[DEFAULT_CMD_SIZE] = {0};
    char value[MAX_DEFAULT_VALUE_SIZE] = {0};

    if (is_wifi_hal_vap_private(vap_index)) {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE,
                                         DEFAULT_WIFI_PASSWORD_KEY,
                                         value, sizeof(value));
    } else if (is_wifi_hal_vap_xhs(vap_index)) {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE,
                                         DEFAULT_XHS_PASSWORD_KEY,
                                         value, sizeof(value));
    } else {
        snprintf(param, sizeof(param), "%s%d.password", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, password, WIFI_AP_MAX_PASSPHRASE_LEN);
        return 0;
    }

    if (ret == -1) {
        wifi_hal_info_print("%s:%d Reading default password for vap %d from qca DB\n",
                            __func__, __LINE__, vap_index);
        snprintf(param, sizeof(param), "%s%d.password", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, password, WIFI_AP_MAX_PASSPHRASE_LEN);
        return 0;
    }

    strncpy(password, value, WIFI_AP_MAX_PASSPHRASE_LEN - 1);
    password[WIFI_AP_MAX_PASSPHRASE_LEN - 1] = '\0';
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    int ret;
    char param[DEFAULT_CMD_SIZE] = {0};
    char value[MAX_DEFAULT_VALUE_SIZE] = {0};

    if (is_wifi_hal_vap_private(vap_index)) {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE,
                                         DEFAULT_24G_SSID_KEY,
                                         value, sizeof(value));
    } else if (is_wifi_hal_vap_xhs(vap_index)) {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE,
                                         DEFAULT_XHS_SSID_KEY,
                                         value, sizeof(value));
    } else {
        snprintf(param, sizeof(param), "%s%d.ssid", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, ssid, MAX_SSID_LEN);
        return 0;
    }

    if (ret == -1) {
        wifi_hal_info_print("%s:%d Reading default SSID for vap %d from qca DB\n",
                            __func__, __LINE__, vap_index);
        snprintf(param, sizeof(param), "%s%d.ssid", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, ssid, MAX_SSID_LEN);
        return 0;
    }

    strncpy(ssid, value, MAX_SSID_LEN - 1);
    ssid[MAX_SSID_LEN - 1] = '\0';
    return 0;
}

/* ──────────────────────── stub / pass-through APIs ──────────────────────── */

int platform_get_aid(void *priv, u16 *aid, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_free_aid(void *priv, u16 *aid)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_sync_done(void *priv)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,
                                    wifi_channelBandwidth_t *channelWidth)
{
    char temp_buff[MAX_BUF_SIZE] = {0};
    u_int8_t seqCounter;

    wifi_getRadioOperatingChannelBandwidth(index, temp_buff);
    if (temp_buff[0] == '\0') {
        wifi_hal_error_print("%s:%d Channel Bandwidth is NULL\n",
                             __func__, __LINE__);
        return -1;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiChannelBandWidthMap); seqCounter++) {
        if (strncmp(temp_buff, wifiChannelBandWidthMap[seqCounter].wifiChanWidthName,
                    strlen(wifiChannelBandWidthMap[seqCounter].wifiChanWidthName)) == 0) {
            *channelWidth = wifiChannelBandWidthMap[seqCounter].halWifiChanWidth;
            return 0;
        }
    }

    wifi_hal_error_print("%s:%d Channel Bandwidth not supported\n",
                         __func__, __LINE__);
    return -1;
}

int platform_update_radio_presence(void)
{
    unsigned int index;
    char path[DEFAULT_CMD_SIZE] = {0};
    wifi_radio_info_t *radio = NULL;

    wifi_hal_info_print("%s:%d: g_wifi_hal.num_radios %d\n",
                        __func__, __LINE__, g_wifi_hal.num_radios);

    for (index = 0; index < g_wifi_hal.num_radios; index++) {
        radio = get_radio_by_rdk_index(index);
        snprintf(path, sizeof(path), "/sys/class/net/wifi%d", index);
        if (!is_interface_exists(path))
            radio->radio_presence = false;
        wifi_hal_info_print("%s:%d: Index %d presence %d\n",
                            __func__, __LINE__, index, radio->radio_presence);
    }

    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int *output_dbm)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_set_txpower(void *priv, uint txpower)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return 0;
}

int platform_set_offload_mode(void *priv, uint offload_mode)
{
    wifi_hal_dbg_print("%s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

int platform_get_radius_key_default(char *radius_key)
{
    char nvram_name[NVRAM_NAME_SIZE] = {0};
    char temp_buff[MAX_BUF_SIZE] = {0};
    char val[WIFI_MAX_RADIUS_KEY] = {0};
    FILE *fptr = NULL;

    snprintf(temp_buff, sizeof(temp_buff), "/usr/bin/GetConfigFile %s stdout",
             getRadiusCfgFile);
    fptr = popen(temp_buff, "r");
    if (fptr == NULL) {
        wifi_hal_dbg_print("%s: popen error\n", __FUNCTION__);
        return -1;
    }

    if (fgets(val, sizeof(val), fptr) == NULL) {
        snprintf(nvram_name, sizeof(nvram_name), "auth_server_shared_secret");
        qcacfg_nvram_get(nvram_name, val, WIFI_MAX_RADIUS_KEY);
    }

    pclose(fptr);
    strncpy(radius_key, val, WIFI_MAX_RADIUS_KEY - 1);
    radius_key[WIFI_MAX_RADIUS_KEY - 1] = '\0';
    memset(val, '\0', sizeof(val));
    return 0;
}

int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}

int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    if (vendor_oui == NULL) {
        wifi_hal_error_print("%s:%d Invalid parameter\n", __func__, __LINE__);
        return -1;
    }
    strncpy(vendor_oui, OUI_QCA, vendor_oui_len - 1);
    vendor_oui[vendor_oui_len - 1] = '\0';
    return 0;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
                                      wifi_radioTemperature_t *radioPhyTemperature)
{
    char temp_buff[MAX_BUF_SIZE] = {0};
    char val[MAX_BUF_SIZE] = {0};
    char *context = NULL;
    FILE *fptr = NULL;

    if (check_radio_index(index) != 0)
        return -1;

    snprintf(temp_buff, sizeof(temp_buff),
             "cat /sys/class/net/wifi%d/thermal/temp", index);
    fptr = popen(temp_buff, "r");
    if (fptr == NULL) {
        wifi_hal_dbg_print("%s: popen error\n", __FUNCTION__);
        return -1;
    }

    fgets(val, MAX_BUF_SIZE, fptr);
    pclose(fptr);
    strtok_r(val, "\n", &context);

    radioPhyTemperature->radio_Temperature = (val[0] != '\0') ? atoi(val) : 0;
    return RETURN_OK;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    return 0;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    wifi_NeighborReport_t nbr_report;

    wifi_hal_info_print("%s:%d Enter %d\n", __func__, __LINE__, index);
    memcpy(nbr_report.bssid, mac, sizeof(mac_address_t));
    wifi_setNeighborReports(index, add, &nbr_report);
    return 0;
}

int platform_set_dfs(wifi_radio_index_t index,
                     wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    int res;

    if (priv == NULL) {
        wifi_hal_error_print("%s:%d:error couldn't find primary interface\n",
                             __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;
    wifi_vap_index_t retry_vap_index = interface->vap_info.vap_index;

    res = wifi_setApRetryLimit(retry_vap_index, RETRY_LIMIT);
    if (res)
        wifi_hal_dbg_print("%s:%d: AP_RETRY_LIMIT failed:%d",
                           __func__, __LINE__, res);

    return 0;
}

/* ============================================================================
 * Missing platform API functions required by rdk-wifi-hal core
 * ============================================================================ */

int is_interface_exists(const char *fname)
{
    char path[128] = {0};
    snprintf(path, sizeof(path), "/sys/class/net/%s", fname);
    return (access(path, F_OK) == 0) ? 1 : 0;
}

void mac_print(u_int8_t *context, u_int8_t *mac)
{
    wifi_hal_dbg_print("%s: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       context ? (char *)context : "",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    char param[DEFAULT_CMD_SIZE] = {0};
    snprintf(param, sizeof(param), "vap%d_passphrase", vap_index);
    return qcacfg_nvram_get(param, l_password, MAX_KEYPASSPHRASE_LEN);
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    char param[DEFAULT_CMD_SIZE] = {0};
    snprintf(param, sizeof(param), "vap%d_ssid", vap_index);
    return qcacfg_nvram_get(param, l_ssid, MAX_SSID_LEN);
}

int platform_flags_init(int *flags)
{
    if (flags == NULL) return -1;
    *flags = 0;
    return 0;
}

int platform_get_country_code_default(char *code)
{
    if (code == NULL) return -1;
    strncpy(code, "US", COUNTRY_LENGTH);
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    if (pin == NULL) return -1;
    strncpy(pin, "12345670", 9);
    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s:%d XE2 platform_pre_create_vap radio=%d\n",
                       __func__, __LINE__, index);
    return RETURN_OK;
}

int platform_wps_event(wifi_wps_event_t data)
{
    wifi_hal_dbg_print("%s:%d WPS event received\n", __func__, __LINE__);
    return RETURN_OK;
}

/* MLD / 802.11be — not supported on XE2 (Dakota IPQ4019, 11ax max) */
INT platform_create_interface_attributes(struct nl_msg **msg_ptr,
                                         wifi_radio_info_t *radio,
                                         wifi_vap_info_t *vap)
{
    wifi_hal_dbg_print("%s:%d XE2 create_interface_attributes for vap %s\n",
                       __func__, __LINE__, vap->vap_name);
    return RETURN_OK;
}

INT platform_set_intf_mld_bonding(wifi_radio_info_t *radio,
                                  wifi_interface_info_t *interface)
{
    /* MLD not supported on XE2 (no 802.11be) */
    return RETURN_OK;
}

INT platform_set_radio_mld_bonding(wifi_radio_info_t *radio)
{
    /* MLD not supported on XE2 (no 802.11be) */
    return RETURN_OK;
}

/* ═══════════════════════ XE2 QCA HAL op supplement ═══════════════════════
 *
 * The QCA "extender" HAL ops below are normally provided by the Qualcomm vendor
 * HAL (hal-qcawifi -> libhal_wifi) on other QCA products such as XER5. That
 * vendor blob is not part of the XE2 workspace, and the generic libhal_wifi
 * that XE2 builds does not export these symbols, so librdk_wifihal (this file)
 * provides them for the XE2 extender.
 *
 * Framework notes:
 *   - The OpenSync/OSW flow that rdk-wifi-hal replaces called qca_getRadiosIndex()
 *     and qca_nl_cfg80211_init() from platform_pre_init(); that call sequence is
 *     preserved above. On the rdk-wifi-hal path the nl80211/cfg80211 sockets and
 *     radio discovery are owned by the HAL core (wifi_hal_nl80211*.c) + the
 *     static interface map, so those two legacy QCA entry points are no-ops here.
 *   - isValidAPIndex() is implemented for real (sysfs presence check) because it
 *     gates the per-VAP cfg80211tool loop in platform_post_init().
 *   - The remaining wifi_hal API ops mirror the XER5 QCA HAL, which stubs them
 *     for this driver release. They are safe bring-up stubs; wire real QCA
 *     driver calls here (cfg80211tool / nl80211 vendor cmds) as features land.
 *
 * All symbols are XE2_PORT-gated (this file is only compiled when XE2_PORT is
 * enabled in the HAL Makefile.am/configure).
 * ═════════════════════════════════════════════════════════════════════════ */

/* --- QCA platform discovery / init (called from platform_pre_init) --------- */

int qca_getRadiosIndex(void)
{
    /* Radio discovery on XE2 is driven by the rdk-wifi-hal nl80211 core and the
     * static interface map; the legacy QCA radio-index cache is not consumed by
     * this platform path, so this is a no-op on XE2. */
    return 0;
}

int qca_nl_cfg80211_init(void)
{
    /* nl80211/cfg80211 sockets are initialised by the rdk-wifi-hal core
     * (wifi_hal_nl80211.c) on XE2; the legacy QCA cfg80211 context is unused. */
    return 0;
}

int isValidAPIndex(int apIndex)
{
    char ap_dir[MAX_BUF_SIZE] = {0};

    if (apIndex < 0 ||
        apIndex >= (IPQ_XE2_MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO))
        return 0;

    snprintf(ap_dir, sizeof(ap_dir), "/sys/class/net/%s%d", VAP_PREFIX, apIndex);
    return (access(ap_dir, F_OK) != -1) ? 1 : 0;
}

/* --- wifi_hal API ops not provided by the generic libhal_wifi on XE2 -------- */

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t sta, UINT frequency,
                            UINT wait, UCHAR *frame, UINT len)
{
    (void)sta; (void)frequency; (void)wait; (void)frame;
    /* TODO(XE2): push action frame via QCA nl80211 vendor cmd / cfg80211tool. */
    wifi_hal_dbg_print("%s:%d apIndex=%d len=%u (XE2 stub)\n",
                       __func__, __LINE__, apIndex, len);
    return RETURN_OK;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t sta, UINT frequency,
                         UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, sta, frequency, 0, frame, len);
}

INT wifi_setNeighborReports(UINT apIndex, UINT numNeighborReports,
                            wifi_NeighborReport_t *neighborReports)
{
    (void)apIndex; (void)numNeighborReports; (void)neighborReports;
    /* 802.11k neighbor-report push not supported by the XE2 driver release. */
    return RETURN_OK;
}

INT wifi_getApDeviceRSSI(INT ap_index, CHAR *MAC, INT *output_RSSI)
{
    (void)ap_index; (void)MAC; (void)output_RSSI;
    return RETURN_ERR;
}

INT wifi_getApInterworkingElement(INT apIndex,
                                  wifi_InterworkingElement_t *output_struct)
{
    (void)apIndex; (void)output_struct;
    return RETURN_ERR;
}

INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable)
{
    /* TODO(XE2): program DFS-at-boot via QCA driver; no-op accept for bring-up. */
    wifi_hal_dbg_print("%s:%d radioIndex=%d enable=%d (XE2 stub)\n",
                       __func__, __LINE__, radioIndex, enable);
    return RETURN_OK;
}

INT wifi_enableCSIEngine(INT apIndex, mac_address_t sta, BOOL enable)
{
    (void)sta;
    /* TODO(XE2): wire CSI engine to QCA driver; accept for bring-up. */
    wifi_hal_dbg_print("%s:%d apIndex=%d enable=%d (XE2 stub)\n",
                       __func__, __LINE__, apIndex, enable);
    return RETURN_OK;
}
