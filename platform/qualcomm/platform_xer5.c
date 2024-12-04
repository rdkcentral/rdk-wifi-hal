#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"
#include "qca_wifi_hal.h"

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
#define MAX_NUM_RADIOS 2
#define OUI_QCA "0x001374"
#define RETRY_LIMIT 7

#define WIFI_24G_MAC_ADDR_KEY "WiFi 2.4GHz MAC address"
#define WIFI_50G_MAC_ADDR_KEY "WiFi 5.0GHz MAC address"
#define DEFAULT_24G_SSID_KEY "Default 2.4 GHz SSID"
#define DEFAULT_50G_SSID_KEY "Default 5.0 GHz SSID"
#define DEFAULT_WIFI_PASSWORD_KEY "Default WIFI Password"
#define DEFAULT_XHS_SSID_KEY "Default XHS SSID for 2.4GHZ and 5.0GHZ"
#define DEFAULT_XHS_PASSWORD_KEY "Default XHS Password"
#define MAX_DEFAULT_VALUE_SIZE 128
#define FACTORY_DEFAULTS_FILE "/tmp/factory_nvram.data"

#define QCA_MAX_CMD_SZ 128
#define MLD_PREFIX "mld"

extern INT wifi_setMLDaddr(INT apIndex, CHAR *mldMacAddress);

static const char* getRadiusCfgFile = "radius.cfg";

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

enum qca_phymode {
    QCA_HAL_IEEE80211_PHYMODE_AUTO             = 0,  /**< autoselect */
    QCA_HAL_IEEE80211_PHYMODE_11A              = 1,  /**< 5GHz, OFDM */
    QCA_HAL_IEEE80211_PHYMODE_11B              = 2,  /**< 2GHz, CCK */
    QCA_HAL_IEEE80211_PHYMODE_11G              = 3,  /**< 2GHz, OFDM */
    QCA_HAL_IEEE80211_PHYMODE_FH               = 4,  /**< 2GHz, GFSK */
    QCA_HAL_IEEE80211_PHYMODE_TURBO_A          = 5,  /**< 5GHz dyn turbo*/
    QCA_HAL_IEEE80211_PHYMODE_TURBO_G          = 6,  /**< 2GHz dyn turbo*/
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT20        = 7,  /**< 5GHz, HT20 */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT20        = 8,  /**< 2GHz, HT20 */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS    = 9,  /**< 5GHz, HT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS   = 10, /**< 5GHz, HT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS    = 11, /**< 2GHz, HT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS   = 12, /**< 2GHz, HT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11NG_HT40        = 13, /**< 2GHz, HT40 auto */
    QCA_HAL_IEEE80211_PHYMODE_11NA_HT40        = 14, /**< 5GHz, HT40 auto */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20       = 15, /**< 5GHz, VHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS   = 16, /**< 5GHz, VHT40 (Ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS  = 17, /**< 5GHz  VHT40 (Ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40       = 18, /**< 5GHz, VHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80       = 19, /**< 5GHz, VHT80 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160      = 20, /**< 5GHz, VHT160 */
    QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80    = 21, /**< 5GHz, VHT80_80 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20       = 22, /**< 5GHz, HE20 */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20       = 23, /**< 2GHz, HE20 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS   = 24, /**< 5GHz, HE40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS  = 25, /**< 5GHz, HE40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS   = 26, /**< 2GHz, HE40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS  = 27, /**< 2GHz, HE40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40       = 28, /**< 5GHz, HE40 */
    QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40       = 29, /**< 2GHz, HE40 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80       = 30, /**< 5GHz, HE80 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160      = 31, /**< 5GHz, HE160 */
    QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80    = 32, /**< 5GHz, HE80_80 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20      = 33, /**< 5GHz, EHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20      = 34, /**< 2GHz, EHT20 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40PLUS  = 35, /**< 5GHz, EHT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40MINUS = 36, /**< 5GHz, EHT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40PLUS  = 37, /**< 2GHz, EHT40 (ext ch +1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40MINUS = 38, /**< 2GHz, EHT40 (ext ch -1) */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40      = 39, /**< 2GHz, EHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40      = 40, /**< 2GHz, EHT40 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80      = 41, /**< 5GHz, EHT80 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160     = 42, /**< 5GHz, EHT160 */
    QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT320     = 43, /**< 5GHz, EHT320 */

    /* keep it last */
    QCA_HAL_IEEE80211_PHYMODE_INVALID                /**< Invalid Phymode */
 };

static const uint8_t *phymode_strings[] = {
    [QCA_HAL_IEEE80211_PHYMODE_AUTO]             = (uint8_t *)"AUTO",
    [QCA_HAL_IEEE80211_PHYMODE_11A]              = (uint8_t *)"11A",
    [QCA_HAL_IEEE80211_PHYMODE_11B]              = (uint8_t *)"11B",
    [QCA_HAL_IEEE80211_PHYMODE_11G]              = (uint8_t *)"11G" ,
    [QCA_HAL_IEEE80211_PHYMODE_FH]               = (uint8_t *)"FH" ,
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_A]          = (uint8_t *)"TA" ,
    [QCA_HAL_IEEE80211_PHYMODE_TURBO_G]          = (uint8_t *)"TG" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT20]        = (uint8_t *)"11NAHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT20]        = (uint8_t *)"11NGHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40PLUS]    = (uint8_t *)"11NAHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40MINUS]   = (uint8_t *)"11NAHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40PLUS]    = (uint8_t *)"11NGHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40MINUS]   = (uint8_t *)"11NGHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NG_HT40]        = (uint8_t *)"11NGHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11NA_HT40]        = (uint8_t *)"11NAHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20]       = (uint8_t *)"11ACVHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40PLUS]   = (uint8_t *)"11ACVHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40MINUS]  = (uint8_t *)"11ACVHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40]       = (uint8_t *)"11ACVHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80]       = (uint8_t *)"11ACVHT80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160]      = (uint8_t *)"11ACVHT160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80_80]    = (uint8_t *)"11ACVHT80_80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20]       = (uint8_t *) "11AHE20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20]       = (uint8_t *) "11GHE20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40PLUS]   = (uint8_t *) "11AHE40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40MINUS]  = (uint8_t *) "11AHE40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40PLUS]   = (uint8_t *) "11GHE40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40MINUS]  = (uint8_t *) "11GHE40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40]       = (uint8_t *) "11AHE40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40]       = (uint8_t *) "11GHE40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80] = (uint8_t *) "11AHE80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160] = (uint8_t *) "11AHE160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80_80] = (uint8_t *) "11AHE80_80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20] = (uint8_t *) "11AEHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20] = (uint8_t *) "11GEHT20" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40PLUS] = (uint8_t *) "11AEHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40MINUS] = (uint8_t *) "11AEHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40PLUS] = (uint8_t *) "11GEHT40PLUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40MINUS]   = (uint8_t *) "11GEHT40MINUS" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40] = (uint8_t *) "11AEHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40] = (uint8_t *) "11GEHT40" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80] = (uint8_t *) "11AEHT80" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160] = (uint8_t *) "11AEHT160" ,
    [QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT320] = (uint8_t *) "11AEHT320" ,

    [QCA_HAL_IEEE80211_PHYMODE_INVALID]          = NULL ,
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
    [WPS_EV_ER_AP_ADD]                 = (uint8_t*) "WPS_EV_ER_AP_ADD",
    [WPS_EV_ER_AP_REMOVE]              = (uint8_t*) "WPS_EV_ER_AP_REMOVE",
    [WPS_EV_ER_ENROLLEE_ADD]           = (uint8_t*) "WPS_EV_ER_ENROLLEE_ADD",
    [WPS_EV_ER_ENROLLEE_REMOVE]        = (uint8_t*) "WPS_EV_ER_ENROLLEE_REMOVE",
    [WPS_EV_ER_AP_SETTINGS]            = (uint8_t*) "WPS_EV_ER_AP_SETTINGS",
    [WPS_EV_ER_SET_SELECTED_REGISTRAR] = (uint8_t*) "WPS_EV_ER_SET_SELECTED_REGISTRAR",
    [WPS_EV_AP_PIN_SUCCESS]            = (uint8_t*) "WPS_EV_AP_PIN_SUCCESS",
};

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
typedef bool (*vap_type) (unsigned int ap_index);

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

int platform_pre_init()
{
    qca_getRadiosIndex();
    qca_nl_cfg80211_init();
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

void qcacfg_nvram_set_str (const char *param, const char *val) {

    char cmd[DEFAULT_CMD_SIZE] = {0};
    if (param == NULL || val == NULL || strlen(param) == NULL || strlen(val) == NULL) {
        return;
    }

    snprintf(cmd,sizeof(cmd),"qc-config update %s %s",param,val);
    system(cmd);
}

void qcacfg_nvram_set_int (const char *param, const int val) {

    char cmd[DEFAULT_CMD_SIZE] = {0};
    if (param == NULL || strlen(param) == NULL) {
        return;
    }

    snprintf(cmd,sizeof(cmd),"qc-config update %s %d",param,val);
    system(cmd);
}


int qcacfg_nvram_get (const char *param, const char *val, const unsigned int size) {

    if (param == NULL || val == NULL || size == 0 || strlen(param) == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return -1;
    }

    char cmd[DEFAULT_CMD_SIZE] = {0};
    FILE *fptr = NULL; char *context = NULL;

    snprintf(cmd,sizeof(cmd),"qc-config get %s",param);
    fptr = popen(cmd, "r");
    if (fptr == NULL) {
        wifi_hal_error_print("%s: popen error\n", __FUNCTION__);
        return -1 ;
    }
    fgets(val,size,fptr);
    pclose(fptr);
    strtok_r(val, "\n", &context);
    return 0;
}

int qcacfg_nvram_get_bool (const char *param, const bool *val) {

    char tmp[DEFAULT_CMD_SIZE] = {0};
    if (param == NULL || val == NULL || strlen(param) == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return -1;
    }

    qcacfg_nvram_get(param,tmp,sizeof(tmp));
    if (strncmp(tmp,"1",1)) {
        val = true;
    }
    else {
        val = false;
    }
    return 0;
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

//check if radio  present in info map
int check_radio_index(uint8_t radio_index)
{
    radio_interface_mapping_t platform_map_t[MAX_NUM_RADIOS];
    uint8_t i = 0;

    get_radio_interface_info_map(platform_map_t);

    for (i = 0; i < MAX_NUM_RADIOS ; i++) {
        if (platform_map_t[i].radio_index == radio_index) {

            return 0;
        }
    }

    wifi_hal_dbg_print("%s: radio not found\n", __FUNCTION__);
    return -1;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    return 0;
}

void getprivatevap2G(unsigned int *index)
{
    unsigned int idx = 0;
    wifi_interface_name_idex_map_t interface_map[(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
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
    wifi_interface_name_idex_map_t interface_map[(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];
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

void qca_setRadioMode(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    unsigned int apindex = 0, i = 0; int band = -1;
    size_t len = 0;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    char tmp[DEFAULT_CMD_SIZE] = {0};
    char command[DEFAULT_CMD_SIZE] = {0};
    char buffer[DEFAULT_CMD_SIZE] = {0};
    char output[DEFAULT_CMD_SIZE]={0};

    wifi_ieee80211Variant_t variant = WIFI_80211_VARIANT_AX;
    wifi_channelBandwidth_t channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;

    variant = operationParam->variant; channelWidth = operationParam->channelWidth;
    //wifi_interface_name_idex_map_t *interface_map;
    wifi_interface_name_idex_map_t interface_map[(MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)];

    get_wifi_interface_info_map(interface_map);

    switch (operationParam->band) {

        case WIFI_FREQUENCY_2_4_BAND:
            getprivatevap2G(&apindex);
            if (variant == WIFI_80211_VARIANT_B) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11B], DEFAULT_CMD_SIZE);

            } else if (variant == WIFI_80211_VARIANT_G) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11G], DEFAULT_CMD_SIZE);

            } else if (variant == (WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G)) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11G], DEFAULT_CMD_SIZE);

            } else if (!(variant & WIFI_80211_VARIANT_AX) && !(variant & WIFI_80211_VARIANT_BE)) {
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NG_HT40], DEFAULT_CMD_SIZE);
                }

            } else if ((variant & WIFI_80211_VARIANT_AX) && !(variant & WIFI_80211_VARIANT_BE)) {
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXG_HE40], DEFAULT_CMD_SIZE);
                }

            } else if (variant & WIFI_80211_VARIANT_BE) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20], DEFAULT_CMD_SIZE);
                if ( channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEG_EHT40], DEFAULT_CMD_SIZE);
                }
            }
            break;

        case WIFI_FREQUENCY_5_BAND:
        case WIFI_FREQUENCY_5L_BAND:
        case WIFI_FREQUENCY_5H_BAND:
            getprivatevap5G(&apindex);
            if ((variant & WIFI_80211_VARIANT_A) && !(variant & ~WIFI_80211_VARIANT_A)) {
                strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11A], DEFAULT_CMD_SIZE);
            }
            else if ((variant & WIFI_80211_VARIANT_N) && (~variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_AC) && (~variant & WIFI_80211_VARIANT_BE)) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11NA_HT40], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_AC) && (~variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_BE))
            {
                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AC_VHT160], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_AX) && (~variant & WIFI_80211_VARIANT_BE) ) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11AXA_HE160], DEFAULT_CMD_SIZE);
                }
            }
            else if ((variant & WIFI_80211_VARIANT_BE)) {

                if (channelWidth & WIFI_CHANNELBANDWIDTH_20MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT20], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_40MHZ) {
                    // QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT40], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_80MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT80], DEFAULT_CMD_SIZE);
                }
                else if (channelWidth & WIFI_CHANNELBANDWIDTH_160MHZ) {
                    strncpy(cmd, phymode_strings[QCA_HAL_IEEE80211_PHYMODE_11BEA_EHT160], DEFAULT_CMD_SIZE);
                }
            }
            break;
        default:
            break;
    }
    snprintf(command, DEFAULT_CMD_SIZE, "cfg80211tool %s%d get_mode | cut -d':' -f2",VAP_PREFIX,apindex);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d Failed to run command \n",__func__,__LINE__);
        return -1;
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncpy(output, buffer, DEFAULT_CMD_SIZE);
        output[strcspn(output, "\n")] = '\0';
    }
    pclose(fp);

    len = strlen(output) > strlen(cmd) ? strlen(output) : strlen(cmd);
    if (strncmp(output, cmd, len) != 0 ) {
        snprintf(tmp, DEFAULT_CMD_SIZE, "cfg80211tool %s%d mode %s",VAP_PREFIX,apindex,cmd);
        system(tmp);
    }

    return;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char param [DEFAULT_CMD_SIZE] = {0};
    char temp_buff [MAX_BUF_SIZE] = {0};
    char cmd[MAX_BUF_SIZE] = {0};
    int ret = 0;
    uint32_t apIndex = 0, primary_vap_index = 0;// check private vap index
    int channel = 0;
    char *guard_int = NULL;

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
    }
    qca_setRadioMode(index, operationParam);
    wifi_setRadioTransmitPower(index, operationParam->transmitPower);

    memset(param, 0 ,sizeof(param));
    snprintf(param,sizeof(param), "wifi%d.autochannel.enabled", index);
    qcacfg_nvram_set_int(param, operationParam->autoChannelEnabled);

    wifi_setRadioObssCoexistenceEnable(primary_vap_index, operationParam->obssCoex);
    wifi_setRadioSTBCEnable(primary_vap_index, operationParam->stbcEnable);
    wifi_getRadioOperatingChannelBandwidth(index, temp_buff);

    memset(param, 0 ,sizeof(param));
    snprintf(param, sizeof(param), "%s%d.bandwidth", RADIO_PREFIX, index);
    qcacfg_nvram_set_str(param, temp_buff);

    memset(param, 0 ,sizeof(param));
    snprintf(param, sizeof(param), "%s%d.dtimPeriod", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->dtimPeriod);

    if (index == RDK_2G_RADIO){
        for (apIndex = 0; apIndex < MAX_NUM_VAP_PER_RADIO; apIndex++){
            if (isValidAPIndex(VAP_RADIO_2G[apIndex])){
                wifi_setRadioFragmentationThreshold(VAP_RADIO_2G[apIndex], operationParam->fragmentationThreshold);
            }
        }
    }

    if (index == RDK_5G_RADIO){
        for (apIndex = 0; apIndex < MAX_NUM_VAP_PER_RADIO; apIndex++){
            if (isValidAPIndex(VAP_RADIO_5G[apIndex])){
                wifi_setRadioFragmentationThreshold(VAP_RADIO_5G[apIndex], operationParam->fragmentationThreshold);
            }
        }
    }

    memset(param, 0 ,sizeof(param));
    snprintf(param, sizeof(param), "%s%d.fragmentationThreshold", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->fragmentationThreshold);

    memset(param, 0 ,sizeof(param));
    snprintf(param, sizeof(param), "%s%d.band", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->band);

    memset(param, 0 ,sizeof(param));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    snprintf(param, sizeof(param), "%s%d.operatingstandard", RADIO_PREFIX, index);
    get_radio_variant_str_from_int(operationParam->variant, temp_buff);
    qcacfg_nvram_set_str(param, temp_buff);

    memset(param, 0 ,sizeof(param));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    snprintf(param, sizeof(param), "%s%d.beaconInterval", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->beaconInterval);

    memset(param, 0 ,sizeof(param));
    snprintf(param, sizeof(param), "%s.%d.guardInterval", RADIO_PREFIX, index);
    qcacfg_nvram_set_int(param, operationParam->guardInterval);
    switch(operationParam->guardInterval)
    {
        case wifi_guard_interval_400:
            guard_int = "400nsec";
            break;
        case wifi_guard_interval_800:
            guard_int = "800nsec";
            break;
        case wifi_guard_interval_1600:
            guard_int = "1600nsec";
            break;
        case wifi_guard_interval_3200:
            guard_int = "3200nsec";
            break;
    }
    if(guard_int != NULL)
    {
        ret = wifi_setRadioGuardInterval(index, guard_int);
        if(ret != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d Failed to set Guard Interval\n",__func__, __LINE__);
        }
    }

    if (index == RDK_2G_RADIO){
        for (apIndex = 0; apIndex < MAX_NUM_VAP_PER_RADIO; apIndex++){
            if (isValidAPIndex(VAP_RADIO_2G[apIndex])){
                wifi_setApRtsThreshold(VAP_RADIO_2G[apIndex], operationParam->rtsThreshold);
            }
        }
    }

    if (index == RDK_5G_RADIO){
        for (apIndex = 0; apIndex < MAX_NUM_VAP_PER_RADIO; apIndex++){
            if (isValidAPIndex(VAP_RADIO_5G[apIndex])){
                wifi_setApRtsThreshold(VAP_RADIO_5G[apIndex], operationParam->rtsThreshold);
            }
        }
    }

    if (operationParam->autoChannelEnabled) {
        snprintf(cmd, sizeof(cmd), "iwconfig %s%d channel 0",VAP_PREFIX, primary_vap_index);
        ret = system(cmd);
        if(ret == -1) {
            wifi_hal_error_print("ACS set command failed %s:%d \n",__func__, __LINE__);
        }

    }

    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *vap;
    int vap_itr;
    char interface_name[32];
    char cmd[DEFAULT_CMD_SIZE];

    for (vap_itr=0; vap_itr < map->num_vaps; vap_itr++) {
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            /*Enabling ap_bridge for all ap vaps for intra bss packet transfer*/
            snprintf(cmd, sizeof(cmd), "cfg80211tool %s ap_bridge 1", interface_name);
            wifi_hal_dbg_print("%s:%d Executing %s\n",__func__,__LINE__, cmd);
            system(cmd);
        }
    }
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
    char param [DEFAULT_CMD_SIZE] = {0};
    
    snprintf(param, DEFAULT_CMD_SIZE, "%s%d.vap_enabled", VAP_PREFIX,vap_index);
    qcacfg_nvram_get_bool(param, vap_enable);
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
    int ret = 0;
    char param [DEFAULT_CMD_SIZE] = {0};
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
        snprintf(param, DEFAULT_CMD_SIZE, "%s%d.password", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, password, WIFI_AP_MAX_PASSPHRASE_LEN);
        return 0;
    }
    if(ret == -1)
    {
        wifi_hal_info_print("%s:%d Reading default password for vap %d from qca DB\n",
                                                           __func__, __LINE__, vap_index);
        snprintf(param, DEFAULT_CMD_SIZE, "%s%d.password", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, password, WIFI_AP_MAX_PASSPHRASE_LEN);
        return 0;
    }
    strcpy(password, value);

    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    int ret = 0;
    char param [DEFAULT_CMD_SIZE] = {0};
    char value[MAX_DEFAULT_VALUE_SIZE] = {0};

    if(is_wifi_hal_vap_private(vap_index))
    {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, DEFAULT_24G_SSID_KEY, value, sizeof(value));
    }
    else if(is_wifi_hal_vap_xhs(vap_index))
    {
        ret = read_from_factory_defaults(FACTORY_DEFAULTS_FILE, DEFAULT_XHS_SSID_KEY, value, sizeof(value));
    }
    else
    {
        snprintf(param, DEFAULT_CMD_SIZE, "%s%d.ssid", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, ssid, WIFI_AP_MAX_SSID_LEN);
        return 0;
    }
    if(ret == -1)
    {
        wifi_hal_info_print("%s:%d Reading default SSID for vap %d from qca DB\n",
                                                           __func__, __LINE__, vap_index);
        snprintf(param, DEFAULT_CMD_SIZE, "%s%d.ssid", VAP_PREFIX, vap_index);
        qcacfg_nvram_get(param, ssid, WIFI_AP_MAX_SSID_LEN);
        return 0;
    }
    strcpy(ssid, value);

    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    /* dummy pin value */
    strcpy(pin,"45276453"); 
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
    if (wps == NULL) {
        wifi_hal_error_print("%s: NULL param error\n", __FUNCTION__);
        return -1;
    }

    u_int8_t event = data.event;
    struct wps_event_success *success = NULL;
    struct wps_event_pwd_auth_fail *auth_fail = NULL;
    struct wps_event_fail *fail = NULL;

    wifi_hal_info_print("%s:%d WPS EVENT Received %d %s\n", __func__, __LINE__, data.event, WPS_enum_to_str[data.event]);
    switch (event) {
        case WPS_EV_M2D:
            wifi_hal_info_print("%s:%d WPS received %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_FAIL:
            fail = &wps->fail;
            mac_print( (uint8_t*) "WPS Registration Fail", fail->peer_macaddr);

            if (fail->error_indication > 0 && fail->error_indication < NUM_WPS_EI_VALUES) {
                wifi_hal_info_print("%s:%d WPS-FAIL msg=%d config_error=%d reason=%d (%s)\n",__func__, __LINE__, fail->msg, 
                                    fail->config_error, fail->error_indication, WPS_ei_to_str[fail->error_indication]);
            } else {
                wifi_hal_info_print("%s:%d WPS-FAIL msg=%d config_error=%d reason=%d (%s)\n",__func__, __LINE__, fail->msg, 
                                    fail->config_error);
            }
            break;
        case WPS_EV_SUCCESS:
            success = &wps->success;
            mac_print( (uint8_t*) "WPS Registration Success", success->peer_macaddr);
            break;
        case WPS_EV_PWD_AUTH_FAIL:
            auth_fail = &wps->pwd_auth_fail;
            mac_print( (uint8_t*) "WPS: Authentication failure update", auth_fail->peer_macaddr);
            break;
        case WPS_EV_PBC_OVERLAP:
            wifi_hal_info_print("%s:%d PBC Status: %s\n",__func__, __LINE__,pbc_status_str[WPS_PBC_STATUS_OVERLAP]);
            break;
        case WPS_EV_PBC_TIMEOUT:
            wifi_hal_info_print("%s:%d PBC Status: %s\n",__func__, __LINE__,pbc_status_str[WPS_PBC_STATUS_TIMEOUT]);
            break;
        case WPS_EV_PBC_DISABLE:
            wifi_hal_info_print("%s:%d PBC Status: %s\n",__func__, __LINE__,pbc_status_str[WPS_PBC_STATUS_DISABLE]);
            break;
        case WPS_EV_PBC_ACTIVE:
            wifi_hal_info_print("%s:%d PBC Status: %s\n",__func__, __LINE__,pbc_status_str[WPS_PBC_STATUS_ACTIVE]);
            break;
        case WPS_EV_ER_AP_ADD:
            wifi_hal_info_print("%s:%d WPS ER: AP added %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_ER_AP_REMOVE:
            wifi_hal_info_print("%s:%d WPS ER: AP removed %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_ER_ENROLLEE_ADD:
            wifi_hal_info_print("%s:%d WPS ER: Enrollee added %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_ER_ENROLLEE_REMOVE:
            wifi_hal_info_print("%s:%d WPS ER: Enrollee removed %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_ER_AP_SETTINGS:
            wifi_hal_info_print("%s:%d WPS ER: AP Settings learned %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_ER_SET_SELECTED_REGISTRAR:
            wifi_hal_info_print("%s:%d WPS ER: SetSelectedRegistrar %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        case WPS_EV_AP_PIN_SUCCESS:
            wifi_hal_info_print("%s:%d WPS External Registrar used correct AP PIN %s\n", __func__, __LINE__, WPS_enum_to_str[data.event]);
            break;
        default:
            break;
    }
    return 0;
}

int platform_get_country_code_default(char *code)
{
    strcpy(code,"US");
    return 0;
}

int nvram_get_current_password(char *l_password, int vap_index)
{
    char param [DEFAULT_CMD_SIZE] = {0};

    snprintf(param, DEFAULT_CMD_SIZE, "%s%d.password", VAP_PREFIX, vap_index);
    qcacfg_nvram_get(param, l_password, WIFI_AP_MAX_PASSPHRASE_LEN);

    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    char param [DEFAULT_CMD_SIZE] = {0};

    snprintf(param, DEFAULT_CMD_SIZE, "%s%d.ssid", VAP_PREFIX,vap_index);
    qcacfg_nvram_get(param, l_ssid, WIFI_AP_MAX_SSID_LEN);
    
    return 0;
}


static int qca_get_vap_mld_addr(wifi_vap_info_t* vap_info, char* mld_mac_buf)
{
    if (vap_info == NULL) {
        wifi_hal_error_print("%s:%d: vap_info is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    mld_mac_buf[0] = 0x00;
    mld_mac_buf[1] = 0x00;
    mld_mac_buf[2] = 0xaa;
    mld_mac_buf[3] = 0xbb;
    mld_mac_buf[4] = 0xcc;
    mld_mac_buf[5] = vap_info->vap_index;
    wifi_hal_info_print("%s:%d: mld address for vap index %d is " MACSTR "\n",
       __func__, __LINE__, vap_info->vap_index, MAC2STR(mld_mac_buf));
    return RETURN_OK;
}

static int qca_create_mld_interfaces(wifi_vap_info_map_t *map)
{
    char cmd[DEFAULT_CMD_SIZE];
    int i;
    wifi_vap_info_t *vap;
    char mld_mac_addr[ETH_ALEN];

    for (i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        snprintf(cmd, sizeof(cmd), "iw dev | grep -w mld%d", vap->vap_index);
        wifi_hal_info_print("%s:%d: Executing %s\n", __func__, __LINE__, cmd);

        if (system(cmd) == 0) {
            wifi_hal_info_print("%s:%d: mld%d already present\n", __func__, __LINE__, vap->vap_index);
        } else {
            qca_get_vap_mld_addr(vap, mld_mac_addr);
            snprintf(cmd, sizeof(cmd), "iw phy mld-phy0 interface add mld%d type __ap mld_addr " MACSTR,
                                            vap->vap_index, MAC2STR(mld_mac_addr));
            wifi_hal_info_print("%s:%d Executing %s\n", __func__, __LINE__, cmd);
            system(cmd);
        }
    }
    return RETURN_OK;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char interface_name[10] = {0};
    char param[128] = {0};
    wifi_vap_info_t *vap = NULL;
    unsigned int vap_itr = 0;

    for (vap_itr=0; vap_itr < map->num_vaps; vap_itr++) {
        memset(interface_name, 0, sizeof(interface_name));
        memset(param, 0, sizeof(param));
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        snprintf(param, sizeof(param), "ath%d.vap_enabled", vap->vap_index);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (vap->u.bss_info.enabled) {
                qcacfg_nvram_set_str(param, "1");
            } else {
                qcacfg_nvram_set_str(param, "0");
            }
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            if (vap->u.sta_info.enabled) {
                qcacfg_nvram_set_str(param, "1");
            } else {
                qcacfg_nvram_set_str(param, "0");
            }
        }
    }
    qca_create_mld_interfaces(map);
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
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

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
    char temp_buff [MAX_BUF_SIZE] = {0};
    u_int8_t seqCounter = 0;

    wifi_getRadioOperatingChannelBandwidth(index, temp_buff);
    if (temp_buff[0] == NULL) {
        wifi_hal_error_print("%s:%d Channel Bandwidth is NULL\n", __func__, __LINE__);
        return -1;
    }

    for (seqCounter = 0; seqCounter < ARRAY_SZ(wifiChannelBandWidthMap); seqCounter++) {
        if (strncmp(temp_buff, wifiChannelBandWidthMap[seqCounter].wifiChanWidthName, strlen(wifiChannelBandWidthMap[seqCounter].wifiChanWidthName))) {
            *channelWidth = wifiChannelBandWidthMap[seqCounter].halWifiChanWidth;
        }
    }

    if (*channelWidth == 0) {
        wifi_hal_error_print("%s:%d Channel Bandwidth not supported\n", __func__, __LINE__);
        return -1; 
    }
    
    return 0;
}

int platform_update_radio_presence(void)
{
    unsigned int index = 0;
    char cmd[DEFAULT_CMD_SIZE] = {0};
    wifi_radio_info_t *radio = NULL;

    wifi_hal_info_print("%s:%d: g_wifi_hal.num_radios %d\n", __func__, __LINE__, g_wifi_hal.num_radios);
    for (index = 0; index < g_wifi_hal.num_radios; index++)
    {
        radio = get_radio_by_rdk_index(index);
        snprintf(cmd, sizeof(cmd), "/sys/class/net/wifi%d",index);
        if (!is_interface_exists(cmd)) {
               radio->radio_presence = false;
        }
        wifi_hal_info_print("%s:%d: Index %d presence %d\n", __func__, __LINE__, index, radio->radio_presence);
    }

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
    char nvram_name[NVRAM_NAME_SIZE] = {0};
    char temp_buff[MAX_BUF_SIZE] = {0};
    char val[WIFI_MAX_RADIUS_KEY] = {0};
    FILE *fptr = NULL;

    snprintf(temp_buff, sizeof(temp_buff), "/usr/bin/GetConfigFile %s stdout", getRadiusCfgFile);

    fptr = popen(temp_buff, "r");
    if (fptr == NULL) {
        wifi_hal_dbg_print("%s: popen error\n", __FUNCTION__);
        return -1;
    }

    if(fgets(val, sizeof(val), fptr) == NULL){
        snprintf(nvram_name, sizeof(nvram_name), "auth_server_shared_secret");
        qcacfg_nvram_get(nvram_name, val, WIFI_MAX_RADIUS_KEY);
    }

    pclose(fptr);
    strncpy(radius_key, val, strlen(val));
    memset(val, '\0', sizeof(val));

    return 0;
}

int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}

int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    if (NULL == vendor_oui) {
        wifi_hal_error_print("%s:%d  Invalid parameter \n", __func__, __LINE__);
        return -1;
    }
    strncpy(vendor_oui, OUI_QCA, vendor_oui_len - 1);

    return 0;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
     char temp_buff [MAX_BUF_SIZE] = {0};
     FILE *fptr = NULL; char *context = NULL;
     char val[MAX_BUF_SIZE] = {0};

     if (check_radio_index(index) != 0) {
             return -1;
     }

     /* NOTE: rdk_index points to wifi%d index while in vendor hal we would convert to qca_index */

     snprintf(temp_buff,sizeof(temp_buff),"cat /sys/class/net/wifi%d/thermal/temp",index);

     fptr = popen(temp_buff, "r");
     if (fptr == NULL) {
             wifi_hal_dbg_print("%s: popen error\n", __FUNCTION__);
             return -1 ;
     }

     fgets(val,MAX_BUF_SIZE,fptr);
     pclose(fptr);
     strtok_r(val, "\n", &context);

     radioPhyTemperature->radio_Temperature = val ? atoi(val) : 0;

     return RETURN_OK;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    return 0;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    wifi_NeighborReport_t nbr_report;

    wifi_hal_info_print("%s:%d Enter %d\n", __func__, __LINE__,index);

    memcpy(nbr_report.bssid, mac, sizeof(mac_address_t));
    wifi_setNeighborReports(index,add, &nbr_report);

    return 0;
}

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
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

    res = wifi_setApRetryLimit(retry_vap_index, RETRY_LIMIT);

    if (res) {
        wifi_hal_dbg_print("%s:%d: AP_RETRY_LIMIT failed:%d", __func__, __LINE__, res);
    }

    return 0;
}

#ifdef CONFIG_IEEE80211BE
int wifi_drv_set_ap_mlo(struct nl_msg *msg, void *priv, struct wpa_driver_ap_params *params) {
#ifdef CONFIG_MLO
    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    int res = 0;
    wifi_hal_dbg_print("%s:%d: params->num_mlo_links: %d\n", __func__, __LINE__, params->num_mlo_links);
    if (params->num_mlo_links) {
        int i;
        struct nlattr *link_ids;
        struct nlattr *mac_addrs;

        link_ids = nla_nest_start(msg, NL80211_ATTR_MLD_LINK_IDS);
        if (link_ids == NULL) {
            wifi_hal_error_print("%s:%d: link_ids is NULL\n", __func__, __LINE__);
            return -1;
        }
        for (i = 0; i < params->num_mlo_links; i++) {
            wifi_hal_dbg_print("nl80211: %s MLO-Link_id %d\n", interface->name,
                                params->mlo_link_ids[i]);
            if ((res = nla_put_u32(msg, i + 1, params->mlo_link_ids[i]))) {
                return res;
            }
        }
        nla_nest_end(msg, link_ids);

        mac_addrs = nla_nest_start(msg, NL80211_ATTR_MLD_LINK_MACS);
        if (mac_addrs == NULL) {
            return -1;
        }
        for (i = 0; i < params->num_mlo_links; i++) {
            wifi_hal_dbg_print("nl80211: %s MLO-Link-Mac " MACSTR "\n",
                                interface->name,
                                MAC2STR(params->mlo_mac_addrs[i]));
            if ((res = nla_put(msg, i + 1, ETH_ALEN, params->mlo_mac_addrs[i]))) {
                return res;
            }
        }
        nla_nest_end(msg, mac_addrs);
    }
    wifi_hal_dbg_print("%s:%d: EXIT\n", __func__, __LINE__);
    return res;
#else
#error "The wifi_drv_set_ap_mlo is not implemented"
#endif /* CONFIG_MLO */
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) {
        size_t len;

        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);

        if (len > sizeof(eht_capab->mac_cap)) {
            len = sizeof(eht_capab->mac_cap);
        }
        os_memcpy(eht_capab->mac_cap,
                nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]), len);
    }
}

int update_hostap_mlo(wifi_interface_info_t *interface) {
#ifdef CONFIG_MLO
    struct hostapd_bss_config *const conf = &interface->u.ap.conf;
    struct hostapd_data *const hapd = &interface->u.ap.hapd;
    char mld_mac_addr[ETH_ALEN];

    wifi_hal_dbg_print("%s:%d: ENTER\n", __func__, __LINE__);
    if(hapd->iface->interfaces->mlds.next == NULL)
    {
        dl_list_init(&hapd->iface->interfaces->mlds);
        wifi_hal_info_print("%s:%d: init dl_list_init(&hapd->iface->interfaces.mld\n", __func__, __LINE__);
    }
    else
    {
        wifi_hal_info_print("%s:%d: Not initializing dl_list_init(&hapd->iface->interfaces.mld Again\n",
                                                                                       __func__, __LINE__);
    }
    if (!conf->disable_11be) {
        wifi_hal_info_print("%s:%d: hostap disable_11be is false\n", __func__, __LINE__);
        //mld_link_mac_list
        os_memcpy(&(conf->mld_link_mac_list.addr[0]), hapd->own_addr, ETH_ALEN);
        conf->mld_link_mac_list.num_links = 1;

        //mld_mac_addr
        qca_get_vap_mld_addr(&interface->vap_info, mld_mac_addr);
        os_memcpy(conf->mld_mac_addr, mld_mac_addr, ETH_ALEN);

        //mld_link_ids
        conf->mld_link_id_list.link_id[0] = interface->vap_info.radio_index;
        conf->mld_link_id_list.num_links = 1;
        wifi_hal_dbg_print("%s:%d: Setting MLD-link-MAC: " MACSTR " link ID: %d MLD_MAC: " MACSTR "\n",
                                          __func__, __LINE__, MAC2STR(conf->mld_link_mac_list.addr[0]),
                                          conf->mld_link_id_list.link_id[0], MAC2STR(conf->mld_mac_addr));
    } else {
        os_memset(&conf->mld_link_mac_list, 0, sizeof(conf->mld_link_mac_list));
        os_memset(conf->mld_mac_addr, 0, sizeof(conf->mld_mac_addr));
        os_memset(&conf->mld_link_id_list, 0, sizeof(conf->mld_link_id_list));
    }
    wifi_hal_dbg_print("%s:%d: EXIT\n", __func__, __LINE__);

    return RETURN_OK;
#else
#error "The update_hostap_mlo is not implemented"
#endif /* CONFIG_MLO */
}

#endif /* CONFIG_IEEE80211BE */

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}

static int qca_add_intf_to_bridge(wifi_interface_info_t *interface, bool is_mld)
{
    char mld_ifname[32];
    wifi_vap_info_t *vap;

    vap = &interface->vap_info;
    if (vap->vap_mode == wifi_vap_mode_ap) {
        wifi_hal_info_print("%s:%d: interface:%s bss enabled:%d bridge:%s\n", __func__,
            __LINE__, interface->name, vap->u.bss_info.enabled, vap->bridge_name);
        if (vap->bridge_name[0] != '\0' && vap->u.bss_info.enabled) {
            wifi_hal_info_print("%s:%d: interface:%s create bridge:%s\n", __func__, __LINE__,
                interface->name, vap->bridge_name);

            snprintf(mld_ifname, sizeof(mld_ifname), "%s%d", MLD_PREFIX, vap->vap_index);
            if (is_mld) {
                if (nl80211_remove_from_bridge(interface->name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to remove from OVS bridge\n",
                    __func__, __LINE__, interface->name);
                }

                if (nl80211_create_bridge(mld_ifname, vap->bridge_name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
                wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                        mld_ifname, vap->bridge_name);
            } else {
                if (nl80211_remove_from_bridge(mld_ifname) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to remove from OVS bridge\n",
                       __func__, __LINE__, interface->name);
                }
                if (nl80211_create_bridge(interface->name, vap->bridge_name) != 0) {
                    wifi_hal_error_print("%s:%d: interface:%s failed to create bridge:%s\n",
                        __func__, __LINE__, interface->name, vap->bridge_name);
                    return RETURN_ERR;
                }
            }
            wifi_hal_info_print("%s:%d: interface:%s set bridge %s up\n", __func__, __LINE__,
                interface->name, vap->bridge_name);
        }
    }
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

static bool is_bonding_slave(const char* mld_name, const char* ifname)
{
    char linebuf[512];
    char slave_list[128];
    char *slave;
    char *rest;
    FILE *fp;
    bool ret = false;

    snprintf(slave_list, sizeof(slave_list), "/sys/class/net/%s/bonding/slaves", mld_name);
    fp = fopen(slave_list,"r");
    if (NULL==fp) {
        wifi_hal_error_print("%s:%d Failed to open file %s\n", __func__, __LINE__, slave_list);
        return ret;
    }

    if (access(slave_list, F_OK ) == 0) {
        linebuf[0] = '\0';
        fgets(linebuf,sizeof(linebuf), fp);
        if (strlen(linebuf) && linebuf[strlen(linebuf)-1] == '\n') {
            linebuf[strlen(linebuf)-1] = '\0'; // remove trailing newline character (\n)
        }
        wifi_hal_dbg_print("%s:%d  slaves=%s\n", __func__, __LINE__, linebuf);
        rest = linebuf;
        while ((slave = strtok_r(rest, " ", &rest))) {
            printf("%s ", slave);
            if (strcmp(slave, ifname)==0) {
                wifi_hal_dbg_print("%s:%d %s is bonding slave of %s\n", __func__, __LINE__, ifname, mld_name);
                ret = true;
                break;
            }
        }
    }
    fclose(fp);
    if (!ret) {
        wifi_hal_dbg_print("%s:%d %s is not a bonding slave of %s\n", __func__, __LINE__, ifname, mld_name);
    }
    return ret;
}

INT platform_set_intf_mld_bonding(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    char cmd[QCA_MAX_CMD_SZ];
    char mld_ifname[32];
    char ifname[32];
    char mld_mac_addr[ETH_ALEN];
    char mld_mac_str[18];

    if (interface == NULL || radio == NULL) {
        wifi_hal_error_print("%s:%d: Invalid arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if ((int)interface->vap_info.vap_index >= 0) {
        if (get_interface_name_from_vap_index(interface->vap_info.vap_index, ifname) != RETURN_OK ) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to get interface name from vap index\n",
                __func__, __LINE__, interface->vap_info.vap_index);
            return RETURN_ERR;
        }
        if (qca_get_vap_mld_addr(&interface->vap_info, mld_mac_addr) == RETURN_ERR) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to get mld address\n",
                __func__, __LINE__, interface->vap_info.vap_index);
            return RETURN_ERR;
        }

        snprintf(mld_mac_str, sizeof(mld_mac_str), MACSTR, MAC2STR(mld_mac_addr));
        snprintf(mld_ifname, sizeof(mld_ifname), "mld%d", interface->vap_info.vap_index);

        if ((!(radio->oper_param.variant & WIFI_80211_VARIANT_BE)) && is_bonding_slave(mld_ifname, ifname)) {
            snprintf(cmd, sizeof(cmd), "cfg80211tool ath%d mode %s", interface->vap_info.vap_index,
                (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND)? "11GHE20" : "11AHE80");
            wifi_hal_info_print("%s:%d Executing: %s\n",__func__, __LINE__, cmd);
            system(cmd);
            wifi_hal_info_print("%s:%d Delete bonding between ifname:%s and mld:%s\n"
                ,__func__, __LINE__, ifname, mld_ifname);
            wifi_setMLDaddr(interface->vap_info.vap_index, "00:00:00:00:00:00");
        } else if ((radio->oper_param.variant & WIFI_80211_VARIANT_BE) && (!is_bonding_slave(mld_ifname, ifname))) {
            snprintf(cmd, sizeof(cmd), "cfg80211tool ath%d mode %s", interface->vap_info.vap_index,
                (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND)? "11GEHT20" : "11AEHT80");
            wifi_hal_info_print("%s:%d Executing: %s\n",__func__, __LINE__, cmd);
            system(cmd);
            wifi_hal_info_print("%s:%d Create bonding between ifname:%s and mld:%s [%s]\n"
                ,__func__, __LINE__, ifname, mld_ifname, mld_mac_str);
            wifi_setMLDaddr(interface->vap_info.vap_index, "00:00:00:00:00:00");
            wifi_setMLDaddr(interface->vap_info.vap_index, mld_mac_str);
        } else {
            wifi_hal_dbg_print("%s:%d No need to changing bonding state for %s\n", __func__, __LINE__, ifname);
        }
    }
    return RETURN_OK;
}

INT platform_set_radio_mld_bonding(wifi_radio_info_t *radio)
{
    char cmd[QCA_MAX_CMD_SZ];
    wifi_interface_info_t *interface;
    interface = hash_map_get_first(radio->interface_map);
    char mld_ifname[32];
    char ifname[32];
    char mld_mac_addr[ETH_ALEN];
    char mld_mac_str[18];

    while (interface != NULL) {
        if ((int)interface->vap_info.vap_index >= 0) {
            if (get_interface_name_from_vap_index(interface->vap_info.vap_index, ifname) != RETURN_OK ) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to get interface name from vap index\n",
                    __func__, __LINE__, interface->vap_info.vap_index);
                return RETURN_ERR;
            }
            if (qca_get_vap_mld_addr(&interface->vap_info, mld_mac_addr) == RETURN_ERR) {
                wifi_hal_error_print("%s:%d: vap index:%d failed to get mld address\n",
                    __func__, __LINE__, interface->vap_info.vap_index);
                return RETURN_ERR;
            }

            snprintf(mld_mac_str, sizeof(mld_mac_str), MACSTR, MAC2STR(mld_mac_addr));
            snprintf(mld_ifname, sizeof(mld_ifname), "mld%d", interface->vap_info.vap_index);

            if ( (!(radio->oper_param.variant & WIFI_80211_VARIANT_BE)) && is_bonding_slave(mld_ifname, ifname)) {
                snprintf(cmd, sizeof(cmd), "cfg80211tool ath%d mode %s", interface->vap_info.vap_index,
                    (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND)? "11GHE20" : "11AHE80");
                wifi_hal_info_print("%s:%d Executing: %s\n",__func__, __LINE__, cmd);
                system(cmd);
                wifi_hal_info_print("%s:%d Delete bonding between ifname:%s and mld:%s\n"
                    ,__func__, __LINE__, ifname, mld_ifname);
                wifi_setMLDaddr(interface->vap_info.vap_index, "00:00:00:00:00:00");
            } else if ((radio->oper_param.variant & WIFI_80211_VARIANT_BE) && (!is_bonding_slave(mld_ifname, ifname))) {
                snprintf(cmd, sizeof(cmd), "cfg80211tool ath%d mode %s", interface->vap_info.vap_index,
                    (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND)? "11GEHT20" : "11AEHT80");
                wifi_hal_info_print("%s:%d Executing: %s\n",__func__, __LINE__, cmd);
                system(cmd);
                wifi_hal_info_print("%s:%d Create bonding between ifname:%s and mld:%s [%s]\n"
                    ,__func__, __LINE__, ifname, mld_ifname, mld_mac_str);
                wifi_setMLDaddr(interface->vap_info.vap_index, "00:00:00:00:00:00");
                wifi_setMLDaddr(interface->vap_info.vap_index, mld_mac_str);
            } else {
                wifi_hal_dbg_print("%s:%d No need to changing bonding state for %s\n", __func__, __LINE__, ifname);
            }
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }
    return RETURN_OK;
}

INT platform_create_interface_attributes(struct nl_msg **msg_ptr, wifi_radio_info_t *radio, wifi_vap_info_t *vap)
{
    char mld_mac_addr[ETH_ALEN];
    (void)radio;

    if (msg_ptr == NULL || *msg_ptr == NULL || vap == NULL) {
        wifi_hal_dbg_print("%s:%d Invalid arguments\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (qca_get_vap_mld_addr(vap, mld_mac_addr) == RETURN_ERR) {
        return RETURN_ERR;
    }
    wifi_hal_info_print("%s:%d:Adding MLD addr " MACSTR " for vap index:%d\n", __func__, __LINE__,
        MAC2STR(mld_mac_addr), vap->vap_index);
    if (nla_put(*msg_ptr, NL80211_ATTR_MLD_MAC, ETH_ALEN, mld_mac_addr) < 0) {
        return RETURN_ERR;
    }
    return RETURN_OK;
}
