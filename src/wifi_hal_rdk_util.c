/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <aes_siv.h>
#include <wifi_hal_rdk_framework.h>
#include "wifi_hal_priv.h"
#include <cjson/cJSON.h>
#include <sys/types.h>
#include <ifaddrs.h>

/* WPS_METHOD_LIMIT */
/* WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE | WIFI_ONBOARDINGMETHODS_ETHERNET | WIFI_ONBOARDINGMETHODS_LABEL | WIFI_ONBOARDINGMETHODS_DISPLAY | WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN | WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN | WIFI_ONBOARDINGMETHODS_NFCINTERFACE | WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN | WIFI_ONBOARDINGMETHODS_PHYSICALPUSHBUTTON | WIFI_ONBOARDINGMETHODS_PHYSICALDISPLAY | WIFI_ONBOARDINGMETHODS_VIRTUALPUSHBUTTON |WIFI_ONBOARDINGMETHODS_VIRTUALDISPLAY | WIFI_ONBOARDINGMETHODS_EASYCONNECT  = 0x7FFF */ 

#define WPS_METHOD_LIMIT 0x7FFF

wifi_device_callbacks_t    g_device_callbacks;

wifi_device_callbacks_t *get_device_callbacks()
{
    return &g_device_callbacks;
}
#if !defined(PLATFORM_LINUX)
char *to_mac_str (mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}
#endif

void to_mac_bytes (mac_addr_str_t key, mac_address_t bmac) {
   unsigned int mac[6];
    sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
             &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
   bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
   bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

const char *wifi_freq_bands_to_string(wifi_freq_bands_t band)
{
#define BANDS2S(x) case x: return #x;
    switch (band) {
    BANDS2S(WIFI_FREQUENCY_2_4_BAND)
    BANDS2S(WIFI_FREQUENCY_5_BAND)
    BANDS2S(WIFI_FREQUENCY_5L_BAND)
    BANDS2S(WIFI_FREQUENCY_5H_BAND)
    BANDS2S(WIFI_FREQUENCY_6_BAND)
    BANDS2S(WIFI_FREQUENCY_60_BAND)
    }

    return "WIFI_FREQUENCY_UNKNOWN";
}

#if !defined(PLATFORM_LINUX)
char *get_formatted_time(char *time)
{
    struct tm *tm_info;
    struct timeval tv_now;
    char tmp[128];

    gettimeofday(&tv_now, NULL);
    tm_info = localtime(&tv_now.tv_sec);

    strftime(tmp, 128, "%y%m%d-%T", tm_info);

    snprintf(time, 128, "%s.%06lu", tmp, tv_now.tv_usec);
    return time;
}
#endif

static int move_radio_capability(wifi_radio_capabilities_t *tmp_cap, wifi_radio_capabilities_t *cap,
    unsigned int arr_loc)
{
    unsigned j = 0;

    tmp_cap->index = cap->index;
    tmp_cap->numSupportedFreqBand = 1;
    tmp_cap->band[0] = cap->band[arr_loc];
    memcpy(&tmp_cap->channel_list[0], &cap->channel_list[arr_loc], sizeof(wifi_channels_list_t));
    memcpy(&tmp_cap->channelWidth[0], &cap->channelWidth[arr_loc], sizeof(wifi_channelBandwidth_t));
    if (tmp_cap->channelWidth[0] == 0) {
        switch(tmp_cap->band[0]) {
            case WIFI_FREQUENCY_2_4_BAND:
                tmp_cap->channelWidth[0] = (WIFI_CHANNELBANDWIDTH_20MHZ | WIFI_CHANNELBANDWIDTH_40MHZ);
            break;
            case WIFI_FREQUENCY_5L_BAND:
            case WIFI_FREQUENCY_5H_BAND:
            case WIFI_FREQUENCY_5_BAND:
                tmp_cap->channelWidth[0] = (WIFI_CHANNELBANDWIDTH_20MHZ | WIFI_CHANNELBANDWIDTH_40MHZ | WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ);
            break;
            case WIFI_FREQUENCY_6_BAND:
                tmp_cap->channelWidth[0] = (WIFI_CHANNELBANDWIDTH_20MHZ | WIFI_CHANNELBANDWIDTH_40MHZ | WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ | WIFI_CHANNELBANDWIDTH_320MHZ);
            break;
            default:
            break;
        }
    }
    memcpy(&tmp_cap->mode[0], &cap->mode[arr_loc], sizeof(wifi_ieee80211Variant_t));
    tmp_cap->maxBitRate[0] = cap->maxBitRate[arr_loc];
    tmp_cap->supportedBitRate[0] = cap->supportedBitRate[arr_loc];
    memcpy(&tmp_cap->transmitPowerSupported_list[0], &cap->transmitPowerSupported_list[arr_loc], sizeof(wifi_radio_trasmitPowerSupported_list_t));
    tmp_cap->autoChannelSupported = cap->autoChannelSupported;
    tmp_cap->DCSSupported = cap->DCSSupported;
    tmp_cap->zeroDFSSupported=cap->zeroDFSSupported;
    memcpy(&tmp_cap->csi, &cap->csi, sizeof(wifi_radio_csi_capabilities_t));
    tmp_cap->cipherSupported = cap->cipherSupported;
    tmp_cap->numcountrySupported = cap->numcountrySupported;
    tmp_cap->maxNumberVAPs = cap->maxNumberVAPs;
    for (j=0 ; j<tmp_cap->numcountrySupported ; j++) {
        tmp_cap->countrySupported[j] = cap->countrySupported[j];
    }
    memcpy(cap, tmp_cap, sizeof(wifi_radio_capabilities_t));
    return RETURN_OK;
}

// The radio can support several bands. The actual band used by driver is retrieved from VAP name
// and set as the first band so the higher layers can access it at 0 index.
int adjust_radio_capability_band(wifi_radio_capabilities_t *cap, unsigned int radio_band)
{
    wifi_radio_capabilities_t tmp_cap;
    unsigned int i = 0;

    memset(&tmp_cap, 0, sizeof(wifi_radio_capabilities_t));
    for (i = 0; i <= cap->numSupportedFreqBand; i++) {
        // The driver reports 5G low and high bands as 5G band. We fix the band based on VAP name.
        if (cap->band[i] == WIFI_FREQUENCY_5_BAND && (radio_band == WIFI_FREQUENCY_5H_BAND ||
            radio_band == WIFI_FREQUENCY_5L_BAND)) {
            cap->band[i] = radio_band;
        }

        // Find band that is actually used and move its capabilities to 0 index.
        if (cap->band[i] == radio_band) {
            move_radio_capability(&tmp_cap, cap, i);
            break;
        }
    }
    return RETURN_OK;
}
typedef enum {
      WIFI_BITRATE_1KBPS   = 10,
      WIFI_BITRATE_2KBPS   = 20,
      WIFI_BITRATE_5_5KBPS = 55,
      WIFI_BITRATE_6KBPS   = 60,
      WIFI_BITRATE_9KBPS   = 90,
      WIFI_BITRATE_11KBPS  = 110,
      WIFI_BITRATE_12KBPS  = 120,
      WIFI_BITRATE_18KBPS  = 180,
      WIFI_BITRATE_24KBPS  = 240,
      WIFI_BITRATE_36KBPS  = 360,
      WIFI_BITRATE_48KBPS  = 480,
      WIFI_BITRATE_54KBPS  = 540
 } wifi_hal_bitrate_t;
 
 struct wifiHalDataTxRateHalMap
{
    wifi_hal_bitrate_t  halDataTxRateEnum;
    char halDataTxRateStr[8];
};
 
 struct wifiHalDataTxRateHalMap wifiHalDataTxRateMap[] =
{
    {WIFI_BITRATE_1KBPS,   "1"},
    {WIFI_BITRATE_2KBPS,   "2"},
    {WIFI_BITRATE_5_5KBPS, "5.5"},
    {WIFI_BITRATE_6KBPS,   "6"},
    {WIFI_BITRATE_9KBPS,   "9"},
    {WIFI_BITRATE_11KBPS,  "11"},
    {WIFI_BITRATE_12KBPS,  "12"},
    {WIFI_BITRATE_18KBPS,  "18"},
    {WIFI_BITRATE_24KBPS,  "24"},
    {WIFI_BITRATE_36KBPS,  "36"},
    {WIFI_BITRATE_48KBPS,  "48"},
    {WIFI_BITRATE_54KBPS,  "54"}
};

int convert_string_to_int(int **int_list, char *val)
{
  int *list;
  int count;
  char *pos;
  //free(*int_list);
  *int_list = NULL;
  int i;

  pos = val; 
  count = 0; 
  while (*pos != '\0') {
    if (*pos == ',') 
      count++;
    pos++;
  }

  list = malloc(sizeof(int) * (count+2)); 
  if (list == NULL)
    return -1;
  pos = val; 
  count = 0; 
  char *new_token = strtok(pos, ",");
   while (new_token != NULL) {
    for (i = 0 ; i < ARRAY_SZ(wifiHalDataTxRateMap) ; ++i)
    if(!strcmp(new_token,wifiHalDataTxRateMap[i].halDataTxRateStr)) {
        list[count]=wifiHalDataTxRateMap[i].halDataTxRateEnum;
    }
    new_token = strtok(NULL, ",");
    count++;
  }
  list[count] = -1;
  *int_list = list;
  return 0;
}

int get_min_rate(int *list, float *min_mbr_rate) {

    int i = 0 , min_rate = 0;

    if (list == NULL) {
        return 0;
    }

    min_rate = list[0];

    for (i = 0; list[i] >= 0; i++) {
        if(min_rate > list[i]) {
            min_rate=list[i];
        }
    }
    *min_mbr_rate = (float)min_rate/10;
    return 0;
}

int convert_string_mcs_to_int(char *string_mcs)
{
    int val = 0, ret =0;
    if(strcmp(string_mcs, "disabled") ==0) {
      return 0;
    }
    ret = sscanf(string_mcs, "%d", &val);
    if (ret != 1) {
      return 0;
    }
    return val;
}

int validate_radio_operation_param(wifi_radio_operationParam_t *param)
{
    switch (param->channelWidth) {
    case WIFI_CHANNELBANDWIDTH_20MHZ:
    case WIFI_CHANNELBANDWIDTH_40MHZ:
    case WIFI_CHANNELBANDWIDTH_80MHZ:
    case WIFI_CHANNELBANDWIDTH_80_80MHZ:
        break;
    case WIFI_CHANNELBANDWIDTH_160MHZ:
#ifdef CONFIG_IEEE80211BE
    case WIFI_CHANNELBANDWIDTH_320MHZ:
#endif /* CONFIG_IEEE80211BE */
        if (((param->band == WIFI_FREQUENCY_5_BAND) || (param->band == WIFI_FREQUENCY_5L_BAND) || (param->band == WIFI_FREQUENCY_5H_BAND)) && (param->DfsEnabled == false)) {
            return RETURN_ERR;
        }
        break;
    default:
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int validate_radius_vap_security_param(wifi_vap_security_t *security, char *msg, int len)
{
    int ret = RETURN_OK;

    if ((strlen(security->u.radius.ip) == 0) || (security->u.radius.port == 0) ||
        (strlen(security->u.radius.key) == 0)) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " Failed to validate vap security params radius ip:%s port:%d key:%s\n",
                                security->u.radius.ip, security->u.radius.port, security->u.radius.key);
    }
    if ((strlen(security->u.radius.s_ip) == 0) || (security->u.radius.s_port == 0) ||
        (strlen(security->u.radius.s_key) == 0)) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " Failed to validate vap security params radius s_ip:%s s_port:%d s_key:%s\n",
                                security->u.radius.s_ip, security->u.radius.s_port, security->u.radius.s_key);
    }
    return ret;
}

bool get_sec_mode_support_radius(int mode)
{
    bool sec_mode = false;
    if ((mode == wifi_security_mode_wpa_enterprise) || (mode == wifi_security_mode_wpa2_enterprise ) || (mode == wifi_security_mode_wpa3_enterprise) || (mode == wifi_security_mode_wpa_wpa2_enterprise)){
        sec_mode = true;
    }

    return sec_mode;
}

int validate_wifi_interface_vap_info_params(wifi_vap_info_t *vap_info, char *msg, int len)
{
    wifi_front_haul_bss_t *bss_info = &vap_info->u.bss_info;
    int ret = RETURN_OK;
    memset(msg, 0, len);

    // vap_info values
    if (bss_info->enabled > 1) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " enabled: %d", bss_info->enabled);
    }
    if (bss_info->ssid[0] == 0) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " ssid is NULL");
    }
    if (bss_info->showSsid > 1) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " showSsid: %d", bss_info->showSsid);
    }
    if (strncmp(vap_info->bridge_name, "", strlen(vap_info->bridge_name)) == 0) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " Bridge name is null for vap index %u", vap_info->vap_index);
    }

    // security parameter values
    if (bss_info->security.mode <= 0 || bss_info->security.mode >  wifi_security_mode_wpa3_compatibility ||
            (bss_info->security.mode &(bss_info->security.mode - 1)) != 0) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " security mode: %d", bss_info->security.mode);
    }
    else if (bss_info->security.mode != wifi_security_mode_none && bss_info->security.mode != wifi_security_mode_enhanced_open && 
            (get_sec_mode_support_radius(bss_info->security.mode) != true) && (bss_info->security.u.key.key[0] == 0)) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " security key is NULL for security mode: %d", bss_info->security.mode);
    } else if ((get_sec_mode_support_radius(bss_info->security.mode) == true) &&
                (validate_radius_vap_security_param(&bss_info->security, msg, len) != RETURN_OK)) {
        ret = RETURN_ERR;
    }

    switch (bss_info->security.encr) {
    case wifi_encryption_none:
    case wifi_encryption_tkip:
    case wifi_encryption_aes:
    case wifi_encryption_aes_tkip:
        break;
    default:
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " security encr: %d", bss_info->security.encr);
        break;
    }

#if defined(WIFI_HAL_VERSION_3)
    switch (bss_info->security.mfp) {
    case wifi_mfp_cfg_disabled:
    case wifi_mfp_cfg_optional:
    case wifi_mfp_cfg_required:
        break;
    default:
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " security mfp: %d", bss_info->security.mfp);
        break;
    }
#endif

    // interworking parameter values
    if (bss_info->interworking.interworking.interworkingEnabled > 1) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " interworkingEnabled: %d", bss_info->interworking.interworking.interworkingEnabled);
    }
    // accessNetworkType possible values are: 0 - Private network; 1 - Private network with guest access; 2 - Chargeable public network; 3 - Free public network; 4 - Personal device network; 5 - Emergency services only network; 6-13 - Reserved; 14 - Test or experimental; 15 - Wildcard
    if (!((bss_info->interworking.interworking.accessNetworkType < 6) ||
            ((bss_info->interworking.interworking.accessNetworkType > 13) && (bss_info->interworking.interworking.accessNetworkType < 16)))) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " accessNetworkType: %d", bss_info->interworking.interworking.accessNetworkType);
    }
    if (bss_info->interworking.interworking.internetAvailable > 1) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " internetAvailable: %d", bss_info->interworking.interworking.internetAvailable);
    }

    // wps values
    if (bss_info->wps.enable > 1) {
        ret = RETURN_ERR;
        snprintf(msg + strlen(msg), len - strlen(msg), " wps enable: %d", bss_info->wps.enable);
    }
    if (bss_info->wps.enable == true) {
        if (bss_info->wps.methods < 0 || bss_info->wps.methods > WPS_METHOD_LIMIT) {
            ret = RETURN_ERR;
            snprintf(msg + strlen(msg), len - strlen(msg), " wps method: %d", bss_info->wps.methods);
        }
        else if (bss_info->wps.methods == WIFI_ONBOARDINGMETHODS_PIN && bss_info->wps.pin[0] == 0) {
            ret = RETURN_ERR;
            snprintf(msg + strlen(msg), len - strlen(msg), " wps pin is NULL");
        }
    }

    return ret;
}

time_t get_boot_time_in_sec(void)
{
    struct timespec tv_now;

    clock_gettime(CLOCK_MONOTONIC, &tv_now);
    return tv_now.tv_sec;
}

cJSON *json_open_file(const char *file_name)
{
    FILE *fp;
    cJSON *json = NULL;
    size_t len;
    char *buff;

    fp = fopen(file_name, "r");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d: Failed (err=%d, msg=%s) to open file:%s\n", __func__, __LINE__,
            errno, strerror(errno), file_name);
        return json;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buff = malloc(len);
    if (buff == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate %zu bytes for json file\n", __func__,
            __LINE__, len);
        return NULL;
    }
    len = fread(buff, 1, len, fp);
    json = cJSON_ParseWithLength(buff, len);
    if (json == NULL) {
        const char *const error_ptr = cJSON_GetErrorPtr();
        wifi_hal_error_print("%s:%d: Error json file parse: %s\n", __func__, __LINE__,
            (error_ptr ? error_ptr : "UNKNOWN"));
    }
    free(buff);
    fclose(fp);
    return json;
}

int json_parse_string(const char* file_name, const char *item_name, char *val, size_t len)
{
    cJSON *item;
    cJSON *json;

    json = json_open_file(file_name);
    if (json == NULL) {
        return -1;
    }

    item = cJSON_GetObjectItem(json, item_name);
    if (!cJSON_IsString(item)) {
        wifi_hal_error_print("%s:%d: (%s) does "
                             "not exist or is not a string\n",
            __func__, __LINE__, item_name);
        cJSON_Delete(json);
        return -1;
    }
    strncpy(val, cJSON_GetStringValue(item), len);
    val[len-1] = '\0';

    cJSON_Delete(json);
    return 0;
}

int json_parse_integer(const char* file_name, const char *item_name, int *val)
{
    cJSON *item;
    cJSON *json;

    json = json_open_file(file_name);
    if (json == NULL) {
        *val = -1;
        return -1;
    }

    item = cJSON_GetObjectItem(json, item_name);
    if (item == NULL || cJSON_IsNumber(item) == false) {
        wifi_hal_error_print("%s:%d: (%s) does "
                             "not exist or is not a number.\n",
            __func__, __LINE__, item_name);
        cJSON_Delete(json);
        *val = -1;
        return -1;
    }
    *val = (int)item->valuedouble;

    cJSON_Delete(json);
    return 0;
}

/* This routine will take mac address from the user and returns associated interfacename */
bool get_ifname_from_mac(const mac_address_t *mac, char *ifname)
{
    struct ifaddrs *ifaddr = NULL, *tmp = NULL;
    struct sockaddr *addr;
    struct sockaddr_ll *ll_addr;
    bool found = false;

    if (getifaddrs(&ifaddr) != 0) {
        wifi_hal_error_print("%s:%d: Failed to get interface information\n", __func__, __LINE__);
        return found;
    }
    tmp = ifaddr;
    while (tmp != NULL) {
        addr = tmp->ifa_addr;
        ll_addr = (struct sockaddr_ll*)tmp->ifa_addr;
        if ((addr != NULL) && (addr->sa_family == AF_PACKET) && (memcmp(ll_addr->sll_addr, mac, sizeof(mac_address_t)) == 0)) {
            strncpy(ifname, tmp->ifa_name, strlen(tmp->ifa_name));
            found = true;
            break;
        }
        tmp = tmp->ifa_next;
    }
    freeifaddrs(ifaddr);
    return found;
}
