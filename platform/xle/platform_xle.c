#include <stddef.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "secure_wrapper.h"
#include "wlcsm_lib_api.h"
#include "rdkconfig.h"
#define BUFFER_LENGTH_WIFIDB 256
#define BUFLEN_128  128

/* API to get encrypted default psk and ssid. */
static int get_default_encrypted_password (char* password);
static int get_default_encrypted_ssid (char* ssid);

/* Get default encrypted PSK key. */
static int get_default_encrypted_password (char* password) {

    if (NULL == password) {
        wifi_hal_error_print("%s:%d Invalid parameter \r\n", __func__, __LINE__);
        return -1;
    }

    const char* default_pwd_encrypted_key = "onewifidefaultcred";
    uint8_t    *encrypted_key=NULL;
    size_t encrypted_keysize;
    if(rdkconfig_get(&encrypted_key, &encrypted_keysize, default_pwd_encrypted_key))
    {
        wifi_hal_error_print("%s:%d Extraction failure for onewifi value \r\n", __func__, __LINE__);
        return -1;
    }

    strncpy(password, (const char*)encrypted_key, BUFLEN_128 - 1);
    password[BUFLEN_128 - 1] = '\0';

    if(rdkconfig_free(&encrypted_key, encrypted_keysize)  == RDKCONFIG_FAIL) {
        wifi_hal_info_print("%s:%d Memory deallocation for onewifi value failed \r\n", __func__, __LINE__);
    }
    return 0;
}

/* Get default encrypted SSID. */
static int get_default_encrypted_ssid (char* ssid) {

    if (NULL == ssid) {
        wifi_hal_error_print("%s:%d Invalid parameter \r\n", __func__, __LINE__);
        return -1;
    }

    const char* default_ssid_encrypted_key = "onewifidefaultssid";
    uint8_t    *ssid_key=NULL;
    size_t ssid_keysize;
    if(rdkconfig_get(&ssid_key, &ssid_keysize, default_ssid_encrypted_key))
    {
        wifi_hal_error_print("%s:%d Extraction failure for onewifi value \r\n", __func__, __LINE__);
        return -1;
    }

    strncpy(ssid, (const char*)ssid_key, BUFLEN_128 -1);
    ssid[BUFLEN_128 - 1] = '\0';

    if(rdkconfig_free(&ssid_key, ssid_keysize)  == RDKCONFIG_FAIL) {
        wifi_hal_info_print("%s:%d Memory deallocation for onewifi value failed \r\n", __func__, __LINE__);
    }
    return 0;
}

extern char *wlcsm_nvram_get(char *name);

int platform_pre_init()
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s \n", __func__);

    wifi_hal_info_print("%s:%d: start_wifi_apps\n", __func__, __LINE__);
    v_secure_system("wifi_setup.sh start_wifi_apps");

    return 0;
}

void set_decimal_nvram_param(char *param_name, unsigned int value)
{
    char temp_buff[8];
    memset(temp_buff, 0 ,sizeof(temp_buff));
    snprintf(temp_buff, sizeof(temp_buff), "%d", value);
    wlcsm_nvram_set(param_name, temp_buff);
}

void set_string_nvram_param(char *param_name, char *value)
{
    wlcsm_nvram_set(param_name, value);
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s \n", __func__);
    if (operationParam == NULL) {
        wifi_hal_dbg_print("%s:%d Invalid Argument \n", __FUNCTION__, __LINE__);
        return -1;
    }
    char temp_buff[BUF_SIZE];
    char param_name[NVRAM_NAME_SIZE];
    wifi_radio_info_t *radio;
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }
    if (radio->radio_presence == false) {
        wifi_hal_dbg_print("%s:%d Skip this radio %d. This is in sleeping mode\n", __FUNCTION__, __LINE__, index);
        return 0;
    }
    if (radio->oper_param.countryCode != operationParam->countryCode) {
        memset(temp_buff, 0 ,sizeof(temp_buff));
        get_coutry_str_from_code(operationParam->countryCode, temp_buff);
        if (wifi_setRadioCountryCode(index, temp_buff) != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d Failure in setting country code as %s in radio index %d\n", __FUNCTION__, __LINE__, temp_buff, index);
            return -1;
        }
        if (wifi_applyRadioSettings(index) != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d Failure in applying Radio settings in radio index %d\n", __FUNCTION__, __LINE__, index);
            return -1;
        }
        //Updating nvram param
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_country_code", index);
        set_string_nvram_param(param_name, temp_buff);
    }
    
    return 0;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

int nvram_get_default_password(char *l_password, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    int len;
    char *key_passphrase;

    memset(interface_name, 0, sizeof(interface_name));
    get_interface_name_from_vap_index(vap_index, interface_name);
    snprintf(nvram_name, sizeof(nvram_name), "%s_wpa_psk", interface_name);
    key_passphrase = wlcsm_nvram_get(nvram_name);
    if (key_passphrase == NULL) {
        wifi_hal_error_print("%s:%d nvram key_passphrase value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    len = strlen(key_passphrase);
    if (len < 8 || len > 63) {
        wifi_hal_error_print("%s:%d invalid wpa passphrase length [%d], expected length is [8..63]\r\n", __func__, __LINE__, len);
        return -1;
    }
    strcpy(l_password, key_passphrase);
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    if(is_wifi_hal_vap_mesh_sta(vap_index)) {
        return get_default_encrypted_password(password);
    }else {
        strncpy(password,"123456789",strlen("123456789")+1);
        return 0;
    }
    return -1;
}
int platform_get_radius_key_default(char *radius_key)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char *key;

    snprintf(nvram_name, sizeof(nvram_name), "default_radius_key");
    key = wlcsm_nvram_get(nvram_name);
    if (key == NULL) {
        wifi_hal_error_print("%s:%d nvram  radius_keydefault value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    else {
        strcpy(radius_key,key);
    }
        return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index){
    char *str = NULL;
    if(is_wifi_hal_vap_mesh_sta(vap_index)) {
        char default_ssid[128] = {0};
        if (get_default_encrypted_ssid(default_ssid) == -1) {
            //Failed to get encrypted ssid.
            str = "OutOfService";
            strncpy(ssid,str,strlen(str)+1);
        }else {
            strncpy(ssid,default_ssid,strlen(default_ssid)+1);
        }
    }else {
        str = "OutOfService";
        strncpy(ssid,str,strlen(str)+1);
    }
    return 0;
}

int platform_get_wps_pin_default(char *pin)
{
    strcpy(pin, "88626277"); /* remove this and read the factory defaults below */
    wifi_hal_dbg_print("%s default wps pin:%s\n", __func__, pin);
    return 0;
#if 0
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;
    fp = popen("grep \"Default WPS Pin:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL) {
            strncpy(pin, value, strlen(value) - 1);
        }
        pclose(fp);
        return 0;
    }
    return -1;
#endif
}

int platform_wps_event(wifi_wps_event_t data)
{
    return 0;
}

int platform_get_country_code_default(char *code)
{
	char value[BUFFER_LENGTH_WIFIDB] = {0};
        FILE *fp = NULL;
        fp = popen("grep \"REGION=\" /tmp/serial.txt | cut -d '=' -f 2 | tr -d '\r\n'","r");
        if (fp != NULL) {
        while(fgets(value, sizeof(value), fp) != NULL) {
                strncpy(code, value, strlen(value));
        }
        pclose(fp);
        return 0;
        }
        return -1;

}

int nvram_get_current_password(char *l_password, int vap_index)
{
    return nvram_get_default_password(l_password, vap_index);
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    int len;
    char *ssid;

    memset(interface_name, 0, sizeof(interface_name));
    get_interface_name_from_vap_index(vap_index, interface_name);
    snprintf(nvram_name, sizeof(nvram_name), "%s_ssid", interface_name);
    ssid = wlcsm_nvram_get(nvram_name);
    if (ssid == NULL) {
        wifi_hal_error_print("%s:%d nvram ssid value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    len = strlen(ssid);
    if (len < 0 || len > 63) {
        wifi_hal_error_print("%s:%d invalid ssid length [%d], expected length is [0..63]\r\n", __func__, __LINE__, len);
        return -1;
    }
    strcpy(l_ssid, ssid);
    wifi_hal_dbg_print("%s:%d vap[%d] ssid:%s nvram name:%s\r\n", __func__, __LINE__, vap_index, l_ssid, nvram_name);
    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char interface_name[10];
    char param[128];
    wifi_vap_info_t *vap;
    unsigned int vap_itr = 0;

    for (vap_itr=0; vap_itr < map->num_vaps; vap_itr++) {
        memset(interface_name, 0, sizeof(interface_name));
        memset(param, 0, sizeof(param));
        vap = &map->vap_array[vap_itr];
        get_interface_name_from_vap_index(vap->vap_index, interface_name);
        snprintf(param, sizeof(param), "%s_bss_enabled", interface_name);
        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (vap->u.bss_info.enabled) {
                wlcsm_nvram_set(param, "1");
            } else {
                wlcsm_nvram_set(param, "0");
            }
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            if (vap->u.sta_info.enabled) {
                wlcsm_nvram_set(param, "1");
            } else {
                wlcsm_nvram_set(param, "0");
            }
        }
    }

    return 0;
}

int platform_flags_init(int *flags)
{
    *flags = PLATFORM_FLAGS_STA_INACTIVITY_TIMER;
    return 0;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
    return 0;
}

int platform_free_aid(void* priv, u16* aid)
{
    return 0;
}

int platform_sync_done(void* priv)
{
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
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

int platform_set_txpower(void* priv, uint txpower)
{
    return 0;
}

int platform_set_offload_mode(void* priv, uint offload_mode)
{
    return RETURN_OK;
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
    return RETURN_OK;
}

int wifi_setQamPlus(void *priv)
{
    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    return 0;
}

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return 0;
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return 0;
}
