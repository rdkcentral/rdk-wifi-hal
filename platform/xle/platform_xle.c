#include <stddef.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#if defined(WLDM_21_2)
#include "wlcsm_lib_api.h"
#else
#include "nvram_api.h"
#endif // defined(WLDM_21_2)
#include "wlcsm_lib_wl.h"
#include "wlcsm_lib_api.h"
#include "rdkconfig.h"
#define BUFFER_LENGTH_WIFIDB 256
#define BUFLEN_128  128
#undef ENABLE
#define wpa_ptk _wpa_ptk
#define wpa_gtk _wpa_gtk
#define mld_link_info _mld_link_info
#if !defined(WLDM_21_2) && (HOSTAPD_VERSION >= 210)
#include <wlioctl.h>
#endif

/*
If include secure_wrapper.h, will need to convert other system calls with v_secure_system calls
#include <secure_wrapper.h>
*/
int v_secure_system(const char *command, ...);
FILE *v_secure_popen(const char *direction, const char *command, ...);
int v_secure_pclose(FILE *);

typedef struct wl_runtime_params {
    char *param_name;
    char *param_val;
}wl_runtime_params_t;

static wl_runtime_params_t g_wl_runtime_params[] = {
    {"he color_collision", "0x7"}
};

static void set_wl_runtime_configs (const wifi_vap_info_map_t *vap_map);


/* API to get encrypted default psk and ssid. */
static int get_default_encrypted_password (char* password);
static int get_default_encrypted_ssid (char* ssid);

static void set_wl_runtime_configs(const wifi_vap_info_map_t *vap_map)
{

    if (NULL == vap_map) {
        wifi_hal_error_print("%s:%d: Invalid parameter error!!\n", __func__, __LINE__);
        return;
    }

    int wl_elems_index = 0;
    int radio_index = 0;
    int vap_index = 0;
    char sys_cmd[128] = { 0 };
    char interface_name[8] = { 0 };
    wifi_vap_info_t *vap = NULL;
    int no_of_elems = sizeof(g_wl_runtime_params) / sizeof(wl_runtime_params_t);

    /* Traverse through each radios and its vaps, and set configurations for private interfaces. */
    for (radio_index = 0; radio_index < g_wifi_hal.num_radios; radio_index++) {
        if (vap_map != NULL) {
            for (vap_index = 0; vap_index < vap_map->num_vaps; vap_index++) {
                vap = &vap_map->vap_array[vap_index];
                if (is_wifi_hal_vap_private(vap->vap_index)) {
                    memset(interface_name, 0, sizeof(interface_name));
                    get_interface_name_from_vap_index(vap->vap_index, interface_name);
                    for (wl_elems_index = 0; wl_elems_index < no_of_elems; wl_elems_index++) {
                        sprintf(sys_cmd, "wl -i %s %s %s", interface_name,
                            g_wl_runtime_params[wl_elems_index].param_name,
                            g_wl_runtime_params[wl_elems_index].param_val);
                        wifi_hal_info_print("%s:%d: wl sys_cmd = %s \n", __func__, __LINE__,
                            sys_cmd);
                        v_secure_system(sys_cmd);
                    }
                }
            }
            vap_map++;
        }
    }
}

/* Get default encrypted PSK key. */
static int get_default_encrypted_password(char *password)
{
    if (NULL == password) {
        wifi_hal_error_print("%s:%d Invalid parameter \r\n", __func__, __LINE__);
        return -1;
    }

    const char *default_pwd_encrypted_key = "onewifidefaultcred";
    char *encrypted_key = NULL;
    size_t encrypted_keysize;

    if (rdkconfig_getStr(&encrypted_key, &encrypted_keysize, default_pwd_encrypted_key) !=
        RDKCONFIG_OK) {
        wifi_hal_error_print("%s:%d Extraction failure for onewifi value \r\n", __func__, __LINE__);
        return -1;
    }

    strncpy(password, (const char *)encrypted_key, BUFLEN_128 - 1);
    password[BUFLEN_128 - 1] = '\0';

    if (rdkconfig_freeStr(&encrypted_key, encrypted_keysize) == RDKCONFIG_FAIL) {
        wifi_hal_info_print("%s:%d Memory deallocation for onewifi value failed \r\n", __func__,
            __LINE__);
    }
    return 0;
}

/* Get default encrypted SSID. */
static int get_default_encrypted_ssid(char *ssid)
{

    if (NULL == ssid) {
        wifi_hal_error_print("%s:%d Invalid parameter \r\n", __func__, __LINE__);
        return -1;
    }

    const char *default_ssid_encrypted_key = "onewifidefaultssid";
    char *ssid_key = NULL;
    size_t ssid_keysize;
    if (rdkconfig_getStr(&ssid_key, &ssid_keysize, default_ssid_encrypted_key) != RDKCONFIG_OK) {
        wifi_hal_error_print("%s:%d Extraction failure for onewifi value \r\n", __func__, __LINE__);
        return -1;
    }

    strncpy(ssid, (const char *)ssid_key, BUFLEN_128 - 1);
    ssid[BUFLEN_128 - 1] = '\0';

    if (rdkconfig_freeStr(&ssid_key, ssid_keysize) == RDKCONFIG_FAIL) {
        wifi_hal_info_print("%s:%d Memory deallocation for onewifi value failed \r\n", __func__,
            __LINE__);
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
    //set runtime configs using wl command.
    set_wl_runtime_configs(vap_map);

    return 0;
}

void set_decimal_nvram_param(char *param_name, unsigned int value)
{
    char temp_buff[8];
    memset(temp_buff, 0 ,sizeof(temp_buff));
    snprintf(temp_buff, sizeof(temp_buff), "%d", value);
#if defined(WLDM_21_2)
    wlcsm_nvram_set(param_name, temp_buff);
#else
    nvram_set(param_name, temp_buff);
#endif // defined(WLDM_21_2)
}

void set_string_nvram_param(char *param_name, char *value)
{
#if defined(WLDM_21_2)
    wlcsm_nvram_set(param_name, value);
#else
    nvram_set(param_name, value);
#endif // defined(WLDM_21_2)
}

static int disable_dfs_auto_channel_change(int radio_index, int disable)
{
#if defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)
    char radio_dev[IFNAMSIZ];

    snprintf(radio_dev, sizeof(radio_dev), "wl%d", radio_index);

    if (wl_ioctl(radio_dev, WLC_DOWN, NULL, 0) < 0) {
        wifi_hal_error_print("%s:%d failed to set radio down for %s, err: %d (%s)\n", __func__,
            __LINE__, radio_dev, errno, strerror(errno));
        return -1;
    }

    if (wl_iovar_set(radio_dev, "dfs_auto_channel_change_disable", &disable, sizeof(disable)) < 0) {
        wifi_hal_error_print("%s:%d failed to set dfs_auto_channel_change_disable %d for %s, "
                             "err: %d (%s)\n",
            __func__, __LINE__, disable, radio_dev, errno, strerror(errno));
        return -1;
    }

    if (wl_ioctl(radio_dev, WLC_UP, NULL, 0) < 0) {
        wifi_hal_error_print("%s:%d failed to set radio up for %s, err: %d (%s)\n", __func__,
            __LINE__, radio_dev, errno, strerror(errno));
        return -1;
    }
#endif // FEATURE_HOSTAP_MGMT_FRAME_CTRL
    return 0;
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

    if (radio->oper_param.DfsEnabled != operationParam->DfsEnabled) {
        /* userspace selects new channel and configures CSA when radar detected */
        disable_dfs_auto_channel_change(index, true);
    }
    
    return 0;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_dbg_print("%s \n", __func__);
    return 0;
}

#if defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)

#define ASSOC_DRIVER_CTRL 0
#define ASSOC_HOSTAP_STATUS_CTRL 1
#define ASSOC_HOSTAP_FULL_CTRL 2

static int platform_set_hostap_ctrl(wifi_radio_info_t *radio, uint vap_index, int enable)
{
    int assoc_ctrl;
    char buf[128] = {0};
    char interface_name[8] = {0};
    struct maclist *maclist = (struct maclist *)buf;

    if (get_interface_name_from_vap_index(vap_index, interface_name) != RETURN_OK) {
        wifi_hal_error_print("%s:%d failed to get interface name for vap index: %d, err: %d (%s)\n",
            __func__, __LINE__, vap_index, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (wl_iovar_set(interface_name, "usr_beacon", &enable, sizeof(enable)) < 0) {
        wifi_hal_error_print("%s:%d failed to set usr_beacon %d for %s, err: %d (%s)\n", __func__,
            __LINE__, enable, interface_name, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (wl_iovar_set(interface_name, "usr_probresp", &enable, sizeof(enable)) < 0) {
        wifi_hal_error_print("%s:%d failed to set usr_probresp %d for %s, err: %d (%s)\n", __func__,
            __LINE__, enable, interface_name, errno, strerror(errno));
        return RETURN_ERR;
    }

    maclist->count = 0;
    if (wl_ioctl(interface_name, WLC_SET_PROBE_FILTER, maclist, sizeof(maclist->count)) < 0) {
        wifi_hal_error_print("%s:%d failed to reset probe filter for %s, err: %d (%s)\n", __func__,
            __LINE__, interface_name, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (enable) {
        maclist->count = 1;
        memset(&maclist->ea[0], 0xff, sizeof(maclist->ea[0]));
        if (wl_ioctl(interface_name, WLC_SET_PROBE_FILTER, maclist, sizeof(buf)) < 0) {
            wifi_hal_error_print("%s:%d failed to set probe filter for %s, err: %d (%s)\n",
                __func__, __LINE__, interface_name, errno, strerror(errno));
            return RETURN_ERR;
        }
    }

    if (wl_iovar_set(interface_name, "usr_auth", &enable, sizeof(enable)) < 0) {
        wifi_hal_error_print("%s:%d failed to set usr_auth %d for %s, err: %d (%s)\n", __func__,
            __LINE__, enable, interface_name, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (enable) {
        assoc_ctrl = ASSOC_HOSTAP_FULL_CTRL;
    } else if (is_wifi_hal_vap_hotspot_open(vap_index) ||
        is_wifi_hal_vap_hotspot_secure(vap_index)) {
        assoc_ctrl = ASSOC_HOSTAP_STATUS_CTRL;
    } else {
        assoc_ctrl = ASSOC_DRIVER_CTRL;
    }

    if (wl_ioctl(interface_name, WLC_DOWN, NULL, 0) < 0) {
         wifi_hal_error_print("%s:%d failed to set interface down for %s, err: %d (%s)\n", __func__,
             __LINE__, interface_name, errno, strerror(errno));
         return RETURN_ERR;
    }

    if (wl_iovar_set(interface_name, "split_assoc_req", &assoc_ctrl, sizeof(assoc_ctrl)) < 0) {
        wifi_hal_error_print("%s:%d failed to set split_assoc_req %d for %s, err: %d (%s)\n",
            __func__, __LINE__, assoc_ctrl, interface_name, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (wl_ioctl(interface_name, WLC_UP, NULL, 0) < 0) {
         wifi_hal_error_print("%s:%d failed to set interface up for %s, err: %d (%s)\n", __func__,
             __LINE__, interface_name, errno, strerror(errno));
         return RETURN_ERR;
    }

    return RETURN_OK;
}
#endif // FEATURE_HOSTAP_MGMT_FRAME_CTRL

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    int vap_index = 0;
    wifi_radio_info_t *radio;

    wifi_hal_dbg_print("%s:%d: Entering Radio index %d\n", __func__, __LINE__, index);

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

    for (vap_index = 0; vap_index < map->num_vaps; vap_index++) {
        if (map->vap_array[vap_index].vap_mode == wifi_vap_mode_ap) {
#if defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)
            wifi_hal_info_print("%s:%d: vap_index:%d, hostap_mgt_frame_ctrl:%d\n", __func__,
                __LINE__, map->vap_array[vap_index].vap_index,
                map->vap_array[vap_index].u.bss_info.hostap_mgt_frame_ctrl);
            platform_set_hostap_ctrl(radio, map->vap_array[vap_index].vap_index,
                map->vap_array[vap_index].u.bss_info.hostap_mgt_frame_ctrl);
#endif // FEATURE_HOSTAP_MGMT_FRAME_CTRL
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
#if defined(WLDM_21_2)
    key_passphrase = wlcsm_nvram_get(nvram_name);
#else
    key_passphrase = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
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
#if defined(WLDM_21_2)
    key = wlcsm_nvram_get(nvram_name);
#else
    key = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
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
#if defined(WLDM_21_2)
    ssid = wlcsm_nvram_get(nvram_name);
#else
    ssid = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
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
#if defined(WLDM_21_2)
                wlcsm_nvram_set(param, "1");
#else
                nvram_set(param, "1");
#endif // defined(WLDM_21_2)
            } else {
#if defined(WLDM_21_2)
                wlcsm_nvram_set(param, "0");
#else
                nvram_set(param, "0");
#endif // defined(WLDM_21_2)
            }
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            if (vap->u.sta_info.enabled) {
#if defined(WLDM_21_2)
                wlcsm_nvram_set(param, "1");
#else
                nvram_set(param, "1");
#endif // defined(WLDM_21_2)
            } else {
#if defined(WLDM_21_2)
                wlcsm_nvram_set(param, "0");
#else
                nvram_set(param, "0");
#endif // defined(WLDM_21_2)
            }
        }
    }

    return 0;
}

int platform_flags_init(int *flags)
{
    *flags = PLATFORM_FLAGS_PROBE_RESP_OFFLOAD | PLATFORM_FLAGS_STA_INACTIVITY_TIMER;
    return 0;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
#if defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)
    int ret;
    sta_info_t sta_info;
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;

    ret = wl_iovar_getbuf(interface->name, "sta_info", addr, ETHER_ADDR_LEN, &sta_info,
        sizeof(sta_info));
    if (ret < 0) {
        wifi_hal_error_print("%s:%d failed to get sta info, err: %d (%s)\n", __func__, __LINE__,
            errno, strerror(errno));
        return RETURN_ERR;
    }

    *aid = sta_info.aid;

    wifi_hal_dbg_print("%s:%d sta aid %d\n", __func__, __LINE__, *aid);
#endif // defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)
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

#if defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)

static int get_rates(char *ifname, int *rates, size_t rates_size, unsigned int *num_rates)
{
    wl_rateset_t rs;

    if (wl_ioctl(ifname, WLC_GET_CURR_RATESET, &rs, sizeof(wl_rateset_t)) < 0) {
        wifi_hal_error_print("%s:%d: failed to get rateset for %s, err %d (%s)\n", __func__,
            __LINE__, ifname, errno, strerror(errno));
        return RETURN_ERR;
    }

    if (rates_size < rs.count) {
        wifi_hal_error_print("%s:%d: rates size %zu is less than %u\n", __func__, __LINE__,
            rates_size, rs.count);
        rs.count = rates_size;
    }

    for (unsigned int i = 0; i < rs.count; i++) {
        // clear basic rate flag and convert 500 kbps to 100 kbps units
        rates[i] = (rs.rates[i] & 0x7f) * 5;
    }
    *num_rates = rs.count;

    return RETURN_OK;
}

static void platform_get_radio_caps_common(wifi_radio_info_t *radio,
    wifi_interface_info_t *interface)
{
    unsigned int num_rates;
    int rates[WL_MAXRATES_IN_SET];
    struct hostapd_iface *iface = &interface->u.ap.iface;

    if (get_rates(interface->name, rates, ARRAY_SZ(rates), &num_rates) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: failed to get rates for %s\n", __func__, __LINE__,
            interface->name);
        return;
    }

    for (int i = 0; i < iface->num_hw_features; i++) {
        if (iface->hw_features[i].num_rates >= num_rates) {
            memcpy(iface->hw_features[i].rates, rates, num_rates * sizeof(rates[0]));
            iface->hw_features[i].num_rates = num_rates;
        }
    }
}

static void platform_get_radio_caps_2g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    // Set values from driver beacon, NL values are not valid.
    // SCS bit is not set in driver
    static const u8 ext_cap[] = { 0x85, 0x00, 0x08, 0x82, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
        0x20 };
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0x00, 0x00 };
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xfa, 0xff, 0xfa, 0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x19, 0x1c, 0xc7, 0x71 };
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x22, 0x20, 0x02, 0xc0, 0x0f, 0x01, 0x95,
        0x08, 0x00, 0xcc, 0x00 };
    struct hostapd_iface *iface = &interface->u.ap.iface;

    radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_UAPSD;

    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);

    for (int i = 0; i < iface->num_hw_features; i++) {
        iface->hw_features[i].ht_capab = 0x11ef;
        iface->hw_features[i].a_mpdu_params &= ~(0x07 << 2);
        iface->hw_features[i].a_mpdu_params |= 0x05 << 2;
        memcpy(iface->hw_features[i].mcs_set, ht_mcs, sizeof(ht_mcs));

        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
        }
    }
}

static void platform_get_radio_caps_5gl(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    struct hostapd_iface *iface = &interface->u.ap.iface;

    static const u8 ext_cap[] = { 0x84, 0x00, 0x08, 0x82, 0x01, 0x00, 0x40, 0x40, 0x00, 0x40,
    0x20 };
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0x00, 0x00 };
    static const u8 vht_mcs[8] = { 0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x20 };
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x44, 0x20, 0x02, 0xc0, 0x0f, 0x01, 0x95,
    0x10, 0x00, 0xcc, 0x00 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xfa, 0xff, 0xfa, 0xff, 0x00, 0x00, 0x00, 0x00 };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };

    radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_UAPSD | WPA_DRIVER_FLAGS_DFS_OFFLOAD;

    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);

    for (int i = 0; i < iface->num_hw_features; i++) {
        iface->hw_features[i].ht_capab = 0x09ef;
        iface->hw_features[i].a_mpdu_params &= ~(0x07 << 2);
        iface->hw_features[i].a_mpdu_params |= 0x05 << 2;
        memcpy(iface->hw_features[i].mcs_set, ht_mcs, sizeof(ht_mcs));
        iface->hw_features[i].vht_capab = 0x0f8979b1;
        memcpy(iface->hw_features[i].vht_mcs_set, vht_mcs, sizeof(vht_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].max_tx_power = 24; // dBm
            } else {
                iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
            }

            /* Re-enable DFS channels disabled due to missing WPA_DRIVER_FLAGS_DFS_OFFLOAD flag */
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_DISABLED &&
                iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].flag &= ~HOSTAPD_CHAN_DISABLED;
            }
        }
    }

}

static void platform_get_radio_caps_5gh(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    struct hostapd_iface *iface = &interface->u.ap.iface;

    static const u8 ext_cap[] = { 0x84, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40,
    0x20 };
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0xff, 0xff };
    static const u8 vht_mcs[8] = { 0xaa, 0xff, 0x00, 0x00, 0xaa, 0xff, 0x00, 0x20 };
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x02, 0x1b, 0x95,
    0x00, 0x00, 0xcc, 0x00 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff, 0xaa, 0xff, 0xaa,
    0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x7b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
    0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };

    radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_UAPSD | WPA_DRIVER_FLAGS_DFS_OFFLOAD;

    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);

    for (int i = 0; i < iface->num_hw_features; i++) {
        iface->hw_features[i].ht_capab = 0x01ef;
        iface->hw_features[i].a_mpdu_params &= ~(0x07 << 2);
        iface->hw_features[i].a_mpdu_params |= 0x05 << 2;
        memcpy(iface->hw_features[i].mcs_set, ht_mcs, sizeof(ht_mcs));
        iface->hw_features[i].vht_capab = 0x0f8b69b6;
        memcpy(iface->hw_features[i].vht_mcs_set, vht_mcs, sizeof(vht_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].max_tx_power = 24; // dBm
            } else {
                iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
            }

            /* Re-enable DFS channels disabled due to missing WPA_DRIVER_FLAGS_DFS_OFFLOAD flag */
            if (iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_DISABLED &&
                iface->hw_features[i].channels[ch].flag & HOSTAPD_CHAN_RADAR) {
                iface->hw_features[i].channels[ch].flag &= ~HOSTAPD_CHAN_DISABLED;
            }
        }
    }
}

int platform_get_radio_caps(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }

    for (interface = hash_map_get_first(radio->interface_map); interface != NULL;
        interface = hash_map_get_next(radio->interface_map, interface)) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            wifi_hal_info_print("%s:%d: skipping interface %s, vap mode is STA\n",
                __func__, __LINE__, interface->name);
            continue;
        }

        platform_get_radio_caps_common(radio, interface);

        if (strstr(interface->vap_info.vap_name, "2g")) {
            platform_get_radio_caps_2g(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "5gl")) {
            platform_get_radio_caps_5gl(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "5gh")) {
            platform_get_radio_caps_5gh(radio, interface);
        } else {
            wifi_hal_error_print("%s:%d: unknown interface %s\n", __func__, __LINE__,
                interface->vap_info.vap_name);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

#else

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}
#endif //defined(FEATURE_HOSTAP_MGMT_FRAME_CTRL)

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    int res = wifi_hal_send_mgmt_frame(apIndex, MacAddr, frame, len, frequency, wait);
    return (res == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_ERROR;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, MacAddr, frequency, 0, frame, len);
}
