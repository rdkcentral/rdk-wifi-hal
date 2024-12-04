#include <stddef.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#if defined(WLDM_21_2)
#include "wlcsm_lib_api.h"
#else
#include "nvram_api.h"
#endif // defined(WLDM_21_2)
#include "wlcsm_lib_wl.h"
#if defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#endif // defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) 
#include <rdk_nl80211_hal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdint.h>
#include <unistd.h>
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT 

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
#undef ENABLE
#undef BW_20MHZ
#undef BW_40MHZ
#undef BW_80MHZ
#undef BW_160MHZ
#undef BW_320MHZ
#define wpa_ptk _wpa_ptk
#define wpa_gtk _wpa_gtk
#define mld_link_info _mld_link_info
#if defined(SCXER10_PORT)
#include <wifi-include/wlioctl.h>
#else
#include <wifi/wlioctl.h>
#endif
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
static bool l_eht_set = false;
void (*g_eht_oneshot_notify)(wifi_interface_info_t *interface) = NULL;

/*
If include secure_wrapper.h, will need to convert other system calls with v_secure_system calls
#include <secure_wrapper.h>
*/
int v_secure_system(const char *command, ...);
FILE *v_secure_popen(const char *direction, const char *command, ...);
int v_secure_pclose(FILE *);

static bool platform_radio_state(wifi_radio_index_t index);
static bool platform_is_eht_enabled(wifi_radio_index_t index);
static void platform_set_eht_hal_callback(wifi_interface_info_t *interface);
static void platform_wait_for_eht(void);
static void platform_set_eht(wifi_radio_index_t index, bool enable);
#if defined(KERNEL_NO_320MHZ_SUPPORT)
static void platform_csa_to_chanspec(struct csa_settings *settings, char *chspec);
static bool platform_is_same_chanspec(wifi_radio_index_t index, char *new_chanspec);
static enum nl80211_chan_width bandwidth_str_to_nl80211_width(char *bandwidth);
static enum nl80211_chan_width platform_get_chanspec_bandwidth(char *chanspec);
#endif
#endif

#define BUFFER_LENGTH_WIFIDB 256
#define BUFLEN_128  128
#define BUFLEN_256 256
#define WIFI_BLASTER_DEFAULT_PKTSIZE 1470

typedef struct wl_runtime_params {
    char *param_name;
    char *param_val;
}wl_runtime_params_t;

static wl_runtime_params_t g_wl_runtime_params[] = {
    {"he color_collision", "0x7"},
    {"nmode_protection_override", "0"},
    {"protection_control", "0"},
    {"gmode_protection_control", "0"}
};

static void set_wl_runtime_configs (const wifi_vap_info_map_t *vap_map);
static int get_chanspec_string(wifi_radio_operationParam_t *operationParam, char *chspec, wifi_radio_index_t index);
int sta_disassociated(int ap_index, char *mac, int reason);
int sta_deauthenticated(int ap_index, char *mac, int reason);
int sta_associated(int ap_index, wifi_associated_dev_t *associated_dev);
#if defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)
static int check_edpdctl_enabled();
static int check_dpd_feature_enabled();
static int enable_echo_feature_and_power_control_configs(void);
int platform_set_ecomode_for_radio(const int wl_idx, const bool eco_pwr_down);
int platform_set_gpio_config_for_ecomode(const int wl_idx, const bool eco_pwr_down);
#endif // defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)

#ifndef NEWPLATFORM_PORT
static char const *bss_nvifname[] = {
    "wl0",      "wl1",
    "wl0.1",    "wl1.1",
    "wl0.2",    "wl1.2",
    "wl0.3",    "wl1.3",
    "wl0.4",    "wl1.4",
    "wl0.5",    "wl1.5",
    "wl0.6",    "wl1.6",
    "wl0.7",    "wl1.7",
    "wl2",      "wl2.1",
    "wl2.2",    "wl2.3",
    "wl2.4",    "wl2.5",
    "wl2.6",    "wl2.7",
};  /* Indexed by apIndex */

static int get_ccspwifiagent_interface_name_from_vap_index(unsigned int vap_index, char *interface_name)
{
    // OneWifi interafce mapping with vap_index
    unsigned char l_index = 0;
    unsigned char total_num_of_vaps = 0;
    char *l_interface_name = NULL;
    wifi_radio_info_t *radio;

    for (l_index = 0; l_index < g_wifi_hal.num_radios; l_index++) {
        radio = get_radio_by_rdk_index(l_index);
        total_num_of_vaps += radio->capab.maxNumberVAPs;
    }

    if ((vap_index >= total_num_of_vaps) || (interface_name == NULL)) {
        wifi_hal_error_print("%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    l_interface_name = bss_nvifname[vap_index];
    if(l_interface_name != NULL) {
        strncpy(interface_name, l_interface_name, (strlen(l_interface_name) + 1));
        wifi_hal_dbg_print("%s:%d: VAP index %d: interface name %s\n", __func__, __LINE__, vap_index, interface_name);
    } else {
        wifi_hal_error_print("%s:%d: Interface name not found:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    return RETURN_OK;
}
#endif

static void set_wl_runtime_configs (const wifi_vap_info_map_t *vap_map)
{
    if (NULL == vap_map) {
        wifi_hal_error_print("%s:%d: Invalid parameter error!!\n",__func__, __LINE__);
        return;
    }

    int wl_elems_index = 0;
    int radio_index = 0;
    int vap_index = 0;
    char sys_cmd[128] = {0};
    char interface_name[8] = {0};
    wifi_vap_info_t *vap = NULL;
    int no_of_elems = sizeof(g_wl_runtime_params) / sizeof(wl_runtime_params_t);

    /* Traverse through each radios and its vaps, and set configurations for private interfaces. */
    for(radio_index = 0; radio_index < g_wifi_hal.num_radios; radio_index++) {
        if (vap_map != NULL) {
            for(vap_index = 0; vap_index < vap_map->num_vaps; vap_index++) {
                vap = &vap_map->vap_array[vap_index];
                if (is_wifi_hal_vap_private(vap->vap_index)) {
                    memset (interface_name, 0 ,sizeof(interface_name));
                    get_interface_name_from_vap_index(vap->vap_index, interface_name);
                    for (wl_elems_index = 0; wl_elems_index < no_of_elems; wl_elems_index++) {
                        snprintf(sys_cmd, sizeof(sys_cmd), "wl -i %s %s %s", interface_name, g_wl_runtime_params[wl_elems_index].param_name, g_wl_runtime_params[wl_elems_index].param_val);
                        wifi_hal_dbg_print("%s:%d: wl sys_cmd = %s \n", __func__, __LINE__,sys_cmd);
                        system(sys_cmd);
                    }
                }
            }
            vap_map++;
        }
    }
}

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
#define SEM_NAME "/semlock"

int get_emu_neighbor_stats(uint radio_index, wifi_neighbor_ap2_t **neighbor_ap_array,
    uint *data_count)
{
    FILE *fp;
    char file_path[64];
    sem_t *sem;
    emu_neighbor_stats_t neighbor_header;
    wifi_neighbor_ap2_t *combined_data;
    uint existing_count = *data_count;

    wifi_hal_dbg_print("%s:%d: Entered with radio_index = %u\n", __func__, __LINE__, radio_index);
    snprintf(file_path, sizeof(file_path), "/dev/shm/wifi_neighbor_ap_emu_%u", radio_index);

    if (access(file_path, F_OK) != 0) {
        return RETURN_OK;
    }

    sem = sem_open(SEM_NAME, 0);
    if (sem == SEM_FAILED) {
        wifi_hal_error_print("%s:%d: Semaphore does not exist, emulation likely disabled.\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sem_wait(sem) == -1) {
        wifi_hal_error_print("%s:%d: Failed to acquire semaphore\n", __func__, __LINE__);
        sem_close(sem);
        return RETURN_ERR;
    }

    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        wifi_hal_error_print("%s:%d: Failed to open file\n", __func__, __LINE__);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    if (fread(&neighbor_header, sizeof(emu_neighbor_stats_t), 1, fp) != 1) {
        wifi_hal_error_print("%s:%d: Failed to read header data\n", __func__, __LINE__);
        fclose(fp);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    combined_data = malloc(
        (existing_count + neighbor_header.neighbor_count) * sizeof(wifi_neighbor_ap2_t));
    if (combined_data == NULL) {
        wifi_hal_error_print("%s:%d: Memory allocation for combined_data failed\n", __func__,
            __LINE__);
        fclose(fp);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    if (existing_count > 0 && *neighbor_ap_array != NULL) {
        memcpy(combined_data, *neighbor_ap_array, existing_count * sizeof(wifi_neighbor_ap2_t));
        free(*neighbor_ap_array);
    }

    if (fread(combined_data + existing_count, sizeof(wifi_neighbor_ap2_t),
            neighbor_header.neighbor_count, fp) != neighbor_header.neighbor_count) {
        wifi_hal_error_print("%s:%d: Failed to read neighbor data:\n", __func__, __LINE__);
        free(combined_data);
        fclose(fp);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    *neighbor_ap_array = malloc(
        (existing_count + neighbor_header.neighbor_count) * sizeof(wifi_neighbor_ap2_t));
    if (*neighbor_ap_array == NULL) {
        wifi_hal_error_print("%s:%d: Memory allocation for neighbor_ap_array failed\n", __func__,
            __LINE__);
        free(combined_data);
        fclose(fp);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    memcpy(*neighbor_ap_array, combined_data,
        (existing_count + neighbor_header.neighbor_count) * sizeof(wifi_neighbor_ap2_t));
    *data_count = existing_count + neighbor_header.neighbor_count;
    free(combined_data);

    if (sem_post(sem) == -1) {
        wifi_hal_error_print("%s:%d: Failed to release semaphore\n", __func__, __LINE__);
    }

    fclose(fp);
    sem_close(sem);
    return RETURN_OK;
}
#endif

INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    return wifi_hal_startNeighborScan(apIndex, scan_mode, dwell_time, chan_num, chan_list);
}

INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array,
    UINT *output_array_size)
{
    int ret;
    ret = wifi_hal_getNeighboringWiFiStatus(radio_index, neighbor_ap_array, output_array_size);
    if (ret == WIFI_HAL_NOT_READY) {
        return ret;
    } else if (ret == RETURN_ERR) {
        wifi_hal_error_print("%s:%d: wifi_hal_getNeighboringWiFiStatus failed\n", __func__,
            __LINE__);
    }
#if defined WIFI_EMULATOR_CHANGE
    if (get_emu_neighbor_stats(radio_index, neighbor_ap_array, output_array_size) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: get_emu_neighbor_stats failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }
#endif
    return ret;
}

int sta_disassociated(int ap_index, char *mac, int reason)
{
    return 0;
}

int sta_deauthenticated(int ap_index, char *mac, int reason)
{
    return 0;
}

int sta_associated(int ap_index, wifi_associated_dev_t *associated_dev)
{
    return 0;
}

void prepare_param_name(char *dest, char *interface_name, char *prefix)
{
    memset(dest, 0, strlen(dest));

    strncpy(dest, interface_name, strlen(interface_name));
    strcat(dest, prefix);
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

int platform_pre_init()
{
    wifi_hal_dbg_print("%s:%d \r\n", __func__, __LINE__);

    system("sysevent set multinet-up 13");
    system("sysevent set multinet-up 14");
    wifi_hal_info_print("sysevent sent to start mesh bridges\r\n");

//    nvram_set("wl0_bw_cap", "3");
    /* registering the dummy callbacks to receive the events in plume */
    wifi_newApAssociatedDevice_callback_register(sta_associated);
    wifi_apDeAuthEvent_callback_register(sta_deauthenticated);
    wifi_apDisassociatedDevice_callback_register(sta_disassociated);
#if 0
    system("wl -i wl0.1 nmode_protection_override 0");
    system("wl -i wl1.1 nmode_protection_override 0");
    system("wl -i wl0.1 protection_control 0");
    system("wl -i wl1.1 protection_control 0");
    system("wl -i wl0.1 gmode_protection_control 0");
    system("wl -i wl1.1 gmode_protection_control 0");
    wifi_hal_dbg_print("%s:%d: wifi param set success\r\n", __func__, __LINE__);
#endif
    return 0;
}

static int enable_spect_management(int radio_index, int enable)
{
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
    char radio_dev[IFNAMSIZ];

    snprintf(radio_dev, sizeof(radio_dev), "wl%d", radio_index);

    if (wl_ioctl(radio_dev, WLC_DOWN, NULL, 0) < 0) {
        wifi_hal_error_print("%s:%d failed to set radio down for %s, err: %d (%s)\n", __func__,
            __LINE__, radio_dev, errno, strerror(errno));
        return -1;
    }

    if (wl_ioctl(radio_dev, WLC_SET_SPECT_MANAGMENT, &enable, sizeof(enable)) < 0) {
        wifi_hal_error_print("%s:%d failed to set spect mgt to %d for %s, err: %d (%s)\n",
            __func__, __LINE__, enable, radio_dev, errno, strerror(errno));
        return -1;
    }

    if (wl_ioctl(radio_dev, WLC_UP, NULL, 0) < 0) {
        wifi_hal_error_print("%s:%d failed to set radio up for %s, err: %d (%s)\n", __func__,
            __LINE__, radio_dev, errno, strerror(errno));
        return -1;
    }
#endif // TCXB7_PORT || TCXB8_PORT
    return 0;
}

int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    if ((index < 0) || (operationParam == NULL)) {
        wifi_hal_dbg_print("%s:%d Invalid Argument \n", __FUNCTION__, __LINE__);
        return -1;
    }

    char temp_buff[BUF_SIZE];
    char param_name[NVRAM_NAME_SIZE];
    char cmd[BUFLEN_128];
    wifi_radio_info_t *radio;
    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        wifi_hal_dbg_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, index);
        return RETURN_ERR;
    }

#if defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)
    int ret = 0;
    if (operationParam->EcoPowerDown) {
        /* Enable eco mode feature and power control configurations. */
        ret = enable_echo_feature_and_power_control_configs();
        if (ret != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Failed to enable EDPD ECO Mode feature\n", __func__, __LINE__);
        }

        //Enable ECO mode for radio
        ret = platform_set_ecomode_for_radio(index, true);
        if (ret != RETURN_OK) {
           wifi_hal_dbg_print("%s:%d: Failed to enable ECO mode for radio index:%d\n", __func__, __LINE__, index);
        }

        //Disconnect the GPIO
        ret = platform_set_gpio_config_for_ecomode(index, true);
        if (ret != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d: Failed to disconnect gpio for radio index:%d\n", __func__, __LINE__, index);
        }
    } else {
        /* Enable eco mode feature and power control configurations. */
        ret = enable_echo_feature_and_power_control_configs();
        if (ret != RETURN_OK) {
            wifi_hal_error_print("%s:%d: Failed to enable EDPD ECO Mode feature\n", __func__, __LINE__);
        }

        //Connect the GPIO
        ret = platform_set_gpio_config_for_ecomode(index, false);
        if (ret != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d: Failed to connect gpio for radio index:%d\n", __func__, __LINE__, index);
        }

        //Disable ECO mode for radio
        ret = platform_set_ecomode_for_radio(index, false);
        if (ret != RETURN_OK) {
            wifi_hal_dbg_print("%s:%d: Failed to disable ECO mode for radio index:%d\n", __func__, __LINE__, index);
        }
    }
#endif // defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)

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

    if (radio->oper_param.autoChannelEnabled != operationParam->autoChannelEnabled) {
        memset(cmd, 0 ,sizeof(cmd));
        if (operationParam->autoChannelEnabled == true) {
            /* Set acsd2 autochannel select mode */
            wifi_hal_dbg_print("%s():%d Enabling autoChannel in radio index %d\n", __FUNCTION__, __LINE__, index);
            sprintf(cmd, "acs_cli2 -i wl%d mode 2 &", index);
            system(cmd);

            /* Run acsd2 autochannel */
            memset(cmd, 0 ,sizeof(cmd));
            sprintf(cmd, "acs_cli2 -i wl%d autochannel &", index);
            system(cmd);
        }
        else {
            /* Set acsd2 disabled mode */
            wifi_hal_dbg_print("%s():%d Disabling autoChannel in radio index %d\n", __FUNCTION__, __LINE__, index);
            sprintf(cmd, "acs_cli2 -i wl%d mode 0 &", index);
            system(cmd);
        }
    }

    snprintf(param_name, sizeof(param_name), "wl%d_reg_mode", index);
    if (operationParam->DfsEnabled) {
        set_string_nvram_param(param_name, "h");
    } else {
        set_string_nvram_param(param_name, "d");
    }

    if (radio->oper_param.DfsEnabled != operationParam->DfsEnabled) {
        /* sometimes spectrum management is not enabled by nvram */
        enable_spect_management(index, operationParam->DfsEnabled);
    }

#if defined(CONFIG_IEEE80211BE) && defined(SCXER10_PORT)
    platform_set_eht(index, (operationParam->variant & WIFI_80211_VARIANT_BE) ? true : false);
#endif

    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    int i, index;
    char param_name[NVRAM_NAME_SIZE];
    char interface_name[8];

    memset(param_name, 0 ,sizeof(param_name));
    memset(interface_name, 0, sizeof(interface_name));

    wifi_hal_info_print("%s:%d: start_wifi_apps\n", __func__, __LINE__);
    system("wifi_setup.sh start_wifi_apps");

    wifi_hal_dbg_print("%s:%d: add wifi interfaces to flow manager\r\n", __func__, __LINE__);
    system("wifi_setup.sh add_ifaces_to_flowmgr");

    if (system("killall -q -9 acsd2 2>/dev/null")) {
        wifi_hal_info_print("%s: system kill acsd2 failed\n", __FUNCTION__);
    }

    if (system("acsd2")) {
        wifi_hal_info_print("%s: system acsd2 failed\n", __FUNCTION__);
    }

#if defined(WLDM_21_2)
    wlcsm_nvram_set("acsd2_started", "1");
#else
    nvram_set("acsd2_started", "1");
#endif // defined(WLDM_21_2)

    wifi_hal_info_print("%s:%d: acsd2_started\r\n", __func__, __LINE__);

    //set runtime configs using wl command.
    set_wl_runtime_configs(vap_map);

    wifi_hal_dbg_print("%s:%d: wifi param set success\r\n", __func__, __LINE__);

    if (vap_map != NULL) {
        for(i = 0; i < g_wifi_hal.num_radios; i++) {
            if (vap_map != NULL) {
                for (index = 0; index < vap_map->num_vaps; index++) {
                    memset(param_name, 0 ,sizeof(param_name));
                    memset(interface_name, 0, sizeof(interface_name));
#if defined(NEWPLATFORM_PORT) || defined(_SR213_PRODUCT_REQ_)
                    get_interface_name_from_vap_index(vap_map->vap_array[index].vap_index, interface_name);
#else
                    get_ccspwifiagent_interface_name_from_vap_index(vap_map->vap_array[index].vap_index, interface_name);
#endif
                    if (vap_map->vap_array[index].vap_mode == wifi_vap_mode_ap) {
                        prepare_param_name(param_name, interface_name, "_bss_maxassoc");
                        set_decimal_nvram_param(param_name, vap_map->vap_array[index].u.bss_info.bssMaxSta);
                        wifi_hal_dbg_print("%s:%d: nvram param name:%s vap_bssMaxSta:%d\r\n", __func__, __LINE__, param_name, vap_map->vap_array[index].u.bss_info.bssMaxSta);
                    }
                }
                vap_map++;
            } else {
                wifi_hal_error_print("%s:%d: vap_map NULL for radio_index:%d\r\n", __func__, __LINE__, i);
            }
        }
    }

    return 0;
}

int nvram_get_radio_enable_status(bool *radio_enable, int radio_index)
{
    char nvram_name[NVRAM_NAME_SIZE];

    snprintf(nvram_name, sizeof(nvram_name), "wl%d_radio", radio_index);
#if defined(WLDM_21_2)
    char *enable = wlcsm_nvram_get(nvram_name);
#else
    char *enable = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)

    *radio_enable = (!enable || *enable == '0') ? FALSE : TRUE;
    wifi_hal_info_print("%s:%d: nvram name:%s, radio enable status:%d for radio index:%d \r\n", __func__, __LINE__, nvram_name, *radio_enable, radio_index);

    return 0;
}


int nvram_get_vap_enable_status(bool *vap_enable, int vap_index)
{
    char interface_name[10];
    char nvram_name[NVRAM_NAME_SIZE];

    memset(interface_name, 0, sizeof(interface_name));
#ifdef NEWPLATFORM_PORT
    get_interface_name_from_vap_index(vap_index, interface_name);
#else
    get_ccspwifiagent_interface_name_from_vap_index(vap_index, interface_name);
#endif

    snprintf(nvram_name, sizeof(nvram_name), "%s_vap_enabled", interface_name);
#if defined(WLDM_21_2)
    char *enable = wlcsm_nvram_get(nvram_name);
#else
    char *enable = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)

    *vap_enable = (!enable || *enable == '0') ? FALSE : TRUE;
    wifi_hal_dbg_print("%s:%d: vap enable status:%d for vap index:%d \r\n", __func__, __LINE__, *vap_enable, vap_index);

    return 0;
}

int nvram_get_current_security_mode(wifi_security_modes_t *security_mode,int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    char *sec_mode_str, *mfp_str;
    wifi_security_modes_t current_security_mode;

    memset(interface_name, 0, sizeof(interface_name));
#ifdef NEWPLATFORM_PORT
    get_interface_name_from_vap_index(vap_index, interface_name);
#else
    get_ccspwifiagent_interface_name_from_vap_index(vap_index, interface_name);
#endif

    snprintf(nvram_name, sizeof(nvram_name), "%s_akm", interface_name);
#if defined(WLDM_21_2)
    sec_mode_str = wlcsm_nvram_get(nvram_name);
#else
    sec_mode_str = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
    if (sec_mode_str == NULL) {
        wifi_hal_error_print("%s:%d nvram sec_mode value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    snprintf(nvram_name, sizeof(nvram_name), "%s_mfp", interface_name);
#if defined(WLDM_21_2)
    mfp_str = wlcsm_nvram_get(nvram_name);
#else
    mfp_str = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
    if (mfp_str == NULL) {
        wifi_hal_error_print("%s:%d nvram mfp value is NULL\r\n", __func__, __LINE__);
        return -1;
    }

    if (get_security_mode_int_from_str(sec_mode_str,mfp_str, &current_security_mode) == 0) {
        *security_mode = current_security_mode;
        return 0;
    }

    return -1;
}

int nvram_get_default_password(char *l_password, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    int len;
    char *key_passphrase;

    memset(interface_name, 0, sizeof(interface_name));
#ifdef NEWPLATFORM_PORT
    get_interface_name_from_vap_index(vap_index, interface_name);
#else
    get_ccspwifiagent_interface_name_from_vap_index(vap_index, interface_name);
#endif
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
    strncpy(l_password, key_passphrase, (len + 1));
    return 0;
}

int nvram_get_default_xhs_password(char *l_password, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    int len;
    char *key_passphrase;

    snprintf(nvram_name, sizeof(nvram_name), "xhs_wpa_psk");
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
    strncpy(l_password, key_passphrase, (len + 1));
    return 0;
}

int platform_get_keypassphrase_default(char *password, int vap_index)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    if(is_wifi_hal_vap_private(vap_index)) {
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
        fp = popen("grep \"WIFIPASSWORD=\" /tmp/serial.txt | cut -d '=' -f 2 | tr -d '\r\n'","r");
#else
        fp = popen("grep \"Default WIFI Password:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif
        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
                strncpy(password,value,strlen(value));
#else
                strncpy(password,value,strlen(value)-1);
#endif
            }
            pclose(fp);
            return 0;
        }
    } else if(is_wifi_hal_vap_xhs(vap_index)) {
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
        return nvram_get_default_xhs_password(password, vap_index);
#else
        return nvram_get_default_password(password, vap_index);
#endif
    } else {
        return nvram_get_default_password(password, vap_index);
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
        wifi_hal_error_print("%s:%d default_radius_key value is NULL\r\n", __func__, __LINE__);
        return -1;
    }
    else {
        strncpy(radius_key, key, (strlen(key) + 1));
    }
    return 0;
}
int platform_get_ssid_default(char *ssid, int vap_index){
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

    if(is_wifi_hal_vap_private(vap_index)) {

#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
        fp = popen("grep \"FACTORYSSID=\" /tmp/serial.txt | cut -d '=' -f2 | tr -d '\r\n'","r");
#else
        fp = popen("grep \"Default 2.4 GHz SSID:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif

        if(fp != NULL) {
            while (fgets(value, sizeof(value), fp) != NULL){
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
                strncpy(ssid,value,strlen(value));
#else
                strncpy(ssid,value,strlen(value)-1);
#endif
            }
            pclose(fp);
            return 0;
        }
    } else if(is_wifi_hal_vap_xhs(vap_index)) {
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
        return nvram_get_default_xhs_ssid(ssid, vap_index);
#else
        return nvram_get_current_ssid(ssid, vap_index);
#endif
    } else {
        return nvram_get_current_ssid(ssid, vap_index);
    }
    return -1;
}

int platform_get_wps_pin_default(char *pin)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
    fp = popen("grep \"WPSPIN=\" /tmp/serial.txt | cut -d '=' -f2 | tr -d '\r\n'","r");
#else
    fp = popen("grep \"Default WPS Pin:\" /tmp/factory_nvram.data | cut -d ':' -f2 | cut -d ' ' -f2","r");
#endif
    if(fp != NULL) {
        while (fgets(value, sizeof(value), fp) != NULL) {
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
            strncpy(pin,value,strlen(value));
#else
            strncpy(pin,value,strlen(value)-1);
#endif
        }
        pclose(fp);
        return 0;
    }
    return -1;
}

int platform_wps_event(wifi_wps_event_t data)
{
    switch(data.event) {
        case WPS_EV_PBC_ACTIVE:
        case WPS_EV_PIN_ACTIVE:
#if defined(_SR213_PRODUCT_REQ_) && defined(FEATURE_RDKB_LED_MANAGER)
            // set led to blinking blue
            system("sysevent set led_event rdkb_wps_start");
            wifi_hal_dbg_print("%s:%d set wps led color to blinking blue \r\n", __func__, __LINE__);
#else
            // set wps led color to blue
            system("led_wps_active 1");
            wifi_hal_dbg_print("%s:%d set wps led color to blue\r\n", __func__, __LINE__);
#endif // defined(_SR213_PRODUCT_REQ_) && defined(FEATURE_RDKB_LED_MANAGER)
            break;

        case WPS_EV_SUCCESS:
        case WPS_EV_PBC_TIMEOUT:
        case WPS_EV_PIN_TIMEOUT:
        case WPS_EV_PIN_DISABLE:
        case WPS_EV_PBC_DISABLE:
#if defined(_SR213_PRODUCT_REQ_) && defined(FEATURE_RDKB_LED_MANAGER)
            system("sysevent set led_event rdkb_wps_stop");
            wifi_hal_dbg_print("%s:%d set wps led color to solid white \r\n", __func__, __LINE__);
#else
            // set wps led color to white
            system("led_wps_active 0");
            wifi_hal_dbg_print("%s:%d set wps led color to white\r\n", __func__, __LINE__);
#endif //defined(_SR213_PRODUCT_REQ_) && defined(FEATURE_RDKB_LED_MANAGER)
            break;

        default:
            wifi_hal_info_print("%s:%d wps event[%d] not handle\r\n", __func__, __LINE__, data.event);
            break;
    }

    return 0;
}

int platform_get_country_code_default(char *code)
{
    char value[BUFFER_LENGTH_WIFIDB] = {0};
    FILE *fp = NULL;

#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
    fp = popen("grep \"REGION=\" /tmp/serial.txt | cut -d '=' -f 2 | tr -d '\r\n'","r");
#else
    fp = popen("cat /data/.customerId", "r");
#endif

    if (fp != NULL) {
        while(fgets(value, sizeof(value), fp) != NULL) {
#if defined(SKYSR300_PORT) || defined(SKYSR213_PORT)
            strncpy(code, value, strlen(value));
#else
            strncpy(code, value, strlen(value)-1);
#endif
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
#ifdef NEWPLATFORM_PORT
    get_interface_name_from_vap_index(vap_index, interface_name);
#else
    get_ccspwifiagent_interface_name_from_vap_index(vap_index, interface_name);
#endif
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
    strncpy(l_ssid, ssid, (len + 1));
    wifi_hal_dbg_print("%s:%d vap[%d] ssid:%s nvram name:%s\r\n", __func__, __LINE__, vap_index, l_ssid, nvram_name);
    return 0;
}

int nvram_get_default_xhs_ssid(char *l_ssid, int vap_index)
{
    char nvram_name[NVRAM_NAME_SIZE];
    int len;
    char *ssid;

    snprintf(nvram_name, sizeof(nvram_name), "xhs_ssid");
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
    strncpy(l_ssid, ssid, (len + 1));
    wifi_hal_dbg_print("%s:%d vap[%d] ssid:%s nvram name:%s\r\n", __func__, __LINE__, vap_index, l_ssid, nvram_name);
    return 0;
}

static int get_control_side_band(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_radio_info_t *radio;
    int sec_chan_offset, freq;
    char country[8];

    radio = get_radio_by_rdk_index(index);
    get_coutry_str_from_code(operationParam->countryCode, country);

    freq = ieee80211_chan_to_freq(country, operationParam->op_class, operationParam->channel);
    sec_chan_offset = get_sec_channel_offset(radio, freq);

    return sec_chan_offset;
}

static char *channel_width_to_string_convert(wifi_channelBandwidth_t channelWidth)
{
    switch(channelWidth)
    {
    case WIFI_CHANNELBANDWIDTH_20MHZ:
        return "20";
    case WIFI_CHANNELBANDWIDTH_40MHZ:
        return "40";
    case WIFI_CHANNELBANDWIDTH_80MHZ:
        return "80";
    case WIFI_CHANNELBANDWIDTH_160MHZ:
        return "160";
#ifdef CONFIG_IEEE80211BE
    case WIFI_CHANNELBANDWIDTH_320MHZ:
        return "320";
#endif /* CONFIG_IEEE80211BE */
    case WIFI_CHANNELBANDWIDTH_80_80MHZ:
    default:
        return NULL;
    }
}

static int get_chanspec_string(wifi_radio_operationParam_t *operationParam, char *chspec, wifi_radio_index_t index)
{
    char *sideband = "";
    char *band = "";
    char *bw = NULL;

    if (operationParam->band != WIFI_FREQUENCY_2_4_BAND) {
        bw = channel_width_to_string_convert(operationParam->channelWidth);
        if (bw == NULL) {
            wifi_hal_error_print("%s:%d: Channel width %d not supported in radio index: %d\n", __func__, __LINE__, operationParam->channelWidth, index);
            return -1;
        }
    }

    if (operationParam->band == WIFI_FREQUENCY_6_BAND) {
        band = "6g";
    }
    if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_20MHZ) {
        sprintf(chspec, "%s%d", band, operationParam->channel);
    }
    else if ((operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ) && (operationParam->band != WIFI_FREQUENCY_6_BAND)) {
        sideband = (get_control_side_band(index, operationParam)) == 1 ? "l" : "u";
        sprintf(chspec, "%d%s", operationParam->channel, sideband);
    }
    else {
        sprintf(chspec, "%s%d/%s", band, operationParam->channel, bw);
    }
    return 0;
}

int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char temp_buff[BUF_SIZE];
    char param_name[NVRAM_NAME_SIZE];
    char chspecbuf[NVRAM_NAME_SIZE];
    memset(chspecbuf, 0 ,sizeof(chspecbuf));
    memset(param_name, 0 ,sizeof(param_name));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, index);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_auto_cha", index);
    set_decimal_nvram_param(param_name, operationParam->autoChannelEnabled);

    if (operationParam->autoChannelEnabled) {
        set_string_nvram_param("acsd_restart", "yes");
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_channel", index);
        set_decimal_nvram_param(param_name, 0);

        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_chanspec", index);
        set_decimal_nvram_param(param_name, 0);
    } else {
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_channel", index);
        set_decimal_nvram_param(param_name, operationParam->channel);

        get_chanspec_string(operationParam, chspecbuf, index);
        memset(param_name, 0 ,sizeof(param_name));
        sprintf(param_name, "wl%d_chanspec", index);
        set_string_nvram_param(param_name, chspecbuf);
    }

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_dtim", index);
    set_decimal_nvram_param(param_name, operationParam->dtimPeriod);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_frag", index);
    set_decimal_nvram_param(param_name, operationParam->fragmentationThreshold);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_nband", index);
    set_decimal_nvram_param(param_name, operationParam->band);

    memset(param_name, 0 ,sizeof(param_name));
    memset(temp_buff, 0 ,sizeof(temp_buff));
    sprintf(param_name, "wl%d_oper_stands", index);
    get_radio_variant_str_from_int(operationParam->variant, temp_buff);
    set_string_nvram_param(param_name, temp_buff);

    memset(param_name, 0 ,sizeof(param_name));
    sprintf(param_name, "wl%d_bcn", index);
    set_decimal_nvram_param(param_name, operationParam->beaconInterval);

    return 0;
}

#if defined(TCXB7_PORT) || defined(TCXB8_PORT)

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

    if (enable) {
        assoc_ctrl = ASSOC_HOSTAP_FULL_CTRL;
    } else if (radio->oper_param.band != WIFI_FREQUENCY_6_BAND &&
        is_wifi_hal_vap_hotspot_open(vap_index) && is_wifi_hal_vap_hotspot_secure(vap_index)) {
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
#endif // TCXB7_PORT || TCXB8_PORT

int platform_create_vap(wifi_radio_index_t r_index, wifi_vap_info_map_t *map)
{
    wifi_hal_dbg_print("%s:%d: Enter radio index:%d\n", __func__, __LINE__, r_index);
    int  index = 0, l_wps_state = 0;
    char temp_buff[256];
    char param_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    wifi_radio_info_t *radio;
    char das_ipaddr[45];
    memset(temp_buff, 0 ,sizeof(temp_buff));
    memset(param_name, 0 ,sizeof(param_name));
    memset(interface_name, 0, sizeof(interface_name));

    for (index = 0; index < map->num_vaps; index++) {

        radio = get_radio_by_rdk_index(r_index);
        if (radio == NULL) {
            wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, r_index);
            return RETURN_ERR;
        }

        memset(interface_name, 0, sizeof(interface_name));
#if defined(NEWPLATFORM_PORT) || defined(_SR213_PRODUCT_REQ_)
        get_interface_name_from_vap_index(map->vap_array[index].vap_index, interface_name);
#else
        get_ccspwifiagent_interface_name_from_vap_index(map->vap_array[index].vap_index, interface_name);
#endif

        prepare_param_name(param_name, interface_name, "_ifname");
        set_string_nvram_param(param_name, interface_name);

        memset(temp_buff, 0 ,sizeof(temp_buff));
        prepare_param_name(param_name, interface_name, "_mode");
        get_vap_mode_str_from_int_mode(map->vap_array[index].vap_mode, temp_buff);
        set_string_nvram_param(param_name, temp_buff);

        prepare_param_name(param_name, interface_name, "_radio");
        set_decimal_nvram_param(param_name, 1);

        if (map->vap_array[index].vap_mode == wifi_vap_mode_ap) {
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
            platform_set_hostap_ctrl(radio, map->vap_array[index].vap_index,
                map->vap_array[index].u.bss_info.hostap_mgt_frame_ctrl);
#endif
            prepare_param_name(param_name, interface_name, "_akm");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_mode_str_from_int(map->vap_array[index].u.bss_info.security.mode, map->vap_array[index].vap_index, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_crypto");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_encryption_mode_str_from_int(map->vap_array[index].u.bss_info.security.encr, map->vap_array[index].vap_index, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_mfp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.mfp);

            prepare_param_name(param_name, interface_name, "_ap_isolate");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.isolation);

            prepare_param_name(param_name, interface_name, "_vap_enabled");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.enabled);

            prepare_param_name(param_name, interface_name, "_closed");
            set_decimal_nvram_param(param_name, !map->vap_array[index].u.bss_info.showSsid);

            prepare_param_name(param_name, interface_name, "_bss_maxassoc");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.bssMaxSta);

            /*
             * RDKB-52611:
             * Call API to populate the 'bssMaxSta' value in driver context (wl) for corresponding VAP index.
             */
            wifi_setApMaxAssociatedDevices(map->vap_array[index].vap_index, map->vap_array[index].u.bss_info.bssMaxSta);

            if (strlen(map->vap_array[index].repurposed_vap_name) == 0) {
                prepare_param_name(param_name, interface_name, "_ssid");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.ssid);
            } else {
                wifi_hal_info_print("%s is repurposed to %s hence not setting in nvram \n",map->vap_array[index].vap_name,map->vap_array[index].repurposed_vap_name);
            }

            memset(temp_buff, 0 ,sizeof(temp_buff));
            prepare_param_name(param_name, interface_name, "_wps_mode");
            if (map->vap_array[index].u.bss_info.wps.enable) {
                strcpy(temp_buff, "enabled");
            } else {
                strcpy(temp_buff, "disabled");
            }
            set_string_nvram_param(param_name, temp_buff);

            prepare_param_name(param_name, interface_name, "_wps_device_pin");
            set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.wps.pin);

            memset(temp_buff, 0 ,sizeof(temp_buff));
            prepare_param_name(param_name, interface_name, "_wps_method_enabled");
            wps_enum_to_string(map->vap_array[index].u.bss_info.wps.methods, temp_buff, sizeof(temp_buff));
            set_string_nvram_param(param_name, temp_buff);

            l_wps_state = map->vap_array[index].u.bss_info.wps.enable ? WPS_STATE_CONFIGURED : 0;
            /* WPS is not supported in 6G */
            if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
                l_wps_state = 0;
            }
            if (l_wps_state && (!map->vap_array[index].u.bss_info.showSsid)) {
                l_wps_state = 0;
            }
            prepare_param_name(param_name, interface_name, "_wps_config_state");
            set_decimal_nvram_param(param_name, l_wps_state);

            if ((get_security_mode_support_radius(map->vap_array[index].u.bss_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index)) {

                prepare_param_name(param_name, interface_name, "_radius_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.port);

                prepare_param_name(param_name, interface_name, "_radius_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.ip);

                prepare_param_name(param_name, interface_name, "_radius_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.key);

                prepare_param_name(param_name, interface_name, "_radius2_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_port);

                prepare_param_name(param_name, interface_name, "_radius2_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_ip);

                prepare_param_name(param_name, interface_name, "_radius2_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.s_key);

                memset(&das_ipaddr, 0, sizeof(das_ipaddr));
                getIpStringFromAdrress(das_ipaddr,&map->vap_array[index].u.bss_info.security.u.radius.dasip);

                prepare_param_name(param_name, interface_name, "_radius_das_client_ipaddr");
                set_string_nvram_param(param_name, das_ipaddr);

                prepare_param_name(param_name, interface_name, "_radius_das_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.daskey);

                prepare_param_name(param_name, interface_name, "_radius_das_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.radius.dasport);
            } else {

                if (strlen(map->vap_array[index].repurposed_vap_name) == 0) {
                    prepare_param_name(param_name, interface_name, "_wpa_psk");
                    set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.security.u.key.key);
                } else {
                    wifi_hal_info_print("%s is repurposed to %s hence not setting in nvram \n",map->vap_array[index].vap_name,map->vap_array[index].repurposed_vap_name);
                }
            }

            prepare_param_name(param_name, interface_name, "_hessid");
            set_string_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.hessid);

            prepare_param_name(param_name, interface_name, "_venuegrp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.venueGroup);

            prepare_param_name(param_name, interface_name, "_venuetype");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.bss_info.interworking.interworking.venueType);
    
            prepare_param_name(param_name, interface_name, "_bcnprs_txpwr_offset");
            set_decimal_nvram_param(param_name, abs(map->vap_array[index].u.bss_info.mgmtPowerControl));

        } else if (map->vap_array[index].vap_mode == wifi_vap_mode_sta) {

            prepare_param_name(param_name, interface_name, "_akm");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_mode_str_from_int(map->vap_array[index].u.sta_info.security.mode, map->vap_array[index].vap_index, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_crypto");
            memset(temp_buff, 0 ,sizeof(temp_buff));
            if (get_security_encryption_mode_str_from_int(map->vap_array[index].u.sta_info.security.encr, map->vap_array[index].vap_index, temp_buff) == RETURN_OK) {
                set_string_nvram_param(param_name, temp_buff);
            }

            prepare_param_name(param_name, interface_name, "_mfp");
            set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.mfp);

            prepare_param_name(param_name, interface_name, "_ssid");
            set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.ssid);


            if ((get_security_mode_support_radius(map->vap_array[index].u.sta_info.security.mode))|| is_wifi_hal_vap_hotspot_open(map->vap_array[index].vap_index)) {

                prepare_param_name(param_name, interface_name, "_radius_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.port);

                prepare_param_name(param_name, interface_name, "_radius_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.ip);

                prepare_param_name(param_name, interface_name, "_radius_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.key);

                prepare_param_name(param_name, interface_name, "_radius2_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_port);

                prepare_param_name(param_name, interface_name, "_radius2_ipaddr");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_ip);

                prepare_param_name(param_name, interface_name, "_radius2_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.s_key);

                memset(&das_ipaddr, 0, sizeof(das_ipaddr));
                getIpStringFromAdrress(das_ipaddr,&map->vap_array[index].u.sta_info.security.u.radius.dasip);

                prepare_param_name(param_name, interface_name, "_radius_das_client_ipaddr");
                set_string_nvram_param(param_name, das_ipaddr);

                prepare_param_name(param_name, interface_name, "_radius_das_key");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.daskey);

                prepare_param_name(param_name, interface_name, "_radius_das_port");
                set_decimal_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.radius.dasport);

            } else {
                prepare_param_name(param_name, interface_name, "_wpa_psk");
                set_string_nvram_param(param_name, map->vap_array[index].u.sta_info.security.u.key.key);
            }
        }
    }

    return 0;
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
#if defined(_SR213_PRODUCT_REQ_)
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
            }else {
#if defined(WLDM_21_2)
                wlcsm_nvram_set(param, "0");
#else
                nvram_set(param, "0");
#endif // defined(WLDM_21_2)
            }
        }else if (vap->vap_mode == wifi_vap_mode_sta) {
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
#endif //defined(_SR213_PRODUCT_REQ_)
    return 0;
}

int wifi_setQamPlus(void *priv)
{
    return 0;
}

int wifi_setApRetrylimit(void *priv)
{
    return 0;
}

int platform_flags_init(int *flags)
{
    *flags = PLATFORM_FLAGS_PROBE_RESP_OFFLOAD | PLATFORM_FLAGS_STA_INACTIVITY_TIMER;
    return 0;
}

int platform_get_aid(void* priv, u16* aid, const u8* addr)
{
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
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
#endif // TCXB7_PORT || TCXB8_PORT
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
    char cmd[32] = {0};
    unsigned int index = 0, value = 0;
    wifi_radio_info_t *radio;
    char buf[2] = {0};
    FILE *fp = NULL;

    wifi_hal_error_print("%s:%d: g_wifi_hal.num_radios %d\n", __func__, __LINE__, g_wifi_hal.num_radios);

    for (index = 0; index < g_wifi_hal.num_radios; index++)
    {
       radio = get_radio_by_rdk_index(index);
       snprintf(cmd, sizeof(cmd), "nvram kget wl%d_dpd", index);
       if ((fp = popen(cmd, "r")) != NULL)
       {
           if (fgets(buf, sizeof(buf), fp) != NULL)
           {
               value = atoi(buf);
               if (1 == value) {
                   radio->radio_presence = false;
               }
               wifi_hal_info_print("%s:%d: Index %d edpd enable %d presence %d\n", __func__, __LINE__, index, value, radio->radio_presence);
           }
           pclose(fp);
       }
    }
    return 0;
}

int platform_get_acl_num(int vap_index, uint *acl_count)
{
    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    char nvram_name[NVRAM_NAME_SIZE];
    char interface_name[8];
    char *str_value;

    if (output_dbm == NULL) {
        wifi_hal_error_print("%s:%d - Null output buffer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(interface_name, 0, sizeof(interface_name));
#ifdef NEWPLATFORM_PORT
    get_interface_name_from_vap_index(vap_index, interface_name);
#else
    get_ccspwifiagent_interface_name_from_vap_index(vap_index, interface_name);
#endif
    snprintf(nvram_name, sizeof(nvram_name), "%s_bcnprs_txpwr_offset", interface_name);
#if defined(WLDM_21_2)
    str_value = wlcsm_nvram_get(nvram_name);
#else
    str_value = nvram_get(nvram_name);
#endif // defined(WLDM_21_2)
    if (str_value == NULL) {
        wifi_hal_error_print("%s:%d nvram %s value is NULL\r\n", __func__, __LINE__, nvram_name);
        return RETURN_ERR;
    }

    *output_dbm = 0 - atoi(str_value);
    wifi_hal_dbg_print("%s:%d - MFPC for VAP %d is %d\n", __func__, __LINE__, vap_index, *output_dbm);
    return RETURN_OK;
}

#if defined(_SR213_PRODUCT_REQ_)

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    // no wl_iovar_getint API
    return RETURN_OK;
}

#endif // _SR213_PRODUCT_REQ_

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) 

static int get_radio_phy_temp_handler(struct nl_msg *msg, void *arg)
{
    int t;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_WIPHY_TEMP] = { .type = NLA_S32 },
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    unsigned int *temp = (unsigned int *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        vendor_policy) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_WIPHY_TEMP] == NULL) {
        wifi_hal_error_print("%s:%d wiphy temp attribute is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    t = nla_get_s32(tb_vendor[RDK_VENDOR_ATTR_WIPHY_TEMP]);
    *temp  = t >= 0 ? t : 0;

    return NL_SKIP;
}

static int get_radio_phy_temp(wifi_interface_info_t *interface, unsigned int *temp)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_WIPHY_TEMP);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_radio_phy_temp_handler, temp, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    radio = get_radio_by_phy_index(index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, index);
        return RETURN_ERR;
    }

    if (get_radio_phy_temp(interface, &radioPhyTemperature->radio_Temperature)) {
        wifi_hal_error_print("%s:%d: Failed to get phy temperature for radio index: %d\n", __func__,
            __LINE__, index);
        return RETURN_ERR;
    }

    wifi_hal_dbg_print("%s:%d: radio index: %d temperature: %u\n", __func__, __LINE__, index,
        radioPhyTemperature->radio_Temperature);

    return RETURN_OK;
}

#elif defined (TCHCBRV2_PORT)

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    char ifname[32];

    snprintf(ifname, sizeof(ifname), "wl%d", index);
    if (wl_iovar_getint(ifname, "phy_tempsense", &radioPhyTemperature->radio_Temperature) < 0) {
        wifi_hal_error_print("%s:%d Failed to get temperature for radio: %d\n", __func__, __LINE__,
            index);
        return RETURN_ERR;
    }
    wifi_hal_dbg_print("%s:%d Temperature is %u\n", __func__, __LINE__, radioPhyTemperature->radio_Temperature);
    return RETURN_OK;
}

#elif defined(SCXER10_PORT)

int platform_get_radio_phytemperature(wifi_radio_index_t index,
    wifi_radioTemperature_t *radioPhyTemperature)
{
    return RETURN_OK;
}

#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT 

#if defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)
/* EDPD - WLAN Power down control support APIs. */
#define GPIO_PIN_24G_RADIO 101
#define GPIO_PIN_5G_RADIO 102
#define GPIO_EXPORT_PATH "/sys/class/gpio/export"
#define GPIO_UNEXPORT_PATH "/sys/class/gpio/unexport"
#define GPIO_DIRECTION_PATH "/sys/class/gpio/gpio%d/direction"
#define GPIO_VALUE_PATH "/sys/class/gpio/gpio%d/value"
#define ECOMODE_SCRIPT_FILE "/etc/init/wifi.sh"
#define GPIO_DIRECTION_OUT "out"
#define BUFLEN_2 2

/**
 * @brief Enable EDPD ECO mode  feature control configuration
 */
static int enable_echo_feature_and_power_control_configs(void)
{
    if (check_edpdctl_enabled() && check_dpd_feature_enabled()) {
        wifi_hal_dbg_print("%s:%d: EDPD feature enabled in CPE\n", __func__, __LINE__);
        return RETURN_OK;
    }

    char cmd[BUFLEN_256] = {0};
    int rc = 0;

    snprintf(cmd, sizeof(cmd), "nvram kset wl_edpdctl_enable=1;nvram kcommit;nvram set wl_edpdctl_enable=1;nvram commit;sync");
    rc = system(cmd);
    if (rc == 0) {
        wifi_hal_dbg_print("%s:%d cmd [%s] successful \n", __func__, __LINE__, cmd);
    } else {
        wifi_hal_dbg_print("%s:%d cmd [%s] unsuccessful \n", __func__, __LINE__, cmd);
    }

    snprintf(cmd, sizeof(cmd), "%s dpden 1", ECOMODE_SCRIPT_FILE);
    rc = system(cmd);
    if (rc == 0) {
        wifi_hal_dbg_print("%s:%d cmd [%s] successful \n", __func__, __LINE__, cmd);
    } else {
        wifi_hal_dbg_print("%s:%d cmd [%s] unsuccessful \n", __func__, __LINE__, cmd);
    }

    return rc;
}

/**
 * @brief API to check DPD feature enabled in CPE.
 *
 * @return int - Return 1 if feature enabled else returns 0.
 */
static int check_dpd_feature_enabled(void)
{
    FILE *fp = NULL;
    int dpd_mode = 0;
    char cmd[BUFLEN_128] = {0};
    char buf[BUFLEN_2] = {0};

    snprintf(cmd, sizeof(cmd), "%s dpden",
             ECOMODE_SCRIPT_FILE);
    if ((fp = popen(cmd, "r")) != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
        {
            dpd_mode = atoi(buf);
        }
        pclose(fp);
    }

    wifi_hal_dbg_print("%s:%d DPD Feature is %s!!! \n", __func__, __LINE__, (dpd_mode ? "enabled" : "disabled"));
    return dpd_mode;
}

/**
 * @brief API to check EDPD control enabled in CPE.
 *
 * @return int - Return 1 if feature enabled else returns 0.
 */
static int check_edpdctl_enabled()
{
    FILE *fp = NULL;
    int edpd_status = 0;
    char cmd[BUFLEN_128] = {0};
    char buf[BUFLEN_2] = {0};

    snprintf(cmd, sizeof(cmd), "nvram kget wl_edpdctl_enable");
    if ((fp = popen(cmd, "r")) != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
        {
            edpd_status = atoi(buf);
        }
        pclose(fp);
    }

    wifi_hal_dbg_print("%s:%d EDPD Power control is %s!!! \n", __func__, __LINE__, (edpd_status ? "enabled" : "disabled"));

    return edpd_status;
}

/**
 * @brief API to export GPIO Pin.
 *
 * @param pin - GPIO pin number
 * @return int - RETURN_OK upon successful, RETURN_ERR upon error
 */
static int export_gpio(const int pin)
{
    int fd = open(GPIO_EXPORT_PATH, O_WRONLY);
    if (fd < 0)
    {
        wifi_hal_error_print("%s:%d  Unable to open GPIO export file", __func__, __LINE__);
        return RETURN_ERR;
    }
    char buffer[BUFLEN_128] = {0};
    int len = snprintf(buffer, sizeof(buffer), "%d", pin);
    if (write(fd, buffer, len) != len)
    {
        wifi_hal_error_print("%s:%d  Unable to export GPIO%d!!! \n", __func__, __LINE__, pin);
        close(fd);
        return RETURN_ERR;
    }
    close(fd);

    wifi_hal_dbg_print("%s:%d Exported GPIO %d!!!\n", __func__, __LINE__, pin);
    return RETURN_OK;
}

/**
 * @brief API to unexport GPIO Pin.
 *
 * @param pin - GPIO pin number
 * @return int - 0 upon successful, -1 upon error
 */
static int unexport_gpio(const int pin)
{
    int fd = open(GPIO_UNEXPORT_PATH, O_WRONLY);
    if (fd < 0)
    {
        wifi_hal_error_print("%s:%d  Unable to open GPIO unexport file \n", __func__, __LINE__);
        return RETURN_ERR;
    }
    char buffer[BUFLEN_128] = {0};
    int len = snprintf(buffer, sizeof(buffer), "%d", pin);
    if (write(fd, buffer, len) != len)
    {
        wifi_hal_error_print("%s:%d  Unable to unexport GPIO%d!!! \n", __func__, __LINE__,pin);
        close(fd);
        return RETURN_ERR;
    }
    close(fd);
    wifi_hal_dbg_print("%s:%d  Unexported GPIO %d!!!\n", __func__, __LINE__, pin);

    return RETURN_OK;
}
/**
 * @brief API to set GPIO Pin direction.
 *
 * @param pin - GPIO pin number
 * @param direction - GPIO direction either "out" or "in"
 * @return int - RETURN_OK upon successful, RETURN_ERR upon error
 */
static int set_gpio_direction(const int pin, const char *direction)
{
    char path[BUFLEN_128] = {0};
    snprintf(path, sizeof(path), GPIO_DIRECTION_PATH, pin);
    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        perror("Unable to open GPIO direction file");
        return RETURN_ERR;
    }
    if (write(fd, direction, strlen(direction)) != (int)strlen(direction))
    {
        wifi_hal_error_print("%s:%d Unable to set GPIO direction \n", __func__, __LINE__);
        close(fd);
        return RETURN_ERR;
    }
    close(fd);
    wifi_hal_dbg_print("%s:%d Set GPIO %d direction to %s. \n", __func__, __LINE__, pin, direction);

    return RETURN_OK;
}

/**
 * @brief API to write value to gpio pin
 *
 * @param pin - GPIO pin number
 * @param value - value could be either 1 or 0
 * @return int - RETURN_OK upon successful, RETURN_ERR upon error
 */
static int write_gpio_value(int pin, int value)
{
    char path[BUFLEN_128] = {0};
    snprintf(path, sizeof(path), GPIO_VALUE_PATH, pin);
    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        perror("Unable to open GPIO value file");
        return RETURN_ERR;
    }
    if (write(fd, value ? "1" : "0", 1) != 1)
    {
        wifi_hal_error_print("%s:%d Unable to write GPIO value \n", __func__, __LINE__);
        close(fd);
        return RETURN_ERR;
    }
    close(fd);
    wifi_hal_dbg_print("%s:%d Write value %d on GPIO %d \n", __func__, __LINE__, value, pin);
    return RETURN_OK;
}

/**
 * @brief Set the gpio configuration for eco mode
 *
 * @description Once we put the board in eco mode, we must need to disconnect
 * power from soc chip from wlan chip. Its using change GPIO configuration.
 * @param wl_idx  - Radio index
 * @param eco_pwr_down - Indicate power down or up radio
 * @return int - 0 on success , -1 on error
 */
int platform_set_gpio_config_for_ecomode(const int wl_idx, const bool eco_pwr_down)
{
    if (!check_edpdctl_enabled() && !check_dpd_feature_enabled())
    {
        wifi_hal_error_print("%s:%d  EDPD Feature control configuration NOT enabled\n", __func__, __LINE__);
        return -1;
    }

    int gpio_pin = (wl_idx == 0) ? GPIO_PIN_24G_RADIO : GPIO_PIN_5G_RADIO;
    int value = (eco_pwr_down) ? 1 : 0;
    int rc = 0;

    rc = export_gpio(gpio_pin);
    if (rc != RETURN_OK)
    {
        wifi_hal_error_print("%s:%d Failed to export gpio %d \n", __func__, __LINE__, gpio_pin);
        goto EXIT;
    }

    rc = set_gpio_direction(gpio_pin, GPIO_DIRECTION_OUT);
    if (rc != RETURN_OK)
    {
        wifi_hal_dbg_print("%s:%d Failed to set direction for gpio %d \n", __func__, __LINE__, gpio_pin);
        goto EXIT;
    }

    rc = write_gpio_value(gpio_pin, value);
    if (rc != RETURN_OK)
    {
        wifi_hal_error_print("%s:%d Failed to set value for gpio %d \n", __func__, __LINE__, gpio_pin);
        goto EXIT;
    }

    unexport_gpio(gpio_pin);

    wifi_hal_dbg_print("%s:%d For wl%d, configured the gpio to %s the PCIe interface \n", __func__, __LINE__, wl_idx, (eco_pwr_down ? "power down" : "power up"));
EXIT:
    return rc;
}

/**
 * @brief Set the ecomode for radio object
 *
 * @description To make enable or disable eco mode, we are using broadcom
 * single control wifi.sh script.
 * @param wl_idx  - Radio index
 * @param eco_pwr_down - Indicate power down or up radio
 * @return int - 0 on success , -1 on error
 */
int platform_set_ecomode_for_radio(const int wl_idx, const bool eco_pwr_down)
{
    if (!check_edpdctl_enabled() && !check_dpd_feature_enabled())
    {
        wifi_hal_error_print("%s:%d  EDPD Feature control configuration NOT enabled\n", __func__, __LINE__);
        return -1;
    }

    char cmd[BUFLEN_128] = {0};
    int rc = 0;

    /* Put radio into eco mode (power down) */
    if (eco_pwr_down)
        snprintf(cmd, sizeof(cmd), "sh %s edpddn wl%d",
                 ECOMODE_SCRIPT_FILE, wl_idx);
    else
        snprintf(cmd, sizeof(cmd), "sh %s edpdup wl%d",
                 ECOMODE_SCRIPT_FILE, wl_idx);

    rc = system(cmd);
    if (rc == 0)
    {
        wifi_hal_dbg_print("%s:%d cmd [%s] successful \n", __func__, __LINE__, cmd);
    }
    else
    {
        wifi_hal_error_print("%s:%d cmd [%s] unsuccessful \n", __func__, __LINE__, cmd);
    }

    return rc;
}
#endif // defined (ENABLED_EDPD) && defined(_SR213_PRODUCT_REQ_)

int platform_set_txpower(void* priv, uint txpower)
{
    return 0;
}

int platform_set_offload_mode(void* priv, uint offload_mode)
{
    return RETURN_OK;
}

int platform_set_neighbor_report(uint index, uint add, mac_address_t mac)
{
    wifi_hal_info_print("%s:%d Enter %d\n", __func__, __LINE__,index);
    wifi_NeighborReport_t nbr_report;
    memcpy(nbr_report.bssid,mac,sizeof(mac_address_t));
    wifi_setNeighborReports(index,add, &nbr_report);

    return 0;
}
#if defined (_SR213_PRODUCT_REQ_)
#define SKY_VENDOR_OUI "DD0480721502"
int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    if (NULL == vendor_oui) {
        wifi_hal_error_print("%s:%d  Invalid parameter \n", __func__, __LINE__);
        return -1;
    }
    strncpy(vendor_oui, SKY_VENDOR_OUI, vendor_oui_len - 1);

    return 0;
}
#else
int platform_get_vendor_oui(char *vendor_oui, int vendor_oui_len)
{
    return -1;
}
#endif /*_SR213_PRODUCT_REQ_ */

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) 

typedef struct sta_list {
    mac_address_t *macs;
    unsigned int num;
} sta_list_t;

static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
    int rem_mac, i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy sta_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY },
        [RDK_VENDOR_ATTR_STA_NUM] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_LIST] = { .type = NLA_NESTED },
    };
    sta_list_t *sta_list = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        sta_policy) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_STA_NUM] == NULL) {
        wifi_hal_error_print("%s:%d STA number data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    sta_list->num = nla_get_u32(tb_vendor[RDK_VENDOR_ATTR_STA_NUM]);
    if (sta_list->num == 0) {
        sta_list->macs = NULL;
        return NL_SKIP;
    }

    sta_list->macs = calloc(sta_list->num, sizeof(mac_address_t));

    if (tb_vendor[RDK_VENDOR_ATTR_STA_LIST] == NULL) {
        wifi_hal_error_print("%s:%d STA list data is missing\n", __func__, __LINE__);
        goto error;
    }

    i = 0;
    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_STA_LIST], rem_mac) {
        if (i >= sta_list->num) {
            wifi_hal_error_print("%s:%d STA list overflow\n", __func__, __LINE__);
            goto error;
        }

        if (nla_len(nlattr) != sizeof(mac_address_t)) {
            wifi_hal_error_print("%s:%d Wrong MAC address len\n", __func__, __LINE__);
            goto error;
        }

        memcpy(sta_list->macs[i], nla_data(nlattr), sizeof(mac_address_t));

        i++;
    }

    if (i != sta_list->num) {
        wifi_hal_error_print("%s:%d Failed to receive all stations\n", __func__, __LINE__);
        goto error;
    }

    return NL_SKIP;

error:
    free(sta_list->macs);
    sta_list->macs = NULL;
    sta_list->num = 0;
    return NL_SKIP;
}

static int get_sta_list(wifi_interface_info_t *interface, sta_list_t *sta_list)
{
    int ret;
    struct nl_msg *msg;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION_LIST);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_sta_list_handler, sta_list, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int standard_to_str(uint32_t standard, char *buf, size_t buf_size)
{
    char *std_str;

    switch (standard) {
        case RDK_VENDOR_NL80211_STANDARD_A: std_str = "a"; break;
        case RDK_VENDOR_NL80211_STANDARD_B: std_str = "b"; break;
        case RDK_VENDOR_NL80211_STANDARD_G: std_str = "g"; break;
        case RDK_VENDOR_NL80211_STANDARD_N: std_str = "n"; break;
        case RDK_VENDOR_NL80211_STANDARD_AC: std_str = "ac"; break;
        case RDK_VENDOR_NL80211_STANDARD_AD: std_str = "ad"; break;
        case RDK_VENDOR_NL80211_STANDARD_AX: std_str = "ax"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_STANDARD_BE: std_str = "be"; break;
#endif /* CONFIG_IEEE80211BE */
        default: std_str = ""; break;
    }

    strncpy(buf, std_str, buf_size - 1);

    return 0;
}

static int bw_to_str(uint8_t bw, char *buf, size_t buf_size)
{
    char *bw_str;

    switch (bw) {
        case RDK_VENDOR_NL80211_CHAN_WIDTH_20: bw_str = "20"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_40: bw_str = "40"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_80: bw_str = "80"; break;
        case RDK_VENDOR_NL80211_CHAN_WIDTH_160: bw_str = "160"; break;
#ifdef CONFIG_IEEE80211BE
        case RDK_VENDOR_NL80211_CHAN_WIDTH_320: bw_str = "320"; break;
#endif /* CONFIG_IEEE80211BE */
        default: bw_str = ""; break;
    }

    strncpy(buf, bw_str, buf_size - 1);

    return 0;
}

static int get_sta_stats_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nl80211_sta_flag_update *sta_flags;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_MAC] = { .type = NLA_BINARY, .minlen = ETHER_ADDR_LEN },
        [RDK_VENDOR_ATTR_STA_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy sta_info_policy[RDK_VENDOR_ATTR_STA_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS] = { .type = NLA_BINARY,
            .minlen = sizeof(struct nl80211_sta_flag_update) },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_ACTIVE] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_SNR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES] = {.type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS] = {. type = NLA_U64 },
        [RDK_VENDOR_ATTR_STA_INFO_MLD_MAC] = {.type = NLA_BINARY, .minlen = ETHER_ADDR_LEN},
        [RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB] = {.type = NLA_U8},
    };
    wifi_associated_dev3_t *stats = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        vendor_policy) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_MAX; i++) {
        if (vendor_policy[i].type != 0 && tb_vendor[i] == NULL) {
            wifi_hal_error_print("%s:%d Vendor attribute %d is missing\n", __func__,
                __LINE__, i);
            return NL_SKIP;
        }
    }

    memcpy(stats->cli_MACAddress, nla_data(tb_vendor[RDK_VENDOR_ATTR_MAC]),
        nla_len(tb_vendor[RDK_VENDOR_ATTR_MAC]));

    if (nla_parse_nested(tb_sta_info, RDK_VENDOR_ATTR_STA_INFO_MAX,
        tb_vendor[RDK_VENDOR_ATTR_STA_INFO], sta_info_policy)) {
        wifi_hal_error_print("%s:%d Failed to parse sta info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]) {
        sta_flags = nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS]);
        stats->cli_AuthenticationState = sta_flags->mask & (1 << NL80211_STA_FLAG_AUTHORIZED) &&
            sta_flags->set & (1 << NL80211_STA_FLAG_AUTHORIZED);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]) {
        stats->cli_LastDataUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]) {
        stats->cli_LastDataDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]) {
        stats->cli_RSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG]);
        stats->cli_SignalStrength = stats->cli_RSSI;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]) {
        stats->cli_MinRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MIN]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]) {
        stats->cli_MaxRSSI = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SIGNAL_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]) {
        stats->cli_Retransmissions =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]) {
        stats->cli_Active = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ACTIVE]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]) {
        standard_to_str(nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD]),
            stats->cli_OperatingStandard, sizeof(stats->cli_OperatingStandard));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]) {
        bw_to_str(nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW]),
            stats->cli_OperatingChannelBandwidth, sizeof(stats->cli_OperatingChannelBandwidth));
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]) {
        stats->cli_SNR = nla_get_s32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SNR]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]) {
        stats->cli_DataFramesSentAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]) {
        stats->cli_DataFramesSentNoAck =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_NO_ACK]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]) {
        stats->cli_BytesSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]) {
        stats->cli_BytesReceived = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]) {
        stats->cli_AuthenticationFailures =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_AUTH_FAILS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]) {
        stats->cli_Associations = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]) {
        stats->cli_PacketsSent = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]) {
        stats->cli_PacketsReceived =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]) {
        stats->cli_ErrorsSent =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]) {
        stats->cli_RetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRANSMIT]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]) {
        stats->cli_FailedRetransCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]) {
        stats->cli_RetryCount = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]) {
        stats->cli_MultipleRetryCount =
            nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_MULT_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]) {
        stats->cli_MaxDownlinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]) {
        stats->cli_MaxUplinkRate =
            nla_get_u32(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]) {
        stats->cli_activeNumSpatialStreams =
            nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]) {
        stats->cli_TxFrames = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]) {
        stats->cli_RxRetries = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES]);
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]) {
        stats->cli_RxErrors = nla_get_u64(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS]);
    }

    if(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]) {
        stats->cli_MLDEnable = nla_get_u8(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_ENAB]);
    } else {
        stats->cli_MLDEnable = 0;
    }

    if (tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]) {
        memcpy(stats->cli_MLDAddr, nla_data(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]),
               nla_len(tb_sta_info[RDK_VENDOR_ATTR_STA_INFO_MLD_MAC]));
    } else {
        memset(stats->cli_MLDAddr, 0, sizeof(stats->cli_MLDAddr));
    }

    wifi_hal_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
           stats->cli_PacketsSent, stats->cli_BytesSent);

    /*
     * Assume the default packet size for wifi blaster is 1470
     * Sometimes when the AP is just up, the cli_BytesSent
     * is very low as just a couple of frames have been sent and not real data.
     * In this case (cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE)
     * will be 1 or 2 or another low value which is in fact lower than
     * cli_PacketsSent.
     */

    stats->cli_DataFramesSentNoAck = stats->cli_FailedRetransCount;
    if (((stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) < stats->cli_PacketsSent)) {
        stats->cli_DataFramesSentAck = stats->cli_PacketsSent - stats->cli_DataFramesSentNoAck;
    } else {
        stats->cli_DataFramesSentAck = (stats->cli_BytesSent / WIFI_BLASTER_DEFAULT_PKTSIZE) -
                          stats->cli_DataFramesSentNoAck;
    }
    stats->cli_PacketsSent = stats->cli_DataFramesSentAck + stats->cli_DataFramesSentNoAck;

    wifi_hal_dbg_print("%s:%d cli_DataFramesSentAck: %lu cli_DataFramesSentNoAck: %lu cli_PacketsSent: %lu cli_BytesSent: %lu\n", __func__, __LINE__, 
            stats->cli_DataFramesSentAck, stats->cli_DataFramesSentNoAck,
            stats->cli_PacketsSent, stats->cli_BytesSent);

    return NL_SKIP;
}

static int get_sta_stats(wifi_interface_info_t *interface, mac_address_t mac,
    wifi_associated_dev3_t *stats)
{
    struct nl_msg *msg;
    struct nlattr *nlattr;
    int ret = RETURN_ERR;

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_STATION);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    nlattr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put(msg, RDK_VENDOR_ATTR_MAC, ETHER_ADDR_LEN, mac) < 0) {
        wifi_hal_error_print("%s:%d Failed to put mac address\n", __func__, __LINE__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }
    nla_nest_end(msg, nlattr);

    ret = nl80211_send_and_recv(msg, get_sta_stats_handler, stats, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return ret;
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
        wifi_hal_error_print("%s:%d Failed to get interface for index %d\n", __func__, __LINE__,
            apIndex);
        return RETURN_ERR;
    }

    ret = get_sta_list(interface, &sta_list);
    if (ret != RETURN_OK) {
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

static int get_channel_stats_handler(struct nl_msg *msg, void *arg)
{
    int i, rem;
    unsigned int freq;
    unsigned char channel;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1];
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy survey_policy[RDK_VENDOR_ATTR_SURVEY_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL] = { .type = NLA_U8 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY] = { .type = NLA_U64 },
    };
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    channel_stats_arr_t *stats = (channel_stats_arr_t *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
        NULL) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
        vendor_policy) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO] == NULL) {
        wifi_hal_error_print("%s:%d Survey info attribute is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nla_for_each_nested(nlattr, tb_vendor[RDK_VENDOR_ATTR_SURVEY_INFO], rem) {

        if (nla_parse(survey_info, RDK_VENDOR_ATTR_SURVEY_INFO_MAX, nla_data(nlattr),
            nla_len(nlattr), survey_policy)) {
            wifi_hal_error_print("%s:%d: Failed to parse survey info attibutes\n", __func__,
                __LINE__);
            return NL_SKIP;
        }

        for (i = 0; i <= RDK_VENDOR_ATTR_SURVEY_INFO_MAX; i++) {
            if (survey_policy[i].type != 0 && survey_info[i] == NULL) {
                wifi_hal_error_print("%s:%d Survey info attribute %d is missing\n", __func__,
                    __LINE__, i);
                return NL_SKIP;
            }
        }

        freq = nla_get_u32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY]);
        if (ieee80211_freq_to_chan(freq, &channel) == NUM_HOSTAPD_MODES) {
            wifi_hal_error_print("%s:%d Failed to convert frequency %u to channel\n", __func__,
                __LINE__, freq);
            return NL_SKIP;
        }

        for (i = 0; i < stats->arr_size && stats->arr[i].ch_number != channel; i++);
        if (i == stats->arr_size) {
            continue;
        }

        stats->arr[i].ch_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NOISE]);
        stats->arr[i].ch_radar_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE]);
        stats->arr[i].ch_max_80211_rssi =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI]);
        stats->arr[i].ch_non_80211_noise =
            nla_get_s32(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE]);
        stats->arr[i].ch_utilization =
            nla_get_u8(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL]);
        stats->arr[i].ch_utilization_total =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE]);
        stats->arr[i].ch_utilization_busy =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY]);
        stats->arr[i].ch_utilization_busy_tx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX]);
        stats->arr[i].ch_utilization_busy_rx =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX]);
        stats->arr[i].ch_utilization_busy_self =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF]);
        stats->arr[i].ch_utilization_busy_ext =
            nla_get_u64(survey_info[RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY]);
    }

    return NL_SKIP;
}

static int get_channel_stats(wifi_interface_info_t *interface,
    wifi_channelStats_t *channel_stats_arr, int channel_stats_arr_size)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;
    channel_stats_arr_t stats = { .arr = channel_stats_arr, .arr_size = channel_stats_arr_size };

    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_SURVEY);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, get_channel_stats_handler, &stats, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioChannelStats(INT radioIndex, wifi_channelStats_t *input_output_channelStats_array,
    INT array_size)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_dbg_print("%s:%d: Get radio stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (get_channel_stats(interface, input_output_channelStats_array, array_size)) {
        wifi_hal_error_print("%s:%d: Failed to get channel stats for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static int get_radio_diag_handler(struct nl_msg *msg, void *arg)
{
    int i;
    struct nlattr *nlattr;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *tb_vendor[RDK_VENDOR_ATTR_MAX + 1];
    struct nlattr *tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy vendor_policy[RDK_VENDOR_ATTR_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO] = { .type = NLA_NESTED },
    };
    static struct nla_policy radio_diag_policy[RDK_VENDOR_ATTR_RADIO_INFO_MAX + 1] = {
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION] = { .type = NLA_U64 },
        [RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR] = { .type = NLA_S32 },
        [RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME] = { .type = NLA_U64 },
    };
    wifi_radioTrafficStats2_t *radioTrafficStats = arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) <
        0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_VENDOR_DATA] == NULL) {
        wifi_hal_error_print("%s:%d Vendor data is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    nlattr = tb[NL80211_ATTR_VENDOR_DATA];
    if (nla_parse(tb_vendor, RDK_VENDOR_ATTR_MAX, nla_data(nlattr), nla_len(nlattr),
            vendor_policy) < 0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_MAX; i++) {
        if (vendor_policy[i].type != 0 && tb_vendor[i] == NULL) {
            wifi_hal_error_print("%s:%d Vendor attribute %d is missing\n", __func__, __LINE__, i);
            return NL_SKIP;
        }
    }

    if (nla_parse_nested(tb_radio_info, RDK_VENDOR_ATTR_STA_INFO_MAX,
            tb_vendor[RDK_VENDOR_ATTR_RADIO_INFO], radio_diag_policy)) {
        wifi_hal_error_print("%s:%d Failed to parse radio info attribute\n", __func__, __LINE__);
        return NL_SKIP;
    }

    for (i = 0; i <= RDK_VENDOR_ATTR_RADIO_INFO_MAX; i++) {
        if (radio_diag_policy[i].type != 0 && tb_radio_info[i] == NULL) {
            wifi_hal_error_print("%s:%d radio info attribute %d is missing\n", __func__, __LINE__,
                i);
            return NL_SKIP;
        }
    }

    radioTrafficStats->radio_BytesSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT]);
    radioTrafficStats->radio_BytesReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED]);
    radioTrafficStats->radio_PacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT]);
    radioTrafficStats->radio_PacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED]);
    radioTrafficStats->radio_ErrorsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT]);
    radioTrafficStats->radio_ErrorsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED]);
    radioTrafficStats->radio_DiscardPacketsSent = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT]);
    radioTrafficStats->radio_DiscardPacketsReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED]);
    radioTrafficStats->radio_PLCPErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT]);
    radioTrafficStats->radio_FCSErrorCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT]);
    radioTrafficStats->radio_InvalidMACCount = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT]);
    radioTrafficStats->radio_PacketsOtherReceived = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED]);
    radioTrafficStats->radio_NoiseFloor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR]);
    radioTrafficStats->radio_ChannelUtilization = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION]);
    radioTrafficStats->radio_ActivityFactor = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR]);
    radioTrafficStats->radio_CarrierSenseThreshold_Exceeded = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD]);
    radioTrafficStats->radio_RetransmissionMetirc = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION]);
    radioTrafficStats->radio_MaximumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR]);
    radioTrafficStats->radio_MinimumNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR]);
    radioTrafficStats->radio_MedianNoiseFloorOnChannel = nla_get_s32(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR]);
    radioTrafficStats->radio_StatisticsStartTime = nla_get_u64(
        tb_radio_info[RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME]);

    wifi_hal_dbg_print(
        "%s:%d radio_BytesSent %lu radio_BytesReceived %lu radio_PacketsSent %lu "
        "radio_PacketsReceived %lu radio_ErrorsSent %lu radio_ErrorsReceived %lu "
        "radio_DiscardPacketsSent %lu radio_DiscardPacketsReceived %lu radio_PLCPErrorCount %lu "
        "radio_FCSErrorCount %lu radio_InvalidMACCount %lu radio_PacketsOtherReceived %lu "
        "radio_NoiseFloor %d radio_ChannelUtilization %lu radio_ActivityFactor %d "
        "radio_CarrierSenseThreshold_Exceeded %d radio_RetransmissionMetirc %d, "
        "radio_MaximumNoiseFloorOnChannel %d radio_MinimumNoiseFloorOnChannel %d "
        "radio_MedianNoiseFloorOnChannel %d radio_StatisticsStartTime %lu",
        __func__, __LINE__, radioTrafficStats->radio_BytesSent,
        radioTrafficStats->radio_BytesReceived, radioTrafficStats->radio_PacketsSent,
        radioTrafficStats->radio_PacketsReceived, radioTrafficStats->radio_ErrorsSent,
        radioTrafficStats->radio_ErrorsReceived, radioTrafficStats->radio_DiscardPacketsSent,
        radioTrafficStats->radio_DiscardPacketsReceived, radioTrafficStats->radio_PLCPErrorCount,
        radioTrafficStats->radio_FCSErrorCount, radioTrafficStats->radio_InvalidMACCount,
        radioTrafficStats->radio_PacketsOtherReceived, radioTrafficStats->radio_NoiseFloor,
        radioTrafficStats->radio_ChannelUtilization, radioTrafficStats->radio_ActivityFactor,
        radioTrafficStats->radio_CarrierSenseThreshold_Exceeded,
        radioTrafficStats->radio_RetransmissionMetirc,
        radioTrafficStats->radio_MaximumNoiseFloorOnChannel,
        radioTrafficStats->radio_MinimumNoiseFloorOnChannel,
        radioTrafficStats->radio_MedianNoiseFloorOnChannel,
        radioTrafficStats->radio_StatisticsStartTime);
    return NL_SKIP;
}

static int get_radio_diagnostics(wifi_interface_info_t *interface,
    wifi_radioTrafficStats2_t *radioTrafficStats)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    wifi_hal_dbg_print("%s:%d Entering\n", __func__, __LINE__);
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_GET_RADIO_INFO);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ret = nl80211_send_and_recv(msg, get_radio_diag_handler, radioTrafficStats, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *radioTrafficStats)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;

    wifi_hal_dbg_print("%s:%d: Get radio traffic stats for index: %d\n", __func__, __LINE__,
        radioIndex);

    radio = get_radio_by_rdk_index(radioIndex);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get radio for index: %d\n", __func__, __LINE__,
            radioIndex);
        return RETURN_ERR;
    }

    interface = get_primary_interface(radio);
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to get interface for radio index: %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (get_radio_diagnostics(interface, radioTrafficStats)) {
        wifi_hal_error_print("%s:%d: Failed to get radio diagnostics stats for radio index: %d\n",
            __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT

int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    wifi_hal_info_print("%s:%d DfsEnabled:%u \n", __func__, __LINE__, operationParam->DfsEnabled);
    if (wifi_setRadioDfsEnable(index, operationParam->DfsEnabled) != RETURN_OK) {
        wifi_hal_error_print("%s:%d RadioDfsEnable Failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (wifi_applyRadioSettings(index) != RETURN_OK) {
        wifi_hal_error_print("%s:%d applyRadioSettings Failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)

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
    static const u8 ext_cap[] = { 0x85, 0x00, 0x08, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40,
        0x20 };
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0xff, 0xff };
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x1b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT
#if defined(TCXB7_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x22, 0x20, 0x02, 0xc0, 0x0f, 0x03, 0x95,
        0x18, 0x00, 0xcc, 0x00 };
#endif // TCXB7_PORT
#if defined(TCXB8_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x22, 0x20, 0x02, 0xc0, 0x02, 0x03, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#endif // TCXB8_PORT
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

#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
#endif // TCXB7_PORT || TCXB8_PORT

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
        }
    }
}

static void platform_get_radio_caps_5g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    static const u8 ext_cap[] = { 0x84, 0x00, 0x08, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40,
        0x20 };
    static const u8 ht_mcs[16] = { 0xff, 0xff, 0xff, 0xff };
    static const u8 vht_mcs[8] = { 0xaa, 0xff, 0x00, 0x00, 0xaa, 0xff, 0x00, 0x20 };
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff, 0xaa, 0xff, 0xaa,
        0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x7b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
        0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT
#if defined(TCXB7_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x6f, 0x1b, 0x95,
        0x18, 0x00, 0xcc, 0x00 };
#endif // TCXB7_PORT
#if defined(TCXB8_PORT)
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x02, 0x1b, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
#endif // TCXB8_PORT
    struct hostapd_iface *iface = &interface->u.ap.iface;

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
#if defined(TCXB7_PORT)
        iface->hw_features[i].vht_capab = 0x0f8b69b5;
#else
        iface->hw_features[i].vht_capab = 0x0f8b69b6;
#endif
        memcpy(iface->hw_features[i].vht_mcs_set, vht_mcs, sizeof(vht_mcs));

#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
#endif

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

static void platform_get_radio_caps_6g(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    static const u8 ext_cap[] = { 0x84, 0x00, 0x48, 0x02, 0x01, 0x00, 0x00, 0x40, 0x00, 0x40,
        0x21 };
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
    static const u8 he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = { 0x05, 0x00, 0x18, 0x12, 0x00, 0x10 };
    static const u8 he_phy_cap[HE_MAX_PHY_CAPAB_SIZE] = { 0x4c, 0x20, 0x02, 0xc0, 0x02, 0x1b, 0x95,
        0x00, 0x00, 0xcc, 0x00 };
    static const u8 he_mcs[HE_MAX_MCS_CAPAB_SIZE] = { 0xaa, 0xff, 0xaa, 0xff, 0xaa, 0xff, 0xaa,
        0xff };
    static const u8 he_ppet[HE_MAX_PPET_CAPAB_SIZE] = { 0x7b, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71,
        0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71 };
#endif // TCXB7_PORT || TCXB8_PORT
    struct hostapd_iface *iface = &interface->u.ap.iface;

    free(radio->driver_data.extended_capa);
    radio->driver_data.extended_capa = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa, ext_cap, sizeof(ext_cap));
    free(radio->driver_data.extended_capa_mask);
    radio->driver_data.extended_capa_mask = malloc(sizeof(ext_cap));
    memcpy(radio->driver_data.extended_capa_mask, ext_cap, sizeof(ext_cap));
    radio->driver_data.extended_capa_len = sizeof(ext_cap);

    // MBSSID is not supported
    radio->driver_data.extended_capa[WLAN_EXT_CAPAB_MULTIPLE_BSSID / 8] &=
        ~(1 << (WLAN_EXT_CAPAB_MULTIPLE_BSSID % 8));

    for (int i = 0; i < iface->num_hw_features; i++) {
#if defined(TCXB7_PORT) || defined(TCXB8_PORT)
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mac_cap, he_mac_cap,
            sizeof(he_mac_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].phy_cap, he_phy_cap,
            sizeof(he_phy_cap));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].mcs, he_mcs, sizeof(he_mcs));
        memcpy(iface->hw_features[i].he_capab[IEEE80211_MODE_AP].ppet, he_ppet, sizeof(he_ppet));
        iface->hw_features[i].he_capab[IEEE80211_MODE_AP].he_6ghz_capa = 0x06bd;
#endif // TCXB7_PORT || TCXB8_PORT

        for (int ch = 0; ch < iface->hw_features[i].num_channels; ch++) {
            iface->hw_features[i].channels[ch].max_tx_power = 30; // dBm
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

#ifdef CONFIG_IEEE80211BE
        radio->driver_data.capa.flags2 |= WPA_DRIVER_FLAGS2_MLO;
#endif /* CONFIG_IEEE80211BE */

    for (interface = hash_map_get_first(radio->interface_map); interface != NULL;
        interface = hash_map_get_next(radio->interface_map, interface)) {

        if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
            continue;
        }

        platform_get_radio_caps_common(radio, interface);

        if (strstr(interface->vap_info.vap_name, "2g")) {
            platform_get_radio_caps_2g(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "5g")) {
            platform_get_radio_caps_5g(radio, interface);
        } else if (strstr(interface->vap_info.vap_name, "6g")) {
            platform_get_radio_caps_6g(radio, interface);
        }
    }

    return RETURN_OK;
}

#else

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return RETURN_OK;
}
#endif // TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
static bool platform_radio_state(wifi_radio_index_t index)
{
    FILE *fp;
    char radio_state[4] = {'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d isup", index);
    if (fp) {
        fgets(radio_state, sizeof(radio_state), fp);
        v_secure_pclose(fp);
    }
    return (radio_state[0] == '1') ? true : false;
}

static bool platform_is_eht_enabled(wifi_radio_index_t index)
{
    FILE *fp;
    char eht[16]={'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d eht", index);
    if (fp) {
        fgets(eht, sizeof(eht), fp);
        v_secure_pclose(fp);
    }
    return (eht[0] == '1') ? true : false;
}

static void platform_set_eht_hal_callback(wifi_interface_info_t *interface)
{
    wifi_hal_dbg_print("%s:%d EHT completed for %s\n", __func__, __LINE__, interface->name);
    l_eht_set = true;
}

static void platform_wait_for_eht(void)
{
    int i;

    usleep(200*1000);
    for (i = 0; i < 32; i++) {
        if (l_eht_set) {
            return;
        }
        usleep(25*1000);
    }
    return;
}

static void platform_set_eht(wifi_radio_index_t index, bool enable)
{
    bool eht_enabled;
    bool radio_up;

    eht_enabled = platform_is_eht_enabled(index);
    if (eht_enabled == enable) {
        return;
    }

    radio_up = platform_radio_state(index);
    if (radio_up) {
        v_secure_system("wl -i wl%d down", index);
    }
    v_secure_system("wl -i wl%d eht %d", index, (enable) ? 1 : 0);
    wifi_hal_dbg_print("%s: wl%d eht changed to %d\n", __func__, index, (enable == true) ? 1 : 0);
    if (radio_up) {
        l_eht_set = false;
        g_eht_oneshot_notify = platform_set_eht_hal_callback;
        v_secure_system("wl -i wl%d up", index);
        platform_wait_for_eht();
    }

    g_eht_oneshot_notify = NULL;

    return;
}

#if defined(KERNEL_NO_320MHZ_SUPPORT)
static void platform_get_current_chanspec(char *ifname, char *cur_chanspec, size_t size)
{
     FILE *fp = NULL;

    fp = (FILE *)v_secure_popen("r", "wl -i %s chanspec", ifname);
    if (fp) {
        fgets(cur_chanspec, size, fp);
        cur_chanspec[strlen(cur_chanspec)-1] = '\0';
        v_secure_pclose(fp);
    } else {
        cur_chanspec[0] = '\0';
    }
}

static bool platform_is_same_chanspec(wifi_radio_index_t index, char *new_chanspec)
{
    char cur_chanspec[32] = {'\0'};
    FILE *fp = NULL;

    fp = (FILE *)v_secure_popen("r", "wl -i wl%d chanspec", index);
    if (fp) {
        fgets(cur_chanspec, sizeof(cur_chanspec), fp);
        cur_chanspec[strlen(cur_chanspec)-1] = '\0';
        v_secure_pclose(fp);
    }

    wifi_hal_dbg_print("%s - current wl%d chanspec=%s,  new chanspec=%s\n", __func__, index, cur_chanspec, new_chanspec);
    return (!strncmp(cur_chanspec, new_chanspec, strlen(new_chanspec))) ? true : false;
}

static void platform_csa_to_chanspec(struct csa_settings *settings, char *chspec)
{
    char *band = "";

    if ((settings->freq_params.freq >= MIN_FREQ_MHZ_6G) && (settings->freq_params.freq <= MAX_FREQ_MHZ_6G)) {
        band = "6g";
    }

    if (settings->freq_params.bandwidth == 20) {
        sprintf(chspec, "%s%d", band, settings->freq_params.channel);
    } else if ((settings->freq_params.bandwidth == 40) && (settings->freq_params.freq < MIN_FREQ_MHZ_6G)) {
        sprintf(chspec, "%d%c", settings->freq_params.channel, (settings->freq_params.sec_channel_offset == 1) ? 'l' : 'u');
    } else {
        sprintf(chspec, "%s%d/%d", band, settings->freq_params.channel, settings->freq_params.bandwidth);
    }
}

static enum nl80211_chan_width bandwidth_str_to_nl80211_width(char *bandwidth)
{
    enum nl80211_chan_width width;

    if (!strncmp(bandwidth, "40", 2)) {
        width = NL80211_CHAN_WIDTH_40;
    } else if (!strncmp(bandwidth, "80", 2)) {
        width = NL80211_CHAN_WIDTH_80;
    } else if (!strncmp(bandwidth, "160", 3)) {
        width = NL80211_CHAN_WIDTH_160;
    } else if (!strncmp(bandwidth, "320", 3)) {
        width = NL80211_CHAN_WIDTH_320;
    } else if (strchr(bandwidth, 'l') || strchr(bandwidth, 'u')) {
        width = NL80211_CHAN_WIDTH_40;
    } else {
        width = NL80211_CHAN_WIDTH_20;
    }

    return width;
}

static enum nl80211_chan_width platform_get_chanspec_bandwidth(char *chanspec)
{
    char *bw = NULL;
    char spec[32];
    char *str;
    char *space;
    enum nl80211_chan_width width;

    str = strncpy(spec, chanspec, sizeof(spec));
    space = strrchr(str, ' ');
    if (space) *space = '\0';
    bw = strchr(str, '/');
    if (!strncmp(str, "6g", 2)) {
        if (bw == NULL) {
            width = NL80211_CHAN_WIDTH_20;
        } else {
            width = bandwidth_str_to_nl80211_width(++bw);
        }
    } else if (bw) {
        width = bandwidth_str_to_nl80211_width(++bw);
    } else {
        width = bandwidth_str_to_nl80211_width(str);
    }

    return width;
}

enum nl80211_chan_width platform_get_bandwidth(wifi_interface_info_t *interface)
{
    char chanspec[32];
    int width;

    platform_get_current_chanspec(interface->name, chanspec, sizeof(chanspec));
    width = platform_get_chanspec_bandwidth(chanspec);
    wifi_hal_dbg_print("%s - Interface=%s chanspec=%s width=%d\n", __func__, interface->name, chanspec, width);
    return width;
}

void platform_switch_channel(wifi_interface_info_t *interface, struct csa_settings *settings)
{
    char chanspec[32] = {'\0'};

    wifi_hal_dbg_print("%s - csa: name=%s block=%d cs_count=%d channel=%d bandwidth=%d\n", \
                        __func__, interface->name, settings->block_tx, settings->cs_count, settings->freq_params.channel, settings->freq_params.bandwidth);
    platform_csa_to_chanspec(settings, chanspec);
    wifi_hal_dbg_print("%s - csa settings: wl -i %s csa %d %d %s\n", __func__, interface->name, settings->block_tx, settings->cs_count, chanspec);
    v_secure_system("wl -i %s csa %d %d %s", interface->name, settings->block_tx, settings->cs_count, chanspec);
}

void platform_set_csa(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char chanspec[32] = {'\0'};

    get_chanspec_string(operationParam, chanspec, index);
    if (platform_is_same_chanspec(index, chanspec) == false) {
        bool bss_up;
        wifi_radio_info_t *radio;
        wifi_interface_info_t *interface;

        radio = get_radio_by_rdk_index(index);
        interface = get_private_vap_interface(radio);
        bss_up = platform_is_bss_up(interface->name);
        if (bss_up == false) {
            wifi_hal_dbg_print("%s - bring %s bss up\n", __func__, interface->name);
            platform_bss_enable(interface->name, true);
        }
        wifi_hal_dbg_print("%s - name=wl%d block=0 cs_count=5 chanspec=%s\n", __func__, index, chanspec);
        v_secure_system("wl -i wl%d csa 0 5 %s", index, chanspec);
    }
}

void platform_set_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam, bool b_check_radio)
{
    char new_chanspec[32] = {'\0'};

    /* construct target chanspec */
    get_chanspec_string(operationParam, new_chanspec, index);

    /* compare current cchanspec to target chanspec */
    if (platform_is_same_chanspec(index, new_chanspec) == false) {
        bool b_radio_up = true;

        if (b_check_radio) {
            b_radio_up = platform_radio_state(index);
            if (b_radio_up) {
                v_secure_system("wl -i wl%d down", index);
            }
        }

        wifi_hal_dbg_print("%s: wl%d chanspec %s\n", __func__, index, new_chanspec);
        v_secure_system("wl -i wl%d chanspec %s", index, new_chanspec);
        if (b_check_radio && b_radio_up) {
            v_secure_system("wl -i wl%d up", index);
        }
    }
}

void platform_config_eht_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    bool enable;
    bool eht_enabled = false;

    enable = (operationParam->variant & WIFI_80211_VARIANT_BE) ? true : false;
    eht_enabled = platform_is_eht_enabled(index);

    /* no op if no change in eht state */
    if (enable == eht_enabled) {
        wifi_hal_dbg_print("%s - No change EHT=%d\n", __func__, (eht_enabled) ? 1 : 0);
        platform_set_csa(index, operationParam);
    } else {
        bool radio_up = platform_radio_state(index);
        if (radio_up) {
            v_secure_system("wl -i wl%d down", index);
        }
        v_secure_system("wl -i wl%d eht %d", index, (enable) ? 1 : 0);
        wifi_hal_dbg_print("%s: wl%d eht changed to %d\n", __func__, index, (enable == true) ? 1 : 0);
        platform_set_chanspec(index, operationParam, false);
        if (radio_up) {
            v_secure_system("wl -i wl%d up", index);
        }
    }
}

bool platform_is_bss_up(char* ifname)
{
    FILE *fp;
    char bss_state[16]={'\0'};

    fp = (FILE *)v_secure_popen("r", "wl -i %s bss", ifname);
    if (fp) {
        fgets(bss_state, sizeof(bss_state), fp);
        v_secure_pclose(fp);
    }
    return !strncmp(bss_state, "up", 2) ? true : false;
}

void platform_bss_enable(char* ifname, bool enable)
{
    bool bss_enabled = platform_is_bss_up(ifname);

    if (bss_enabled == enable) {
        return;
    }
    if (enable) {
        v_secure_system("wl -i %s bss up", ifname);
    } else {
        v_secure_system("wl -i %s bss down", ifname);
    }
}
#endif
#endif

#ifdef CONFIG_IEEE80211BE
int wifi_drv_set_ap_mlo(struct nl_msg *msg, void *priv, struct wpa_driver_ap_params *params) {
    //TODO: FIXME
    return 0;
}

void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb) {
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] &&
        nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) >= 2) {
        const u8 *pos;

        pos = nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);
        eht_capab->mac_cap = WPA_GET_LE16(pos);
    }
}

/* TODO: temporary solution, mld id should come from vap configuration */
static inline int get_mld_id_for_ap(int ap_index)
{
    if(is_wifi_hal_vap_private(ap_index)) {
        return 0;
    } else if(is_wifi_hal_vap_xhs(ap_index)) {
        return 1;
    } else if(is_wifi_hal_vap_hotspot_open(ap_index)) {
        return 2;
    } else if(is_wifi_hal_vap_lnf_psk(ap_index)) {
        return 3;
    } else if(is_wifi_hal_vap_hotspot_secure(ap_index)) {
        return 4;
    } else if(is_wifi_hal_vap_lnf_radius(ap_index)) {
        return 5;
    } else if(is_wifi_hal_vap_mesh_backhaul(ap_index)) {
        return 6;
    }
    return 7;
}

int update_hostap_mlo(wifi_interface_info_t *interface) {
    /* TODO: add correct way to configure MLD. These changes are done only for
     * testing wifi-7 single-link connection */
    struct hostapd_bss_config *conf;
    struct hostapd_data *hapd;

    conf = &interface->u.ap.conf;
    hapd = &interface->u.ap.hapd;

    conf->mld_ap = !conf->disable_11be;

    conf->mld_id = -1;
    free(hapd->mld);
    hapd->mld = NULL;
    hapd->mld_link_id = 0;

    if (conf->mld_ap) {
        wifi_vap_info_t *vap;

        vap = &interface->vap_info;

        conf->mld_id = get_mld_id_for_ap(vap->vap_index);
        hapd->mld = malloc(sizeof(*hapd->mld));
        memset(hapd->mld, 0, sizeof(*hapd->mld));
        os_memcpy(hapd->mld->mld_addr, hapd->own_addr, ETH_ALEN);
        os_memcpy(conf->mld_addr, hapd->own_addr, ETH_ALEN);
        dl_list_init(&hapd->mld->links);
        snprintf(hapd->mld->name, sizeof(hapd->mld->name), "mld_id_%d", vap->vap_index);
        hostapd_mld_add_link(hapd);
    }

    wifi_hal_info_print("%s:%d: mlo vap: %s - mld_ap:%d mld_id:%d mld_link_id:%d\n", __func__,
        __LINE__, interface->name, conf->mld_ap, conf->mld_id, hapd->mld_link_id);

    return RETURN_OK;
}

#endif /* CONFIG_IEEE80211BE */
