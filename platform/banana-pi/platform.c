/************************************************************************
* If not stated otherwise in this file or this component's LICENSE
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

#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include <net/if.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define BPI_LEN_32 32
#define BPI_LEN_16 16
#define BPI_LEN_8 8
#define MAX_KEYPASSPHRASE_LEN 129
#define MAX_SSID_LEN 33
#define INVALID_KEY  "12345678"

int wifi_nvram_defaultRead(char *in,char *out);
int _syscmd(char *cmd, char *retBuf, int retBufSize);
int dealloc_mld(wifi_interface_info_t *interface);

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
    return 0;
}

int platform_post_init(wifi_vap_info_map_t *vap_map)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);    
    system("brctl addif brlan0 wifi0");
    system("brctl addif brlan0 wifi1");
    system("brctl addif brlan0 wifi2");
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
#if (HOSTAPD_VERSION >= 211)
    wifi_vap_info_t *vap;
    wifi_interface_info_t *interface;
    struct hostapd_data *hapd, *link_bss;

    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: failed to get interface for vap_index %d\n", __func__,
                __LINE__, vap->vap_index);
            continue;
        }

        if (interface->u.ap.conf.disable_11be) {
            continue;
        }

        if (!wifi_hal_is_mld_enabled(interface) || !vap->u.bss_info.enabled) {
            continue;
        }

        /* beacon has to be set twice to make it broadcast */
        hapd = &interface->u.ap.hapd;
        for_each_mld_link(link_bss, hapd) {
            if (ieee802_11_set_beacon(link_bss) != 0) {
                wifi_hal_error_print("%s:%d: Failed to set beacon for interface: %s link id: %d\n",
                    __func__, __LINE__, wifi_hal_get_interface_name(interface),
                    link_bss->mld_link_id);
                return -1;
            }
        }
    }
#endif
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
    char serial[BPI_LEN_8] = {0};
    FILE *fp = NULL;
    size_t bytes_read = 0;

    if((fp = fopen("/nvram/serial_number.txt", "rb")) != NULL)
    {
        if(fseek(fp, -7, SEEK_END))
        {
            wifi_hal_dbg_print("%s:%d, fseek() failed \n", __func__, __LINE__);
	        fclose(fp);
	        return -1;
        }
	    bytes_read = fread(serial, 1, sizeof(serial)-1, fp);
	    fclose(fp);
	    if(!bytes_read)
	        return -1;
	    serial[strcspn(serial, "\n")] = 0;
	    wifi_hal_dbg_print("%s:%d, appending serial is :%s \n", __func__, __LINE__, serial);
    }
#ifdef CONFIG_GENERIC_MLO
    snprintf(ssid, BPI_LEN_32, "BPI-RDKB-MLO-AP-%s", serial);
#else    
    snprintf(ssid, BPI_LEN_32, "BPI_RDKB-AP%d-%s", vap_index, serial);
#endif    
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
#ifdef CONFIG_GENERIC_MLO    
    snprintf(l_ssid, BPI_LEN_16, "BPI-RDKB-MLO-AP");
#else    
    snprintf(l_ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
#endif    
    return 0;
}

static bool has_config_changed(wifi_vap_info_t *current_config, wifi_vap_info_t *new_config)
{
    return ((current_config->u.bss_info.mld_info.common_info.mld_enable !=
                new_config->u.bss_info.mld_info.common_info.mld_enable) ||
        (current_config->u.bss_info.enabled != new_config->u.bss_info.enabled));
}

#ifdef CONFIG_GENERIC_MLO
static int teardown_mlo_vap(wifi_interface_info_t *interface)
{
    wifi_interface_info_t *first_interface = NULL;
    unsigned int ifidx = 0;

    if (nl80211_enable_ap(interface, false) < 0) {
        wifi_hal_error_print("%s:%d: interface:%s link id:%d failed to disable AP\n", __func__,
            __LINE__, interface->mld_name, wifi_hal_get_mld_link_id(interface));
        return -1;
    }

    if (hostapd_mld_is_first_bss(&interface->u.ap.hapd)) {
        // We are removing the first link.
        // First interface pointer could point to invalid data
        // for shared resources if removed first.
        // Clearing all other links first
        struct hostapd_data *link;
        struct hostapd_data *hapd = &interface->u.ap.hapd;
        for_each_mld_link(link, hapd) {
            if (hapd == link)
                continue;
            hostapd_bss_deinit_no_free(link);
            hostapd_free_hapd_data(link);
        }

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        deinit_bss(&interface->u.ap.hapd);
        if (interface->u.ap.hapd.conf->ssid.wpa_psk != NULL &&
            interface->u.ap.hapd.conf->ssid.wpa_psk->next == NULL) {
            hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        if (dealloc_mld(interface) != 0) {
            wifi_hal_error_print("%s:%d: Failed to deinitialize VAP %d from MLD %s\n", __func__,
                __LINE__, interface->vap_info.vap_index, interface->mld_name);
            return -1;
        }

        if (interface->mgmt_frames_registered) {
            nl80211_unregister_mgmt_frames(interface);
        }
        if (interface->spurious_frames_registered) {
            nl80211_unregister_spurious_frames(interface);
        }
        if (interface->data_frames_registered) {
            unregister_data_frame_socket(interface);
        }

        first_interface = wifi_hal_get_first_mld_interface(interface);
        if (first_interface != NULL && hostapd_mld_is_first_bss(&first_interface->u.ap.hapd)) {
            first_interface->vap_configured = false;
            wifi_drv_set_operstate(first_interface, 1);
        }
    } else {
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        deinit_bss(&interface->u.ap.hapd);
        if (interface->u.ap.hapd.conf->ssid.wpa_psk != NULL &&
            interface->u.ap.hapd.conf->ssid.wpa_psk->next == NULL) {
            hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        if (dealloc_mld(interface) != 0) {
            wifi_hal_error_print("%s:%d: Failed to deinitialize VAP %d from MLD %s\n", __func__,
                __LINE__, interface->vap_info.vap_index, interface->mld_name);
            return -1;
        }

        first_interface = wifi_hal_get_first_mld_interface(interface);
    }

    // Necessary in case of readding
    nl80211_remove_from_bridge(interface->name);

    // Remove MLD mac address
    if (wifi_hal_set_mld_mac_address(interface, interface->mac) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set MAC address for interface %s\n", __func__,
            __LINE__, interface->mld_name);
        return -1;
    }

    ifidx = if_nametoindex(interface->name);
    if (ifidx == 0) {
        wifi_hal_error_print("%s:%d: Failed to get ifindex for switching from MLD interface %s\n",
            __func__, __LINE__, interface->mld_name);
        return -1;
    }
    interface->index = ifidx;

    if (wifi_hal_set_mld_enabled(interface, false) < 0) {
        wifi_hal_error_print("%s: %d: Failed to disable MLD %s on VAP idx %d\n", __func__, __LINE__,
            interface->mld_name, interface->vap_info.vap_index);
        return -1;
    }

    interface->bss_started = false;
    interface->vap_initialized = false;
    interface->vap_configured = false;

    // Reload to update MLD
    if (first_interface != NULL && hostapd_mld_is_first_bss(&first_interface->u.ap.hapd)) {
        reload_vap_configuration(first_interface);
    }
    return 0;
}

static int setup_mlo_vap(wifi_interface_info_t *interface, wifi_vap_info_t *new_vap_config)
{
    unsigned int if_idx;

    if (wifi_hal_set_mld_enabled(interface, true) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set mld_enable:%d on VAP idx %d\n", __func__,
            __LINE__, new_vap_config->u.bss_info.mld_info.common_info.mld_enable,
            interface->vap_info.vap_index);
        return -1;
    }

    if (wifi_hal_set_mld_id(interface, new_vap_config->u.bss_info.mld_info.common_info.mld_id) <
        0) {
        wifi_hal_error_print("%s:%d: Failed to set MLD id %d on VAP idx %d\n", __func__, __LINE__,
            new_vap_config->u.bss_info.mld_info.common_info.mld_id, interface->vap_info.vap_index);
        return -1;
    }

    if_idx = if_nametoindex(interface->mld_name);
    if (if_idx == 0) {
        wifi_hal_error_print("%s:%d: Failed to find interface %s for MLD setup\n", __func__,
            __LINE__, interface->mld_name);
        return -1;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    deinit_bss(&interface->u.ap.hapd);
    if (interface->u.ap.hapd.conf->ssid.wpa_psk != NULL &&
        interface->u.ap.hapd.conf->ssid.wpa_psk->next == NULL) {
        hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    nl80211_unregister_mgmt_frames(interface);
    nl80211_unregister_spurious_frames(interface);
    unregister_data_frame_socket(interface);

    if (new_vap_config->u.bss_info.mld_info.common_info.mld_enable &&
        if_nametoindex(interface->name) != 0 &&
        nl80211_interface_enable(interface->name, false) < 0) {
        wifi_hal_error_print("%s:%d: failed to disable interface %s\n", __func__, __LINE__,
            interface->name);
        return -1;
    }

    // Necessary in case of readding
    nl80211_remove_from_bridge(interface->mld_name);

    // This will enforce:
    // Security reload
    // BSS restart
    // netlink handlers registration if applicable
    interface->bss_started = false;
    interface->vap_initialized = false;
    interface->vap_configured = false;

    interface->index = if_idx;
    return 0;
}
#endif // CONFIG_GENERIC_MLO

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char output_val[BPI_LEN_32] = { 0 };
    int i = 0;
    wifi_vap_info_t *vap = NULL;
    wifi_interface_info_t *interface = NULL;

    char *mld_name = NULL;
    mac_address_t mld_mac = { 0 };

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

    for (unsigned int i = 0; i < map->num_vaps; i++) {
        vap = &map->vap_array[i];
        if (vap->vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        interface = get_interface_by_vap_index(vap->vap_index);
        if (interface == NULL) {
            wifi_hal_error_print("%s:%d: failed to get interface for vap_index %d\n", __func__,
                __LINE__, vap->vap_index);
            continue;
        }

#ifdef CONFIG_GENERIC_MLO
        // TODO: resolve wifi-hal driven changes
        // Because of DML cache, even if we update those values, the DML
        // cache used with i.e. TR-181 stays the same and will keep
        // trying to push it's cached values on us as we have no means to
        // update it. We need to either:
        //- force cache to resync with db after change, as db has proper
        // values
        //- have a feedback mechanism, i.e. a callback for DML to fetch
        // the VAP status and do the updates
        if (interface->u.ap.hapd.mld != NULL) {
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id =
                interface->u.ap.hapd.mld_link_id;
            vap->u.bss_info.mld_info.common_info.mld_link_id = interface->u.ap.hapd.mld_link_id;
            wifi_hal_info_print("%s:%d: interface:%s link id:%d\n", __func__, __LINE__,
                interface->name, wifi_hal_get_mld_link_id(interface));
        }

        mld_name = wifi_hal_get_mld_name_by_interface_name(interface->name);
        if (mld_name == NULL) {
            wifi_hal_error_print(
                "%s:%d: MLD interface is enabled, but interface name is unset - skipping\n",
                __func__, __LINE__);
            return -1;
        }

        if (vap->u.bss_info.mld_info.common_info.mld_enable) {
            strncpy(interface->mld_name, mld_name, sizeof(interface->mld_name) - 1);
            if (wifi_hal_get_mac_address(mld_name, mld_mac) < 0) {
                wifi_hal_error_print("%s:%d: Failed to get MAC address for interface %s\n",
                    __func__, __LINE__, mld_name);
                return -1;
            }

            if (wifi_hal_set_mld_mac_address(interface, mld_mac) < 0) {
                wifi_hal_error_print("%s: %d: Failed to set MAC on MLD id %d on VAP idx %d\n",
                    __func__, __LINE__, vap->u.bss_info.mld_info.common_info.mld_id,
                    vap->vap_index);
                return -1;
            }

            // This is feedback info to datamodel on MLD address.
            memcpy(vap->u.bss_info.mld_info.common_info.mld_addr,
                interface->vap_info.u.bss_info.mld_info.common_info.mld_addr,
                sizeof(vap->u.bss_info.mld_info.common_info.mld_addr));
        }

        if (has_config_changed(&interface->vap_info, vap) == false) {
            continue;
        }

        if (vap->u.bss_info.mld_info.common_info.mld_enable == false ||
            vap->u.bss_info.enabled == false) {
            if (teardown_mlo_vap(interface) != 0) {
                wifi_hal_error_print("%s:%d: Failed to teardown link for MLD ID %d on VAP idx %d\n",
                    __func__, __LINE__, vap->u.bss_info.mld_info.common_info.mld_id,
                    vap->vap_index);
                return -1;
            }

            // Set link_id to NA in DML
            vap->u.bss_info.mld_info.common_info.mld_link_id = NL80211_DRV_LINK_ID_NA;
            interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id =
                NL80211_DRV_LINK_ID_NA;

            continue;
        } else {
            if (setup_mlo_vap(interface, vap) != 0) {
                wifi_hal_error_print("%s:%d: Failed to setup link for MLD ID %d with VAP idx %d\n",
                    __func__, __LINE__, vap->u.bss_info.mld_info.common_info.mld_id,
                    vap->vap_index);
                return -1;
            }
        }
    }
#endif // CONFIG_GENERIC_MLO
    return 0;
}

int platform_flags_init(int *flags)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    *flags = PLATFORM_FLAGS_STA_INACTIVITY_TIMER | PLATFORM_FLAGS_CONTROL_PORT_FRAME;
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

int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain)
{
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
    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] &&
        nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]) >= 2) {
        const u8 *pos;

        pos = nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC]);
        eht_capab->mac_cap = WPA_GET_LE16(pos);
    }
}

static struct hostapd_mld *find_mld(struct wifi_interface_info_t *interface)
{
    struct hostapd_mld *mld_it = NULL;

    for (unsigned int i = 0; i < g_wifi_hal.mld_count; ++i) {
        mld_it = g_wifi_hal.mld_array[i];

        if (strncmp(interface->mld_name, mld_it->name, sizeof(mld_it->name)) == 0) {
            return mld_it;
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

    dl_list_for_each(link_bss, &hapd->mld->links, struct hostapd_data, link) {
        if (link_bss == hapd) {
            return true;
        }
    }

    return false;
}

static int alloc_mld(wifi_interface_info_t *interface)
{
    struct hostapd_mld *mld;
    struct hostapd_mld **new_mld_array;
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    mld = find_mld(interface);
    if (mld) {
        wifi_hal_dbg_print("%s:%d hapd->mld was found for interface %s\n", __func__, __LINE__,
            interface->name);
        hapd->mld = mld;
        mld->refcount++;
        return 0;
    }

    mld = calloc(1, sizeof(struct hostapd_mld));
    if (mld == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate memory for hostapd_mld %s\n", __func__,
            __LINE__, interface->mld_name);
        return -1;
    }

    new_mld_array = realloc(g_wifi_hal.mld_array,
        (g_wifi_hal.mld_count + 1) * sizeof(struct hostapd_mld *));
    if (new_mld_array == NULL) {
        wifi_hal_error_print("%s:%d: Failed to reallocate MLD array\n", __func__, __LINE__);
        free(mld);
        return -1;
    }

    strncpy(mld->name, interface->mld_name, sizeof(mld->name) - 1);
    dl_list_init(&mld->links);
    mld->ctrl_sock = -1;
    memcpy(mld->mld_addr, wifi_hal_get_mld_mac_address(interface), ETH_ALEN);

    new_mld_array[g_wifi_hal.mld_count] = mld;
    hapd->mld = mld;
    mld->refcount++;
    mld->num_links = 0;
    mld->next_link_id = 0;

    g_wifi_hal.mld_array = new_mld_array;
    g_wifi_hal.mld_count++;

    return 0;
}

static void remove_mld_from_array(struct hostapd_mld *mld)
{
    unsigned int idx = 0;
    for (; idx < g_wifi_hal.mld_count; ++idx) {
        if (g_wifi_hal.mld_array[idx] == mld) {
            free(g_wifi_hal.mld_array[idx]);
            g_wifi_hal.mld_array[idx] = NULL;
            break;
        }
    }

    // Reorder remaining MLDs
    while (idx + 1 < g_wifi_hal.mld_count) {
        g_wifi_hal.mld_array[idx] = g_wifi_hal.mld_array[idx + 1];
        ++idx;
    }
}

int dealloc_mld(wifi_interface_info_t *interface)
{
    struct hostapd_data *hapd;
    struct hostapd_mld **new_mld_array;
    hapd = &interface->u.ap.hapd;

    if (hapd->mld == NULL) {
        wifi_hal_info_print("%s:%d hapd->mld empty, nothing to free \n", __func__, __LINE__);
        return 0;
    }

    if (hostapd_if_link_remove(hapd, WPA_IF_AP_BSS, hapd->conf->iface, hapd->mld_link_id) != 0) {
        wifi_hal_error_print("%s:%d Failed to remove link from driver ! Link id: %d, MLD: %s\n",
            __func__, __LINE__, hapd->mld_link_id, interface->mld_name);
        return -1;
    }

    if (hostapd_mld_remove_link(hapd) != 0) {
        wifi_hal_error_print(
            "%s:%d Failed to remove link from hostapd_mld ! Link id: %d, MLD: %s\n", __func__,
            __LINE__, hapd->mld_link_id, interface->mld_name);
        return -1;
    }

    if (hapd->mld->refcount > 0) {
        hapd->mld->refcount--;
    }

    if (hapd->mld->refcount == 0) {
        remove_mld_from_array(hapd->mld);

        if (g_wifi_hal.mld_count > 1) {
            // There are still other MLDs in the current config
            new_mld_array = realloc(g_wifi_hal.mld_array,
                (g_wifi_hal.mld_count - 1) * sizeof(struct hostapd_mld *));
            if (new_mld_array == NULL) {
                wifi_hal_error_print("%s:%d Failed to reallocate MLD array\n", __func__, __LINE__);
                return -1;
            }
        } else {
            new_mld_array = NULL;
        }

        g_wifi_hal.mld_count--;
        g_wifi_hal.mld_array = new_mld_array;
    }

    hapd->mld = NULL;
    hapd->conf->mld_ap = 0;
    hapd->conf->okc = 0;

    return 0;
}

int update_hostap_mlo(wifi_interface_info_t *interface)
{
#if (HOSTAPD_VERSION >= 211)
    struct hostapd_bss_config *conf;
    struct hostapd_data *hapd, *first_link, *link_bss;

    if (!interface->vap_info.u.bss_info.enabled) {
        return 0;
    }

    if (interface->u.ap.conf.disable_11be) {
        return 0;
    }

    if (!wifi_hal_is_mld_enabled(interface)) {
        return 0;
    }

    wifi_hal_info_print("%s:%d: interface:%s link id:%d update MLD links\n", __func__, __LINE__,
        wifi_hal_get_interface_name(interface), wifi_hal_get_mld_link_id(interface));

    hapd = &interface->u.ap.hapd;
    conf = hapd->conf;

    if (hapd->mld == NULL) {
        if (alloc_mld(interface) < 0) {
            wifi_hal_error_print("Failed to obtain hostapd_mld for MLD interface %s\n",
                interface->mld_name);
            return -1;
        }
    }

    conf->mld_ap = 1;
    conf->okc = 1;

    if (!wifi_hal_is_mld_link_exists(hapd)) {
        hapd->mld_link_id = hapd->mld->next_link_id++;
        if (hostapd_mld_add_link(hapd)) {
            wifi_hal_error_print("%s:%d: Failed to add link %d in MLD %s\n", __func__, __LINE__,
                hapd->mld_link_id, hapd->conf->iface);
            return -1;
        }
        interface->vap_info.u.bss_info.mld_info.common_info.mld_link_id = hapd->mld_link_id;
    }

    /* Links have been removed due to interface down-up. Re-add all links and enable them,
     * but enable the first link BSS before doing that. */
    first_link = hostapd_mld_is_first_bss(hapd) ? hapd : hostapd_mld_get_first_bss(hapd);

    if (hostapd_drv_link_add(first_link, first_link->mld_link_id, first_link->own_addr)) {
        wifi_hal_error_print("%s:%d: Failed to add link %d in MLD %s\n", __func__, __LINE__,
            first_link->mld_link_id, first_link->conf->iface);
        return -1;
    }

    /* Add other affiliated links */
    for_each_mld_link(link_bss, first_link) {
        if (link_bss == first_link) {
            continue;
        }

        if (hostapd_drv_link_add(link_bss, link_bss->mld_link_id, link_bss->own_addr)) {
            wifi_hal_error_print("%s:%d: Failed to add link %d in MLD %s\n", __func__, __LINE__,
                link_bss->mld_link_id, link_bss->conf->iface);
            return -1;
        }
    }

#endif
    return 0;
}
#endif /* CONFIG_IEEE80211BE */

