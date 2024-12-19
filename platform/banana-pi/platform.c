/************************************************************************
* If not stated otherwise in this file or this component's Licenses.txt
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
**************************************************************************/

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"

#define NULL_CHAR '\0'
#define NEW_LINE '\n'
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define BPI_LEN_32 32
#define BPI_LEN_16 16

int wifi_nvram_defaultRead(char *in,char *out);
int _syscmd(char *cmd, char *retBuf, int retBufSize);

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
    char output_val[BPI_LEN_32];
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
    wifi_nvram_defaultRead("bpi_wifi_password",password);
    return 0;
}

int platform_get_ssid_default(char *ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);   
    snprintf(ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
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
    snprintf(l_ssid,BPI_LEN_16,"BPI_RDKB-AP%d",vap_index);
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

int platform_get_radio_caps(wifi_radio_index_t index)
{
    return 0;
}

