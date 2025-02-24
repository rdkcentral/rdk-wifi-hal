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
            "failed: %i (%s)", __func__, ret, strerror(-ret));
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
            "failed: %i (%s)", __func__, ret, strerror(-ret));
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
            "failed: %i (%s)", __func__, ret, strerror(-ret));
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
INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return RETURN_ERR;
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
