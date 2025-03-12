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
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
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
#include <pthread.h>
#include <sys/prctl.h>
#include <wifi_hal_rdk_framework.h>
#include <collection.h>
#include <cjson/cJSON.h>
#if defined (RDK_ONEWIFI)
#include "wifi_hal_priv.h"
#endif
#if defined(PLATFORM_LINUX)
unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};
#else 
extern unsigned char wifi_common_hal_test_signature[8];
#endif
extern char* get_formatted_time(char *);

//Currently ANQP(Adv ID:0) is the only GAS type supported
#define MAX_AP_INDEX 15
#define MAX_BUFF 8192

#define MAC_STR_LEN 18

static wifi_GASConfiguration_t gasCfg[GAS_CFG_TYPE_SUPPORTED];

#if defined (FEATURE_SUPPORT_PASSPOINT)
static wifi_HS2Settings_t hs2Settings[MAX_AP_INDEX + 1];
static BOOL hs2SettingsStored;
#endif

void wifi_anqp_dbg_print(int level, char *format, ...)
{
    char buff[4096] = {0};
    va_list list;
    static FILE *fpg = NULL;

    if ((access("/nvram/wifiAnqpDbg", R_OK)) != 0)
    {
        return;
    }
    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);
    if (fpg == NULL)
    {
        fpg = fopen("/tmp/wifiAnqp", "a+");
        if (fpg == NULL)
        {
            return;
        }
        else
        {
            fputs(buff, fpg);
        }
    }
    else
    {
        fputs(buff, fpg);
    }

    fflush(fpg);
}

void wifi_storeInitialPassPointSettings()
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    int ap_index;
    BOOL _countryIe;
    BOOL _layer2TIF;
    BOOL _downStreamGroupAddress;
    BOOL _bssLoad;
    BOOL _proxyArp;

    for (ap_index = 0; ap_index < MAX_AP_INDEX; ap_index++)
    {
        wifi_anqp_dbg_print(1, "%s:%d:Storing initial HS2 Values:   %d\n", __func__, __LINE__, ap_index);
        wifi_getCountryIe(ap_index, &_countryIe);
        hs2Settings[ap_index].countryIe = _countryIe;

        wifi_getLayer2TrafficInspectionFiltering(ap_index, &_layer2TIF);
        hs2Settings[ap_index].layer2TIF = _layer2TIF;

        wifi_getDownStreamGroupAddress(ap_index, &_downStreamGroupAddress);
        hs2Settings[ap_index].downStreamGroupAddress = _downStreamGroupAddress;

        wifi_getBssLoad(ap_index, &_bssLoad);
        hs2Settings[ap_index].bssLoad = _bssLoad;

        wifi_getProxyArp(ap_index, &_proxyArp);
        hs2Settings[ap_index].proxyArp = _proxyArp;
    }
#endif
}

int enablePassPointSettings(int ap_index, BOOL passpoint_enable, BOOL downstream_disable, BOOL p2p_disable, BOOL layer2TIF)
{
#if defined (FEATURE_SUPPORT_PASSPOINT)
    if (ap_index < 0 || ap_index > MAX_AP_INDEX)
    {
        wifi_anqp_dbg_print(1, "%s:%d:Invalid ap index:   %d\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    if(!hs2SettingsStored)
    {
        hs2SettingsStored = TRUE;
        wifi_storeInitialPassPointSettings();
    }

    if (passpoint_enable)
    {
        wifi_anqp_dbg_print(1, "%s:%d:Enabling HS2 Settings for ap index:   %d\n", __func__, __LINE__, ap_index);
        wifi_setCountryIe(ap_index, passpoint_enable);
        wifi_setProxyArp(ap_index, passpoint_enable);
        wifi_setLayer2TrafficInspectionFiltering(ap_index, layer2TIF);
        wifi_setDownStreamGroupAddress(ap_index, downstream_disable);
        wifi_setBssLoad(ap_index, passpoint_enable);
        wifi_setP2PCrossConnect(ap_index, p2p_disable);
    }
    else
    {
        //set the values initially stored in hs2settings for ap index.
        wifi_anqp_dbg_print(1, "%s:%d:Disabling HS2 Settings for ap index:   %d\n", __func__, __LINE__, ap_index);
        wifi_setCountryIe(ap_index, hs2Settings[ap_index].countryIe);
        wifi_setProxyArp(ap_index, hs2Settings[ap_index].proxyArp);
        wifi_setLayer2TrafficInspectionFiltering(ap_index, hs2Settings[ap_index].layer2TIF);
        wifi_setDownStreamGroupAddress(ap_index, hs2Settings[ap_index].downStreamGroupAddress);
        wifi_setBssLoad(ap_index, hs2Settings[ap_index].bssLoad);
    }

    if(wifi_pushApHotspotElement(ap_index,passpoint_enable)!= RETURN_OK)
    {
        return RETURN_ERR;
    }
#else
    wifi_anqp_dbg_print(1, "%s:%d: FEATURE NOT SUPPORTED \n", __func__, __LINE__);
    return RETURN_ERR;
#endif
    return RETURN_OK;
}

void callback_anqp_gas_init_frame_received(int ap_index, mac_address_t sta, unsigned char token, unsigned char *attrib, unsigned int len)
{
    char macStr[MAC_STR_LEN];
    memset(macStr,0,sizeof(macStr));
    if(sta){
        snprintf(macStr, MAC_STR_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
        wifi_anqp_dbg_print(1, "%s:%d: converted mac: %s ap_index=%d\n", __func__, __LINE__,macStr,ap_index);
    }
    else{
        wifi_anqp_dbg_print(1, "%s:%d: Invalid mac. Return\n", __func__, __LINE__);
    }  

    if((ap_index < 0)){
        wifi_anqp_dbg_print(1, "%s:%d: Invalid AP Index: %d \n", __func__,__LINE__,ap_index);
        return;
    }

    if((len <= 0) || (attrib == NULL)){
        wifi_anqp_dbg_print(1, "%s:%d: Invalid Attributes in Request. Return \n", __func__,__LINE__);
        return;
    }

#if defined (FEATURE_SUPPORT_PASSPOINT)
#if !defined (RDK_ONEWIFI)
    BOOL enabled;
    INT rc;
    rc = wifi_getApInterworkingServiceEnable(ap_index, &enabled);
    if (rc == RETURN_OK)
    {
        if (!enabled)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking is disabled on AP: %d. \n", __func__,__LINE__,ap_index+1);
            wifi_anqp_dbg_print(1, "Not processing gas query from STA: %s \n",macStr);
            return;
        }
    }
    else
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking enabled flag could not be retreived for AP: %d. Not processing any gas queries \n", __func__, __LINE__,ap_index+1);
        return;
    }
#else
    const wifi_interface_info_t *interface = get_interface_by_vap_index(ap_index);
    const wifi_vap_info_t *vap = &(interface->vap_info);
    wifi_anqp_dbg_print(1,"Interworking enabled=%d and passpoint enabled =%d vap name=%s\n",
            vap->u.bss_info.interworking.interworking.interworkingEnabled,
            vap->u.bss_info.interworking.passpoint.enable,
            vap->vap_name);

    if ( !(vap->u.bss_info.interworking.interworking.interworkingEnabled) || !(vap->u.bss_info.interworking.passpoint.enable)) {
        wifi_anqp_dbg_print(1, "%s:%d: ONEWIFI passpoint is disabled  for ap_index=%d\n", __func__, __LINE__,ap_index);
        return;
    }
    else {
        wifi_anqp_dbg_print(1, "%s:%d: ONEWIFI passpoint is enabled for ap_index=%d\n", __func__, __LINE__,ap_index);
    }
#endif
#else
    wifi_anqp_dbg_print(1, "%s:%d: FEATURE NOT SUPPORTED \n", __func__, __LINE__);
    return;
#endif

    wifi_anqp_dbg_print(1, "%s:%d: Interworking is enabled on AP: %d \n", __func__,__LINE__,ap_index +1);
    wifi_anqp_dbg_print(1, "Process request from %s. \n",macStr);

    wifi_device_callbacks_t *callbacks;
    wifi_anqp_element_format_t *anqp_info;
    wifi_hs_2_anqp_element_format_t *anqp_hs_2_info;
    unsigned char wfa_oui[3] = {0x50, 0x6f, 0x9a};
    wifi_anqp_node_t *head = NULL, *tmp = NULL, *prev = NULL;
    wifi_anqp_elem_t *elem;
    signed short anqp_queries_len, anqp_hs_2_queries_len;
    bool first = true;
    unsigned short *query_list_id;
    unsigned char *buff, *query_list_hs_id;

    callbacks = get_device_callbacks();

    if(callbacks && callbacks->anqp_req_callback)
    {
        buff = attrib;

        while (buff < (attrib+len))
        {
            anqp_info = (wifi_anqp_element_format_t *)buff;

            if (anqp_info->info_id == wifi_anqp_element_name_vendor_specific)
            {
                anqp_hs_2_info = (wifi_hs_2_anqp_element_format_t *)buff;

                if (memcmp(anqp_hs_2_info->oi, wfa_oui, sizeof(wfa_oui)) != 0)
                {
                    wifi_anqp_dbg_print(1, "%s:%d: Invalid HS2.0  Query; Break\n", __func__,__LINE__);
                    break;
                }

                anqp_hs_2_queries_len = anqp_hs_2_info->len - 6;//wifi_oui(3) + Type(1) + SubType(1) + Reserved (1) 
                query_list_hs_id = anqp_hs_2_info->payload;

                while (anqp_hs_2_queries_len)
                {

                    tmp = (wifi_anqp_node_t *)malloc(sizeof(wifi_anqp_node_t));
                    memset((unsigned char *)tmp, 0, sizeof(wifi_anqp_node_t));

                    elem = (wifi_anqp_elem_t *)malloc(sizeof(wifi_anqp_elem_t));
                    memset((unsigned char *)elem, 0, sizeof(wifi_anqp_elem_t));

                    elem->type = wifi_anqp_id_type_hs;
                    elem->u.anqp_hs_id = *query_list_hs_id;

                    tmp->value = elem;
                    tmp->next = NULL;

                    if (first == true)
                    {
                        head = tmp;
                        first = false;
                        prev = head;
                    }
                    else
                    {
                        prev->next = tmp;
                        prev = tmp;
                    }
                    anqp_hs_2_queries_len -= sizeof(unsigned char);
                    query_list_hs_id++;
                }

                buff = query_list_hs_id;
            }
            else if (anqp_info->info_id == wifi_anqp_element_name_query_list)
            {
                anqp_queries_len = anqp_info->len;

                query_list_id = (unsigned short *)anqp_info->info;

                while (anqp_queries_len > 0)
                {
                    tmp = (wifi_anqp_node_t *)malloc(sizeof(wifi_anqp_node_t));
                    memset((unsigned char *)tmp, 0, sizeof(wifi_anqp_node_t));

                    elem = (wifi_anqp_elem_t *)malloc(sizeof(wifi_anqp_elem_t));
                    memset((unsigned char *)elem, 0, sizeof(wifi_anqp_elem_t));

                    elem->type = wifi_anqp_id_type_anqp;
                    elem->u.anqp_elem_id = *query_list_id;

                    tmp->value = elem;
                    tmp->next = NULL;

                    if (first == true)
                    {
                        head = tmp;
                        first = false;
                        prev = head;
                    }
                    else
                    {
                        prev->next = tmp;
                        prev = tmp;
                    }

                    anqp_queries_len -= sizeof(unsigned short);
                    query_list_id++;
                }

                buff = (unsigned char *)query_list_id;
            }
            else 
            {
                wifi_anqp_dbg_print(1, "%s:%d: Invalid Query; Break\n", __func__,__LINE__);
                break;
            }
        }

        if(head == NULL)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Invalid Query List; Return\n", __func__,__LINE__);
            return;
        }
    
        wifi_anqp_dbg_print(1, "%s:%d: callback_anqp_gas_init_frame_received on AP: %d \n", __func__,__LINE__,ap_index +1);
        wifi_anqp_dbg_print(1, "STA:%s\n",macStr);

        callbacks->anqp_req_callback(ap_index, sta, token, head);
    }
    else
    {
        wifi_anqp_dbg_print(
            1, "%s:%d: get_device_callbacks: %d, anqp_req_callback: %d \n",
            __func__, __LINE__, !!callbacks,
            (callbacks ? !!callbacks->anqp_req_callback : 0));
    }
}

INT wifi_anqp_request_callback_register(wifi_anqp_request_callback_t anqpReqCallback)
{
    wifi_device_callbacks_t *callbacks;

    if (!anqpReqCallback)
    {
        wifi_anqp_dbg_print(1, "%s:%d: received NULL callback function\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    callbacks = get_device_callbacks();

    if (callbacks)
    {
        wifi_anqp_dbg_print(1, "%s:%d: setting anqp_req_callback \n", __func__,__LINE__);
        callbacks->anqp_req_callback = anqpReqCallback;
        return RETURN_OK;
    }
    else{
        wifi_anqp_dbg_print(1, "%s:%d: get_device_callbacks returned NULL \n", __func__,__LINE__);
        return RETURN_ERR;
    }
}

INT wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *head)
{
    char macStr[MAC_STR_LEN];
    memset(macStr,0,sizeof(macStr));
    if(sta){
        snprintf(macStr, MAC_STR_LEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
             wifi_anqp_dbg_print(1, "%s:%d: converted mac: %s ap_index=%d\n", __func__, __LINE__,macStr,apIndex);
    }

    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpSendResponse start on AP: %d \n", __func__,__LINE__,apIndex+1);
    wifi_anqp_dbg_print(1, "STA: %s\n",macStr);
    if (head == NULL)
    {
        wifi_anqp_dbg_print(1, "%s:%d: node list is null returning -1:    \n", __func__,__LINE__);
        return RETURN_ERR;
    }

    unsigned char wfa_oui[3] = {0x50, 0x6f, 0x9a};

    unsigned char buff[MAX_BUFF];
    unsigned char anqpBuffer[MAX_BUFF];
    unsigned char *next_pos;
    next_pos = &anqpBuffer[0];

    int total_length = 0;

    wifi_anqp_node_t *tmp = NULL;

    wifi_anqp_elem_t *elem = NULL;
    wifi_anqp_element_format_t *anqp_info = NULL;
    wifi_hs_2_anqp_element_format_t *anqp_hs_2_info = NULL;

    while (head != NULL)
    {
        elem = head->value;
        if (NULL == elem)
        {
            head = head->next;
            continue;
        }
        //construct the buffer for gas
        if (elem->type == wifi_anqp_id_type_anqp)
        {
            if (elem->data && elem->len)
            {
                total_length += sizeof(wifi_anqp_element_format_t) + elem->len;
                //8179 +13(max gas frame size = 8192)
                if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
                {
                    wifi_anqp_dbg_print(1, "%s:%d:%d: Anqp_info length buffer is too big to process returning:    \n", __func__, __LINE__);
                    break;
                }

                anqp_info = (wifi_anqp_element_format_t *)malloc(sizeof(wifi_anqp_element_format_t) + elem->len);
                memset((unsigned char *)anqp_info, 0, sizeof(wifi_anqp_element_format_t) + elem->len);

                wifi_anqp_dbg_print(1, "%s:%d: Anqp Element type received:    \n", __func__, __LINE__);
                anqp_info->info_id = elem->u.anqp_elem_id;
                anqp_info->len = elem->len;

                wifi_anqp_dbg_print(1, "%s:%d: Anqp_info length:    %d:\n", __func__, __LINE__, anqp_info->len);

                memcpy(anqp_info->info, elem->data, elem->len);

                memcpy(next_pos, anqp_info, sizeof(wifi_anqp_element_format_t) + anqp_info->len);
#if defined(_64BIT_ARCH_SUPPORT_)                
		next_pos += sizeof(wifi_anqp_element_format_t) + anqp_info->len;
#else
		next_pos += sizeof(anqp_info) + anqp_info->len;
#endif
                if (anqp_info)
                {
                    wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info:    \n", __func__, __LINE__);
                    free(anqp_info);
                    anqp_info = NULL;
                }
            }
        }
        else if (elem->type == wifi_anqp_id_type_hs)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Anqp Element type HS2  received \n", __func__, __LINE__);
            if (elem->data && elem->len)
            {
                total_length += sizeof(wifi_hs_2_anqp_element_format_t) + elem->len;
                wifi_anqp_dbg_print(1, "%s:%d: anqp_hs_2_info elem length: %hu\n", __func__, __LINE__, elem->len);
                //8179 +13(gas frame header = 8192)
                if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
                {
                    wifi_anqp_dbg_print(1, "%s:%d:%d: Anqp buffer is too big to process returning:    \n", __func__, __LINE__);
                    break;
                }
                anqp_hs_2_info = (wifi_hs_2_anqp_element_format_t *)malloc(sizeof(wifi_hs_2_anqp_element_format_t) + elem->len);
                memset((unsigned char *)anqp_hs_2_info, 0, sizeof(wifi_hs_2_anqp_element_format_t) + elem->len);
                anqp_hs_2_info->info_id = wifi_anqp_element_name_vendor_specific;
                anqp_hs_2_info->len = elem->len + 6;
                wifi_anqp_dbg_print(1, "%s:%d: anqp_hs_2_info length: %hu\n", __func__, __LINE__, anqp_hs_2_info->len);
                anqp_hs_2_info->type = 0x11;
                anqp_hs_2_info->subtype = elem->u.anqp_hs_id;
                anqp_hs_2_info->reserved = 0x00;
                memcpy(anqp_hs_2_info->oi, wfa_oui, sizeof(wfa_oui));

                memcpy(anqp_hs_2_info->payload, elem->data, elem->len);

                // char buffer[elem->len - 6];
                // memcpy(buffer, anqp_hs_2_info->payload, elem->len - 6);
                // wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info start: %d\n", __func__, __LINE__);
                // for (int i = 0; i < elem->len - 6; i++)
                // {
                //     wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info length: 0x%02x\n", __func__, __LINE__, buffer[i]);
                //     printf("0x%02x      ", buffer[i]);
                // }
                // wifi_anqp_dbg_print("%s:%d:\n", __func__, __LINE__);
                // wifi_anqp_dbg_print("%s:%d: HS2 End\n", __func__, __LINE__);

                // char buffer1[total_length];
                // memcpy(buffer1, anqp_hs_2_info, total_length);

                // wifi_anqp_dbg_print("%s:%d: HS2 Buffer Start: %d\n", __func__, __LINE__);
                // for (int i = 0; i < total_length; i++)
                // {
                //     wifi_anqp_dbg_print("%s:%d: anqp_hs_2_info length: 0x%02x\n", __func__, __LINE__, buffer1[i]);
                // }
                // wifi_anqp_dbg_print("%s:%d:\n", __func__, __LINE__);
                // wifi_anqp_dbg_print("%s:%d: HS2 Buffer End\n", __func__, __LINE__);

                memcpy(next_pos, anqp_hs_2_info, sizeof(wifi_hs_2_anqp_element_format_t) + elem->len /*anqp_hs_2_info->len-6*/);
                next_pos += sizeof(wifi_hs_2_anqp_element_format_t) + elem->len /*anqp_hs_2_info->len-6*/;

                if (anqp_hs_2_info)
                {
                    wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_hs_2_info elem-data:    \n", __func__, __LINE__);
                    free(anqp_hs_2_info);
                    anqp_hs_2_info = NULL;
                }
            }
        }
        if (elem->data)
        {
            wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info elem-data:    \n", __func__, __LINE__);
            free(elem->data);
            elem->data = NULL;
        }
        free(elem);
        elem = NULL;
        tmp = head;
        head = head->next;
        free(tmp);
        tmp = NULL;
    }

    //Free up memory in case of too large response
    while (head)
    {
        elem = head->value;

        if (elem)
        {
            if (elem->data)
            {
                wifi_anqp_dbg_print(1, "%s:%d: freeing anqp_info elem-data:    \n", __func__, __LINE__);
                free(elem->data);
                elem->data = NULL;
            }
            free(elem);
            elem = NULL;
        }
        tmp = head;
        head = head->next;
        free(tmp);
        tmp = NULL;
    }
 
#if defined (FEATURE_SUPPORT_PASSPOINT)
#if !defined (RDK_ONEWIFI)
    BOOL enabled;
    INT rc;
    rc = wifi_getApInterworkingServiceEnable(apIndex, &enabled);
    if (rc == RETURN_OK)
    {
        if (!enabled)
        {
            wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking is disabled on AP: %d. Not sending any GAS Responses \n", __func__, __LINE__,(apIndex+1));
            return RETURN_ERR;
        }
    }
    else
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error: Interworking enabled flag could not be retreived for AP: %d. Not sending any GAS Responses \n", __func__, __LINE__,(apIndex+1));
        return RETURN_ERR;
    }
#endif
#else
    wifi_anqp_dbg_print(1, "%s:%d: Error: FEATURE NOT SUPPORTED", __func__, __LINE__);
    return RETURN_ERR;
#endif

    wifi_anqp_dbg_print(1, "%s:%d: Interworking is enabled will proceed to gas response send on AP: %d \n", __func__,__LINE__,apIndex+1);
    wifi_anqp_dbg_print(1, "STA: %s. \n", macStr);

    //8179 +13(gas frame header = 8192)
    if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
    {
        wifi_anqp_dbg_print(1, "%s:%d: Anqp buffer is too big to process.%d\n", __func__, __LINE__, total_length);
        return RETURN_ERR;
    }

    /*For gas frame and concatenating anqp buffer contructed above */
    wifi_anqpResponseFrame_t *anqp_gas_initial_response_frame = NULL;

    anqp_gas_initial_response_frame = (wifi_anqpResponseFrame_t *)buff;

    anqp_gas_initial_response_frame->public_action_hdr.cat = 0x04;
    anqp_gas_initial_response_frame->public_action_hdr.action = 0x0b;
    anqp_gas_initial_response_frame->gas_resp_body.token = token;
    anqp_gas_initial_response_frame->gas_resp_body.comeback_delay = 0; //we are not supporting fragmentation or we dont have a server
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.id = 0x6c;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.len = 0x02;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.proto_tuple.query_rsp_info = (unsigned char)gasCfg[GAS_CFG_TYPE_SUPPORTED - 1].QueryResponseLengthLimit;
    anqp_gas_initial_response_frame->gas_resp_body.proto_elem.proto_tuple.adv_proto_id = gasCfg[GAS_CFG_TYPE_SUPPORTED - 1].AdvertisementID; //currently only anqp supported.


    if (total_length == 0)
    {
        wifi_anqp_dbg_print(1, "total Length is 0 from the list will send frame protocol not supported.\n", __func__, __LINE__);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_advertisement_protocol_not_supported;
    }
    else if (total_length > MAX_BUFF - sizeof(wifi_anqpResponseFrame_t))
    {
        wifi_anqp_dbg_print(1, "%s:%d:%d: Anqp buffer is too big to process we are setting gas response length to zero.\n", __func__, __LINE__);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_query_response_too_large;
        total_length = 0; //as per spec we need to set response length to zero
    }
    else
    {
        wifi_anqp_dbg_print(1, "we have a gas query response to fill the buffer\n", __func__, __LINE__);
        anqp_gas_initial_response_frame->gas_resp_body.status = wifi_gas_status_success;
    }

    anqp_gas_initial_response_frame->rsp_len = total_length;
    memcpy(anqp_gas_initial_response_frame->rsp_body, anqpBuffer, total_length);

   wifi_anqp_dbg_print(1, "we have a gas query response to fill the buffer\n", __func__, __LINE__);
#if !defined (RDK_ONEWIFI) || defined(TCHCBRV2_PORT)
    ULONG hm_channel = 0;
    UINT radioIndex = apIndex % 2;
    wifi_getRadioChannel(radioIndex, &hm_channel);
    wifi_anqp_dbg_print(1, "%s:%d: gathered channel for sending the frame out: %lu\n", __func__, __LINE__, hm_channel);
    unsigned int freq = 0;
    freq = channel_to_frequency(hm_channel);

    wifi_anqp_dbg_print(1, "%s:%d: frequency for sending the frame out: %lu\n", __func__, __LINE__, freq);
    wifi_anqp_dbg_print(1, "%s:%d: apIndex for sending the frame out: %d\n", __func__, __LINE__, apIndex + 1);

    wifi_sendActionFrame(apIndex, sta, freq, (unsigned char *)anqp_gas_initial_response_frame, sizeof(wifi_anqpResponseFrame_t) + total_length);
#else
    wifi_hal_send_mgmt_frame(apIndex,  sta,(unsigned char *)anqp_gas_initial_response_frame,(sizeof(wifi_anqpResponseFrame_t) + total_length),0);
#endif
    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpSendResponse exit\n", __func__, __LINE__);
    return RETURN_OK;
}

// @description set the GAS protocol configuration for an Advertisement Id supported by the AP.
//
// @param apIndex - Index of the Access Point.
// @param advertisementID - ID of the Advertisement protocol.  ANQP (0) is the only value currently supported.
// @param input_struct - GAS configuration values.
// @return The status of the operation.
// @retval RETURN_OK if successful.
// @retval RETURN_ERR if any error is detected.
INT wifi_setGASConfiguration(UINT advertisementID, wifi_GASConfiguration_t *input_struct)
{
    if (!input_struct)
    {
        return RETURN_ERR;
    }
    if (0 != advertisementID)
    {
        return RETURN_ERR; //Only ANQP (0) is supported
    }
    memcpy(&gasCfg[advertisementID], input_struct, sizeof(wifi_GASConfiguration_t));

#if defined (FEATURE_SUPPORT_PASSPOINT)
    wifi_applyGASConfiguration(input_struct);
#endif
    return RETURN_OK;
}

void *wifi_anqpTestFrameHandler(void *arg)
{
    wifi_anqp_dbg_print(1, "%s:%d: wifi_anqpTestFrameHandler entry:    \n", __func__, __LINE__);
    int sockfd;
    int ret = RETURN_OK;
    char interface_name[32];
    unsigned char msg[1024];
    size_t len = 0;
    wifi_test_command_id_t cmd;
    mac_address_t bmac;
    unsigned char frame[128];
    wifi_tlv_t *tlv;
    fd_set rfds;
    struct timeval tv;
    int retval, ap_index;
    bool exit = false;

    struct sockaddr_in saddr;
    socklen_t slen;
    unsigned short port = 8889;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error opening raw socket , err:%d\n", __func__, __LINE__, errno);
        return NULL;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    inet_aton("127.0.0.1", &saddr.sin_addr);

    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error binding to interface, err:%d\\n", __func__, __LINE__, errno);
        close(sockfd);
        return NULL;
    }

    while (exit == false)
    {

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == 0)
        {
            continue;
        }
        else if (retval == -1)
        {
            exit = true;
            continue;
        }

        if (FD_ISSET(sockfd, &rfds) == 0)
        {
            continue;
        }
        if ((ret = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&saddr, &slen)) < 0)
        {
            continue;
        }

        if (memcmp(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature)) != 0)
        {
            continue;
        }

        wifi_anqp_dbg_print(1, "%s:%d: Received test signature\n", __func__, __LINE__);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_cmd, ret)) == NULL)
        {
            continue;
        }
        memcpy((unsigned char *)&cmd, tlv->value, tlv->length);

        switch (cmd)
        {
        case wifi_test_command_id_anqp:
            wifi_anqp_dbg_print(1, "%s:%d: Received anqp test command\n", __func__, __LINE__);
            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_vap_name, ret)) == NULL)
            {
                continue;
            }
            memcpy(interface_name, tlv->value, tlv->length);
            sscanf(interface_name, "ath%d", &ap_index);

            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_sta_mac, ret)) == NULL)
            {
                continue;
            }
            memcpy(bmac, tlv->value, tlv->length);

            if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_raw, ret)) == NULL)
            {
                continue;
            }
            memcpy(frame, tlv->value, tlv->length);
            wifi_anqp_dbg_print(1, "%s:%d: Calling mgmt frame receive\n", __func__, __LINE__);

            mgmt_frame_received_callback(ap_index, bmac, frame, len, WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
            break;

        default:
            break;
        }
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);
    return arg;
}

void wifi_anqpStartReceivingTestFrame()
{
    pthread_t frame_recv_tid;

    pthread_create(&frame_recv_tid, NULL, wifi_anqpTestFrameHandler, NULL);
}

int wifi_anqpStartTest(unsigned int apIndex, mac_address_t sta)
{
    int ret, sockfd;
    struct sockaddr_in sockaddr;
    unsigned char msg[1024];
    char interface_name[32];
    size_t len = 0, tlv_len = 0;
    wifi_tlv_t *tlv;
    unsigned short port = 8889;
    //All ANQP HS2 Query Types defined in RDKB-16611 and RDKB-1317
    unsigned char test_data[42] = {
        0x04, 0x0a, 0x1a, 0x6c, 0x02, 0x00, 0x00, 0x22, 0x00, 0x00, 0x01, 0x0e, 0x00, 0x01, 0x01, 0x0c, 0x01,
        0x07, 0x01, 0x08, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0xdd, 0xdd, 0x0b, 0x00, 0x50, 0x6f, 0x9a,
        0x11, 0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
    //Based on Sniffer Data
    /*unsigned char test_data[32] = {
        0x04, 0x0a, 0x1a, 0x6c, 0x02, 0x00, 0x00, 0x17, 0x00, 0x00, 0x01, 0x04, 0x00, 0x0c, 0x01, 0x07,
        0x01, 0xdd, 0xdd, 0x07, 0x00, 0x50, 0x6f, 0x9a, 0x11, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};*/

    wifi_test_command_id_t cmd = wifi_test_command_id_anqp;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error opening raw socket, err:%d\n", __func__, __LINE__, errno);
        return RETURN_ERR;
    }

    //setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_aton("127.0.0.1", &sockaddr.sin_addr);

    memcpy(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature));
    len = sizeof(wifi_common_hal_test_signature);

    tlv = (wifi_tlv_t *)&msg[sizeof(wifi_common_hal_test_signature)];

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_cmd, sizeof(wifi_test_command_id_t), (unsigned char*)&cmd);
    tlv_len += (4 + sizeof(wifi_test_command_id_t));

    sprintf(interface_name, "ath%d", apIndex);
    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, interface_name);
    tlv_len += (4 + IFNAMSIZ);

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), sta);
    tlv_len += (4 + sizeof(mac_address_t));

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, sizeof(test_data), test_data);
    tlv_len += (4 + sizeof(test_data));

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0)
    {
        wifi_anqp_dbg_print(1, "%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

    return RETURN_OK;
}
