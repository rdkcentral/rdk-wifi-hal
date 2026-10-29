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
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <math.h>
#include <unistd.h>
#include "wifi_hal_priv.h"
#include "wifi_hal.h"

#define RETRY_LIMIT     7

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

INT wifi_sendActionFrameExt(INT apIndex, mac_address_t MacAddr, UINT frequency, UINT wait, UCHAR *frame, UINT len)
{
    int res = wifi_hal_send_mgmt_frame(apIndex, MacAddr, frame, len, frequency, wait);
    return (res == 0) ? WIFI_HAL_SUCCESS : WIFI_HAL_ERROR;
}

INT wifi_sendActionFrame(INT apIndex, mac_address_t MacAddr, UINT frequency, UCHAR *frame, UINT len)
{
    return wifi_sendActionFrameExt(apIndex, MacAddr, frequency, 0, frame, len);
}

int wifi_setQamPlus(void *radioIndex)
{
    return 0;
}

INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable)
{
    /* TODO(XE2): program DFS-at-boot via QCA driver; no-op accept for bring-up. */
    wifi_hal_dbg_print("%s:%d radioIndex=%d enable=%d (XE2 stub)\n",
                       __func__, __LINE__, radioIndex, enable);
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

INT wifi_enableCSIEngine(INT apIndex, mac_address_t sta, BOOL enable)
{
    (void)sta;
    /* TODO(XE2): wire CSI engine to QCA driver; accept for bring-up. */
    wifi_hal_dbg_print("%s:%d apIndex=%d enable=%d (XE2 stub)\n",
                      __func__, __LINE__, apIndex, enable);
    return RETURN_OK;
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

int nvram_get_current_password(char *l_password, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_current_ssid(char *l_ssid, int vap_index)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm)
{
    wifi_hal_dbg_print("%s:%d \n",__func__,__LINE__);
    return 0;
}

int platform_get_channel_bandwidth(wifi_radio_index_t index,  wifi_channelBandwidth_t *channelWidth)
{
    return 0;
}

INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    /* XE2 stub: MAC ACL not implemented yet (disable_nl80211_acl set for XE2).
     * TODO: implement via QCA cfg80211tool maccmd before MAC filtering is needed. */
    wifi_hal_dbg_print("%s:%d apIndex=%d filterMode=%d (XE2 stub)\n",
        __func__, __LINE__, apIndex, filterMode);
    return RETURN_OK;
}

/* Radio-wide ENHIND; without it the driver rejects START_AP during scans or with an unassociated STA vdev */
static void xe2_set_radio_enhind(wifi_radio_index_t index)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    char cmd[64];

    radio = get_radio_by_rdk_index(index);
    if (radio == NULL) {
        return;
    }

    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL) {
        return;
    }

    /* Not cfg80211tool: qcacommands_vap.xml has no athnewind entry */
    snprintf(cmd, sizeof(cmd), "iwpriv %s athnewind 1", interface->name);
    wifi_hal_dbg_print("%s:%d Executing %s\n", __func__, __LINE__, cmd);
    if (system(cmd) != 0) {
        wifi_hal_error_print("%s:%d: %s failed\n", __func__, __LINE__, cmd);
    }
}

int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    xe2_set_radio_enhind(index);
    return 0;
}

int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    /* Covers the first VAP on a radio: pre-create had no netdev to send it through */
    xe2_set_radio_enhind(index);
    return 0;
}
