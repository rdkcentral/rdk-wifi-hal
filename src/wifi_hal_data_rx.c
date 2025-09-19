/*
 * If not stated otherwise in this file or this component's LICENSE file the
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
#include "wifi_hal_rdk_framework.h"
#include "wifi_hal.h"
#include "wifi_hal_rdk.h"
#include "ieee80211.h"

#if 0
static void DumpHex(const void* data, size_t size)
{
       char ascii[17];
       size_t i, j;
       ascii[16] = '\0';
       for (i = 0; i < size; ++i) {
               wifi_rdk_hal_dbg_print("%02X ", ((unsigned char*)data)[i]);
               if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
                       ascii[i % 16] = ((unsigned char*)data)[i];
               } else {
                       ascii[i % 16] = '.';
               }
               if ((i+1) % 8 == 0 || i+1 == size) {
                       wifi_rdk_hal_dbg_print(" ");
                       if ((i+1) % 16 == 0) {
                               wifi_rdk_hal_dbg_print("|  %s \n", ascii);
                       } else if (i+1 == size) {
                               ascii[(i+1) % 16] = '\0';
                               if ((i+1) % 16 <= 8) {
                                       wifi_rdk_hal_dbg_print(" ");
                               }
                               for (j = (i+1) % 16; j < 16; ++j) {
                                       wifi_rdk_hal_dbg_print("   ");
                               }
                               wifi_rdk_hal_dbg_print("|  %s \n", ascii);
                       }
               }
       }
}
#endif

static inline unsigned short be_to_host16(unsigned short v)
{
       return ((v & 0xff) << 8) | (v >> 8);
}

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/* handle_8021x_frame will receive the l2 frame directly through RAW socket,
 * no need to handle 802.11 mac header, llc, ccmp headers.
 */
int handle_8021x_frame(INT ap_index, mac_address_t sta_mac, unsigned char *frame, UINT len, wifi_direction_t dir)
{
       wifi_8021x_frame_t *data;
       wifi_device_callbacks_t *callbacks = get_device_callbacks();
        if (callbacks == NULL) {
                return -1;
        }
       data = (wifi_8021x_frame_t *)((unsigned char *)frame + sizeof(struct ethhdr));
       len -= sizeof(struct ethhdr);
       if (callbacks->eapol_frame_rx_callback != NULL) {
               callbacks->eapol_frame_rx_callback(ap_index, sta_mac, data->type, data, len);
               return RETURN_OK;
       } else {
               wifi_rdk_hal_dbg_print("Packet is not of EAP/EAPOL type %s:%d\n", __func__, __LINE__);
               return 0;
       }
       return RETURN_OK;
}

int data_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_dataFrameType_t type, wifi_direction_t dir)
{
    if (type == WIFI_DATA_FRAME_TYPE_8021x) {
               handle_8021x_frame(ap_index, sta_mac, frame, len, dir); 
    }
    return RETURN_OK;
}

void wifi_8021x_data_tx_callback_register(wifi_sent8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_tx_callback = func;
}

void wifi_8021x_data_rx_callback_register(wifi_received8021xFrame_callback func)
{
       wifi_device_callbacks_t *callbacks;

       callbacks = get_device_callbacks();

       callbacks->eapol_frame_rx_callback = func;
}
