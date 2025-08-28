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
#include <string.h>
#include "wifi_hal_rdk_framework.h"
#include "wifi_hal_rdk.h"
#include "ieee80211.h"

const char dpp_oui[3] = {0x50, 0x6f, 0x9a};

#if !defined(PLATFORM_LINUX)
#define printf wifi_dpp_dbg_print
#endif

int handle_assoc_rsp_frame(INT ap_index, mac_address_t sta_mac, unsigned char *frame, UINT len) 
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();

    if (callbacks->assoc_rsp_frame_tx_callback != NULL) {
        callbacks->assoc_rsp_frame_tx_callback(ap_index, sta_mac, frame, len);
    }
    return RETURN_OK;
}

int handle_assoc_req_frame(INT ap_index, mac_address_t sta_mac, unsigned char *frame, UINT len) 
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();

    if (callbacks->assoc_req_frame_rx_callback != NULL) {
        callbacks->assoc_req_frame_rx_callback(ap_index, sta_mac, frame, len);
    }
    return RETURN_OK;
}

int handle_auth_frame(INT ap_index, mac_address_t sta_mac, unsigned char *frame, UINT len, wifi_direction_t dir) 
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();

    if (dir == wifi_direction_downlink) {
        if (callbacks->auth_frame_tx_callback != NULL) {
            callbacks->auth_frame_tx_callback(ap_index, sta_mac, frame, len);
        }
    } else if (dir == wifi_direction_uplink) {
        if (callbacks->auth_frame_rx_callback != NULL) {
            callbacks->auth_frame_rx_callback(ap_index, sta_mac, frame, len);
        }
    }
    return RETURN_OK;
}

int handle_gas_init_public_action_frame(INT ap_index, mac_address_t sta_mac, unsigned char *public_action_data, UINT len)
{
	unsigned short query_len, *pquery_len;
	unsigned char *query_req;
	wifi_advertisementProtoElement_t *adv_proto_elem;
	wifi_advertisementProtoTuple_t *adv_tuple;
	wifi_gasInitialRequestFrame_t *pgas_req = (wifi_gasInitialRequestFrame_t *)public_action_data;

	adv_proto_elem = &pgas_req->proto_elem;	
	adv_tuple = &adv_proto_elem->proto_tuple;

	printf("%s:%d: advertisement proto element id:%d length:%d\n", __func__, __LINE__, adv_proto_elem->id, adv_proto_elem->len);

	pquery_len = (unsigned short*)((unsigned char *)&adv_proto_elem->proto_tuple + adv_proto_elem->len);
	query_len = *pquery_len;
	query_req = (unsigned char *)((unsigned char *)pquery_len + sizeof(unsigned short));

	switch (adv_tuple->adv_proto_id) {

		case wifi_adv_proto_id_vendor_specific:
			if ((adv_tuple->len == sizeof(dpp_oui) + 2) && (memcmp(adv_tuple->oui, dpp_oui, sizeof(dpp_oui)) == 0) && 
					(*(adv_tuple->oui + sizeof(dpp_oui)) == DPP_OUI_TYPE) && (*(adv_tuple->oui + sizeof(dpp_oui) + 1) == DPP_CONFPROTO)) {
				printf("%s:%d dpp gas initial req frame received callback, length:%d\n", __func__, __LINE__, query_len);
#if !defined(PLATFORM_LINUX)
   				callback_dpp_config_req_frame_received(ap_index, sta_mac, pgas_req->token, query_req, query_len);
#endif

			}
			break;

		case wifi_adv_proto_id_anqp:
			printf("%s:%d anqp gas initial req frame received call back, length:%d\n", __func__, __LINE__, query_len);
   			callback_anqp_gas_init_frame_received(ap_index, sta_mac, pgas_req->token, query_req, query_len);
			break;

		default:
			break;
	}
        return RETURN_OK;
}

int handle_vendor_public_action_frame(INT ap_index, mac_address_t sta_mac, unsigned char *public_action_data, UINT len)
{
	wifi_dppPublicActionFrameBody_t *frame;
	wifi_dppOUI *frame_oui;

	frame = (wifi_dppPublicActionFrameBody_t *)public_action_data;
	frame_oui = (wifi_dppOUI *)public_action_data;

	if ((frame != NULL) && (memcmp(frame_oui->oui, dpp_oui, sizeof(dpp_oui)) == 0) 
				&& (frame_oui->oui_type == DPP_OUI_TYPE)) {
      	printf("%s:%d callback_dpp_auth_frame_received, length:%d\n", __func__, __LINE__, len);
#if !defined(PLATFORM_LINUX)
       	callback_dpp_public_action_frame_received(ap_index, sta_mac, (wifi_dppPublicActionFrameBody_t*)public_action_data, len);
#endif
    } else {
		// not dpp frame
	}
      return RETURN_OK;
}

int	handle_public_action_frame	(INT ap_index, mac_address_t sta_mac, wifi_publicActionFrameHdr_t *ppublic_hdr, UINT len)
{
    unsigned char    *public_action_data = NULL;

	public_action_data = (unsigned char *)ppublic_hdr + sizeof(wifi_publicActionFrameHdr_t);
   
	switch (ppublic_hdr->action) { 

		case wifi_public_action_type_vendor:
			handle_vendor_public_action_frame(ap_index, sta_mac, public_action_data, len - sizeof(wifi_publicActionFrameHdr_t));
			break;

		case wifi_public_action_type_gas_init_req:
			handle_gas_init_public_action_frame(ap_index, sta_mac, public_action_data, len - sizeof(wifi_publicActionFrameHdr_t));
			break;

		case wifi_public_action_type_gas_comeback_req:
			break;

		default:
			break;
    }
    return RETURN_OK;
}

int mgmt_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_mgmtFrameType_t type, wifi_direction_t dir)
{
    wifi_actionFrameHdr_t *paction = NULL;
    if (type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
        ;
    } else if (type == WIFI_MGMT_FRAME_TYPE_ACTION) {
        paction = (wifi_actionFrameHdr_t *)frame;

		switch (paction->cat) {

			case wifi_action_frame_type_public:
				handle_public_action_frame(ap_index, sta_mac, (wifi_publicActionFrameHdr_t *)frame, len);
				break;
			default:
				break;
		}
    } else if (type == WIFI_MGMT_FRAME_TYPE_AUTH) {
        handle_auth_frame(ap_index, sta_mac, frame, len, dir);
    } else if (type == WIFI_MGMT_FRAME_TYPE_ASSOC_REQ) {
        handle_assoc_req_frame(ap_index, sta_mac, frame, len);
    } else if (type == WIFI_MGMT_FRAME_TYPE_ASSOC_RSP) {
        handle_assoc_rsp_frame(ap_index, sta_mac, frame, len);
    }
    return RETURN_OK;
}

void wifi_assoc_rsp_frame_callback_register(wifi_sentAssocRspFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_device_callbacks();
    callbacks->assoc_rsp_frame_tx_callback = func;
}
void wifi_assoc_req_frame_callback_register(wifi_receivedAssocReqFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_device_callbacks();
    callbacks->assoc_req_frame_rx_callback = func;
}
void wifi_auth_frame_tx_callback_register(wifi_sentAuthFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_device_callbacks();
    callbacks->auth_frame_tx_callback = func;
}
void wifi_auth_frame_rx_callback_register(wifi_receivedAuthFrame_callback func)
{
    wifi_device_callbacks_t *callbacks;
    callbacks = get_device_callbacks();
    callbacks->auth_frame_rx_callback = func;
}
