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
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "ap/dfs.h"
#ifdef CONFIG_WIFI_EMULATOR
#include "config_supplicant.h"
#endif
int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

#if defined(_PLATFORM_RASPBERRYPI_)
int notify_assoc_data(wifi_interface_info_t *interface, struct nlattr **tb,
    union wpa_event_data event)
{
    wifi_device_callbacks_t *callbacks;
    wifi_device_frame_hooks_t *hooks;
    wifi_vap_info_t *vap;
    struct nlattr *attr;
    mac_address_t sta_mac;
    mac_addr_str_t sta_mac_str;
    wifi_frame_t mgmt_frame;
    int sig_dbm = -100;
    int phy_rate = 60;
    wifi_mgmtFrameType_t mgmt_type;
    wifi_direction_t dir;
    struct ieee80211_mgmt *mgmt = NULL;
    int frame_len = 0;

    callbacks = get_hal_device_callbacks();
    hooks = get_device_frame_hooks();
    vap = &interface->vap_info;

    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute not present ... dropping\n", __func__, __LINE__);
        return -1;
    }
    memcpy(sta_mac, nla_data(attr), sizeof(mac_address_t));
    if (tb[NL80211_ATTR_RX_SIGNAL_DBM]) {
        sig_dbm = nla_get_u32(tb[NL80211_ATTR_RX_SIGNAL_DBM]);
    }
    wifi_hal_dbg_print("%s:%d: Received assoc frame from: %s\n", __func__, __LINE__,
        to_mac_str(sta_mac, sta_mac_str));
    mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_REQ;
    dir = wifi_direction_uplink;
    frame_len = IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req) + event.assoc_info.req_ies_len;
    mgmt = (struct ieee80211_mgmt *)malloc(frame_len);
    if (mgmt == NULL) {
        wifi_hal_error_print("%s:%d: Unable to allocate frame, returning\n", __func__, __LINE__);
        return -1;
    }
    memset(mgmt, 0, frame_len);
    wifi_hal_dbg_print("%s:%d: Creating ieee80211_mgmt of size: %u\n", __func__, __LINE__,
        frame_len);
    memcpy(mgmt->sa, sta_mac, sizeof(mac_address_t));
    memcpy(mgmt->da, interface->mac, sizeof(mac_address_t));
    memcpy(mgmt->bssid, interface->mac, sizeof(mac_address_t));
    memcpy(mgmt->u.assoc_req.variable, event.assoc_info.req_ies, event.assoc_info.req_ies_len);

    if (callbacks->mgmt_frame_rx_callback) {
        mgmt_frame.ap_index = vap->vap_index;
        memcpy(mgmt_frame.sta_mac, sta_mac, sizeof(mac_address_t));
        mgmt_frame.type = mgmt_type;
        mgmt_frame.dir = dir;
        mgmt_frame.sig_dbm = sig_dbm;
        mgmt_frame.len = frame_len;
        mgmt_frame.data = (unsigned char *)mgmt;
#ifdef WIFI_HAL_VERSION_3_PHASE2
        callbacks->mgmt_frame_rx_callback(vap->vap_index, &mgmt_frame);
#else
#if defined(RDK_ONEWIFI) &&                                                                     \
    (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || \
        defined(TCHCBRV2_PORT) || defined(SCXER10_PORT))
        if (tb[NL80211_ATTR_RX_PHY_RATE_INFO]) {
            phy_rate = nla_get_u32(tb[NL80211_ATTR_RX_PHY_RATE_INFO]);
        }
        callbacks->mgmt_frame_rx_callback(vap->vap_index, sta_mac, (unsigned char *)mgmt, frame_len,
            mgmt_type, dir, sig_dbm, phy_rate);
#else
        callbacks->mgmt_frame_rx_callback(vap->vap_index, sta_mac, (unsigned char *)mgmt, frame_len,
            mgmt_type, dir);
#endif
#endif

        for (unsigned int i = 0; i < hooks->num_hooks; i++) {
            if (hooks->frame_hooks_fn[i](vap->vap_index, mgmt_type) == NL_SKIP) {
                goto cleanup;
            }
        }
    }
cleanup:
    if (mgmt) {
        free(mgmt);
    }
}

static void nl80211_new_station_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    union wpa_event_data event;
    unsigned char *ies = NULL;
    size_t ies_len = 0;
    struct nlattr *attr;
    mac_address_t mac;
    mac_addr_str_t mac_str;
    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute not present ... dropping\n", __func__, __LINE__);
        return;
    }
    memcpy(mac, nla_data(attr), sizeof(mac_address_t));
    if (tb[NL80211_ATTR_IE]) {
        ies = nla_data(tb[NL80211_ATTR_IE]);
        ies_len = nla_len(tb[NL80211_ATTR_IE]);
    } else {
        wifi_hal_error_print("%s:%d:ie attribute not present\n", __func__, __LINE__);
        return;
    }
    wifi_hal_error_print("%s:%d: New station:%s, sending event: EVENT_ASSOC\n", __func__, __LINE__,
        to_mac_str(mac, mac_str));
    os_memset(&event, 0, sizeof(event));
    event.assoc_info.reassoc = 0;
    event.assoc_info.req_ies = ies;
    event.assoc_info.req_ies_len = ies_len;
    event.assoc_info.addr = mac;
    wifi_hal_dbg_print("%s:%d: New station ies_len:%zu, ies:%p\n", __func__, __LINE__, ies_len, ies);
    notify_assoc_data(interface, tb, event);
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_ASSOC, &event);
}

static void nl80211_del_station_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    union wpa_event_data event;
    struct nlattr *attr;
    mac_address_t mac;
    mac_addr_str_t mac_str;
    char br_buff[128] = {0};

    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute not present ... dropping\n", __func__, __LINE__);
        return;
    }
    memcpy(mac, nla_data(attr), sizeof(mac_address_t));
    wifi_hal_error_print("%s:%d: DEL station:%s, sending event: EVENT_DISASSOC\n", __func__, __LINE__,
        to_mac_str(mac, mac_str));

    snprintf(br_buff,sizeof(br_buff),"bridge fdb del %s dev %s master",to_mac_str(mac, mac_str),interface->name); //deleting fdb entries in bridge
    system(br_buff);
    os_memset(&event, 0, sizeof(event));
    event.disassoc_info.addr = mac;
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_DISASSOC, &event);
}
#endif

#ifdef CONFIG_WIFI_EMULATOR
static void nl80211_parse_wmm_params(struct nlattr *wmm_attr,
        struct wmm_params *wmm_params)
{
    struct nlattr *wmm_info[NL80211_STA_WME_MAX + 1];
    static struct nla_policy wme_policy[NL80211_STA_WME_MAX + 1] = {
        [NL80211_STA_WME_UAPSD_QUEUES] = { .type = NLA_U8 },
    };

    if (!wmm_attr ||
            nla_parse_nested(wmm_info, NL80211_STA_WME_MAX, wmm_attr,
                wme_policy) ||
            !wmm_info[NL80211_STA_WME_UAPSD_QUEUES])
        return;

    wmm_params->uapsd_queues =
        nla_get_u8(wmm_info[NL80211_STA_WME_UAPSD_QUEUES]);
    wmm_params->info_bitmap |= WMM_PARAMS_UAPSD_QUEUES_INFO;
}

static void nl80211_associate_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    union wpa_event_data event;
    const struct ieee80211_mgmt *mgmt;
    u16 status = 0;
    size_t len = 0;

    wifi_hal_dbg_print("%s:%d: Enter \n", __func__, __LINE__);
    if (tb[NL80211_ATTR_FRAME]) {
        len = nla_len(tb[NL80211_ATTR_FRAME]);
        mgmt = (const struct ieee80211_mgmt *) nla_data(tb[NL80211_ATTR_FRAME]);
        status = le_to_host16(mgmt->u.assoc_resp.status_code);
        if (status != WLAN_STATUS_SUCCESS) {
            os_memset(&event, 0, sizeof(event));
            event.assoc_reject.bssid = mgmt->bssid;
            if (len > 24 + sizeof(mgmt->u.assoc_resp)) {
                event.assoc_reject.resp_ies =
                    (u8 *) mgmt->u.assoc_resp.variable;
                event.assoc_reject.resp_ies_len =
                    len - 24 - sizeof(mgmt->u.assoc_resp);
            }
            event.assoc_reject.status_code = status;

            wpa_supplicant_event_wpa(&interface->wpa_s, EVENT_ASSOC_REJECT, &event);
            return;
        }
        memset(&event, 0, sizeof(event));
        event.assoc_info.resp_frame = nla_data(tb[NL80211_ATTR_FRAME]);
        event.assoc_info.resp_frame_len = nla_len(tb[NL80211_ATTR_FRAME]);
        if (len > 24 + sizeof(mgmt->u.assoc_resp)) {
            event.assoc_info.resp_ies = (u8 *) mgmt->u.assoc_resp.variable;
            event.assoc_info.resp_ies_len =
                len - 24 - sizeof(mgmt->u.assoc_resp);
        }
        if(tb[NL80211_ATTR_REQ_IE]) {
            event.assoc_info.req_ies = nla_data(tb[NL80211_ATTR_REQ_IE]);
            event.assoc_info.req_ies_len = nla_len(tb[NL80211_ATTR_REQ_IE]);
        }
        nl80211_parse_wmm_params(tb[NL80211_ATTR_STA_WME], &event.assoc_info.wmm_params);
    }
    wpa_supplicant_event_wpa(&interface->wpa_s, EVENT_ASSOC, &event);
    return;
}


static void nl80211_authenticate_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    union wpa_event_data event;
    const struct ieee80211_mgmt *mgmt;

    wifi_hal_dbg_print("%s:%d: Enter \n", __func__, __LINE__);
    if (tb[NL80211_ATTR_FRAME]) {
        mgmt = (const struct ieee80211_mgmt *) nla_data(tb[NL80211_ATTR_FRAME]);
        memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
        event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
        event.auth.auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
        event.auth.status_code = le_to_host16(mgmt->u.auth.status_code);
        size_t len = nla_len(tb[NL80211_ATTR_FRAME]);
        if (len > 24 + sizeof(mgmt->u.auth)) {
            event.auth.ies = mgmt->u.auth.variable;
            event.auth.ies_len = len - 24 - sizeof(mgmt->u.auth);
        }

    } else {
        wifi_hal_dbg_print("%s:%d: NO FRAME \n", __func__, __LINE__);
    }

    wpa_supplicant_event_wpa(&interface->wpa_s, EVENT_AUTH, &event);

    return;
}
#endif

static void nl80211_frame_tx_status_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    struct nlattr *frame, *addr, *cookie, *ack, *attr;
    union wpa_event_data event;
    const struct ieee80211_hdr *hdr;
    mac_addr_str_t  sta_mac_str;
    u16 reason = 0;
    u16 fc;
    struct sta_info *station = NULL;
    wifi_device_callbacks_t *callbacks = NULL;
    wifi_steering_event_t steering_evt;
    wifi_frame_t mgmt_frame;
    int sig_dbm = -100;
#if  (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined (TCHCBRV2_PORT) || defined(SCXER10_PORT) || defined(VNTXER5_PORT))
    int phy_rate = 60;
#endif

    wifi_mgmtFrameType_t mgmt_type = WIFI_MGMT_FRAME_TYPE_INVALID;
    wifi_vap_info_t *vap;
    wifi_direction_t dir;
    mac_address_t   sta, bmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    callbacks = get_hal_device_callbacks();

    if ((frame = tb[NL80211_ATTR_FRAME]) == NULL) {
        wifi_hal_dbg_print("%s:%d: frame attribute not present\n", __func__, __LINE__);
        return;
    }

    vap = &interface->vap_info;
    if ((addr = tb[NL80211_ATTR_MAC]) == NULL) {
        //wifi_hal_dbg_print("%s:%d: mac attribute not present\n", __func__, __LINE__);
    }

    if ((cookie = tb[NL80211_ATTR_COOKIE]) == NULL) {
        wifi_hal_dbg_print("%s:%d: cookie attribute not present\n", __func__, __LINE__);
    }

    if ((ack = tb[NL80211_ATTR_ACK]) == NULL) {
        wifi_hal_dbg_print("%s:%d: ack attribute not present\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_RX_SIGNAL_DBM]) {
        sig_dbm = nla_get_u32(tb[NL80211_ATTR_RX_SIGNAL_DBM]);
    }
#if  (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined (TCHCBRV2_PORT) || defined(VNTXER5_PORT))
    if (tb[NL80211_ATTR_RX_PHY_RATE_INFO]) {
        phy_rate = nla_get_u32(tb[NL80211_ATTR_RX_PHY_RATE_INFO]);
    }
#endif

    hdr = (const struct ieee80211_hdr *)nla_data(frame);
    fc = le_to_host16(hdr->frame_control);

    if (memcmp(hdr->addr1, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr2, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else if (memcmp(hdr->addr2, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr1, sizeof(mac_address_t));
        dir = wifi_direction_downlink;
    } else if (memcmp(hdr->addr1, bmac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, hdr->addr2, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else {
        wifi_hal_dbg_print("%s:%d: unknown interface... dropping\n", __func__, __LINE__);
        return;
    }

    os_memset(&event, 0, sizeof(event));
    event.tx_status.type = WLAN_FC_GET_TYPE(fc);
    event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
    event.tx_status.dst = hdr->addr1;
    event.tx_status.data = nla_data(frame);
    event.tx_status.data_len = nla_len(frame);
    event.tx_status.ack = ack != NULL;
#if HOSTAPD_VERSION >= 211
    event.tx_status.link_id = NL80211_DRV_LINK_ID_NA;
#endif /* HOSTAPD_VERSION >= 211 */

   if (event.tx_status.type  == WLAN_FC_TYPE_MGMT &&
     (event.tx_status.stype == WLAN_FC_STYPE_AUTH ||
        event.tx_status.stype == WLAN_FC_STYPE_ASSOC_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_REASSOC_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_DISASSOC ||
        event.tx_status.stype == WLAN_FC_STYPE_DEAUTH ||
        event.tx_status.stype == WLAN_FC_STYPE_PROBE_RESP ||
        event.tx_status.stype == WLAN_FC_STYPE_ACTION)) {

        switch(event.tx_status.stype) {
         case WLAN_FC_STYPE_AUTH:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_AUTH;
            break;

        case WLAN_FC_STYPE_ASSOC_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_RSP;
            break;

        case WLAN_FC_STYPE_REASSOC_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_REASSOC_RSP;
            break;

        case WLAN_FC_STYPE_DISASSOC:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_DISASSOC;
            wifi_hal_dbg_print("%s:%d: Received disassoc frame from: %s\n", __func__, __LINE__,
                           to_mac_str(sta, sta_mac_str));
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            station = ap_get_sta(&interface->u.ap.hapd, sta);
            if (station) {
#if !defined(PLATFORM_LINUX)
                if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                    reason = station->disconnect_reason_code;
                }
#endif
                ap_free_sta(&interface->u.ap.hapd, station);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

            for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
                if (callbacks->disassoc_cb[i] != NULL) {
                    callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
                }
            }

            if (callbacks->steering_event_callback != 0) {
                steering_evt.type = WIFI_STEERING_EVENT_CLIENT_DISCONNECT;
                steering_evt.apIndex = vap->vap_index;
                steering_evt.timestamp_ms = time(NULL);
                memcpy(steering_evt.data.disconnect.client_mac, sta, sizeof(mac_address_t));
                steering_evt.data.disconnect.reason = reason;
                steering_evt.data.disconnect.source = DISCONNECT_SOURCE_LOCAL;
                steering_evt.data.disconnect.type = DISCONNECT_TYPE_DISASSOC;

                wifi_hal_dbg_print("%s:%d: Send Client Disassoc steering event\n", __func__, __LINE__);

                callbacks->steering_event_callback(0, &steering_evt);
            }

            break;

        case WLAN_FC_STYPE_DEAUTH:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_DEAUTH;
            wifi_hal_dbg_print("%s:%d: Received deauth frame from: %s\n", __func__, __LINE__,
                           to_mac_str(sta, sta_mac_str));
            if (callbacks->num_apDeAuthEvent_cbs == 0) {
                break;
            }
            if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
                reason = nla_get_u16(attr);
            }
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            station = ap_get_sta(&interface->u.ap.hapd, sta);
            if (station) {
#if !defined(PLATFORM_LINUX)
                if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                    reason = station->disconnect_reason_code;
                    wifi_hal_info_print("reason from disconnect reason code is %d\n",reason);
                }
#endif
                ap_free_sta(&interface->u.ap.hapd, station);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

            for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
                if (callbacks->apDeAuthEvent_cb[i] != NULL) {
                   callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
                }
            }

            if (callbacks->steering_event_callback != 0) {
                steering_evt.type = WIFI_STEERING_EVENT_CLIENT_DISCONNECT;
                steering_evt.apIndex = vap->vap_index;
                steering_evt.timestamp_ms = time(NULL);
                memcpy(steering_evt.data.disconnect.client_mac, sta, sizeof(mac_address_t));
                steering_evt.data.disconnect.reason = reason;
                steering_evt.data.disconnect.source = DISCONNECT_SOURCE_LOCAL;
                steering_evt.data.disconnect.type = DISCONNECT_TYPE_DEAUTH;

                wifi_hal_dbg_print("%s:%d: Send Client Deauth steering event\n", __func__, __LINE__);

                callbacks->steering_event_callback(0, &steering_evt);
            }

            break;

        case WLAN_FC_STYPE_PROBE_RESP:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_PROBE_RSP;
            break;

        case WLAN_FC_STYPE_ACTION:
            mgmt_type = WIFI_MGMT_FRAME_TYPE_ACTION;
            break;

        default:
            break;
        }

        callbacks = get_hal_device_callbacks();
        if (callbacks->mgmt_frame_rx_callback && mgmt_type != WIFI_MGMT_FRAME_TYPE_ACTION) {
            mgmt_frame.ap_index = vap->vap_index; 
            memcpy(mgmt_frame.sta_mac, sta, sizeof(mac_address_t));
            mgmt_frame.type = mgmt_type;
            mgmt_frame.dir = dir;
            mgmt_frame.sig_dbm = sig_dbm; 
            mgmt_frame.len = event.tx_status.data_len;
            mgmt_frame.data = (unsigned char *)event.tx_status.data; 
#ifdef WIFI_HAL_VERSION_3_PHASE2
            callbacks->mgmt_frame_rx_callback(vap->vap_index, &mgmt_frame);
#else
#if defined(RDK_ONEWIFI) && (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined (TCHCBRV2_PORT) || defined(VNTXER5_PORT))
            callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)event.tx_status.data,
                event.tx_status.data_len, mgmt_type, dir, sig_dbm, phy_rate);
#else
            callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)event.tx_status.data,
                event.tx_status.data_len, mgmt_type, dir);
#endif
#endif
        }
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_TX_STATUS, &event);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

static void nl80211_new_scan_results_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    int rem;
    struct nlattr *nl;

    wifi_hal_dbg_print("%s:%d: [SCAN] new scan results for interface '%s'\n", __func__, __LINE__, interface->name);
    
    if (tb[NL80211_ATTR_SCAN_SSIDS]) {
        nla_for_each_nested(nl, tb[NL80211_ATTR_SCAN_SSIDS], rem) {
            ;//wifi_hal_dbg_print("%s:%d: Scan probed for SSID '%s'", __func__, __LINE__, nla_data(nl));
        }
    } else {
        wifi_hal_info_print("%s:%d: [SCAN] attribute scan_ssids not present\n", __func__, __LINE__);
    }

    nl80211_get_scan_results(interface);
}

static void nl80211_new_trigger_scan_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    wifi_hal_dbg_print("%s:%d: [SCAN] scan started for interface '%s'\n", __func__, __LINE__, interface->name);
}

static void nl80211_new_scan_aborted_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    wifi_hal_dbg_print("%s:%d: [SCAN] scan aborted for interface '%s'\n", __func__, __LINE__, interface->name);

    pthread_mutex_lock(&interface->scan_state_mutex);
    if (interface->scan_state != WIFI_SCAN_STATE_STARTED) {
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_dbg_print("%s:%d: [SCAN] received scan abort for scan not triggered by us\n", __func__, __LINE__);
        return;
    }
    interface->scan_state = WIFI_SCAN_STATE_ABORTED;
    pthread_mutex_unlock(&interface->scan_state_mutex);
}

void send_sta_connection_status_to_cb(unsigned char *mac, unsigned int vap_index, wifi_connection_status_t conn_status)
{
    wifi_bss_info_t bss;
    wifi_station_stats_t sta;
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();

    if ((callbacks != NULL) && (callbacks->sta_conn_status_callback)) {
        memcpy(bss.bssid, mac, sizeof(bssid_t));

        sta.vap_index = vap_index;
        sta.connect_status = conn_status;

        wifi_hal_purgeScanResult(vap_index, mac);
        callbacks->sta_conn_status_callback(vap_index, &bss, &sta);
    }
}

static void nl80211_connect_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    mac_address_t mac;
    mac_addr_str_t mac_str;
    unsigned short status;
    char *assoc_req, *assoc_rsp;
    mac_addr_str_t bssid_str;
    wifi_bss_info_t *backhaul;
    wifi_vap_security_t *sec;
    sec = &interface->vap_info.u.sta_info.security;

    backhaul = &interface->u.sta.backhaul;

    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
        to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    assoc_req = interface->u.sta.assoc_req;
    assoc_rsp = interface->u.sta.assoc_rsp;

    if (tb[NL80211_ATTR_STATUS_CODE] == NULL) {
        wifi_hal_error_print("%s:%d: status code attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy((unsigned char *)&status, nla_data(tb[NL80211_ATTR_STATUS_CODE]), nla_len(tb[NL80211_ATTR_STATUS_CODE]));
    }

    if (status != WLAN_STATUS_SUCCESS) {
        wifi_hal_error_print("%s:%d: status code unsuccessful, returning\n", __func__, __LINE__);
        send_sta_connection_status_to_cb(backhaul->bssid, interface->vap_info.vap_index, wifi_connection_status_ap_not_found);
        return;    
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy(mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
        wifi_hal_dbg_print("%s:%d: Connect indication for %s\n", __func__, __LINE__,
            to_mac_str(mac, mac_str));

    }

    if (tb[NL80211_ATTR_REQ_IE] == NULL) { 
        wifi_hal_dbg_print("%s:%d: req ie attribute absent\n", __func__, __LINE__);
    } else {
        interface->u.sta.assoc_req_len = nla_len(tb[NL80211_ATTR_REQ_IE]);
        memcpy(assoc_req, nla_data(tb[NL80211_ATTR_REQ_IE]), nla_len(tb[NL80211_ATTR_REQ_IE])); 
    }

    if (tb[NL80211_ATTR_RESP_IE] == NULL) {
        wifi_hal_dbg_print("%s:%d: resp ie attribute absent\n", __func__, __LINE__);
    } else {
        interface->u.sta.assoc_rsp_len = nla_len(tb[NL80211_ATTR_RESP_IE]);
        memcpy(assoc_rsp, nla_data(tb[NL80211_ATTR_RESP_IE]), nla_len(tb[NL80211_ATTR_RESP_IE])); 
    }

    if (tb[NL80211_ATTR_TIMED_OUT] == NULL) {
        wifi_hal_dbg_print("%s:%d: timed out attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_TIMEOUT_REASON] == NULL) {
        wifi_hal_dbg_print("%s:%d: timed out reason attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_PMK] == NULL) {
        wifi_hal_dbg_print("%s:%d: pmk attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_PMKID] == NULL) {
        wifi_hal_dbg_print("%s:%d: pmkid attribute absent\n", __func__, __LINE__);
    }

    update_wpa_sm_params(interface);

    if (sec->mode != wifi_security_mode_none) {
        update_eapol_sm_params(interface);
        eapol_sm_notify_portEnabled(interface->u.sta.wpa_sm->eapol, TRUE);
    }

    if (interface->u.sta.pending_rx_eapol) {
        struct ieee802_1x_hdr *hdr;

        hdr = (struct ieee802_1x_hdr *)(interface->u.sta.rx_eapol_buff + sizeof(struct ieee8023_hdr));

        //XXX: eapol_sm_rx_eapol
#if HOSTAPD_VERSION >= 211 //2.11
        wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&interface->u.sta.src_addr, (unsigned char *)hdr,
            interface->u.sta.buff_len - sizeof(struct ieee8023_hdr), FRAME_ENCRYPTION_UNKNOWN);
#else
        wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&interface->u.sta.src_addr, (unsigned char *)hdr,
            interface->u.sta.buff_len - sizeof(struct ieee8023_hdr));
#endif
        interface->u.sta.pending_rx_eapol = false;
    }

    if (sec->mode == wifi_security_mode_none) {
        wpa_sm_set_state(interface->u.sta.wpa_sm, WPA_COMPLETED);
    }
#ifdef CONFIG_WIFI_EMULATOR
    wpa_supplicant_cancel_auth_timeout(&interface->wpa_s);
#endif
    interface->u.sta.state = WPA_ASSOCIATED;
}

static void nl80211_disconnect_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    mac_address_t mac;
    mac_addr_str_t mac_str;
    struct nlattr *attr;

    wifi_device_callbacks_t *callbacks;
    wifi_vap_info_t *vap;
    wifi_bss_info_t bss;
    wifi_station_stats_t sta;

    vap = &interface->vap_info;
    interface->u.sta.state = WPA_DISCONNECTED;
    callbacks = get_hal_device_callbacks();

    if (callbacks->sta_conn_status_callback) {
        memcpy(bss.bssid, interface->u.sta.backhaul.bssid, sizeof(bssid_t));

        sta.vap_index = vap->vap_index;
        sta.connect_status = wifi_connection_status_disconnected;

        callbacks->sta_conn_status_callback(vap->vap_index, &bss, &sta);
    }

#ifdef CONFIG_WIFI_EMULATOR
    wpa_supplicant_cancel_auth_timeout(&interface->wpa_s);
    interface->wpa_s.disconnected = 1;
    wpa_supplicant_event_wpa(&interface->wpa_s, EVENT_DISASSOC, NULL);
#endif
    if (interface->u.sta.wpa_sm != NULL) {
        eapol_sm_deinit(interface->u.sta.wpa_sm->eapol);
        interface->u.sta.wpa_sm->eapol = NULL;

        wpa_sm_deinit(interface->u.sta.wpa_sm);
        interface->u.sta.wpa_sm = NULL;
    }

    if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
        wifi_hal_info_print("%s:%d: reason code:%d\n", __func__, __LINE__, nla_get_u16(attr));
    } else {
        wifi_hal_dbg_print("%s:%d: reason code attribute absent\n", __func__, __LINE__);
    }

    if (tb[NL80211_ATTR_MAC] == NULL) {
        wifi_hal_error_print("%s:%d: mac attribute absent\n", __func__, __LINE__);
        return;
    } else {
        memcpy(mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
        wifi_hal_dbg_print("%s:%d: Disconnect indication for %s\n", __func__, __LINE__,
            to_mac_str(mac, mac_str));

    }

    if (tb[NL80211_ATTR_DISCONNECTED_BY_AP] == NULL) {
        wifi_hal_dbg_print("%s:%d: disconnected by ap attribute absent\n", __func__, __LINE__);
    }
}

bool is_channel_supported_on_radio(wifi_freq_bands_t l_band, unsigned int channel)
{
    if ((l_band == WIFI_FREQUENCY_2_4_BAND) && (channel >= 1) && (channel <= 14)) {
        return true;
    } else if (((l_band == WIFI_FREQUENCY_5L_BAND) || (l_band == WIFI_FREQUENCY_5H_BAND) || (l_band == WIFI_FREQUENCY_5_BAND))
                    && (channel >= 36) && (channel <= 169)) {
        return true;
    } else if ((l_band == WIFI_FREQUENCY_6_BAND) && (channel >= 1) && (channel <= 233)) {
        return true;
    } else if (l_band == WIFI_FREQUENCY_60_BAND) {
        return true;
    }

    return false;
}

static void ch_switch_update_hostap_config(wifi_radio_info_t *radio, u8 channel, int op_class,
    int freq, int cf1, int cf2, int hostap_channel_width, int hal_channel_width)
{
    u8 seg0_idx = 0, seg1_idx = 0;
    struct hostapd_config *iconf = &radio->iconf;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);

    iconf->channel = channel;
#if HOSTAPD_VERSION >= 210
    iconf->op_class = op_class;
#endif
    iconf->secondary_channel = get_sec_channel_offset(radio, freq);
    ieee80211_freq_to_chan(cf1, &seg0_idx);
    ieee80211_freq_to_chan(cf2, &seg1_idx);
    hostapd_set_oper_centr_freq_seg0_idx(iconf, seg0_idx);
    hostapd_set_oper_centr_freq_seg1_idx(iconf, seg1_idx);
    hostapd_set_oper_chwidth(iconf, hostap_channel_width);

#ifdef CONFIG_IEEE80211AX
#if HOSTAPD_VERSION >= 210
    if (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND) {
        iconf->he_2ghz_40mhz_width_allowed = hal_channel_width == WIFI_CHANNELBANDWIDTH_40MHZ;
    }
#endif
#endif

    iconf->ht_capab &= ~HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    if (hal_channel_width >= WIFI_CHANNELBANDWIDTH_40MHZ) {
        iconf->ht_capab |= HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    }

    iconf->vht_capab &= ~VHT_CAP_SUPP_CHAN_WIDTH_MASK;
    if (hal_channel_width == WIFI_CHANNELBANDWIDTH_160MHZ) {
        iconf->vht_capab |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

static void nl80211_ch_switch_notify_event(wifi_interface_info_t *interface, struct nlattr **tb, wifi_chan_eventType_t wifi_chan_event_type)
{
    int ifidx = 0, freq = 0, bw = NL80211_CHAN_WIDTH_20_NOHT, cf1 = 0, cf2 = 0;
    enum nl80211_channel_type ch_type = 0;
    u8 channel;
    wifi_channel_change_event_t radio_channel_param;
    int l_channel_width, hostap_channel_width, op_class;
    enum nl80211_radar_event event_type = 0;
    wifi_radio_info_t *radio;

    wifi_hal_dbg_print("%s:%d: wifi_chan_event_type: %d interface: %s\n", __func__, __LINE__,
        wifi_chan_event_type, interface->name);

/*  XER10-530
    XER10 needs to go through 'wl' commands to enable/disable the EHT.
    It will generate a notify event from driver and the platform EHT function 
    need to know if the command is done before proceeding further.
*/
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
    bool b_bypass_callback = false;
    if (g_eht_oneshot_notify) {
        g_eht_oneshot_notify(interface);
        g_eht_oneshot_notify = NULL;
        b_bypass_callback = true;
    }
#endif

    memset(&radio_channel_param, 0, sizeof(radio_channel_param));

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    }

    if(tb[NL80211_ATTR_WIPHY_FREQ] == NULL) {
        wifi_hal_dbg_print("%s:%d: channel attribute not present\n", __func__, __LINE__);
        return;
    } else {
        freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
        ieee80211_freq_to_chan(freq, &channel);
    }

    if(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
        ch_type = nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
    }

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio && radio->oper_param.band == WIFI_FREQUENCY_6_BAND) { 
        bw = platform_get_bandwidth(interface);
    } else {
#endif
    if(tb[NL80211_ATTR_CHANNEL_WIDTH]) {
        bw = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
    }
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
    }
#endif

    if(tb[NL80211_ATTR_CENTER_FREQ1]) {
        cf1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
    }

    if(tb[NL80211_ATTR_CENTER_FREQ2]) {
        cf2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
    }
    
    if (tb[NL80211_ATTR_RADAR_EVENT]) {
        event_type = nla_get_u32(tb[NL80211_ATTR_RADAR_EVENT]);
        radio_channel_param.sub_event = (wifi_radar_eventType_t)event_type;
    }

    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: could not find radio index:%d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return;
    }

    wifi_radio_operationParam_t *radio_param;
    wifi_radio_operationParam_t tmp_radio_param;
    radio_param = &radio->oper_param;

    if (is_channel_supported_on_radio(radio_param->band, channel) != true) {
        wifi_hal_error_print("%s:%d: channel:%d and radio index:%d radio_band:%d not Compatible\n", __func__, __LINE__,
                                    channel, interface->vap_info.radio_index, radio_param->band);
        return;
    }

    switch (bw) {
    case NL80211_CHAN_WIDTH_20:
        l_channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        hostap_channel_width = CHANWIDTH_USE_HT;
        break;
    case NL80211_CHAN_WIDTH_40:
        l_channel_width = WIFI_CHANNELBANDWIDTH_40MHZ;
        hostap_channel_width = CHANWIDTH_USE_HT;
        break;
    case NL80211_CHAN_WIDTH_80:
        l_channel_width = WIFI_CHANNELBANDWIDTH_80MHZ;
        hostap_channel_width = CHANWIDTH_80MHZ;
        break;
    case NL80211_CHAN_WIDTH_160:
        l_channel_width = WIFI_CHANNELBANDWIDTH_160MHZ;
        hostap_channel_width = CHANWIDTH_160MHZ;
        break;
#ifdef CONFIG_IEEE80211BE
    case NL80211_CHAN_WIDTH_320:
        l_channel_width = WIFI_CHANNELBANDWIDTH_320MHZ;
        hostap_channel_width = CHANWIDTH_320MHZ;
        break;
#endif /* CONFIG_IEEE80211BE */
    case NL80211_CHAN_WIDTH_80P80:
        l_channel_width = WIFI_CHANNELBANDWIDTH_80_80MHZ;
        hostap_channel_width = CHANWIDTH_80P80MHZ;
        break;
    default:
        wifi_hal_info_print("%s:%d: unsupported ChanWidth: %d. set 20mhz default\n", __func__, __LINE__, bw);
        l_channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        hostap_channel_width = CHANWIDTH_USE_HT;
        break;
    }

    memcpy(&tmp_radio_param, radio_param, sizeof(wifi_radio_operationParam_t));
    tmp_radio_param.channelWidth = l_channel_width;
    tmp_radio_param.channel = channel;

    if ((op_class = get_op_class_from_radio_params(&tmp_radio_param)) == -1) {
        wifi_hal_error_print("%s:%d: failed to get op class for channel: %d, width: %d,"
            "country: %d\n", __func__, __LINE__, tmp_radio_param.channel,
            tmp_radio_param.channelWidth, tmp_radio_param.countryCode);
        return;
    }

    wifi_hal_dbg_print("%s:%d: ifidx: %d vap_name: %s radio: %d channel: %d freq: %d bandwidth: %d "
        "cf1: %d cf2: %d op class: %d channel type: %d radar event type: %d\n", __func__, __LINE__,
        ifidx, interface->vap_info.vap_name, interface->vap_info.radio_index, channel, freq, bw,
        cf1, cf2, op_class, ch_type, event_type);

    if (wifi_chan_event_type == WIFI_EVENT_CHANNELS_CHANGED) {
        radio_param->channel = channel;
        radio_param->channelWidth = l_channel_width;
        radio_param->op_class = op_class;

        ch_switch_update_hostap_config(radio, channel, op_class, freq, cf1, cf2,
            hostap_channel_width, l_channel_width);

        if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
            wifi_hal_info_print("%s:%d:csa_in_progress:%d for radio:%d\r\n", __func__,
                __LINE__, interface->u.ap.hapd.csa_in_progress, interface->vap_info.radio_index);
        }
        if (interface->vap_info.vap_mode == wifi_vap_mode_ap &&
            (interface->u.ap.hapd.csa_in_progress || interface->u.ap.hapd.iface->freq != freq)) {
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            if (interface->u.ap.hapd.iface != NULL) {
                interface->u.ap.hapd.iface->freq = freq;
            }

            if (interface->u.ap.hapd.csa_in_progress) {
                hostapd_cleanup_cs_params(&interface->u.ap.hapd);
            }

            if (interface->beacon_set) {
                ieee802_11_set_beacon(&interface->u.ap.hapd);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        }
    }

    if (wifi_chan_event_type == WIFI_EVENT_CHANNELS_CHANGED && radio->prev_channel == channel &&
        radio->prev_channelWidth == l_channel_width) {
        return;
    }
    radio->prev_channel = channel;
    radio->prev_channelWidth = l_channel_width;

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
/*  XER10-530
    No need to call the callback function when enabling or disabling EHT
*/
    if (b_bypass_callback) return;
#endif
    if ((callbacks != NULL) && (callbacks->channel_change_event_callback) && !(radio_channel_param.sub_event == WIFI_EVENT_RADAR_NOP_FINISHED)) {
        radio_channel_param.radioIndex = interface->vap_info.radio_index;
        radio_channel_param.event = wifi_chan_event_type;
        radio_channel_param.channel = channel;
        radio_channel_param.channelWidth = l_channel_width;
        radio_channel_param.op_class = op_class;
        callbacks->channel_change_event_callback(radio_channel_param);
    }

}

// This function will handle all DFS Events
static void nl80211_dfs_radar_event(wifi_interface_info_t *interface, struct nlattr **tb)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *mgt_interface;
    enum nl80211_radar_event event_type = 0;
    int freq = 5180, cf1 = 5180, cf2 = 0, bw = 0, ht_enabled = 0, chan_offset = 0, bandwidth = 0;

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed get radio for index %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return;
    }

    if (radio->oper_param.band != WIFI_FREQUENCY_5_BAND &&
        radio->oper_param.band != WIFI_FREQUENCY_5L_BAND &&
        radio->oper_param.band != WIFI_FREQUENCY_5H_BAND) {
        return;
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        mgt_interface = get_primary_interface(radio);
    }
    else {
        mgt_interface = get_private_vap_interface(radio);
    }

    if (mgt_interface == NULL) {
        wifi_hal_error_print("%s:%d failed to get primary/private interface\n", __func__, __LINE__);
        return;
    }

    if (interface != mgt_interface) {
        return;
    }

    if (!tb[NL80211_ATTR_WIPHY_FREQ] || !tb[NL80211_ATTR_RADAR_EVENT])
        return;

    if(tb[NL80211_ATTR_WIPHY_FREQ] == NULL) {
        wifi_hal_dbg_print("%s:%d: channel attribute not present\n", __func__, __LINE__);
        return;
    } else {
        freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);
    }

    if(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
        chan_offset = 0;
        ht_enabled = 1;
        switch(nla_get_u32(tb[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) ) {
            case NL80211_CHAN_NO_HT:
                ht_enabled = 0;
                break;

            case NL80211_CHAN_HT20:
                break;

            case NL80211_CHAN_HT40PLUS:
                chan_offset = 1;
                break;

            case NL80211_CHAN_HT40MINUS:
                chan_offset = -1;
                break;
        }
    }

    if(tb[NL80211_ATTR_CHANNEL_WIDTH]) {
        bw = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
        switch (bw) {
            case NL80211_CHAN_WIDTH_20_NOHT:
            case NL80211_CHAN_WIDTH_20:
                bandwidth = WIFI_CHANNELBANDWIDTH_20MHZ;
                break;

            case NL80211_CHAN_WIDTH_40:
                bandwidth = WIFI_CHANNELBANDWIDTH_40MHZ;
                break;

            case NL80211_CHAN_WIDTH_80:
                bandwidth = WIFI_CHANNELBANDWIDTH_80MHZ;
                break;

            case NL80211_CHAN_WIDTH_160:
                bandwidth = WIFI_CHANNELBANDWIDTH_160MHZ;
                break;

            default:
                bandwidth = WIFI_CHANNELBANDWIDTH_80MHZ;
                break;
        }
    }

    if(tb[NL80211_ATTR_CENTER_FREQ1]) {
        cf1 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ1]);
    }

    if(tb[NL80211_ATTR_CENTER_FREQ2]) {
        cf2 = nla_get_u32(tb[NL80211_ATTR_CENTER_FREQ2]);
    }

    if (tb[NL80211_ATTR_RADAR_EVENT]) {
        event_type = nla_get_u32(tb[NL80211_ATTR_RADAR_EVENT]);
    }

    wifi_hal_error_print("%s:%d name:%s freq:%d cf1:%d cf2:%d chan_offset:%d event_type:%d bw:%d bandwidth:%d \n", __func__, __LINE__,
                        interface->name, freq, cf1, cf2, chan_offset, event_type, bw, bandwidth);

    switch(event_type) {
        case NL80211_RADAR_DETECTED:
            nl80211_dfs_radar_detected(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        case NL80211_RADAR_CAC_FINISHED:
            nl80211_dfs_radar_cac_finished(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        case NL80211_RADAR_CAC_ABORTED:
            nl80211_dfs_radar_cac_aborted(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        case NL80211_RADAR_NOP_FINISHED:
            nl80211_dfs_nop_finished(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        case NL80211_RADAR_PRE_CAC_EXPIRED:
            nl80211_dfs_pre_cac_expired(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        case NL80211_RADAR_CAC_STARTED:
            nl80211_dfs_cac_started(interface, freq, ht_enabled, chan_offset, bandwidth, bw, cf1, cf2);
            break;

        default:
            wifi_hal_error_print("%s:%d  Unknown radar event detected\n", __FUNCTION__, __LINE__);
            break;
    }

    return ;
}

#ifdef CMXB7_PORT

#define WIFI_DRV_MAX_NR_B0          4
#define WIFI_DRV_MAX_NR             5
#define WIFI_DRV_MAX_NC             4
#define WIFI_DRV_MAX_SUB_CARRIERS   48 /* Currently only 20MHz is supported for CSI*/
#define CSI_RAW_DATA_SIZE           788
#define CSI_MATRIX_DATA_SIZE        768
#define CSI_TIMESTAMP_BIT_POS       24

typedef signed short wifi_drv_streams_rssi_t [WIFI_DRV_MAX_NR];

typedef struct _wifi_drv_frame_info {
    unsigned char           bw_mode;
    unsigned char           mcs;
    unsigned char           Nr;
    unsigned char           Nc;
    wifi_drv_streams_rssi_t nr_rssi;
    int32_t                 channel;
    unsigned short          valid_mask;
    unsigned short          phy_bw;
    unsigned short          cap_bw;
    int32_t                 num_sc;
    unsigned char           decimation;
    int16_t                 frequency_offset;
    uint64_t                time_stamp;
} __attribute__((aligned(1), packed)) wifi_drv_frame_info_t;

typedef struct _wifi_drv_csi_data_t {
    wifi_drv_frame_info_t frame_info;
    int csi_raw_data[CSI_RAW_DATA_SIZE];
} wifi_drv_csi_data_t;

typedef struct _wifi_csi_driver_nl_event_data_t {
    mac_address_t sta_addr; /* Station MAC addr */
    wifi_drv_csi_data_t csi_data;
} wifi_csi_driver_nl_event_data_t;

static inline int min(int a, int b) {
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

/*
Function    : _wlan_wifi_parse_csi_matrix
Description : This function is a parser to convert the CSI Raw Data to CSI Matrix.
The owner of this parser is PHY CSI Team.
This code is converted from Matlab Script to C code.
Wlan SW will maintain this code as it w/o changing anything.
 */
void _wlan_wifi_parse_csi_matrix(const int Data[788], int output_CSI_matrix_data[],
        int output_CSI_matrix_size[3], int *time_stamp_1,
        int *time_stamp_2, int *error_flag)
{
    int CSI_matrix_B0[768];
    int b_ants_mat[768];
    int CSI_matrix_D2[240];
    int ants_mat[240];
    unsigned int index_data_arr[4];
    int ant_num;
    int chip_type;
    int i;
    unsigned int q0;
    unsigned int qY;
    int stream_num;
    *time_stamp_1 = 0;
    *time_stamp_2 = 0;
    *error_flag = 0;
    chip_type = 0;
    memset(&CSI_matrix_B0[0], 0, 768U * sizeof(int));
    memset(&CSI_matrix_D2[0], 0, 240U * sizeof(int));
    if ((Data[0] >> 24 & 15) == 10) {
        chip_type = Data[0] & 3;
        /*  1-600B0, 2-600D2 */
        if ((chip_type != 1) && (chip_type != 2)) {
            *error_flag = 1;
        }
    } else {
        *error_flag = 1;
    }
    if (chip_type == 2) {
        /* wave600D2 */
        index_data_arr[0] = 1U;
        memset(&ants_mat[0], 0, 240U * sizeof(int));
        /*  separate the data for different antennas */
        for (chip_type = 0; chip_type < 245; chip_type++) {
            i = Data[chip_type];
            stream_num = i >> 24 & 15;
            if ((stream_num == 10) || (stream_num == 11) || (stream_num == 12) ||
                    (stream_num == 13) || (stream_num == 14)) {
                if (stream_num == 12) {
                    *time_stamp_1 = i & 65535;
                } else if (stream_num == 13) {
                    *time_stamp_2 = i & 16777215;
                }
            } else {
                ants_mat[(int)index_data_arr[0] - 1] = i & 16777215;
                qY = index_data_arr[0] + 1U;
                if (index_data_arr[0] + 1U < index_data_arr[0]) {
                    qY =  UINT32_MAX; /* replaced MAX_uint32_T with UINT32_MAX to fix compilation issue */
                }
                index_data_arr[0] = qY;
            }
        }
        /*  arrange the data in 3 dimentional matrix (number of
         * subcarriers)*5(antennas)*1(streams)  */
        for (chip_type = 0; chip_type < 48; chip_type++) {
            stream_num = chip_type * 5;
            for (i = 0; i < 5; i++) {
                CSI_matrix_D2[i + 5 * chip_type] = ants_mat[i + stream_num];
            }
        }
        output_CSI_matrix_size[0] = 5;
        output_CSI_matrix_size[1] = 1;
        output_CSI_matrix_size[2] = 48;
        memcpy_s(&output_CSI_matrix_data[0], 240U * sizeof(int), &CSI_matrix_D2[0], 240U * sizeof(int));
    } else {
        if (chip_type == 1) {
            /* wave600B0 */
            index_data_arr[0] = 1U;
            index_data_arr[1] = 1U;
            index_data_arr[2] = 1U;
            index_data_arr[3] = 1U;
            memset(&b_ants_mat[0], 0, 768U * sizeof(int));
            /*  separate the data for different antennas */
            for (chip_type = 0; chip_type < 784; chip_type++) {
                i = Data[chip_type];
                stream_num = i >> 24 & 15;
                ant_num = i >> 28 & 3;
                if ((stream_num == 10) || (stream_num == 11) || (stream_num == 12) ||
                        (stream_num == 13) || (stream_num == 14)) {
                    if (stream_num == 12) {
                        *time_stamp_1 = i & 65535;
                    } else if (stream_num == 13) {
                        *time_stamp_2 = i & 16777215;
                    }
                } else {
                    b_ants_mat[((int)index_data_arr[ant_num] + 192 * ant_num) - 1] =
                        i & 16777215;
                    q0 = index_data_arr[ant_num];
                    qY = q0 + 1U;
                    if (q0 + 1U < q0) {
                        qY =  UINT32_MAX; /* replaced MAX_uint32_T with UINT32_MAX to fix compilation issue */
                    }
                    index_data_arr[ant_num] = qY;
                }
            }
            /*  arrange the data in 3 dimentional matrix (number of
             * subcarriers)*4(antennas)*4(streams)  */
            for (chip_type = 0; chip_type < 4; chip_type++) {
                for (stream_num = 0; stream_num < 4; stream_num++) {
                    for (i = 0; i < 48; i++) {
                        CSI_matrix_B0[(chip_type + (stream_num << 2)) + (i << 4)] =
                            b_ants_mat[((i << 2) + chip_type) + 192 * stream_num];
                    }
                }
            }
        }
        output_CSI_matrix_size[0] = 4;
        output_CSI_matrix_size[1] = 4;
        output_CSI_matrix_size[2] = 48;
        memcpy_s(&output_CSI_matrix_data[0], 768U * sizeof(int), &CSI_matrix_B0[0], 768U * sizeof(int));
    }
}

#ifdef CMXB7_PORT
/* Input:  two concatenated signed 12 bit numbers
 * Output: two concatenated signed 16 bit numbers */
uint32_t _sign_extend_2x12_to_2x16(unsigned in_12_bit_numbers)
{
        int16_t num1 = (in_12_bit_numbers >> 0) & 0x000FFF;
        int16_t num2 = (in_12_bit_numbers >> 12) & 0x000FFF;

        /* sign extend 12 to 16 */
        num1 <<= 4; num1 >>= 4;
        num2 <<= 4; num2 >>= 4;

        return (uint16_t)num1 | ((uint16_t)num2 << 16);
}
#endif

static int _wlan_wifi_drv_to_hal_csi_data(wifi_csi_data_t *hal_csi, wifi_drv_csi_data_t *drv_csi)
{
    unsigned i, j, k;
    wifi_frame_info_t *hal_frame = &hal_csi->frame_info;
    wifi_drv_frame_info_t *drv_frame = &drv_csi->frame_info;
    int csi_matrix[CSI_MATRIX_DATA_SIZE] = { 0 };
    int csi_matrix_size[3] = { 0 };
    int time_stamp1, time_stamp2, csi_parsing_error = 0;

    /* frame info */
    hal_frame->bw_mode = (UCHAR)drv_frame->bw_mode;
    hal_frame->mcs = (UCHAR)drv_frame->mcs;
    hal_frame->Nr = (UCHAR)drv_frame->Nr;
    hal_frame->Nc = (UCHAR)drv_frame->Nc;

    for(i = 0; i < min(MAX_NR, WIFI_DRV_MAX_NR_B0); i++) {
        hal_frame->nr_rssi[i] = (INT)drv_frame->nr_rssi[i];
    }

    hal_frame->valid_mask = (USHORT)drv_frame->valid_mask;
    hal_frame->phy_bw = (USHORT)drv_frame->phy_bw;
    hal_frame->cap_bw = (USHORT)drv_frame->cap_bw;
    hal_frame->num_sc = (UINT)drv_frame->num_sc;
    hal_frame->decimation = (UCHAR)drv_frame->decimation;
    hal_frame->channel = (UINT)drv_frame->channel;
    hal_frame->cfo = (INT)drv_frame->frequency_offset;

    /* CSI matrix */
    _wlan_wifi_parse_csi_matrix(drv_csi->csi_raw_data, csi_matrix, csi_matrix_size, &time_stamp1, &time_stamp2, &csi_parsing_error);

    if (csi_parsing_error) {
        wifi_hal_error_print("%s:%d: Error in parsing CSI raw data \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    hal_frame->time_stamp = (((ULLONG)time_stamp1 << CSI_TIMESTAMP_BIT_POS) | (ULLONG)time_stamp2);

    for(i = 0; i < min(MAX_SUB_CARRIERS, WIFI_DRV_MAX_SUB_CARRIERS); i++) {
        for(j = 0; j < min(MAX_NR, WIFI_DRV_MAX_NR_B0); j++) {
            for(k = 0; k < min(MAX_NC, WIFI_DRV_MAX_NC); k++) {
                int index = (i*csi_matrix_size[0]*csi_matrix_size[1]) + (j * csi_matrix_size[0]) + k;
#ifdef CMXB7_PORT
                hal_csi->csi_matrix[i][j][k] = _sign_extend_2x12_to_2x16(csi_matrix[index]);
#else
                hal_csi->csi_matrix[i][j][k] = (UINT)csi_matrix[index];
#endif
            }
        }
    }
    return RETURN_OK;

    /* EVM matrix not supported */
}

void prepare_to_call_process_csi(unsigned char *data, size_t len)
{
    wifi_csi_data_t  *cli_CsiData = NULL;
    wifi_drv_csi_data_t *driver_csi = NULL;
    wifi_csi_driver_nl_event_data_t *csi_nl_data = NULL;
    cli_CsiData = calloc(1, sizeof(wifi_csi_data_t));
    csi_nl_data = (wifi_csi_driver_nl_event_data_t *)data;
    driver_csi = (wifi_drv_csi_data_t *) &(csi_nl_data->csi_data);

    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();

    wifi_hal_dbg_print("%s:%d: Vendor data len is %zu and data is %p\n", __func__, __LINE__, len, data);

    _wlan_wifi_drv_to_hal_csi_data(cli_CsiData, driver_csi);

    if (callbacks && callbacks->csi_callback) {
        callbacks->csi_callback(csi_nl_data->sta_addr, cli_CsiData);
    } else {
        wifi_hal_dbg_print("%s: wifi csi callback is NULL\n", __FUNCTION__);
    }
    free(cli_CsiData);
}

/******************************************************************************/
/*! \brief      Handle Flush station event from driver
 *
 *  \param[in]  hapd     pointer to hostapd_data
 *  \param[in]  data     pointer to data
 *  \param[in]  len      data size, 0 or 4 bytes
 *
 *  \note       \a hapd is not NULL
 *  \note       if \a len is 0, will flush all STAs, if 4, will flush STAs on BSS of index provided in \a data
 *
 *  \return     void
 */

int wifi_drv_sync_done(void* priv);
static void ltq_nl80211_handle_flush_stations(wifi_interface_info_t *interface,
                             const u8 *data, size_t len)
{
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    wifi_radio_info_t *radio = get_radio_by_rdk_index(interface->vap_info.radio_index);

    wifi_hal_dbg_print("%s:%d: nl80211: Receive LTQ vendor event:Flush Stations\n",  __func__, __LINE__);

    if (data && (len == sizeof(s32))) {
        wifi_hal_info_print("%s:%d: nl80211: LTQ vendor event: Flush Stations: flush for specific interface index not supported", __func__, __LINE__);
        return;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    interface = hash_map_get_first(radio->interface_map);
    while (interface != NULL) {
        if (interface->vap_configured)
#ifdef MXL_WIFI
            mxl_drv_event_flush_stations(&interface->u.ap.hapd, data, len);
#else
            drv_event_ltq_flush_stations(&interface->u.ap.hapd, data, len);
#endif

        interface = hash_map_get_next(radio->interface_map, interface);
    }

    wifi_drv_sync_done(hapd->drv_priv);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

void nl80211_vendor_event_ltq(wifi_interface_info_t *interface, unsigned int subcmd, unsigned char *data, size_t len)
{
    switch (subcmd) {
        case LTQ_NL80211_VENDOR_EVENT_FLUSH_STATIONS:
            ltq_nl80211_handle_flush_stations(interface, data, len);
            break;
        case LTQ_NL80211_VENDOR_EVENT_CSI_STATS:
            prepare_to_call_process_csi(data,len);
            break;
        default:
            wifi_hal_dbg_print("%s:%d: nl80211: Ignore unsupported LTQ vendor event %u\n",  __func__, __LINE__, subcmd);
            break;
    }
}

#endif // CMXB7_PORT

static void nl80211_vendor_event(wifi_interface_info_t *interface,
                    struct nlattr **tb)
{
    unsigned int vendor_id, subcmd, wiphy = 0;
    unsigned char *data = NULL;
    size_t len = 0;

    if (!tb[NL80211_ATTR_VENDOR_ID] ||
        !tb[NL80211_ATTR_VENDOR_SUBCMD])
        return;

    vendor_id = nla_get_u32(tb[NL80211_ATTR_VENDOR_ID]);
    subcmd = nla_get_u32(tb[NL80211_ATTR_VENDOR_SUBCMD]);

    if (tb[NL80211_ATTR_WIPHY])
        wiphy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);

    wifi_hal_dbg_print("%s:%d: nl80211: Vendor event: wiphy=%u vendor_id=0x%x subcmd=%u\n",
            __func__, __LINE__, wiphy, vendor_id, subcmd);

    if (tb[NL80211_ATTR_VENDOR_DATA]) {
        data = nla_data(tb[NL80211_ATTR_VENDOR_DATA]);
        len = nla_len(tb[NL80211_ATTR_VENDOR_DATA]);
       
        wifi_hal_dbg_print("%s:%d: nl80211: len %zu data %p\n", __func__, __LINE__, len, data);
    }

    switch (vendor_id) {
#ifdef CMXB7_PORT
    case OUI_LTQ:
        nl80211_vendor_event_ltq(interface, subcmd, data, len);
        break;
#endif // CMXB7_PORT
    default:
        wifi_hal_dbg_print("%s:%d: nl80211: Ignore unsupported vendor event\n", __func__, __LINE__);
        break;
    }
}

static void do_process_drv_event(wifi_interface_info_t *interface, int cmd, struct nlattr **tb)
{
    switch (cmd) {
#if defined(_PLATFORM_RASPBERRYPI_) 
    case NL80211_CMD_NEW_STATION:
        nl80211_new_station_event(interface, tb);
        break;

    case NL80211_CMD_DEL_STATION:
        nl80211_del_station_event(interface, tb);
        break;
#endif
    case NL80211_CMD_FRAME_TX_STATUS:
        nl80211_frame_tx_status_event(interface, tb);
        break;

    case NL80211_CMD_NEW_SCAN_RESULTS:
        nl80211_new_scan_results_event(interface, tb);
        break;

    case NL80211_CMD_TRIGGER_SCAN:
        nl80211_new_trigger_scan_event(interface, tb);
        break;

    case NL80211_CMD_SCAN_ABORTED:
        nl80211_new_scan_aborted_event(interface, tb);
        break;

    case NL80211_CMD_CONNECT:
        nl80211_connect_event(interface, tb);
        break;
#ifdef CONFIG_WIFI_EMULATOR
    case NL80211_CMD_AUTHENTICATE:
        nl80211_authenticate_event(interface, tb);
        break;
    case NL80211_CMD_ASSOCIATE:
        nl80211_associate_event(interface, tb);
        break;
#endif
    case NL80211_CMD_DISCONNECT:
        nl80211_disconnect_event(interface, tb);
        break;

    case NL80211_CMD_CHANNEL_SWITCH:
        break;

    case NL80211_CMD_CH_SWITCH_NOTIFY:
        nl80211_ch_switch_notify_event(interface, tb, WIFI_EVENT_CHANNELS_CHANGED);
        break;

    case NL80211_CMD_RADAR_DETECT:
        nl80211_ch_switch_notify_event(interface, tb, WIFI_EVENT_DFS_RADAR_DETECTED);
        nl80211_dfs_radar_event(interface, tb);
        break;

    case NL80211_CMD_VENDOR:
        nl80211_vendor_event(interface, tb);
        break;

   default:
        break;
    }
}

int process_global_nl80211_event(struct nl_msg *msg, void *arg)
{
    wifi_hal_priv_t *priv = (wifi_hal_priv_t *)arg;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    unsigned int ifidx = 0;
    int wiphy_idx_rx = -1;
    //unsigned long wdev_id = 0;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    //To get subtype for DFS radar event
    enum nl80211_radar_event event_type = 0;

    if (tb[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
    } else if (tb[NL80211_ATTR_WIPHY]) {
        wiphy_idx_rx = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
    }
    //else if (tb[NL80211_ATTR_WDEV]) {
      //  wdev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
    //}

    //wifi_hal_dbg_print("%s:%d:event %d for interface (ifindex %d wdev 0x%llx wiphy %d)\n",
                //__func__, __LINE__, gnlh->cmd,
                //ifidx, (long long unsigned int) wdev_id, wiphy_idx_rx);

    if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS ||
        gnlh->cmd == NL80211_CMD_TRIGGER_SCAN ||
        gnlh->cmd == NL80211_CMD_SCAN_ABORTED)
    {
        /* Special case for SCAN events - don't drop these event even if the interface is not fully configured */
        interface = get_interface_by_if_index(ifidx);
        if (interface) {
            do_process_drv_event(interface, gnlh->cmd, tb);
            return NL_SKIP;
        }
    }

    //To handle CAC Finish and CAC Abort for DFS. These event involve only the primary interface of the radio.
    if(gnlh->cmd == NL80211_CMD_RADAR_DETECT) {
        event_type = nla_get_u32(tb[NL80211_ATTR_RADAR_EVENT]);
        if( event_type == NL80211_RADAR_CAC_FINISHED || event_type == NL80211_RADAR_CAC_ABORTED ) {
            interface = get_interface_by_if_index(ifidx);
            if(interface) {
                do_process_drv_event(interface, gnlh->cmd, tb);
                return NL_SKIP;
            }
        }
    }

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if ((wiphy_idx_rx != -1) || ((ifidx == interface->index) && (interface->vap_configured == true)) ) {
                do_process_drv_event(interface, gnlh->cmd, tb);
            } else {
                //wifi_hal_dbg_print("%s:%d: Skipping event %d for foreign interface (ifindex %d wdev 0x%llx)\n", 
                    //__func__, __LINE__,
                    //gnlh->cmd,
                    //ifidx, (long long unsigned int) wdev_id);
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return NL_SKIP;
}
