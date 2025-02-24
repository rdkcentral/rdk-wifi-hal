/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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

/*
* hostapd - WNM
* hostapd / Radio Measurement (RRM)
* Copyright (c) 2011-2014, Qualcomm Atheros, Inc.
* Copyright(c) 2013 - 2016 Intel Mobile Communications GmbH.
* Copyright(c) 2011 - 2016 Intel Corporation. All rights reserved.
* Copyright (c) 2016-2017, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README_hostapd for more details.
*/


#include "wifi_hal_priv.h"
#include "wifi_hal_wnm_rrm.h"

/* See Table 9-112—Optional subelement IDs for Beacon report */
#define WLAN_BEACON_REPORT_SUBELEM_WIDE_BW_CHSWITCH 163

#ifndef CONFIG_USE_HOSTAP_BTM_PATCH

#define WLAN_BEACON_REQUEST_SUBELEM_WIDE_BW_CHSWITCH 163
#define MBO_IE_HEADER 6 /* type + length + oui + oui type */

/* IEEE Std 802.11-2015 - Table 8-171 - Transition and Transition Query Reasons */
enum bss_trans_mgmt_reason_code {
    WNM_BSS_TM_REASON_UNSPECIFIED = 0,
    WNM_BSS_TM_REASON_EXESSIVE_FRAME_LOSS = 1,
    WNM_BSS_TM_REASON_EXESSIVE_DELAY = 2,
    WNM_BSS_TM_REASON_TSPEC_REJECTED = 3,
    WNM_BSS_TM_REASON_FIRST_ASSOCIATION_TO_ESS = 4,
    WNM_BSS_TM_REASON_LOAD_BALANCING = 5,
    WNM_BSS_TM_REASON_BETTER_AP_FOUND = 6,
    WNM_BSS_TM_REASON_DEAUTH_FROM_PREV_AP = 7,
    WNM_BSS_TM_REASON_AP_FAILED_EAP_AUTH = 8,
    WNM_BSS_TM_REASON_AP_FAILED_4WAY_HANDSHAKE = 9,
    WNM_BSS_TM_REASON_TOO_MANY_REPLAY_COUNTER_FAILURES = 10,
    WNM_BSS_TM_REASON_TOO_MANY_MIC_FAILURES = 11,
    WNM_BSS_TM_REASON_EXCEEDED_MAX_RETRANSMISSIONS = 12,
    WNM_BSS_TM_REASON_TOO_MANY_BCAST_DISASSOCIATIONS = 13,
    WNM_BSS_TM_REASON_TOO_MANY_BCAST_DEAUTHENTICATIONS = 14,
    WNM_BSS_TM_REASON_PREVIOUS_TRANSITION_FAILED = 15,
    WNM_BSS_TM_REASON_LOW_RSSI = 16,
    WNM_BSS_TM_REASON_ROAM_FROM_NON_80211_SYSTEM = 17,
    WNM_BSS_TM_REASON_RECV_BSS_TM_REQUEST = 18,
    WNM_BSS_TM_REASON_CANDIDATE_LIST_INCLUDED = 19,
    WNM_BSS_TM_REASON_LEAVING_ESS = 20
};
#endif // CONFIG_USE_HOSTAP_BTM_PATCH

/* Compatibility with Hostapd 2.9 */
#if HOSTAPD_VERSION < 210 //2.10

/* WNM notification type (IEEE P802.11-REVmd/D3.0, Table 9-430) */
enum wnm_notification_Type {
    WNM_NOTIF_TYPE_FIRMWARE_UPDATE = 0,
    WNM_NOTIF_TYPE_BEACON_PROTECTION_FAILURE = 2,
    WNM_NOTIF_TYPE_VENDOR_SPECIFIC = 221,
};

#endif

/* ====== BTM support ====== */
typedef struct bss_tm_resp {
    u8 action; /* 8 */
    u8 dialog_token;
    u8 status_code;
    u8 bss_termination_delay;
    /* Target BSSID (optional),
        * BSS Transition Candidate List
        * Entries (optional) */
    u8 variable[];
} STRUCT_PACKED bss_tm_resp_t;

typedef struct bss_tm_query {
    u8 action; /* 6 */
    u8 dialog_token;
    u8 query_reason;
    /* BSS Transition Candidate List
        * Entries (optional) */
    u8 variable[];
} STRUCT_PACKED bss_tm_query_t;

typedef struct bss_tm_req {
    u8 action; /* 7 */
    u8 dialog_token;
    u8 req_mode;
    le16 disassoc_timer;
    u8 validity_interval;
    /* BSS Termination Duration (optional),
        * Session Information URL (optional),
        * BSS Transition Candidate List
        * Entries */
    u8 variable[];
} STRUCT_PACKED bss_tm_req_t;

typedef struct wnm_notif_req {
    u8 action; /* 26 */
    u8 dialog_token;
    u8 type;
} STRUCT_PACKED wnm_notif_req_t;


/* Implementation is based on ieee802_11_send_bss_trans_mgmt_request() from wnm_ap.c */
static int wifi_ieee802_11_send_bss_trans_mgmt_request(struct hostapd_data *hapd,
                        const u8 *addr,
                        u8 dialog_token,
                        const u8 *nei_rep, size_t nei_rep_len,
                        const u8 *mbo_attrs, size_t mbo_len)
{
    struct ieee80211_mgmt *mgmt;
    size_t len;
    u8 *pos;
    int res;

    mgmt = os_zalloc(sizeof(*mgmt) + nei_rep_len + mbo_len);
    if (mgmt == NULL)
        return -1;
    os_memcpy(mgmt->da, addr, ETH_ALEN);
    os_memcpy(mgmt->sa, hapd->own_addr, ETH_ALEN);
    os_memcpy(mgmt->bssid, hapd->own_addr, ETH_ALEN);
    mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                    WLAN_FC_STYPE_ACTION);
    mgmt->u.action.category = WLAN_ACTION_WNM;
    mgmt->u.action.u.bss_tm_req.action = WNM_BSS_TRANS_MGMT_REQ;
    mgmt->u.action.u.bss_tm_req.dialog_token = dialog_token;
    mgmt->u.action.u.bss_tm_req.req_mode = 0;
    mgmt->u.action.u.bss_tm_req.disassoc_timer = host_to_le16(0);
    mgmt->u.action.u.bss_tm_req.validity_interval = 1;
    pos = mgmt->u.action.u.bss_tm_req.variable;

    if (nei_rep) {
        mgmt->u.action.u.bss_tm_req.req_mode |= WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED;
        memcpy(pos, nei_rep, nei_rep_len);
        pos += nei_rep_len;
    }

    if (mbo_len > 0) {
        pos += mbo_add_ie(pos, mbo_len + MBO_IE_HEADER, mbo_attrs, mbo_len);
    }

    wifi_hal_dbg_print("%s:%d: WNM: Send BSS Transition Management Request to "
        MACSTR " dialog_token=%u req_mode=0x%x disassoc_timer=%u "
        "validity_interval=%u, mbo_len=%zu\n", __func__, __LINE__,
        MAC2STR(addr), dialog_token,
        mgmt->u.action.u.bss_tm_req.req_mode,
        le_to_host16(mgmt->u.action.u.bss_tm_req.disassoc_timer),
        mgmt->u.action.u.bss_tm_req.validity_interval, mbo_len);

    len = pos - &mgmt->u.action.category;
    res = hostapd_drv_send_action(hapd, hapd->iface->freq, 0,
                    mgmt->da, &mgmt->u.action.category, len);
    os_free(mgmt);
    return res;
}

/* Implementation is based on ieee802_11_rx_bss_trans_mgmt_query() */
static int handle_rx_bss_trans_mgmt_query(wifi_interface_info_t *interface,
    const mac_address_t addr, struct bss_tm_query *frm, size_t len)
{
    const u8 *pos, *end;
    int enabled;
    struct hostapd_neighbor_entry *nr;
    /* Neighbor report buffer - Maximum candidate list size assuming there are no other optional fields */
    u8 nei_rep [IEEE80211_MAX_MMPDU_SIZE - 7] = { 0 };
    size_t btm_req_nr_list_len = 0;
    wifi_BTMQuery_t *query = NULL;
    wifi_BTMRequest_t *request = NULL;
    uint num_of_candidates = 0;
    wifi_device_callbacks_t *callbacks = NULL;
    int ret = WIFI_HAL_ERROR;
    bool mutex_locked = false;
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    int ap_index = interface->vap_info.vap_index;
#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    bool wnm_bss_trans_query_auto_resp = hapd->conf->wnm_bss_trans_query_auto_resp;
#else
    bool wnm_bss_trans_query_auto_resp = interface->wnm_bss_trans_query_auto_resp;
#endif
    u8 *nei_rep_tmp = nei_rep;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    mutex_locked = true;

    enabled = hapd->conf->bss_transition;
#ifdef CONFIG_MBO
    if (hapd->conf->mbo_enabled)
        enabled = 1;
#endif /* CONFIG_MBO */

    if (!enabled) {
        wifi_hal_dbg_print("%s:%d: Ignore BSS Transition Management Query from " MACSTR
            " since BSS Transition Management is disabled\n", __func__, __LINE__, MAC2STR(addr));
        ret = WIFI_HAL_SUCCESS;
        goto exit;
    }

    if (len < sizeof(struct bss_tm_query)) {
        wifi_hal_error_print("%s:%d: WNM: Ignore too short BSS Transition Management Query from " MACSTR "\n", __func__, __LINE__, MAC2STR(addr));
        goto exit;
    }

    pos = frm->variable;
    end = ((u8*)frm) + len;

    query = calloc(1, sizeof(wifi_BTMQuery_t));
    if (!query) {
        wifi_hal_error_print("%s:%d: WNM: query's memory allocation error\n", __func__, __LINE__);
        goto exit;
    }

    request = calloc(1, sizeof(wifi_BTMRequest_t));
    if (!request) {
        wifi_hal_error_print("%s:%d: WNM: request's memory allocation error\n", __func__, __LINE__);
        goto exit;
    }

    query->token = frm->dialog_token;
    query->queryReason = frm->query_reason;

    wifi_hal_dbg_print("%s:%d: WNM: BSS Transition Management Query from " MACSTR
        " dialog_token=%u reason=%u len=%zu\n", __func__, __LINE__, MAC2STR(addr), query->token, query->queryReason, len);

    if (query->queryReason == WNM_BSS_TM_REASON_CANDIDATE_LIST_INCLUDED) {
        if (pos == end){
            wifi_hal_error_print("%s:%d: WNM: BSS Transition Management Query from " MACSTR ". "
                "Reason is set to Preferred candidate list included but no candidate list found\n", __func__, __LINE__, MAC2STR(addr));
        } else {
            int nei_element_len;

            while (pos < end) {
                wifi_NeighborReport_t *rep;

                if (num_of_candidates >= MAX_CANDIDATES)
                    break;

                if (end - pos < (1 + 1 + ETH_ALEN + 4 + 1 + 1 + 1) /* 15 */ ) {
                    wifi_hal_error_print("%s:%d: WNM: BSS TM Query, neighbor report element in candidate list is too short\n", __func__, __LINE__);
                    break;
                }

                if (*pos++ != WLAN_EID_NEIGHBOR_REPORT) {
                    wifi_hal_dbg_print("%s:%d: WNM: BSS Transition Management Query from " MACSTR ". "
                    "Expected Neighbor report Element ID\n", __func__, __LINE__, MAC2STR(addr));
                    break;
                }

                nei_element_len = *pos++;
                if (pos + nei_element_len > end) {
                    wifi_hal_dbg_print("%s:%d: WNM: BSS Transition Management Query from " MACSTR ". "
                    "Expected Neighbor report invalid\n", __func__, __LINE__, MAC2STR(addr));
                    break;
                }

                rep = &query->candidates[num_of_candidates++];
                memcpy(rep->bssid, pos, ETH_ALEN);
                pos += ETH_ALEN;
                nei_element_len -= ETH_ALEN;
                rep->info     = WPA_GET_LE32(pos);
                rep->opClass  = pos[4];
                rep->channel  = pos[5];
                rep->phyTable = pos[6];

                pos += 7;
                nei_element_len -= 7;

                /* Priority (optional sub-element) */
                if ((nei_element_len >= 3) && (*pos == WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE)) {
                    rep->bssTransitionCandidatePreferencePresent = 1;
                    rep->bssTransitionCandidatePreference.preference = pos[2];
                    pos +=3;
                    nei_element_len -=3;
                }

                /* Additional optional sub-elements may follow, skip to next candidate */
                pos += nei_element_len;
            }

            query->numCandidates = num_of_candidates;
        }
    }

    if (!wnm_bss_trans_query_auto_resp) {
        /* Unlock hostapd mutex to avoid possible deadlocks/mutual locks in callback handlers */
        mutex_locked = false;
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        callbacks = get_hal_device_callbacks();
        if (callbacks->btm_callback[ap_index].query_callback != NULL)
        {
            #ifndef WIFI_HAL_VERSION_3_PHASE2
            mac_addr_str_t sta_mac_str = "";
            to_mac_str(addr, sta_mac_str);
            if (RETURN_OK != callbacks->btm_callback[ap_index].query_callback(ap_index,
                    sta_mac_str, query, sizeof(*request), request)) {
                wifi_hal_error_print("%s:%d: BTMQueryRequestCallback failed\n", __func__, __LINE__);
                goto exit;
            }
            #else
            if (RETURN_OK != callbacks->btm_callback[ap_index].query_callback(ap_index,
                    addr, query, sizeof(*request), request)) {
                wifi_hal_error_print("%s:%d: BTMQueryRequestCallback failed\n", __func__, __LINE__);
                goto exit;
            }
            #endif

            /* Send the btm request with data received by callback call */
            if (RETURN_OK != wifi_hal_setBTMRequest(ap_index, addr, request)) {
                wifi_hal_error_print("%s:%d: wifi_setBTMRequest() failed\n", __func__, __LINE__);
                goto exit;
            }
        }
        ret = WIFI_HAL_SUCCESS;
        goto exit;
    }

    /* Add candidate list to BSS TM Request */
    dl_list_for_each(nr, &hapd->nr_db, struct hostapd_neighbor_entry, list) {
        size_t nr_len = wpabuf_len(nr->nr);

        if ((nei_rep_tmp - nei_rep) + nr_len + 2 > sizeof (nei_rep))
            break;

        *nei_rep_tmp++ = WLAN_EID_NEIGHBOR_REPORT;
        *nei_rep_tmp++ = nr_len;

        memcpy(nei_rep_tmp, wpabuf_head(nr->nr), nr_len);
        nei_rep_tmp += nr_len;
    }

    btm_req_nr_list_len = nei_rep_tmp - nei_rep;

    wifi_ieee802_11_send_bss_trans_mgmt_request(hapd, addr, query->token,
            btm_req_nr_list_len > 0 ? nei_rep : NULL, btm_req_nr_list_len,
            //mbo_len ? mbo_attributes : NULL, mbo_len);
            NULL, 0);
    ret = WIFI_HAL_SUCCESS;

exit:
    if (mutex_locked) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }

    free(query);
    free(request);
    return ret;
}

#if 0
/* Implemented in wnm_ap.c */
void ap_sta_reset_steer_flag_timer(void *eloop_ctx, void *timeout_ctx)
{
    struct hostapd_data *hapd = eloop_ctx;
    struct sta_info *sta = timeout_ctx;

    if (sta->agreed_to_steer) {
        wifi_hal_dbg_print("%s:%d: %s: Reset steering flag for STA " MACSTR "\n", __func__, __LINE__,
            hapd->conf->iface, MAC2STR(sta->addr));
        sta->agreed_to_steer = 0;
    }
}
#endif

/* Implementation is based on ieee802_11_rx_bss_trans_mgmt_resp() */
static int handle_rx_bss_trans_mgmt_resp(wifi_interface_info_t *interface,
    const mac_address_t addr, const struct bss_tm_resp *frm, size_t len)
{
    const u8 *pos, *end;
    int enabled;
    struct sta_info *sta;
    wifi_device_callbacks_t *callbacks = get_hal_device_callbacks();
    wifi_BTMResponse_t *resp = NULL;
    int ret = WIFI_HAL_ERROR;
    bool mutex_locked = false;
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    int ap_index = interface->vap_info.vap_index;

    if (NULL == callbacks->btm_callback[ap_index].response_callback)
        return WIFI_HAL_SUCCESS;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    mutex_locked = true;

    enabled = hapd->conf->bss_transition;
#ifdef CONFIG_MBO
    if (hapd->conf->mbo_enabled)
        enabled = 1;
#endif /* CONFIG_MBO */

    if (!enabled) {
        wifi_hal_dbg_print("%s:%d: Ignore BSS Transition Management Response from " MACSTR
            " since BSS Transition Management is disabled\n", __func__, __LINE__, MAC2STR(addr));
        ret = WIFI_HAL_SUCCESS;
        goto exit;
    }

    if (len < sizeof(struct bss_tm_resp)) {
        wifi_hal_error_print("%s:%d: WNM: Ignore too short BSS Transition Management Response from " MACSTR "\n", __func__, __LINE__, MAC2STR(addr));
        goto exit;
    }

    pos = frm->variable;
    end = ((u8*)frm) + len;

    resp = calloc(1, sizeof(wifi_BTMResponse_t));
    if (!resp) {
        wifi_hal_error_print("%s:%d: WNM: memory allocation error\n", __func__, __LINE__);
        goto exit;
    }
    resp->token = frm->dialog_token;
    resp->status = frm->status_code;
    resp->terminationDelay = frm->bss_termination_delay;

    wifi_hal_dbg_print("%s:%d: WNM: BSS Transition Management Response from " MACSTR
        " dialog_token=%u status_code=%u bss_termination_delay=%u\n", __func__, __LINE__, MAC2STR(addr),
            resp->token, resp->status, resp->terminationDelay);

    sta = ap_get_sta(hapd, addr);
    if (!sta) {
        wifi_hal_dbg_print("%s:%d: Station " MACSTR " not found for received BSS TM Response\n", __func__, __LINE__, MAC2STR(addr));
        ret = WIFI_HAL_SUCCESS;
        goto exit;
    }

    if (resp->status == WNM_BSS_TM_ACCEPT) {
        if (end - pos < ETH_ALEN) {
            wifi_hal_error_print("%s:%d: WNM: not enough room for Target BSSID field\n", __func__, __LINE__);
            goto exit;
        }
        sta->agreed_to_steer = 1;
        memcpy(resp->target, pos, ETH_ALEN);
        pos += ETH_ALEN;

        // - TODO: how to implement timers in OneWifi? Is it correct usage?
        //   ap_sta_reset_steer_flag_timer() is exported from wnm_ap.c
        eloop_cancel_timeout(ap_sta_reset_steer_flag_timer, hapd, sta);
        eloop_register_timeout(2, 0, ap_sta_reset_steer_flag_timer, hapd, sta);

        wifi_hal_dbg_print("%s:%d: WNM: Agreed to steer. Target BSSID: " MACSTR "\n", __func__, __LINE__, MAC2STR(resp->target));
    } else {
        sta->agreed_to_steer = 0;
        wifi_hal_dbg_print("%s:%d: WNM: Disagreed to steer.\n", __func__, __LINE__);
    }

    // - candidate list isn't supported at this moment
    // ****

    // - process callback wifi_BTMResponse_callback.
    //   This call back is invoked when a STA responds to a BTM Request from the gateway.
    //   NOTE: unlock hostapd mutex to avoid possible deadlocks/mutual locks in callback handlers.
    mutex_locked = false;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

#ifndef WIFI_HAL_VERSION_3_PHASE2
    {
        mac_addr_str_t sta_mac_str = "";
        to_mac_str(addr, sta_mac_str);
        callbacks->btm_callback[ap_index].response_callback(ap_index, sta_mac_str, resp);
    }
#else
    callbacks->btm_callback[ap_index].response_callback(ap_index, addr, resp);
#endif
    ret = WIFI_HAL_SUCCESS;

exit:
    if (mutex_locked) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }
    free(resp);
    return ret;
}

static int handle_wnm_beacon_protection_failure(wifi_interface_info_t *interface, const mac_address_t addr)
{
    struct sta_info *sta;
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);

#if HOSTAPD_VERSION >= 210 //2.10
    if (!hapd->conf->beacon_prot ||
        !(hapd->iface->drv_flags & WPA_DRIVER_FLAGS_BEACON_PROTECTION))
        goto exit;
#endif

    sta = ap_get_sta(hapd, addr);
    if (!sta || !(sta->flags & WLAN_STA_AUTHORIZED)) {
        wifi_hal_dbg_print("%s:%d: Station " MACSTR " not found for received WNM-Notification Request\n", __func__, __LINE__, MAC2STR(addr));
        goto exit;
    }

    wifi_hal_info_print("%s:%d: Beacon protection failure reported: " MACSTR "\n", __func__, __LINE__, MAC2STR(addr));

    /* Possible callback in a future */

exit:
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return WIFI_HAL_SUCCESS;
}

static int handle_rx_wnm_notification_req(wifi_interface_info_t *interface,
    const mac_address_t addr, const struct wnm_notif_req* frm, size_t len)
{
    if (len < sizeof(struct wnm_notif_req))
        return WIFI_HAL_ERROR;
    len -= sizeof(struct wnm_notif_req);

    wifi_hal_dbg_print("%s:%d: WNM: Received WNM Notification Request frame from " MACSTR " (dialog_token=%u type=%u)\n", __func__, __LINE__,
        MAC2STR(addr), frm->dialog_token, frm->type);

    switch (frm->type) {
        case WNM_NOTIF_TYPE_BEACON_PROTECTION_FAILURE:
            return handle_wnm_beacon_protection_failure(interface, addr);
        default:
            wifi_hal_dbg_print("%s:%d: WNM: Received WNM Notification Request type=%u is not supported by HAL code\n", __func__, __LINE__, frm->type);
            break;
    }
    return WIFI_HAL_UNSUPPORTED;
}

#if !defined(PLATFORM_LINUX)
int handle_wnm_action_frame(wifi_interface_info_t *interface, const mac_address_t sta, struct ieee80211_mgmt *mgmt, size_t len)
{
    u8 action;
    const u8 *payload;
    size_t plen;

    if (len < IEEE80211_HDRLEN + 2)
        return WIFI_HAL_ERROR;

    // ieee80211_hdr + category:
    payload = ((const u8 *) mgmt) + IEEE80211_HDRLEN + 1;
    action = *payload;
    plen = len - IEEE80211_HDRLEN - 1;

    switch (action) {
        case WNM_BSS_TRANS_MGMT_QUERY:
            return handle_rx_bss_trans_mgmt_query(interface, /*mgmt->sa*/ sta, (struct bss_tm_query*)payload, plen);
        case WNM_BSS_TRANS_MGMT_RESP:
            return handle_rx_bss_trans_mgmt_resp(interface, /*mgmt->sa*/ sta, (struct bss_tm_resp*)payload, plen);
        case WNM_NOTIFICATION_REQ:
            return handle_rx_wnm_notification_req(interface, /*mgmt->sa*/ sta, (struct wnm_notif_req*)payload, plen);
        default:
            wifi_hal_dbg_print("%s:%d: Received WNM action=%u is not supported by HAL code\n", __func__, __LINE__, action);
            break;
    }
    return WIFI_HAL_UNSUPPORTED;
}

/* based on hostapd_send_beacon_req() */
int wifi_rrm_send_beacon_req(wifi_interface_info_t *interface, const u8 *addr,
        u16 num_of_repetitions, u8 measurement_request_mode,
        u8 oper_class, u8 channel, u16 random_interval,
        u16 measurement_duration, u8 mode, const u8* bssid,
        struct wpa_ssid_value* ssid, u8* rep_cond, u8* rep_cond_threshold,
        u8* rep_detail, const u8* ap_ch_rep, unsigned int ap_ch_rep_len,
        const u8* req_elem, unsigned int req_elem_len, u8 *ch_width,
        u8 *ch_center_freq0, u8 *ch_center_freq1, u8 last_indication)
{
    struct wpabuf *buf;
    struct sta_info *sta = NULL;
    u8 *len;
    int ret, i;
    static const u8 wildcard_bssid[ETH_ALEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    wifi_hal_dbg_print("%s:%d: Request beacon: dest addr: " MACSTR ", mode: %d\n", __func__, __LINE__, MAC2STR(addr), mode);

    for (i = 0; i < hapd->iface->num_bss; i++) {
        sta = ap_get_sta(hapd->iface->bss[i], addr);
        if (sta) {
            hapd = hapd->iface->bss[i];
            break;
        }
    }

    if (!sta || !(sta->flags & WLAN_STA_AUTHORIZED)) {
        wifi_hal_error_print("%s:%d: Request beacon: Destination address is not connected\n", __func__, __LINE__);
        return -1;
    }

    if ((mode == BEACON_REPORT_MODE_PASSIVE &&
        !(sta->rrm_enabled_capa[0] & WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE))
        || (mode == BEACON_REPORT_MODE_ACTIVE &&
        !(sta->rrm_enabled_capa[0] & WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE))
        || (mode == BEACON_REPORT_MODE_TABLE &&
        !(sta->rrm_enabled_capa[0] & WLAN_RRM_CAPS_BEACON_REPORT_TABLE)))
    {
        wifi_hal_error_print("%s:%d: Request beacon: Destination station does not support BEACON report (mode %d) in RRM\n", __func__, __LINE__, mode);
        return -1;
    }

    if (channel == 255 && !ap_ch_rep) {
        wifi_hal_error_print("%s:%d: Request beacon: channel set to 255, but no ap channel report data provided\n", __func__, __LINE__);
        return -1;
    }

    /* Measurement request (5) + Measurement element with beacon (18) + optional sub-elements (255)*/
    buf = wpabuf_alloc(5 + 18 + 255);
    if (!buf)
        return -1;

    hapd->beacon_req_token++;
    if (!hapd->beacon_req_token) /* For wraparounds */
        hapd->beacon_req_token++;

    /* IEEE P802.11-REVmc/D5.0, 9.6.7.2 */
    wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
    wpabuf_put_u8(buf, WLAN_RRM_RADIO_MEASUREMENT_REQUEST);
    wpabuf_put_u8(buf, hapd->beacon_req_token);
    wpabuf_put_le16(buf, num_of_repetitions);

    /* IEEE P802.11-REVmc/D5.0, 9.4.2.21 */
    wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
    len = wpabuf_put(buf, 1); /* Length will be set later */

    wpabuf_put_u8(buf, hapd->beacon_req_token); /* Measurement Token */
    wpabuf_put_u8(buf, measurement_request_mode);
    wpabuf_put_u8(buf, MEASURE_TYPE_BEACON);

    /* IEEE P802.11-REVmc/D4.0, 8.4.2.20.7 */
    wpabuf_put_u8(buf, oper_class);
    wpabuf_put_u8(buf, channel);
    wpabuf_put_le16(buf, random_interval);
    wpabuf_put_le16(buf, measurement_duration);
    wpabuf_put_u8(buf, mode); /* Measurement Mode */
    if (!bssid) {
        /* use wildcard BSSID instead of a specific BSSID */
        bssid = wildcard_bssid;
    }
    wpabuf_put_data(buf, bssid, ETH_ALEN);

    /* optional sub-elements should go here */

    if (ssid) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_SSID);
        wpabuf_put_u8(buf, ssid->ssid_len);
        wpabuf_put_data(buf, ssid->ssid, ssid->ssid_len);
    }

    /*
    * Note:
    * The Beacon Reporting subelement indicates the condition for issuing a
    * Beacon report. The Beacon Reporting subelement is optionally present in
    * a Beacon request for repeated measurements; otherwise it is not present.
    * Mandatory for MBO test plan, redundant according to specifications.
    */
    if (rep_cond && *rep_cond <= 10 && rep_cond_threshold) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_INFO);
        wpabuf_put_u8(buf, 2);
        wpabuf_put_u8(buf, *rep_cond);
        wpabuf_put_u8(buf, *rep_cond_threshold);
    }

    if (rep_detail && (*rep_detail == 0 || *rep_detail == 1 || *rep_detail == 2)) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_DETAIL);
        wpabuf_put_u8(buf, 1);
        wpabuf_put_u8(buf, *rep_detail);
    }

    if (req_elem && req_elem_len) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_REQUEST);
        wpabuf_put_u8(buf, req_elem_len); /* size */
        wpabuf_put_data(buf, req_elem, req_elem_len); /* data */
    }

    /* in case channel is not 255, this IE is omitted */
    if (ap_ch_rep && ap_ch_rep_len && channel == 255) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_AP_CHANNEL);
        wpabuf_put_u8(buf, ap_ch_rep_len + 1);
        wpabuf_put_u8(buf, oper_class);
        wpabuf_put_data(buf, ap_ch_rep, ap_ch_rep_len);
    }

    if (ch_width && ch_center_freq0 && ch_center_freq1) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_WIDE_BW_CHSWITCH); /* wide bandwidth channel switch sub element id */
        wpabuf_put_u8(buf, 5);   /* sub element length */
#if HOSTAPD_VERSION >= 211 // 2.11
        wpabuf_put_u8(buf, WLAN_EID_WIDE_BW_CHSWITCH); /* wide bandwidth channel switch element id */
#else
        wpabuf_put_u8(buf, WLAN_EID_VHT_WIDE_BW_CHSWITCH); /* wide bandwidth channel switch element id */
#endif //2.11
        wpabuf_put_u8(buf, 3);   /* element length */
        wpabuf_put_u8(buf, *ch_width);
        wpabuf_put_u8(buf, *ch_center_freq0);
        wpabuf_put_u8(buf, *ch_center_freq1);
    }

    if (last_indication) {
        wpabuf_put_u8(buf, WLAN_BEACON_REQUEST_SUBELEM_LAST_INDICATION);
        wpabuf_put_u8(buf, 1); /* size */
        wpabuf_put_u8(buf, last_indication);
    }

    /* Action + measurement type + token + reps + EID + len = 7 */
    *len = wpabuf_len(buf) - 7;

    ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, addr,
                    wpabuf_head(buf), wpabuf_len(buf));
    wpabuf_free(buf);
    if (ret) {
        wifi_hal_error_print("%s:%d: hostapd_drv_send_action() error\n", __func__, __LINE__);
        return -1;
    }

    return hapd->beacon_req_token;
}
#endif

static void wifi_set_disassoc_timer(struct hostapd_data *hapd, struct sta_info *sta,
                int disassoc_timer)
{
    int timeout, beacon_int;

    /*
    * Prevent STA from reconnecting using cached PMKSA to force
    * full authentication with the authentication server (which may
    * decide to reject the connection),
    */

#if defined(VNTXER5_PORT) && (HOSTAPD_VERSION == 210) //2.10
    wpa_auth_pmksa_remove(hapd->wpa_auth, sta->addr, false);
#else
    wpa_auth_pmksa_remove(hapd->wpa_auth, sta->addr);
#endif

    beacon_int = hapd->iconf->beacon_int;
    if (beacon_int < 1)
        beacon_int = 100; /* best guess */
    /* Calculate timeout in ms based on beacon_int in TU */
    timeout = disassoc_timer * beacon_int * 128 / 125;
    wifi_hal_dbg_print("%s:%d: Disassociation timer for " MACSTR
        " set to %d ms\n", __func__, __LINE__, MAC2STR(sta->addr), timeout);

    sta->timeout_next = STA_DISASSOC_FROM_CLI;
    eloop_cancel_timeout(ap_handle_timer, hapd, sta);
    eloop_register_timeout(timeout / 1000,
                timeout % 1000 * 1000,
                ap_handle_timer, hapd, sta);
}

#if !defined(PLATFORM_LINUX)
/* Implementation is based on wnm_send_bss_tm_req() from wnm_ap.c */
int wifi_wnm_send_bss_tm_req(wifi_interface_info_t *interface, struct sta_info *sta,
            u8 dialog_token, u8 req_mode, int disassoc_timer, u8 valid_int,
            const u8 *bss_term_dur, const char *url,
            const u8 *nei_rep, size_t nei_rep_len,
            const u8 *mbo_attrs, size_t mbo_len)
{
    u8 *buf, *pos;
    struct ieee80211_mgmt *mgmt;
    size_t url_len;
    struct hostapd_data *hapd = &interface->u.ap.hapd;
#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    struct hostapd_data *intf = hapd;
#else
    wifi_interface_info_t *intf = interface;
#endif

    wifi_hal_dbg_print("%s:%d: WNM: Send BSS Transition Management Request to "
        MACSTR " dialog_token=%u req_mode=0x%x disassoc_timer=%d valid_int=0x%x\n", __func__, __LINE__,
        MAC2STR(sta->addr), dialog_token, req_mode, disassoc_timer,
        valid_int);
    buf = os_zalloc(1000 + nei_rep_len + mbo_len);
    if (buf == NULL)
        return -1;

    if (!dialog_token) {
        dialog_token = ++intf->bss_transition_token;
        if (!intf->bss_transition_token) /* For wraparounds */
            dialog_token = ++intf->bss_transition_token;
    }

    mgmt = (struct ieee80211_mgmt *) buf;
    mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                    WLAN_FC_STYPE_ACTION);
    os_memcpy(mgmt->da, sta->addr, ETH_ALEN);
    os_memcpy(mgmt->sa, hapd->own_addr, ETH_ALEN);
    os_memcpy(mgmt->bssid, hapd->own_addr, ETH_ALEN);
    mgmt->u.action.category = WLAN_ACTION_WNM;
    mgmt->u.action.u.bss_tm_req.action = WNM_BSS_TRANS_MGMT_REQ;
    mgmt->u.action.u.bss_tm_req.dialog_token = dialog_token;
    mgmt->u.action.u.bss_tm_req.req_mode = req_mode;
    mgmt->u.action.u.bss_tm_req.disassoc_timer =
        host_to_le16(disassoc_timer);
    mgmt->u.action.u.bss_tm_req.validity_interval = valid_int;

    pos = mgmt->u.action.u.bss_tm_req.variable;

    if ((req_mode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) && bss_term_dur) {
        wifi_hal_dbg_print("%s:%d: WNM: set bss_term_dur attibute\n", __func__, __LINE__);
        os_memcpy(pos, bss_term_dur, 12);
        pos += 12;
    }

    if (url) {
        /* Session Information URL */
        wifi_hal_dbg_print("%s:%d: WNM: set URL attibute\n", __func__, __LINE__);
        url_len = os_strlen(url);
        if (url_len > 255) {
            os_free(buf);
            return -1;
        }

        *pos++ = url_len;
        os_memcpy(pos, url, url_len);
        pos += url_len;
    }

    if (nei_rep) {
        os_memcpy(pos, nei_rep, nei_rep_len);
        pos += nei_rep_len;
    }

    if (mbo_len > 0) {
        pos += mbo_add_ie(pos, buf + sizeof(buf) - pos, mbo_attrs,
                mbo_len);
    }

#if HOSTAPD_VERSION >= 210 //2.10
    if (hostapd_drv_send_mlme(hapd, buf, pos - buf, 0, NULL, 0, 0) < 0) {
        wifi_hal_dbg_print("%s:%d: Failed to send BSS Transition Management Request frame\n", __func__, __LINE__);
        os_free(buf);
        return -1;
    }
#else
    if (hostapd_drv_send_mlme(hapd, buf, pos - buf, 0) < 0) {
        wifi_hal_dbg_print("%s:%d: Failed to send BSS Transition Management Request frame\n", __func__, __LINE__);
        os_free(buf);
        return -1;
    }
#endif
    os_free(buf);

    if (disassoc_timer) {
        /* send disassociation frame after time-out */
        wifi_set_disassoc_timer(hapd, sta, disassoc_timer);
    }

    return dialog_token;
}
#endif

/*************************************/

typedef struct dyn_array {
    size_t size;
    size_t capacity;
    size_t elem_size;
    char *data;
} dyn_array;

static inline void darray_init(dyn_array* array, size_t elem_size)
{
    memset(array, 0, sizeof(*array));
    array->elem_size = elem_size;
}

static inline void darray_cleanup(dyn_array* array)
{
    free(array->data);
    array->data = NULL;
    array->size = array->capacity = 0;
}

static void* darray_add(dyn_array* array)
{
    size_t new_size = array->size + 1;
    if (new_size > array->capacity) {
        // grow array twice. Initial capacity is 4 elements
        size_t new_capacity = array->capacity ? array->capacity * 2 : 4;
        char* new_data = (char*)realloc(array->data, new_capacity * array->elem_size);
        if (new_data == NULL) {
            wifi_hal_error_print("%s:%d: realloc error!\n", __func__, __LINE__);
            return NULL;
        }
        array->data = new_data;
        array->capacity = new_capacity;
    }
    array->size = new_size;
    // - return last element
    return array->data + ((new_size-1) * array->elem_size);
}

static inline void* darray_at(dyn_array* array, size_t index)
{
    return (index >= array->size) ? NULL : array->data + (index * array->elem_size);
}

static void call_BeaconReport_callback(uint ap_index, wifi_BeaconReport_t *rep, uint size, UCHAR dialog_token)
{
    wifi_device_callbacks_t *callbacks = get_hal_device_callbacks();

    if (NULL == callbacks->bcnrpt_callback[ap_index])
        return;

    if (get_bit_u8(g_DialogToken[ap_index], dialog_token)) {
        /* Call this callback only for client which initiated Beacon Request */
        UCHAR temp_dialog_token = dialog_token;
        uint arr_size = size;
        callbacks->bcnrpt_callback[ap_index](ap_index, rep, &arr_size, &temp_dialog_token);

        /* Validate results.
            Although the callback API interface assumes that the function can change the number of entries and
            the dialog token, the current implementation does not allow them to be changed. */
        if (arr_size != size || temp_dialog_token != dialog_token) {
            wifi_hal_error_print("%s:%d: incorrect implementation of callback function\n", __func__, __LINE__);
        }
    }
}

/* Implementation is based on hostapd_handle_beacon_report_response(). See 9.4.2.22.7 Beacon report */
static void handle_beacon_report_response(int ap_index, struct hostapd_data *hapd,
        u8 token, const u8 *pos, size_t len, const mac_address_t sta_addr, wifi_BeaconReport_t* rep)
{
    // const u8 *end;
    const u8 *attr;
    u8 measurement_rep_mode = 0;

    if (!rep) return;

    os_memset(rep, 0, sizeof(wifi_BeaconReport_t));
    measurement_rep_mode = pos[1];
    if (measurement_rep_mode != 0 || (len < 29)) {
        /* call callbacks with empty data */
        return;
    }

    // end = pos + len;

    rep->opClass   = pos[3];                         /* Operating Class */
    rep->channel   = pos[4];                         /* Channel Number */
    rep->startTime = WPA_GET_LE64(&pos[5]);          /* Actual Measurement Start Time (in TSF of the BSS requesting the measurement) */
    rep->duration  = WPA_GET_LE16(&pos[13]);         /* in TUs */
    rep->frameInfo = pos[15];                        /* Reported Frame Information */
    rep->rcpi      = pos[16];                        /* RCPI */
    rep->rsni      = pos[17];                        /* RSNI */
    os_memcpy(rep->bssid, &pos[18], ETH_ALEN);       /* BSSID */
    rep->antenna   = pos[24];                        /* Antenna ID */
    rep->tsf       = WPA_GET_LE32(&pos[25]);         /* Parent TSF */
    // rep.numRepetitions = ??? No such element in Radio Measurement Report frame format (see 9.6.7.3)

    attr = get_ie(&pos[29], len - 29, WLAN_BEACON_REPORT_SUBELEM_WIDE_BW_CHSWITCH);
    if (attr) {
        if (attr[1] < 3) { // 3 bytes, see below
            wifi_hal_error_print("%s:%d: beacon report wide wb channel switch corrupted\n", __func__, __LINE__);
        }
        else {
            rep->wideBandWidthChannelPresent = 1;
            rep->wideBandwidthChannel.bandwidth  = attr[2];
            rep->wideBandwidthChannel.centerSeg0 = attr[3];
            rep->wideBandwidthChannel.centerSeg1 = attr[4];
        }
    }

    return;
}

static int handle_radio_msmt_report(wifi_interface_info_t *interface, const mac_address_t sta,
                        const struct ieee80211_mgmt *mgmt, size_t len)
{
    const u8 *pos, *ie, *end;
    u8 dialog_token;
    dyn_array reps;
    wifi_BeaconReport_t *rep;
    struct hostapd_data *hapd = &interface->u.ap.hapd;
    int ap_index = interface->vap_info.vap_index;

    darray_init(&reps, sizeof(wifi_BeaconReport_t));

    end = ((u8*)mgmt) + len;
    dialog_token = mgmt->u.action.u.rrm.dialog_token;
    pos = mgmt->u.action.u.rrm.variable;

    while ((ie = get_ie(pos, end - pos, WLAN_EID_MEASURE_REPORT))) {
        if (ie[1] < 3) {
            wifi_hal_dbg_print("%s:%d: Bad Measurement Report element\n", __func__, __LINE__);
            break;
        }

        wifi_hal_dbg_print("%s:%d: Measurement report mode 0x%x type %u\n", __func__, __LINE__, ie[3], ie[4]);

        /* Report type */
        switch (ie[4]) {
            case MEASURE_TYPE_BEACON:
                /* Add a new entry to the reports array and fill it with report info */
                rep = darray_add(&reps);
                handle_beacon_report_response(ap_index, hapd, dialog_token, ie + 2, ie[1], /* mgmt->sa */ sta, rep);
                break;
            default:
                wifi_hal_dbg_print("%s:%d: Measurement report type %u is not supported by HAL code\n", __func__, __LINE__, ie[4]);
                break;
        }

        pos = ie + ie[1] + 2;
    }


    /* Pass the reports array to the callback function */
    call_BeaconReport_callback(ap_index, (wifi_BeaconReport_t*)reps.data, reps.size, dialog_token);
    darray_cleanup(&reps);
    return WIFI_HAL_SUCCESS;
}

#if !defined(PLATFORM_LINUX)
int handle_rrm_action_frame(wifi_interface_info_t *interface, const mac_address_t sta,
                    const struct ieee80211_mgmt *mgmt, size_t len, int ssi_signal)
{
    /*
    * Check for enough bytes: header + (1B)Category + (1B)Action +
    * (1B)Dialog Token.
    */
    (void)ssi_signal;

    if (len < IEEE80211_HDRLEN + 3)
        return WIFI_HAL_ERROR;

    wifi_hal_dbg_print("%s:%d: Radio measurement frame, action %u from " MACSTR "\n", __func__, __LINE__,
        mgmt->u.action.u.rrm.action, MAC2STR(mgmt->sa));

    switch (mgmt->u.action.u.rrm.action) {
        case WLAN_RRM_RADIO_MEASUREMENT_REPORT:
            return handle_radio_msmt_report(interface, sta, mgmt, len);
        default:
            wifi_hal_dbg_print("%s:%d: RRM action %u is not supported by HAL code\n", __func__, __LINE__, mgmt->u.action.u.rrm.action);
    }
    return WIFI_HAL_UNSUPPORTED;
}
#endif
