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
 *
 * Some material is:
 * Copyright (c) 2002-2015, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 * Licensed under the BSD-3 License
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <netlink/route/link/bridge.h>
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "wpa_auth_i.h"
#include "driver_nl80211.h"
#include "ieee802_11.h"
#include "ap/sta_info.h"
#include "ap/dfs.h"
#include "ap/wmm.h"
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/filter.h>
#include <fcntl.h>

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <semaphore.h>
#endif

#ifdef CONFIG_WIFI_EMULATOR
#include "config_supplicant.h"
#include "sme.h"
#endif

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
#include <rdk_nl80211_hal.h>
#endif

#define AP_UNABLE_TO_HANDLE_ADDITIONAL_ASSOCIATIONS 17
#define OVS_MODULE "/sys/module/openvswitch"
#define ONEWIFI_TESTSUITE_TMPFILE "/tmp/onewifi_testsuite_configured"
#define KEY_MGMT_SAE_EXT 67108864
#define MAX_MBSSID_INTERFACES 8

#ifdef WIFI_EMULATOR_CHANGE
static unsigned char eapol_qos_info[] = {0x88,0x02,0x3c,0x00,0x04,0xf0,0x21,0x5f,0x03,0x7c,0xe2,0xdb,0xd1,0xe4,0xdf,0x53,0xe2,0xdb,0xd1,0xe4,0xdf,0x53,0x10,0x00,0x05,0x00};

static unsigned char llc_info[] = {0xaa, 0xaa, 0x03, 0x00,0x00,0x00,0x88,0x8e};
#endif

static int scan_info_handler(struct nl_msg *msg, void *arg);
static int nl80211_register_mgmt_frames(wifi_interface_info_t *interface);
static void nl80211_unregister_mgmt_frames(wifi_interface_info_t *interface);

struct family_data {
    const char *group;
    int id;
};

int nl80211_send_and_recv(struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data,
             int (*valid_finish_handler)(struct nl_msg *, void *),
             void *valid_finish_data);

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
struct phy_info_arg {
    u16 *num_modes;
    struct hostapd_hw_modes *modes;
    int last_mode, last_chan_idx;
    int failed;
    u8 dfs_domain;
};
#endif

// Define the BPF filter.
struct sock_filter bpf_filter[6] = {
    //Load a Half word
    { BPF_LD | BPF_H | BPF_ABS, 0, 0, 12 },
    // Allow EAPOL
    { BPF_JMP | BPF_JEQ | BPF_K, 3, 0, ETH_P_EAPOL},
    // Allow 9001
    { BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 0x2329},
    // Allow 9002
    { BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 0x232A},
    //Reject the packet
    { BPF_RET | BPF_K, 0, 0, 0x00},
    //Accpet the packet
    { BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF },
};

struct sock_fprog bpf = { 6, bpf_filter };

#ifdef WIFI_EMULATOR_CHANGE
typedef enum {
    wlan_emu_msg_type_none,
    wlan_emu_msg_type_emu80211,
    wlan_emu_msg_type_cfg80211,
    wlan_emu_msg_type_mac80211,
    wlan_emu_msg_type_frm80211,
    wlan_emu_msg_type_webconfig
} wlan_emu_msg_type_t;
#endif

void prepare_interface_fdset(wifi_hal_priv_t *priv)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;
#ifndef EAPOL_OVER_NL
    wifi_vap_info_t *vap;
    int sock_fd;
#endif
    
    FD_ZERO(&priv->drv_rfds);
    FD_SET(priv->nl_event_fd, &priv->drv_rfds);
    FD_SET(priv->link_fd, &priv->drv_rfds);

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_configured == true && interface->bridge_configured == true) {
#ifndef EAPOL_OVER_NL
                vap = &interface->vap_info;
    		sock_fd = (vap->vap_mode == wifi_vap_mode_ap) ?
                                    interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd;
                FD_SET(sock_fd, &priv->drv_rfds);
#endif
                if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
#ifdef EAPOL_OVER_NL
                    if (interface->bss_frames_registered == 1) {
                        FD_SET(interface->bss_nl_connect_event_fd, &priv->drv_rfds);
                    }
#endif
                    if (interface->mgmt_frames_registered == 1) {
                        FD_SET(interface->nl_event_fd, &priv->drv_rfds);
                    }
                    if (interface->spurious_frames_registered == 1) {
                        FD_SET(interface->spurious_nl_event_fd, &priv->drv_rfds);
                    }
                }
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }
    eloop_sock_table_read_set_fds(&priv->drv_rfds);
}

int get_biggest_in_fdset(wifi_hal_priv_t *priv)
{
    int sock_fd = 0;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;
    int eloop_sock_fd = 0;

    sock_fd = priv->nl_event_fd > priv->link_fd ? priv->nl_event_fd : priv->link_fd;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->vap_configured == true && interface->bridge_configured == true) {
                vap = &interface->vap_info;
                if (sock_fd < ((vap->vap_mode == wifi_vap_mode_ap) ?
                        interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd)) {
                    sock_fd = (vap->vap_mode == wifi_vap_mode_ap) ?
                                    interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd;
                }
                if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
#ifdef EAPOL_OVER_NL
                    if (sock_fd < interface->bss_nl_connect_event_fd) {
                        sock_fd = interface->bss_nl_connect_event_fd;
                    }
#endif
                    if (sock_fd < interface->nl_event_fd) {
                        sock_fd = interface->nl_event_fd;
                    }
                    if (sock_fd < interface->spurious_nl_event_fd) {
                        sock_fd = interface->spurious_nl_event_fd;
                    }
                }

            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }
    eloop_sock_fd = eloop_sock_table_read_get_biggest_fd();
    if(sock_fd < eloop_sock_fd) {
        sock_fd = eloop_sock_fd;
    }
    //wifi_hal_dbg_print("%s:%d:Biggest descriptor:%d\n", __func__, __LINE__, fd);
    return sock_fd;
}

static u32 sta_flags_nl80211(int flags)
{
    u32 f = 0;

    if (flags & WPA_STA_AUTHORIZED)
        f |= BIT(NL80211_STA_FLAG_AUTHORIZED);
    if (flags & WPA_STA_WMM)
        f |= BIT(NL80211_STA_FLAG_WME);
    if (flags & WPA_STA_SHORT_PREAMBLE)
        f |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
    if (flags & WPA_STA_MFP)
        f |= BIT(NL80211_STA_FLAG_MFP);
    if (flags & WPA_STA_TDLS_PEER)
        f |= BIT(NL80211_STA_FLAG_TDLS_PEER);
    if (flags & WPA_STA_AUTHENTICATED)
        f |= BIT(NL80211_STA_FLAG_AUTHENTICATED);
    if (flags & WPA_STA_ASSOCIATED)
        f |= BIT(NL80211_STA_FLAG_ASSOCIATED);

    return f;
}

#ifdef EAPOL_OVER_NL
bool bss_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->vap_configured == true &&
                interface->vap_info.vap_mode == wifi_vap_mode_ap &&
                interface->bss_frames_registered == 1 &&
                    FD_ISSET(interface->bss_nl_connect_event_fd, &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break;
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return found;
}
#endif

bool mgmt_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->vap_configured == true &&
                interface->vap_info.vap_mode == wifi_vap_mode_ap &&
                interface->mgmt_frames_registered == 1 &&
                    FD_ISSET(interface->nl_event_fd, &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break;
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return found;
}

static bool spurious_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int i;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->vap_configured == true &&
                interface->vap_info.vap_mode == wifi_vap_mode_ap &&
                interface->spurious_frames_registered == 1 &&
                    FD_ISSET(interface->spurious_nl_event_fd, &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break;
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }

    return found;
}

bool bridge_fd_isset(wifi_hal_priv_t *priv, wifi_interface_info_t **intf)
{
    bool found = false;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned int i;

    for (i = 0; i < priv->num_radios; i++) {
        radio = &priv->radio_info[i];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            vap = &interface->vap_info;
            if ((interface->vap_configured == true) && (interface->bridge_configured == true) &&
                    FD_ISSET(((vap->vap_mode == wifi_vap_mode_ap)?
                            interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd), &priv->drv_rfds)) {
                found = true;
                *intf = interface;
                break;
            }

            interface = hash_map_get_next(radio->interface_map, interface);
        }

    }

    return found;
}

static u8 he_mcs_nss_size(const struct ieee80211_he_cap_elem *he_cap)
{
    u8 count = 4;

    if (he_cap->phy_cap_info[0] & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G) {
        count += 4;
    }

    if (he_cap->phy_cap_info[0] & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G) {
        count += 4;
    }

    return count;
}

static int get_ht_mcs_max(uint32_t mcs_set)
{
    int i;

    // We don't handle mcs_set == 0. Just return 0 in that case.
    for (i = 0; i < 32; i++) {
        // Shift right the mcs_set until no more bits
        // are set. Amount of the shifts equals to
        // the position of highest bit set to '1'. Position
        // of highest '1' determines the max supported
        // MCS. We check here only for 0-31 MCS set.
        mcs_set = mcs_set >> 1;
        if (mcs_set == 0) {
            break;
        }
    }

    return i;
}

static int get_vht_mcs_max(uint16_t rx_mcs_map)
{
    int i;
    int max_mcs = 0;

    for (i = 0; i < 8; i++) {
        switch (rx_mcs_map & 0x03)
        {
            case 0x00:
                max_mcs = max_mcs < 7 ? 7 : max_mcs;
                break;
            case 0x01:
                max_mcs = max_mcs < 8 ? 8 : max_mcs;
                break;
            case 0x02:
                max_mcs = max_mcs < 9 ? 9 : max_mcs;
                break;
            default:
                // Not supported or invalid
                break;
        }

        rx_mcs_map = rx_mcs_map >> 2;
    }

    return max_mcs;
}

static int get_vht_nss_max(uint16_t rx_mcs_map)
{
    int i;
    int number_of_spatial_streams = 0;

    for (i = 0; i < 8; i++) {
        // Set number of spatial streams for highest found valid bit pair.
        if ((rx_mcs_map & 0x03) != 0x03) {
            number_of_spatial_streams = i + 1;
        }
        rx_mcs_map = rx_mcs_map >> 2;
    }

    return number_of_spatial_streams;
}

static int get_he_mcs_max(uint16_t rx_mcs_map)
{
    int i;
    int max_mcs = 0;

    for (i = 0; i < 8; i++) {
        switch (rx_mcs_map & 0x03)
        {
            case 0x00:
                max_mcs = max_mcs < 7 ? 7 : max_mcs;
                break;
            case 0x01:
                max_mcs = max_mcs < 9 ? 9 : max_mcs;
                break;
            case 0x02:
                max_mcs = max_mcs < 11 ? 11 : max_mcs;
                break;
            default:
                // Not supported or invalid
                break;
        }

        rx_mcs_map = rx_mcs_map >> 2;
    }

    return max_mcs;
}

static int get_he_nss_max(uint16_t rx_mcs_map)
{
    int i;
    int number_of_spatial_streams = 0;

    for (i = 0; i < 8; i++) {
        // Set number of spatial streams for highest found valid bit pair.
        if ((rx_mcs_map & 0x03) != 0x03) {
            number_of_spatial_streams = i + 1;
        }
        rx_mcs_map = rx_mcs_map >> 2;
    }

    return number_of_spatial_streams;
}

static void parse_btm_supported(wifi_steering_evConnect_t *steering_event, uint32_t ext_caps)
{
    // We only check the first 4 bytes from extended capabilities
    steering_event->isBTMSupported = !!(ext_caps & IEEE80211_EXTCAPIE_BSSTRANSITION);
}

static void parse_rrm_supported(wifi_steering_evConnect_t *steering_event, uint8_t rm_cap_oct1,
    uint8_t rm_cap_oct2, uint8_t rm_cap_oct5)
{
    steering_event->rrmCaps.linkMeas = !!(rm_cap_oct1 & IEEE80211_RRM_CAPS_LINK_MEASUREMENT);
    steering_event->rrmCaps.neighRpt = !!(rm_cap_oct1 & IEEE80211_RRM_CAPS_NEIGHBOR_REPORT);
    steering_event->rrmCaps.bcnRptPassive = !!(rm_cap_oct1 & IEEE80211_RRM_CAPS_BEACON_REPORT_PASSIVE);
    steering_event->rrmCaps.bcnRptActive = !!(rm_cap_oct1 & IEEE80211_RRM_CAPS_BEACON_REPORT_ACTIVE);
    steering_event->rrmCaps.bcnRptTable = !!(rm_cap_oct1 & IEEE80211_RRM_CAPS_BEACON_REPORT_TABLE);
    steering_event->rrmCaps.lciMeas = !!(rm_cap_oct2 & IEEE80211_RRM_CAPS_LCI_MEASUREMENT);
    steering_event->rrmCaps.ftmRangeRpt = !!(rm_cap_oct5 & IEEE80211_RRM_CAPS_FTM_RANGE_REPORT);
}

static void parse_ht_cap(wifi_steering_evConnect_t *steering_event, uint16_t ht_cap_info, uint32_t mcs_set)
{
    int ht_mcs_max;
    int ht_nss_max;

    if ((ht_cap_info & IEEE80211_HTCAP_C_CHWIDTH40) && (steering_event->datarateInfo.maxChwidth < 40)) {
        steering_event->datarateInfo.maxChwidth = 40;
    }

    ht_mcs_max = get_ht_mcs_max(mcs_set);
    ht_nss_max = ht_mcs_max / 8 + 1;

    if (steering_event->datarateInfo.maxMCS < ht_mcs_max) {
        steering_event->datarateInfo.maxMCS = ht_mcs_max % 8;  // we always normalize to VHT
    }

    if (steering_event->datarateInfo.maxStreams < ht_nss_max) {
        steering_event->datarateInfo.maxStreams = ht_nss_max;
    }

    steering_event->datarateInfo.isStaticSmps = (ht_cap_info & IEEE80211_HTCAP_C_SM_MASK) == 0x00 ? 1 : 0;
}

static void parse_pwr_cap(wifi_steering_evConnect_t *steering_event, uint8_t max_tx_power)
{
    steering_event->datarateInfo.maxTxpower = max_tx_power;
}

static void parse_vht_cap(wifi_steering_evConnect_t *steering_event, uint32_t vht_info, uint16_t rx_mcs_map)
{
    int vht_max;
    int nss_max;

    steering_event->datarateInfo.maxChwidth = 80;
    if (vht_info & IEEE80211_VHTCAP_SHORTGI_160) {
        steering_event->datarateInfo.maxChwidth = 160;
    }

    vht_max = get_vht_mcs_max(rx_mcs_map);
    nss_max = get_vht_nss_max(rx_mcs_map);


    if (steering_event->datarateInfo.maxMCS < vht_max) {
        steering_event->datarateInfo.maxMCS = vht_max;
    }

    if (steering_event->datarateInfo.maxStreams < nss_max) {
        steering_event->datarateInfo.maxStreams = nss_max;
    }

    steering_event->datarateInfo.isMUMimoSupported = !!(vht_info & IEEE80211_VHTCAP_MU_BFORMEE) ||
        !!(vht_info & IEEE80211_VHTCAP_MU_BFORMER);
}

void create_connect_steering_event(wifi_interface_info_t *interface, wifi_steering_evConnect_t *steering_event,
    struct ieee80211_mgmt *mgmt, unsigned int len)
{
    wifi_radio_info_t *radio;
    ieee80211_tlv_t *he_cap_tlv = NULL;
    unsigned short he_cap_len;
    struct ieee80211_sta_he_cap sta_he_cap = {0};
    int has_vht = 0, has_ht = 0, has_he = 0;

    const struct element *elem;
    unsigned short fc, stype;
    unsigned char *l_variable = NULL;

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);

    if (radio->oper_param.band == WIFI_FREQUENCY_5_BAND) {
        steering_event->bandCap5G = 1;
    } else if (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND) {
        steering_event->bandCap2G = 1;
    }

    steering_event->datarateInfo.maxChwidth = 20;

    fc = le_to_host16(mgmt->frame_control);
    stype = WLAN_FC_GET_STYPE(fc);
    wifi_hal_info_print("%s:%d: mgmt frame stype:%d\n", __func__, __LINE__, stype);
    if (stype == WLAN_FC_STYPE_REASSOC_REQ) {
        l_variable = (unsigned char *)mgmt->u.reassoc_req.variable;
    } else {
        l_variable = (unsigned char *)mgmt->u.assoc_req.variable;
    }

    for_each_element(elem, (unsigned char *)(l_variable), len - 4) {
        switch (elem->id) {
        case WLAN_EID_EXT_CAPAB:
            parse_btm_supported(steering_event, le32toh(*(uint32_t *)elem->data));
            break;
        case WLAN_EID_RRM_ENABLED_CAPABILITIES:
            parse_rrm_supported(steering_event, elem->data[0], elem->data[1], elem->data[4]);
            if (elem->data[0] || elem->data[1] ||
                elem->data[2] || elem->data[3] || elem->data[4]) {
                steering_event->isRRMSupported = 1;
            }
            break;
        case WLAN_EID_HT_CAP:
            parse_ht_cap(steering_event, le16toh(*(uint16_t *)elem->data), le32toh(*(uint32_t *)&elem->data[3]));
            has_ht = 1;
            break;
        case WLAN_EID_VHT_CAP:
            parse_vht_cap(steering_event, le32toh(*(uint32_t *)elem->data), le16toh(*(uint16_t*)&elem->data[4]));
            has_vht = 1;
            break;
        case WLAN_EID_PWR_CAPABILITY:
            parse_pwr_cap(steering_event, elem->data[1]);
            break;
        default:
            break;
        }
    }

    /* HE */
    if (get_ie_ext_by_eid(WLAN_EID_EXT_HE_CAPABILITIES, (unsigned char *)(l_variable), len - 4,
        (unsigned char **)&he_cap_tlv, &he_cap_len) == true) {
        u8 mcs_nss_size;

        // value[0] is eid
        memcpy(&sta_he_cap.he_cap_elem, he_cap_tlv->value + 1, sizeof(sta_he_cap.he_cap_elem));
        mcs_nss_size = he_mcs_nss_size(&sta_he_cap.he_cap_elem);
        memcpy(&sta_he_cap.he_mcs_nss_supp, &he_cap_tlv->value[sizeof(sta_he_cap.he_cap_elem) + 1], mcs_nss_size);

        has_he = 1;

        if (sta_he_cap.he_cap_elem.phy_cap_info[3] & IEEE80211_HE_PHY_CAP3_SU_BEAMFORMER ||
            sta_he_cap.he_cap_elem.phy_cap_info[4] & IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE ||
            sta_he_cap.he_cap_elem.phy_cap_info[4] & IEEE80211_HE_PHY_CAP4_MU_BEAMFORMER) {
            steering_event->datarateInfo.isMUMimoSupported = 1;
        }
    }

    if (has_he) {
        steering_event->datarateInfo.phyMode = 13; /* AX */
    } else if (has_vht) {
        steering_event->datarateInfo.phyMode = 11; /* AC */
    } else if (has_ht) {
        steering_event->datarateInfo.phyMode = 4; /* N */
    } else {
        steering_event->datarateInfo.phyMode = 2; /* G */
    }

    if (he_cap_tlv != NULL) {
        u8 info = sta_he_cap.he_cap_elem.phy_cap_info[0];

        int he_max, nss_max;

        he_max = get_he_mcs_max(sta_he_cap.he_mcs_nss_supp.rx_mcs_80);
        nss_max = get_he_nss_max(sta_he_cap.he_mcs_nss_supp.rx_mcs_80);

        if (steering_event->datarateInfo.maxMCS < he_max) {
            steering_event->datarateInfo.maxMCS = he_max;
        }

        if (steering_event->datarateInfo.maxStreams < nss_max) {
            steering_event->datarateInfo.maxStreams = nss_max;
        }

        if (steering_event->bandCap2G) {
            if (info & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G && steering_event->datarateInfo.maxChwidth < 40) {
                steering_event->datarateInfo.maxChwidth = 40;
            }
        } else if (steering_event->bandCap5G) {
            if (info & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G ||
                info & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G) {
                steering_event->datarateInfo.maxChwidth = 160;

                he_max = get_he_mcs_max(sta_he_cap.he_mcs_nss_supp.rx_mcs_160);
                nss_max = get_he_nss_max(sta_he_cap.he_mcs_nss_supp.rx_mcs_160);

                if (steering_event->datarateInfo.maxMCS < he_max) {
                    steering_event->datarateInfo.maxMCS = he_max;
                }

                if (steering_event->datarateInfo.maxStreams < nss_max) {
                    steering_event->datarateInfo.maxStreams = nss_max;
                }
            } else if (info & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G &&
                steering_event->datarateInfo.maxChwidth < 80) {
                steering_event->datarateInfo.maxChwidth = 80;
            }
        }
    }
}

static void fill_steering_event_general(wifi_steering_event_t *event, wifi_steering_eventType_t type, wifi_vap_info_t *vap)
{
    event->type = type;
    event->apIndex = vap->vap_index;
    event->timestamp_ms = time(NULL);
}

static bool is_probe_req_to_our_ssid(struct ieee80211_mgmt *mgmt, unsigned int len,
    wifi_interface_info_t *interface)
{
    unsigned char *ie;
    unsigned int ie_len, ssid_len;
    char *ssid;
    int ret;

    if (memcmp(mgmt->da, interface->mac, sizeof(mac_address_t)) == 0) {
        return true;
    }

    if (len < IEEE80211_HDRLEN) {
        return false;
    }

    ie = ((unsigned char *)mgmt) + IEEE80211_HDRLEN;
    ie_len = len - IEEE80211_HDRLEN;

    ie = get_ie(ie, ie_len, WLAN_EID_SSID);
    if (ie == NULL) {
        return false;
    }

    ssid_len = ie[1];
    if (ssid_len == 0 || ssid_len > SSID_MAX_LEN) {
        return false;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    if (ssid_len != interface->u.ap.hapd.conf->ssid.ssid_len) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return false;
    }

    ssid = ie + 2;

    ret = strncmp(ssid, interface->u.ap.hapd.conf->ssid.ssid, ssid_len) == 0;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    return ret;
}

static int wifi_hal_get_radio_channel_noise(wifi_interface_info_t *interface, int *ch_noise)
{
    int radio_index = interface->vap_info.radio_index, channel;
    wifi_radio_info_t *radio;
    wifi_channelStats_t channel_stats;
    memset(&channel_stats, 0, sizeof(channel_stats));

    radio = get_radio_by_rdk_index(radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:Could not find radio index:%d\n", __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    channel = radio->oper_param.channel;
    channel_stats.ch_number = channel;
    channel_stats.ch_in_pool = true;
    if (wifi_getRadioChannelStats(radio_index, &channel_stats, 1) != RETURN_OK) {
        wifi_hal_error_print("%s:%d: Radio:%d stats get failed for channel:%d\n", __func__, __LINE__, radio_index, channel);
        return RETURN_ERR;
    } else {
        if ((channel_stats.ch_noise == 0) || (channel_stats.ch_in_pool != true)) {
            wifi_hal_error_print("%s:%d: Radio:%d stats get for channel:%d, invalid ch_noise:%d\n", __func__,
                                            __LINE__, radio_index, channel, channel_stats.ch_noise);
            return RETURN_ERR;
        }
        *ch_noise = channel_stats.ch_noise;
    }
    return RETURN_OK;
}

static void remove_station_from_other_interfaces(wifi_interface_info_t *interface, mac_address_t sta)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *iter;
    mac_addr_str_t sta_mac_str;

#ifndef FEATURE_SINGLE_PHY
    radio = get_radio_by_phy_index(interface->phy_index);
#else //FEATURE_SINGLE_PHY
    radio = get_radio_by_rdk_index(interface->rdk_radio_index);
#endif //FEATURE_SINGLE_PHY
    if (radio == NULL) {
        wifi_hal_error_print(
            "%s:%d: radio with rdk_radio_index %d is not found for interface %s (ifindex %d)\n",
            __func__, __LINE__, interface->rdk_radio_index, interface->name, interface->index);
        return;
    }

    to_mac_str(sta, sta_mac_str);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    iter = hash_map_get_first(radio->interface_map);
    while (iter != NULL) {
        if (iter->index != interface->index && iter->vap_info.vap_mode == wifi_vap_mode_ap) {
            struct sta_info *station = ap_get_sta(&iter->u.ap.hapd, sta);
            if (station) {
                wifi_hal_dbg_print("%s:%d: {phy %s (index %d), interface %s (ifindex %d)} stale sta %s on interface %s (ifindex %d)\n", __func__, __LINE__,
                                   radio->name, radio->index, interface->name, interface->index, sta_mac_str, iter->name, iter->index);
                ap_free_sta(&iter->u.ap.hapd, station);
            }
        }
        iter = hash_map_get_next(radio->interface_map, iter);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

#ifdef NL80211_ACL
bool is_core_acl_drop_mgmt_frame(wifi_interface_info_t *interface, mac_address_t sta_mac)
{
    wifi_vap_info_t *l_vap_info;
    acl_map_t *l_acl_map = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    memset(sta_mac_str, 0, sizeof(sta_mac_str));

    l_vap_info = &interface->vap_info;

    if (l_vap_info->u.bss_info.mac_filter_enable == TRUE) {
        key = to_mac_str(sta_mac, sta_mac_str);
        l_acl_map = hash_map_get(interface->acl_map, key);

        if (l_vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
            if (l_acl_map != NULL)
                return false;
        } else {
            if (l_acl_map == NULL)
                return false;
        }
        return true;
    }
    return false;
}
#endif

bool is_sta_in_blocked_state(wifi_interface_info_t *interface, mac_address_t sta_mac)
{
    wifi_vap_info_t *l_vap_info;
    acl_map_t *l_acl_map = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;

    memset(sta_mac_str, 0, sizeof(sta_mac_str));

    l_vap_info = &interface->vap_info;

    if (l_vap_info->u.bss_info.mac_filter_enable == TRUE) {
        if (l_vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
            key = to_mac_str(sta_mac, sta_mac_str);
            l_acl_map = hash_map_get(interface->acl_map, key);

            if (l_acl_map != NULL) {
                wifi_hal_dbg_print("%s:%d: MAC %s entry present in acl list\n", __func__, __LINE__, key);
                return true;
            }
        }
    }

    return false;
}

static void steering_remove_mac_filter_on_all_interfaces(mac_address_t sta_addr)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface;
    unsigned int index;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    bm_sta_list_t *bm_client_info = NULL;

    key = to_mac_str(sta_addr, sta_mac_str);
    for (index = 0; index < g_wifi_hal.num_radios; index++) {
        radio = &g_wifi_hal.radio_info[index];
        interface = hash_map_get_first(radio->interface_map);

        while (interface != NULL) {
            if (interface->bm_sta_map != NULL) {
                bm_client_info = hash_map_get(interface->bm_sta_map, key);
                if (bm_client_info != NULL && bm_client_info->type & BM_STA_TYPE_CLIENT_SET) {
                    wifi_vap_info_t *vap;
                    vap = &interface->vap_info;
                    if (wifi_steering_del_mac_list(vap->vap_index, bm_client_info) == RETURN_OK) {
                        wifi_hal_info_print("Remove MAC=%s from maclist for vap:%d\n", key, vap->vap_index);
                    }
                }
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
    }
}

static int wifi_hal_send_disconnect_steering_event(uint32_t group_index, int vap_index, mac_address_t sta_addr, wifi_mgmtFrameType_t mgmt_type, u16 reason, int source)
{
    wifi_steering_event_t steering_evt;
    wifi_device_callbacks_t *callbacks;
    mac_addr_str_t sta_mac_str;
    char *key;

    callbacks = get_hal_device_callbacks();

    if ((callbacks != NULL) && (callbacks->steering_event_callback != 0)) {
        steering_evt.type = WIFI_STEERING_EVENT_CLIENT_DISCONNECT;
        steering_evt.apIndex = vap_index;
        steering_evt.timestamp_ms = time(NULL);
        memcpy(steering_evt.data.disconnect.client_mac, sta_addr, sizeof(mac_address_t));
        steering_evt.data.disconnect.reason = reason;
        steering_evt.data.disconnect.source = source;
        key = to_mac_str(sta_addr, sta_mac_str);
        if (mgmt_type == WIFI_MGMT_FRAME_TYPE_DISASSOC) {
            wifi_hal_info_print("wifi_hal_DISASSOC:%s group_idx=%d ap_idx=%d\n", key, group_index, vap_index);
            steering_evt.data.disconnect.type = DISCONNECT_TYPE_DISASSOC;
        } else if (mgmt_type == WIFI_MGMT_FRAME_TYPE_DEAUTH) {
            steering_evt.data.disconnect.type = DISCONNECT_TYPE_DEAUTH;
            wifi_hal_info_print("wifi_hal_DEAUTH:%s group_idx=%d ap_idx=%d\n", key, group_index, vap_index);
        } else {
            wifi_hal_info_print("Wrong event:%d: sta:%s group_idx=%d ap_idx=%d\n", mgmt_type, key, group_index, vap_index);
            return RETURN_ERR;
        }
        //remove this sta mac from all interface mac filter list.
        steering_remove_mac_filter_on_all_interfaces(sta_addr);

        callbacks->steering_event_callback(group_index, &steering_evt);
        return RETURN_OK;
    }
    return RETURN_ERR;
}

bm_sta_list_t *steering_add_stalist(wifi_interface_info_t *interface, char *ssid, mac_address_t client_mac, uint8_t type)
{
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    bm_sta_list_t *bm_client_info = NULL;

    if (interface->bm_sta_map == NULL) {
        interface->bm_sta_map = hash_map_create();
        if (interface->bm_sta_map == NULL) {
            wifi_hal_error_print("%s:%d: bm sta_list map create failure for ap index %d\n", __func__,
                                            __LINE__, interface->vap_info.vap_index);
            return NULL;
        }
        wifi_hal_info_print("%s:%d: steering sta_list map:%p is created for ap_index:%d\n", __func__,
                                        __LINE__, interface->bm_sta_map, interface->vap_info.vap_index);
    }

    key = to_mac_str(client_mac, sta_mac_str);
    bm_client_info = hash_map_get(interface->bm_sta_map, key);
    if (bm_client_info == NULL) {
        bm_client_info = (bm_sta_list_t *)malloc(sizeof(bm_sta_list_t));
        if (bm_client_info == NULL) {
            wifi_hal_error_print("%s:%d: malloc failed\n", __func__, __LINE__);
            return NULL;
        }

        memset(bm_client_info, 0, sizeof(bm_sta_list_t));
        bm_client_info->vap_index = interface->vap_info.vap_index;
        memcpy(bm_client_info->mac_addr, client_mac, sizeof(mac_address_t));

        hash_map_put(interface->bm_sta_map, strdup(key), bm_client_info);
    }
    if (ssid) {
        strncpy(bm_client_info->ssid, ssid, sizeof(bm_client_info->ssid));
        bm_client_info->ssid[sizeof(bm_client_info->ssid)-1] = '\0';
    }

    if (type & BM_STA_TYPE_ASSOC) {
        bm_client_info->state = ACTIVE;
        bm_client_info->assoc_time = get_boot_time_in_sec();
        bm_client_info->active = get_boot_time_in_sec();
        bm_client_info->event_sent = 0;
    } else if (type & BM_STA_TYPE_MACLIST) {
    }

    bm_client_info->type |= type;
    wifi_hal_info_print("%s:%d: Added client:%s for interface:%s type:%d\n", __func__, __LINE__, key, interface->name, bm_client_info->type);
    return bm_client_info;
}

/* remove addr from steering stalist */
void steering_del_stalist(wifi_interface_info_t *interface, mac_address_t client_mac, uint8_t type)
{
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    bm_sta_list_t *bm_client_info = NULL, *tmp_client_info = NULL;

    if (interface->bm_sta_map != NULL) {
        key = to_mac_str(client_mac, sta_mac_str);
        bm_client_info = hash_map_get(interface->bm_sta_map, key);
        if (bm_client_info != NULL) {
            bm_client_info->type &= ~type;
            if (!bm_client_info->type) {
                wifi_hal_info_print("remove sta ssid %s, MAC=%s, assoc_time=%lu type=0x%x(%x)\n",
                                bm_client_info->ssid, key, bm_client_info->assoc_time, bm_client_info->type, type);
                tmp_client_info = hash_map_remove(interface->bm_sta_map, key);
                if (tmp_client_info != NULL) {
                    free(tmp_client_info);
                    tmp_client_info = NULL;
                }
            } else {
                wifi_hal_info_print("sta status: ssid %s, MAC=%s, assoc_time=%lu type=0x%x(%x)\n",
                                bm_client_info->ssid, key, bm_client_info->assoc_time, bm_client_info->type, type);
            }
        }
    }
}

static void wifi_hal_send_rssi_xing_event(uint32_t group_index, int ap_idx, bm_sta_list_t *sta, int rssi, int rssi_type)
{
    wifi_steering_clientConfig_t *cli_cfg;
    uint32_t high = 0, low = 0;
    int rssi_xing = 0;
    mac_addr_str_t sta_mac_str;
    wifi_device_callbacks_t *callbacks;
    wifi_steering_event_t steering_evt;

    if (sta == NULL) {
        wifi_hal_error_print(":%s:%d Err: sta is NULL\n", __func__, __LINE__);
        return;
    }

    cli_cfg = &sta->bm_client_cfg;

    switch (rssi_type) {
        case BM_STA_RSSI_PROBE:
            high = cli_cfg->rssiProbeHWM;
            low = cli_cfg->rssiProbeLWM;
            break;
        case BM_STA_RSSI_AUTH:
            high = cli_cfg->rssiAuthHWM;
            low = cli_cfg->rssiAuthLWM;
            break;
        case BM_STA_RSSI_INACTIVE:
            break;
        case BM_STA_RSSI_XING:
            high = cli_cfg->rssiHighXing;
            low = cli_cfg->rssiLowXing;
        break;
        default:
            wifi_hal_error_print("%s:%d:Err: wrong rssi type %d\n", __func__, __LINE__, rssi_type);
            return;
    }

    wifi_hal_dbg_print("Check RSSI for %s rssi=%d high=%d low=%d type=%d\n",
                to_mac_str(sta->mac_addr, sta_mac_str), rssi, high, low, rssi_type);

    /* compare rssi and send event */
    if (rssi_type == BM_STA_RSSI_INACTIVE) {
        rssi_xing = 1;
        steering_evt.data.rssiXing.inactveXing = WIFI_STEERING_RSSI_HIGHER;
        steering_evt.data.rssiXing.highXing = WIFI_STEERING_RSSI_UNCHANGED;
        steering_evt.data.rssiXing.lowXing = WIFI_STEERING_RSSI_UNCHANGED;
    } else {
        steering_evt.data.rssiXing.inactveXing = WIFI_STEERING_RSSI_UNCHANGED;
        if (rssi > high) {
            steering_evt.data.rssiXing.highXing = WIFI_STEERING_RSSI_HIGHER;
            rssi_xing = 1;
        } else {
            steering_evt.data.rssiXing.highXing = WIFI_STEERING_RSSI_UNCHANGED;
        }

        if (rssi < low) {
            steering_evt.data.rssiXing.lowXing = WIFI_STEERING_RSSI_LOWER;
            rssi_xing = 1;
        } else {
            steering_evt.data.rssiXing.lowXing = WIFI_STEERING_RSSI_UNCHANGED;
        }
    }

    wifi_hal_dbg_print("send_rssi_xing_event: g_idx=%d ap_idx=%d, Client-MAC=%s rssi_xing=%d\n",
                group_index, ap_idx, to_mac_str(sta->mac_addr, sta_mac_str), rssi_xing);

    callbacks = get_hal_device_callbacks();
    if (rssi_xing) {
        steering_evt.type = WIFI_STEERING_EVENT_RSSI_XING;
        steering_evt.apIndex = ap_idx;
        steering_evt.timestamp_ms = time(NULL);

        /* parameter */
        memcpy(steering_evt.data.rssiXing.client_mac, sta->mac_addr, sizeof(mac_address_t));
        steering_evt.data.rssiXing.rssi = rssi;

        callbacks->steering_event_callback(group_index, &steering_evt);
    }
}

static void handle_assoc_req_event_for_bm(wifi_interface_info_t *interface, struct ieee80211_mgmt *mgmt, unsigned int len, mac_address_t client_mac)
{
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    unsigned char *ie;
    unsigned int ie_len, ssid_len = 0, g_idx = 0;
    char ssid[SSID_MAX_LEN];
    bm_sta_list_t *sta_info = NULL;
    wifi_vap_info_t *vap;
    wifi_device_callbacks_t *callbacks;
    wifi_steering_event_t steering_evt;

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap || vap->u.bss_info.enabled != true) {
        wifi_hal_error_print("%s:%d: vap is not enabled:%s vap_mode:%d\n", __func__, __LINE__, vap->vap_name, vap->vap_mode);
        return;
    }

    if (len < IEEE80211_HDRLEN) {
        return;
    }

    ie = ((unsigned char *)mgmt) + IEEE80211_HDRLEN;
    ie_len = len - IEEE80211_HDRLEN;

    ie = get_ie(ie, ie_len, WLAN_EID_SSID);
    if (ie == NULL) {
        wifi_hal_error_print("%s:%d: vap:%s assoc ie ssid is not found\n", __func__, __LINE__, vap->vap_name);
    } else {
        ssid_len = ie[1];
        if (ssid_len < sizeof(ssid)) {
            strncpy(ssid, (char*)(ie + 2), ssid_len);
            ssid[ssid_len] = '\0';
        }
    }

    key = to_mac_str(client_mac, sta_mac_str);
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    sta_info = hash_map_get(interface->bm_sta_map, key);
    if (sta_info) {
        /* the sta may be a pre-configured client */
        wifi_hal_info_print("Existing STA: MAC=%s assoc_time=%lu disassoc_time=%lu state=%d type=0x%x\n",
                                   key, sta_info->assoc_time, sta_info->disassoc_time, sta_info->state, sta_info->type);
        if ((sta_info->disassoc_time > 0) && (sta_info->state == INACTIVE)) {
            sta_info->disassoc_time = 0;
        }
    }
    /* always call add_stalist to update info (type, assoc_time etc.) */
    sta_info = steering_add_stalist(interface, ssid, client_mac, BM_STA_TYPE_ASSOC);
    if (sta_info == NULL) {
        wifi_hal_error_print("Fail to get the sta MAC=%s after adding it to list\n", key);
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
        return;
    }
    if (steering_find_ap_cfg(sta_info->vap_index, &g_idx) == NULL) {
        wifi_hal_error_print("AP Config for vap:%d is not found\n", sta_info->vap_index);
    }
    callbacks = get_hal_device_callbacks();
    if (callbacks->steering_event_callback != 0 && vap->u.bss_info.security.mode == wifi_security_mode_none) {
        wifi_steering_evConnect_t connect_steering_event = {0};

        create_connect_steering_event(interface, &connect_steering_event, mgmt, len);

        fill_steering_event_general(&steering_evt, WIFI_STEERING_EVENT_CLIENT_CONNECT, vap);
        steering_evt.data.connect = connect_steering_event;
        memcpy(steering_evt.data.connect.client_mac, client_mac, sizeof(mac_address_t));

        wifi_hal_dbg_print("%s:%d: Send Client Connect steering event\n", __func__, __LINE__);
        callbacks->steering_event_callback(g_idx, &steering_evt);
        sta_info->event_sent |= BM_SENT_E_ASSOC;
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
}

static void handle_disconnect_event_for_bm(wifi_interface_info_t *interface, mac_address_t client_mac, wifi_mgmtFrameType_t mgmt_type, u16 reason)
{
    bm_sta_list_t *sta_info = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    wifi_vap_info_t *vap;
    uint32_t group_idx = 0;

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap || vap->u.bss_info.enabled != true) {
        wifi_hal_error_print("%s:%d: vap is not enabled:%s vap_mode:%d\n", __func__, __LINE__, vap->vap_name, vap->vap_mode);
        return;
    }

    key = to_mac_str(client_mac, sta_mac_str);
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    sta_info = hash_map_get(interface->bm_sta_map, key);
    if (sta_info != NULL) {
        if ((sta_info->assoc_time > 0) && (sta_info->state == ACTIVE)) {
            sta_info->disassoc_time = get_boot_time_in_sec();
            sta_info->assoc_time = 0;
            sta_info->state = INACTIVE;
            sta_info->event_sent &= ~BM_SENT_E_ASSOC;
        }

        /* send steering disconnection event */
        if (steering_find_ap_cfg(vap->vap_index, &group_idx)) {
            if (wifi_hal_send_disconnect_steering_event(group_idx, vap->vap_index, client_mac, mgmt_type, reason, DISCONNECT_SOURCE_REMOTE) == RETURN_OK) {
                sta_info->event_sent |= BM_SENT_E_DISASSOC;
            }
        } else {
            wifi_hal_error_print("wifi_hal_DEAUTH: no steering event due to ap_idx=%d not in apconfig\n", vap->vap_index);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
}

static void wifi_hal_send_steering_authfail_event(wifi_interface_info_t *interface, uint32_t g_idx, int ap_idx,
                                        mac_address_t sta_addr, int rssi, int reason, bool rejected)
{
    wifi_device_callbacks_t *callbacks;
    wifi_steering_event_t steering_evt;
    bool blocked = is_sta_in_blocked_state(interface, sta_addr);
    mac_addr_str_t sta_mac_str;

    callbacks = get_hal_device_callbacks();
    if ((callbacks != NULL) && (callbacks->steering_event_callback != 0)) {

        steering_evt.type = WIFI_STEERING_EVENT_AUTH_FAIL;
        steering_evt.apIndex = ap_idx;
        steering_evt.timestamp_ms = time(NULL);

        /* parameter */
        memcpy(steering_evt.data.authFail.client_mac, sta_addr, sizeof(mac_address_t));
        steering_evt.data.authFail.rssi = rssi;
        steering_evt.data.authFail.reason = reason;
        steering_evt.data.authFail.bsBlocked = blocked;
        steering_evt.data.authFail.bsRejected = rejected;

        wifi_hal_dbg_print("send_steering_authfail_event: g_idx=%d ap_idx=%d "
                "Client-MAC=%s rssi=%d reason=%d blocked=%d rejected=%d\n", g_idx, ap_idx,
                to_mac_str(sta_addr, sta_mac_str), rssi, reason, blocked, rejected);
        callbacks->steering_event_callback(g_idx, &steering_evt);
    }
}

static void handle_auth_req_event_for_bm(wifi_interface_info_t *interface, mac_address_t client_mac, int32_t rssi)
{
    wifi_vap_info_t *vap;
    bm_sta_list_t *sta_info = NULL;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    uint32_t group_idx = 0;

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap || vap->u.bss_info.enabled != true) {
        wifi_hal_error_print("%s:%d: vap is not enabled:%s vap_mode:%d\n", __func__, __LINE__, vap->vap_name, vap->vap_mode);
        return;
    }

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    /* send auth rssi xing event if necessary */
    if (steering_find_ap_cfg(vap->vap_index, &group_idx) != NULL) {
        key = to_mac_str(client_mac, sta_mac_str);
        sta_info = hash_map_get(interface->bm_sta_map, key);
        if (sta_info != NULL && (sta_info->type & (BM_STA_TYPE_ASSOC | BM_STA_TYPE_CLIENT_SET))) {
            bool be_rejected;
            int ch_noise;
            /* default: in range */
            int32_t rssi_change_auth = WIFI_STEERING_RSSI_UNCHANGED;

            wifi_hal_dbg_print("Old snr=%d for MAC=%s\n", sta_info->rssi, key);

            if (wifi_hal_get_radio_channel_noise(interface, &ch_noise) != RETURN_OK) {
                ch_noise = -90;/* use a default value */
            }
            /* convert to snr */
            sta_info->rssi = (rssi > ch_noise) ? (rssi - ch_noise) : 0;
            wifi_hal_dbg_print("Wifi_hal_AUTH_REQ: rssi=%d snr=%d aHWM=%d aLWM=%d\n", rssi, sta_info->rssi,
                                sta_info->bm_client_cfg.rssiAuthHWM, sta_info->bm_client_cfg.rssiAuthLWM);
            /* use status change to reduce auth request crossing
             * event flooding for same STA
             * if sta_info->rssi == 0 (not updated yet), allow it in
             */
            if (sta_info->rssi && (sta_info->bm_client_cfg.rssiAuthLWM || sta_info->bm_client_cfg.rssiAuthHWM)) {
                /* if both WM are 0, skip the comparison (same as in range) */
                if ((uint32_t)sta_info->rssi > sta_info->bm_client_cfg.rssiAuthHWM) {
                    rssi_change_auth = WIFI_STEERING_RSSI_HIGHER;
                } else if ((uint32_t)sta_info->rssi < sta_info->bm_client_cfg.rssiAuthLWM) {
                    rssi_change_auth = WIFI_STEERING_RSSI_LOWER;
                }

                if (sta_info->rssi_change_auth != rssi_change_auth) {
                    sta_info->rssi_change_auth = rssi_change_auth;
                    wifi_hal_send_rssi_xing_event(group_idx, vap->vap_index, sta_info, sta_info->rssi, BM_STA_RSSI_AUTH);
                }
            }

            /* auth response control */
            if (rssi_change_auth != WIFI_STEERING_RSSI_UNCHANGED) {
                /* not in watermark range, add to deny list */
                if (wifi_steering_add_mac_list(vap->vap_index, sta_info) == RETURN_OK) {
                    wifi_hal_dbg_print("Add MAC=%s to maclist SNR=%d (aHWM=%d aLWM=%d) when Auth on %d\n", key, (uint)sta_info->rssi,
                                            sta_info->bm_client_cfg.rssiAuthHWM, sta_info->bm_client_cfg.rssiAuthLWM, sta_info->vap_index);
                }

                if (sta_info->bm_client_cfg.authRejectReason == 0) {
                    be_rejected = FALSE;
                    wifi_hal_dbg_print("Auth silently ignore for MAC=%s when wifi_hal_AUTH_REQ\n", key);
                } else {
                    be_rejected = TRUE;
                    /* send deauth with the reason */
                    wifi_hal_dbg_print("Deauth reason %d for MAC=%s when wifi_hal_AUTH_REQ\n",
                                            sta_info->bm_client_cfg.authRejectReason, key);
#ifdef CMXB7_PORT
                    wifi_hal_steering_clientDisconnect(group_idx, vap->vap_index, sta_info->mac_addr,
                                                        DISCONNECT_TYPE_DEAUTH, sta_info->bm_client_cfg.authRejectReason);
#elif !defined(PLATFORM_LINUX)
                    wifi_steering_clientDisconnect(group_idx, vap->vap_index, sta_info->mac_addr,
                                                        DISCONNECT_TYPE_DEAUTH, sta_info->bm_client_cfg.authRejectReason);
#endif
                }

                wifi_hal_send_steering_authfail_event(interface, group_idx, vap->vap_index, sta_info->mac_addr, sta_info->rssi,
                                                        sta_info->bm_client_cfg.authRejectReason, be_rejected);
            } else {
                /* remove from deny list if RSSI is in watermark range */
                wifi_hal_dbg_print("Remove MAC=%s from blacklist (SNR in range) when wifi_hal_AUTH_REQ\n", key);
                if (wifi_steering_del_mac_list(vap->vap_index, sta_info) == RETURN_OK) {
                    wifi_hal_dbg_print("Remove MAC=%s from maclist SNR=%d (aHWM=%d aLWM=%d) when Auth on %d\n", key, (uint32_t)sta_info->rssi,
                                              sta_info->bm_client_cfg.rssiAuthHWM, sta_info->bm_client_cfg.rssiAuthLWM, sta_info->vap_index);
                }
            }
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
}

static void wifi_hal_send_active_state_event(uint32_t group_index, int vap_index, mac_address_t sta_addr, bool active)
{
    wifi_steering_event_t steering_evt;
    wifi_device_callbacks_t *callbacks;
    mac_addr_str_t sta_mac_str;

    callbacks = get_hal_device_callbacks();
    if ((callbacks != NULL) && (callbacks->steering_event_callback != 0)) {
        steering_evt.type = WIFI_STEERING_EVENT_CLIENT_ACTIVITY;
        steering_evt.apIndex = vap_index;
        steering_evt.timestamp_ms = time(NULL);
        memcpy(steering_evt.data.activity.client_mac, sta_addr, sizeof(mac_address_t));
        steering_evt.data.activity.active = active;

        wifi_hal_dbg_print("send_active_state_event: g_idx=%d ap_idx=%d, Client-MAC=%s\n",
                group_index, vap_index, to_mac_str(sta_addr, sta_mac_str));

        callbacks->steering_event_callback(group_index, &steering_evt);
    }
}

static wifi_associated_dev3_t *sta_in_driver_assoclist(wifi_associated_dev3_t *dev_array, unsigned int num_devs, mac_address_t sta_addr)
{
    unsigned int index;

    for (index = 0; index < num_devs; index++) {
        if (memcmp(dev_array->cli_MACAddress, sta_addr, sizeof(mac_address_t)) == 0) {
            return dev_array;
        }
        dev_array++;
    }
    return NULL;
}

static void update_steering_stalist_by_assoclist(bm_sta_list_t *ptr)
{
    wifi_associated_dev3_t *dev_array = NULL;
    unsigned int num_devs = 0, group_idx = 0;
    bool sta_found_in_driver = false;
    mac_addr_str_t sta_mac_str;
    wifi_associated_dev3_t *sta_info = NULL;
    int ret;

    ret = wifi_getApAssociatedDeviceDiagnosticResult3(ptr->vap_index, &dev_array, &num_devs);
    if (ret != RETURN_OK) {
        wifi_hal_error_print("%s AP Associated device diagnostic result3 failure for vap_index=%d\n", __func__, ptr->vap_index);
        return;
    }

    if ((sta_info = sta_in_driver_assoclist(dev_array, num_devs, ptr->mac_addr)) != NULL) {
        sta_found_in_driver = true;
    }

    /* for disconnect event missing */
    if ((ptr->type & BM_STA_TYPE_ASSOC) && (ptr->disassoc_time == 0) && (sta_found_in_driver == false)) {
        ptr->type &= ~BM_STA_TYPE_ASSOC;
        ptr->disassoc_time = get_boot_time_in_sec();
        ptr->assoc_time = 0;
        ptr->state = INACTIVE;
        ptr->event_sent &= ~BM_SENT_E_ASSOC;

        /* send steering disconnection event */
        if (steering_find_ap_cfg(ptr->vap_index, &group_idx)) {
            if (wifi_hal_send_disconnect_steering_event(group_idx, ptr->vap_index, ptr->mac_addr,
                    WIFI_MGMT_FRAME_TYPE_DEAUTH, AUTH_INVAL_REASON, DISCONNECT_SOURCE_LOCAL) == RETURN_OK) {
                ptr->event_sent |= BM_SENT_E_DISASSOC;
            }
        } else {
            wifi_hal_info_print("wifi_hal_DEAUTH: no steering event due to ap_idx=%d not in apconfig\n", ptr->vap_index);
        }
    }

    if (sta_found_in_driver == true) {
        if (!((ptr->type & BM_STA_TYPE_ASSOC) && (ptr->event_sent & BM_SENT_E_ASSOC))) {
            wifi_hal_info_print("=>Existing STA: MAC=%s assoc_time=%lu disassoc_time=%lu "
                                                "state=%d type=0x%x event_sent=0x%x\n",
                                                to_mac_str(ptr->mac_addr, sta_mac_str), ptr->assoc_time,
                                                ptr->disassoc_time, ptr->state, ptr->type, ptr->event_sent);
        }

        /* updating tx and rx packet count */
        if ((ptr->type & BM_STA_TYPE_ASSOC) && (ptr->state == ACTIVE)) {
            /* update rx_tot_pkts/tx_tot_pkts */
            if ((ptr->tx_tot_pkts != sta_info->cli_PacketsSent) || (ptr->rx_tot_pkts != sta_info->cli_PacketsReceived)) {
                //ptr->active = get_boot_time_in_sec();
                ptr->rx_tot_pkts = sta_info->cli_PacketsReceived;
                ptr->tx_tot_pkts = sta_info->cli_PacketsSent;
                wifi_hal_info_print("STA:MAC=%s assoc_time=%lu tot_tx_packet:%ld,tot_rx_packet:%ld\r\n",
                                    to_mac_str(ptr->mac_addr, sta_mac_str), ptr->active, ptr->rx_tot_pkts, ptr->tx_tot_pkts);
            }
            ptr->active = get_boot_time_in_sec();
        }
    }

    if (dev_array != NULL) {
        free(dev_array);
    }
}

/* check inactive and RSSI, if hit threshold, send event to mesh */
static void wifi_hal_steering_check_sta_status(wifi_interface_info_t *interface)
{
    uint32_t g_idx = 0;
    wifi_steering_apConfig_t *ap_cfg = NULL;
    bm_sta_list_t *ptr = NULL;
    time_t now = get_boot_time_in_sec();
    wifi_steering_clientConfig_t *cli_cfg;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    static int tick = 0;
    wifi_device_callbacks_t *callbacks;
    static time_t old_time;
    mac_address_t temp_sta_mac;

    callbacks = get_hal_device_callbacks();
    if (callbacks->steering_event_callback == 0) {
        return;
    }

    //Trigger this functionality every 1 seconds
    if ((now - old_time) < 1) {
        return;
    }
    old_time = now;

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    ptr = hash_map_get_first(interface->bm_sta_map);
    while (ptr != NULL) {
        if ((ptr->type & BM_STA_TYPE_ASSOC) && (ptr->state == INACTIVE) && (ptr->disassoc_time > 0)) {
            if ((now - ptr->disassoc_time) > INACTIVITY_TIMEOUT) {
                wifi_hal_info_print("Deleting MAC=%s on ssid %s vap_index=%d assoc_time=%lu disassoc_time=%lu\n",
                                        to_mac_str(ptr->mac_addr, sta_mac_str), ptr->ssid, ptr->vap_index,
                                        ptr->assoc_time, ptr->disassoc_time);
                memcpy(temp_sta_mac, ptr->mac_addr, sizeof(mac_address_t));
                ptr = hash_map_get_next(interface->bm_sta_map, ptr);
                steering_del_stalist(interface, temp_sta_mac, BM_STA_TYPE_ASSOC);
                continue;
            }
        }

        if ((tick % STA_INFO_UPDATE_TIMEOUT) == 0) {
            update_steering_stalist_by_assoclist(ptr);
        }

        if (!(ptr->type & BM_STA_TYPE_ASSOC) || (ptr->state == INACTIVE)) {
            ptr = hash_map_get_next(interface->bm_sta_map, ptr);
            continue;
        }

        /* inactive */
        ap_cfg = steering_find_ap_cfg(ptr->vap_index, &g_idx);
        if (ap_cfg == NULL) {
            wifi_hal_dbg_print("AP Config for vap:%d is not found\n", ptr->vap_index);
        } else {
            if (ap_cfg->inactCheckIntervalSec && ((tick % ap_cfg->inactCheckIntervalSec) == 0)) {
                if ((now - ptr->active) > ap_cfg->inactCheckThresholdSec) {
                    /* inactive */
                    if (ptr->inactive_state == 0) {
                        /* send event from active to inactive */
                        wifi_hal_dbg_print("MAC=%s from active to inactive\n", to_mac_str(ptr->mac_addr, sta_mac_str));
                        wifi_hal_send_active_state_event(g_idx, ap_cfg->apIndex, ptr->mac_addr, FALSE);
                        ptr->inactive_state = 1;
                    }

                    cli_cfg = &ptr->bm_client_cfg;
                    /* check rssi for inactive STA */
                    if (ptr->rssi > cli_cfg->rssiInactXing) {
                        wifi_hal_dbg_print("rssiInactXing mark for %s: %d, %d\n", to_mac_str(ptr->mac_addr, sta_mac_str),
                                                    ptr->rssi, cli_cfg->rssiInactXing);
                        wifi_hal_send_rssi_xing_event(g_idx, ap_cfg->apIndex, ptr, ptr->rssi, BM_STA_RSSI_INACTIVE);
                    }
                } else {
                    /* active */
                    if (ptr->inactive_state) {
                        /* send event from inactive to active */
                        wifi_hal_dbg_print("MAC=%s from inactive to active\n", to_mac_str(ptr->mac_addr, sta_mac_str));
                        wifi_hal_send_active_state_event(g_idx, ap_cfg->apIndex, ptr->mac_addr, TRUE);
                        ptr->inactive_state = 0;
                    }
                }
                tick = 0;
            }
            /* check RSSI xing for associated STA */
            cli_cfg = &ptr->bm_client_cfg;
            int32_t rssi_change_assoc = WIFI_STEERING_RSSI_UNCHANGED;
            key = to_mac_str(ptr->mac_addr, sta_mac_str);
#if defined(CMXB7_PORT) || defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_BANANAPI_R4_)
            wifi_associated_dev3_t associated_dev;
            memset(&associated_dev, 0, sizeof(associated_dev));
            //wifi_getApDeviceRSSI API is not available on CMXB7 platform. So, we need to use this API to get rssi value.
            if (wifi_getApAssociatedClientDiagnosticResult(ptr->vap_index, key, &associated_dev) == RETURN_OK) {
                wifi_hal_dbg_print("old_snr::%d,New updated snr:%d for MAC=%s - vap:%d:: rssi:%d\n", ptr->rssi, associated_dev.cli_SNR, key, ptr->vap_index, associated_dev.cli_RSSI);
                ptr->rssi = associated_dev.cli_SNR;
#else
            int rssi;
            if (wifi_getApDeviceRSSI(ptr->vap_index, key, &rssi) == RETURN_OK) {
                int snr = (rssi > -90) ? (rssi + 90) : 0;
                wifi_hal_dbg_print("old_snr::%d,New updated snr:%d for MAC=%s - vap:%d:: rssi:%d\n", ptr->rssi, snr, key, ptr->vap_index, rssi);
                ptr->rssi = snr;
#endif // _PLATFORM_RASPBERRYPI_ || _PLATFORM_BANANAPI_R4_
            }

            wifi_hal_dbg_print("Check RSSI state for associated MAC=%s snr=%d hXing=%d, lXing=%d\n",
                                    to_mac_str(ptr->mac_addr, sta_mac_str), ptr->rssi,
                                    cli_cfg->rssiHighXing, cli_cfg->rssiLowXing);

            if (cli_cfg->rssiHighXing || cli_cfg->rssiLowXing) {
                /* use status change to reduce crossing event flooding for same STA */
                if (ptr->rssi > cli_cfg->rssiHighXing) {
                    rssi_change_assoc = WIFI_STEERING_RSSI_HIGHER;
                } else if (ptr->rssi < cli_cfg->rssiLowXing) {
                    rssi_change_assoc = WIFI_STEERING_RSSI_LOWER;
                }

                if (ptr->rssi_change_assoc != rssi_change_assoc) {
                    ptr->rssi_change_assoc = rssi_change_assoc;
                    wifi_hal_send_rssi_xing_event(g_idx, ap_cfg->apIndex, ptr, ptr->rssi, BM_STA_RSSI_XING);
                }
            }
        }
        ptr = hash_map_get_next(interface->bm_sta_map, ptr);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    tick++;
}

static void wifi_hal_send_probe_req_event(wifi_interface_info_t *interface, uint32_t group_index, uint32_t vap_index,
                    bm_sta_list_t *bm_client_info, int32_t rssi, bool broadcast) {
    wifi_device_callbacks_t *callbacks;
    wifi_steering_event_t steering_evt;
    mac_addr_str_t sta_mac_str;

    callbacks = get_hal_device_callbacks();
    if ((callbacks != NULL) && (callbacks->steering_event_callback != 0)) {
        steering_evt.type = WIFI_STEERING_EVENT_PROBE_REQ;
        steering_evt.apIndex = vap_index;
        steering_evt.timestamp_ms = time(NULL);
        memcpy(steering_evt.data.probeReq.client_mac, bm_client_info->mac_addr, sizeof(mac_address_t));
        steering_evt.data.probeReq.rssi = rssi;
        steering_evt.data.probeReq.broadcast = broadcast;
        steering_evt.data.probeReq.blocked = is_sta_in_blocked_state(interface, bm_client_info->mac_addr);

        wifi_hal_dbg_print("%s:%d: Send Probe Req steering:%d event for %s\n", __func__, __LINE__,
                                group_index, to_mac_str(bm_client_info->mac_addr, sta_mac_str));

        callbacks->steering_event_callback(group_index, &steering_evt);
    }
}

static void handle_probe_req_event_for_bm(wifi_interface_info_t *interface, struct ieee80211_mgmt *mgmt, unsigned int len, mac_address_t client_mac, int sig_dbm) {

    unsigned char *ie;
    unsigned int ie_len, ssid_len = 0;
    char ssid[SSID_MAX_LEN];
    bool broadcast = false, ssid_bcast = false;
    wifi_vap_info_t *vap;
    bm_sta_list_t *bm_client_info = NULL;
    bm_sta_list_t temp_client_info;
    mac_addr_str_t sta_mac_str;
    char *key = NULL;
    uint32_t group_index = 0;
    int ch_noise;

    vap = &interface->vap_info;
    if (vap->vap_mode != wifi_vap_mode_ap || vap->u.bss_info.enabled != true) {
        wifi_hal_error_print("%s:%d: vap is not enabled:%s vap_mode:%d\n", __func__, __LINE__, vap->vap_name, vap->vap_mode);
        return;
    }

    if (len < IEEE80211_HDRLEN) {
        wifi_hal_error_print("%s:%d: wrong mgmt:%d frame for vap:%d\n", __func__, __LINE__, len, vap->vap_index);
        return;
    }

    ie = ((unsigned char *)mgmt) + IEEE80211_HDRLEN;
    ie_len = len - IEEE80211_HDRLEN;

    ie = get_ie(ie, ie_len, WLAN_EID_SSID);
    if (ie == NULL) {
        wifi_hal_error_print("%s:%d: vap:%s probe ie ssid is not found\n", __func__, __LINE__, vap->vap_name);
    } else {
        ssid_len = ie[1];
    }

    //wifi_hal_dbg_print("probe req for vap:%d ssid_len:%d\n", vap->vap_index, ssid_len);
    if (ssid_len == 0) {
        broadcast = TRUE;
    } else if (ssid_len < sizeof(ssid)) {
        strncpy(ssid, (char*)(ie + 2), ssid_len);
        ssid[ssid_len] = '\0';
        if (strncmp(ssid, "Broadcast", sizeof("Broadcast") - 1) == 0) {
            broadcast = TRUE;
            ssid_bcast = TRUE;
        }
    }
    // this code added for debugging purpose only.
    if (is_wifi_hal_vap_private(vap->vap_index)) {
        wifi_hal_dbg_print("==>probe req frame on interface:%s from sta:%s, rssi:%d\n", interface->name, to_mac_str(client_mac, sta_mac_str), sig_dbm);
        mac_addr_str_t  sta_mac_str1;
        wifi_hal_dbg_print("src:%s dst:%s: vap_index:%d broadcast:%d\n", to_mac_str(mgmt->sa, sta_mac_str), to_mac_str(mgmt->da, sta_mac_str1), vap->vap_index, broadcast);
    }

    if (ssid_len && !ssid_bcast) {
        wifi_hal_dbg_print("ssid:%s\r\n", ssid);
        if (strcmp(ssid, (char *)(vap->u.bss_info.ssid)) != 0) {
            wifi_hal_dbg_print("%s:%d: SSID mis-match:%s::%s\n", __func__, __LINE__, vap->u.bss_info.ssid, ssid);
            return;
        }
    }

    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    if (steering_find_ap_cfg(vap->vap_index, &group_index) == NULL) {
        //wifi_hal_dbg_print("%s:%d: steering group:%d not found for vap:%d\n", __func__, __LINE__, group_index, vap->vap_index);
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
        return;
    }

    key = to_mac_str(client_mac, sta_mac_str);
    bm_client_info = hash_map_get(interface->bm_sta_map, key);
    if (bm_client_info == NULL) {
        bm_client_info = &temp_client_info;

        memset(&temp_client_info, 0, sizeof(temp_client_info));
        memcpy(&bm_client_info->mac_addr, client_mac, sizeof(bm_client_info->mac_addr));
        bm_client_info->vap_index = vap->vap_index;
    }
    if (wifi_hal_get_radio_channel_noise(interface, &ch_noise) != RETURN_OK) {
        ch_noise = -90;/* use a default value */
    }
    bm_client_info->rssi = (sig_dbm > ch_noise) ? (sig_dbm - ch_noise) : 0;

    wifi_hal_dbg_print("vap_index:%d client:%s snr:%d type:%d\n", vap->vap_index, key, bm_client_info->rssi, bm_client_info->type);
    if (bm_client_info->type & BM_STA_TYPE_CLIENT_SET) {
        int32_t rssi_change = WIFI_STEERING_RSSI_UNCHANGED;
        int send_event = 1;

        if (ssid_len != 0) {
            if (strcmp(ssid, (char *)(vap->u.bss_info.ssid)) == 0) {
                broadcast = FALSE;
            } else if (strcmp(ssid, "Broadcast")) {
                send_event = 0;
            }
        }
        if (send_event) {
            wifi_hal_send_probe_req_event(interface, group_index, vap->vap_index, bm_client_info, bm_client_info->rssi, broadcast);
        }

        /* use status change to reduce probe request xing event flooding for same STA */
        if (bm_client_info->bm_client_cfg.rssiProbeLWM || bm_client_info->bm_client_cfg.rssiProbeHWM) {
            /* if both WM are 0, skip the comparison */
            if ((uint32_t)bm_client_info->rssi > bm_client_info->bm_client_cfg.rssiProbeHWM) {
                rssi_change = WIFI_STEERING_RSSI_HIGHER;
            } else if ((uint32_t)bm_client_info->rssi < bm_client_info->bm_client_cfg.rssiProbeLWM) {
                rssi_change = WIFI_STEERING_RSSI_LOWER;
            }

            if (bm_client_info->rssi_changed != rssi_change) {
                bm_client_info->rssi_changed = rssi_change;
                wifi_hal_send_rssi_xing_event(group_index, vap->vap_index, bm_client_info,
                                             bm_client_info->rssi, BM_STA_RSSI_PROBE);
            }
        }

        /* probe response control */
        if (rssi_change != WIFI_STEERING_RSSI_UNCHANGED) {
            /* add to deny list */
            wifi_steering_add_mac_list(vap->vap_index, bm_client_info);
        } else {
            /* del from deny list */
            wifi_steering_del_mac_list(vap->vap_index, bm_client_info);
        }
    } else if (memcmp(mgmt->da, interface->mac, sizeof(mac_address_t)) == 0) {
        wifi_hal_send_probe_req_event(interface, group_index, vap->vap_index, bm_client_info, bm_client_info->rssi, broadcast);
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
}

#ifdef CMXB7_PORT
int process_frame_mgmt(wifi_interface_info_t *interface, struct ieee80211_mgmt *mgmt, u16 reason, int sig_dbm, int snr, int phy_rate, unsigned int len) {
#else
int process_frame_mgmt(wifi_interface_info_t *interface, struct ieee80211_mgmt *mgmt, u16 reason, int sig_dbm, int phy_rate, unsigned int len) {
#endif

    wifi_mgmtFrameType_t mgmt_type;
    wifi_direction_t dir;
    unsigned char cat;
    unsigned short fc, stype;
    mac_address_t   sta, bmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    mac_addr_str_t  sta_mac_str, interface_mac_str, frame_da_str;
    wifi_vap_info_t *vap;
    bool drop = false;
    wifi_device_callbacks_t *callbacks;
    wifi_device_frame_hooks_t *hooks;
    struct sta_info *station = NULL;
    wifi_frame_t mgmt_frame;
    bool forward_frame = true;
#ifdef WIFI_EMULATOR_CHANGE
    static int fd_c = -1;
    unsigned int msg_type = wlan_emu_msg_type_frm80211;
    unsigned int msg_ops_type = 0;
    unsigned char *c_buff;
    unsigned char *frame_buff;
    unsigned int total_len=0;
    bool send_mgmt_to_char_dev = false;
#endif

    if (mgmt == NULL) {
        return -1;
    }

    callbacks = get_hal_device_callbacks();
    hooks = get_device_frame_hooks();
    vap = &interface->vap_info;

    if (memcmp(mgmt->da, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->sa, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else if (memcmp(mgmt->sa, interface->mac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->da, sizeof(mac_address_t));
        dir = wifi_direction_downlink;
    } else if (memcmp(mgmt->da, bmac, sizeof(mac_address_t)) == 0) {
        memcpy(sta, mgmt->sa, sizeof(mac_address_t));
        dir = wifi_direction_uplink;
    } else {
        to_mac_str(interface->mac, interface_mac_str);
        to_mac_str(mgmt->sa, sta_mac_str);
        to_mac_str(mgmt->da, frame_da_str);
        wifi_hal_error_print("%s:%d: interface:%s dropping mgmt frame, interface mac:%s sta mac:%s"
                             " frame da:%s\n",
            __func__, __LINE__, interface->name, interface_mac_str, sta_mac_str, frame_da_str);
        if ((callbacks != NULL) && (callbacks->analytics_callback != NULL)) {
            callbacks->analytics_callback("Dropping mgmt frame from interface:%s sta mac:%s frame da:%s",
                interface_mac_str, sta_mac_str, frame_da_str);
        }
        return -1;
    }


    fc = le_to_host16(mgmt->frame_control);
    stype = WLAN_FC_GET_STYPE(fc);

    switch(stype) {
    case WLAN_FC_STYPE_AUTH:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_AUTH;

        if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.auth)) {
            wifi_hal_info_print("%s:%d: interface:%s received auth frame from:%s to:%s alg:%d "
                                "seq:%d sc:%d len:%d rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), le_to_host16(mgmt->u.auth.auth_alg),
                le_to_host16(mgmt->u.auth.auth_transaction), le_to_host16(mgmt->u.auth.status_code),
                len, sig_dbm);
        } else {
            wifi_hal_info_print("%s:%d: interface:%s received auth frame from:%s to:%s len:%d "
                                "rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), len, sig_dbm);
        }

        if (callbacks->steering_event_callback != 0) {
            handle_auth_req_event_for_bm(interface, sta, sig_dbm);
        }
#ifdef NL80211_ACL
        if (is_core_acl_drop_mgmt_frame(interface, sta)) {
            wifi_hal_dbg_print("%s:%d: Station present in acl list dropping auth req\n",
                                   __func__, __LINE__);
            return -1;
        }
#endif
        remove_station_from_other_interfaces(interface, sta);
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif

#if !defined(WIFI_EMULATOR_CHANGE)
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || \
		defined(SKYSR213_PORT) || defined(SKYSR300_PORT) || defined(TCHCBRV2_PORT)
		/* Authentication done in driver except SAE */
		if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.auth) &&
				le_to_host16(mgmt->u.auth.auth_alg) != WLAN_AUTH_SAE) {
			forward_frame = false;
		}
#endif /* defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) ||
		 defined(SCXER10_PORT) || defined(SKYSR213_PORT) || defined(SKYSR300_PORT) ||
		 defined(TCHCBRV2_PORT) */
#endif //WIFI_EMULATOR_CHANGE

        break;

    case WLAN_FC_STYPE_ASSOC_REQ:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_REQ;

        if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req)) {
            wifi_hal_info_print(
                "%s:%d: interface:%s received assoc frame from:%s to:%s cap:0x%x len:%d rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), le_to_host16(mgmt->u.assoc_req.capab_info), len,
                sig_dbm);
        } else {
            wifi_hal_info_print("%s:%d: interface:%s received assoc frame from:%s to:%s len:%d "
                                "rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), len, sig_dbm);
        }

        if (callbacks->steering_event_callback != 0) {
            handle_assoc_req_event_for_bm(interface, mgmt, len, sta);
        }
        remove_station_from_other_interfaces(interface, sta);
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    case WLAN_FC_STYPE_REASSOC_REQ:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_REASSOC_REQ;

        if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req)) {
            wifi_hal_info_print("%s:%d: interface:%s received reassoc frame from:%s to:%s cap:0x%x "
                                "len:%d rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), le_to_host16(mgmt->u.reassoc_req.capab_info),
                len, sig_dbm);
        } else {
            wifi_hal_info_print("%s:%d: interface:%s received reassoc frame from:%s to:%s len:%d "
                                "rssi:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), len, sig_dbm);
        }

        remove_station_from_other_interfaces(interface, sta);
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    case WLAN_FC_STYPE_ASSOC_RESP:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ASSOC_RSP;
        break;

    case WLAN_FC_STYPE_PROBE_REQ:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_PROBE_REQ;
        //wifi_hal_dbg_print("%s:%d: Received probe req frame on interface:%s from the sta : %s and the phy_rate:%d\n", __func__, __LINE__,interface->name,to_mac_str(sta, sta_mac_str),phy_rate);

        if (callbacks->steering_event_callback != 0) {
            handle_probe_req_event_for_bm(interface, mgmt, len, sta, sig_dbm);
        }
#ifdef NL80211_ACL
        // If mac filter acl is enabled then we need to drop mgmt frame based on acl config
        if (is_core_acl_drop_mgmt_frame(interface, sta)) {
            return -1;
        }
#endif
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    case WLAN_FC_STYPE_ACTION:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_ACTION;
        cat = mgmt->u.action.category;

        wifi_hal_dbg_print("%s:%d: interface:%s received action frame from:%s to:%s, category:%d\n",
            __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
            to_mac_str(mgmt->da, frame_da_str), cat);

        switch (cat) {
        case wifi_action_frame_wnm:
            // - don't handle frame by calling wpa_supplicant_event() if action frame was already handled:
            forward_frame = (WIFI_HAL_UNSUPPORTED == handle_wnm_action_frame(interface, sta, mgmt, len));
            break;
        case wifi_action_frame_type_radio_msmt:
            // - don't handle frame by calling wpa_supplicant_event() if action frame was already handled:
            forward_frame = (WIFI_HAL_UNSUPPORTED == handle_rrm_action_frame(interface, sta, mgmt, len, sig_dbm));
            break;
        case wifi_action_frame_type_public:
            // - don't handle frame by calling wpa_supplicant_event() if action frame was already
            // handled: The below code is commented as it is causing duplicates. handling of public
            // action frames is taken care further below of this function via
            // callbacks->mgmt_frame_rx_callback
            forward_frame = false;
            break;
        default:
            break;
        }
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    case WLAN_FC_STYPE_DISASSOC:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_DISASSOC;

        if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.disassoc)) {
            wifi_hal_info_print("%s:%d: interface:%s received disassoc frame from:%s to:%s sc:%d "
                                "len:%d reason:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), le_to_host16(mgmt->u.disassoc.reason_code), len,
                reason);
        } else {
            wifi_hal_info_print("%s:%d: interface:%s received disassoc frame from:%s to:%s len:%d "
                                "reason:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), len, reason);
        }

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        station = ap_get_sta(&interface->u.ap.hapd, sta);
        if (station) {
            wifi_hal_dbg_print("station disassocreason in disassoc frame is %d\n", station->disconnect_reason_code);
#if !defined(PLATFORM_LINUX)
            if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                reason = station->disconnect_reason_code;
            }
#endif
            ap_free_sta(&interface->u.ap.hapd, station);
        } else {
            wifi_hal_dbg_print("%s:%d: interface:%s sta %s not found\n", __func__, __LINE__,
                interface->name, to_mac_str(sta, sta_mac_str));
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
            if (callbacks->disassoc_cb[i] != NULL) {
                callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
            }
        }
        if (callbacks->steering_event_callback != 0) {
            handle_disconnect_event_for_bm(interface, sta, mgmt_type, reason);
        }
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    case WLAN_FC_STYPE_DEAUTH:
        mgmt_type = WIFI_MGMT_FRAME_TYPE_DEAUTH;

        if (len >= IEEE80211_HDRLEN + sizeof(mgmt->u.deauth)) {
            wifi_hal_info_print("%s:%d: interface:%s received deauth frame from:%s to:%s sc:%d "
                                "len:%d reason:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), le_to_host16(mgmt->u.disassoc.reason_code), len,
                reason);
        } else {
            wifi_hal_info_print("%s:%d: interface:%s received deauth frame from:%s to:%s len:%d "
                                "reason:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, sta_mac_str),
                to_mac_str(mgmt->da, frame_da_str), len, reason);
        }

        if (callbacks->num_apDeAuthEvent_cbs == 0) {
            break;
        }
        for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
            if (callbacks->apDeAuthEvent_cb[i] != NULL) {
                callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
            }
        }

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        station = ap_get_sta(&interface->u.ap.hapd, sta);
        if (station) {
            wifi_hal_dbg_print("station deauthreason in deauth frame is %d\n", station->disconnect_reason_code);
#if !defined(PLATFORM_LINUX)
            if (station->disconnect_reason_code == WLAN_RADIUS_GREYLIST_REJECT) {
                reason = station->disconnect_reason_code;
            }
#endif
            ap_free_sta(&interface->u.ap.hapd, station);
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        if (station) {
            for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
                if (callbacks->disassoc_cb[i] != NULL) {
                    callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), reason);
                }
            }
        } else {
            wifi_hal_dbg_print("%s:%d: interface:%s sta %s not found\n", __func__, __LINE__,
                interface->name, to_mac_str(sta, sta_mac_str));
        }
        if (callbacks->steering_event_callback != 0) {
            handle_disconnect_event_for_bm(interface, sta, mgmt_type, reason);
        }
#ifdef WIFI_EMULATOR_CHANGE
        send_mgmt_to_char_dev = true;
#endif
        break;

    default:
        drop = true;
        break;
    }

    if (drop == true) {
        wifi_hal_error_print("%s:%d: unknown frame type:%d, dropping\n", __func__, __LINE__, stype);
        return -1;
    }

    if (callbacks->mgmt_frame_rx_callback &&
        (stype != WLAN_FC_STYPE_PROBE_REQ || is_probe_req_to_our_ssid(mgmt, len, interface))) {
            mgmt_frame.ap_index = vap->vap_index;
            memcpy(mgmt_frame.sta_mac, sta, sizeof(mac_address_t));
            mgmt_frame.type = mgmt_type;
            mgmt_frame.dir = dir;
            mgmt_frame.sig_dbm = sig_dbm;
            mgmt_frame.len = len;
            mgmt_frame.data = (unsigned char *)mgmt;

#ifdef WIFI_HAL_VERSION_3_PHASE2
        callbacks->mgmt_frame_rx_callback(vap->vap_index, &mgmt_frame);
#else
#if defined(RDK_ONEWIFI) && (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(TCHCBRV2_PORT) || defined(SCXER10_PORT) || defined(VNTXER5_PORT))
        callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)mgmt, len, mgmt_type, dir, sig_dbm, phy_rate);
#else
        callbacks->mgmt_frame_rx_callback(vap->vap_index, sta, (unsigned char *)mgmt, len, mgmt_type, dir);
#endif
#endif

        for (unsigned int i = 0; i < hooks->num_hooks; i++) {
            if (hooks->frame_hooks_fn[i](vap->vap_index, mgmt_type) == NL_SKIP) {
                return -1;
            }
        }
    }

    //mgmt_frame_received_callback(vap->vap_index, sta, mgmt, len, mgmt_type, dir);

    /* if frame wasn't completely handled by this function, call the hostapd code */
    if (forward_frame) {
        union wpa_event_data event;

        os_memset(&event, 0, sizeof(event));
        event.rx_mgmt.frame = (unsigned char *)mgmt;
        event.rx_mgmt.frame_len = len;
#ifdef CMXB7_PORT
        event.rx_mgmt.snr_db = snr;
#endif
#if HOSTAPD_VERSION >= 211
        event.rx_mgmt.link_id = NL80211_DRV_LINK_ID_NA;
#endif /* HOSTAPD_VERSION >= 211 */
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        wpa_supplicant_event(&interface->u.ap.hapd, EVENT_RX_MGMT, &event);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }

#ifdef WIFI_EMULATOR_CHANGE
    if (send_mgmt_to_char_dev == true) {
        if ((access(ONEWIFI_TESTSUITE_TMPFILE, R_OK)) == 0) {
            if (fd_c < 0) {
                fd_c = open("/dev/rdkfmac_dev", O_RDWR);
                if (fd_c < 0) {
                    wifi_hal_info_print("%s:%d: failed to open to char dev\n", __func__, __LINE__);
                }
            }

            if  (fd_c > 0) {
                //wlan_emu_msg_type_t + wlan_emu_cfg80211_ops_type_t + sizeof(len) +(frame_len)  +  macaddr + client_macaddr
                total_len = sizeof(msg_type) + sizeof(msg_ops_type) + sizeof(len) + (len) + sizeof(mac_address_t) + sizeof(mac_address_t);

                c_buff = (unsigned char *)malloc(sizeof(unsigned char) * total_len);
                if (c_buff != NULL) {
                    memset(c_buff, 0, total_len);
                    frame_buff = c_buff;
                    memcpy(c_buff, &msg_type, sizeof(msg_type));
                    c_buff += sizeof(msg_type);

                    memcpy(c_buff, &msg_ops_type, sizeof(msg_ops_type));
                    c_buff += sizeof(msg_ops_type);

                    memcpy(c_buff, &len, sizeof(len));
                    c_buff += sizeof(len);

                    memcpy(c_buff, mgmt->sa, sizeof(mac_address_t));
                    c_buff += sizeof(mac_address_t);

                    memcpy(c_buff, mgmt->da, sizeof(mac_address_t));
                    c_buff += sizeof(mac_address_t);

                    memcpy(c_buff, mgmt, len);
                    c_buff += len;

                    if (write(fd_c, frame_buff, total_len) > 0) {
                        //wifi_hal_dbg_print("%s:%d: write succesful bytes written : %d for msg_ops_type : %d\n", __func__, __LINE__, total_len, msg_ops_type);
                    }
                    free(frame_buff);
                }
                close(fd_c);
                fd_c = -1;
            }
        }
    }

#endif

    return -1;
}

int process_mgmt_frame(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1], *attr;
    unsigned int len;
    struct ieee80211_mgmt *mgmt = NULL;
    u16 reason = 0;
    int sig_dbm = -100;
    int phy_rate = 60;
#ifdef CMXB7_PORT
    int snr = 0;
#endif

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    interface = (wifi_interface_info_t *)arg;

    if ((gnlh->cmd != NL80211_CMD_FRAME) && (gnlh->cmd != NL80211_CMD_UNEXPECTED_FRAME)) {
        wifi_hal_error_print("%s:%d: Unknown event\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (gnlh->cmd == NL80211_CMD_UNEXPECTED_FRAME) {
        union wpa_event_data event;

        os_memset(&event, 0, sizeof(event));

        event.rx_from_unknown.bssid = &interface->mac[0];

        if (!tb[NL80211_ATTR_MAC]) {
            wifi_hal_error_print("%s:%d: FAIL: No peer MAC address in RX_FROM_UNKNOWN event.\n", __func__, __LINE__);
            return NL_SKIP;
        }
        event.rx_from_unknown.addr = nla_get_string(tb[NL80211_ATTR_MAC]);

        event.rx_from_unknown.wds = 0;

        wifi_hal_dbg_print("%s%d: received spurious frame event on interface %s sent to hostapd.\n", __func__, __LINE__, interface->name);
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        wpa_supplicant_event(&interface->u.ap.hapd, EVENT_RX_FROM_UNKNOWN, &event);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        return NL_SKIP;
    }

    if ((attr = tb[NL80211_ATTR_FRAME]) == NULL) {
        wifi_hal_error_print("%s:%d: frame attribute absent ... dropping\n", __func__, __LINE__);
        return NL_SKIP;
    }
    mgmt = (struct ieee80211_mgmt *)nla_data(attr);
    len = nla_len(attr);

    //my_print_hex_dump(len, mgmt);
    if ((attr = tb[NL80211_ATTR_MAC]) == NULL) {
        //;
    }

    if (tb[NL80211_ATTR_RX_SIGNAL_DBM]) {
        sig_dbm = nla_get_u32(tb[NL80211_ATTR_RX_SIGNAL_DBM]);
    }
#if  (defined(TCXB7_PORT) || defined(CMXB7_PORT) || defined(TCXB8_PORT) || defined(TCHCBRV2_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined(VNTXER5_PORT))
    if (tb[NL80211_ATTR_RX_PHY_RATE_INFO]) {
        phy_rate = nla_get_u32(tb[NL80211_ATTR_RX_PHY_RATE_INFO]);
    }
#endif
    if ((attr = tb[NL80211_ATTR_REASON_CODE]) != NULL) {
        reason = nla_get_u16(attr);
    }
#ifdef CMXB7_PORT
    if (tb[NL80211_ATTR_RX_SNR_DB]) {
        snr = (int)nla_get_u32(tb[NL80211_ATTR_RX_SNR_DB]);
    }

    if (process_frame_mgmt(interface, mgmt, reason, sig_dbm, snr, phy_rate, len) < 0) {
        return NL_SKIP;
    }
#else
    if (process_frame_mgmt(interface, mgmt, reason, sig_dbm, phy_rate, len) < 0) {
        return NL_SKIP;
    }
#endif

    return NL_SKIP;
}

#ifdef WIFI_EMULATOR_CHANGE
char extra_mgmt[68] = { 0x10, 0xA7, 0x61, 0x04, 0xE9, 0x02, 0x00, 0x00, 0xE5, 0xE7, 0xDE, 0xE9, 
    0x84, 0x00, 0x02, 0x02, 
    0x0E, 0x00, 0x88, 0x00, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0x02, 0x80, 0x00, 0x00, 0x0B, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20, 0xA2, 0x01, 0x00, 0xBE, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x04, 0xB0, 0x04, 0x5B, 0x3F,
    0x00, 0x00, 0x00, 0x00 };

char mgmt_fcs[4] = { 0x33, 0x0E, 0xD1, 0x88 };

char extra_data[66] = { 0x75, 0xEB, 0x15, 0x03, 0xE7, 0x02, 0x00, 0x00, 0xE4, 0xE7, 0xDF, 0xDF,
    0x38, 0x00, 0x02, 0x01,
    0x16, 0x00, 0x87, 0x00, 0x01, 0x9B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x02, 0x80, 0x00, 0x01, 0x0B, 0x10, 0x00, 0x00, 0x00, 0x00, 0x63, 0xEA, 0x01, 0x00, 0x6E, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEB, 0x13, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00 };
#endif

static bool is_eapol_m3(uint8_t *data, size_t data_len)
{
    struct wpa_eapol_key *eapol_key;
    size_t min_eapol_len;
    uint16_t key_info_m3;

    min_eapol_len = sizeof(struct ieee802_1x_hdr) + sizeof(struct wpa_eapol_key);
    if (data_len < min_eapol_len) {
        wifi_hal_dbg_print("%s:%d: eapol data len %zu is less than %zu\n", __func__, __LINE__,
            data_len, min_eapol_len);
        return false;
    }

    eapol_key = (struct wpa_eapol_key *)(data + sizeof(struct ieee802_1x_hdr));
    key_info_m3 = WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_ACK | WPA_KEY_INFO_MIC;

    return (WPA_GET_BE16(eapol_key->key_info) & key_info_m3) == key_info_m3;
}

static bool is_eapol_m4(uint8_t *data, size_t data_len)
{
    struct wpa_eapol_key *eapol_key;
    size_t min_eapol_len;
    uint16_t key_info_m4;

    min_eapol_len = sizeof(struct ieee802_1x_hdr) + sizeof(struct wpa_eapol_key);
    if (data_len < min_eapol_len) {
        wifi_hal_dbg_print("%s:%d: eapol data len %zu is less than %zu\n", __func__, __LINE__,
            data_len, min_eapol_len);
        return false;
    }

    eapol_key = (struct wpa_eapol_key *)(data + sizeof(struct ieee802_1x_hdr));
    key_info_m4 = WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE;

    return (WPA_GET_BE16(eapol_key->key_info) & key_info_m4) == key_info_m4;
}

static int get_eapol_reply_counter(uint8_t *data, size_t data_len)
{
    struct wpa_eapol_key *eapol_key;
    size_t min_eapol_len;

    min_eapol_len = sizeof(struct ieee802_1x_hdr) + sizeof(struct wpa_eapol_key);
    if (data_len < min_eapol_len) {
        wifi_hal_dbg_print("%s:%d: eapol data len %zu is less than %zu\n", __func__, __LINE__,
            data_len, min_eapol_len);
        return -1;
    }

    eapol_key = (struct wpa_eapol_key *)(data + sizeof(struct ieee802_1x_hdr));

    return eapol_key->replay_counter[WPA_REPLAY_COUNTER_LEN - 1];
}

void recv_data_frame(wifi_interface_info_t *interface)
{
    unsigned char buff[2048];
    struct sockaddr saddr;
    int buflen, saddr_len, sock;
    struct ieee8023_hdr *eth_hdr;
    //wifi_direction_t dir;
    wifi_vap_info_t *vap;
    mac_address_t sta;
    union wpa_event_data event;
    struct ieee802_1x_hdr *hdr;
    mac_addr_str_t src_mac_str, dst_mac_str;
#ifdef WIFI_EMULATOR_CHANGE
    static int fd_c = -1;
#endif

    vap = &interface->vap_info;
    saddr_len = sizeof(saddr);
    memset(buff, 0, sizeof(buff));

    //Receive a network packet and copy in to buffer
    sock = (vap->vap_mode == wifi_vap_mode_ap) ? interface->u.ap.br_sock_fd :
        interface->u.sta.sta_sock_fd;
    buflen = recvfrom(sock, buff, sizeof(buff), MSG_DONTWAIT, &saddr, (socklen_t *)&saddr_len);
    if (buflen < 0) {
        wifi_hal_info_print("%s:%d: failed to receive packet on sock: %d interface: %s, "
            "err: %d (%s)\n", __func__, __LINE__, sock, interface->name, errno, strerror(errno));
        return;
    }

    if (buflen == 0) {
        wifi_hal_info_print("%s:%d: vap %s socket was closed\n", __func__, __LINE__,
            vap->vap_name);
        return;
    }
    //wifi_hal_dbg_print("%s:%d: %s bridge descriptor set, received %d bytes of data\n", __func__, __LINE__,
        //interface->name, buflen);

    //my_print_hex_dump(buflen, buff);
    if (buflen < sizeof(struct ieee8023_hdr)) {
        wifi_hal_info_print("%s:%d: packet is too short, len=%d\n", __func__, __LINE__,
            buflen);
        return;
    }
#ifdef WIFI_EMULATOR_CHANGE
    if ((access(ONEWIFI_TESTSUITE_TMPFILE, R_OK)) == 0) {
        struct ethhdr ethhdr;
        memcpy(&ethhdr, buff, sizeof(struct ethhdr));

        if (ethhdr.h_proto == ntohs(9001)) {
            if (vap->vap_mode == wifi_vap_mode_ap) {
                int ret;
                struct nl_msg *msg;
                unsigned char *data;
                size_t shift, len;
                u16 rtap_len;
                struct ieee80211_mgmt *mgmt = NULL;
                mac_address_t bmac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

                rtap_len = WPA_GET_BE16(buff + sizeof(struct ethhdr) + 2);
                shift = sizeof(struct ethhdr) + ntohs(rtap_len);
                len  = buflen - shift;

                char rssi = *(buff + sizeof(struct ethhdr) + 15);
                char bitrate = *(buff + sizeof(struct ethhdr) + 10);
                char noise = *(buff + sizeof(struct ethhdr) + 16);

                wifi_hal_dbg_print("%s:%d Rssi 0x%02x bitrate 0x%02x noise 0x%02x\n", __func__, __LINE__, rssi, bitrate, noise);
                mgmt = (struct ieee80211_mgmt *)(buff + shift);

                if ((memcmp(mgmt->da, bmac, sizeof(mac_address_t)) != 0) && (memcmp(mgmt->da, interface->mac, sizeof(mac_address_t)) != 0))
                    return;

                // 66 Broadcom SW+HW headers + 2 pad + 4 fcs
                data = (unsigned char*)calloc(len + 68 + 4, sizeof(unsigned char));

                if (data == NULL)
                    return;

                memcpy(data, extra_mgmt, 68);
                memcpy(data + 68, buff + shift, len);
                memcpy(data + 68 + len, mgmt_fcs, 4);

                // Update len for Broadcom header
                data[12] = len + 20;
                data[6] = interface->phy_index;
                // RSSI + antenas rssi
                data[4] = rssi;
                data[8] = rssi + 2;
                data[9] = rssi + 4;
                data[10] = rssi + 1;
                data[11] = rssi - 3;

                if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SEND_USR_PACKET)) == NULL) {
                    wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
                } else {
                    nla_put(msg, NL80211_ATTR_FRAME, len + 68 + 4, data);

                    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
                    if (ret != 0) {
                        wifi_hal_error_print("%s:%d: Failed to send packet for interface: %s error: %d(%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
                    }
                }

                free(data);
            }

            return;
        }

        if (ethhdr.h_proto == ntohs(9002)) {
            int ret;
            unsigned char *data;
            struct nl_msg *msg;
            struct sta_info *station;
            size_t shift, len;
            u16 rtap_len;
            mac_addr_str_t mac_str;
            int proto;
            char rssi, noise;

            rtap_len = WPA_GET_BE16(buff + sizeof(struct ethhdr) + 2);
            shift = sizeof(struct ethhdr) + ntohs(rtap_len);
            len  = buflen - shift;

            memcpy(sta, buff + shift + 10, sizeof(mac_address_t));
            //Check if not from us and to us
            if ((memcmp(sta, interface->mac, sizeof(mac_address_t)) == 0) ||
                (memcmp(buff + shift + 4, interface->mac, sizeof(mac_address_t)) != 0)) {
                return;
            }

            station = ap_get_sta(&interface->u.ap.hapd, sta);
            proto = WPA_GET_BE16(buff + shift + 32);
            if ((proto == ETH_P_EAPOL)) {
                //Shift for QoS+LLC headers
                hdr = (struct ieee802_1x_hdr *)(buff + shift + 34);

                wifi_hal_dbg_print("%s:%d: EAPOL version:%d type:%d length:%d from: %s\n", __func__, __LINE__,
                    hdr->version, hdr->type, hdr->length, to_mac_str(sta, mac_str));
            } else if (!station || !(station->flags & WLAN_STA_AUTHORIZED)) {
                return;
            }

            rssi = *(buff + sizeof(struct ethhdr) + 15);
            noise = *(buff + sizeof(struct ethhdr) + 16);

            wifi_hal_dbg_print("%s:%d Data frame Rssi 0x%02x Noise 0x%02x\n", __func__, __LINE__, rssi, noise);


            // 66 is Broadcom SW+HW headers
            data = (unsigned char*) calloc(len + 66, sizeof(unsigned char));

            if (data == NULL) {
                return;
            }

            memcpy(data, extra_data, 66);
            memcpy(data + 66, buff + shift, len);
            // Update len for Broadcom header
            data[12] = len + 20;
            data[6] = interface->phy_index;
            // RSSI + antenas rssi
            data[4] = rssi;
            data[8] = rssi + 2;
            data[9] = rssi + 4;
            data[10] = rssi + 1;
            data[11] = rssi - 3;



            if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SEND_USR_PACKET)) == NULL) {
                wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
            } else {
                nla_put(msg, NL80211_ATTR_FRAME, len + 66, data);

                ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
                if (ret != 0) {
                    wifi_hal_error_print("%s:%d: Failed to send packet for interface: %s error: %d(%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
                }
            }

            free(data);

            return;
        }
    }
#endif

    eth_hdr = (struct ieee8023_hdr *)buff;

    if (eth_hdr->ethertype != host_to_be16(ETH_P_EAPOL)) {
        return;
    }

    if (memcmp(eth_hdr->dest, interface->mac, sizeof(mac_address_t)) == 0) {
        // received frame
      //  dir = wifi_direction_uplink;
        memcpy(sta, eth_hdr->src, sizeof(mac_address_t));
    } else if (memcmp(eth_hdr->src, interface->mac, sizeof(mac_address_t)) == 0) {
        // transmitted frame
      //  dir = wifi_direction_downlink;
        memcpy(sta, eth_hdr->dest, sizeof(mac_address_t));
    } else {
        // drop
        return;
    }


    //data_frame_received_callback(vap->vap_index, sta, buff, buflen, WIFI_DATA_FRAME_TYPE_8021x, dir);
    if (buflen < sizeof(struct ieee8023_hdr) + sizeof(struct ieee802_1x_hdr)) {
        wifi_hal_info_print("%s:%d: packet is too short, len=%d\n", __func__, __LINE__,
            buflen);
        return;
    }

    hdr = (struct ieee802_1x_hdr *)(buff + sizeof(struct ieee8023_hdr));
    wifi_hal_dbg_print("%s:%d:version:%d type:%d length:%d\n", __func__, __LINE__,
        hdr->version, hdr->type, hdr->length);
    if (vap->vap_mode == wifi_vap_mode_ap) {
        os_memset(&event, 0, sizeof(event));
        event.eapol_rx.src = (unsigned char *)&sta;
        event.eapol_rx.data = (unsigned char *)hdr;
        event.eapol_rx.data_len = buflen - sizeof(struct ieee8023_hdr);
#if HOSTAPD_VERSION >= 211
        event.eapol_rx.link_id = NL80211_DRV_LINK_ID_NA;
#endif /* HOSTAPD_VERSION >= 211 */
        //Capture the EAPOL frames 2 and 4 on AP
#ifdef WIFI_EMULATOR_CHANGE
        if ((access(ONEWIFI_TESTSUITE_TMPFILE, R_OK)) == 0) {
            if (fd_c < 0) {
                fd_c = open("/dev/rdkfmac_dev", O_RDWR);
                if (fd_c < 0) {
                    wifi_hal_info_print("%s:%d: failed to open to char dev\n", __func__, __LINE__);
                }
            }
            if (fd_c > 0) {
                unsigned char c_buff[2048];
                unsigned char *t_buff = c_buff;
                unsigned int type = wlan_emu_msg_type_frm80211, ops_type = 0;
                memset(t_buff, 0, 2048);
                memcpy(t_buff, &type, sizeof(unsigned int));
                t_buff += sizeof(unsigned int);

                memcpy(t_buff, &ops_type, sizeof(unsigned int));
                t_buff += sizeof(unsigned int);

                unsigned int len = buflen + sizeof(eapol_qos_info) + sizeof(llc_info);
                memcpy(t_buff, &len, sizeof(unsigned int));
                t_buff += sizeof(unsigned int);

                memcpy(t_buff, eth_hdr->src, ETH_ALEN);
                t_buff += ETH_ALEN;

                memcpy(t_buff, eth_hdr->dest, ETH_ALEN);
                t_buff += ETH_ALEN;

                memcpy(eapol_qos_info+4, eth_hdr->dest, ETH_ALEN);
                memcpy(eapol_qos_info+10, eth_hdr->src, ETH_ALEN);
                memcpy(eapol_qos_info+10+ETH_ALEN, eth_hdr->src, ETH_ALEN);
                memcpy(t_buff, eapol_qos_info, sizeof(eapol_qos_info));
                t_buff += sizeof(eapol_qos_info);

                memcpy(t_buff, llc_info, sizeof(llc_info));
                t_buff += sizeof(llc_info);

                unsigned char *eapol_tmp_buff = NULL;

                eapol_tmp_buff = buff + 14;

                memcpy(t_buff, eapol_tmp_buff, len);

                if (write(fd_c, c_buff, 2048) > 0) {
//                    wifi_hal_dbg_print("%s:%d: write succesful bytes written : %d for EAPOL data\n", __func__, __LINE__, len);
                }

                close(fd_c);
                fd_c = -1;
            }
        }
#endif

        buflen -= sizeof(struct ieee8023_hdr);
        wifi_hal_info_print("%s:%d: interface:%s received eapol m%d from:%s to:%s "
                            "reply counter:%d\n",
            __func__, __LINE__, interface->name, is_eapol_m4((uint8_t *)hdr, buflen) ? 4 : 2,
            to_mac_str(eth_hdr->src, src_mac_str), to_mac_str(eth_hdr->dest, dst_mac_str),
            get_eapol_reply_counter((uint8_t *)hdr, buflen));

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        wpa_supplicant_event(&interface->u.ap.hapd, EVENT_EAPOL_RX, &event);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    } else if (vap->vap_mode == wifi_vap_mode_sta) {
        if (interface->u.sta.wpa_sm) {
#if HOSTAPD_VERSION >= 211 //2.11
            if (!interface->u.sta.wpa_sm->eapol || !eapol_sm_rx_eapol(interface->u.sta.wpa_sm->eapol,(unsigned char *)&sta,
                (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr), FRAME_ENCRYPTION_UNKNOWN)) {
                wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&sta, (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr), FRAME_ENCRYPTION_UNKNOWN);
            }
#else
            if (!interface->u.sta.wpa_sm->eapol || !eapol_sm_rx_eapol(interface->u.sta.wpa_sm->eapol,(unsigned char *)&sta,
                (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr))) {
                wpa_sm_rx_eapol(interface->u.sta.wpa_sm, (unsigned char *)&sta, (unsigned char *)hdr, buflen - sizeof(struct ieee8023_hdr));
            }
#endif
        }
        else if (interface->u.sta.state < WPA_ASSOCIATED) {
            interface->u.sta.pending_rx_eapol = true;
            memcpy(interface->u.sta.rx_eapol_buff, buff, sizeof(buff));
            interface->u.sta.buff_len = buflen;
            memcpy(interface->u.sta.src_addr, sta, sizeof(mac_address_t));
        }
    }
}

int parsertattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{

    if ((tb == NULL) && (rta == NULL)) {
        return -1;
    }

    memset(tb, 0 , sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta,len);
    }
    return 0;
}

void process_vapstatus_event(wifi_interface_info_t *interface, bool status)
{

    unsigned int i;
    wifi_device_callbacks_t *callbacks;
    wifi_vapstatus_t vap_status;
    callbacks = get_hal_device_callbacks();

    if (interface == NULL) {
        return;
    }

    if (callbacks == NULL) {
        return;
    }

    if(status) {
        vap_status = wifi_vapstatus_up;
    } else {
        vap_status = wifi_vapstatus_down;
    }
    if ((interface != NULL) && (interface->interface_status != status)) {
        interface->interface_status = status;
        for (i = 0; i < callbacks->num_vapstatus_cbs; i++) {
            if ((callbacks->vapstatus_cb[i] != NULL)){
                callbacks->vapstatus_cb[i](interface->vap_info.vap_index,vap_status);
            }
        }
    }
}

void recv_link_status()
{

    struct sockaddr_nl local;
    char buf[8192];
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    bool status;
    int sock_fd;
    struct sockaddr_ll sockaddr;
    char *ifName=NULL;
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio;
    unsigned int i = 0;
    bool found = false;

    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;
    local.nl_pid = getpid();

    struct msghdr msg;
    {
        msg.msg_name = &local;
        msg.msg_namelen = sizeof(local);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
    }

    ssize_t recvlen = recvmsg(g_wifi_hal.link_fd, &msg, 0);

    if (recvlen < 0) {
        return;
    }

    struct nlmsghdr *nlmsgHdr;

    for (nlmsgHdr = (struct nlmsghdr *)buf; NLMSG_OK(nlmsgHdr, (unsigned int)recvlen); nlmsgHdr = NLMSG_NEXT(nlmsgHdr, recvlen)) {
        if (nlmsgHdr->nlmsg_type == NLMSG_DONE) {
            return;
        }

        if (nlmsgHdr->nlmsg_type == NLMSG_ERROR) {
            return;
        }

        if ((nlmsgHdr->nlmsg_type == RTM_NEWLINK) || (nlmsgHdr->nlmsg_type == RTM_DELLINK)) {
            struct ifinfomsg *ifi;
            struct rtattr *tb[IFLA_MAX + 1];

            ifi = (struct ifinfomsg*) NLMSG_DATA(nlmsgHdr);

            if (parsertattr(tb, IFLA_MAX, IFLA_RTA(ifi), nlmsgHdr->nlmsg_len) < 0) {
                return;
            }

            if (tb[IFLA_IFNAME]) {
                ifName = (char *)RTA_DATA(tb[IFLA_IFNAME]);
                for (i = 0; ((i < g_wifi_hal.num_radios) && !found) ; i++) {
                    radio = get_radio_by_rdk_index(i);
                    if (radio == NULL) continue;
                    if (radio->interface_map == NULL) continue;
                    interface = hash_map_get_first(radio->interface_map);
                    while (interface != NULL) {
                        if(strncmp(interface->vap_info.bridge_name, ifName, strlen(interface->vap_info.bridge_name)+1) == 0) {
                            if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
                                switch (nlmsgHdr->nlmsg_type)
                                {
                                case RTM_DELLINK:
                                    if (interface->u.ap.br_sock_fd != 0) {
                                        wifi_hal_info_print("%s:%d: %s BRIDGE IS DELETED\n", __func__, __LINE__, interface->vap_info.bridge_name);
                                        close(interface->u.ap.br_sock_fd);
                                        interface->u.ap.br_sock_fd = 0;
                                        interface->bridge_configured = false;
                                    }
                                    break;
                                case RTM_NEWLINK:
                                    if (interface->u.ap.br_sock_fd != 0) {
                                        close(interface->u.ap.br_sock_fd);
                                        interface->u.ap.br_sock_fd = 0;
                                    }
                                    if (interface->u.ap.br_sock_fd == 0) {
                                        wifi_hal_info_print("%s:%d: %s BRIDGE IS CREATED\n", __func__, __LINE__, interface->vap_info.bridge_name);
                                        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

                                        if (sock_fd < 0) {
                                            wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, interface->vap_info.bridge_name);
                                        } else {
                                            memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
                                            sockaddr.sll_family   = AF_PACKET;
                                            sockaddr.sll_protocol = htons(ETH_P_ALL);
                                            sockaddr.sll_ifindex  = if_nametoindex(interface->vap_info.bridge_name);

                                            if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
                                                wifi_hal_error_print("%s:%d: Error in setting sockopt err:%d\n", __func__, __LINE__, errno);
                                                close(sock_fd);
                                                break;
                                            }
                                            if (bind(sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
                                                wifi_hal_error_print("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
                                                close(sock_fd);
                                            } else { 
                                                interface->u.ap.br_sock_fd = sock_fd;
                                                interface->bridge_configured = true;
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    break;
                                }
                            }
                        }

                        if(strncmp(interface->name, ifName, strlen(interface->name)+1) == 0) {
                            found = true;
                            break;
                        }
                        interface = hash_map_get_next(radio->interface_map, interface);
                    }
                }
            }
            if (!found) {
                return;
            }

            if (ifi->ifi_flags & IFF_UP) {
                status = true;
            } else {
                status = false;
            }

            switch (nlmsgHdr->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK:
                    process_vapstatus_event(interface, status);
                    break;
            }
        }
    }
}

void *nl_recv_func(void *arg)
{
    int ret, res;
    struct timeval tv_towait;
    wifi_hal_priv_t *priv = (wifi_hal_priv_t *)arg;
    wifi_interface_info_t *interface;
    int eloop_timeout_ms;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    while (1) {

        prepare_interface_fdset(priv);

        eloop_timeout_ms = eloop_get_timeout_ms();
        if (eloop_timeout_ms >= 0) {
            tv_towait.tv_sec = (eloop_timeout_ms / 1000);
            tv_towait.tv_usec = (eloop_timeout_ms % 1000) * 1000;
        } else {
            tv_towait.tv_sec = 1;
            tv_towait.tv_usec = 0;
        }

        ret = select(get_biggest_in_fdset(priv) + 1, &priv->drv_rfds, NULL, NULL, &tv_towait);
        if (ret < 0) {
            if ((errno == EINTR) || (errno == EBADF)) {
                continue;
            } else {
                wifi_hal_error_print("%s:%d:select error %d\n", __func__, __LINE__, errno);
                return NULL;
            }
        }

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        eloop_timeout_run();
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        if (FD_ISSET(priv->nl_event_fd, &priv->drv_rfds)) {
            res = nl_recvmsgs((struct nl_sock *)priv->nl_event, priv->nl_cb);
            if (res < 0) {
                wifi_hal_error_print("%s:%d: sock:%d nl_recvmsgs failed:%d (%s), errno:%d (%s)\n",
                    __func__, __LINE__, priv->nl_event_fd, res, nl_geterror(res), errno,
                    strerror(errno));
            }
        }

        if (mgmt_fd_isset(priv, &interface)) {
            //wifi_hal_dbg_print("%s:%d:Mgmt frame descriptor is set\n", __func__, __LINE__);
            res = nl_recvmsgs((struct nl_sock *)interface->nl_event, interface->nl_cb);
            if (res < 0) {
                wifi_hal_error_print("%s:%d: interface:%s ifindex:%d ifnametoindex:%d sock:%d "
                                    "nl_recvmsgs failed:%d (%s), errno:%d (%s)\n",
                    __func__, __LINE__, interface->name, interface->index,
                    if_nametoindex(interface->name), interface->nl_event_fd, res, nl_geterror(res),
                    errno, strerror(errno));
                /* workaround for socket error issue */
		wifi_hal_error_print("%s:%d: reopen NL socket\n", __func__, __LINE__);
		nl80211_unregister_mgmt_frames(interface);
		nl80211_register_mgmt_frames(interface);
            }
        }

        if (spurious_fd_isset(priv, &interface)) {
            res = nl_recvmsgs((struct nl_sock *)interface->spurious_nl_event,
                interface->spurious_nl_cb);
            if (res < 0) {
                wifi_hal_error_print("%s:%d: interface:%s ifindex:%d ifnametoindex:%d sock:%d "
                                     "spurious nl_recvmsgs failed:%d (%s), errno:%d (%s)\n",
                    __func__, __LINE__, interface->name, interface->index,
                    if_nametoindex(interface->name), interface->spurious_nl_event_fd, res,
                    nl_geterror(res), errno, strerror(errno));
            }
        }

#ifdef EAPOL_OVER_NL
        if (bss_fd_isset(priv, &interface)) {
            res = nl_recvmsgs((struct nl_sock *)interface->bss_nl_connect_event, interface->bss_nl_cb);
            if (res < 0) {
                wifi_hal_error_print("%s:%d: interface:%s ifindex:%d ifnametoindex:%d sock:%d "
                                     "eapol nl_recvmsgs failed:%d (%s), errno:%d (%s)\n",
                    __func__, __LINE__, interface->name, interface->index,
                    if_nametoindex(interface->name), interface->bss_nl_connect_event_fd, res,
                    nl_geterror(res), errno, strerror(errno));
            }
        }
#else
        if (bridge_fd_isset(priv, &interface)) {
            recv_data_frame(interface);
        }
#endif
        if (FD_ISSET(priv->link_fd, &priv->drv_rfds)) {
            recv_link_status();
        }

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        eloop_sock_table_read_dispatch(&priv->drv_rfds);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        wifi_hal_steering_check_sta_status(interface);
    }

    return NULL;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *err = arg;
    *err = 0;
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
    int *ret = arg;
    *ret = 0;

    return NL_SKIP;
}

static int cookie_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    u64 *cookie = arg;
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_COOKIE]) {
        *cookie = nla_get_u64(tb[NL80211_ATTR_COOKIE]);
    }
    return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
             void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
    int *ret = arg;
    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

    *ret = err->error;

    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
        return NL_SKIP;

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
        ack_len += err->msg.nlmsg_len - sizeof(*nlh);

    if (len <= ack_len)
        return NL_STOP;

    attrs = (void *) ((unsigned char *) nlh + ack_len);
    len -= ack_len;

    nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb[NLMSGERR_ATTR_MSG]) {
        len = strnlen((char *) nla_data(tb[NLMSGERR_ATTR_MSG]),
                  nla_len(tb[NLMSGERR_ATTR_MSG]));
        wifi_hal_dbg_print("%s:%d: kernel reports: %*s\n", __func__, __LINE__, len, (char *) nla_data(tb[NLMSGERR_ATTR_MSG]));
    }

    return NL_SKIP;
}


static void nl_destroy_handles(struct nl_handle **handle)
{
    if (*handle == NULL)
        return;

    nl_socket_free((struct nl_sock *)*handle);

    *handle = NULL;
}

static void handle_destroy(struct nl_handle *handle)
{
    uint32_t port = nl_socket_get_local_port((const struct nl_sock *)handle);

    port >>= 22;
    g_wifi_hal.port_bitmap[port / 32] &= ~(1 << (port % 32));

    nl_socket_free((struct nl_sock *)handle);
}

struct nl_handle *nl_create_handle(struct nl_cb *cb, const char *dbg)
{
    struct nl_handle *handle;
    uint32_t pid = getpid() & 0x3FFFFF;
    int i;

    handle = (struct nl_handle *)nl_socket_alloc_cb(cb);
    if (handle == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate netlink callbacks (%s)\n", __func__, __LINE__, dbg);
        return NULL;
    }


    for (i = 0; i < 1024; i++) {
        if (g_wifi_hal.port_bitmap[i / 32] & (1 << (i % 32))) {
            continue;
        }
        g_wifi_hal.port_bitmap[i / 32] |= 1 << (i % 32);
        pid += i << 22;
        break;
    }

    nl_socket_set_local_port((struct nl_sock *)handle, pid);


    if (genl_connect((struct nl_sock *)handle)) {
        wifi_hal_error_print("%s:%d: Failed to connect to generic netlink (%s)\n", __func__, __LINE__, dbg);
        handle_destroy(handle);
        return NULL;
    }

    return handle;
}

static wifi_netlink_thread_info_t *create_nl80211_socket()
{
    wifi_netlink_thread_info_t *netlink_info = NULL;

    netlink_info = (wifi_netlink_thread_info_t *)malloc(sizeof(wifi_netlink_thread_info_t));
    memset(netlink_info, 0, sizeof(wifi_netlink_thread_info_t));

    netlink_info->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!netlink_info->nl_cb) {
        wifi_hal_error_print("%s:%d: Failed to allocate netlink callbacks\n", __func__, __LINE__);
        free(netlink_info);
        return NULL;
    }

    netlink_info->nl = nl_create_handle(netlink_info->nl_cb, "nl");
    if (netlink_info->nl == NULL) {
        nl_cb_put(netlink_info->nl_cb);
        free(netlink_info);
        return NULL;
    }

    nl_socket_set_nonblocking((struct nl_sock *)netlink_info->nl);
    /* after timeout seq numbers are not valid */
    nl_socket_disable_seq_check((struct nl_sock *)netlink_info->nl);

    return netlink_info;
}

static void nl80211_nlmsg_clear(struct nl_msg *msg)
{
    /*
     * Clear nlmsg data, e.g., to make sure key material is not left in
     * heap memory for unnecessarily long time.
     */
    if (msg) {
        struct nlmsghdr *hdr = nlmsg_hdr(msg);
        void *data = nlmsg_data(hdr);
        /*
         * This would use nlmsg_datalen() or the older nlmsg_len() if
         * only libnl were to maintain a stable API.. Neither will work
         * with all released versions, so just calculate the length
         * here.
         */
        int len = hdr->nlmsg_len - NLMSG_HDRLEN;

        memset(data, 0, len);
    }
}

static int nl80211_nlmsg_read(struct nl_sock *sock, struct nl_cb *cb)
{
    int ret;
    const int one_fd = 1;
    const int timeout_ms = 1000;
    struct pollfd pfd = { .events = POLLIN };

    pfd.fd = nl_socket_get_fd(sock);

    while ((ret = poll(&pfd, one_fd, timeout_ms)) < 0 && errno == EINTR) {
        wifi_hal_info_print("%s:%d: poll nl message interrupted, retry\n", __func__, __LINE__);
    }

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: failed to poll nl message, err %d (%s)\n", __func__, __LINE__,
            errno, strerror(errno));
        return -1;
    }

    if (ret == 0) {
        wifi_hal_error_print("%s:%d: failed to poll nl message, timeout\n", __func__, __LINE__);
        return -1;
    }

    ret = nl_recvmsgs(sock, cb);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: failed to receive nl message, err %d (%s)\n", __func__,
            __LINE__, ret, nl_geterror(ret));
        return -1;
    }

    return ret;
}

static int execute_send_and_recv(struct nl_cb *cb_ctx,
             struct nl_handle *nl_handle, struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data,
             int (*valid_finish_handler)(struct nl_msg *, void *),
             void *valid_finish_data)
{
    struct nl_cb *cb;
    wifi_finish_data_t  *finish_arg;
    int err = -1, opt;

    if (!msg) {
        wifi_hal_error_print("%s:%d: msg is null\n", __func__, __LINE__);
        return -1;
    }

    cb = nl_cb_clone(cb_ctx);
    if (!cb) {
        wifi_hal_error_print("%s:%d: failed to clone nl cb\n", __func__, __LINE__);
        goto out;
    }

    /* try to set NETLINK_EXT_ACK to 1, ignoring errors */
    opt = 1;
    setsockopt(nl_socket_get_fd((const struct nl_sock *)nl_handle), SOL_NETLINK,
           NETLINK_EXT_ACK, &opt, sizeof(opt));

    /* try to set NETLINK_CAP_ACK to 1, ignoring errors */
    opt = 1;
    setsockopt(nl_socket_get_fd((const struct nl_sock *)nl_handle), SOL_NETLINK,
           NETLINK_CAP_ACK, &opt, sizeof(opt));

    err = nl_send_auto_complete((struct nl_sock *)nl_handle, msg);
    if (err < 0) {
        wifi_hal_error_print("%s:%d: failed to send nl message, err %d (%s)\n", __func__, __LINE__,
            err, nl_geterror(err));
        goto out;
    }

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    if ((valid_finish_handler != NULL) && (valid_finish_data != NULL)) {
        finish_arg = (wifi_finish_data_t *)valid_finish_data;
        finish_arg->err = &err;
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, valid_finish_handler, valid_finish_data);
    } else {
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    }
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    if (valid_handler) {
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);
    }

    while (err > 0) {
        int res = nl80211_nlmsg_read((struct nl_sock *)nl_handle, cb);
        if (res < 0) {
            wifi_hal_error_print("%s:%d: failed to read nl message\n", __func__, __LINE__);
            break;
        }
    }
 out:
    nl_cb_put(cb);
    if (!valid_handler && valid_data == (void *) -1)
        nl80211_nlmsg_clear(msg);
    nlmsg_free(msg);
    return err;
}

#ifdef EAPOL_OVER_NL
static int nl80211_set_rx_control_port_owner(struct nl_msg *msg,
        void *valid_data)
{
    wifi_interface_info_t *interface = (wifi_interface_info_t*)valid_data;
    struct nl_handle *handle = interface->bss_nl_connect_event;
    struct nl_cb *cb = interface->bss_nl_cb;
    int ret = -1;

    if (!msg) {
        return -ENOMEM;
    }

    if (handle) {
        ret = (nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_OVER_NL80211) ||
                nla_put_flag(msg, NL80211_ATTR_SOCKET_OWNER) ||
                nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE) ||
                nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_PREAUTH));
        if (ret) {
            wifi_hal_error_print("%s:%d: NL Socket Owner set failed \n", __func__, __LINE__);
            return ret;
        }
    } else {
        wifi_hal_error_print("%s:%d: NL BSS connect handle is NULL \n", __func__, __LINE__);
        return ret;
    }

    ret = execute_send_and_recv(cb, handle, msg, NULL, valid_data, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d: Error sending \n", __func__, __LINE__);
    }

    return ret;
}
#endif


int nl80211_send_and_recv(struct nl_msg *msg,
             int (*valid_handler)(struct nl_msg *, void *),
             void *valid_data,
             int (*valid_finish_handler)(struct nl_msg *, void *),
             void *valid_finish_data)
{
    char thread_id[12];
    wifi_netlink_thread_info_t *nl_info = NULL;

    sprintf(thread_id, "%lu", pthread_self());

    pthread_mutex_lock(&g_wifi_hal.nl_create_socket_lock);
    nl_info = hash_map_get(g_wifi_hal.netlink_socket_map, thread_id);
    if (!nl_info) {
        if ((nl_info = create_nl80211_socket())) {
            hash_map_put(g_wifi_hal.netlink_socket_map, strdup(thread_id), nl_info);
        }
    }
    pthread_mutex_unlock(&g_wifi_hal.nl_create_socket_lock);

    return (nl_info ? execute_send_and_recv(nl_info->nl_cb, nl_info->nl, msg,
                    valid_handler, valid_data, valid_finish_handler,
                    valid_finish_data) : -1);
}

static int family_handler(struct nl_msg *msg, void *arg)
{
    struct family_data *res = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *mcgrp;
    int i;

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
        struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
        nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
              nla_len(mcgrp), NULL);
        if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
            !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
            strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
                   res->group,
                   nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0) {
            continue;
        }
        res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    };

    return NL_SKIP;
}

static inline int min_int(int a, int b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static int get_key_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                genlmsg_attrlen(gnlh, 0), NULL);

    /*
    * TODO: validate the key index and mac address!
    * Otherwise, there's a race condition as soon as
    * the kernel starts sending key notifications.
    */

    if (tb[NL80211_ATTR_KEY_SEQ]) {
        memcpy(arg, nla_data(tb[NL80211_ATTR_KEY_SEQ]),
           min_int(nla_len(tb[NL80211_ATTR_KEY_SEQ]), 6));
    }
    nl80211_nlmsg_clear(msg);
    return NL_SKIP;
}

static int nl_get_multicast_id(const char *family, const char *group)
{
    struct nl_msg *msg;
    int ret;
    struct family_data res = { group, -ENOENT };

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;
    if (!genlmsg_put(msg, 0, 0, genl_ctrl_resolve((struct nl_sock *)g_wifi_hal.nl, "nlctrl"),
             0, 0, CTRL_CMD_GETFAMILY, 0) ||
        nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family)) {
        nlmsg_free(msg);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, family_handler, &res, NULL, NULL);
    if (ret == 0)
        ret = res.id;
    return ret;
}

struct nl_msg *nl80211_cmd_msg_build(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd, struct nl_msg *msg)
{
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (intf != NULL) {
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, intf->index);
        nla_put_u32(msg, NL80211_ATTR_WIPHY, intf->phy_index);
    }

    return msg;
}

struct nl_msg *nl80211_ifindex_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd,
    int ifindex)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex) < 0) {
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

struct nl_msg *nl80211_drv_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd)
{
    struct nl_msg *msg;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        return NULL;
    }

    if (genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0) == NULL) {
        nlmsg_free(msg);
        return NULL;
    }

    if (intf != NULL) {
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, intf->index);
        nla_put_u32(msg, NL80211_ATTR_WIPHY, intf->phy_index);
    }

    return msg;
}

struct nl_msg *nl80211_drv_vendor_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags,
    uint32_t vendor_id, uint32_t subcmd)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(nl80211_id, intf, flags, NL80211_CMD_VENDOR);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create vendor command\n", __func__, __LINE__);
        return NULL;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendor_id) < 0) {
        wifi_hal_error_print("%s:%d Failed to put vendor id attribute\n", __func__, __LINE__);
        goto error;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd) < 0) {
        wifi_hal_error_print("%s:%d Failed to put sub command attribute\n", __func__, __LINE__);
        goto error;
    }

    return msg;

error:
    nlmsg_free(msg);
    return NULL;
}

int get_vap_state(const char *ifname, short *flags)
{
    struct ifreq ifr;
    int fd, res;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    wifi_hal_dbg_print("%s:%d interface name = '%s'\n", __func__, __LINE__, ifr.ifr_name);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        wifi_hal_error_print("%s %d socket error %s\n", __func__, __LINE__, strerror(errno));
        return -1;
    }

    errno = 0;
    res = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (res < 0) {
        wifi_hal_error_print("%s:%d ioctl failed: (%d) %s\n", __func__, __LINE__, res, strerror(errno));
    }
    close(fd);

    *flags = ifr.ifr_flags;

    return res;
}

#define run_prog(p, ...) ({ \
        int rc = -1, status; \
        pid_t pid = fork(); \
        if (!pid) \
                exit(execlp(p, p, ##__VA_ARGS__, NULL)); \
        if (pid < 0) {\
                rc = -1;\
        } else {\
                while ((rc = waitpid(pid, &status, 0)) == -1 && errno == EINTR); \
                rc = (rc == pid && WIFEXITED(status)) ? WEXITSTATUS(status) : -1; \
        }\
        rc;\
})

static
int ovs_add_br(const char *brname)
{
    wifi_hal_dbg_print("%s:%d ovs-vsctl add-br %s\n", __func__, __LINE__, brname);
    int rc = run_prog("/usr/bin/ovs-vsctl",
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
                      "--may-exist",
#endif
                      "add-br", brname);
    if (rc)
        return -1;

    return 0;
}

static
int ovs_br_exists(const char *brname)
{
    char buf[128] = {};
    char *p;
    FILE *f;

    f = popen("/usr/bin/ovs-vsctl list-br", "r");
    while (f && (p = fgets(buf, sizeof(buf), f))) {
        if (!strcmp(strsep(&p, "\n") ?: "", brname)) {
            if (f) pclose(f);
            return 0;
        }
    }

    if (f) pclose(f);
    return -1;
}

static
int ovs_if_get_br(char *brname, const char *ifname)
{
    char cmd[128];
    char *p;
    FILE *f;

    os_snprintf(cmd, sizeof(cmd), "/usr/bin/ovs-vsctl port-to-br %s", ifname);
    f = popen(cmd, "r");
    if (!f) return -1;
    p = fgets(brname, IFNAMSIZ, f);
    pclose(f);
    if (p == NULL || strlen(p) == 0) return -1;
    strsep(&p, "\n"); /* chomp \n */
    return 0;
}

static
int ovs_br_add_if(const char *brname, const char *ifname)
{
    wifi_hal_dbg_print("%s:%d ovs-vsctl add-port %s %s\n", __func__, __LINE__, brname, ifname);
    int rc = run_prog("/usr/bin/ovs-vsctl",
#if !defined(_PLATFORM_RASPBERRYPI_) && !defined(_PLATFORM_BANANAPI_R4_)
                      "--may-exist",
#endif
                      "add-port", brname, ifname);
    if (rc)
        return -1;
    return 0;
}

static
int ovs_br_del_if(const char *brname, const char *ifname)
{
    wifi_hal_dbg_print("%s:%d ovs-vsctl del-port %s %s\r\n", __func__, __LINE__, brname, ifname);
    if (run_prog("/usr/bin/ovs-vsctl", "del-port", brname, ifname))
        return -1;
    return 0;
}

int nl80211_set_mac(wifi_interface_info_t *interface)
{
    int ret;
    struct nl_sock *sk;
    struct nl_cache *link_cache;
    struct rtnl_link *device;
    struct nl_addr* addr;
    struct rtnl_link *newlink;
    mac_addr_str_t mac_str;
    wifi_vap_info_t *vap;

    vap = &interface->vap_info;

    wifi_hal_error_print("%s:%d Change mac for %s to %s \n", __func__, __LINE__, interface->name,
            to_mac_str(vap->u.sta_info.mac, mac_str));

    sk = nl_socket_alloc();
    if (sk == NULL) {
        wifi_hal_error_print("%s:%d Failed to allocate the socket\n", __func__, __LINE__);
        return -1;
    }

    if (nl_connect(sk, NETLINK_ROUTE)) {
        wifi_hal_error_print("%s:%d Unable to connect socket", __func__, __LINE__);
        nl_socket_free(sk);
        return -1;
    }

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) {
        wifi_hal_error_print("%s:%d Unable to allocate cache", __func__, __LINE__);
        nl_socket_free(sk);
        return -1;
    }

    nl_cache_refill(sk, link_cache);

    device = rtnl_link_get_by_name(link_cache, interface->name);

    newlink = rtnl_link_alloc();

    if (newlink == NULL) {
        wifi_hal_error_print("%s:%d Unable to allocate cache", __func__, __LINE__);
        rtnl_link_put(device);
        nl_cache_free(link_cache);
        nl_socket_free(sk);
        return NLE_NOMEM;
    }

    addr = nl_addr_build(AF_LLC, ether_aton(to_mac_str(vap->u.sta_info.mac, mac_str)), ETH_ALEN);
    rtnl_link_set_addr(newlink, addr);

    ret = rtnl_link_change(sk, device, newlink, NLM_F_CREATE | NLM_F_REPLACE);

    if (!ret) {
        wifi_hal_error_print("%s:%d Change mac for %s ret %d\n", __func__, __LINE__, interface->name, ret);
    }

    nl_addr_put(addr);
    rtnl_link_put(device);
    rtnl_link_put(newlink);
    nl_cache_free(link_cache);
    nl_socket_free(sk);

    return 0;
}

int nl80211_remove_from_bridge(const char *if_name)
{
    struct nl_sock *sk;
    struct nl_cache *link_cache;
    struct rtnl_link *device;
    char ovs_brname[IFNAMSIZ];

    if (access(OVS_MODULE, F_OK) == 0) {
        if (ovs_if_get_br(ovs_brname, if_name) == 0) {
            wifi_hal_dbg_print("%s:%d delete interface:%s mapping from ovs_brname:%s\n",  __func__, __LINE__, if_name, ovs_brname);
            if(ovs_br_del_if(ovs_brname, if_name) != 0) {
                wifi_hal_error_print("%s:%d deleting interface:%s on bridge:%s failed\n",  __func__, __LINE__, if_name, ovs_brname);
                return -1;
            }
        }
    }

    sk = nl_socket_alloc();

    if (nl_connect(sk, NETLINK_ROUTE)) {
        wifi_hal_error_print("Unable to connect socket");
        nl_socket_free(sk);
        return -1;
    }

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) {
        wifi_hal_error_print("Unable to allocate cache");
        nl_socket_free(sk);
        return -1;
    }

    nl_cache_refill(sk, link_cache);

    device = rtnl_link_get_by_name(link_cache, if_name);

    if (rtnl_link_release(sk, device)) {
        wifi_hal_error_print("%s:%d:Unable to release interface:%s \n", __func__, __LINE__, if_name);
        nl_cache_free(link_cache);
        nl_socket_free(sk);
        return -1;
    }

    rtnl_link_put(device);

    nl_cache_free(link_cache);
    nl_socket_free(sk);

    return 0;
}

int nl80211_create_bridge(const char *if_name, const char *br_name)
{
    struct nl_sock *sk;
    struct nl_cache *link_cache;
    struct rtnl_link *bridge, *device;
    char ovs_brname[IFNAMSIZ];
    bool is_hotspot_interface = false;
#if defined(VNTXER5_PORT)
    int ap_index;
#endif
    is_hotspot_interface = is_wifi_hal_vap_hotspot_from_interfacename(if_name);

#if defined(VNTXER5_PORT)
    if (strncmp(if_name, "mld", 3) == 0) {
        sscanf(if_name + 3, "%d", &ap_index);
        wifi_hal_info_print("%s:%d: ap_index is %d for interface:%s\n", __func__, __LINE__, ap_index, if_name);
        is_hotspot_interface |= is_wifi_hal_vap_hotspot(ap_index);
    }
#endif

    wifi_hal_info_print("%s:%d: bridge:%s interface:%s is hotspot:%d\n", __func__, __LINE__,
        br_name, if_name, is_hotspot_interface);

    if (access(OVS_MODULE, F_OK) == 0 && !is_hotspot_interface) {
        if (ovs_if_get_br(ovs_brname, if_name) == 0) {
            if (strcmp(br_name, ovs_brname) != 0) {
                wifi_hal_dbg_print("%s:%d mismatch\n",  __func__, __LINE__);
                if((ovs_br_del_if(ovs_brname, if_name) != 0) || (ovs_br_add_if(br_name, if_name) != 0)) {
                    wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                    return -1;
                }
            }
        } else {
            if(ovs_br_exists(br_name) == 0) {
                if (ovs_br_add_if(br_name, if_name) != 0) {
                    wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                    return -1;
                }
            } else {
                if (ovs_add_br(br_name) == 0) {
                    if (ovs_br_add_if(br_name, if_name) != 0) {
                        wifi_hal_error_print("%s:%d adding interface:%s to bridge:%s failed\n",  __func__, __LINE__, if_name, br_name);
                        return -1;
                    }
                }
            }
        }
        wifi_hal_dbg_print("%s:%d ovs bridge mapping for bridge:%s, interface:%s is created\n",  __func__, __LINE__, br_name, if_name);
        return 0;
    }

    sk = nl_socket_alloc();

    // verbose logging for bridge configuration debug
    wifi_hal_info_print("%s:%d: bridge:%s nl connect\n", __func__, __LINE__, br_name);

    if (nl_connect(sk, NETLINK_ROUTE)) {
        wifi_hal_error_print("Unable to connect socket");
        nl_socket_free(sk);
        return -1;
    }

    wifi_hal_info_print("%s:%d: bridge:%s nl add\n", __func__, __LINE__, br_name);
    rtnl_link_bridge_add(sk, br_name);

    wifi_hal_info_print("%s:%d: bridge:%s alloc cache\n", __func__, __LINE__, br_name);
    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache)) {
        wifi_hal_error_print("%s:%d bridge:%s failed to allocate cache\n",  __func__, __LINE__,
            br_name);
        nl_socket_free(sk);
        return -1;
    }

    wifi_hal_info_print("%s:%d: bridge:%s cache refill\n", __func__, __LINE__, br_name);
    nl_cache_refill(sk, link_cache);

    wifi_hal_info_print("%s:%d: bridge:%s get link\n", __func__, __LINE__, br_name);
    bridge = rtnl_link_get_by_name(link_cache, br_name);
    device = rtnl_link_get_by_name(link_cache, if_name);

    if(bridge == NULL) {
	wifi_hal_error_print("%s:%d: bridge:%s failed to get link\n", __func__, __LINE__, br_name);
        return -1;
    }

    if(device == NULL) {
	wifi_hal_error_print("%s:%d: bridge:%s failed to get link for device:%s\n", __func__,
            __LINE__, br_name, if_name);
        return -1;
    }

    wifi_hal_info_print("%s:%d: bridge:%s enslave device %s\n", __func__, __LINE__, br_name,
        if_name);
    if (rtnl_link_enslave(sk, bridge, device)) {
        wifi_hal_info_print("%s:%d: bridge:%s failed to enslave device %s\n", __func__, __LINE__,
            br_name, if_name);
        nl_cache_free(link_cache);
        nl_socket_free(sk);
        return -1;
    }

    wifi_hal_info_print("%s:%d: bridge:%s nl free\n", __func__, __LINE__, br_name);

    rtnl_link_put(bridge);
    rtnl_link_put(device);

    nl_cache_free(link_cache);
    nl_socket_free(sk);

    return 0;
}

void nl80211_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event)
{
    wifi_device_callbacks_t *callbacks;

    if (event->type == WIFI_STEERING_EVENT_CLIENT_CONNECT ||
        event->type == WIFI_STEERING_EVENT_PROBE_REQ ||
        event->type == WIFI_STEERING_EVENT_CLIENT_DISCONNECT ||
        event->type == WIFI_STEERING_EVENT_AUTH_FAIL) {
        return;
    }

    callbacks = get_hal_device_callbacks();
    if (callbacks->steering_event_callback != 0) {
        callbacks->steering_event_callback(steeringgroupIndex, event);
    }
}

int nl80211_interface_enable(const char *ifname, bool enable)
{
    struct ifreq ifr;
    int fd, res;
    short flags;

    if (get_vap_state(ifname, &flags) < 0) {
        wifi_hal_error_print("%s:%d could not get state of interface %s\n", __func__, __LINE__, ifname);
        return -1;
    }

    if (enable == true) {
        if (flags & IFF_UP) {
            // already up
            wifi_hal_dbg_print("%s:%d interface %s already up\n", __func__, __LINE__, ifname);
            return 0;
        } else {
            flags |= IFF_UP;
        }
    } else {
        if ((flags | ~IFF_UP) == 0) {
            // already down
            wifi_hal_dbg_print("%s:%d interface %s already down\n", __func__, __LINE__, ifname);
            return 0;
        } else {
            flags &= ~IFF_UP;
        }
    }

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        wifi_hal_error_print("%s:%d socket error %s\n", __func__, __LINE__, strerror(errno));
        return -1;
    }

    res = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);

    wifi_hal_dbg_print("Interface %s %s\n", ifname, enable ? "enabled" : "disabled");

    return res;
}

int nl80211_retry_interface_enable(wifi_interface_info_t *interface, bool enable)
{
    /* This function is required only for Raspberry PI platform when interfacing
      with Canakit dongle. In other platforms it does not do anything but returns
      success */
#ifdef _PLATFORM_RASPBERRYPI_
    /* Bring down the primary interface and then enable the secondary interface*/
    wifi_interface_info_t *primary_interface = NULL;
    wifi_radio_info_t *radio = NULL;
    int ret = 0;

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d interface is NULL.\n", __func__, __LINE__);
        return -1;
    }

    radio = get_radio_by_rdk_index(interface->rdk_radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d Radio of interface:%s is NULL.\n", __func__, __LINE__,
            interface->name);
        return -1;
    }

    primary_interface = get_primary_interface(radio);
    if (primary_interface == NULL) {
        wifi_hal_error_print("%s:%d primary interface of interface:%s is NULL.\n", __func__,
            __LINE__, interface->name);
        return -1;
    }

    ret = nl80211_interface_enable(primary_interface->name, false);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d unable to disable primary interface:%s\n", __func__, __LINE__,
            primary_interface->name);
        return ret;
    }

    ret = nl80211_interface_enable(interface->name, enable);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d unable to %s interface:%s\n", __func__, __LINE__,
            enable ? "enable" : "disable", interface->name);
        /* Don't return here, enable the primary_interface and then return*/
    }

    ret = nl80211_interface_enable(primary_interface->name, true);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d unable to enable primary interface:%s\n", __func__, __LINE__,
            primary_interface->name);
        return ret;
    }
    wifi_hal_dbg_print("%s:%d %s of interface:%s successful.\n", __func__, __LINE__,
        enable ? "enable" : "disable", interface->name);
    return ret;
#else
    wifi_hal_dbg_print("%s:%d Interface:%s do nothing, return success.\n", __func__, __LINE__,
        interface->name);
    return 0;
#endif
}

static int phy_info_rates(wifi_radio_info_t *radio, struct hostapd_hw_modes *mode, enum nl80211_band band, struct nlattr *tb)
{
    static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
        [NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
        [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] =
        { .type = NLA_FLAG },
    };
    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
    struct nlattr *nl_rate;
    int rem_rate, idx;

    if (tb == NULL) {
        return NL_OK;
    }

    mode->num_rates = 0;
    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
            continue;
        mode->num_rates++;
    }

    mode->rates = radio->rates[band];

    idx = 0;

    //wifi_hal_dbg_print("%s:%d: band: %d mode:%p number of rates: %d Rates: ", __func__, __LINE__,
    //    band, mode, mode->num_rates);
    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate), nla_len(nl_rate), rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE]) {
            continue;
        }
        mode->rates[idx] = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);
        //wifi_hal_dbg_print("%d\n", mode->rates[idx]);
        idx++;
    }

    //wifi_hal_dbg_print("\n");

    return NL_OK;
}


static void phy_info_ht_capa(struct hostapd_hw_modes *mode, struct nlattr *capa,
                 struct nlattr *ampdu_factor,
                 struct nlattr *ampdu_density,
                 struct nlattr *mcs_set)
{
    if (capa)
        mode->ht_capab = nla_get_u16(capa);

    if (ampdu_factor)
        mode->a_mpdu_params |= nla_get_u8(ampdu_factor) & 0x03;

    if (ampdu_density)
        mode->a_mpdu_params |= nla_get_u8(ampdu_density) << 2;

    if (mcs_set && nla_len(mcs_set) >= 16) {
        u8 *mcs;
        mcs = nla_data(mcs_set);
        os_memcpy(mode->mcs_set, mcs, 16);
    }
}


static void phy_info_vht_capa(struct hostapd_hw_modes *mode,
                  struct nlattr *capa,
                  struct nlattr *mcs_set)
{
    if (capa)
        mode->vht_capab = nla_get_u32(capa);

    if (mcs_set && nla_len(mcs_set) >= 8) {
        u8 *mcs;
        mcs = nla_data(mcs_set);
        os_memcpy(mode->vht_mcs_set, mcs, 8);
    }
}

static struct hostapd_hw_modes *phy_info_freqs(wifi_radio_info_t *radio, struct nlattr *tb, enum nl80211_band *nlband)
{
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *nl_freq;
    int rem_freq;
    wifi_radio_capabilities_t *cap;
    wifi_channels_list_t *channels;
    unsigned int freq = 0, freq_band = 0, i;
    struct hostapd_hw_modes *mode = NULL;
    struct hostapd_channel_data *chan;
    enum nl80211_dfs_state dfs_state;
    enum nl80211_band band;
    int found = 0;
    char channel_str[8], channels_str[512] = {};
#ifdef CONFIG_WMM
    static struct nla_policy wmm_policy[NL80211_WMMR_MAX + 1] = {
        [NL80211_WMMR_CW_MIN] = { .type = NLA_U16 },
        [NL80211_WMMR_CW_MAX] = { .type = NLA_U16 },
        [NL80211_WMMR_AIFSN] = { .type = NLA_U8 },
        [NL80211_WMMR_TXOP] = { .type = NLA_U16 },
    };
    struct nlattr *nl_wmm;
    struct nlattr *tb_wmm[NL80211_WMMR_MAX + 1];
    int rem_wmm, ac, count = 0;
#endif

    nla_for_each_nested(nl_freq, tb, rem_freq) {
        nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq), nla_len(nl_freq), NULL);

        if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
            goto skip;
        }

        if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ]) {
            goto skip;
        }

        freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
        if ((freq >= MIN_FREQ_MHZ_2G) && (freq <= MAX_FREQ_MHZ_2G)) {
            freq_band = WIFI_FREQUENCY_2_4_BAND;
            band = NL80211_BAND_2GHZ;
        } else if ((freq >= MIN_FREQ_MHZ_5G) && (freq <= MAX_FREQ_MHZ_5G)) {
            freq_band = WIFI_FREQUENCY_5_BAND;
            band = NL80211_BAND_5GHZ;
#if HOSTAPD_VERSION >= 210
        } else if ((freq >= MIN_FREQ_MHZ_6G) && (freq <= MAX_FREQ_MHZ_6G)) {
            freq_band = WIFI_FREQUENCY_6_BAND;
#ifndef LINUX_VM_PORT
            band = NL80211_BAND_6GHZ;
#endif
#endif
        } else {
            //wifi_hal_dbg_print("%s:%d: Unknown frequency: %d in attribute of phy index: %d\n", __func__, __LINE__,
            //    freq_band, radio->index);
            return NULL;
        }

        *nlband = band;

        mode = &radio->hw_modes[band];
        mode->channels = radio->channel_data[band];

        for (i = 0; i < mode->num_channels; i++) {
            if (freq == radio->channel_data[band][i].freq) {
                chan = &radio->channel_data[band][i];
                found = 1;
                break;
            }
        }

        if (!found) {
            chan = &radio->channel_data[band][mode->num_channels];
        }
        memset((unsigned char *)chan, 0, sizeof(struct hostapd_channel_data));
        chan->freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
        chan->flag = 0;
        chan->allowed_bw = ~0;
        chan->dfs_cac_ms = 0;


        if (ieee80211_freq_to_chan(chan->freq, (u8 *)&chan->chan) == NUM_HOSTAPD_MODES) {
            wifi_hal_error_print("%s:%d: Unable to convert frequency %d to channel number on phy index %d.\n", __func__, __LINE__,
                chan->freq, radio->index);
        }

        if (chan->chan == 0) {
            goto skip;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR]) {
            chan->flag |= HOSTAPD_CHAN_NO_IR;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR]) {
            chan->flag |= HOSTAPD_CHAN_RADAR;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_INDOOR_ONLY]) {
            chan->flag |= HOSTAPD_CHAN_INDOOR_ONLY;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_GO_CONCURRENT]) {
            chan->flag |= HOSTAPD_CHAN_GO_CONCURRENT;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_10MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_10;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_20MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_20;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40P;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40M;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_80;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_NO_160MHZ]) {
            chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_160;
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
            dfs_state = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

            switch (dfs_state) {
                case NL80211_DFS_USABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_USABLE;
                    break;

                case NL80211_DFS_AVAILABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_AVAILABLE;
                    break;

                case NL80211_DFS_UNAVAILABLE:
                    chan->flag |= HOSTAPD_CHAN_DFS_UNAVAILABLE;
                    break;
            }
        }

        if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]) {
            chan->dfs_cac_ms = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]);
        }

#ifdef CONFIG_WMM
        chan->wmm_rules_valid = 0;

        if (tb_freq[NL80211_FREQUENCY_ATTR_WMM]) {
            nla_for_each_nested(nl_wmm, tb_freq[NL80211_FREQUENCY_ATTR_WMM], rem_wmm) {
                if (nla_parse_nested(tb_wmm, NL80211_WMMR_MAX, nl_wmm, wmm_policy)) {
                    wifi_hal_info_print("%s:%d:Failed to parse WMM rules attribute\n", __func__, __LINE__);
                    break;
                }

                if (!tb_wmm[NL80211_WMMR_CW_MIN] || !tb_wmm[NL80211_WMMR_CW_MAX] || !tb_wmm[NL80211_WMMR_AIFSN] || !tb_wmm[NL80211_WMMR_TXOP]) {
                    wifi_hal_info_print("%s:%d: Channel is missing WMM rule attribute\n", __func__, __LINE__);
                    break;
                }

                ac = nl_wmm->nla_type;
                if (ac < 0 || ac >= WMM_AC_NUM) {
                    wifi_hal_info_print("%s:%d: Invalid AC value %d", __func__, __LINE__, ac);
                    break;
                }

                chan->wmm_rules[ac].min_cwmin = nla_get_u16(tb_wmm[NL80211_WMMR_CW_MIN]);
                chan->wmm_rules[ac].min_cwmax = nla_get_u16(tb_wmm[NL80211_WMMR_CW_MAX]);
                chan->wmm_rules[ac].min_aifs = nla_get_u8(tb_wmm[NL80211_WMMR_AIFSN]);
                chan->wmm_rules[ac].max_txop = nla_get_u16(tb_wmm[NL80211_WMMR_TXOP]) / 32;
                count++;
            }

            /* Set valid flag if all the AC rules are present */
            if (count == WMM_AC_NUM) {
                chan->wmm_rules_valid = 1;
            }
        }
#endif // CONFIG_WMM

        if (!found) {
            mode->num_channels++;
        }
skip:   found = 0;
    }

    if (!mode)
        return NULL;
    cap = &radio->capab;
    cap->band[cap->numSupportedFreqBand] = freq_band;
    channels = &cap->channel_list[cap->numSupportedFreqBand];
    channels->num_channels = mode->num_channels;
    chan = mode->channels;

    for (i = 0; i < channels->num_channels; i++) {
        u8 channel = 0;
        ieee80211_freq_to_chan(chan->freq, &channel);
        channels->channels_list[i] = channel;
        snprintf(channel_str, sizeof(channel_str), "%u ", channels->channels_list[i]);
        strcat(channels_str, channel_str);
        chan++;
    }
    wifi_hal_dbg_print("%s:%d: Freq Band: %s for radio: %d num channels: %d channels:\n%s\n",
        __func__, __LINE__, wifi_freq_bands_to_string(freq_band), radio->index,
        mode->num_channels, channels_str);

    return mode;
}

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
static void phy_info_iftype_copy(struct hostapd_hw_modes *mode,
                 enum ieee80211_op_mode opmode,
                 struct nlattr **tb, struct nlattr **tb_flags)
{
    enum nl80211_iftype iftype;
    size_t len;
    struct he_capabilities *he_capab = &mode->he_capab[opmode];

    switch (opmode) {
    case IEEE80211_MODE_INFRA:
        iftype = NL80211_IFTYPE_STATION;
        break;
    case IEEE80211_MODE_IBSS:
        iftype = NL80211_IFTYPE_ADHOC;
        break;
    case IEEE80211_MODE_AP:
        iftype = NL80211_IFTYPE_AP;
        break;
    case IEEE80211_MODE_MESH:
        iftype = NL80211_IFTYPE_MESH_POINT;
        break;
    default:
        return;
    }

    if (!nla_get_flag(tb_flags[iftype])) {
        return;
    }

    he_capab->he_supported = 1;

    if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]);

        if (len > sizeof(he_capab->phy_cap)) {
            len = sizeof(he_capab->phy_cap);
        }

        os_memcpy(he_capab->phy_cap,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]),
              len);
    }

    if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]);

        if (len > sizeof(he_capab->mac_cap)) {
            len = sizeof(he_capab->mac_cap);
        }

        os_memcpy(he_capab->mac_cap,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]),
              len);
    }

    if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]);

        if (len > sizeof(he_capab->mcs)) {
            len = sizeof(he_capab->mcs);
        }

        os_memcpy(he_capab->mcs,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]),
              len);
    }

    if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]);

        if (len > sizeof(he_capab->ppet)) {
            len = sizeof(he_capab->ppet);
        }

        os_memcpy(&he_capab->ppet,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]),
              len);
    }

#if HOSTAPD_VERSION >= 210
    if (tb[NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA]) {
        u16 capa;

        capa = nla_get_u16(tb[NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA]);
        he_capab->he_6ghz_capa = le_to_host16(capa);
    }
#endif /* HOSTAPD_VERSION >= 210 */

#ifdef CONFIG_IEEE80211BE
    struct eht_capabilities *eht_capab = &mode->eht_capab[opmode];

    if (!tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC] ||
        !tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY]) {
        return;
    }

    eht_capab->eht_supported = true;

    wifi_drv_get_phy_eht_cap_mac(eht_capab, tb);

    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY]);
        if (len > sizeof(eht_capab->phy_cap))
            len = sizeof(eht_capab->phy_cap);
        os_memcpy(eht_capab->phy_cap,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY]),
              len);
    }

    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET]);
        if (len > sizeof(eht_capab->mcs)) {
            len = sizeof(eht_capab->mcs);
        }

        os_memcpy(eht_capab->mcs,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET]),
              len);
    }

    if (tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE]) {
        len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE]);
        if (len > sizeof(eht_capab->ppet)) {
            len = sizeof(eht_capab->ppet);
        }

        os_memcpy(&eht_capab->ppet,
              nla_data(tb[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE]),
              len);
    }
#endif /* CONFIG_IEEE80211BE */
}

static int wiphy_info_iface_comb_process(wifi_radio_info_t *radio,
                     struct nlattr *nl_combi)
{
    struct nlattr *tb_comb[NUM_NL80211_IFACE_COMB];
    struct nlattr *tb_limit[NUM_NL80211_IFACE_LIMIT];
    struct nlattr *nl_limit, *nl_mode;
    int err, rem_limit, rem_mode;
    int combination_has_p2p = 0, combination_has_mgd = 0;
    static struct nla_policy
    iface_combination_policy[NUM_NL80211_IFACE_COMB] = {
        [NL80211_IFACE_COMB_LIMITS] = { .type = NLA_NESTED },
        [NL80211_IFACE_COMB_MAXNUM] = { .type = NLA_U32 },
        [NL80211_IFACE_COMB_STA_AP_BI_MATCH] = { .type = NLA_FLAG },
        [NL80211_IFACE_COMB_NUM_CHANNELS] = { .type = NLA_U32 },
        [NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS] = { .type = NLA_U32 },
    },
    iface_limit_policy[NUM_NL80211_IFACE_LIMIT] = {
        [NL80211_IFACE_LIMIT_TYPES] = { .type = NLA_NESTED },
        [NL80211_IFACE_LIMIT_MAX] = { .type = NLA_U32 },
    };

    err = nla_parse_nested(tb_comb, MAX_NL80211_IFACE_COMB,
                   nl_combi, iface_combination_policy);
    if (err || !tb_comb[NL80211_IFACE_COMB_LIMITS] ||
         !tb_comb[NL80211_IFACE_COMB_MAXNUM] ||
         !tb_comb[NL80211_IFACE_COMB_NUM_CHANNELS]) {
        return 0; /* broken combination */
    }

    if (tb_comb[NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS]) {
        radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_RADAR;
    }

    nla_for_each_nested(nl_limit, tb_comb[NL80211_IFACE_COMB_LIMITS],
                rem_limit) {
        err = nla_parse_nested(tb_limit, MAX_NL80211_IFACE_LIMIT,
                       nl_limit, iface_limit_policy);
        if (err || !tb_limit[NL80211_IFACE_LIMIT_TYPES]) {
            return 0; /* broken combination */
        }

        nla_for_each_nested(nl_mode,
                    tb_limit[NL80211_IFACE_LIMIT_TYPES],
                    rem_mode) {
            int ift = nla_type(nl_mode);
            if (ift == NL80211_IFTYPE_P2P_GO ||
                 ift == NL80211_IFTYPE_P2P_CLIENT) {
                combination_has_p2p = 1;
            }

            if (ift == NL80211_IFTYPE_STATION) {
                combination_has_mgd = 1;
            }
        }
        if (combination_has_p2p && combination_has_mgd) {
            break;
        }
    }

    if (combination_has_p2p && combination_has_mgd) {
        unsigned int num_channels =
            nla_get_u32(tb_comb[NL80211_IFACE_COMB_NUM_CHANNELS]);

        radio->driver_data.p2p_concurrent = 1;
        if (radio->driver_data.num_multichan_concurrent < num_channels) {
            radio->driver_data.num_multichan_concurrent = num_channels;
        }
    }

    return 0;
}

static unsigned int get_akm_suites_info(struct nlattr *tb)
{
    int i, num;
    unsigned int key_mgmt = 0;
    u32 *akms;

    if (!tb) {
        return 0;
    }

    num = nla_len(tb) / sizeof(u32);
    akms = nla_data(tb);
    for (i = 0; i < num; i++) {
        switch (akms[i]) {
        case RSN_AUTH_KEY_MGMT_UNSPEC_802_1X:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_WPA |
                WPA_DRIVER_CAPA_KEY_MGMT_WPA2;
            break;
        case RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
                WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
            break;
        case RSN_AUTH_KEY_MGMT_FT_802_1X:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT;
            break;
        case RSN_AUTH_KEY_MGMT_FT_PSK:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT_PSK;
            break;
#if HOSTAPD_VERSION >= 210 //2.10
        case RSN_AUTH_KEY_MGMT_802_1X_SHA256:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_802_1X_SHA256;
            break;
        case RSN_AUTH_KEY_MGMT_PSK_SHA256:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_PSK_SHA256;
            break;
        case RSN_AUTH_KEY_MGMT_TPK_HANDSHAKE:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_TPK_HANDSHAKE;
            break;
        case RSN_AUTH_KEY_MGMT_FT_SAE:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT_SAE;
            break;
        case RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT_802_1X_SHA384;
            break;
        case RSN_AUTH_KEY_MGMT_CCKM:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_CCKM;
            break;
        case RSN_AUTH_KEY_MGMT_OSEN:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_OSEN;
            break;
#endif
        case RSN_AUTH_KEY_MGMT_802_1X_SUITE_B:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_SUITE_B;
            break;
        case RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_SUITE_B_192;
            break;
        case RSN_AUTH_KEY_MGMT_OWE:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_OWE;
            break;
        case RSN_AUTH_KEY_MGMT_DPP:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_DPP;
            break;
        case RSN_AUTH_KEY_MGMT_FILS_SHA256:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FILS_SHA256;
            break;
        case RSN_AUTH_KEY_MGMT_FILS_SHA384:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FILS_SHA384;
            break;
        case RSN_AUTH_KEY_MGMT_FT_FILS_SHA256:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT_FILS_SHA256;
            break;
        case RSN_AUTH_KEY_MGMT_FT_FILS_SHA384:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_FT_FILS_SHA384;
            break;
        case RSN_AUTH_KEY_MGMT_SAE:
            key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_SAE;
            break;
        }
    }

    return key_mgmt;
}

static void get_iface_akm_suites_info(wifi_radio_info_t *radio,
                    struct nlattr *nl_akms)
{
    struct nlattr *tb[NL80211_IFTYPE_AKM_ATTR_MAX + 1];
    struct nlattr *nl_iftype;
    unsigned int key_mgmt;
    int i;

    if (!nl_akms) {
        return;
    }

    nla_parse(tb, NL80211_IFTYPE_AKM_ATTR_MAX,
          nla_data(nl_akms), nla_len(nl_akms), NULL);

    if (!tb[NL80211_IFTYPE_AKM_ATTR_IFTYPES] ||
         !tb[NL80211_IFTYPE_AKM_ATTR_SUITES]) {
        return;
    }

    radio->driver_data.has_key_mgmt_iftype = 1;
    key_mgmt = get_akm_suites_info(tb[NL80211_IFTYPE_AKM_ATTR_SUITES]);

    nla_for_each_nested(nl_iftype, tb[NL80211_IFTYPE_AKM_ATTR_IFTYPES], i) {
        switch (nla_type(nl_iftype)) {
        case NL80211_IFTYPE_ADHOC:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_IBSS] = key_mgmt;
            break;
        case NL80211_IFTYPE_STATION:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_STATION] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_AP:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_AP_BSS] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_AP_VLAN:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_AP_VLAN] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_MESH_POINT:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_MESH] = key_mgmt;
            break;
        case NL80211_IFTYPE_P2P_CLIENT:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_P2P_CLIENT] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_P2P_GO:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_P2P_GO] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_P2P_DEVICE] =
                key_mgmt;
            break;
        case NL80211_IFTYPE_NAN:
            radio->driver_data.capa.key_mgmt_iftype[WPA_IF_NAN] = key_mgmt;
            break;
        }

        wifi_hal_info_print("%s:%d: nl80211: supported key_mgmt 0x%x\n", __func__, __LINE__,
                key_mgmt);
    }
}

static void wiphy_info_feature_flags(wifi_radio_info_t *radio,
                     struct nlattr *tb)
{
    u32 flags;
    struct wpa_driver_capa *capa = &radio->driver_data.capa;

    if (tb == NULL) {
        return;
    }

    flags = nla_get_u32(tb);

    if (flags & NL80211_FEATURE_SK_TX_STATUS) {
        radio->driver_data.data_tx_status = 1;
    }

    if (flags & NL80211_FEATURE_INACTIVITY_TIMER) {
        capa->flags |= WPA_DRIVER_FLAGS_INACTIVITY_TIMER;
    }

    if (flags & NL80211_FEATURE_SAE) {
        capa->flags |= WPA_DRIVER_FLAGS_SAE;
    }

    if (flags & NL80211_FEATURE_NEED_OBSS_SCAN) {
        capa->flags |= WPA_DRIVER_FLAGS_OBSS_SCAN;
    }

    if (flags & NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE) {
        capa->flags |= WPA_DRIVER_FLAGS_HT_2040_COEX;
    }

    if (flags & NL80211_FEATURE_TDLS_CHANNEL_SWITCH) {
        wpa_printf(MSG_DEBUG, "nl80211: TDLS channel switch");
        capa->flags |= WPA_DRIVER_FLAGS_TDLS_CHANNEL_SWITCH;
    }

    if (flags & NL80211_FEATURE_P2P_GO_CTWIN) {
        radio->driver_data.p2p_go_ctwindow_supported = 1;
    }

    if (flags & NL80211_FEATURE_LOW_PRIORITY_SCAN) {
        radio->driver_data.have_low_prio_scan = 1;
    }

    if (flags & NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR) {
        radio->driver_data.mac_addr_rand_scan_supported = 1;
    }

    if (flags & NL80211_FEATURE_SCHED_SCAN_RANDOM_MAC_ADDR) {
        radio->driver_data.mac_addr_rand_sched_scan_supported = 1;
    }

    if (flags & NL80211_FEATURE_SUPPORTS_WMM_ADMISSION) {
        radio->driver_data.wmm_ac_supported = 1;
    }

    if (flags & NL80211_FEATURE_DS_PARAM_SET_IE_IN_PROBES) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_DS_PARAM_SET_IE_IN_PROBES;
    }

    if (flags & NL80211_FEATURE_WFA_TPC_IE_IN_PROBES) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_WFA_TPC_IE_IN_PROBES;
    }

    if (flags & NL80211_FEATURE_QUIET) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_QUIET;
    }

    if (flags & NL80211_FEATURE_TX_POWER_INSERTION) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_TX_POWER_INSERTION;
    }

    if (flags & NL80211_FEATURE_HT_IBSS) {
        capa->flags |= WPA_DRIVER_FLAGS_HT_IBSS;
    }

    if (flags & NL80211_FEATURE_FULL_AP_CLIENT_STATE) {
        capa->flags |= WPA_DRIVER_FLAGS_FULL_AP_CLIENT_STATE;
    }
}

static int ext_feature_isset(const u8 *ext_features, int ext_features_len,
                 enum nl80211_ext_feature_index ftidx)
{
    u8 ft_byte;

    if ((int) ftidx / 8 >= ext_features_len) {
        return 0;
    }

    ft_byte = ext_features[ftidx / 8];
    return (ft_byte & BIT(ftidx % 8)) != 0;
}


static void wiphy_info_ext_feature_flags(wifi_radio_info_t *radio,
                     struct nlattr *tb)
{
    struct wpa_driver_capa *capa = &radio->driver_data.capa;
    u8 *ext_features;
    int len;

    if (tb == NULL) {
        return;
    }

    ext_features = nla_data(tb);
    len = nla_len(tb);

    if (ext_feature_isset(ext_features, len, NL80211_EXT_FEATURE_VHT_IBSS)) {
        capa->flags |= WPA_DRIVER_FLAGS_VHT_IBSS;
    }

    if (ext_feature_isset(ext_features, len, NL80211_EXT_FEATURE_RRM)) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_SUPPORT_RRM;
    }

    if (ext_feature_isset(ext_features, len, NL80211_EXT_FEATURE_FILS_STA)) {
        capa->flags |= WPA_DRIVER_FLAGS_SUPPORT_FILS;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_RATE_LEGACY)) {
        capa->flags |= WPA_DRIVER_FLAGS_BEACON_RATE_LEGACY;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_RATE_HT)) {
        capa->flags |= WPA_DRIVER_FLAGS_BEACON_RATE_HT;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_RATE_VHT)) {
        capa->flags |= WPA_DRIVER_FLAGS_BEACON_RATE_VHT;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_RATE_HE)) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_BEACON_RATE_HE;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_SET_SCAN_DWELL)) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_SUPPORT_SET_SCAN_DWELL;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_SCAN_START_TIME) &&
        ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BSS_PARENT_TSF) &&
        ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_SET_SCAN_DWELL)) {
        capa->rrm_flags |= WPA_DRIVER_FLAGS_SUPPORT_BEACON_REPORT;
    }
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA)) {
        capa->flags |= WPA_DRIVER_FLAGS_MGMT_TX_RANDOM_TA;
    }
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_MGMT_TX_RANDOM_TA_CONNECTED)) {
        capa->flags |= WPA_DRIVER_FLAGS_MGMT_TX_RANDOM_TA_CONNECTED;
    }
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI)) {
        capa->flags |= WPA_DRIVER_FLAGS_SCHED_SCAN_RELATIVE_RSSI;
    }
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_FILS_SK_OFFLOAD)) {
        capa->flags |= WPA_DRIVER_FLAGS_FILS_SK_OFFLOAD;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK)) {
        capa->flags |= WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK;
    }
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X)) {
        capa->flags |= WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_8021X;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_MFP_OPTIONAL)) {
        capa->flags |= WPA_DRIVER_FLAGS_MFP_OPTIONAL;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_DFS_OFFLOAD)) {
        capa->flags |= WPA_DRIVER_FLAGS_DFS_OFFLOAD;
    }

#ifdef CONFIG_MBO
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_FILS_MAX_CHANNEL_TIME) &&
        ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_ACCEPT_BCAST_PROBE_RESP) &&
        ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_OCE_PROBE_REQ_HIGH_TX_RATE) &&
        ext_feature_isset(
            ext_features, len,
            NL80211_EXT_FEATURE_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION)) {
        capa->flags |= WPA_DRIVER_FLAGS_OCE_STA;
    }
#endif /* CONFIG_MBO */

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER)) {
        capa->flags |= WPA_DRIVER_FLAGS_FTM_RESPONDER;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211)) {
        capa->flags |= WPA_DRIVER_FLAGS_CONTROL_PORT;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_CONTROL_PORT_NO_PREAUTH)) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_CONTROL_PORT_RX;
    }

    if (ext_feature_isset(
            ext_features, len,
            NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS)) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_CONTROL_PORT_TX_STATUS;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_VLAN_OFFLOAD)) {
        capa->flags |= WPA_DRIVER_FLAGS_VLAN_OFFLOAD;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_CAN_REPLACE_PTK0)) {
        capa->flags |= WPA_DRIVER_FLAGS_SAFE_PTK0_REKEYS;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_PROTECTION)) {
        capa->flags |= WPA_DRIVER_FLAGS_BEACON_PROTECTION;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_EXT_KEY_ID)) {
        capa->flags |= WPA_DRIVER_FLAGS_EXTENDED_KEY_ID;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS)) {
        radio->driver_data.multicast_registrations = 1;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_FILS_DISCOVERY)) {
        radio->driver_data.fils_discovery = 1;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_UNSOL_BCAST_PROBE_RESP)) {
        radio->driver_data.unsol_bcast_probe_resp = 1;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT)) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_BEACON_PROTECTION_CLIENT;
    }

    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_OPERATING_CHANNEL_VALIDATION)) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_OCV;
    }

    /* XXX: is not present in nl80211_copy.h, maybe needs to be fixed
    if (ext_feature_isset(ext_features, len,
                  NL80211_EXT_FEATURE_RADAR_BACKGROUND)) {
        capa->flags2 |= WPA_DRIVER_RADAR_BACKGROUND;
    }*/
}

static unsigned int probe_resp_offload_support(int supp_protocols)
{
    unsigned int prot = 0;

    if (supp_protocols & NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS) {
        prot |= WPA_DRIVER_PROBE_RESP_OFFLOAD_WPS;
    }

    if (supp_protocols & NL80211_PROBE_RESP_OFFLOAD_SUPPORT_WPS2) {
        prot |= WPA_DRIVER_PROBE_RESP_OFFLOAD_WPS2;
    }

    if (supp_protocols & NL80211_PROBE_RESP_OFFLOAD_SUPPORT_P2P) {
        prot |= WPA_DRIVER_PROBE_RESP_OFFLOAD_P2P;
    }

    if (supp_protocols & NL80211_PROBE_RESP_OFFLOAD_SUPPORT_80211U) {
        prot |= WPA_DRIVER_PROBE_RESP_OFFLOAD_INTERWORKING;
    }

    return prot;
}

static void wiphy_info_probe_resp_offload(struct wpa_driver_capa *capa,
                      struct nlattr *tb)
{
    u32 protocols;

    if (tb == NULL) {
        return;
    }

    protocols = nla_get_u32(tb);
    wifi_hal_info_print("%s:%d: nl80211: Supports Probe Response offload in AP mode\n", __func__, __LINE__);
    capa->flags |= WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD;
    capa->probe_resp_offloads = probe_resp_offload_support(protocols);
}

static void wiphy_info_extended_capab(wifi_driver_data_t *drv,
                      struct nlattr *tb)
{
    int rem = 0, i;
    struct nlattr *tb1[NL80211_ATTR_MAX + 1], *attr;

    if (!tb || drv->num_iface_ext_capa == NL80211_IFTYPE_MAX) {
        return;
    }

    nla_for_each_nested(attr, tb, rem) {
        unsigned int len;
#if HOSTAPD_VERSION >= 211 // 2.11
        struct drv_nl80211_iface_capa *capa;
#else
        struct drv_nl80211_ext_capa *capa;
#endif // 2.11
        nla_parse(tb1, NL80211_ATTR_MAX, nla_data(attr),
              nla_len(attr), NULL);

        if (!tb1[NL80211_ATTR_IFTYPE] ||
             !tb1[NL80211_ATTR_EXT_CAPA] ||
             !tb1[NL80211_ATTR_EXT_CAPA_MASK]) {
            continue;
        }

        capa = &drv->iface_ext_capa[drv->num_iface_ext_capa];
        capa->iftype = nla_get_u32(tb1[NL80211_ATTR_IFTYPE]);
        wifi_hal_dbg_print(
            "%s:%d: nl80211: Driver-advertised extended capabilities for interface type %s",
            __func__, __LINE__, nl80211_iftype_str(capa->iftype));

        len = nla_len(tb1[NL80211_ATTR_EXT_CAPA]);
        capa->ext_capa = os_memdup(nla_data(tb1[NL80211_ATTR_EXT_CAPA]),
                       len);

        if (!capa->ext_capa) {
            goto err;
        }

        capa->ext_capa_len = len;

        len = nla_len(tb1[NL80211_ATTR_EXT_CAPA_MASK]);
        capa->ext_capa_mask =
            os_memdup(nla_data(tb1[NL80211_ATTR_EXT_CAPA_MASK]),
                  len);

        if (!capa->ext_capa_mask) {
            goto err;
        }

#if HOSTAPD_VERSION >= 211
#ifdef CONFIG_IEEE80211BE
        if (tb1[NL80211_ATTR_EML_CAPABILITY] &&
            tb1[NL80211_ATTR_MLD_CAPA_AND_OPS]) {
            capa->eml_capa = nla_get_u16(tb1[NL80211_ATTR_EML_CAPABILITY]);
            capa->mld_capa_and_ops =
                nla_get_u16(tb1[NL80211_ATTR_MLD_CAPA_AND_OPS]);
        }

        wifi_hal_dbg_print("%s:%d: nl80211: EML Capability: 0x%x MLD Capability: 0x%x", __func__,
            __LINE__, capa->eml_capa, capa->mld_capa_and_ops);
#endif /* CONFIG_IEEE80211BE */
#endif /* HOSTAPD_VERSION >= 211 */

        drv->num_iface_ext_capa++;
        if (drv->num_iface_ext_capa == NL80211_IFTYPE_MAX) {
            break;
        }
    }

    return;

err:
    /* Cleanup allocated memory on error */
    for (i = 0; i < NL80211_IFTYPE_MAX; i++) {
        os_free(drv->iface_ext_capa[i].ext_capa);
        drv->iface_ext_capa[i].ext_capa = NULL;
        os_free(drv->iface_ext_capa[i].ext_capa_mask);
        drv->iface_ext_capa[i].ext_capa_mask = NULL;
        drv->iface_ext_capa[i].ext_capa_len = 0;
    }
    drv->num_iface_ext_capa = 0;
}

static void wiphy_info_wowlan_triggers(struct wpa_driver_capa *capa,
                       struct nlattr *tb)
{
    struct nlattr *triggers[MAX_NL80211_WOWLAN_TRIG + 1];

    if (tb == NULL) {
        return;
    }

    if (nla_parse_nested(triggers, MAX_NL80211_WOWLAN_TRIG,
                 tb, NULL)) {
        return;
    }

    if (triggers[NL80211_WOWLAN_TRIG_ANY]) {
        capa->wowlan_triggers.any = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_DISCONNECT]) {
        capa->wowlan_triggers.disconnect = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_MAGIC_PKT]) {
        capa->wowlan_triggers.magic_pkt = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE]) {
        capa->wowlan_triggers.gtk_rekey_failure = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST]) {
        capa->wowlan_triggers.eap_identity_req = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE]) {
        capa->wowlan_triggers.four_way_handshake = 1;
    }
    if (triggers[NL80211_WOWLAN_TRIG_RFKILL_RELEASE]) {
        capa->wowlan_triggers.rfkill_release = 1;
    }
}

static int phy_info_iftype(struct hostapd_hw_modes *mode,
               struct nlattr *nl_iftype)
{
    struct nlattr *tb[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
    struct nlattr *tb_flags[NL80211_IFTYPE_MAX + 1];
    unsigned int i;

    nla_parse(tb, NL80211_BAND_IFTYPE_ATTR_MAX,
          nla_data(nl_iftype), nla_len(nl_iftype), NULL);

    if (!tb[NL80211_BAND_IFTYPE_ATTR_IFTYPES]) {
        return NL_STOP;
    }

    if (nla_parse_nested(tb_flags, NL80211_IFTYPE_MAX,
                 tb[NL80211_BAND_IFTYPE_ATTR_IFTYPES], NULL)) {
        return NL_STOP;
    }

    for (i = 0; i < IEEE80211_MODE_NUM; i++) {
        phy_info_iftype_copy(mode, i, tb, tb_flags);
    }

    return NL_OK;
}
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT

static int phy_info_band(wifi_radio_info_t *radio, struct nlattr *nl_band)
{
    struct nlattr *tb[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct hostapd_hw_modes *mode = NULL;
    enum nl80211_band band = 0;

    nla_parse(tb, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

    wifi_hal_dbg_print("%s:%d:band_type:%d rdk_radio_index:%d\n", __func__, __LINE__,
        nl_band->nla_type, radio->rdk_radio_index);
    if (tb[NL80211_BAND_ATTR_FREQS] == NULL) {
        wifi_hal_dbg_print("%s:%d: Frequency attributes not present\n", __func__, __LINE__);
        return NL_OK;
    }

    // get the hw mode also
    if ((mode = phy_info_freqs(radio, tb[NL80211_BAND_ATTR_FREQS], &band)) == NULL) {
        wifi_hal_dbg_print("%s:%d: Mode returned from phy_info_freqs is NULL\n", __func__,
            __LINE__);
        return NL_OK;
    }

    mode->mode = NUM_HOSTAPD_MODES;
    mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN | HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;
    mode->vht_mcs_set[0] = 0xff;
    mode->vht_mcs_set[1] = 0xff;
    mode->vht_mcs_set[4] = 0xff;
    mode->vht_mcs_set[5] = 0xff;

    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);
    phy_info_ht_capa(mode, tb_band[NL80211_BAND_ATTR_HT_CAPA],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
             tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
    phy_info_vht_capa(mode, tb_band[NL80211_BAND_ATTR_VHT_CAPA],
              tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
    phy_info_rates(radio, mode, band, tb_band[NL80211_BAND_ATTR_RATES]);

    return NL_OK;
}

static int phy_info_cipher(wifi_radio_info_t *radio, struct nlattr *nl_cipher)
{
    unsigned int num, i, *cipher;

    num = nla_len(nl_cipher)/sizeof(unsigned int);

    cipher = nla_data(nl_cipher);
    for (i = 0; i < num; i++) {
        //wifi_hal_dbg_print("%s:%d: supported cipher:%02x-%02x-%02x:%d\n", __func__, __LINE__,
            //cipher[i] >> 24, (cipher[i] >> 16) & 0xff,
            //(cipher[i] >> 8) & 0xff, cipher[i] & 0xff);

        switch (cipher[i]) {
        case RSN_CIPHER_SUITE_CCMP_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_CCMP_256;
            break;

        case RSN_CIPHER_SUITE_GCMP_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GCMP_256;
            break;

        case RSN_CIPHER_SUITE_CCMP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_CCMP;
            break;

        case RSN_CIPHER_SUITE_GCMP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GCMP;
            break;

        case RSN_CIPHER_SUITE_TKIP:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_TKIP;
            break;

        case RSN_CIPHER_SUITE_AES_128_CMAC:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP;
            break;

        case RSN_CIPHER_SUITE_BIP_GMAC_128:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_GMAC_128;
            break;

        case RSN_CIPHER_SUITE_BIP_GMAC_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_GMAC_256;
            break;

        case RSN_CIPHER_SUITE_BIP_CMAC_256:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_BIP_CMAC_256;
            break;

        case RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED:
            radio->capab.cipherSupported |= WIFI_CIPHER_CAPA_ENC_GTK_NOT_USED;
            break;

        }
    }

    return NL_OK;
}

static int wiphy_set_info_handler(struct nl_msg *msg, void *arg)
{
    return 0;
}

static int regulatory_domain_set_info_handler(struct nl_msg *msg, void *arg)
{
    return 0;
}

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
static void wiphy_info_mbssid(struct wpa_driver_capa *cap, struct nlattr *attr)
{
    struct nlattr *config[NL80211_MBSSID_CONFIG_ATTR_MAX + 1];

    if (nla_parse_nested(config, NL80211_MBSSID_CONFIG_ATTR_MAX, attr, NULL) != 0) {
        return;
    }

    if (config[NL80211_MBSSID_CONFIG_ATTR_MAX_INTERFACES] != NULL) {
        return;
    }

    cap->mbssid_max_interfaces = nla_get_u8(config[NL80211_MBSSID_CONFIG_ATTR_MAX_INTERFACES]);

    if (config[NL80211_MBSSID_CONFIG_ATTR_MAX_EMA_PROFILE_PERIODICITY] != NULL) {
        cap->ema_max_periodicity = nla_get_u8(
            config[NL80211_MBSSID_CONFIG_ATTR_MAX_EMA_PROFILE_PERIODICITY]);
    }

    wifi_hal_dbg_print("%s:%d mbssid: max interfaces %u, max profile periodicity %u", __func__,
        __LINE__, cap->mbssid_max_interfaces, cap->ema_max_periodicity);
}
#endif /* defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT) */

static int wiphy_dump_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio;
#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
    struct wpa_driver_capa *capa;
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    //unsigned int *cmd;
    unsigned int phy_index = 0;
#ifndef FEATURE_SINGLE_PHY
    int rdk_radio_index;
#else //FEATURE_SINGLE_PHY
    int rdk_radio_indices[MAX_NUM_RADIOS];
    int num_radios_mapped = MAX_NUM_RADIOS;
    int ret = 0;
#endif //FEATURE_SINGLE_PHY

#if defined(VNTXER5_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || \
    defined(SCXER10_PORT)
    int existing_radio_found = 0;
#endif
#ifdef CONFIG_WIFI_EMULATOR
  if (g_wifi_hal.num_radios > MAX_NUM_SIMULATED_CLIENT) {
#else
#ifndef FEATURE_SINGLE_PHY
    if (g_wifi_hal.num_radios > MAX_NUM_RADIOS) {
#else //FEATURE_SINGLE_PHY
    if (g_wifi_hal.num_radios >= MAX_NUM_RADIOS) {
#endif //FEATURE_SINGLE_PHY
#endif //CONFIG_WIFI_EMULATOR
        wifi_hal_dbg_print("%s:%d: Returning num radios:%d exceeds MAX:%d\n",
            __func__, __LINE__, g_wifi_hal.num_radios, MAX_NUM_RADIOS);
        return NL_SKIP;
    }

    gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

#if !defined(VNTXER5_PORT) && !defined(TCXB7_PORT) && !defined(TCXB8_PORT) && \
    !defined(XB10_PORT) && !defined(SCXER10_PORT)
    for (unsigned int j = 0; j < g_wifi_hal.num_radios; j++)
    {
        if (strcmp(g_wifi_hal.radio_info[j].name, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME])) == 0) {
            wifi_hal_dbg_print("%s:%d: Returning phy:%s already configured earlier\n",
                __func__, __LINE__, g_wifi_hal.radio_info[j].name);
            return NL_SKIP;
        }
    }
#endif

#ifdef CONFIG_WIFI_EMULATOR
    static unsigned int interface_radio_index = 0;
    static unsigned int prev_tidx = UINT_MAX;
    unsigned int tidx = 0, check = 0;
    sscanf(nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]), "wsim%d%n", &tidx, &check);
    if (check > 0 && prev_tidx != tidx) {
        phy_index = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
        update_interfaces_map(phy_index, interface_radio_index);
        interface_radio_index++;
        prev_tidx = tidx;
    }
    wifi_hal_info_print("%s:%d phy_index received is %d\n", __func__, __LINE__, phy_index);
#else
    phy_index = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
#endif //CONFIG_WIFI_EMULATOR

#ifndef FEATURE_SINGLE_PHY
    rdk_radio_index = get_rdk_radio_index(phy_index);

    if ( rdk_radio_index == -1 ) {
#else //FEATURE_SINGLE_PHY
    // Get the array of rdk_radio_indexes associated with this phy
    memset(rdk_radio_indices, 0, sizeof(rdk_radio_indices));
    ret = get_rdk_radio_indices(phy_index, rdk_radio_indices, &num_radios_mapped);
    wifi_hal_dbg_print("%s:%d: For phy_index:%u, num_radios_mapped:%d, g_wifi_hal.num_radios:%d\n",
                __func__, __LINE__, phy_index, num_radios_mapped, g_wifi_hal.num_radios);
    if (ret != 0) {
#endif //FEATURE_SINGLE_PHY
        wifi_hal_error_print("%s:%d: Skipping for phy_index = %u, "
                   "since it is not present in the interface table\n",
                   __func__,__LINE__, phy_index);
        return NL_SKIP;
    }

    //print_attributes(__func__, tb);
#ifdef FEATURE_SINGLE_PHY
    /* In case of BananaPi due to single phy architecture, multiple radios have to be
       processed in a single wiphy_dump_handler, thus the loop */
    for (unsigned int j=0; (j < num_radios_mapped && g_wifi_hal.num_radios < MAX_NUM_RADIOS); j++) {
#endif //FEATURE_SINGLE_PHY
#if !defined(VNTXER5_PORT) && !defined(TCXB7_PORT) && !defined(TCXB8_PORT) && \
    !defined(XB10_PORT) && !defined(SCXER10_PORT)
    radio = &g_wifi_hal.radio_info[g_wifi_hal.num_radios];
    memset((unsigned char *)radio, 0, sizeof(wifi_radio_info_t));
#else
#ifdef CONFIG_WIFI_EMULATOR
    for (int i = 0; i < MAX_NUM_SIMULATED_CLIENT; i++) {
#else
    for (int i = 0; i < MAX_NUM_RADIOS; i++) {
#endif
        if (g_wifi_hal.radio_info[i].index == phy_index) {
            radio = &g_wifi_hal.radio_info[i];
            existing_radio_found = 1;
            break;
        }
    }
    if (!existing_radio_found) {
        radio = &g_wifi_hal.radio_info[g_wifi_hal.num_radios];
        g_wifi_hal.num_radios++;
    }
#endif

    if (tb[NL80211_ATTR_WIPHY]) {
        radio->index = phy_index;
#ifndef FEATURE_SINGLE_PHY
        radio->rdk_radio_index = rdk_radio_index;
#else //FEATURE_SINGLE_PHY
        radio->rdk_radio_index = rdk_radio_indices[j];
#endif //FEATURE_SINGLE_PHY
        radio->capab.index = radio->index;
    }

    if (tb[NL80211_ATTR_WIPHY_NAME]) {
        strcpy(radio->name, nla_get_string(tb[NL80211_ATTR_WIPHY_NAME]));
    }
#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
    capa = &radio->driver_data.capa;

    if (tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]) {
        capa->max_scan_ssids =
            nla_get_u8(tb[NL80211_ATTR_MAX_NUM_SCAN_SSIDS]);
    }

    if (tb[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]) {
        capa->max_sched_scan_ssids =
            nla_get_u8(tb[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS]);
    }

    if (tb[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS] &&
        tb[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL] &&
        tb[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]) {
        capa->max_sched_scan_plans =
            nla_get_u32(tb[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS]);

        capa->max_sched_scan_plan_interval =
            nla_get_u32(tb[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL]);

        capa->max_sched_scan_plan_iterations =
            nla_get_u32(tb[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS]);
    }

    if (tb[NL80211_ATTR_MAX_MATCH_SETS]) {
        capa->max_match_sets =
            nla_get_u8(tb[NL80211_ATTR_MAX_MATCH_SETS]);
    }

    if (tb[NL80211_ATTR_MAC_ACL_MAX]) {
        capa->max_acl_mac_addrs =
            nla_get_u32(tb[NL80211_ATTR_MAC_ACL_MAX]);
    }

    if (tb[NL80211_ATTR_SUPPORTED_IFTYPES]) {
        struct nlattr *nl_mode;
        int i;

        nla_for_each_nested(nl_mode, tb[NL80211_ATTR_SUPPORTED_IFTYPES], i) {
            switch (nla_type(nl_mode)) {
            case NL80211_IFTYPE_AP:
                capa->flags |= WPA_DRIVER_FLAGS_AP;
                break;
            case NL80211_IFTYPE_MESH_POINT:
                capa->flags |= WPA_DRIVER_FLAGS_MESH;
                break;
            case NL80211_IFTYPE_ADHOC:
                capa->flags |= WPA_DRIVER_FLAGS_IBSS;
                break;
            case NL80211_IFTYPE_P2P_DEVICE:
                capa->flags |=
                    WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE;
                break;
            case NL80211_IFTYPE_P2P_GO:
                radio->driver_data.p2p_go_supported = 1;
                break;
            case NL80211_IFTYPE_P2P_CLIENT:
                radio->driver_data.p2p_client_supported = 1;
                break;
            }
        }
    }

    if (tb[NL80211_ATTR_INTERFACE_COMBINATIONS]) {
        struct nlattr *nl_combi;
        int rem_combi;

        nla_for_each_nested(nl_combi, tb[NL80211_ATTR_INTERFACE_COMBINATIONS], rem_combi) {
            if (wiphy_info_iface_comb_process(radio, nl_combi) > 0)
                break;
        }
    }

    if (tb[NL80211_ATTR_SUPPORTED_COMMANDS]) {
        struct nlattr *nl_cmd;
        int i;

        nla_for_each_nested(nl_cmd, tb[NL80211_ATTR_SUPPORTED_COMMANDS], i) {
            switch (nla_get_u32(nl_cmd)) {
            case NL80211_CMD_AUTHENTICATE:
                radio->driver_data.auth_supported = 1;
                break;
            case NL80211_CMD_CONNECT:
                radio->driver_data.connect_supported = 1;
                break;
            case NL80211_CMD_START_SCHED_SCAN:
                capa->sched_scan_supported = 1;
                break;
            case NL80211_CMD_PROBE_CLIENT:
                radio->driver_data.poll_command_supported = 1;
                break;
            case NL80211_CMD_CHANNEL_SWITCH:
                radio->driver_data.channel_switch_supported = 1;
                break;
            case NL80211_CMD_SET_QOS_MAP:
                radio->driver_data.set_qos_map_supported = 1;
                break;
            case NL80211_CMD_UPDATE_FT_IES:
                radio->driver_data.update_ft_ies_supported = 1;
                break;
            }
        }
    }

    if (tb[NL80211_ATTR_CIPHER_SUITES]) {
        int i, num;
        u32 *ciphers;

        num = nla_len(tb[NL80211_ATTR_CIPHER_SUITES]) / sizeof(u32);
        ciphers = nla_data(tb[NL80211_ATTR_CIPHER_SUITES]);
        for (i = 0; i < num; i++) {
            u32 c = ciphers[i];

            wifi_hal_info_print("%s:%d: nl80211: Supported cipher %02x-%02x-%02x:%d\n", __func__, __LINE__,
                c >> 24, (c >> 16) & 0xff, (c >> 8) & 0xff, c & 0xff);

            switch (c) {
            case RSN_CIPHER_SUITE_CCMP_256:
                capa->enc |= WPA_DRIVER_CAPA_ENC_CCMP_256;
                break;
            case RSN_CIPHER_SUITE_GCMP_256:
                capa->enc |= WPA_DRIVER_CAPA_ENC_GCMP_256;
                break;
            case RSN_CIPHER_SUITE_CCMP:
                capa->enc |= WPA_DRIVER_CAPA_ENC_CCMP;
                break;
            case RSN_CIPHER_SUITE_GCMP:
                capa->enc |= WPA_DRIVER_CAPA_ENC_GCMP;
                break;
            case RSN_CIPHER_SUITE_TKIP:
                capa->enc |= WPA_DRIVER_CAPA_ENC_TKIP;
                break;
            case RSN_CIPHER_SUITE_WEP104:
                capa->enc |= WPA_DRIVER_CAPA_ENC_WEP104;
                break;
            case RSN_CIPHER_SUITE_WEP40:
                capa->enc |= WPA_DRIVER_CAPA_ENC_WEP40;
                break;
            case RSN_CIPHER_SUITE_AES_128_CMAC:
                capa->enc |= WPA_DRIVER_CAPA_ENC_BIP;
                break;
            case RSN_CIPHER_SUITE_BIP_GMAC_128:
                capa->enc |= WPA_DRIVER_CAPA_ENC_BIP_GMAC_128;
                break;
            case RSN_CIPHER_SUITE_BIP_GMAC_256:
                capa->enc |= WPA_DRIVER_CAPA_ENC_BIP_GMAC_256;
                break;
            case RSN_CIPHER_SUITE_BIP_CMAC_256:
                capa->enc |= WPA_DRIVER_CAPA_ENC_BIP_CMAC_256;
                break;
            case RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED:
                capa->enc |= WPA_DRIVER_CAPA_ENC_GTK_NOT_USED;
                break;
            }
        }
    }

    if (tb[NL80211_ATTR_AKM_SUITES]) {
        radio->driver_data.has_key_mgmt = 1;
        capa->key_mgmt = get_akm_suites_info(tb[NL80211_ATTR_AKM_SUITES]);

        wifi_hal_info_print("%s:%d: nl80211: wiphy supported key_mgmt 0x%x\n", __func__, __LINE__,
                capa->key_mgmt);
    }

    if (tb[NL80211_ATTR_IFTYPE_AKM_SUITES]) {
        struct nlattr *nl_if;
        int rem_if;

        nla_for_each_nested(nl_if, tb[NL80211_ATTR_IFTYPE_AKM_SUITES], rem_if)
            get_iface_akm_suites_info(radio, nl_if);
    }

    if (tb[NL80211_ATTR_OFFCHANNEL_TX_OK]) {
        wifi_hal_info_print("%s:%d: nl80211: Using driver-based off-channel TX\n", __func__, __LINE__);
        capa->flags |= WPA_DRIVER_FLAGS_OFFCHANNEL_TX;
    }

    if (tb[NL80211_ATTR_ROAM_SUPPORT]) {
        wifi_hal_info_print("%s:%d: nl80211: Using driver-based roaming\n", __func__, __LINE__);
        capa->flags |= WPA_DRIVER_FLAGS_BSS_SELECTION;
    }

    if (tb[NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION]) {
        capa->max_remain_on_chan = nla_get_u32(tb[NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION]);
    }

    if (tb[NL80211_ATTR_SUPPORT_AP_UAPSD]) {
        capa->flags |= WPA_DRIVER_FLAGS_AP_UAPSD;
    }

    if (tb[NL80211_ATTR_TDLS_SUPPORT]) {
        wifi_hal_info_print("%s:%d: nl80211: TDLS supported\n", __func__, __LINE__);
        capa->flags |= WPA_DRIVER_FLAGS_TDLS_SUPPORT;

        if (tb[NL80211_ATTR_TDLS_EXTERNAL_SETUP]) {
            wifi_hal_info_print("%s:%d: nl80211: TDLS external setup\n", __func__, __LINE__);
            capa->flags |= WPA_DRIVER_FLAGS_TDLS_EXTERNAL_SETUP;
        }
    }

    if (tb[NL80211_ATTR_DEVICE_AP_SME]) {
        /* XXX: undeclared in nl80211_copy.h, maybe needs to be fixed
        u32 ap_sme_features_flags =
            nla_get_u32(tb[NL80211_ATTR_DEVICE_AP_SME]);

        if (ap_sme_features_flags & NL80211_AP_SME_SA_QUERY_OFFLOAD) {
            capa->flags2 |= WPA_DRIVER_FLAGS2_SA_QUERY_OFFLOAD_AP;
        }*/

        radio->driver_data.device_ap_sme = 1;
    }

    wiphy_info_feature_flags(radio, tb[NL80211_ATTR_FEATURE_FLAGS]);
    wiphy_info_ext_feature_flags(radio, tb[NL80211_ATTR_EXT_FEATURES]);
    wiphy_info_probe_resp_offload(capa,
                    tb[NL80211_ATTR_PROBE_RESP_OFFLOAD]);

    if (tb[NL80211_ATTR_EXT_CAPA] && tb[NL80211_ATTR_EXT_CAPA_MASK] &&
        radio->driver_data.extended_capa == NULL) {
        radio->driver_data.extended_capa =
            os_malloc(nla_len(tb[NL80211_ATTR_EXT_CAPA]));
        if (radio->driver_data.extended_capa) {
            os_memcpy(radio->driver_data.extended_capa,
                nla_data(tb[NL80211_ATTR_EXT_CAPA]),
                nla_len(tb[NL80211_ATTR_EXT_CAPA]));
            radio->driver_data.extended_capa_len =
                nla_len(tb[NL80211_ATTR_EXT_CAPA]);
        }
        radio->driver_data.extended_capa_mask =
            os_malloc(nla_len(tb[NL80211_ATTR_EXT_CAPA_MASK]));
        if (radio->driver_data.extended_capa_mask) {
            os_memcpy(radio->driver_data.extended_capa_mask,
                nla_data(tb[NL80211_ATTR_EXT_CAPA_MASK]),
                nla_len(tb[NL80211_ATTR_EXT_CAPA_MASK]));
        } else {
            os_free(radio->driver_data.extended_capa);
            radio->driver_data.extended_capa = NULL;
            radio->driver_data.extended_capa_len = 0;
        }
    }

    wiphy_info_extended_capab(&radio->driver_data, tb[NL80211_ATTR_IFTYPE_EXT_CAPA]);

    wiphy_info_wowlan_triggers(capa,
                tb[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED]);

    if (tb[NL80211_ATTR_MAX_AP_ASSOC_STA]) {
        capa->max_stations =
            nla_get_u32(tb[NL80211_ATTR_MAX_AP_ASSOC_STA]);
    }

    if (tb[NL80211_ATTR_MAX_CSA_COUNTERS]) {
        capa->max_csa_counters =
            nla_get_u8(tb[NL80211_ATTR_MAX_CSA_COUNTERS]);
    }

    if (tb[NL80211_ATTR_WIPHY_SELF_MANAGED_REG]) {
        capa->flags |= WPA_DRIVER_FLAGS_SELF_MANAGED_REGULATORY;
    }

    if (tb[NL80211_ATTR_MBSSID_CONFIG]) {
        wiphy_info_mbssid(capa, tb[NL80211_ATTR_MBSSID_CONFIG]);
    }

#if HOSTAPD_VERSION >= 211
#ifdef CONFIG_IEEE80211BE
    if (tb[NL80211_ATTR_MLO_SUPPORT]) {
        capa->flags2 |= WPA_DRIVER_FLAGS2_MLO;
    }
#endif /* CONFIG_IEEE80211BE */
#endif /* HOSTAPD_VERSION >= 211 */
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT
    if (tb[NL80211_ATTR_WDEV]) {
        radio->dev_id = nla_get_u64(tb[NL80211_ATTR_WDEV]);
    }

#if !defined(VNTXER5_PORT) && !defined(TCXB7_PORT) && !defined(TCXB8_PORT) && \
    !defined(XB10_PORT) && !defined(SCXER10_PORT)
    g_wifi_hal.num_radios++;
#endif
#ifdef FEATURE_SINGLE_PHY
    }
#endif //Braces corresponding to the for loop, for (j=0; (j < num_radios_mapped
    return NL_SKIP;

}

static int wiphy_get_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio = (wifi_radio_info_t *) arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    struct nlattr *nl_band;//, *nl_cmd;
    struct nlattr *nl_combi;
    struct nlattr *tb_comb[NUM_NL80211_IFACE_COMB];
    int rem_combi;
    int rem_band;
#ifdef FEATURE_SINGLE_PHY
    enum nl80211_band band_type, radio_nl80211_band_type;
    int num_bands=0;
#endif //FEATURE_SINGLE_PHY

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

#ifndef FEATURE_SINGLE_PHY
    if (tb[NL80211_ATTR_WIPHY]) {
        radio = get_radio_by_phy_index(nla_get_u32(tb[NL80211_ATTR_WIPHY]));
    } else {
        return NL_OK;
    }
#endif

    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio is null, returning\n", __func__, __LINE__);
        return NL_OK;
    }

    wifi_hal_dbg_print("%s:%d:wiphy index:%d rdk_radio_index:%d name:%s\n",
        __func__, __LINE__, radio->index, radio->rdk_radio_index, radio->name);

    radio->capab.cipherSupported = 0;
    if (tb[NL80211_ATTR_CIPHER_SUITES]) {
        phy_info_cipher(radio, tb[NL80211_ATTR_CIPHER_SUITES]);
    }
    radio->capab.numSupportedFreqBand = 0;
    memset((unsigned char *)radio->hw_modes, 0, NUM_NL80211_BANDS*sizeof(struct hostapd_hw_modes));
    if (tb[NL80211_ATTR_WIPHY_BANDS] != NULL) {
        nla_for_each_nested(nl_band, tb[NL80211_ATTR_WIPHY_BANDS], rem_band) {
#ifndef FEATURE_SINGLE_PHY
            phy_info_band(radio, nl_band);
            radio->capab.numSupportedFreqBand++;
#else //FEATURE_SINGLE_PHY
            //Check whether nl_band is applicable to the radio and process only
            //if it is applicable
            band_type = nl_band->nla_type;
            radio_nl80211_band_type = get_nl80211_band_from_rdk_radio_index(radio->rdk_radio_index);
            wifi_hal_dbg_print("%s:%d:band_type:%d radio_band_type:%d processing:%s\n",
                __func__, __LINE__, band_type, radio_nl80211_band_type,
                ((band_type == radio_nl80211_band_type)? "yes":"no"));
            if (band_type == radio_nl80211_band_type) {
                phy_info_band(radio, nl_band);
                radio->capab.numSupportedFreqBand++;
            }
            num_bands++;
#endif //FEATURE_SINGLE_PHY
        }
    } else {
        wifi_hal_info_print("%s:%d: Bands attribute not present in radio index:%d\n", __func__, __LINE__, radio->index);
    }
#ifdef FEATURE_SINGLE_PHY
    wifi_hal_dbg_print("%s:%d:Num bands supported:%d by phy index:%d\n", __func__, __LINE__,
        num_bands, radio->index);
    wifi_hal_dbg_print("%s:%d:Configured bands supported:%d in radio based on rdk_radio_index:%d\n",
        __func__, __LINE__, radio->capab.numSupportedFreqBand, radio->rdk_radio_index);
#endif //FEATURE_SINGLE_PHY
    if (tb[NL80211_ATTR_INTERFACE_COMBINATIONS]) {
        nla_for_each_nested(nl_combi, tb[NL80211_ATTR_INTERFACE_COMBINATIONS], rem_combi) {
            static struct nla_policy iface_combination_policy[NUM_NL80211_IFACE_COMB] = {
              [NL80211_IFACE_COMB_LIMITS] = { .type = NLA_NESTED },
              [NL80211_IFACE_COMB_MAXNUM] = { .type = NLA_U32 },
              [NL80211_IFACE_COMB_STA_AP_BI_MATCH] = { .type = NLA_FLAG },
              [NL80211_IFACE_COMB_NUM_CHANNELS] = { .type = NLA_U32 },
              [NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS] = { .type = NLA_U32 },
            };
            if ((nla_parse_nested(tb_comb, MAX_NL80211_IFACE_COMB, nl_combi, iface_combination_policy) != 0 ) || !tb_comb[NL80211_IFACE_COMB_MAXNUM])
                wifi_hal_info_print("%s:%d: Failed to parse interface combinations for radio index:%d\n", __func__, __LINE__, radio->index);
            else {
                radio->capab.maxNumberVAPs = nla_get_u32(tb_comb[NL80211_IFACE_COMB_MAXNUM]);
                if (radio->capab.maxNumberVAPs > MAX_NUM_VAP_PER_RADIO) {
                    wifi_hal_error_print("%s:%d: max number of vaps per radio[%d] value[%d] out of range\r\n",
                                            __func__, __LINE__, radio->index, radio->capab.maxNumberVAPs);
                    radio->capab.maxNumberVAPs = MAX_NUM_VAP_PER_RADIO;
                }
                //wifi_hal_dbg_print("%s:%d: Total number of interfaces for radio index:%d -> %d\n", __func__, __LINE__, radio->index, nla_get_u32(tb_comb[NL80211_IFACE_COMB_MAXNUM]));
            }
        }
    } else {
        wifi_hal_info_print("%s:%d: Interface combinations attribute not present in radio index:%d\n", __func__, __LINE__, radio->index);
    }
    return NL_OK;
}

static int interface_del_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int mgmt_frame_register_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    return NL_SKIP;
}

static int interface_set_mtu(wifi_interface_info_t *interface, int mtu)
{
    int ret, nl_sock;
    struct rtattr  *rta;
    struct {
        struct nlmsghdr nh;
        struct ifinfomsg  ifinfo;
        char   attrbuf[512];
    } req;

    nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (nl_sock < 0) {
        wifi_hal_error_print("%s:%d Failed to open socket\n", __func__, __LINE__);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_type  = RTM_NEWLINK;
    req.ifinfo.ifi_family = AF_UNSPEC;
    req.ifinfo.ifi_index  = if_nametoindex(interface->name);

    if (!req.ifinfo.ifi_index) {
        wifi_hal_error_print("%s:%d Failed to get ifindex for %s\n", __func__, __LINE__, interface->name);
        close(nl_sock);
        return -1;
    }

    req.ifinfo.ifi_change = 0xffffffff;
    rta = (struct rtattr *)(((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = IFLA_MTU;
    rta->rta_len = RTA_LENGTH(sizeof(unsigned int));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(mtu));
    memcpy(RTA_DATA(rta), &mtu, sizeof(mtu));

    ret = send(nl_sock, &req, req.nh.nlmsg_len, 0);

    if (ret < 0) {
        wifi_hal_error_print("%s:%d Failed to set MTU for %s\n", __func__, __LINE__, interface->name);
        close(nl_sock);
        return -1;
    }

    close(nl_sock);
    return 0;
}

void interface_free(wifi_interface_info_t *interface)
{
    if (!interface) return;

    uint_array_set(&interface->scan_filter, 0, NULL);
    hash_map_destroy(interface->scan_info_map);
    hash_map_destroy(interface->scan_info_ap_map[0]);
    hash_map_destroy(interface->scan_info_ap_map[1]);
    pthread_mutex_destroy(&interface->scan_info_mutex);
    pthread_mutex_destroy(&interface->scan_info_ap_mutex);
    pthread_mutex_destroy(&interface->scan_state_mutex);

    // WARN!! What about others allocated structures inside the 'interface'? Is it memory leak?
    free(interface);
}

int interface_info_handler(struct nl_msg *msg, void *arg)
{
    //unsigned int radio_index;
    wifi_radio_info_t *radio = (wifi_radio_info_t *)arg;
    wifi_interface_info_t *interface = NULL;
    wifi_vap_info_t *vap;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
#ifdef FEATURE_SINGLE_PHY
    int rdk_radio_index_of_intf = -1;

    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: radio is null, returning\n", __func__, __LINE__);
        return NL_SKIP;
    }

    wifi_hal_dbg_print("%s:%d: Invoked for rdk_radio_index:%d\n", __func__, __LINE__,
        radio->rdk_radio_index);
#endif //FEATURE_SINGLE_PHY
    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    //print_attributes(__func__, tb);
    if (tb[NL80211_ATTR_WIPHY]) {
#ifndef FEATURE_SINGLE_PHY
        radio = get_radio_by_phy_index(nla_get_u32(tb[NL80211_ATTR_WIPHY]));
#endif //FEATURE_SINGLE_PHY
        if (radio != NULL && tb[NL80211_ATTR_IFNAME]) {
#ifdef FEATURE_SINGLE_PHY
            // Get rdk radio index associated with interface name and continue only if it is
            // matching with radio's rdk index
            rdk_radio_index_of_intf = get_rdk_radio_index_from_interface_name(
                nla_get_string(tb[NL80211_ATTR_IFNAME]));
            if (rdk_radio_index_of_intf != radio->rdk_radio_index) {
                // Interface does not belong to this radio, return
                wifi_hal_dbg_print("%s:%d: Interface:%s not part of rdk_radio_index:%d\n", __func__,
                    __LINE__, nla_get_string(tb[NL80211_ATTR_IFNAME]), radio->rdk_radio_index);
                return NL_SKIP;
            }
#endif //FEATURE_SINGLE_PHY
#ifdef CONFIG_WIFI_EMULATOR
            update_interface_names(nla_get_u32(tb[NL80211_ATTR_WIPHY]), nla_get_string(tb[NL80211_ATTR_IFNAME]));
#endif
            interface = hash_map_get_first(radio->interface_map);
            while (interface != NULL) {
                if (strcmp(interface->name, nla_get_string(tb[NL80211_ATTR_IFNAME])) == 0) {
                    break;
                }
                interface = hash_map_get_next(radio->interface_map, interface);
            }
            if (interface == NULL) {
                interface = (wifi_interface_info_t *)malloc(sizeof(wifi_interface_info_t));
                memset(interface, 0, sizeof(wifi_interface_info_t));
            }
            else {
                hash_map_remove(radio->interface_map, interface->name);
            }
            interface->phy_index = radio->index;
            interface->rdk_radio_index = radio->rdk_radio_index;

            vap = &interface->vap_info;

            if (tb[NL80211_ATTR_IFINDEX]) {
                interface->index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
            }

            if (tb[NL80211_ATTR_IFTYPE]) {
                interface->type = nla_get_u32(tb[NL80211_ATTR_IFTYPE]);
            }

            if (tb[NL80211_ATTR_IFNAME]) {
                strcpy(interface->name, nla_get_string(tb[NL80211_ATTR_IFNAME]));
            }

            if (tb[NL80211_ATTR_MAC]) {
                memcpy(interface->mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));
            }


            if (set_interface_properties(nla_get_u32(tb[NL80211_ATTR_WIPHY]), interface) != 0) {
                wifi_hal_info_print("%s:%d: Could not map interface name to index:%d\n", __func__, __LINE__, nla_get_u32(tb[NL80211_ATTR_WIPHY]));
                interface_free(interface);
                return NL_SKIP;
            }

            wifi_hal_dbg_print("%s:%d: phy index: %d\tradio index: %d\tinterface index: %d\nname: %s\ttype:%d, mac:%02x:%02x:%02x:%02x:%02x:%02x\nvap index: %d\tvap name: %s\n",
                    __func__, __LINE__,
                    radio->index, vap->radio_index, interface->index, interface->name, interface->type,
                    interface->mac[0], interface->mac[1], interface->mac[2],
                    interface->mac[3], interface->mac[4], interface->mac[5],
                    vap->vap_index, vap->vap_name);

            if (interface->scan_info_map == NULL) {
                interface->scan_info_map = hash_map_create();
                pthread_mutex_init(&interface->scan_info_mutex, NULL);
            }
            if (interface->scan_info_ap_map[0] == NULL) {
                interface->scan_info_ap_map[0] = hash_map_create();
                interface->scan_info_ap_map[1] = hash_map_create();
                pthread_mutex_init(&interface->scan_info_ap_mutex, NULL);
                pthread_mutex_init(&interface->scan_state_mutex, NULL);
                interface->scan_has_results = WIFI_SCAN_RES_NONE;
                interface->scan_state = WIFI_SCAN_STATE_NONE;
            }

            hash_map_put(radio->interface_map, strdup(interface->name), interface);

            if (is_backhaul_interface(interface)) {
                interface_set_mtu(interface, 1600);
            }
        }
    }

    return NL_SKIP;
}

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
static int phy_info_rates_get_hw_features(struct hostapd_hw_modes *mode, struct nlattr *tb)
{
    static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
        [NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
        [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] =
        { .type = NLA_FLAG },
    };
    struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
    struct nlattr *nl_rate;
    int rem_rate, idx;

    if (tb == NULL)
        return NL_OK;

    mode->num_rates = 0;
    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
              nla_data(nl_rate), nla_len(nl_rate),
              rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
            continue;
        mode->num_rates++;
    }

    mode->rates = os_calloc(mode->num_rates, sizeof(int));
    if (!mode->rates)
        return NL_STOP;

    idx = 0;

    nla_for_each_nested(nl_rate, tb, rem_rate) {
        nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
              nla_data(nl_rate), nla_len(nl_rate),
              rate_policy);
        if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
            continue;
        mode->rates[idx] = nla_get_u32(
            tb_rate[NL80211_BITRATE_ATTR_RATE]);
        idx++;
    }

    return NL_OK;
}
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT

static int phy_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_radio_info_t *radio;
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_band;
    int rem_band;
    enum nl80211_band band = 0;
    enum nl80211_band radio_nl80211_band_type;
#ifdef FEATURE_SINGLE_PHY
    int i;
#endif //FEATURE_SINGLE_PHY

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);

#ifndef FEATURE_SINGLE_PHY
    if (tb_msg[NL80211_ATTR_WIPHY]) {
        radio = get_radio_by_phy_index(nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]));
        if (radio == NULL) {
            return NL_SKIP;
        }
    } else {
        return NL_OK;
    }
#endif //FEATURE_SINGLE_PHY

#ifdef CMXB7_PORT
    if (tb_msg[NL80211_ATTR_INTERFACE_COMBINATIONS])
    {
        struct nlattr *nl_combi;
        int rem_combi;

        nla_for_each_nested(nl_combi, tb_msg[NL80211_ATTR_INTERFACE_COMBINATIONS], rem_combi)
        {
                if ( wiphy_info_iface_comb_process(radio, nl_combi) > 0 )
                        break;
        }
    }
#endif

    if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
        return NL_SKIP;

    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
        nla_parse(tb_msg, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

        if (tb_msg[NL80211_BAND_ATTR_RATES]) {
#ifdef FEATURE_SINGLE_PHY
            // Update the right radio with the bit rates in case of single phy
            for (i = 0; i < g_wifi_hal.num_radios; i++) {
                radio = &g_wifi_hal.radio_info[i];
#else //FEATURE_SINGLE_PHY
            {
#endif //FEATURE_SINGLE_PHY
                radio_nl80211_band_type = get_nl80211_band_from_rdk_radio_index(
                    radio->rdk_radio_index);
                wifi_hal_dbg_print("%s:%d: wiphy index:%d name:%s rdk_radio_index:%d\n", __func__,
                    __LINE__, radio->index, radio->name, radio->rdk_radio_index);
                wifi_hal_dbg_print("%s:%d:band_type:%d radio_band_type:%d processing:%s\n",
                    __func__, __LINE__, nl_band->nla_type, radio_nl80211_band_type,
                    ((nl_band->nla_type == radio_nl80211_band_type) ? "yes" : "no"));
                if (nl_band->nla_type == radio_nl80211_band_type) {
                    wifi_hal_dbg_print("%s:%d:phy_info_rates being invoked from phy_info_handler\n",
                        __func__, __LINE__);
                    phy_info_ht_capa(&radio->hw_modes[radio_nl80211_band_type],
                        tb_msg[NL80211_BAND_ATTR_HT_CAPA],
                        tb_msg[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
                        tb_msg[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
                        tb_msg[NL80211_BAND_ATTR_HT_MCS_SET]);
                    phy_info_vht_capa(&radio->hw_modes[radio_nl80211_band_type],
                        tb_msg[NL80211_BAND_ATTR_VHT_CAPA], tb_msg[NL80211_BAND_ATTR_VHT_MCS_SET]);
                    phy_info_rates(radio, &radio->hw_modes[radio_nl80211_band_type],
                        radio_nl80211_band_type, tb_msg[NL80211_BAND_ATTR_RATES]);
                }
            }
        }

        if (tb_msg[NL80211_BAND_ATTR_FREQS] == NULL) {
            wifi_hal_dbg_print("%s:%d: Frequency attributes not present\n", __func__, __LINE__);
            return NL_OK;
        }

#ifndef FEATURE_SINGLE_PHY
        if (phy_info_freqs(radio, tb_msg[NL80211_BAND_ATTR_FREQS], &band) == NULL) {
            return NL_OK;
        }
#else //FEATURE_SINGLE_PHY
        for (i = 0; i < g_wifi_hal.num_radios; i++) {
            radio = &g_wifi_hal.radio_info[i];
            radio_nl80211_band_type = get_nl80211_band_from_rdk_radio_index(radio->rdk_radio_index);
            wifi_hal_dbg_print("%s:%d: wiphy index:%d name:%s rdk_radio_index:%d\n", __func__,
                __LINE__, radio->index, radio->name, radio->rdk_radio_index);
            wifi_hal_dbg_print("%s:%d:band_type:%d radio_band_type:%d processing:%s\n", __func__,
                __LINE__, nl_band->nla_type, radio_nl80211_band_type,
                ((nl_band->nla_type == radio_nl80211_band_type) ? "yes" : "no"));

            if (nl_band->nla_type == radio_nl80211_band_type) {
                if (phy_info_freqs(radio, tb_msg[NL80211_BAND_ATTR_FREQS], &band) == NULL) {
                    return NL_OK;
                }
            }
        }
#endif //FEATURE_SINGLE_PHY
    }
    return NL_SKIP;
}

static int kick_device_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

static int get_sta_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *nl;
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_CHAIN_SIGNAL] = { .type = NLA_NESTED },
    };
    int rem, signals_cnt = 0;
    int8_t rssi = 0;
    mac_address_t sta_mac;
    mac_addr_str_t sta_mac_str;
    wifi_device_callbacks_t *callbacks;
    wifi_associated_dev_t associated_dev;

    interface = (wifi_interface_info_t *)arg;
    vap = &interface->vap_info;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_IFINDEX]) {
        wifi_hal_error_print("%s:%d: Interface index missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (interface->index != nla_get_u32(tb[NL80211_ATTR_IFINDEX])) {
        wifi_hal_error_print("%s:%d: Wrong interface index\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_MAC]) {
        wifi_hal_error_print("%s:%d: MAC addr missing!", __func__, __LINE__);
        return NL_SKIP;
    }

    memcpy(sta_mac, nla_data(tb[NL80211_ATTR_MAC]), nla_len(tb[NL80211_ATTR_MAC]));

    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_info_print("%s:%d: STA stats missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    wifi_hal_dbg_print("%s:%d: Received stats for %s\n", __func__, __LINE__, to_mac_str(sta_mac, sta_mac_str));

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        wifi_hal_info_print("%s:%d: Failed to parse nested attributes\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (stats[NL80211_STA_INFO_CHAIN_SIGNAL]) {
        nla_for_each_nested(nl, stats[NL80211_STA_INFO_CHAIN_SIGNAL], rem) {
            rssi = (int8_t)nla_get_u8(nl);
            signals_cnt++;
        }
    }

    if (signals_cnt != 0)
        rssi = rssi/signals_cnt;

    wifi_hal_dbg_print("%s:%d: RSSI %d\n", __func__, __LINE__, rssi);

    callbacks = get_hal_device_callbacks();
    if (callbacks->num_assoc_cbs == 0) {
        return NL_SKIP;
    }

    memset(&associated_dev, 0, sizeof(associated_dev));
    memcpy(associated_dev.cli_MACAddress, &sta_mac, sizeof(mac_address_t));
    associated_dev.cli_RSSI = rssi;
    associated_dev.cli_Active = true;

    for (int i = 0; i < callbacks->num_assoc_cbs; i++) {
        if (callbacks->assoc_cb[i] != NULL) {
            callbacks->assoc_cb[i](vap->vap_index, &associated_dev);
        }
    }

    if (callbacks->steering_event_callback != 0 &&
        vap->u.bss_info.security.mode != wifi_security_mode_none) {
        wifi_steering_event_t steering_evt;
        struct sta_info *station = NULL;
        uint32_t g_idx = 0;

        wifi_steering_evConnect_t connect_steering_event = {0};
        station = ap_get_sta(&interface->u.ap.hapd, sta_mac);

        if (station == NULL) {
            wifi_hal_error_print("%s:%d: No station for Client Connect steering event", __func__, __LINE__);
            return NL_SKIP;
        }

        pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
        /* always call add_stalist to update info (type, assoc_time etc.) */
        bm_sta_list_t *l_sta_info = steering_add_stalist(interface, NULL, sta_mac, BM_STA_TYPE_ASSOC);
        if (l_sta_info == NULL) {
            wifi_hal_error_print("Fail to get the sta MAC=%s after adding it to list.\n", to_mac_str(sta_mac, sta_mac_str));
        }

        if (steering_find_ap_cfg(vap->vap_index, &g_idx) == NULL) {
            wifi_hal_error_print("%s:%d AP Config for vap:%d is not found\n", __func__, __LINE__, vap->vap_index);
        }
        create_connect_steering_event(interface, &connect_steering_event,
            (struct ieee80211_mgmt *)station->assoc_req, station->assoc_req_len);

        fill_steering_event_general(&steering_evt, WIFI_STEERING_EVENT_CLIENT_CONNECT, vap);
        steering_evt.data.connect = connect_steering_event;
        memcpy(steering_evt.data.connect.client_mac, sta_mac, sizeof(mac_address_t));

        wifi_hal_dbg_print("%s:%d: Send Client Connect steering event\n", __func__, __LINE__);

        callbacks->steering_event_callback(g_idx, &steering_evt);
        if (l_sta_info != NULL) {
            l_sta_info->event_sent |= BM_SENT_E_ASSOC;
        }
        pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    }

    return NL_SKIP;
}

int nl80211_kick_device(wifi_interface_info_t *interface, mac_address_t addr)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_DEL_STATION);
    if (msg == NULL) {
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, sizeof(mac_address_t), addr);

    if (nl80211_send_and_recv(msg, kick_device_handler, interface, NULL, NULL)) {
        wifi_hal_error_print("%s:%d: Error getting sta info\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int nl80211_read_sta_data(wifi_interface_info_t *interface, const u8 *addr)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_STATION);
    if (msg == NULL) {
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

    if (nl80211_send_and_recv(msg, get_sta_handler, interface, NULL, NULL)) {
        wifi_hal_error_print("%s:%d: Error getting sta info\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

int update_channel_flags()
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    if (msg == NULL) {
        nlmsg_free(msg);
        return -1;
    }

    if (nl80211_send_and_recv(msg, phy_info_handler, &g_wifi_hal, NULL, NULL)) {
        return -1;
    }

    return 0;
}

#if defined(VNTXER5_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || \
    defined(SCXER10_PORT)
static int protocol_feature_handler(struct nl_msg *msg, void *arg)
{
    u32 *feat = arg;
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]) {

        *feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);
    }

    return NL_SKIP;
}

static u32 get_nl80211_protocol_features(int nl_id)
{
    u32 feat = 0;
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(nl_id, NULL, 0, NL80211_CMD_GET_PROTOCOL_FEATURES);
    if (!msg) {
        nlmsg_free(msg);
        return 0;
    }

    if (nl80211_send_and_recv(msg, protocol_feature_handler, &feat, NULL, NULL) == 0) {
        return feat;
    }

    return 0;
}
#endif // VNTXER5_PORT || TCXB7_PORT || TCXB8_PORT || XB10_PORT || SCXER10_PORT

int init_nl80211()
{
    int ret;
#if defined(VNTXER5_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || \
    defined(SCXER10_PORT)
    u32 feat;
    int flags = 0;
#endif
    unsigned int i;
    struct nl_msg *msg;
    wifi_radio_info_t *radio;
    char thread_id[12];
    wifi_netlink_thread_info_t *core_thread_socket = NULL;

    core_thread_socket = create_nl80211_socket();

    if (!core_thread_socket) {
        wifi_hal_error_print("%s:%d: Failed to allocate netlink info\n", __func__, __LINE__);
        return -1;
    }

    sprintf(thread_id, "%lu", pthread_self());
    hash_map_put(g_wifi_hal.netlink_socket_map, strdup(thread_id), core_thread_socket);

    g_wifi_hal.nl_cb = core_thread_socket->nl_cb;
    g_wifi_hal.nl = core_thread_socket->nl;

    g_wifi_hal.nl80211_id = genl_ctrl_resolve((struct nl_sock *)g_wifi_hal.nl, "nl80211");
    if (g_wifi_hal.nl80211_id < 0) {
        wifi_hal_error_print("%s:%d: generic netlink not found\n", __func__, __LINE__);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    g_wifi_hal.nl_event = nl_create_handle(g_wifi_hal.nl_cb, "event");
    if (g_wifi_hal.nl_event == NULL) {
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }


    ret = nl_get_multicast_id("nl80211", "scan");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Could not add multicast membership for scan events: %d (%s)\n", __func__, __LINE__,
               ret, strerror(-ret));
        nl_destroy_handles(&g_wifi_hal.nl);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    ret = nl_get_multicast_id("nl80211", "mlme");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Could not add multicast membership for mlme events: %d (%s)\n", __func__, __LINE__,
               ret, strerror(-ret));
        nl_destroy_handles(&g_wifi_hal.nl);
        nl_cb_put(g_wifi_hal.nl_cb);
        return -1;
    }

    ret = nl_get_multicast_id("nl80211", "regulatory");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_info_print("%s:%d: Could not add multicast membership for regulatory events: %d (%s)\n",
                __func__, __LINE__, ret, strerror(-ret));
    }

    ret = nl_get_multicast_id("nl80211", "vendor");
    if (ret >= 0) {
        ret = nl_socket_add_membership((struct nl_sock *)g_wifi_hal.nl_event, ret);
    }

    if (ret < 0) {
        wifi_hal_info_print("%s:%d: Could not add multicast membership for vendor events: %d (%s)\n",
                __func__, __LINE__, ret, strerror(-ret));
    }

    nl_cb_set(g_wifi_hal.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(g_wifi_hal.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_global_nl80211_event, &g_wifi_hal);


    g_wifi_hal.nl_event_fd = nl_socket_get_fd((struct nl_sock *)g_wifi_hal.nl_event);
    wifi_hal_info_print("%s:%d: hal nl sock: %d\n", __func__, __LINE__, g_wifi_hal.nl_event_fd);

    // dump all phy info
    g_wifi_hal.num_radios = 0;
#ifdef CONFIG_WIFI_EMULATOR
    memset((unsigned char *)g_wifi_hal.radio_info, 0, MAX_NUM_SIMULATED_CLIENT*sizeof(wifi_radio_info_t));
    for (int i = 0; i < MAX_NUM_SIMULATED_CLIENT; i++) {
#else
    memset((unsigned char *)g_wifi_hal.radio_info, 0, MAX_NUM_RADIOS*sizeof(wifi_radio_info_t));
    for (int i = 0; i < MAX_NUM_RADIOS; i++) {
#endif
        g_wifi_hal.radio_info[i].index = -1;
    }
    init_interface_map();
#if !defined(VNTXER5_PORT) && !defined(TCXB7_PORT) && !defined(TCXB8_PORT) && \
    !defined(XB10_PORT) && !defined(SCXER10_PORT)
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
    if (msg == NULL) {
#else
    feat = get_nl80211_protocol_features(g_wifi_hal.nl80211_id);

    if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
        flags = NLM_F_DUMP;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, flags, NL80211_CMD_GET_WIPHY);

    if (!msg || nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
#endif
        nlmsg_free(msg);
        return -1;
    }

    if (nl80211_send_and_recv(msg, wiphy_dump_handler, &g_wifi_hal, NULL, NULL)) {
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Number of supported radios: %d\n", __func__, __LINE__, g_wifi_hal.num_radios);

    g_wifi_hal.link_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (g_wifi_hal.link_fd  > 0) {
        struct sockaddr_nl local;
        memset(&local, 0, sizeof(local));
        local.nl_family = AF_NETLINK;
        local.nl_groups = RTMGRP_LINK;
        local.nl_pid = getpid();

        if (bind(g_wifi_hal.link_fd, (struct sockaddr*)&local, sizeof(local)) <0) {
            wifi_hal_error_print("%s:%d: Socket bind failed \n", __func__, __LINE__);
            close(g_wifi_hal.link_fd);
            return -1;
        }
    } else {
        wifi_hal_error_print("%s:%d: socket creation failed for link_fd\n", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];

#if defined(CONFIG_HW_CAPABILITIES)
        if (radio->driver_data.auth_supported) {
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_SME;
        }

        if (radio->driver_data.p2p_go_supported && radio->driver_data.p2p_client_supported) {
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_P2P_CAPABLE;
        }
        if (radio->driver_data.p2p_concurrent) {
            wifi_hal_info_print("%s:%d: nl80211: Use separate P2P group interface (driver advertised support)\n",
                __func__, __LINE__);
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_P2P_CONCURRENT;
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_P2P_MGMT_AND_NON_P2P;
        }
        if (radio->driver_data.num_multichan_concurrent > 1) {
            wifi_hal_info_print("%s:%d: nl80211: Enable multi-channel concurrent (driver advertised support)\n",
                __func__, __LINE__);
            radio->driver_data.capa.num_multichan_concurrent =
                radio->driver_data.num_multichan_concurrent;
        }

        /* default to 5000 since early versions of mac80211 don't set it */
        if (!radio->driver_data.capa.max_remain_on_chan) {
            radio->driver_data.capa.max_remain_on_chan = 5000;
        }

        radio->driver_data.capa.wmm_ac_supported = radio->driver_data.wmm_ac_supported;

        radio->driver_data.capa.mac_addr_rand_sched_scan_supported =
            radio->driver_data.mac_addr_rand_sched_scan_supported;
        radio->driver_data.capa.mac_addr_rand_scan_supported =
            radio->driver_data.mac_addr_rand_scan_supported;

        if (radio->driver_data.channel_switch_supported) {
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_AP_CSA;
            if (!radio->driver_data.capa.max_csa_counters)
                radio->driver_data.capa.max_csa_counters = 1;
        }

        if (!radio->driver_data.capa.max_sched_scan_plans) {
            radio->driver_data.capa.max_sched_scan_plans = 1;
            radio->driver_data.capa.max_sched_scan_plan_interval = UINT32_MAX;
            radio->driver_data.capa.max_sched_scan_plan_iterations = 0;
        }

        if (radio->driver_data.update_ft_ies_supported) {
            radio->driver_data.capa.flags |= WPA_DRIVER_FLAGS_UPDATE_FT_IES;
        }

        if (radio->driver_data.capa.mbssid_max_interfaces == 0) {
            radio->driver_data.capa.mbssid_max_interfaces = MAX_MBSSID_INTERFACES;
        }

#endif // CONFIG_HW_CAPABILITIES
        // initialize the interface map
        radio->interface_map = hash_map_create();

        // get the interface information
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE);
        if (msg == NULL) {
            return -1;
        }
        nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index);
        if (nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL)) {
            return -1;
        }

        wifi_hal_dbg_print("%s:%d: Found %d interfaces on radio index:%d\n", __func__, __LINE__,
            hash_map_count(radio->interface_map), radio->index);
    }

    return 0;

}

static int ap_enable_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}

void wifi_hal_nl80211_wps_pbc(unsigned int ap_index)
{
    union wpa_event_data event;
    wifi_interface_info_t *interface;

    interface = get_interface_by_vap_index(ap_index);

    if (interface->u.ap.conf.wps_state == 0) {
        wifi_hal_error_print("%s:%d: WPS is not enabled for interface %s\n", __func__, __LINE__, interface->name);
        return;
    }

    os_memset(&event, 0, sizeof(event));
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_WPS_BUTTON_PUSHED, &event);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

void wifi_hal_nl80211_wps_cancel(unsigned int ap_index)
{
    union wpa_event_data event = {0};
    const wifi_interface_info_t *interface = get_interface_by_vap_index(ap_index);

    wifi_hal_dbg_print("%s:%d: WPS cancel for ap=%d\n", __func__, __LINE__, ap_index);

    if (interface->u.ap.conf.wps_state == 0) {
        wifi_hal_error_print("%s:%d: WPS is not enabled for interface %s\n", __func__, __LINE__, interface->name);
        return;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
#if !defined(PLATFORM_LINUX)
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_WPS_CANCEL, &event);
#endif /* !defined(PLATFORM_LINUX) */
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

int wifi_hal_nl80211_wps_pin(unsigned int ap_index, char *wps_pin)
{
    int ret;
    wifi_interface_info_t *interface;

    interface = get_interface_by_vap_index(ap_index);
    if ((wps_pin == NULL) || (interface == NULL)) {
        wifi_hal_error_print("%s:%d: WPS Pin or interface is NULL for vap_index:%d\n", __func__, __LINE__, ap_index);
        return RETURN_ERR;
    }

    if (interface->u.ap.conf.wps_state == 0) {
        wifi_hal_error_print("%s:%d: WPS is not enabled for interface %s\n", __func__, __LINE__, interface->name);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    ret = hostapd_wps_add_pin(&interface->u.ap.hapd, NULL, "any", wps_pin, MAX_WPS_CONN_TIMEOUT);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: WPS pin configuration failure[%d] for interface:%s vap_index:%d\n",
                                __func__, __LINE__, ret, interface->name, ap_index);
        return RETURN_ERR;
    }

    return 0;
}

int nl80211_enable_ap(wifi_interface_info_t *interface, bool enable)
{
    struct nl_msg *msg;
    int ret;

    if (enable) {
        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        ieee802_11_update_beacons(interface->u.ap.hapd.iface);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        return RETURN_OK;
    } else {
        interface->beacon_set = 0;
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_STOP_AP);
    }

    if (msg == NULL) {
        return -1;
    }


    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }


    wifi_hal_dbg_print("%s:%d: %s ap on interface: %d\n", __func__, __LINE__,
        enable ? "Starting" : "Stopping", interface->index);
    if ((ret = nl80211_send_and_recv(msg, ap_enable_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error stopping/starting ap: %d (%s) \n", __func__, __LINE__, ret, strerror(-ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int nl80211_delete_interface(wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

#if 0
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_STOP_AP);
    if (msg == NULL) {
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Sopping ap on interface: %d\n", __func__, __LINE__, interface->index);
    if ((ret = nl80211_send_and_recv(msg, ap_stop_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error stopping ap: %s\n", __func__, __LINE__, strerror(-ret));
    }
#endif


    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_DEL_INTERFACE);
    if (msg == NULL) {
        return -1;
    }
    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Deleting interface:%s (%d) on radio:%d\n", __func__, __LINE__,
            interface->name, interface->index, radio->index);

    if ((ret = nl80211_send_and_recv(msg, interface_del_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error in deleting interface: %d (%s) \n", __func__, __LINE__, ret, strerror(-ret));
        return -1;
    }

    hash_map_remove(radio->interface_map, interface->name);
    free(interface);

    return 0;
}

int nl80211_delete_interfaces(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface, *tmp;

    // now delete all interfaces on radios so that we are ready for rdkb
    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        tmp = interface;
        interface = hash_map_get_next(radio->interface_map, interface);

        nl80211_delete_interface(radio, tmp);
    }

    return 0;
}

int nl80211_init_primary_interfaces()
{
    unsigned int i, ret;
    struct nl_msg *msg;
    wifi_radio_info_t *radio;
    wifi_interface_info_t *primary_interface;
    wifi_interface_info_t *interface;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio->radio_presence == false) {
            wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
            continue;
        }
        primary_interface = get_primary_interface(radio);
        if (primary_interface == NULL) {
            wifi_hal_error_print("%s:%d: Error updating dev:%d no primary interfaces exist\n", __func__, __LINE__, radio->index);
            return -1;
        }

        interface = get_private_vap_interface(radio);
        if (interface == NULL) {
            wifi_hal_info_print("%s:%d: INFO: updating dev:%d no private vap interfaces exist "
                                "using primary interface\n", __func__, __LINE__, radio->index);
            interface = primary_interface;
        }

        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
        if (msg == NULL) {
            return -1;
        }

        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

        if ((ret = nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL))) {
            wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %d (%s) \n",
                __func__, __LINE__, interface->name, radio->index, ret, strerror(-ret));
            if (ret != ENODEV) {
                // Try updating the mode again after bringing the interface down
                nl80211_interface_enable(interface->name, false);
                wifi_hal_dbg_print(
                    "%s:%d: Updating %s interface after bringing the interface down.\n", __func__,
                    __LINE__, interface->name);
                msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                    NL80211_CMD_SET_INTERFACE);
                nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
                ret = nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL);
                if (ret) {
                    wifi_hal_error_print("%s:%d: Error updating %s interface even after interface "
                                         "is down on dev:%d error: %d (%s) \n",
                        __func__, __LINE__, interface->name, radio->index, ret, strerror(-ret));
                    return -1;
                }
            } else {
                // If failure was ENODEV then no need of retrying as the device is not present
                return -1;
            }
        }
        nl80211_interface_enable(primary_interface->name, true);
    }

    return 0;
}

int nl80211_init_radio_info()
{
    unsigned int i;
    wifi_radio_info_t *radio;
    struct nl_msg *msg;

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = &g_wifi_hal.radio_info[i];

        if (radio->radio_presence == false) {
           wifi_hal_error_print("%s:%d: Skip the Radio %d .This is sleeping in ECO mode \n", __func__, __LINE__, radio->index);
           continue;
        }

        // get information about phy
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_GET_WIPHY);
        if (msg == NULL) {
            wifi_hal_dbg_print("%s:%d: Error creating nl80211 message\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index) < 0) {
            wifi_hal_dbg_print("%s:%d: Error adding nl80211 message data\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nl80211_send_and_recv(msg, wiphy_get_info_handler,
            radio, NULL, NULL)) {
            return -1;
        }
    }

    return 0;
}

static int set_beacon_data(struct nl_msg *msg, struct beacon_data *settings)
{
    if ((settings->head && nla_put(msg, NL80211_ATTR_BEACON_HEAD,
        settings->head_len, settings->head)) || (settings->tail &&
            nla_put(msg, NL80211_ATTR_BEACON_TAIL, settings->tail_len, settings->tail)) ||
        (settings->beacon_ies && nla_put(msg, NL80211_ATTR_IE,
        settings->beacon_ies_len, settings->beacon_ies)) ||
        (settings->proberesp_ies && nla_put(msg, NL80211_ATTR_IE_PROBE_RESP,
        settings->proberesp_ies_len, settings->proberesp_ies)) ||
        (settings->assocresp_ies && nla_put(msg, NL80211_ATTR_IE_ASSOC_RESP,
        settings->assocresp_ies_len, settings->assocresp_ies)) ||
        (settings->probe_resp && nla_put(msg, NL80211_ATTR_PROBE_RESP,
        settings->probe_resp_len, settings->probe_resp))) {
        return -1;
    }

    return 0;
}

static int nl80211_put_freq_params(struct nl_msg *msg, const struct hostapd_freq_params *freq)
{
#ifdef CONFIG_IEEE80211BE
    enum hostapd_hw_mode hw_mode;
    int is_24ghz;
    u8 channel;
#endif /* CONFIG_IEEE80211BE */
    int set_freq_cw;

    wifi_hal_dbg_print("%s:%d: freq=%d\n", __func__, __LINE__, freq->freq);
    if (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq->freq))
        return -1;

    wifi_hal_dbg_print("  * he_enabled=%d\n", freq->he_enabled);
    wifi_hal_dbg_print("  * vht_enabled=%d\n", freq->vht_enabled);
    wifi_hal_dbg_print("  * ht_enabled=%d\n", freq->ht_enabled);
#ifdef CONFIG_IEEE80211BE
    wifi_hal_dbg_print("  * eht_enabled=%d\n", freq->eht_enabled);
    hw_mode = ieee80211_freq_to_chan(freq->freq, &channel);
    is_24ghz = (hw_mode == HOSTAPD_MODE_IEEE80211G ||
               hw_mode == HOSTAPD_MODE_IEEE80211B);
    set_freq_cw = (freq->vht_enabled ||
                   ((freq->he_enabled || freq->eht_enabled) && !is_24ghz));
#else
    set_freq_cw = (freq->vht_enabled || freq->he_enabled);
#endif /* CONFIG_IEEE80211BE */

    if (set_freq_cw) {
        enum nl80211_chan_width cw;

        wifi_hal_dbg_print("  * bandwidth=%d\n", freq->bandwidth);
        switch (freq->bandwidth) {
        case 20:
            cw = NL80211_CHAN_WIDTH_20;
            break;
        case 40:
            cw = NL80211_CHAN_WIDTH_40;
            break;
        case 80:
            if (freq->center_freq2)
                cw = NL80211_CHAN_WIDTH_80P80;
            else
                cw = NL80211_CHAN_WIDTH_80;
            break;
        case 160:
            cw = NL80211_CHAN_WIDTH_160;
            break;
#ifdef CONFIG_IEEE80211BE
        case 320:
            cw = NL80211_CHAN_WIDTH_320;
            break;
#endif /* CONFIG_IEEE80211BE */
        default:
            return -1;
        }

        wifi_hal_dbg_print("  * channel_width=%d\n", cw);
        wifi_hal_dbg_print("  * center_freq1=%d\n", freq->center_freq1);
        wifi_hal_dbg_print("  * center_freq2=%d\n", freq->center_freq2);
        if (nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, cw) ||
            nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, freq->center_freq1) ||
            (freq->center_freq2 && nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, freq->center_freq2))) {
            return -1;
        }
    } else if (freq->ht_enabled) {
        enum nl80211_channel_type ct;

        wifi_hal_dbg_print("  * sec_channel_offset=%d\n", freq->sec_channel_offset);
        switch (freq->sec_channel_offset) {
        case -1:
            ct = NL80211_CHAN_HT40MINUS;
            break;
        case 1:
            ct = NL80211_CHAN_HT40PLUS;
            break;
        default:
            ct = NL80211_CHAN_HT20;
            break;
        }

        wifi_hal_dbg_print("  * channel_type=%d\n", ct);
        if (nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, ct))
            return -1;
    } else {
        wifi_hal_dbg_print("  * channel_type=%d\n", NL80211_CHAN_NO_HT);
        if (nla_put_u32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT)) {
            return -1;
        }
    }

    return 0;
}

static int nl80211_fill_chandef(struct nl_msg *msg, wifi_radio_info_t *radio, wifi_interface_info_t *interface)
{
    int freq, freq1;
    unsigned int width;
    char country[8];
    int sec_chan_offset;
    wifi_radio_operationParam_t *param;

    param = &radio->oper_param;

    get_coutry_str_from_code(param->countryCode, country);
    freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    freq1 = freq;
    wifi_hal_dbg_print("%s:%d: index= %d Country = %s, country code = %d, channel = :%d op_class = %d \n", __func__, __LINE__, radio->index, country, param->countryCode, param->channel, param->op_class);
    switch (param->channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            width = NL80211_CHAN_WIDTH_20;
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            width = NL80211_CHAN_WIDTH_40;
            if ((sec_chan_offset = get_sec_channel_offset(radio, freq)) == 0) {
                wifi_hal_info_print("%s:%d: Failed to get sec channel offset for dev:%d\n", __func__, __LINE__, radio->index);
            }

            freq1 = freq + sec_chan_offset*10;
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            width = NL80211_CHAN_WIDTH_80;
            freq1 = get_bw80_center_freq(param, country);
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            width = NL80211_CHAN_WIDTH_160;
            freq1 = get_bw160_center_freq(param, country);
            break;
#ifdef CONFIG_IEEE80211BE
        case WIFI_CHANNELBANDWIDTH_320MHZ:
            width = NL80211_CHAN_WIDTH_320;
            freq1 = get_bw320_center_freq(param, country);
            break;
#endif /* CONFIG_IEEE80211BE */
        case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            width = NL80211_CHAN_WIDTH_80P80;
            break;
        default:
            width = NL80211_CHAN_WIDTH_20;
            break;
    }

    if (freq1 == -1) {
        wifi_hal_error_print("%s:%d - No center frequency is found\n", __func__, __LINE__);
        return -1;
    }

    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
    nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, freq1);
    nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, 0);
    nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, width);

    wifi_hal_dbg_print("%s:%d Setting channel freq:%d freq1:%d width:%d on interface:%d\n", __func__, __LINE__, freq, freq1, width, interface->index);
    return 0;
}

int nl80211_switch_channel(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface;
    wifi_radio_operationParam_t *param;
    struct csa_settings csa_settings;
    int sec_chan_offset, freq, freq1, bandwidth;
    u8 seg0;
    char country[8];
    int ret = 0;
    bool is_first_interface;

    param = &radio->oper_param;
    get_coutry_str_from_code(param->countryCode, country);
    freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    freq1 = freq;
    sec_chan_offset = get_sec_channel_offset(radio, freq);

    wifi_hal_info_print("%s:%d Switching channel to %d on radio %d\n", __func__, __LINE__, param->channel, radio->index);

    switch (param->channelWidth) {
    case WIFI_CHANNELBANDWIDTH_20MHZ:
        bandwidth = 20;
        break;

    case WIFI_CHANNELBANDWIDTH_40MHZ:
        bandwidth = 40;
        freq1 = freq + sec_chan_offset*10;
        break;

    case WIFI_CHANNELBANDWIDTH_80MHZ:
        bandwidth = 80;
        freq1 = get_bw80_center_freq(param, country);
        break;

    case WIFI_CHANNELBANDWIDTH_160MHZ:
        bandwidth = 160;
        freq1 = get_bw160_center_freq(param, country);
        break;
#ifdef CONFIG_IEEE80211BE
    case WIFI_CHANNELBANDWIDTH_320MHZ:
        bandwidth = 320;
        freq1 = get_bw320_center_freq(param, country);
        break;
#endif /* CONFIG_IEEE80211BE */
    default:
        bandwidth = 20;
        break;
    }

    if (freq1 == -1) {
        wifi_hal_error_print("%s:%d - No center frequency found\n", __func__, __LINE__);
        return -1;
    }

    ieee80211_freq_to_chan(freq1, &seg0);

    /* Setup CSA request */
    os_memset(&csa_settings, 0, sizeof(csa_settings));

    if (radio->radar_detected) {
        csa_settings.cs_count = 8;
        csa_settings.block_tx = 1;
        radio->radar_detected = false;
    } else {
        csa_settings.cs_count = 5;
        csa_settings.block_tx = 0;
    }

    os_memset(&csa_settings.freq_params, 0, sizeof(struct hostapd_freq_params));

    csa_settings.freq_params.mode = radio->iconf.hw_mode;
    csa_settings.freq_params.freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);
    csa_settings.freq_params.channel = param->channel;
    csa_settings.freq_params.ht_enabled = radio->iconf.ieee80211n;
    csa_settings.freq_params.vht_enabled = radio->iconf.ieee80211ac;
    csa_settings.freq_params.he_enabled = radio->iconf.ieee80211ax;
#ifdef CONFIG_IEEE80211BE
    csa_settings.freq_params.eht_enabled = radio->iconf.ieee80211be;
#endif /* CONFIG_IEEE80211BE */
    csa_settings.freq_params.sec_channel_offset = sec_chan_offset;
    csa_settings.freq_params.center_freq1 = freq1;
    csa_settings.freq_params.center_freq2 = 0;
    csa_settings.freq_params.bandwidth = bandwidth;

    wifi_hal_dbg_print("%s:%d chan_freq: %d center_freq: %d bandwidth: %d sec_chan_offset: %d\n",
        __func__, __LINE__, freq, freq1, bandwidth, sec_chan_offset);

    is_first_interface = true;
    hash_map_foreach(radio->interface_map, interface) {
        if (!interface->bss_started) {
            continue;
        }

        wifi_hal_dbg_print("%s:%d interface: %s switch channel to %d\n", __func__, __LINE__,
            interface->name, param->channel);

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        ret = hostapd_switch_channel(&interface->u.ap.hapd, &csa_settings);
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        /* Ignore the error if the error is not on first interface,
           as CSA would be in progress after the first interface channel switch. */
        if (ret != 0 && is_first_interface == true) {
            wifi_hal_error_print("%s:%d interface: %s failed to switch channel to %d, error: %d\n",
                __func__, __LINE__, interface->name, param->channel, ret);
            return ret;
        }
        is_first_interface = false;
    }
    return 0;
}

int nl80211_update_wiphy(wifi_radio_info_t *radio)
{
    struct nl_msg *msg;
    int ret;
    wifi_interface_info_t *interface;
    bool reconfigure = false;

    interface = hash_map_get_first(radio->interface_map);

    while (interface != NULL) {
        if (interface->bss_started) {
                reconfigure = true;
                nl80211_enable_ap(interface, false);
                pthread_mutex_lock(&g_wifi_hal.hapd_lock);
                hostapd_bss_deinit_no_free(&interface->u.ap.hapd);
                hostapd_free_hapd_data(&interface->u.ap.hapd);
                if (interface->u.ap.hapd.conf != NULL && interface->u.ap.hapd.conf->ssid.wpa_psk != NULL && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                    hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);

                pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
                nl80211_interface_enable(interface->name, false);
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        interface = get_primary_interface(radio);
    }
    else {
        interface = get_private_vap_interface(radio);
        if (interface == NULL) {
            interface = get_primary_interface(radio);
        }
    }

    if (!interface) {
        wifi_hal_error_print("%s:%d: Error updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
        return -1;
    }

    if (!radio->configured) {
        nl80211_enable_ap(interface, false);
        wifi_hal_dbg_print("%s:%d: Radio is not configured, set beacon to 0 for %s\n", __func__, __LINE__, interface->name);
    }
    
    wifi_hal_dbg_print("%s:%d: update transmitPower:%d\n", __func__, __LINE__, radio->oper_param.transmitPower);
    wifi_drv_set_txpower(interface, radio->oper_param.transmitPower);

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_SET_WIPHY);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
    if (nl80211_fill_chandef(msg, radio, interface) == -1) {
        return -1;
    }

#if defined(VNTXER5_PORT)
    platform_set_radio_mld_bonding(radio);
#endif
    if ((ret = nl80211_send_and_recv(msg, wiphy_set_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_info_print("%s:%d: Error updating dev:%d error: %d (%s)\n",
            __func__, __LINE__, radio->index, ret, strerror(-ret));

        if(!reconfigure) {
            interface = hash_map_get_first(radio->interface_map);

            while (interface != NULL) {
                if(is_wifi_hal_vap_mesh_sta(interface->vap_info.vap_index) == false) {
                    nl80211_enable_ap(interface, false);
                    nl80211_interface_enable(interface->name, false);
                }
                interface = hash_map_get_next(radio->interface_map, interface);
            }

            if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
                interface = get_primary_interface(radio);
            }
            else {
                interface = get_private_vap_interface(radio);
                if (interface == NULL) {
                    interface = get_primary_interface(radio);
                }
            }

            if (!interface) {
                wifi_hal_error_print("%s:%d: Error updating dev:%d no interfaces exist\n", __func__, __LINE__, radio->index);
                return -1;
            }

           msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_SET_WIPHY);

           nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
           if (nl80211_fill_chandef(msg, radio, interface) == -1) {
                return -1;
            }

           if ((ret = nl80211_send_and_recv(msg, wiphy_set_info_handler, &g_wifi_hal, NULL, NULL))) {
               wifi_hal_error_print("%s:%d: reconfig error, updating dev:%d error: %d (%s) \n",
                                  __func__, __LINE__, radio->index, ret, strerror(-ret));
               return -1;
           }
           wifi_hal_info_print("%s:%d: reconfig success\n", __func__, __LINE__);
           goto Exit;
       }
        return -1;
    }
Exit:
    if (wifi_setApRetrylimit(interface) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:failed to set retrylimit\n", __func__,__LINE__);
    }

    if (wifi_setQamPlus(interface) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:failed to set Qamplus\n", __func__,__LINE__);
    }

    if (wifi_drv_set_offload_mode(interface, PROBEREQ_OFFLOAD_WILDCARD_SSID_OFF) != RETURN_OK) {
        wifi_hal_error_print("%s:%d:failed to set proberq offload mode\n", __func__,__LINE__);
    }

    if(reconfigure) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->bss_started) {
                if (nl80211_interface_enable(interface->name, true) != 0) {
                    ret = nl80211_retry_interface_enable(interface, true);
                    if (ret != 0) {
                        wifi_hal_error_print("%s:%d: Retry of interface enable failed:%d\n",
                            __func__, __LINE__, ret);
                    }
                }
                if (update_hostap_interface_params(interface) != RETURN_OK) {
                    wifi_hal_error_print("%s:%d - Failed to update_hostap_interface_params\n", __func__, __LINE__);
                    return RETURN_ERR;
                }

                interface->beacon_set = 0;
                start_bss(interface);
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
                if (radio->oper_param.variant & WIFI_80211_VARIANT_BE) {
                    if (platform_is_bss_up(interface->name) == false) {
                        wifi_hal_error_print("%s:%d - %s BSS is down. Bringing it up.\n", __func__, __LINE__, interface->name);
                        platform_bss_enable(interface->name, true);
                    }
                }               
#endif
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
        wifi_hal_configure_mbssid(radio);
    }

    wifi_hal_info_print("%s:%d: Updating dev:%d successful\n",
            __func__, __LINE__, radio->index);

    return 0;
}

int nl80211_set_regulatory_domain(wifi_countrycode_type_t country_code)
{
    struct nl_msg *msg;
    int ret;
    char alpha2[3];
    memset(alpha2, 0, sizeof(alpha2));

    get_coutry_str_from_code(country_code, alpha2);
#ifdef CMXB7_PORT
    if( alpha2[0] == 'C' && alpha2[1] == 'A') {
        alpha2[1] = 'B';
        wifi_hal_dbg_print("%s:%d: Forcing to CA High Power\n", __func__, __LINE__);
    }
#endif

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_REQ_SET_REG);
    nla_put_string(msg, NL80211_ATTR_REG_ALPHA2, alpha2);
    if ((ret = nl80211_send_and_recv(msg, regulatory_domain_set_info_handler, &g_wifi_hal, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Error updating regulatory_domain error: %d (%s)\n",
            __func__, __LINE__, ret, strerror(-ret));
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static int nl80211_register_mgmt_frames(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    unsigned int i;
    int ret;
    //wifi_vap_info_t *vap;
    //wifi_radio_info_t *radio;
    static const int stypes[] = {
        WLAN_FC_STYPE_AUTH,
        WLAN_FC_STYPE_ASSOC_REQ,
        WLAN_FC_STYPE_REASSOC_REQ,
        WLAN_FC_STYPE_DISASSOC,
        WLAN_FC_STYPE_DEAUTH,
        WLAN_FC_STYPE_PROBE_REQ,
        WLAN_FC_STYPE_ACTION,
        /*WLAN_FC_STYPE_BEACON,*/
    };
    unsigned short frame_type;

    if (interface->mgmt_frames_registered == 1) {
        wifi_hal_dbg_print("%s:%d: Mgmt frames already registered for %s\n", __func__, __LINE__, interface->name);
        return 0;
    }

   // vap = &interface->vap_info;
   // radio = get_radio_by_index(vap->radio_index);

    interface->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!interface->nl_cb) {
        return -1;
    }

    nl_cb_set(interface->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(interface->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_mgmt_frame, interface);

    interface->nl_event = nl_create_handle(g_wifi_hal.nl_cb, "mgmt");
    if (interface->nl_event == NULL) {
        nl_cb_put(interface->nl_cb);
        return -1;
    }

    interface->nl_event_fd = nl_socket_get_fd((struct nl_sock *)interface->nl_event);
    wifi_hal_info_print("%s:%d: interface:%s ifindex:%d nl sock:%d\n", __func__, __LINE__,
        interface->name, interface->index, interface->nl_event_fd);

    for (i = 0; i < sizeof(stypes)/sizeof(int); i++) {
        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_REGISTER_FRAME);
        if (msg == NULL) {
            return -1;
        }

        if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
            nlmsg_free(msg);
            return -1;
        }

        frame_type = (WLAN_FC_TYPE_MGMT << 2) | (stypes[i] << 4);

        if (nla_put_u16(msg, NL80211_ATTR_FRAME_TYPE, frame_type) < 0) {
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put(msg, NL80211_ATTR_FRAME_MATCH, 0, NULL) < 0) {
            nlmsg_free(msg);
            return -1;
        }

        if ((ret = execute_send_and_recv(interface->nl_cb, interface->nl_event, msg, mgmt_frame_register_handler, interface, NULL, NULL))) {
            if ((-ret) == EALREADY) {
                wifi_hal_dbg_print("%s:%d: Mgmt frames already registered\n", __func__, __LINE__);
            } else {
                wifi_hal_error_print("%s:%d: Error registering for management frames on interface %s error: %d (%s)\n",
                    __func__, __LINE__, interface->name, ret, strerror(-ret));
                return -1;
            }
        }
    }

    interface->mgmt_frames_registered = 1;

    return 0;
}

static void nl80211_unregister_mgmt_frames(wifi_interface_info_t *interface)
{
    if (interface->mgmt_frames_registered == 0) {
        wifi_hal_dbg_print("%s:%d: interface:%s mgmt frames not registered\n", __func__, __LINE__,
            interface->name);
        return;
    }

    wifi_hal_info_print("%s:%d: interface:%s ifindex:%d nl sock:%d\n", __func__, __LINE__,
        interface->name, interface->index, interface->nl_event_fd);

    nl_destroy_handles(&interface->nl_event);
    interface->nl_event = NULL;
    nl_cb_put(interface->nl_cb);
    interface->nl_cb = NULL;
    interface->nl_event_fd = -1;

    interface->mgmt_frames_registered = 0;
}

int nl80211_update_interface(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;

    vap = &interface->vap_info;

    radio = get_radio_by_rdk_index(vap->radio_index);

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d: nl80211 driver command msg failure for %s interface on dev:%d \n",
                    __func__, __LINE__, interface->name, radio->index);
        return -1;
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
    } else {

        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

        if ((ret = nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL))) {
            wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %d (%s)\n",
                        __func__, __LINE__, interface->name, radio->index, ret, strerror(-ret));
            return -1;
        }

        wifi_hal_dbg_print("%s:%d: Updating %s interface on dev:%d to type: NL80211_IFTYPE_AP successful\n",
                    __func__, __LINE__, interface->name, radio->index);

        if (interface->vap_info.u.sta_info.enabled != true) {
            return 0;
        }

        msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_INTERFACE);
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_STATION);
    }

    if ((ret = nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error updating %s interface on dev:%d error: %d (%s)\n",
            __func__, __LINE__, interface->name, radio->index, ret, strerror(-ret));
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: Updating %s interface on dev:%d to type:%s successful\n",
            __func__, __LINE__, interface->name, radio->index,
            (vap->vap_mode == wifi_vap_mode_ap) ? "NL80211_IFTYPE_AP":"NL80211_IFTYPE_STATION");

    return 0;
}

int nl80211_create_interface(wifi_radio_info_t *radio, wifi_vap_info_t *vap, wifi_interface_info_t **interface)
{
    struct nl_msg *msg;
    wifi_interface_info_t *intf;
    char ifname[32];
    int ret;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_NEW_INTERFACE);
    if (msg == NULL) {
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, radio->index) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (get_interface_name_from_vap_index(vap->vap_index, ifname) != RETURN_OK) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_string(msg, NL80211_ATTR_IFNAME, ifname) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFTYPE, is_wifi_hal_vap_mesh_sta(vap->vap_index) ?
        NL80211_IFTYPE_STATION : NL80211_IFTYPE_AP) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, vap->u.bss_info.bssid) < 0) {
        nlmsg_free(msg);
        return -1;
    }

#if defined(VNTXER5_PORT)
    if (platform_create_interface_attributes(&msg, radio, vap) != RETURN_OK) {
        nlmsg_free(msg);
        return -1;
    }
#endif

    if ((ret = nl80211_send_and_recv(msg, interface_info_handler, radio, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Error creating %s interface on dev:%d error: %d (%s)\n", __func__, __LINE__,
            ifname, radio->index, ret, strerror(-ret));
        return -1;
    }

    if ((intf = get_interface_by_vap_index(vap->vap_index)) != NULL) {
        wifi_hal_dbg_print("%s:%d:interface for vap index:%d already exists\n", __func__, __LINE__, 
            vap->vap_index);

        memcpy(&intf->vap_info, vap, sizeof(wifi_vap_info_t));
        nl80211_interface_enable(intf->name, true);
    }

    *interface = intf;

    return 0;
}

int nl80211_create_interfaces(wifi_radio_info_t *radio, wifi_vap_info_map_t *map)
{
    unsigned int i;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    wifi_hal_dbg_print("%s:%d: Number of VAP(s) to create: %d\n", __func__, __LINE__, map->num_vaps);

    for (i = 0; i < map->num_vaps; i++) {

        vap = &map->vap_array[i];

        if ((interface = get_interface_by_vap_index(vap->vap_index)) != NULL) {
            wifi_hal_dbg_print("%s:%d:interface for vap index:%d already exists\n",
            __func__, __LINE__, vap->vap_index);

            memcpy(&interface->vap_info, vap, sizeof(wifi_vap_info_t));
            nl80211_interface_enable(interface->name, true);
            continue;
        }

        interface = NULL;

        wifi_hal_dbg_print("%s:%d:interface for vap index:%d not found ... creating with mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            __func__, __LINE__, vap->vap_index,
            vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1], vap->u.bss_info.bssid[2],
            vap->u.bss_info.bssid[3], vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);

        if (nl80211_create_interface(radio, vap, &interface) != 0) {
            wifi_hal_error_print("%s:%d:interface for vap index:%d create failed\n",
                __func__, __LINE__, vap->vap_index);
            return -1;
        }
    }

    return 0;
}

static int scan_results_handler(struct nl_msg *msg, void *arg)
{
    uint count = 0;
    uint desired_scanned_ssid_pos = 0;
    uint ssid_found_count = 0;

    wifi_bss_info_t *bss, *scan_info;
    wifi_device_callbacks_t *callbacks;
    wifi_finish_data_t *finish_data = (wifi_finish_data_t *)arg;
    wifi_interface_info_t   *interface = (wifi_interface_info_t *)finish_data->arg;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] ENTER\n", __func__, __LINE__);

    *finish_data->err = 0;


    callbacks = get_hal_device_callbacks();
    if (callbacks == NULL) {
        return NL_SKIP;
    }

    pthread_mutex_lock(&interface->scan_info_mutex);
    count = hash_map_count(interface->scan_info_map);
    if (count == 0) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] No Scan results...\n", __func__, __LINE__);
        bss = NULL;
        if (callbacks->scan_result_callback != NULL) {
            callbacks->scan_result_callback(interface->vap_info.radio_index, &bss, &count);
        }
        return NL_SKIP;
    }

    bss = calloc(count, sizeof(wifi_bss_info_t));
    if (!bss) {
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] memory allocation error!\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (interface->vap_info.vap_mode == wifi_vap_mode_sta) {
        // STA mode: filter result
        scan_info = hash_map_get_first(interface->scan_info_map);
        while (scan_info != NULL) {
            if (strcmp(scan_info->ssid, interface->vap_info.u.sta_info.ssid) == 0){
                bss[desired_scanned_ssid_pos] = *scan_info;
                ssid_found_count++;
                desired_scanned_ssid_pos++;
            }
            scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
        }
        pthread_mutex_unlock(&interface->scan_info_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan found %u results with ssid:%s\n", __func__, __LINE__, ssid_found_count, interface->vap_info.u.sta_info.ssid);
    }
    else {
        // AP mode: copy all
        unsigned total_ap_count;
        scan_info = hash_map_get_first(interface->scan_info_map);
        while (scan_info != NULL) {
            // wifi_hal_dbg_print("%s:%d: [SCAN] ssid:%s, freq->%d\n", scan_info->ssid, scan_info->freq, __func__, __LINE__);
            bss[desired_scanned_ssid_pos] = *scan_info;
            ssid_found_count++;
            desired_scanned_ssid_pos++;
            scan_info = hash_map_get_next(interface->scan_info_map, scan_info);
        }
        pthread_mutex_unlock(&interface->scan_info_mutex);

        pthread_mutex_lock(&interface->scan_info_ap_mutex);
        total_ap_count = hash_map_count(interface->scan_info_ap_map[0]);
        pthread_mutex_unlock(&interface->scan_info_ap_mutex);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan found %u (w/o hidden SSID's)\n", __func__, __LINE__, ssid_found_count);
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan found %u (total)\n", __func__, __LINE__, total_ap_count);
    }

    if (callbacks->scan_result_callback != NULL &&
        interface->vap_info.vap_mode == wifi_vap_mode_sta && ssid_found_count) {
        if (ssid_found_count < count) {
            wifi_bss_info_t* new_bss = realloc(bss, ssid_found_count * sizeof(wifi_bss_info_t));
            if (!new_bss) {
                // - error, but not critical, original array still is valid
                wifi_hal_stats_error_print("%s:%d: [SCAN] memory re-allocation error!\n", __func__, __LINE__);
            }
            else
                bss = new_bss;
        }

        // It is assumed that "bss" has to be released by callback function:
        callbacks->scan_result_callback(interface->vap_info.radio_index, &bss, &ssid_found_count);
    } else {
        free(bss);
    }

    return NL_SKIP;
}

int nl80211_get_scan_results(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;
    wifi_finish_data_t scan_results_data = {};
    enum scan_state_type_e scan_state;

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan results available for interface '%s'\n", __func__, __LINE__, interface->name);

    pthread_mutex_lock(&interface->scan_state_mutex);
    scan_state = interface->scan_state;
    pthread_mutex_unlock(&interface->scan_state_mutex);
    if (scan_state != WIFI_SCAN_STATE_STARTED) {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] received scan results ready not started by us\n", __func__, __LINE__);
    }

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_SCAN);
    if (msg == NULL) {
        pthread_mutex_lock(&interface->scan_state_mutex);
        interface->scan_state = WIFI_SCAN_STATE_ERROR;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] nl80211_drv_cmd_msg() returned ERROR ==> Abort!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    scan_results_data.arg = interface;

    ret = nl80211_send_and_recv(msg, scan_info_handler, interface, scan_results_handler, &scan_results_data);
    if (ret) {
        pthread_mutex_lock(&interface->scan_state_mutex);
        interface->scan_state = WIFI_SCAN_STATE_ERROR;
        pthread_mutex_unlock(&interface->scan_state_mutex);
        wifi_hal_stats_error_print("%s:%d: [SCAN] Scan command failed: ret=%d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return RETURN_ERR;
    }

    pthread_mutex_lock(&interface->scan_state_mutex);
    {
        pthread_mutex_lock(&interface->scan_info_ap_mutex);
        {
            hash_map_t *tmp;
            // - cleanup old result data (they are not needed anymore)
            hash_map_cleanup(interface->scan_info_ap_map[1]);
            // - exchange scan data and result data
            tmp = interface->scan_info_ap_map[0];
            interface->scan_info_ap_map[0] = interface->scan_info_ap_map[1];
            interface->scan_info_ap_map[1] = tmp;
        }
        pthread_mutex_unlock(&interface->scan_info_ap_mutex);

        // - raise a flag indicating that the new result data are available
        interface->scan_has_results = WIFI_SCAN_RES_COLLECTED;
        interface->scan_state = WIFI_SCAN_STATE_NONE;
    }
    pthread_mutex_unlock(&interface->scan_state_mutex);

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan results collected\n", __func__, __LINE__);
    return RETURN_OK;
}

int nl80211_disconnect_sta(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_DISCONNECT)) == NULL) {
        return -1;
    }
    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: disconnect command failed: ret=%d (%s)\n", __func__, __LINE__,
                      ret, strerror(-ret));

    return -1;
}

#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
#define SEM_NAME "/semlock"

int wifi_hal_emu_set_neighbor_stats(unsigned int radio_index, bool emu_state,
    wifi_neighbor_ap2_t *neighbor_stats, unsigned int count)
{
    int fd;
    emu_neighbor_stats_t *neighbor_data;
    size_t file_size;
    char file_path[64];
    sem_t *sem;

    snprintf(file_path, sizeof(file_path), "/dev/shm/wifi_neighbor_ap_emu_%u", radio_index);

    sem = sem_open(SEM_NAME, O_CREAT, 0666, 1);
    if (sem == SEM_FAILED) {
        wifi_hal_stats_error_print("%s:%d: Failed to open semaphore\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sem_wait(sem) == -1) {
        wifi_hal_stats_error_print("%s:%d: Failed to acquire semaphore\n", __func__, __LINE__);
        sem_close(sem);
        return RETURN_ERR;
    }

    if (!emu_state && access(file_path, F_OK) == 0) {
        fd = open(file_path, O_RDWR);
        if (fd != -1) {
            size_t file_size = sizeof(emu_neighbor_stats_t) + count * sizeof(wifi_neighbor_ap2_t);
            neighbor_data = mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (neighbor_data != MAP_FAILED) {
                if (munmap(neighbor_data, file_size) == -1) {
                    wifi_hal_stats_error_print("%s:%d: Failed to unmap memory: %s\n", __func__, __LINE__,
                        strerror(errno));
                }
            }
            close(fd);
        }

        if (remove(file_path) != 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to remove the file: %s\n", __func__, __LINE__,
                file_path);
        }
        wifi_hal_stats_dbg_print("%s:%d: Emulation disabled; data cleared.\n", __func__, __LINE__);

        sem_post(sem);
        sem_close(sem);
        return RETURN_OK;
    }

    file_size = sizeof(emu_neighbor_stats_t) + count * sizeof(wifi_neighbor_ap2_t);

    fd = open(file_path, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        wifi_hal_stats_error_print("%s:%d: Failed to open file: %s\n", __func__, __LINE__, file_path);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    if (ftruncate(fd, file_size) == -1) {
        wifi_hal_stats_error_print("%s:%d: Failed to set file size\n", __func__, __LINE__);
        close(fd);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    neighbor_data = mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (neighbor_data == MAP_FAILED) {
        wifi_hal_stats_error_print("%s:%d: Failed to map file\n", __func__, __LINE__);
        close(fd);
        sem_post(sem);
        sem_close(sem);
        return RETURN_ERR;
    }

    neighbor_data->emu_enable = emu_state;
    neighbor_data->radio_index = radio_index;
    neighbor_data->neighbor_count = count;
    memcpy(neighbor_data->data, neighbor_stats, count * sizeof(wifi_neighbor_ap2_t));

    if (sem_post(sem) == -1) {
        wifi_hal_stats_error_print("%s:%d: Failed to release semaphore\n", __func__, __LINE__);
    }

    close(fd);
    sem_close(sem);
    return RETURN_OK;
}

int wifi_hal_emu_set_radio_diag_stats(unsigned int radio_index, bool emu_state,
    wifi_radioTrafficStats2_t *radio_diag_stat, unsigned int count, unsigned int phy_index,
    unsigned int interface_index)
{
    struct nl_msg *msg;
    struct nlattr *nlattr_vendor = NULL, *nlattr_radio_info = NULL;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: value of radio index %d emu_enable %d and count is %d\n", __func__,
        __LINE__, radio_index, emu_state, count);
    interface = malloc(sizeof(wifi_interface_info_t));
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to allocate memory for interface\n", __func__,
            __LINE__);
        return -1;
    }
    memset(interface, 0, sizeof(wifi_interface_info_t));
    interface->index = interface_index;
    interface->phy_index = phy_index;
    // Create the vendor-specific command message
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST,
        RDK_VENDOR_NL80211_SUBCMD_SET_RADIO_INFO);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
        free(interface);
        return -1;
    }

    /*
     * message format
     *
     * NL80211_ATTR_VENDOR_DATA
     *  RDK_VENDOR_ATTR_EMU_ENABLE
     *  RDK_VENDOR_ATTR_RADIO_INDEX
     *  RDK_VENDOR_ATTR_RADIO_INFO
     *
     */

    nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put_u32(msg, RDK_VENDOR_ATTR_EMU_ENABLE, emu_state) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set emu enable\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (nla_put_u32(msg, RDK_VENDOR_ATTR_RADIO_INDEX, radio_index) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set radio index\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (emu_state) {
        ULLONG radio_bytessent, radio_bytes_received, radio_packetssent, radio_packetsreceived,
            radio_errorsent, radio_errorsreceived, radio_discardpacketssent,
            radio_discardpacketsreceived, plcperrorcount, fcserrorcount, invalidmac_count,
            radio_packetsotherreceived, radio_channelutilization, statisticsstarttime;

        nlattr_radio_info = nla_nest_start(msg, RDK_VENDOR_ATTR_RADIO_INFO);
        if (nlattr_radio_info == NULL) {
            nlmsg_free(msg);
            free(interface);
            return -1;
        }

        radio_bytessent = radio_diag_stat->radio_BytesSent;
        radio_bytes_received = radio_diag_stat->radio_BytesReceived;
        radio_packetssent = radio_diag_stat->radio_PacketsSent;
        radio_packetsreceived = radio_diag_stat->radio_PacketsReceived;
        radio_errorsent = radio_diag_stat->radio_ErrorsSent;
        radio_errorsreceived = radio_diag_stat->radio_ErrorsReceived;
        radio_discardpacketssent = radio_diag_stat->radio_DiscardPacketsSent;
        radio_discardpacketsreceived = radio_diag_stat->radio_DiscardPacketsReceived;
        plcperrorcount = radio_diag_stat->radio_PLCPErrorCount;
        fcserrorcount = radio_diag_stat->radio_FCSErrorCount;
        invalidmac_count = radio_diag_stat->radio_InvalidMACCount;
        radio_packetsotherreceived = radio_diag_stat->radio_PacketsOtherReceived;
        radio_channelutilization = radio_diag_stat->radio_ChannelUtilization;
        statisticsstarttime = radio_diag_stat->radio_StatisticsStartTime;

        if (nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_NOISE_FLOOR,
                radio_diag_stat->radio_NoiseFloor) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_BYTES_SENT, radio_bytessent) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_BYTES_RECEIVED, radio_bytes_received) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_ACTIVITY_FACTOR,
                radio_diag_stat->radio_ActivityFactor) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_SENT, radio_packetssent) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_RECEIVED, radio_packetsreceived) <
                0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_CARRIERSENSE_THRESHOLD,
                radio_diag_stat->radio_CarrierSenseThreshold_Exceeded) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_SENT, radio_errorsent) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_ERRORS_RECEIVED, radio_errorsreceived) <
                0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_RETRANSMISSION,
                radio_diag_stat->radio_RetransmissionMetirc) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_SENT,
                radio_discardpacketssent) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_DISCARD_PACKETS_RECEIVED,
                radio_discardpacketsreceived) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_PLCP_ERRORS_COUNT, plcperrorcount) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_MAX_NOISE_FLOOR,
                radio_diag_stat->radio_MaximumNoiseFloorOnChannel) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_FCS_ERRORS_COUNT, fcserrorcount) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_INVALID_MAC_COUNT, invalidmac_count) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_MIN_NOISE_FLOOR,
                radio_diag_stat->radio_MinimumNoiseFloorOnChannel) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_PACKETS_OTHER_RECEIVED,
                radio_packetsotherreceived) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_CHANNEL_UTILIZATION,
                radio_channelutilization) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_RADIO_INFO_MEDIAN_NOISE_FLOOR,
                radio_diag_stat->radio_MedianNoiseFloorOnChannel) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_RADIO_INFO_STATS_START_TIME, statisticsstarttime) <
                0) {

            nlmsg_free(msg);
            nla_nest_cancel(msg, nlattr_radio_info);
            free(interface);
            return -1;
        }
        nla_nest_end(msg, nlattr_radio_info);
    }
    nla_nest_end(msg, nlattr_vendor);

    if (nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) != 0) {
        wifi_hal_error_print("%s:%d: Failed to send NL command for radio index %d\n", __func__,
            __LINE__, radio_index);
        free(interface);
        return -1;
    }
    free(interface);
    return 0;
}

typedef struct {
    const char *str;
    uint32_t standard;
} standard_mapping_t;

static standard_mapping_t standard_map[] = {
    { "", RDK_VENDOR_NL80211_STANDARD_NONE},
    { "a", RDK_VENDOR_NL80211_STANDARD_A },
    { "b", RDK_VENDOR_NL80211_STANDARD_B },
    { "g", RDK_VENDOR_NL80211_STANDARD_G },
    { "n", RDK_VENDOR_NL80211_STANDARD_N },
    { "ac", RDK_VENDOR_NL80211_STANDARD_AC },
    { "ad", RDK_VENDOR_NL80211_STANDARD_AD },
    { "ax", RDK_VENDOR_NL80211_STANDARD_AX },
#ifdef CONFIG_IEEE80211BE
    { "be", RDK_VENDOR_NL80211_STANDARD_BE },
#endif /* CONFIG_IEEE80211BE */
};
static void str_to_standard(const char *str, uint32_t *standard)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(standard_map); i++) {
        if (strcmp(standard_map[i].str, str) == 0) {
            *standard = standard_map[i].standard;
            return;
        }
    }
}
static void wl_cfgvendor_get_station_bw(wifi_associated_dev3_t *sta_info, u8 *bw)
{
    switch (atoi(sta_info->cli_OperatingChannelBandwidth)) {
        case 20: *bw = RDK_VENDOR_NL80211_CHAN_WIDTH_20; break;
        case 40: *bw = RDK_VENDOR_NL80211_CHAN_WIDTH_40; break;
        case 80: *bw = RDK_VENDOR_NL80211_CHAN_WIDTH_80; break;
        case 160: *bw = RDK_VENDOR_NL80211_CHAN_WIDTH_160; break;
#ifdef CONFIG_IEEE80211BE
        case 320: *bw = RDK_VENDOR_NL80211_CHAN_WIDTH_320; break;
#endif /* CONFIG_IEEE80211BE */
        default: *bw = 0; break;
    }
}
static int wifi_hal_emu_set_assoc_clients_stats_data(unsigned int vap_index, bool emu_state, wifi_associated_dev3_t *stats, unsigned int count, wifi_interface_info_t *interface)
{
    wifi_hal_stats_dbg_print("%s:%d: value of vap index %d emu_enable %d and count is %d\n", __func__, __LINE__, vap_index, emu_state, count);
    if (stats == NULL) {
        wifi_hal_stats_error_print("%s:%d: Stats is NULL\n", __func__, __LINE__);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        u8 bw;
        uint32_t standard = 0;
        struct nl_msg *msg;
        struct nlattr *nlattr_vendor = NULL, *nlattr_sta_info = NULL;
        ULLONG cli_DataFramesSentAck = 0, cli_PacketsReceived = 0,
            cli_ErrorsSent = 0, cli_FailedRetransCount = 0,
            cli_RetryCount = 0, cli_BytesSent = 0, cli_BytesReceived = 0;

        cli_DataFramesSentAck = stats[i].cli_DataFramesSentAck;
        cli_PacketsReceived = stats[i].cli_PacketsReceived;
        cli_ErrorsSent = stats[i].cli_ErrorsSent;
        cli_FailedRetransCount = stats[i].cli_FailedRetransCount;
        cli_RetryCount = stats[i].cli_RetryCount;
        cli_BytesSent = stats[i].cli_BytesSent;
        cli_BytesReceived = stats[i].cli_BytesReceived;

        // Create the vendor-specific command message
        msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST, RDK_VENDOR_NL80211_SUBCMD_SET_STATION_EMU);
        if (msg == NULL) {
            wifi_hal_stats_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
            return -1;
        }
        /*
         * message format for each client stats
         *
         *  NL80211_ATTR_VENDOR_DATA
         *  RDK_VENDOR_ATTR_EMU_ENABLE
         *  RDK_VENDOR_ATTR_VAP_INDEX
         *  RDK_VENDOR_ATTR_SURVEY_INFO
         *      Client stats //nlattr_sta_info_msg
         * */

        nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        if (nla_put_u32(msg, RDK_VENDOR_ATTR_EMU_ENABLE, emu_state) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to set emu enable\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put_u32(msg, RDK_VENDOR_ATTR_VAP_INDEX, vap_index) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to set vap index\n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put_u32(msg, RDK_VENDOR_ATTR_STA_NUM, i) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to RDK_VENDOR_ATTR_STA_NUM \n", __func__, __LINE__);
            nlmsg_free(msg);
            return -1;
        }

        if (nla_put(msg, RDK_VENDOR_ATTR_MAC, ETHER_ADDR_LEN, stats[i].cli_MACAddress) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to add station mac attribute for vap index %d\n", __func__, __LINE__, vap_index);
            nlmsg_free(msg);
            return -1;
        }

        nlattr_sta_info = nla_nest_start(msg, RDK_VENDOR_ATTR_STA_INFO);
        if (!nlattr_sta_info) {
            wifi_hal_stats_error_print("%s:%d: Failed to add station list attribute for vap index %d\n", __func__, __LINE__, vap_index);
            nlmsg_free(msg);
            return -1;
        }

        wl_cfgvendor_get_station_bw(&stats[i], &bw);
        str_to_standard(stats[i].cli_OperatingStandard, &standard);

        if (nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_STA_FLAGS, stats[i].cli_AuthenticationState) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_RX_BITRATE_LAST, stats[i].cli_LastDataUplinkRate) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_TX_BITRATE_LAST, stats[i].cli_LastDataDownlinkRate) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_STA_INFO_SIGNAL_AVG, stats[i].cli_RSSI) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES_PERCENT, stats[i].cli_Retransmissions) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_OPER_STANDARD, standard) < 0 ||
            nla_put_u8(msg, RDK_VENDOR_ATTR_STA_INFO_OPER_CHANNEL_BW, bw) < 0 ||
            nla_put_s32(msg, RDK_VENDOR_ATTR_STA_INFO_SNR, stats[i].cli_SNR) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_TX_PACKETS_ACK, cli_DataFramesSentAck) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_TX_RATE_MAX, stats[i].cli_MaxDownlinkRate) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_TX_BYTES64, cli_BytesSent) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_RX_RATE_MAX, stats[i].cli_MaxUplinkRate) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_RX_BYTES64, cli_BytesReceived) < 0 ||
            nla_put_u8(msg, RDK_VENDOR_ATTR_STA_INFO_SPATIAL_STREAM_NUM, stats[i].cli_activeNumSpatialStreams) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_TX_FRAMES, stats[i].cli_TxFrames) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_RX_PACKETS64, cli_PacketsReceived) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_TX_ERRORS, cli_ErrorsSent) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_RX_RETRIES, stats[i].cli_RxRetries) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_TX_FAILED_RETRIES, cli_FailedRetransCount) < 0 ||
            nla_put_u32(msg, RDK_VENDOR_ATTR_STA_INFO_ASSOC_NUM, stats[i].cli_Associations) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_TX_RETRIES, cli_RetryCount) < 0 ||
            nla_put_u64(msg, RDK_VENDOR_ATTR_STA_INFO_RX_ERRORS, stats[i].cli_RxErrors) < 0 ) {

            nla_nest_cancel(msg, nlattr_sta_info);
            nlmsg_free(msg);
            return -1;
        }
        nla_nest_end(msg, nlattr_sta_info);
        nla_nest_end(msg, nlattr_vendor);

        if (nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) != 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to send NL command for vap index %d\n", __func__, __LINE__, vap_index);
            return -1;
        }
    }
    return 0;
}
int wifi_hal_emu_set_assoc_clients_stats(unsigned int vap_index, bool emu_state, wifi_associated_dev3_t *stats, unsigned int count, unsigned int phy_index, unsigned int interface_index)
{
    struct nl_msg *msg;
    struct nlattr *nlattr_vendor = NULL;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: value of vap index %d emu_enable %d and count is %d\n", __func__, __LINE__, vap_index, emu_state, count);
    interface = malloc(sizeof(wifi_interface_info_t));
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to allocate memory for interface\n", __func__, __LINE__);
        return -1;
    }
    memset(interface, 0, sizeof(wifi_interface_info_t));
    interface->index = interface_index;
    interface->phy_index = phy_index;
    wifi_hal_stats_dbg_print("%s:%d: value of index %d and phy_index is %d \n", __func__, __LINE__, interface->index, interface->phy_index);
    // Create the vendor-specific command message
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST, RDK_VENDOR_NL80211_SUBCMD_SET_STATION_LIST_EMU);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
        free(interface);
        return -1;
    }
    /*
     * message format
     *
     *  NL80211_ATTR_VENDOR_DATA
     *  RDK_VENDOR_ATTR_EMU_ENABLE
     *  RDK_VENDOR_ATTR_VAP_INDEX
     *  RDK_VENDOR_ATTR_STA_NUM
     * */

    nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put_u32(msg, RDK_VENDOR_ATTR_EMU_ENABLE, emu_state) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to set emu enable\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (nla_put_u32(msg, RDK_VENDOR_ATTR_VAP_INDEX, vap_index) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to set vap index\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (emu_state) {
        if (nla_put_u32(msg, RDK_VENDOR_ATTR_STA_NUM, count) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to RDK_VENDOR_ATTR_STA_NUM \n", __func__, __LINE__);
            nlmsg_free(msg);
            free(interface);
            return -1;
        }
    }
    nla_nest_end(msg, nlattr_vendor);

    if (nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) != 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to send NL command for vap index %d\n", __func__, __LINE__, vap_index);
        free(interface);
        return -1;
    }

    if (emu_state) {
        if (wifi_hal_emu_set_assoc_clients_stats_data(vap_index, emu_state, stats, count, interface) != 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to send assoc client data for vap index %d\n", __func__, __LINE__, vap_index);
            free(interface);
            return -1;
        }
    }
    free(interface);
    return 0;
}

int wifi_hal_emu_set_radio_temp(unsigned int radio_index, bool emu_state, int temperature,
    unsigned int phy_index, unsigned int interface_index)
{
    struct nl_msg *msg;
    struct nlattr *nlattr_vendor = NULL;
    wifi_interface_info_t *interface;

    wifi_hal_dbg_print("%s:%d: value of radio index %d emu_enable %d\n", __func__, __LINE__, radio_index, emu_state);
    interface = malloc(sizeof(wifi_interface_info_t));
    if (interface == NULL) {
        wifi_hal_error_print("%s:%d: Failed to allocate memory for interface\n", __func__, __LINE__);
        return -1;
    }
    memset(interface, 0, sizeof(wifi_interface_info_t));
    interface->index = interface_index;
    interface->phy_index = phy_index;
    wifi_hal_dbg_print("%s:%d: value of index %d and phy_index is %d\n", __func__, __LINE__, interface->index, interface->phy_index);
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST, RDK_VENDOR_NL80211_SUBCMD_SET_WIPHY_TEMP);
    // Create the vendor-specific command message
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
        free(interface);
        return -1;
    }

    nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put_u32(msg, RDK_VENDOR_ATTR_EMU_ENABLE, emu_state) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set emu enable\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (nla_put_u32(msg, RDK_VENDOR_ATTR_RADIO_INDEX, radio_index) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set radio index\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (nla_put_s32(msg, RDK_VENDOR_ATTR_WIPHY_TEMP, temperature) < 0) {
        wifi_hal_error_print("%s:%d: Failed to set wiphy temp\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }
    nla_nest_end(msg, nlattr_vendor);

    if (nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) != 0) {
        wifi_hal_error_print("%s:%d: Failed to send NL command for radio index %d\n", __func__, __LINE__, radio_index);
        free(interface);
        return -1;
    }
    free(interface);
    return 0;
}

int wifi_hal_emu_set_radio_channel_stats(unsigned int radio_index, bool emu_state, wifi_channelStats_t *chan_stat, unsigned int count, unsigned int phy_index, unsigned int interface_index)
{
    struct nl_msg *msg;
    struct nlattr *nlattr_vendor = NULL, *nlattr_survey = NULL, *nlattr_channel = NULL;
    wifi_interface_info_t *interface;

    wifi_hal_stats_dbg_print("%s:%d: value of radio index %d emu_enable %d and count is %d\n", __func__, __LINE__, radio_index, emu_state, count);
    interface = malloc(sizeof(wifi_interface_info_t));
    if (interface == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to allocate memory for interface\n", __func__, __LINE__);
        return -1;
    }
    memset(interface, 0, sizeof(wifi_interface_info_t));
    interface->index = interface_index;
    interface->phy_index = phy_index;
    wifi_hal_stats_dbg_print("%s:%d: value of index %d and phy_index is %d \n", __func__, __LINE__, interface->index, interface->phy_index);
    // Create the vendor-specific command message
    msg = nl80211_drv_vendor_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, OUI_COMCAST, RDK_VENDOR_NL80211_SUBCMD_SET_SURVEY_EMU);
    if (msg == NULL) {
        wifi_hal_stats_error_print("%s:%d: Failed to create NL command\n", __func__, __LINE__);
        free(interface);
        return -1;
    }


    /*
     * message format
     *
     * NL80211_ATTR_VENDOR_DATA
     *  RDK_VENDOR_ATTR_EMU_ENABLE
     *  RDK_VENDOR_ATTR_RADIO_INDEX
     *      RDK_VENDOR_ATTR_SURVEY_INFO
     *          Channel 0 //nlattr_channel
     *          Channel 1 //nlattr_channel
     *
     *
     * */

    nlattr_vendor = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (nla_put_u32(msg, RDK_VENDOR_ATTR_EMU_ENABLE, emu_state) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to set emu enable\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (nla_put_u32(msg, RDK_VENDOR_ATTR_RADIO_INDEX, radio_index) < 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to set radio index\n", __func__, __LINE__);
        nlmsg_free(msg);
        free(interface);
        return -1;
    }

    if (emu_state) {
        if (nla_put_u32(msg, RDK_VENDOR_ATTR_STA_NUM, count) < 0) {
            wifi_hal_stats_error_print("%s:%d: Failed to RDK_VENDOR_ATTR_STA_NUM \n", __func__, __LINE__);
            nlmsg_free(msg);
            free(interface);
            return -1;
        }

        nlattr_survey = nla_nest_start(msg, RDK_VENDOR_ATTR_SURVEY_INFO);
        if (!nlattr_survey) {
            nlmsg_free(msg);
            free(interface);
            return -1;
        }

        for (size_t i = 0; i < count; ++i) {
            nlattr_channel = nla_nest_start(msg, i);
            if (!nlattr_channel) {
                nlmsg_free(msg);
                free(interface);
                return -1;
            }

            wifi_hal_stats_dbg_print("%s:%d: Channel %u: Noise %d, Radar Noise %d, Max RSSI %d, Non-80211 Noise %d, Utilization %u, Utilization Total %llu, Utilization Busy %llu, Utilization Busy TX %llu, Utilization Busy RX %llu, Utilization Busy Self %llu, Utilization Busy Ext %llu\n",
                __func__, __LINE__, chan_stat[i].ch_number, chan_stat[i].ch_noise, chan_stat[i].ch_radar_noise, chan_stat[i].ch_max_80211_rssi,
                chan_stat[i].ch_non_80211_noise, chan_stat[i].ch_utilization, chan_stat[i].ch_utilization_total, chan_stat[i].ch_utilization_busy,
                chan_stat[i].ch_utilization_busy_tx, chan_stat[i].ch_utilization_busy_rx,
                chan_stat[i].ch_utilization_busy_self, chan_stat[i].ch_utilization_busy_ext);

            /* RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY is reused to send channel number instead of channel spec */
            if (nla_put_u32(msg, RDK_VENDOR_ATTR_SURVEY_INFO_FREQUENCY, chan_stat[i].ch_number) < 0 ||
                nla_put_s32(msg, RDK_VENDOR_ATTR_SURVEY_INFO_NOISE, chan_stat[i].ch_noise) < 0 ||
                nla_put_s32(msg, RDK_VENDOR_ATTR_SURVEY_INFO_RADAR_NOISE, chan_stat[i].ch_radar_noise) < 0 ||
                nla_put_s32(msg, RDK_VENDOR_ATTR_SURVEY_INFO_MAX_RSSI, chan_stat[i].ch_max_80211_rssi) < 0 ||
                nla_put_s32(msg, RDK_VENDOR_ATTR_SURVEY_INFO_NON_80211_NOISE, chan_stat[i].ch_non_80211_noise) < 0 ||
                nla_put_u8(msg, RDK_VENDOR_ATTR_SURVEY_INFO_CHAN_UTIL, chan_stat[i].ch_utilization) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_ACTIVE, chan_stat[i].ch_utilization_total) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY, chan_stat[i].ch_utilization_busy) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_TX, chan_stat[i].ch_utilization_busy_tx) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX, chan_stat[i].ch_utilization_busy_rx) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_BUSY_RX_SELF, chan_stat[i].ch_utilization_busy_self) < 0 ||
                nla_put_u64(msg, RDK_VENDOR_ATTR_SURVEY_INFO_TIME_EXT_BUSY, chan_stat[i].ch_utilization_busy_ext) < 0) {

                nla_nest_cancel(msg, nlattr_channel);
                nlmsg_free(msg);
                free(interface);
                return -1;
            }

            nla_nest_end(msg, nlattr_channel);
        }

        nla_nest_end(msg, nlattr_survey);
    }
    nla_nest_end(msg, nlattr_vendor);

    if (nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL) != 0) {
        wifi_hal_stats_error_print("%s:%d: Failed to send NL command for radio index %d\n", __func__, __LINE__, radio_index);
        free(interface);
        return -1;
    }

    free(interface);

    return 0;
}
#endif


#define MAX_PWD_LEN 64
#define MAX_SAE_GROUP 5
int nl80211_connect_sta(wifi_interface_info_t *interface)
{
    int ret;
    wifi_vap_info_t *vap;
    wifi_bss_info_t *backhaul;
    wifi_vap_security_t *security;
    mac_addr_str_t bssid_str;
    //unsigned int rsn_ie_len;
#ifndef CONFIG_WIFI_EMULATOR
    u32 ver = 0;
    u8 *pos, rsn_ie[128];
    struct wpa_auth_config wpa_conf = {0};
    struct wpa_ie_data data;
    struct nl_msg *msg;
    int sel, key_mgmt = 0;
#endif

    vap = &interface->vap_info;
    backhaul = &interface->u.sta.backhaul;
    security = &vap->u.sta_info.security;

#ifdef CONFIG_WIFI_EMULATOR
    struct wpa_bss *bss;
    wifi_radio_info_t *radio;
    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
        to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    if ((interface->wpa_s.current_ssid == NULL) || (interface->wpa_s.p2pdev == NULL) ||
        (interface->wpa_s.conf == NULL)) {
        wifi_hal_error_print("%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }
    if (interface->wpa_s.current_bss == NULL) {
        interface->wpa_s.current_bss = (struct wpa_bss *)malloc(
                sizeof(struct wpa_bss) + interface->ie_len);
        if (interface->wpa_s.current_bss == NULL) {
            wifi_hal_error_print("%s:%d NULL Pointer\n", __func__, __LINE__);
            return -1;
        }
    }
    // Fill in current bss struct where we are going to connect.
    memset(interface->wpa_s.current_bss, 0, sizeof(struct wpa_bss) + interface->ie_len);
    strcpy(interface->wpa_s.current_bss->ssid, backhaul->ssid);
    interface->wpa_s.current_bss->ssid_len = strlen(backhaul->ssid);
    memcpy(interface->wpa_s.current_bss->bssid, backhaul->bssid, ETH_ALEN);
    memcpy(interface->wpa_s.current_ssid->bssid, backhaul->bssid, ETH_ALEN);
    if (security->encr == wifi_encryption_aes) {
        interface->wpa_s.current_ssid->pairwise_cipher = WPA_CIPHER_CCMP;
        interface->wpa_s.current_ssid->group_cipher = WPA_CIPHER_CCMP;
    } else if (security->encr == wifi_encryption_tkip) {
        interface->wpa_s.current_ssid->pairwise_cipher = WPA_CIPHER_TKIP;
        interface->wpa_s.current_ssid->group_cipher = WPA_CIPHER_TKIP;
    } else if (security->encr == wifi_encryption_aes_tkip) {
        interface->wpa_s.current_ssid->pairwise_cipher = WPA_CIPHER_TKIP;
        interface->wpa_s.current_ssid->group_cipher = WPA_CIPHER_CCMP;
    } else if (security->encr == wifi_encryption_none) {
        interface->wpa_s.current_ssid->pairwise_cipher = WPA_CIPHER_NONE;
        interface->wpa_s.current_ssid->group_cipher = WPA_CIPHER_NONE;
    } else {
        wifi_hal_info_print("%s:%d:Invalid encryption mode:%d in wifi_hal_connect\n", __func__,
            __LINE__, security->encr);
        return -1;
    }

    update_wpa_sm_params(interface);
    interface->wpa_s.current_ssid->proto = WPA_PROTO_RSN;
    interface->wpa_s.current_ssid->group_mgmt_cipher = WPA_CIPHER_AES_128_CMAC;

    interface->wpa_s.current_ssid->key_mgmt = interface->u.sta.wpa_sm->key_mgmt;
    if ((security->mode == wifi_security_mode_wpa3_personal) ||
        (security->mode == wifi_security_mode_wpa3_transition) ||
        (security->mode == wifi_security_mode_wpa3_enterprise)) {
        interface->wpa_s.current_ssid->ieee80211w = MGMT_FRAME_PROTECTION_REQUIRED;
        if (interface->wpa_s.conf->sae_groups == NULL) {
            interface->wpa_s.conf->sae_groups =
                os_malloc(sizeof(*interface->wpa_s.conf->sae_groups) * MAX_SAE_GROUP);
            if (interface->wpa_s.conf->sae_groups == NULL) {
                wifi_hal_error_print("%s:%d: NULL pointer\n", __func__, __LINE__);
                free(interface->wpa_s.current_bss);
                interface->wpa_s.current_bss = NULL;
                return -1;
            }
        }

	interface->wpa_s.conf->sae_groups[0] = 19;
	interface->wpa_s.conf->sae_groups[1] = 20;
	interface->wpa_s.conf->sae_groups[2] = 21;
	interface->wpa_s.conf->sae_groups[3] = -1;
    }
    if (interface->wpa_s.current_ssid->ssid == NULL) {
        interface->wpa_s.current_ssid->ssid = malloc(strlen(backhaul->ssid) + 1);
        if (interface->wpa_s.current_ssid->ssid == NULL) {
            wifi_hal_error_print("%s:%d: NULL pointer\n", __func__, __LINE__);
            free(interface->wpa_s.current_bss);
            interface->wpa_s.current_bss = NULL;
            if (interface->wpa_s.conf->sae_groups) {
                free(interface->wpa_s.conf->sae_groups);
                interface->wpa_s.conf->sae_groups = NULL;
            }
            return -1;
        }
    }

    if ( (security->mode == wifi_security_mode_wpa3_personal) ||
        (security->mode == wifi_security_mode_wpa3_compatibility)) {
        interface->wpa_s.current_ssid->sae_password = malloc(MAX_PWD_LEN);
        if (interface->wpa_s.current_ssid->sae_password == NULL) {
            wifi_hal_error_print("%s:%d: NULL pointer\n", __func__, __LINE__);
            free(interface->wpa_s.current_ssid->ssid);
            interface->wpa_s.current_ssid->ssid = NULL;
            free(interface->wpa_s.current_bss);
            interface->wpa_s.current_bss = NULL;
            return -1;
        }
        memset(interface->wpa_s.current_ssid->sae_password, 0, MAX_PWD_LEN);
        strncpy(interface->wpa_s.current_ssid->sae_password, security->u.key.key,
            MAX_PWD_LEN-1);
    } else if ((security->mode != wifi_security_mode_wpa2_enterprise) &&
        (security->mode != wifi_security_mode_wpa3_enterprise)) {
        interface->wpa_s.current_ssid->passphrase = malloc(MAX_PWD_LEN);
        if (interface->wpa_s.current_ssid->passphrase == NULL) {
            wifi_hal_error_print("%s:%d: NULL pointer\n", __func__, __LINE__);
            free(interface->wpa_s.current_ssid->ssid);
            free(interface->wpa_s.current_bss);
            return -1;
        }
        interface->wpa_s.current_ssid->bssid_set = 1;
        interface->wpa_s.current_ssid->ssid_len = 0;
        memset(interface->wpa_s.current_ssid->passphrase, 0, MAX_PWD_LEN);
        strncpy(interface->wpa_s.current_ssid->passphrase, security->u.key.key,
            MAX_PWD_LEN-1);
    }

    if (security->mode != wifi_security_mode_wpa3_personal) {
        interface->wpa_s.current_ssid->ieee80211w = security->mfp;
    }

    memset(interface->wpa_s.current_ssid->ssid, 0, (strlen(backhaul->ssid) + 1));
    strcpy(interface->wpa_s.current_ssid->ssid, backhaul->ssid);
    if ((security->mode != wifi_security_mode_wpa2_personal) &&
            (security->mode != wifi_security_mode_wpa3_transition) &&
            (security->mode != wifi_security_mode_wpa3_compatibility)) {
        interface->wpa_s.current_ssid->ssid_len = strlen(backhaul->ssid);
    }
    interface->wpa_s.current_bss->freq = backhaul->freq;
    interface->wpa_s.current_bss->ie_len = interface->ie_len;
    interface->wpa_s.current_bss->beacon_ie_len = interface->beacon_ie_len;
    interface->wpa_s.drv_priv = interface;
    radio = get_radio_by_phy_index(interface->phy_index);
    interface->wpa_s.hw.modes = radio->hw_modes;
    interface->wpa_s.hw.num_modes = NUM_NL80211_BANDS;
    memcpy(interface->wpa_s.own_addr, vap->u.sta_info.mac, ETH_ALEN);
    struct wpa_bss *curr_bss = (struct wpa_bss *)malloc(sizeof(struct wpa_bss) + interface->ie_len);
    if (curr_bss == NULL) {
        wifi_hal_error_print("%s:%d: NULL pointer\n", __func__, __LINE__);
        free(interface->wpa_s.current_ssid->ssid);
        free(interface->wpa_s.current_bss);
        if (interface->wpa_s.current_ssid->sae_password)
            free(interface->wpa_s.current_ssid->sae_password);
        if (interface->wpa_s.current_ssid->passphrase)
            free(interface->wpa_s.current_ssid->passphrase);
        return -1;
    }
    memset(curr_bss, 0, sizeof(struct wpa_bss) + interface->ie_len);
    strcpy(curr_bss->ssid, backhaul->ssid);
    curr_bss->ssid_len = strlen(backhaul->ssid);
    memcpy(curr_bss->bssid, backhaul->bssid, ETH_ALEN);
    curr_bss->freq = backhaul->freq;
    curr_bss->ie_len = interface->ie_len;
    curr_bss->beacon_ie_len = interface->beacon_ie_len;
    if (interface->ie != NULL) {
        memcpy(curr_bss + 1, interface->ie, interface->ie_len);
    }

    if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        interface->wpa_s.conf->sae_pwe = 1;

        interface->wpa_s.current_ssid->pt = sae_derive_pt(interface->wpa_s.conf->sae_groups,
            interface->wpa_s.current_ssid->ssid,
            interface->wpa_s.current_ssid->ssid_len,
            interface->wpa_s.current_ssid->sae_password,
            os_strlen(interface->wpa_s.current_ssid->sae_password),
            interface->wpa_s.current_ssid->sae_password_id);
    }

    interface->wpa_s.driver = &g_wpa_supplicant_driver_nl80211_ops;
    memcpy(interface->wpa_s.conf->ssid, interface->wpa_s.current_ssid, sizeof(struct wpa_ssid));
    memcpy(interface->wpa_s.bssid, backhaul->bssid, ETH_ALEN);
    dl_list_add(&interface->wpa_s.bss, &interface->wpa_s.current_bss->list);

    bss = wpa_bss_get_bssid_latest(&interface->wpa_s, backhaul->bssid);
    if (bss) { 
        memcpy(bss + 1, interface->ie, interface->ie_len);
    }

    sme_send_authentication(&interface->wpa_s, curr_bss, interface->wpa_s.current_ssid, 1);
    return 0;
#else
    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_CONNECT)) == NULL) {
        return -1;
    }


    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
            to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    nla_put(msg, NL80211_ATTR_SSID, strlen(backhaul->ssid), backhaul->ssid);
    nla_put(msg, NL80211_ATTR_MAC, sizeof(backhaul->bssid), backhaul->bssid);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, backhaul->freq);

    pos = rsn_ie;


    if (backhaul->ie_len && (wpa_parse_wpa_ie_rsn(backhaul->ie, backhaul->ie_len, &data) == 0)) {
        wpa_conf.wpa_group = data.group_cipher;
        wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
        if (data.key_mgmt & WPA_KEY_MGMT_NONE) {
            wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_NONE;
        } else {
            sel = (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_PSK_SHA256) & data.key_mgmt;
            key_mgmt = pick_akm_suite(sel);

            if (key_mgmt == -1) {
                wifi_hal_error_print("Unsupported AKM suite: 0x%x\n", data.key_mgmt);
                return -1;
            }

            wpa_conf.wpa_key_mgmt = key_mgmt;
        }

        wifi_hal_dbg_print("%s:%d: %x %x %x\n", __func__, __LINE__, data.group_cipher,
            data.pairwise_cipher, key_mgmt);
    } else {
        if (security->mode == wifi_security_mode_none) {
            wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_NONE;
            wpa_conf.wpa_group = WPA_CIPHER_NONE;
            wpa_conf.rsn_pairwise = WPA_CIPHER_NONE;
        } else {
            if (security->encr == wifi_encryption_aes) {
                wpa_conf.wpa_group = WPA_CIPHER_CCMP;
                wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
            } else if (security->encr == wifi_encryption_tkip) {
                wpa_conf.wpa_group = WPA_CIPHER_TKIP;
                wpa_conf.rsn_pairwise = WPA_CIPHER_TKIP;
            } else if (security->encr == wifi_encryption_aes_tkip) {
                wpa_conf.wpa_group = WPA_CIPHER_TKIP;
                wpa_conf.rsn_pairwise = WPA_CIPHER_CCMP;
            } else {
                wifi_hal_info_print("%s:%d:Invalid encryption mode:%d in wifi_hal_connect\n", __func__, __LINE__, security->encr);
            }

            switch (security->mode) {
                case wifi_security_mode_wpa_personal:
                case wifi_security_mode_wpa2_personal:
                case wifi_security_mode_wpa_wpa2_personal:
                    wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_PSK;
                    break;

                case wifi_security_mode_wpa_enterprise:
                case wifi_security_mode_wpa2_enterprise:
                case wifi_security_mode_wpa_wpa2_enterprise:
                    wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X;
                    break;
                case wifi_security_mode_wpa3_personal:
                case wifi_security_mode_wpa3_enterprise:
                    wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_SAE;
                    break;
                case wifi_security_mode_wpa3_transition:
                    wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE;
                    break;
                    case wifi_security_mode_wpa3_compatibility:
                    wpa_conf.wpa_key_mgmt = WPA_KEY_MGMT_PSK;
#if HOSTAPD_VERSION >= 210
                    wpa_conf.wpa_key_mgmt_rsno = WPA_KEY_MGMT_SAE;
#endif /* HOSTAPD_VERSION >= 210 */
                    break;
                default:
                    wifi_hal_info_print("%s:%d:Invalid security mode: %d in wifi_hal_connect\r\n", __func__, __LINE__, security->mode);
                    wpa_conf.wpa_key_mgmt = -1;
                    break;
            }
        }
    }

    wpa_conf.ieee80211w = 0;

    if (security->mode != wifi_security_mode_none) {
        if ((ret = wpa_write_rsn_ie(&wpa_conf, pos, rsn_ie + sizeof(rsn_ie) - pos, NULL)) < 0) {
            wifi_hal_error_print("%s:%d Failed to build RSN %d\r\n", __func__, __LINE__, ret);
            return ret;
        }
        else {
            pos += ret;
            nla_put(msg, NL80211_ATTR_IE, pos - rsn_ie, rsn_ie);
        }

        if (security->mode == wifi_security_mode_wpa2_enterprise || security->mode == wifi_security_mode_wpa2_personal)
            ver |= NL80211_WPA_VERSION_2;
        else
            ver |= NL80211_WPA_VERSION_1;
        nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, ver);

        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, RSN_CIPHER_SUITE_CCMP);
        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, RSN_CIPHER_SUITE_CCMP);

        if (security->mode == wifi_security_mode_wpa2_enterprise)
            nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X);
        else if (security->mode == wifi_security_mode_wpa2_personal)
            nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X);

        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
        nla_put_flag(msg, NL80211_ATTR_PRIVACY);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
        wifi_hal_dbg_print("security mode open:%d encr:%d\n", security->mode, security->encr);
    }

    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }
#endif /* CONFIG_WIFI_EMULATOR */
    wifi_hal_error_print("%s:%d: connect command failed: ret=%d (%s)\n", __func__, __LINE__,
            ret, strerror(-ret));

    return -1;
}

static int conn_get_interface_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface  = (wifi_interface_info_t*)arg;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    wifi_bss_info_t bss;
    unsigned int channel_width = 0;
    wifi_vap_info_t *vap;
    int bw = NL80211_CHAN_WIDTH_20_NOHT;
    wifi_device_callbacks_t *callbacks;
    wifi_station_stats_t sta;
    wifi_radio_info_t *radio =  NULL;
    wifi_radio_operationParam_t *radio_param = NULL;
    int op_class;
    u8 channel;


    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    vap = &interface->vap_info;
    memcpy(&bss, &interface->u.sta.backhaul, sizeof(wifi_bss_info_t));

    if (tb[NL80211_ATTR_IFINDEX]) {
        if (interface->index == nla_get_u32(tb[NL80211_ATTR_IFINDEX]))
        {
            if (tb[NL80211_ATTR_WIPHY_FREQ])
            {
                ieee80211_freq_to_chan(nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]), &channel);
            }
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
           radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
            if (radio && radio->oper_param.band == WIFI_FREQUENCY_6_BAND){
                bw = platform_get_bandwidth(interface);
            } else {
#endif
            if (tb[NL80211_ATTR_CHANNEL_WIDTH])
            {
                bw = nla_get_u32(tb[NL80211_ATTR_CHANNEL_WIDTH]);
            }
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
            }
#endif
        }
    }
    switch (bw) {
    case NL80211_CHAN_WIDTH_20:
        channel_width = WIFI_CHANNELBANDWIDTH_20MHZ;
        break;
    case NL80211_CHAN_WIDTH_40:
        channel_width = WIFI_CHANNELBANDWIDTH_40MHZ;
        break;
    case NL80211_CHAN_WIDTH_80:
        channel_width = WIFI_CHANNELBANDWIDTH_80MHZ;
        break;
    case NL80211_CHAN_WIDTH_160:
        channel_width = WIFI_CHANNELBANDWIDTH_160MHZ;
        break;
#ifdef CONFIG_IEEE80211BE
    case NL80211_CHAN_WIDTH_320:
        channel_width = WIFI_CHANNELBANDWIDTH_320MHZ;
        break;
#endif /* CONFIG_IEEE80211BE */
    case NL80211_CHAN_WIDTH_80P80:
        channel_width = WIFI_CHANNELBANDWIDTH_80_80MHZ;
        break;
    default:
        break;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d: Unable to get radio_info for radio index %d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return NL_SKIP;
    }

    radio_param = &radio->oper_param;
    if (radio_param == NULL) {
        wifi_hal_error_print("%s:%d: Unable to get radio params\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if ((op_class = get_op_class_from_radio_params(radio_param)) == -1) {
        wifi_hal_error_print("%s:%d: could not find op_class for radio index:%d\n", __func__, __LINE__, interface->vap_info.radio_index);
        return NL_SKIP;
    }

    sta.channel = channel;
    sta.op_class = op_class;
    sta.channelWidth = channel_width;

    sta.vap_index = vap->vap_index;
    sta.connect_status = wifi_connection_status_connected;

    callbacks = get_hal_device_callbacks();

    if (callbacks->sta_conn_status_callback) {
        callbacks->sta_conn_status_callback(vap->vap_index, &bss, &sta);
    }

    return NL_SKIP;
}

int nl80211_get_channel_bw_conn(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_GET_INTERFACE);
    if (msg == NULL){
        return -1;
    }

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index);
    if (nl80211_send_and_recv(msg, conn_get_interface_handler, interface, NULL, NULL)) {
        return -1;
    }

    return 0;

}

// convert time in ms to TUs ( 1 TU == 1024 us == 1.024 ms )
static inline uint ms_to_TU(uint ms)
{
    return  ((ms * 1000) + 1023) / 1024;
}

int nl80211_start_scan(wifi_interface_info_t *interface, uint flags,
        unsigned int num_freq, unsigned int  *freq_list, unsigned int dwell_time,
        unsigned int num_ssid, ssid_t *ssid_list)
{
    struct nl_msg *msg;
    int ret;
    unsigned int i;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_TRIGGER_SCAN)) == NULL) {
        return -1;
    }

    //nla_put_u32(msg, NL80211_ATTR_SCHED_SCAN_INTERVAL, scan_params->period);
#ifndef CONFIG_WIFI_EMULATOR
    // - NL80211_ATTR_MEASUREMENT_DURATION is specified in TUs, not in ms:
    nla_put_u16(msg, NL80211_ATTR_MEASUREMENT_DURATION, ms_to_TU(dwell_time));
    if (dwell_time > 0) {
        nla_put_flag(msg, NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY);
    }
#endif
    /* Handle SSID's */
    if (num_ssid && ssid_list) {
        struct nlattr *ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
        if (ssids == NULL) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] nl message build failure (ssid's)\n", __func__, __LINE__);
            goto failure;
        }

        for (i = 0; i < num_ssid; i++) {
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] Added scan ssid '%s'\n", __func__, __LINE__, ssid_list[i]);
            if (nla_put(msg, i + 1, wifi_strnlen(ssid_list[i], SSID_MAX_LEN), ssid_list[i])) {
                wifi_hal_stats_error_print("%s:%d: [SCAN] nl message build failure (ssid's)\n", __func__, __LINE__);
                goto failure;
            }
        }
        nla_nest_end(msg, ssids);
    }
    /* Handle Frequencies */
    if (num_freq && freq_list) {
        struct nlattr *freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
        if (freqs == NULL) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] nl message build failure (freq's)\n", __func__, __LINE__);
            goto failure;
        }
        for (i = 0; i < num_freq; i++) {
            if (0 == freq_list[i]) // <-- break the loop if freq is 0
                break;
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] Added scan frequency %u MHz\n", __func__, __LINE__, freq_list[i]);
            if (nla_put_u32(msg, i + 1, freq_list[i])) {
                wifi_hal_stats_error_print("%s:%d: [SCAN] nl message build failure (freq's)\n", __func__, __LINE__);
                goto failure;
            }
        }
        nla_nest_end(msg, freqs);
    }

    /* In case that flags are present, update msg with it */
    if (flags != 0) {
        wifi_hal_stats_dbg_print("%s:%d: [SCAN] set SCAN flags (0x%x)\n", __func__, __LINE__, flags);
        if (nla_put_u32(msg, NL80211_ATTR_SCAN_FLAGS, flags)) {
            wifi_hal_stats_error_print("%s:%d: [SCAN] nl message build failure (flags)\n", __func__, __LINE__);
            goto failure;
        }
    }

    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] TRIGGER_SCAN command failed: ret=%d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return -1;
    }
    wifi_hal_stats_dbg_print("%s:%d: [SCAN] scan started successfully\n", __func__, __LINE__);
    return 0;

failure:
    nlmsg_free(msg);
    return -1;
}
#if 0
static int bss_info_handler(struct nl_msg *msg, void *arg)
{
    return NL_SKIP;
}
#endif

//  ========= scan results parser ===============

// MXL vendor-specific attribute
#define NO_NL80211_BSS_NOISE

struct parse_ies_data {
    unsigned char *ie;
    int ielen;
};

#if 0
static const unsigned char ms_oui[3] = { 0x00, 0x50, 0xf2 };
#endif

// - helper macro for copying string
#define _COPY(out,s)   ({ \
    int res = wifi_strcpy(out, sizeof(out), s); \
    if (res) wifi_hal_error_print("%s:%d: string copying error!\n", __func__, __LINE__); \
    res; \
})

// - helper macro for adding string to a comma-separated list
#define _APPEND(out,s) ({ \
    int res = str_list_append(out, sizeof(out), s); \
    if (res) wifi_hal_error_print("%s:%d: string adding error!\n", __func__, __LINE__); \
    res; \
})

static void parse_supprates(const uint8_t type, uint8_t len,
                const uint8_t *data,
                const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    int i;
    wifi_bitrate_t rates;

    (void)type;
    (void)ie_buffer;

    for (i = 0; i < len; i++) {
        unsigned r = data[i] & 0x7f;

        if ( r/2 == 11 ) {
            if (bss->oper_freq_band & WIFI_FREQUENCY_2_4_BAND) {
                bss->supp_standards |= WIFI_80211_VARIANT_B;
                bss->oper_standards = WIFI_80211_VARIANT_B;
            }
        }
        else if ( r/2 == 54 )
        {
            if (bss->oper_freq_band & WIFI_FREQUENCY_5_BAND) {
                bss->supp_standards |= WIFI_80211_VARIANT_A;
                bss->oper_standards = WIFI_80211_VARIANT_A;
            }
            else{
                bss->supp_standards |= WIFI_80211_VARIANT_G;
                bss->oper_standards = WIFI_80211_VARIANT_G;
            }
        }

        rates = 0;
        switch (r) {
            case 1*2:
                rates = WIFI_BITRATE_1MBPS;
                break;
            case 2*2:
                rates = WIFI_BITRATE_2MBPS;
                break;
            case 11: // 5.5
                rates = WIFI_BITRATE_5_5MBPS;
                break;
            case 6*2:
                rates = WIFI_BITRATE_6MBPS;
                break;
            case 9*2:
                rates = WIFI_BITRATE_9MBPS;
                break;
            case 11*2:
                rates = WIFI_BITRATE_11MBPS;
                break;
            case 12*2:
                rates = WIFI_BITRATE_12MBPS;
                break;
            case 18*2:
                rates = WIFI_BITRATE_18MBPS;
                break;
            case 24*2:
                rates = WIFI_BITRATE_24MBPS;
                break;
            case 36*2:
                rates = WIFI_BITRATE_36MBPS;
                break;
            case 48*2:
                rates = WIFI_BITRATE_48MBPS;
                break;
            case 54*2:
                rates = WIFI_BITRATE_54MBPS;
                break;
            default:
                wifi_hal_error_print("%s:%d: [SCAN] Unsupported bitrate value: 0x%02X (%u.%u Mbps)\n",
                    __func__, __LINE__, r, r/2, 5*(r & 1)); 
                break;
        }

        if ( data[i] & 0x80 ) {
            bss->basic_rates |= rates;
        }
        else {
            bss->supp_rates |= rates;
        }
    }
}

static inline wifi_security_modes_t add_wpa(wifi_security_modes_t mode)
{
    switch (mode) {
        case wifi_security_mode_wpa2_personal:
            return wifi_security_mode_wpa_wpa2_personal;
        case wifi_security_mode_wpa2_enterprise:
            return wifi_security_mode_wpa_wpa2_enterprise;
        default:
            return wifi_security_mode_wpa_personal;
    }
}

static inline wifi_security_modes_t add_wpa2(wifi_security_modes_t mode)
{
    switch (mode) {
        case wifi_security_mode_wpa_personal:
            return wifi_security_mode_wpa_wpa2_personal;
        case wifi_security_mode_wpa_enterprise:
            return wifi_security_mode_wpa_wpa2_enterprise;
        default:
            return wifi_security_mode_wpa2_personal;
    }
}

static inline wifi_security_modes_t add_wpa3(wifi_security_modes_t mode)
{
    switch (mode) {
        case wifi_security_mode_wpa3_transition:
            return wifi_security_mode_wpa3_transition;
        case wifi_security_mode_wpa3_enterprise:
            return wifi_security_mode_wpa3_enterprise;
        default:
            return wifi_security_mode_wpa3_personal;
    }
}

static inline wifi_security_modes_t add_wpa_akm(wifi_security_modes_t mode)
{
    switch (mode) {
        case wifi_security_mode_wpa_personal:
            return wifi_security_mode_wpa_personal;
        case wifi_security_mode_wpa_wpa2_personal:
            return wifi_security_mode_wpa_wpa2_personal;
        default:
            return wifi_security_mode_wpa2_personal;
    }
}

static inline wifi_security_modes_t add_enterprise(wifi_security_modes_t mode)
{
    switch (mode) {
        case wifi_security_mode_wpa_enterprise:
            return wifi_security_mode_wpa_enterprise;
        case wifi_security_mode_wpa_wpa2_enterprise:
            return wifi_security_mode_wpa_wpa2_enterprise;
        default:
            return wifi_security_mode_wpa2_enterprise;
    }
}

#define PARSE_CHECK(name, len, min_value) \
    if ((len) == 0) return; \
    else if ((len) < (min_value)) { \
        wifi_hal_error_print("%s:%d: [SCAN] incomplete " name "\n", __func__, __LINE__); \
        return; \
    }

static void parse_rsn(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    uint16_t suite_count = 0;
    uint i;
    bool multiple_suite_count = false;
    (void)type;
    (void)len;
    (void)data;
    (void)ie_buffer;

    // skip version
    len -= 2; data += 2;

    if (len == 0) {
        // - No elements, default: AES, WPA2
        bss->enc_method |= wifi_encryption_aes;
        bss->sec_mode = add_wpa2(bss->sec_mode);
        return;
    }

    if (len < 4) {
        wifi_hal_error_print("%s:%d: [SCAN] incomplete Group Cipher suite\n", __func__, __LINE__);
        return;
    }

    // - group suit type
    {
        uint32_t group_suite_type = WPA_GET_BE32(data);
        switch (group_suite_type) {
            case RSN_CIPHER_SUITE_NONE:
                bss->sec_mode = wifi_security_mode_none;
                bss->enc_method = wifi_encryption_none;
                break;
            case RSN_CIPHER_SUITE_WEP40:
                bss->sec_mode = wifi_security_mode_wep_64;
                bss->enc_method = wifi_encryption_none;
                break;
            case RSN_CIPHER_SUITE_WEP104:
                bss->sec_mode = wifi_security_mode_wep_128;
                bss->enc_method = wifi_encryption_none;
                break;
            case RSN_CIPHER_SUITE_TKIP:
                bss->sec_mode = add_wpa(bss->sec_mode);
                bss->enc_method = wifi_encryption_tkip;
                break;
            case RSN_CIPHER_SUITE_CCMP:
                bss->sec_mode = add_wpa2(bss->sec_mode);
                bss->enc_method = wifi_encryption_aes;
                break;
            case RSN_CIPHER_SUITE_GCMP:
                bss->sec_mode = add_wpa3(bss->sec_mode);
                bss->enc_method = wifi_encryption_aes;
                break;
            default:
                // unsupported combination (can be exteneded in future)
                break;
        }
        len -= 4; data += 4;
    }

    //- Pairwise Cipher suite
    PARSE_CHECK("Pairwise Cipher suite count", len, 2);
    {
        suite_count = WPA_GET_LE16(data);
        len -= 2; data += 2;
    }

    PARSE_CHECK("Pairwise Cipher suite", len, 4*suite_count);
    {
        for (i = 0; i < suite_count; ++i) {
            uint32_t suite_type = WPA_GET_BE32(data);
            switch (suite_type) {
                case RSN_CIPHER_SUITE_NONE:
                    break;
                case RSN_CIPHER_SUITE_WEP40:
                    bss->sec_mode = wifi_security_mode_wep_64;
                    //bss->enc_method = wifi_encryption_none;
                    break;
                case RSN_CIPHER_SUITE_WEP104:
                    bss->sec_mode = wifi_security_mode_wep_128;
                    //bss->enc_method = wifi_encryption_none;
                    break;
                case RSN_CIPHER_SUITE_TKIP:
                    bss->sec_mode = add_wpa(bss->sec_mode);
                    bss->enc_method = wifi_encryption_tkip;
                    break;
                case RSN_CIPHER_SUITE_CCMP:
                    bss->sec_mode = add_wpa2(bss->sec_mode);
                    bss->enc_method = wifi_encryption_aes;
                    break;
                case RSN_CIPHER_SUITE_GCMP:
                    bss->sec_mode = add_wpa3(bss->sec_mode);
                    bss->enc_method = wifi_encryption_aes;
                    break;
                default:
                    // unsupported combination (can be exteneded in future)
                    break;
            }
            len -= 4; data += 4;
        }
    }

    //- AKM suite
    PARSE_CHECK("AKM suite count", len, 2);
    {
        suite_count = WPA_GET_LE16(data);
        len -= 2; data += 2;
        if (suite_count > 1) {
            multiple_suite_count = true;
        }
    }

    PARSE_CHECK("AKM suite", len, 4*suite_count);
    {
        for (i = 0; i < suite_count; ++i) {
            uint32_t suite_type = WPA_GET_BE32(data);
            switch (suite_type) {
                case RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X:
                    if (multiple_suite_count == true) {
                        bss->sec_mode = wifi_security_mode_wpa3_transition;
                    } else {
                        bss->sec_mode = add_wpa_akm(bss->sec_mode);
                    }
                    break;
                case RSN_AUTH_KEY_MGMT_SAE:
                    if (multiple_suite_count == true) {
                        bss->sec_mode = wifi_security_mode_wpa3_transition;
                    } else {
                        bss->sec_mode = add_wpa3(bss->sec_mode);
                    }
                    break;
                case WPA_AUTH_KEY_MGMT_UNSPEC_802_1X:
                case RSN_AUTH_KEY_MGMT_UNSPEC_802_1X:
                    bss->sec_mode = add_enterprise(bss->sec_mode);
                    break;
                default:
                    // unsupported combination (can be exteneded in future)
                    break;
            }
            len -= 4; data += 4;
        }
    }
}

static void parse_secchan_offs(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)data;
    (void)ie_buffer;
    (void)bss;

    /* Placeholder for secondary channel offset parsing */
    /*
    switch (data[0]) {
        case 0:
            // - no secondary
            break;
        case 1:
            // - above CF
            break;
        case 3:
            // - below CF
            break;
    }
    */
}

static void parse_ht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    /* Std 802.11-2020 9.4.2.55.2 */
    if (data[0] & (BIT(1))) {
        bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_40MHZ;
    }
}

static void parse_ht_op(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    /* TODO: data[0] contains channel number.
    * Should we use it instead of calculation from bss[NL80211_BSS_FREQUENCY]? */

    switch (data[1] & 0x3) {
        case 0:
            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_20MHZ;
            break;
        case 1:
            // - Above central freq
            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_40MHZ;
            break;
        case 3:
            // - Below central freq
            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_40MHZ;
            break;
    }

    bss->supp_standards |= WIFI_80211_VARIANT_N;
    bss->oper_standards = WIFI_80211_VARIANT_N;
}

static void parse_tim(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    bss->dtim_period = (unsigned int) data[1];
}

static void parse_vht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    bss->supp_chan_bw |= (WIFI_CHANNELBANDWIDTH_20MHZ | WIFI_CHANNELBANDWIDTH_40MHZ | WIFI_CHANNELBANDWIDTH_80MHZ);

    /* Std 802.11-2020 9.4.2.157.2 */
    if (data[0] & (BIT(2)|BIT(3))) {
        bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_160MHZ;
    }
}

static void parse_vht_oper(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    switch (data[0]) {
        case 0:
            break;

        case 1:
            if (data[2]) {
                bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_160MHZ;
            }
            else {
                bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_80MHZ;
            }
            break;

        case 2:
            /* See standard */
            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_160MHZ;
            break;

        case 3:
            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_80_80MHZ;
            break;

        default:
            wifi_hal_error_print("%s:%d: [SCAN] Illegal value: %u\n", __func__, __LINE__, data[0]);
            break;
    }

    if (bss->oper_freq_band & WIFI_FREQUENCY_5_BAND) {
        bss->supp_standards |= WIFI_80211_VARIANT_AC;
        bss->oper_standards = WIFI_80211_VARIANT_AC;
    }
}

static void parse_he_capa(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    uint8_t he_supported_chan_width_set;

    (void)type;
    (void)ie_buffer;

    if (len <= 7) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] length of he capabilities elem is %hhu <= 7\n", __func__, __LINE__, len);
        return;
    }

    /* [0] = elem_id ; [1-6] = MAC capab ; [7-17] = PHY capab
    * PHY_capab[0] = 1 BIT resv + 7 BITs for Supported Channel Width Set */
    he_supported_chan_width_set = data[7] >> 1;

    bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_20MHZ;

    /* B0 indicates support for a 40 MHz channel width in 2.4GHz */
    if ((bss->oper_freq_band & WIFI_FREQUENCY_2_4_BAND) && (he_supported_chan_width_set & BIT(0))) {
        bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_40MHZ;
    }

    /* B1 indicates support for a 40 MHz and 80 MHz channel width in 5GHz */
    if ((bss->oper_freq_band & WIFI_FREQUENCY_5_BAND) && (he_supported_chan_width_set & BIT(1))) {
        bss->supp_chan_bw |= (WIFI_CHANNELBANDWIDTH_40MHZ | WIFI_CHANNELBANDWIDTH_80MHZ);
    }

    /* B2 indicates support for a 160 MHz channel width in 5GHz
    * B3 indicates support for a 160/80+80 MHz channel width in 5GHz */
    if ((bss->oper_freq_band & WIFI_FREQUENCY_5_BAND) && (he_supported_chan_width_set & (BIT(2) | BIT(3)))) {
        bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_160MHZ;
    }

    bss->supp_standards |= WIFI_80211_VARIANT_AX;
    bss->oper_standards = WIFI_80211_VARIANT_AX;
}

static void parse_he_oper(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)ie_buffer;

    if (len <= 4) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] length of he capabilities elem is %hhu <= 4\n", __func__, __LINE__, len);
        return;
    }

    /* [0] = elem_id ; [1-3] = HE Oper Params ; [4-4] = BSS color; [5-6] = MCS NSS; [7-9] VHT oper info;
    * HE_Oper_Params.bits[14] = VHT Oper Info Present boolean */
    if ((bss->oper_freq_band & WIFI_FREQUENCY_5_BAND) && (data[2] & BIT(6))) {
        if (len > 9) {
            data += 7;

            switch (data[0])
            {
                case 0:
                    break;
                /* Set to 1 for 80 MHz, 160 MHz or 80+80 MHz BSS bandwidth */
                case 1:
                    if (data[2]) {
                        int center_freq_seg0 = data[1];
                        int center_freq_seg1 = data[2];

                        if (abs(center_freq_seg1 - center_freq_seg0) == 16)
                            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_160MHZ;
                        else
                            bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_80_80MHZ;
                    } else {
                        bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_80MHZ;
                    }
                    break;

                /* Set to 2 for 160 MHz BSS bandwidth (deprecated) */
                case 2:
                    bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_160MHZ;
                    break;

                /* Set to 3 for non-contiguous 80+80 MHz BSS bandwidth (deprecated) */
                case 3:
                    bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_80_80MHZ;
                    break;

                default:
                    wifi_hal_stats_error_print("%s:%d: [SCAN] illegal 'Values in the range 4 to 255 are reserved.'\n", __func__, __LINE__);
            }
        } else
            wifi_hal_stats_error_print("%s:%d: [SCAN] VHT oper info present bit is on, by len is %hu\n", __func__, __LINE__, len);
    }

    bss->supp_standards |= WIFI_80211_VARIANT_AX;
    bss->oper_standards = WIFI_80211_VARIANT_AX;
}

#ifdef CONFIG_IEEE80211BE
static void parse_eht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    uint8_t eht_phy_bits_0_7;

    (void)type;
    (void)ie_buffer;

    if (len <= 3) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] length of eht capabilities elem is %hhu <= 3\n", __func__, __LINE__, len);
        return;
    }

    /* [0] = elem_id ; [1-2] = MAC capab ; [3-11] = PHY capab */
    eht_phy_bits_0_7 = data[3];

    /* B1 indicates support for a 320 MHz channel width in 6GHz */
    if ((bss->oper_freq_band & WIFI_FREQUENCY_6_BAND) && (eht_phy_bits_0_7 & BIT(1))) {
        bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_320MHZ;
    }

    bss->supp_standards |= WIFI_80211_VARIANT_BE;
    bss->oper_standards = WIFI_80211_VARIANT_BE;
}
#endif /* CONFIG_IEEE80211BE */

static void parse_bss_load(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)ie_buffer;

    bss->chan_utilization = ((unsigned)data[2] * 100) / 255;
}

static void parse_extension_tag(const uint8_t type, uint8_t len, const uint8_t *data,
                const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    if (len == 0) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] length of extension elem is 0\n", __func__, __LINE__);
        return;
    }

    wifi_hal_stats_dbg_print("%s:%d: [SCAN] Extension TagNumber=%d\n", __func__, __LINE__, data[0]);

    switch (data[0]) {
        case WLAN_EID_EXT_HE_CAPABILITIES:
            parse_he_capa(type, len, data, ie_buffer, bss);
            break;
        case WLAN_EID_EXT_HE_OPERATION:
            parse_he_oper(type, len, data, ie_buffer, bss);
            break;
#ifdef CONFIG_IEEE80211BE
        case WLAN_EID_EXT_EHT_CAPABILITIES:
            parse_eht_capa(type, len, data, ie_buffer, bss);
            break;
#endif /* CONFIG_IEEE80211BE */
        default:
            break;
    }
}

static void parse_ssid(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)ie_buffer;

    memset(bss->ssid, 0, sizeof(bss->ssid));
    if (len > sizeof(bss->ssid)-1) len = sizeof(bss->ssid)-1; // - reserve 1 byte for zero char
    memcpy(bss->ssid, data, len);
}

struct ie_parse {
    const char *name;
    void (*parser)(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss);
    uint8_t minlen, maxlen;
    uint8_t flags;
};

static void parse_ie(const struct ie_parse *p, const uint8_t type, uint8_t len,
            const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    if (!p->parser) {
        /* wifi_hal_error_print("%s:%d: [SCAN] no parser!\n", __func__, __LINE__); */
        return;
    }

    if (len < p->minlen || len > p->maxlen) {
        wifi_hal_error_print("%s:%d: [SCAN] Elem %u: length %u doesn't match 'min' and 'max' len criterion: [%u:%u]\n", __func__, __LINE__,
            type, len, p->minlen, p->maxlen);
        return;
    }

    p->parser(type, len, data, ie_buffer, bss);
}

enum parse_ie_type {
    PARSE_SCAN,
    PARSE_LINK,
};

static const struct ie_parse ie_parsers[] = {
    [WLAN_EID_SSID]           = { "SSID", parse_ssid, 0, 32, BIT(PARSE_SCAN) | BIT(PARSE_LINK), },
    [WLAN_EID_SUPP_RATES]     = { "Supported rates", parse_supprates, 0, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_TIM]            = { "TIM", parse_tim, 4, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_BSS_LOAD]       = { "BSS Load", parse_bss_load, 5, 5, BIT(PARSE_SCAN), },
    [WLAN_EID_HT_CAP]         = { "HT capabilities", parse_ht_capa, 26, 26, BIT(PARSE_SCAN), },
    [WLAN_EID_HT_OPERATION]   = { "HT operation", parse_ht_op, 22, 22, BIT(PARSE_SCAN), },
    [WLAN_EID_VHT_CAP]        = { "VHT capabilities", parse_vht_capa, 12, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_VHT_OPERATION]  = { "VHT operation", parse_vht_oper, 5, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_RSN]            = { "RSN", parse_rsn, 2, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_EXT_SUPP_RATES] = { "Extended supported rates", parse_supprates, 0, 255, BIT(PARSE_SCAN), },
    [WLAN_EID_SECONDARY_CHANNEL_OFFSET] = { "Secondary Channel Offset", parse_secchan_offs, 1, 1, BIT(PARSE_SCAN), },
    [WLAN_EID_EXTENSION]      = { "Extension Tag", parse_extension_tag, 0, 255, BIT(PARSE_SCAN), },
};

#if 0
static void parse_wifi_wpa(const uint8_t type, uint8_t len, const uint8_t *data,
            const struct parse_ies_data *ie_buffer, wifi_bss_info_t *bss)
{
    (void)type;
    (void)len;
    (void)data;
    (void)ie_buffer;

    // - append TKIP
    bss->enc_method |= wifi_encryption_tkip;
    // - append WPA
    bss->sec_mode = (bss->sec_mode == wifi_security_mode_wpa2_personal)
        ? wifi_security_mode_wpa_wpa2_personal
        : wifi_security_mode_wpa_personal;
}

static const struct ie_parse wifi_parsers[] = {
    [1] = { "WPA", parse_wifi_wpa, 2, 255, BIT(PARSE_SCAN), }
};
#endif

static void parse_vendor(unsigned char len, unsigned char *data)
{
    (void)len;
    (void)data;
#if 0
    if (len < 3) {
        return;
    }

    if (len >= 4 && memcmp(data, ms_oui, 3) == 0) {
        if (data[3] < ARRAY_SIZE(wifi_parsers) &&
            wifi_parsers[data[3]].name &&
            wifi_parsers[data[3]].flags) {
            return;
        }
        return;
    }
#endif
}

static void parse_ies(unsigned char *ie, int ielen, wifi_bss_info_t *bss)
{
    struct parse_ies_data ie_buffer = {
        .ie = ie,
        .ielen = ielen };

    /* Set initial values, needed in case its legacy mode AP with no HT, VHT or HE IEs present */
    bss->supp_chan_bw |= WIFI_CHANNELBANDWIDTH_20MHZ;
    bss->oper_chan_bw = WIFI_CHANNELBANDWIDTH_20MHZ;

    while (ielen >= 2 && ielen >= ie[1]) {
        uint16_t elem_id = (uint16_t)ie[0];

        if (elem_id < ARRAY_SIZE(ie_parsers) &&
            ie_parsers[elem_id].name &&
            ie_parsers[elem_id].flags ) {
            parse_ie(&ie_parsers[elem_id], elem_id, ie[1], ie + 2, &ie_buffer, bss);
        } else if (ie[0] == WLAN_EID_VENDOR_SPECIFIC /* vendor */) {
            parse_vendor(ie[1], ie + 2);
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
}

// ==========================================

static int scan_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh;
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_BSSID] = { .type = NLA_UNSPEC },
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { .type = NLA_UNSPEC },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { .type = NLA_UNSPEC },
        [NL80211_BSS_PARENT_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_PARENT_BSSID] = { .type = NLA_UNSPEC },
        [NL80211_BSS_LAST_SEEN_BOOTTIME] = { .type = NLA_U64 },
#ifndef NO_NL80211_BSS_NOISE
        [NL80211_BSS_NOISE] = { .type = NLA_U8 },
#endif
    };

    mac_address_t   bssid;
    mac_addr_str_t  bssid_str = {0};
    wifi_vap_info_t *vap;
    ieee80211_tlv_t *rsn_ie = NULL;
    ieee80211_tlv_t *ie = NULL, *ie_ssid = NULL;
    signed int len;
    unsigned short ie_ssid_len;
    const char *key = NULL;
    wifi_bss_info_t* scan_info_ap = NULL;
    ssid_t          ssid = {0};

    interface = (wifi_interface_info_t *)arg;
    vap = &interface->vap_info;

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_BSS] == NULL) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] bss attribute not present\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) != 0) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] nested bss attribute not present\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (bss[NL80211_BSS_BSSID] != NULL) {
        memcpy(bssid, nla_data(bss[NL80211_BSS_BSSID]), sizeof(mac_address_t));
        key = to_mac_str(bssid, bssid_str);
    } else {
        // wifi_hal_dbg_print("%s:%d: [SCAN] BSSID not found\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        wifi_hal_stats_dbg_print("[SCAN] BSSID: %s, IE LEN %d\n", bssid_str, len);
        if (len > 512) {
            wifi_hal_stats_error_print("[Wrong NL SCAN output] BSSID: %s, IE LEN %d\n", bssid_str, len);
            return NL_SKIP;
        }
    } else {
        ie = NULL;
        len = 0;
        // wifi_hal_dbg_print("%s:%d: [SCAN] BSS info for BSSID:%s not found\n", __func__, __LINE__, key);
        return NL_SKIP;
    }

    if (get_ie_by_eid(WLAN_EID_SSID, (unsigned char *)ie, len, (unsigned char **)&ie_ssid, &ie_ssid_len) == true) {
        size_t ssid_len = ie_ssid_len - sizeof(ieee80211_tlv_t);
        if (ssid_len > sizeof(ssid_t)-1) ssid_len = sizeof(ssid_t)-1;
        memcpy(ssid, ie_ssid->value, ssid_len);
    }

    // - create separate AP info entry for wifi_getNeighboringWiFiStatus().
    //   The scan_info_ap_map contains all SSID's including hidden (with empty SSID name)
    scan_info_ap = (wifi_bss_info_t *)calloc(1, sizeof(wifi_bss_info_t));
    if (!scan_info_ap) {
        wifi_hal_stats_error_print("%s:%d: [SCAN] memory allocation error!\n", __func__, __LINE__);
        return NL_SKIP;
    }

    // - reset security mode
    scan_info_ap->sec_mode = wifi_security_mode_none;

    // - update BSSID and SSID in AP scan results
    memcpy(scan_info_ap->bssid, bssid, sizeof(mac_address_t));
    _COPY(scan_info_ap->ssid, ssid);

    // - freq / channel / band
    if (bss[NL80211_BSS_FREQUENCY]) {
        uint freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        scan_info_ap->freq = freq;

        if ( freq >= 5955 ) {
            scan_info_ap->oper_freq_band = WIFI_FREQUENCY_6_BAND;
        }
        else if( freq >= 5180 ) {
            scan_info_ap->oper_freq_band = WIFI_FREQUENCY_5_BAND;
        }
        else {
            scan_info_ap->oper_freq_band = WIFI_FREQUENCY_2_4_BAND;
        }
    }

    // - beacon interval
    if (bss[NL80211_BSS_BEACON_INTERVAL]) {
        uint beacon_int = nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
        scan_info_ap->beacon_int = beacon_int;
    }

    // - capabillities
    if (bss[NL80211_BSS_CAPABILITY]) {
        ushort caps = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
        scan_info_ap->caps = caps;

        if (caps & WLAN_CAPABILITY_PRIVACY) {
            if ((scan_info_ap->sec_mode == wifi_security_mode_none) || (scan_info_ap->sec_mode == 0)) {
                /* - update sec_mode only uf it wasn't already set
                   - set sec_mode to WEP_64.
                     In fact, we should end up returning the string "WEP" without the details.
                     If detailed information about the WEP encryption type is requested, it can be added later.
                */
                scan_info_ap->sec_mode = wifi_security_mode_wep_64;
            }
        }
    }

    // - RSSI
    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        int rssi = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
        rssi /= 100;
        scan_info_ap->rssi = rssi;
    }
    else if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
        int rssi = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
        scan_info_ap->rssi = rssi;
    }

#ifndef NO_NL80211_BSS_NOISE
    wifi_hal_stats_dbg_print("noise attribute: %p\n", bss[NL80211_BSS_NOISE]);
    // - noise
    if (bss[NL80211_BSS_NOISE]) {
        uint8_t noise = nla_get_u8(bss[NL80211_BSS_NOISE]);
        scan_info_ap->noise = noise;
        wifi_hal_stats_dbg_print("noise: %d\n", noise);
    }
#else
    // wifi_hal_dbg_print("WARNING: NL80211_BSS_NOISE is not defined! Need to update header nl80211.h\n");
#endif

    // - ies
    if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        parse_ies(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
            nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]), scan_info_ap);
    }
    else {
        if (bss[NL80211_BSS_BEACON_IES]) {
            parse_ies(nla_data(bss[NL80211_BSS_BEACON_IES]),
                nla_len(bss[NL80211_BSS_BEACON_IES]), scan_info_ap);
        }
    }

    if (vap->vap_mode == wifi_vap_mode_sta) {
        if (strcmp(scan_info_ap->ssid, vap->u.sta_info.ssid) == 0) {
            wifi_hal_stats_dbg_print("%s:%d: [SCAN] found backhaul bssid:%s rssi:%d on freq:%d for ssid:%s\n", __func__, __LINE__,
                        to_mac_str(bssid, bssid_str), scan_info_ap->rssi, scan_info_ap->freq, scan_info_ap->ssid);
            memcpy(vap->u.sta_info.bssid, bssid, sizeof(bssid_t));
#ifdef CONFIG_WIFI_EMULATOR
            if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
                interface->ie_len = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
                interface->ie = (unsigned char *)malloc(interface->ie_len);
                if (interface->ie != NULL) {
                    memset(interface->ie, 0, interface->ie_len);
                    memcpy(interface->ie, nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]), interface->ie_len);
                }
            }
            if (bss[NL80211_BSS_BEACON_IES]) {
                interface->beacon_ie_len = nla_len(bss[NL80211_BSS_BEACON_IES]);
                interface->beacon_ie = (unsigned char *)malloc(interface->beacon_ie_len);
                if (interface->beacon_ie != NULL) {
                    memset(interface->beacon_ie, 0, interface->beacon_ie_len);
                    memcpy(interface->beacon_ie, nla_data(bss[NL80211_BSS_BEACON_IES]), interface->beacon_ie_len);
                }
            }
#endif
        }
    }

    if (ie != NULL) {
        // wifi_hal_dbg_print("[SCAN] RSN FOUND\n");
        rsn_ie = (ieee80211_tlv_t *)get_ie((unsigned char*)ie, len, WLAN_EID_RSN);

        if (rsn_ie != NULL) {
            scan_info_ap->ie_len = rsn_ie->length + 2;
            os_memcpy(scan_info_ap->ie, rsn_ie, scan_info_ap->ie_len);
        } else {
            // wifi_hal_dbg_print("[SCAN] RSN NOT FOUND\n");
        }
    }

    // - create or update the scan info in 'scan_info_map'
    if (ssid[0] != '\0') {
        wifi_bss_info_t *scan_info = NULL;
        pthread_mutex_lock(&interface->scan_info_mutex);
        scan_info = hash_map_get(interface->scan_info_map, key);
        if (scan_info == NULL) {
            scan_info = (wifi_bss_info_t *)calloc(1, sizeof(wifi_bss_info_t));
            if (scan_info == NULL) {
                pthread_mutex_unlock(&interface->scan_info_mutex);
                free(scan_info_ap);
                wifi_hal_stats_error_print("%s:%d: [SCAN] memory allocation error!\n", __func__, __LINE__);
                return NL_SKIP;
            }

            if (hash_map_put(interface->scan_info_map, strdup(key), scan_info)) {
                pthread_mutex_unlock(&interface->scan_info_mutex);
                free(scan_info);
                free(scan_info_ap);
                wifi_hal_stats_error_print("%s:%d: [SCAN] map adding error!\n", __func__, __LINE__);
                return NL_SKIP;
            }
        }
        // - copy full info
        *scan_info = *scan_info_ap;
        pthread_mutex_unlock(&interface->scan_info_mutex);
    }

    // - add AP info into AP map under AP mutex
    pthread_mutex_lock(&interface->scan_info_ap_mutex);
    if (hash_map_put(interface->scan_info_ap_map[0], strdup(key), scan_info_ap)) {
        pthread_mutex_unlock(&interface->scan_info_ap_mutex);
        wifi_hal_stats_error_print("%s:%d: map adding error!\n", __func__, __LINE__);
        free(scan_info_ap);
        return NL_SKIP;
    }
    pthread_mutex_unlock(&interface->scan_info_ap_mutex);

    // wifi_hal_dbg_print("%s:%d: [SCAN] bssid:%s, ssid:%s\n", __func__, __LINE__, bssid_str, l_ssid);
    return NL_SKIP;
}


static int beacon_info_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    return NL_SKIP;
}

int nl80211_update_beacon_params(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    int ret;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, NLM_F_DUMP, NL80211_CMD_GET_BEACON)) == NULL) {
        return -1;
    }

    ret = nl80211_send_and_recv(msg, beacon_info_handler, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: beacon get command failed: %d (%s)\n", __func__, __LINE__, ret, strerror(-ret));

    return -1;
}

static int nl80211_send_frame_cmd(wifi_interface_info_t *interface,
                                  unsigned int freq,
                                  const u8 *buf, size_t buf_len,
                                  int save_cookie, int no_ack,
                                  const u16 *csa_offs,
                                  size_t csa_offs_len)
{
    struct nl_msg *msg;
    u64 cookie;
    int ret = -1;

    wpa_printf(MSG_MSGDUMP, "nl80211: CMD_FRAME freq=%u no_ack=%d \n", freq, no_ack);
    wpa_hexdump(MSG_MSGDUMP, "CMD_FRAME", buf, buf_len);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_FRAME)) ||
        (freq && nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq)) ||
        (no_ack && nla_put_flag(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK)) ||
        (csa_offs && nla_put(msg, NL80211_ATTR_CSA_C_OFFSETS_TX,
                             csa_offs_len * sizeof(u16), csa_offs)) ||
        nla_put(msg, NL80211_ATTR_FRAME, buf_len, buf)) {
        goto fail;
    }

    cookie = 0;
    ret = nl80211_send_and_recv(msg, cookie_handler, &cookie, NULL, NULL);
    msg = NULL;
    if (ret) {
        wifi_hal_info_print("nl80211: Frame command failed: ret=%d (%s) (freq=%u )\n",
                           ret, strerror(-ret), freq);
    } else {
        //wifi_hal_dbg_print("nl80211: Frame TX command accepted%s; "
        //"cookie 0x%llx\n", no_ack ? " (no ACK)" : "",
        //(long long unsigned int) cookie);
    }

    fail:
    nlmsg_free(msg);
    return ret;
}

static int wifi_sta_remove(wifi_interface_info_t *interface,
    const u8 *addr, int deauth, u16 reason_code)
{
    struct nl_msg *msg;
    mac_addr_str_t src_mac_str, dst_mac_str;
    int ret;

    wifi_hal_info_print("%s:%d: interface:%s send %s from:%s to:%s reason:%d\n", __func__, __LINE__,
        interface->name, deauth ? "deauth" : "disassoc", to_mac_str(interface->mac, src_mac_str),
        to_mac_str(addr, dst_mac_str), reason_code);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
            NL80211_CMD_DEL_STATION)) ||
            nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr) ||
            (deauth == 0 &&
            nla_put_u8(msg, NL80211_ATTR_MGMT_SUBTYPE,
            WLAN_FC_STYPE_DISASSOC)) ||
            (deauth == 1 &&
            nla_put_u8(msg, NL80211_ATTR_MGMT_SUBTYPE,
            WLAN_FC_STYPE_DEAUTH)) ||
            (reason_code &&
            nla_put_u16(msg, NL80211_ATTR_REASON_CODE, reason_code))) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: failed to sent deauth/disassoc, error:%d (%s)\n", __func__,
            __LINE__, ret, strerror(-ret));
    }

    if (ret == -ENOENT) {
        return 0;
    }
    return ret;
}

int wifi_drv_set_4addr_mode(void *priv, const char *bridge_ifname, int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_send_external_auth_status(void *priv, struct external_auth *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_update_connection_params(
    void *priv, struct wpa_driver_associate_params *params,
    enum wpa_drv_update_connect_params_mask mask)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#if defined(CONFIG_HW_CAPABILITIES) || defined(CMXB7_PORT) || defined(VNTXER5_PORT)
int wifi_drv_get_ext_capab(void *priv, enum wpa_driver_if_type type,
                 const u8 **ext_capa, const u8 **ext_capa_mask,
                 unsigned int *ext_capa_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_driver_data_t *drv;
    enum nl80211_iftype nlmode;
    unsigned int i;

    if (!ext_capa || !ext_capa_mask || !ext_capa_len) {
        return -1;
    }

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    drv = &radio->driver_data;

    nlmode = wpa_driver_nl80211_if_type(type);

    /* By default, use the per-radio values */
    *ext_capa = drv->extended_capa;
    *ext_capa_mask = drv->extended_capa_mask;
    *ext_capa_len = drv->extended_capa_len;

    /* Replace the default value if a per-interface type value exists */
    for (i = 0; i < drv->num_iface_ext_capa; i++) {
        if (nlmode == drv->iface_ext_capa[i].iftype) {
            *ext_capa = drv->iface_ext_capa[i].ext_capa;
            *ext_capa_mask = drv->iface_ext_capa[i].ext_capa_mask;
            *ext_capa_len = drv->iface_ext_capa[i].ext_capa_len;
            break;
        }
    }
    return 0;
}

#if HOSTAPD_VERSION >= 211
#ifdef CONFIG_IEEE80211BE
static int wifi_drv_get_mld_capab(void *priv, enum wpa_driver_if_type type,
                                 u16 *eml_capa, u16 *mld_capa_and_ops)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_driver_data_t *drv;
    enum nl80211_iftype nlmode;
    unsigned int i;

    if (!eml_capa || !mld_capa_and_ops) {
        return -1;
    }

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    drv = &radio->driver_data;

    nlmode = wpa_driver_nl80211_if_type(type);

    /* By default, set to UNSPECIFIED */
    *eml_capa = drv->iface_ext_capa[NL80211_IFTYPE_UNSPECIFIED].eml_capa;
    *mld_capa_and_ops = drv->iface_ext_capa[NL80211_IFTYPE_UNSPECIFIED].mld_capa_and_ops;

    /* Replace the default value if a per-interface type value exists */
    for (i = 0; i < drv->num_iface_ext_capa; i++) {
        if (nlmode == drv->iface_ext_capa[i].iftype) {
            *eml_capa = drv->iface_ext_capa[i].eml_capa;
            *mld_capa_and_ops = drv->iface_ext_capa[i].mld_capa_and_ops;
            break;
        }
    }

    wifi_hal_dbg_print("%s:%d: eml_capa: 0x%x, mld_capa_and_ops: 0x%x\n", __func__, __LINE__,
        *eml_capa, *mld_capa_and_ops);

    return 0;
}
#endif /* CONFIG_IEEE80211BE */
#endif /* HOSTAPD_VERSION >= 211 */
#endif /* CONFIG_HW_CAPABILITIES || CMXB7_PORT || VNTXER5_PORT */

int wifi_drv_configure_data_frame_filters(void *priv, u32 filter_flags)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_ignore_assoc_disallow(void *priv, int ignore_disallow)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_bss_transition_status_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

unsigned int wifi_drv_get_ifindex(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_del_ts(void *priv, u8 tsid, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_add_ts(void *priv, u8 tsid, const u8 *addr, u8 user_priority, u16 admitted_time)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_set_net_param(void *priv, enum drv_br_net_param param, unsigned int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_port_set_attr(void *priv, enum drv_br_port_attr attr, unsigned int val)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_delete_ip_neigh(void *priv, u8 version, const u8 *ipaddr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_br_add_ip_neigh(void *priv, u8 version,
                      const u8 *ipaddr, int prefixlen,
                      const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_mac_addr(void *priv, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_wowlan(void *priv, const struct wowlan_triggers *triggers)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_qos_map(void *priv, const u8 *qos_map_set, u8 qos_map_set_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#ifdef CONFIG_VENDOR_COMMANDS
static int vendor_reply_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *nl_vendor_reply, *nl;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wpabuf *buf = arg;
    int rem;

    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    if (!buf) {
        return NL_SKIP;
    }

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);
    nl_vendor_reply = tb[NL80211_ATTR_VENDOR_DATA];

    if (!nl_vendor_reply) {
        return NL_SKIP;
    }

    if ((size_t) nla_len(nl_vendor_reply) > wpabuf_tailroom(buf)) {
        wpa_printf(MSG_INFO, "nl80211: Vendor command: insufficient buffer space for reply");
        return NL_SKIP;
    }

    nla_for_each_nested(nl, nl_vendor_reply, rem) {
        wpabuf_put_data(buf, nla_data(nl), nla_len(nl));
    }

    return NL_SKIP;

}
#endif //CONFIG_VENDOR_COMMANDS

#if HOSTAPD_VERSION >= 210 //2.10

#ifdef CONFIG_VENDOR_COMMANDS
static int vendor_ltq_reply_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *nl_vendor_reply;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wpabuf *buf = arg;

    //wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    if (!buf) {
        return NL_SKIP;
    }

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0), NULL);
    nl_vendor_reply = tb[NL80211_ATTR_VENDOR_DATA];

    if (!nl_vendor_reply) {
        return NL_SKIP;
    }

    if ((size_t) nla_len(nl_vendor_reply) > wpabuf_tailroom(buf)) {
        wpa_printf(MSG_INFO, "nl80211: Vendor command: insufficient buffer space for reply");
        wifi_hal_error_print("%s:%d: nl80211: Vendor command: insufficient buffer space for reply\n", __func__, __LINE__);
        return NL_SKIP;
    }

    wpabuf_put_data(buf, nla_data(nl_vendor_reply), nla_len(nl_vendor_reply));

    return NL_SKIP;
}
#endif //CONFIG_VENDOR_COMMANDS

int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
    unsigned int subcmd, const u8 *data,
    size_t data_len, enum nested_attr nested_attr_flag, struct wpabuf *buf)
{
#ifdef CONFIG_VENDOR_COMMANDS
    int nla_flag;
    struct nl_msg *msg;
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;

    //wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if (nested_attr_flag == NESTED_ATTR_USED) {
        nla_flag = NLA_F_NESTED;
    }
    else if (nested_attr_flag == NESTED_ATTR_UNSPECIFIED) {/* &&
        is_cmd_with_nested_attrs(vendor_id, subcmd) */
        nla_flag = NLA_F_NESTED;
    }
    else {
        nla_flag = 0;
    }

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_VENDOR)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendor_id) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd) ||
        (data && nla_put(msg, nla_flag | NL80211_ATTR_VENDOR_DATA, data_len, data)))
    {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    if (OUI_LTQ == vendor_id) {
        return nl80211_send_and_recv(msg, vendor_ltq_reply_handler, buf, NULL, NULL);
    }
    else {
        return nl80211_send_and_recv(msg, vendor_reply_handler, buf, NULL, NULL);
    }
#endif //CONFIG_VENDOR_COMMANDS

    return 0;
}
#else
int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
                  unsigned int subcmd, const u8 *data,
                  size_t data_len, struct wpabuf *buf)
{
#ifdef CONFIG_VENDOR_COMMANDS
    struct nl_msg *msg;
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_VENDOR)) == NULL) {
        wifi_hal_dbg_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, vendor_id) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd) ||
        (data && nla_put(msg, NL80211_ATTR_VENDOR_DATA, data_len, data)))
    {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    return nl80211_send_and_recv(msg, vendor_reply_handler, buf, NULL, NULL);
#endif //CONFIG_VENDOR_COMMANDS

    return 0;

}
#endif

int wifi_drv_switch_channel(void *priv, struct csa_settings *settings)
{
    struct nl_msg *msg;
    struct nlattr *beacon_csa;
    int ret = -1;
    int csa_off_len = 0;
    int i;
    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_info_print("%s:%d: channel switch request (cs_count=%u block_tx=%u freq=%d width=%d cf1=%d cf2=%d)\n",
        __func__, __LINE__, settings->cs_count, settings->block_tx, settings->freq_params.freq,
        settings->freq_params.bandwidth, settings->freq_params.center_freq1, settings->freq_params.center_freq2);

    if (settings->counter_offset_beacon[0] && !settings->counter_offset_beacon[1]) {
        csa_off_len = 1;
    } else if (settings->counter_offset_beacon[1] && !settings->counter_offset_beacon[0]) {
        csa_off_len = 1;
        settings->counter_offset_beacon[0] = settings->counter_offset_beacon[1];
        settings->counter_offset_presp[0] = settings->counter_offset_presp[1];
    } else if (settings->counter_offset_beacon[1] && settings->counter_offset_beacon[0]) {
        csa_off_len = 2;
    } else {
        wifi_hal_error_print("%s:%d: No CSA counters provided", __func__, __LINE__);
        return -1;
    }

    if (!settings->beacon_csa.tail) {
        wifi_hal_error_print("%s:%d: beacon_csa.tail is null", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i < csa_off_len; i++) {
        u16 csa_c_off_bcn = settings->counter_offset_beacon[i];
        u16 csa_c_off_presp = settings->counter_offset_presp[i];

        if (settings->beacon_csa.tail_len <= csa_c_off_bcn) {
            wifi_hal_error_print("%s:%d: beacon_csa.tail_len=%zu csa_c_off_bcn=%d\n", __func__,
                __LINE__, settings->beacon_csa.tail_len, csa_c_off_bcn);
            return -1;
        }

        if (settings->beacon_csa.tail[csa_c_off_bcn] != settings->cs_count) {
            wifi_hal_error_print("%s:%d: beacon_csa.tail[csa_c_off_bcn]=%d settings->cs_count=%d\n",
                __func__, __LINE__, settings->beacon_csa.tail[csa_c_off_bcn], settings->cs_count);
            return -1;
        }

        if (settings->beacon_csa.probe_resp) {
            if (settings->beacon_csa.probe_resp_len <= csa_c_off_presp) {             
                wifi_hal_error_print("%s:%d: beacon_csa.probe_resp_len=%zu csa_c_off_presp=%d\n",
                    __func__, __LINE__, settings->beacon_csa.probe_resp_len, csa_c_off_presp);
                return -1;
            }

            if (settings->beacon_csa.probe_resp[csa_c_off_presp] != settings->cs_count) {
                wifi_hal_error_print("%s:%d: beacon_csa.probe_resp[csa_c_off_presp]=%d "
                    "settings->cs_count=%d\n", __func__, __LINE__,
                    settings->beacon_csa.probe_resp[csa_c_off_presp], settings->cs_count);
                return -1;
            }
        }
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
        NL80211_CMD_CHANNEL_SWITCH))) {
        wifi_hal_error_print("%s:%d: failed to create CMD_CHANNEL_SWITCH\n", __func__, __LINE__);
        goto error;
    }

    if (nla_put_u32(msg, NL80211_ATTR_CH_SWITCH_COUNT, settings->cs_count)) {
        wifi_hal_error_print("%s:%d: failed to put CH_SWITCH_COUNT\n", __func__, __LINE__);
        goto error;
    }

    if ((ret = nl80211_put_freq_params(msg, &settings->freq_params))) {
        wifi_hal_error_print("%s:%d: failed to put freq params, ret=%d\n", __func__, __LINE__, ret);
        goto error;
    }

    if (settings->block_tx && nla_put_flag(msg, NL80211_ATTR_CH_SWITCH_BLOCK_TX)) {
        wifi_hal_error_print("%s:%d: failed to put CH_SWITCH_BLOCK_TX\n", __func__, __LINE__);
        goto error;
    }

    /* beacon_after params */
    ret = set_beacon_data(msg, &settings->beacon_after);
    if (ret) {
        wifi_hal_error_print("%s:%d: failed to set beacon data, ret=%d\n", __func__, __LINE__, ret);
        goto error;
    }

    /* beacon_csa params */
    beacon_csa = nla_nest_start(msg, NL80211_ATTR_CSA_IES);
    if (!beacon_csa) {
        wifi_hal_error_print("%s:%d: failed to create ATTR_CSA_IES\n", __func__, __LINE__);
        goto fail;
    }

    ret = set_beacon_data(msg, &settings->beacon_csa);
    if (ret) {
        wifi_hal_error_print("%s:%d: failed to set beacon data, ret=%d\n", __func__, __LINE__, ret);
        goto error;
    }

    if (nla_put(msg, NL80211_ATTR_CSA_C_OFF_BEACON, csa_off_len * sizeof(u16),
        settings->counter_offset_beacon)) {
        wifi_hal_error_print("%s:%d: failed to put CSA_C_OFF_BEACON\n", __func__, __LINE__);
        goto fail;
    }

    if (settings->beacon_csa.probe_resp && nla_put(msg, NL80211_ATTR_CSA_C_OFF_PRESP,
        csa_off_len * sizeof(u16), settings->counter_offset_presp)) {
        wifi_hal_error_print("%s:%d: failed to put CSA_C_OFF_PRESP\n", __func__, __LINE__);
        goto fail;
    }

    nla_nest_end(msg, beacon_csa);

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
    if (settings->freq_params.eht_enabled && (settings->freq_params.freq >= MIN_FREQ_MHZ_6G) && (settings->freq_params.freq <= MAX_FREQ_MHZ_6G)) {
        platform_switch_channel(interface, settings);
        ret = 0;
    } else
#endif
    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_info_print("nl80211: switch_channel failed err=%d (%s)\n", ret, strerror(-ret));
    }
    return ret;

fail:
    ret = -1;
error:
    nlmsg_free(msg);
    wifi_hal_error_print("nl80211: Could not build channel switch request\n");
    return ret;
}

int wifi_drv_status(void *priv, char *buf, size_t buflen)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_survey(void *priv, unsigned int freq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

const u8 * wifi_drv_get_macaddr(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_update_dh_ie(void *priv, const u8 *peer_mac,
                u16 reason_code, const u8 *ie, size_t ie_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_update_ft_ies(void *priv, const u8 *md,
                        const u8 *ies, size_t ies_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#if HOSTAPD_VERSION >= 211
int wifi_drv_stop_ap(void *priv, int link_id)
#else
int wifi_drv_stop_ap(void *priv)
#endif /* HOSTAPD_VERSION >= 211 */
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_start_radar_detection(void *priv, struct hostapd_freq_params *freq)
{
    struct nl_msg *msg;
    int ret = -1;
    wifi_interface_info_t *interface;
    interface = (wifi_interface_info_t *)priv;

    wifi_hal_info_print("%s nl80211: Start radar detection (CAC) %d MHz (ht_enabled=%d, vht_enabled=%d, he_enabled=%d, bandwidth=%d MHz, cf1=%d MHz, cf2=%d MHz)",
             __func__, freq->freq, freq->ht_enabled, freq->vht_enabled, freq->he_enabled,
                         freq->bandwidth, freq->center_freq1, freq->center_freq2);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id,interface, 0, NL80211_CMD_RADAR_DETECT)) ||
        nl80211_put_freq_params(msg, freq) < 0) {
        nlmsg_free(msg);
        wifi_hal_error_print("%s nl80211: Failed to set nl80211 radar msg \n", __FUNCTION__);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s Failed to start radar detection: "
                         "%d (%s) \n", __FUNCTION__, ret, strerror(-ret));
        return -1;
    }

    return 0;
}

int wifi_drv_set_p2p_powersave(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_poll_client(void *priv, const u8 *own_addr, const u8 *addr, int qos)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}


void wifi_drv_set_rekey_info(void *priv, const u8 *kek, size_t kek_len,
                   const u8 *kck, size_t kck_len,
                   const u8 *replay_ctr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_flush_pmkid(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_remove_pmkid(void *priv, struct wpa_pmkid_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_add_pmkid(void *priv, struct wpa_pmkid_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

const char * wifi_drv_get_radio_name(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_param(void *priv, const char *param)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_send_frame(void *priv, const u8 *data, size_t data_len, int encrypt)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_channel_info(void *priv, struct wpa_channel_info *ci)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_signal_poll(void *priv, struct wpa_signal_info *si)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_signal_monitor(void *priv, int threshold, int hysteresis)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_resume(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_deinit_p2p_cli(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_deinit_ap(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_probe_req_report(void *priv, int report)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_cancel_remain_on_channel(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_remain_on_channel(void *priv, unsigned int freq, unsigned int duration)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_send_action_cancel_wait(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

int wifi_drv_send_action(void *priv,
                      unsigned int freq,
                      unsigned int wait_time,
                      const u8 *dst, const u8 *src,
                      const u8 *bssid,
                      const u8 *data, size_t data_len,
                      int no_cck)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)priv;

    int ret = -1;
    unsigned char *buf;
    struct ieee80211_hdr *hdr;
    int off_chan = 1;

    if ((int) freq == interface->u.ap.iface.freq &&
        interface->beacon_set)
    {
        off_chan = 0;
    }

    wifi_hal_dbg_print("%s:%d: nl80211: Send Action frame (ifindex=%d, "
            "freq=%u MHz wait=%d ms no_cck=%d offchanok=%d)",__func__, __LINE__,
            interface->index, freq, wait_time, no_cck, off_chan);

    buf = (unsigned char*) calloc(sizeof(struct ieee80211_hdr) + data_len, sizeof(unsigned char));
    if (buf == NULL)
        return ret;
    memcpy(buf + sizeof(struct ieee80211_hdr), data, data_len);
    hdr = (struct ieee80211_hdr *) buf;
    hdr->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
    memcpy(hdr->addr1, dst, ETH_ALEN);
    memcpy(hdr->addr2, src, ETH_ALEN);
    memcpy(hdr->addr3, bssid, ETH_ALEN);

    int use_cookie = 0;
    int no_ack = 0; // wait for ACK
    uint16_t *csa_offs = NULL;
    size_t csa_offs_len = 0;

    // workaround <--
    // TODO:
    // in case we send off-chan action frame
    // fill csa offset data
    if (off_chan) {
        csa_offs_len = 1;
        csa_offs = (uint16_t*) calloc(csa_offs_len, sizeof(uint16_t));
        if (!csa_offs) {
            free(buf);
            return ret;
        }
        // *csa_offs = <csa offset data>
    }

    ret = nl80211_send_frame_cmd(interface, freq, buf, 24 + data_len,
            use_cookie, no_ack, csa_offs, csa_offs_len);

    free(csa_offs);
    free(buf);

    return ret;
}

static int nl80211_set_channel(wifi_interface_info_t *interface,
                               struct hostapd_freq_params *freq, int set_chan)
{
    struct nl_msg *msg;
    int ret;

    wifi_hal_info_print("nl80211: Set freq %d (ht_enabled=%d vht_enabled=%d, he_enabled=%d, bandwidth=%d MHz, " \
           "cf1=%d MHz, cf2=%d MHz)", freq->freq, freq->ht_enabled, freq->vht_enabled, freq->he_enabled, freq->bandwidth,
           freq->center_freq1, freq->center_freq2);

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, set_chan ? NL80211_CMD_SET_CHANNEL : NL80211_CMD_SET_WIPHY);
    if (!msg || nl80211_put_freq_params(msg, freq) < 0) {
        wifi_hal_error_print("%s:%d nl80211_put_freq_params failed \n", __func__, __LINE__);
        nlmsg_free(msg);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret == 0) {
        interface->u.ap.iface.freq = freq->freq;
        return 0;
    }
    wifi_hal_error_print("nl80211: Failed to set channel (freq=%d): "
                    "%d (%s) \n", freq->freq, ret, strerror(-ret));
    return -1;
}

int wifi_drv_set_freq(void *priv, struct hostapd_freq_params *freq)
{
    wifi_interface_info_t *interface = (wifi_interface_info_t *) priv;
    return nl80211_set_channel(interface, freq, 0);
}

int wifi_drv_read_sta_data(void *priv,
                    struct hostap_sta_driver_data *data,
                    const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#ifdef HOSTAPD_2_11 //2.11
int wifi_drv_send_mlme(void *priv, const u8 *data,
                      size_t data_len,int noack,
                      unsigned int freq, const u16 *csa_offs,
                      size_t csa_offs_len, int no_encrypt,
                      unsigned int wait, int link_id)
#elif HOSTAPD_2_10 //2.10
 int wifi_drv_send_mlme(void *priv, const u8 *data,
                      size_t data_len,int noack,
                      unsigned int freq, const u16 *csa_offs,
                      size_t csa_offs_len, int no_encrypt,
                      unsigned int wait)
#else
 int wifi_drv_send_mlme(void *priv, const u8 *data,
                                          size_t data_len, int noack,
                                          unsigned int freq,
                                          const u16 *csa_offs,
                                          size_t csa_offs_len)
#endif
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt *mgmt;
    u16 fc;
    int use_cookie = 1;
    int res, interface_freq;
    mac_addr_str_t src_mac_str, dst_mac_str;

    char country[8];
    wifi_device_callbacks_t *callbacks;
    callbacks = get_hal_device_callbacks();

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    get_coutry_str_from_code(radio_param->countryCode, country);

    interface_freq = ieee80211_chan_to_freq(country, radio_param->op_class,
          radio_param->channel);


    mgmt = (struct ieee80211_mgmt *) data;
    fc = le_to_host16(mgmt->frame_control);

    if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT) {
        switch (WLAN_FC_GET_STYPE(fc)) {
        case WLAN_FC_STYPE_AUTH:
            wifi_hal_info_print("%s:%d: interface:%s send auth frame from:%s to:%s alg:%d seq:%d "
                                "sc:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, src_mac_str),
                to_mac_str(mgmt->da, dst_mac_str), le_to_host16(mgmt->u.auth.auth_alg),
                le_to_host16(mgmt->u.auth.auth_transaction),
                le_to_host16(mgmt->u.auth.status_code));
            break;
        case WLAN_FC_STYPE_ASSOC_RESP:
            wifi_hal_info_print("%s:%d: interface:%s send assoc resp frame from:%s to:%s cap:0x%x "
                                "aid:%d sc:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, src_mac_str),
                to_mac_str(mgmt->da, dst_mac_str), le_to_host16(mgmt->u.assoc_resp.capab_info),
                le_to_host16(mgmt->u.assoc_resp.aid) & 0x3fff,
                le_to_host16(mgmt->u.assoc_resp.status_code));
            break;
        case WLAN_FC_STYPE_REASSOC_RESP:
            wifi_hal_info_print("%s:%d: interface:%s send reassoc resp frame from:%s to:%s "
                                "cap:0x%x aid:%d sc:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, src_mac_str),
                to_mac_str(mgmt->da, dst_mac_str), le_to_host16(mgmt->u.assoc_resp.capab_info),
                le_to_host16(mgmt->u.assoc_resp.aid) & 0x3fff,
                le_to_host16(mgmt->u.assoc_resp.status_code));
            break;
        case WLAN_FC_STYPE_DISASSOC:
            wifi_hal_info_print("%s:%d: interface:%s send disassoc frame from:%s to:%s sc:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, src_mac_str),
                to_mac_str(mgmt->da, dst_mac_str), le_to_host16(mgmt->u.disassoc.reason_code));
            break;
        case WLAN_FC_STYPE_DEAUTH:
            wifi_hal_info_print("%s:%d: interface:%s send deauth frame from:%s to:%s sc:%d\n",
                __func__, __LINE__, interface->name, to_mac_str(mgmt->sa, src_mac_str),
                to_mac_str(mgmt->da, dst_mac_str), le_to_host16(mgmt->u.deauth.reason_code));
            break;
        }
    }

    if (WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH &&
        mgmt->u.auth.status_code == AP_UNABLE_TO_HANDLE_ADDITIONAL_ASSOCIATIONS &&
        callbacks->max_cli_rejection_cb != NULL) {
        mac_addr_str_t mac_str;
        callbacks->max_cli_rejection_cb(interface->vap_info.vap_index,
            to_mac_str(mgmt->da, mac_str), AP_UNABLE_TO_HANDLE_ADDITIONAL_ASSOCIATIONS);
    }

    //wifi_hal_dbg_print("nl80211: send_mlme - da= %s noack=%d freq=%u fc=0x%x\n",
    //to_mac_str(mgmt->da, mac_str), noack, freq, fc);

    if (drv->device_ap_sme) {
        if (freq == 0) {
            //wifi_hal_dbg_print("nl80211: Use interface freq=%d\n", interface_freq);
            freq = interface_freq;
        }
        goto send_frame_cmd;
    }
#if 0
    if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
          WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH) {
        /*
         * Only one of the authentication frame types is encrypted.
         * In order for static WEP encryption to work properly (i.e.,
         * to not encrypt the frame), we need to tell mac80211 about
         * the frames that must not be encrypted.
         */
        u16 auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
        u16 auth_trans = le_to_host16(mgmt->u.auth.auth_transaction);
    }
#endif
    if (freq == 0) {
        //wifi_hal_dbg_print("nl80211: send_mlme - Use interface freq=%u\n", interface_freq);
        freq = interface_freq;
    }

    if (noack || WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
            WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ACTION)
          use_cookie = 0;
send_frame_cmd:

    //wifi_hal_dbg_print("nl80211: send_mlme -> send_frame_cmd\n");
    res = nl80211_send_frame_cmd(interface, freq, data, data_len,
              use_cookie, noack, csa_offs, csa_offs_len);

    return res;
}


/* The purpose of this function is to allow user send response to auth/assoc
 * requests with specific failure directly without using wpa_supplicant_event.
*/
int wifi_send_response_failure(int ap_index, const u8 *mac, int frame_type, int status_code, int rssi)
{
    int ret = 0;
    wifi_interface_info_t *interface = get_interface_by_vap_index(ap_index);
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);

    switch(frame_type) {
        case WLAN_FC_STYPE_ASSOC_RESP:
#if !defined(PLATFORM_LINUX)
#ifdef HOSTAPD_2_11 //2.11
                /* setting allow_mld_addr_trans to false */
                send_assoc_resp(hapd, NULL, mac, status_code, 0, NULL, 0, rssi, 1, false);
#elif HOSTAPD_2_10 //2.10
                send_assoc_resp(hapd, NULL, mac, status_code, 0, NULL, 0, rssi, 1);
#else
                send_assoc_resp(hapd, NULL, mac, status_code, 0, NULL, 0, rssi);
#endif
#endif
            break;
        case WLAN_FC_STYPE_REASSOC_RESP:
#if !defined(PLATFORM_LINUX)
#ifdef HOSTAPD_2_11 //2.11
                /* setting allow_mld_addr_trans to false */
                send_assoc_resp(hapd, NULL, mac, status_code, 1, NULL, 0, rssi, 1, false);
#elif HOSTAPD_2_10 //2.10
                send_assoc_resp(hapd, NULL, mac, status_code, 1, NULL, 0, rssi, 1);
#else
                send_assoc_resp(hapd, NULL, mac, status_code, 1, NULL, 0, rssi);
#endif
#endif
            break;
        default:
            break;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return ret;
}

/* The purpose of this function is to allow apps to send response to mgmt frames
 * directly if it was blocked in process_mgmt_frames
*/
void wifi_send_wpa_supplicant_event(int ap_index, uint8_t *frame, int len)
{
    union wpa_event_data event;
    wifi_interface_info_t *interface = get_interface_by_vap_index(ap_index);

    os_memset(&event, 0, sizeof(event));
    event.rx_mgmt.frame = (unsigned char *)frame;
    event.rx_mgmt.frame_len = len;
#if HOSTAPD_VERSION >= 211
    event.rx_mgmt.link_id = NL80211_DRV_LINK_ID_NA;
#endif /* HOSTAPD_VERSION >= 211 */
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    wpa_supplicant_event(&interface->u.ap.hapd, EVENT_RX_MGMT, &event);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
}

int wifi_drv_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    //wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt mgmt;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    //radio_param = &radio->oper_param;
    drv = &radio->driver_data;
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_BANANAPI_R4_)
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_disassoc_cbs; i++) {
        if (callbacks->disassoc_cb[i] != NULL) {
            callbacks->disassoc_cb[i](vap->vap_index, to_mac_str(addr, mac_str), 0);
        }
    }
#endif // _PLATFORM_RASPBERRYPI_ || _PLATFORM_BANANAPI_R4_
    if (drv->device_ap_sme) {
        return wifi_sta_remove(interface, addr, 0, reason);
    }

    memset(&mgmt, 0, sizeof(mgmt));
    mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                                        WLAN_FC_STYPE_DISASSOC);
    memcpy(mgmt.da, addr, ETH_ALEN);
    memcpy(mgmt.sa, own_addr, ETH_ALEN);
    memcpy(mgmt.bssid, own_addr, ETH_ALEN);
    mgmt.u.disassoc.reason_code = host_to_le16(reason);
#ifdef HOSTAPD_2_11 //2.11
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0, 0, 0, 0);
#elif HOSTAPD_2_10 //2.10
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0, 0, 0);
#else
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.disassoc), 0, 0, NULL, 0);
#endif
}



int wifi_drv_sta_notify_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_device_callbacks_t *callbacks;
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
        if (callbacks->apDeAuthEvent_cb[i] != NULL) {
            callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(addr, mac_str), reason);
        }
    }

    if (callbacks->steering_event_callback != 0) {
        wifi_steering_event_t steering_evt;

        fill_steering_event_general(&steering_evt, WIFI_STEERING_EVENT_AUTH_FAIL, vap);
        memcpy(steering_evt.data.authFail.client_mac, addr, sizeof(mac_address_t));
        steering_evt.data.authFail.reason = reason;
        steering_evt.data.authFail.bsBlocked = 0;
        steering_evt.data.authFail.bsBlocked = 0;

        wifi_hal_dbg_print("%s:%d: Send Auth Fail steering event\n", __func__, __LINE__);

        callbacks->steering_event_callback(0, &steering_evt);
    }

    return 0;
}

#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason, int link_id)
#else
int wifi_drv_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason)
#endif
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct ieee80211_mgmt mgmt;
    u8 channel;
    int freq;
    char country[8];
    mac_addr_str_t mac_str;

    wifi_hal_dbg_print("%s:%d: Enter %s %d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    get_coutry_str_from_code(radio_param->countryCode, country);

    freq = ieee80211_chan_to_freq(country, radio_param->op_class, radio_param->channel);

    if (ieee80211_freq_to_chan(freq, &channel) ==
          HOSTAPD_MODE_IEEE80211AD) {
        /* Deauthentication is not used in DMG/IEEE 802.11ad;
           * disassociate the STA instead. */
        return wifi_drv_sta_disassoc(priv, own_addr, addr, reason);
    }
#if 0
    //TODO: check if mesh, return
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    for (int i = 0; i < callbacks->num_apDeAuthEvent_cbs; i++) {
        if (callbacks->apDeAuthEvent_cb[i] != NULL) {
            callbacks->apDeAuthEvent_cb[i](vap->vap_index, to_mac_str(addr, mac_str), reason);
        }
    }
#endif
    if (drv->device_ap_sme) {
        return wifi_sta_remove(interface, addr, 1, reason);
    }

    memset(&mgmt, 0, sizeof(mgmt));
    mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
                                        WLAN_FC_STYPE_DEAUTH);
    memcpy(mgmt.da, addr, ETH_ALEN);
    memcpy(mgmt.sa, own_addr, ETH_ALEN);
    memcpy(mgmt.bssid, own_addr, ETH_ALEN);
    mgmt.u.deauth.reason_code = host_to_le16(reason);
    wifi_hal_info_print("%s:%d: Send drv mlme: client mac:%s reason_code:%d\n", __func__, __LINE__, to_mac_str(addr, mac_str), reason);
#ifdef HOSTAPD_2_11 //2.11
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.deauth), 0, 0, NULL, 0, 0, 0, 0);
#elif HOSTAPD_2_10 //2.10
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                                IEEE80211_HDRLEN + sizeof(mgmt.u.deauth), 0, 0, NULL, 0, 0, 0);
#else
    return wifi_drv_send_mlme(priv, (u8 *) &mgmt,
                              IEEE80211_HDRLEN + sizeof(mgmt.u.deauth), 0, 0, NULL, 0);
#endif
    return 0;
}

#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_set_sta_vlan(void *priv, const u8 *addr,
                       const char *ifname, int vlan_id, int link_id)
#else
int wifi_drv_set_sta_vlan(void *priv, const u8 *addr,
                       const char *ifname, int vlan_id)
#endif
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_set_tx_queue_params(void *priv, int queue, int aifs,
                    int cw_min, int cw_max, int burst_time, int link_id)
#else
int wifi_drv_set_tx_queue_params(void *priv, int queue, int aifs,
                    int cw_min, int cw_max, int burst_time)
#endif
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_frag(void *priv, int frag)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_rts(void *priv, int rts)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_clear_stats(void *priv, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int get_sta_inactive_handler (struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct hostap_sta_driver_data *data = arg;
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
        [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb[NL80211_ATTR_STA_INFO]) {
        wifi_hal_dbg_print("%s:%d: sta stats missing!\n", __func__, __LINE__);
        return NL_SKIP;
    }
    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        wifi_hal_dbg_print("%s:%d: failed to parse nested attributes!\n", __func__, __LINE__);
        return NL_SKIP;
    }
    if (stats[NL80211_STA_INFO_INACTIVE_TIME]) {
        data->inactive_msec = nla_get_u32(stats[NL80211_STA_INFO_INACTIVE_TIME]);
        wifi_hal_dbg_print("%s:%d: Inactive time :%ld\n", __func__, __LINE__,data->inactive_msec);
    }
    return NL_SKIP;
}


int wifi_drv_get_inact_sec(void *priv, const u8 *addr)
{
    struct hostap_sta_driver_data data;
    struct nl_msg *msg;
    wifi_interface_info_t *interface;
    int ret = 0;
    mac_addr_str_t mac_str;

    interface = (wifi_interface_info_t *)priv;
    os_memset(&data, 0, sizeof(data));
    data.inactive_msec = (unsigned long) -1;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                                    NL80211_CMD_GET_STATION)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }
    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

    ret = nl80211_send_and_recv(msg, get_sta_inactive_handler, &data, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Station get failed: ret=%d (%s)\n", ret, strerror(-ret));
    }
    if (ret == -ENOENT){
        return -ENOENT;
    }
    if (ret || data.inactive_msec == (unsigned long) -1) {
        return -1;
    }

    char *key = to_mac_str(addr, mac_str);
    bm_sta_list_t *bm_client_info = NULL;
    pthread_mutex_lock(&g_wifi_hal.steering_data_lock);
    bm_client_info = hash_map_get(interface->bm_sta_map, key);
    if (bm_client_info != NULL) {
        bm_client_info->active = get_boot_time_in_sec();
    }
    pthread_mutex_unlock(&g_wifi_hal.steering_data_lock);
    wifi_hal_error_print("Inactivity time for client %s:%ld\n", to_mac_str(addr, mac_str), (data.inactive_msec / 1000));
    return data.inactive_msec / 1000;
}

#if HOSTAPD_VERSION >= 211
int wifi_drv_flush(void *priv, int link_id)
#else
int wifi_drv_flush(void *priv)
#endif /* HOSTAPD_VERSION >= 211 */
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg;
    int ret;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: nl80211: flush -> DEL_STATION %s (all) \n", __func__, __LINE__, interface->name);

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0,
                                    NL80211_CMD_DEL_STATION)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Station flush failed: ret=%d (%s)", ret, strerror(-ret));
    }
    return ret;
}

#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_get_seqnum(const char *iface, void *priv, const u8 *addr, int idx, int link_id, u8 *seq)
#else
int wifi_drv_get_seqnum(const char *iface, void *priv, const u8 *addr, int idx, u8 *seq)
#endif
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;

    msg = nl80211_ifindex_msg(g_wifi_hal.nl80211_id, interface, 0,
                                NL80211_CMD_GET_KEY, if_nametoindex(iface));
    if (!msg ||
        (addr && nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr)) ||
        nla_put_u8(msg, NL80211_ATTR_KEY_IDX, idx)) {

        nlmsg_free(msg);
        return -ENOBUFS;
    }

    memset(seq, 0, 6);

    return nl80211_send_and_recv(msg, get_key_handler, seq, NULL, NULL);
}

int wifi_drv_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
                const char *bridge_ifname, char *ifname_wds)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_set_airtime_weight(void *priv, const u8 *addr, unsigned int weight)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_set_flags(void *priv, const u8 *addr,
                        unsigned int total_flags,
                        unsigned int flags_or,
                        unsigned int flags_and)
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg;
    struct nlattr *flags;
    struct nl80211_sta_flag_update upd;
    mac_addr_str_t mac_str;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_hal_info_print("nl80211: Set STA flags - ifname=%s addr=%s"
          " total_flags=0x%x flags_or=0x%x flags_and=0x%x authorized=%d\n",
          interface->name, to_mac_str(addr, mac_str), total_flags, flags_or, flags_and,
          !!(total_flags & WPA_STA_AUTHORIZED));

    if (!!(total_flags & WPA_STA_AUTHORIZED)) {
        nl80211_read_sta_data(interface, addr);
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_STATION)) ||
          nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
    {
        goto fail;
    }

    /*
     * Backwards compatibility version using NL80211_ATTR_STA_FLAGS. This
     * can be removed eventually.
     */
    flags = nla_nest_start(msg, NL80211_ATTR_STA_FLAGS);
    if (!flags ||
        ((total_flags & WPA_STA_AUTHORIZED) &&
         nla_put_flag(msg, NL80211_STA_FLAG_AUTHORIZED)) ||
        ((total_flags & WPA_STA_WMM) &&
         nla_put_flag(msg, NL80211_STA_FLAG_WME)) ||
        ((total_flags & WPA_STA_SHORT_PREAMBLE) &&
         nla_put_flag(msg, NL80211_STA_FLAG_SHORT_PREAMBLE)) ||
        ((total_flags & WPA_STA_MFP) &&
         nla_put_flag(msg, NL80211_STA_FLAG_MFP)) ||
        ((total_flags & WPA_STA_TDLS_PEER) &&
         nla_put_flag(msg, NL80211_STA_FLAG_TDLS_PEER))) {
        goto fail;
    }

    nla_nest_end(msg, flags);

    os_memset(&upd, 0, sizeof(upd));
    upd.mask = sta_flags_nl80211(flags_or | ~flags_and);
    upd.set = sta_flags_nl80211(flags_or);
    if (nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd)) {
        goto fail;
    }

    return nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
fail:
    nlmsg_free(msg);
    return -ENOBUFS;
}

int nl80211_tx_control_port(wifi_interface_info_t *interface, const u8 *dest,
    u16 proto, const u8 *buf, size_t len, int no_encrypt)
{
    struct nl_msg *msg;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_CONTROL_PORT_FRAME)) == NULL) {
        wifi_hal_dbg_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    if (!msg ||
        nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, proto) ||
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, dest) ||
        nla_put(msg, NL80211_ATTR_FRAME, len, buf) ||
        (no_encrypt &&
        nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT))) {
        nlmsg_free(msg);
        wifi_hal_dbg_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -ENOBUFS;
    }

    return nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
}



#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_hapd_send_eapol(
    void *priv, const u8 *addr, const u8 *data,
    size_t data_len, int encrypt, const u8 *own_addr, u32 flags, int link_id)
#else
int wifi_drv_hapd_send_eapol(
    void *priv, const u8 *addr, const u8 *data,
    size_t data_len, int encrypt, const u8 *own_addr, u32 flags)
#endif
{
    int ret;
    unsigned char buff[2048];
    struct ieee8023_hdr *eth_hdr;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    mac_addr_str_t src_mac_str, dst_mac_str;
    int sock_fd;
    struct sockaddr_ll sockaddr;
    const char *ifname;
#ifdef WIFI_EMULATOR_CHANGE
    static int fd_c = -1;
#endif
    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: interface:%s sending eapol m%d from:%s to:%s replay counter:%d\n",
        __func__, __LINE__, interface->name, is_eapol_m3(data, data_len) ? 3 : 1,
        to_mac_str(own_addr, src_mac_str), to_mac_str(addr, dst_mac_str),
        get_eapol_reply_counter(data, data_len));

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_CONTROL_PORT_FRAME) {
        if ((ret = nl80211_tx_control_port(interface, addr, ETH_P_EAPOL, data, data_len, !encrypt))) {
            wifi_hal_dbg_print("%s:%d: eapol send failed ret=%d \n", __func__, __LINE__,ret);
            return -1;
        }

        return 0;
    }

    eth_hdr = (struct ieee8023_hdr *)buff;
    memcpy(eth_hdr->src, own_addr, sizeof(mac_address_t));
    memcpy(eth_hdr->dest, addr, sizeof(mac_address_t));
    eth_hdr->ethertype = host_to_be16(ETH_P_EAPOL);
    memcpy(buff + sizeof(struct ieee8023_hdr), data, data_len);

#ifdef WIFI_EMULATOR_CHANGE
    if ((access(ONEWIFI_TESTSUITE_TMPFILE, R_OK)) == 0) {
        if (fd_c < 0) {
            fd_c = open("/dev/rdkfmac_dev", O_RDWR);
            if (fd_c < 0) {
                wifi_hal_info_print("%s:%d: failed to open to char dev\n", __func__, __LINE__);
            }
        }
        if (fd_c > 0) {
            unsigned char c_buff[2048];
            unsigned char *t_buff = c_buff;
            unsigned int type = wlan_emu_msg_type_frm80211, ops_type = 0;
            memset(t_buff, 0, 2048);
            memcpy(t_buff, &type, sizeof(unsigned int));
            t_buff += sizeof(unsigned int);

            memcpy(t_buff, &ops_type, sizeof(unsigned int));
            t_buff += sizeof(unsigned int);

            unsigned int len = data_len + sizeof(eapol_qos_info) + sizeof(llc_info);
            memcpy(t_buff, &len, sizeof(unsigned int));
            t_buff += sizeof(unsigned int);

            memcpy(t_buff, eth_hdr->src, ETH_ALEN);
            t_buff += ETH_ALEN;

            memcpy(t_buff, eth_hdr->dest, ETH_ALEN);
            t_buff += ETH_ALEN;

            memcpy(eapol_qos_info+4, eth_hdr->dest, ETH_ALEN);
            memcpy(eapol_qos_info+10, eth_hdr->src, ETH_ALEN);
            memcpy(eapol_qos_info+10+ETH_ALEN, eth_hdr->src, ETH_ALEN);
            memcpy(t_buff, eapol_qos_info, sizeof(eapol_qos_info));
            t_buff += sizeof(eapol_qos_info);

            memcpy(t_buff, llc_info, sizeof(llc_info));
            t_buff += sizeof(llc_info);

            memcpy(t_buff, data, len);

            if (write(fd_c, c_buff, 2048) > 0) {
            //    wifi_hal_dbg_print("%s:%d: write succesful bytes written : %d for EAPOL data\n", __func__, __LINE__, len);
            }
            close(fd_c);
            fd_c = -1;
        }
    }
#endif

    //my_print_hex_dump(data_len + sizeof(struct ieee8023_hdr), buff);
    if ((ret = send((vap->vap_mode == wifi_vap_mode_ap) ? interface->u.ap.br_sock_fd:interface->u.sta.sta_sock_fd,
            buff, data_len + sizeof(struct ieee8023_hdr), flags)) < 0) {
        wifi_hal_error_print("%s:%d: eapol send failed ret=%d\n", __func__, __LINE__,ret);

        if (vap->vap_mode == wifi_vap_mode_ap) {
            if (interface->u.ap.br_sock_fd != 0) {
                close(interface->u.ap.br_sock_fd);
                interface->u.ap.br_sock_fd = 0;
            }
        } else {
            if (interface->u.sta.sta_sock_fd != 0) {
                close(interface->u.sta.sta_sock_fd);
                interface->u.sta.sta_sock_fd = 0;
            }
        }
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));

        if (sock_fd < 0) {
            wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, interface->vap_info.bridge_name);
        } else {
            ifname = (vap->vap_mode == wifi_vap_mode_ap) ? vap->bridge_name:interface->name;

            memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
            sockaddr.sll_family   = AF_PACKET;
            sockaddr.sll_protocol = htons(ETH_P_EAPOL);
            sockaddr.sll_ifindex  = if_nametoindex(ifname);

            if (bind(sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
                wifi_hal_error_print("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
                close(sock_fd);
                return -1;
            } else { 
                if (vap->vap_mode == wifi_vap_mode_ap) {
                    interface->u.ap.br_sock_fd = sock_fd;
                } else {
                    interface->u.sta.sta_sock_fd = sock_fd;
                }
            }
            wifi_hal_info_print("%s:%d: Socket for interface %s reopened successfully.\n", __func__, __LINE__, interface->name);
        }
        return -1;
    }

    return 0;
}

int wifi_drv_sta_remove(void *priv, const u8 *addr)
{
    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)priv;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    return wifi_sta_remove(interface, addr, -1, 0);
}

int wifi_drv_sta_add(void *priv, struct hostapd_sta_add_params *params)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    //wifi_radio_operationParam_t *radio_param;
    wifi_driver_data_t *drv;
    struct nl_msg *msg;
    struct nl80211_sta_flag_update upd;
    mac_addr_str_t mac_str;
    int ret = -ENOBUFS;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    //radio_param = &radio->oper_param;
    drv = &radio->driver_data;

    if ((params->flags & WPA_STA_TDLS_PEER) &&
          !(drv->capa.flags & WPA_DRIVER_FLAGS_TDLS_SUPPORT)) {
        return -EOPNOTSUPP;
    }

#ifdef CONFIG_IEEE80211BE
#ifdef CONFIG_DRIVER_BRCM
    //! WORKAROUND: BRCM cfg80211 does not support NL80211_CMD_NEW_STATION(add_station)
    if (params->mld_link_sta) {
        wifi_hal_dbg_print(
            "%s:%d: WORKAROUND: Replacement Add to Set for the mld_link(id=%d, addr=" MACSTR ")\n",
            __func__, __LINE__, params->mld_link_id, MAC2STR(params->mld_link_addr));

        params->set = 1;
    }
#endif /* CONFIG_DRIVER_BRCM */
#endif /* CONFIG_IEEE80211BE */

    wifi_hal_info_print("%s:%d: %s STA %s\n", __func__, __LINE__, params->set ? "Set" : "Add",
        to_mac_str(params->addr, mac_str));
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, params->set ? NL80211_CMD_SET_STATION :
          NL80211_CMD_NEW_STATION);
    if (!msg || nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr)) {
        goto fail;
    }

    /*
     * Set the below properties only in one of the following cases:
     * 1. New station is added, already associated.
     * 2. Set WPA_STA_TDLS_PEER station.
     * 3. Set an already added unassociated station, if driver supports
     * full AP client state. (Set these properties after station became
     * associated will be rejected by the driver).
     */
    if (!params->set || (params->flags & WPA_STA_TDLS_PEER) ||
          (params->set && FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags) &&
           (params->flags & WPA_STA_ASSOCIATED))) {

        wpa_hexdump(MSG_DEBUG, "  * supported rates",
                    params->supp_rates, params->supp_rates_len);
        wifi_hal_dbg_print("%s:%d: capability=0x%x\n", __func__, __LINE__, params->capability);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
                    params->supp_rates_len, params->supp_rates) ||
            nla_put_u16(msg, NL80211_ATTR_STA_CAPABILITY,
                        params->capability)) {
            goto fail;
        }

        if (params->ht_capabilities) {
            wpa_hexdump(MSG_DEBUG, "  * ht_capabilities",
                        (u8 *) params->ht_capabilities,
                        sizeof(*params->ht_capabilities));
            if (nla_put(msg, NL80211_ATTR_HT_CAPABILITY,
                        sizeof(*params->ht_capabilities),
                        params->ht_capabilities)) {
                goto fail;
            }
        }

        if (params->vht_capabilities) {
            wpa_hexdump(MSG_DEBUG, "  * vht_capabilities",
                        (u8 *) params->vht_capabilities,
                        sizeof(*params->vht_capabilities));
            if (nla_put(msg, NL80211_ATTR_VHT_CAPABILITY,
                        sizeof(*params->vht_capabilities),
                        params->vht_capabilities)) {
                goto fail;
            }
        }
#if defined(CMXB7_PORT) || defined(VNTXER5_PORT)
        if (params->he_capab) {
            wpa_hexdump(MSG_DEBUG, "  * he_capab",
                        params->he_capab, params->he_capab_len);
            if (nla_put(msg, NL80211_ATTR_HE_CAPABILITY,
                        params->he_capab_len, params->he_capab)) {
                goto fail;
            }
        }
#endif
#ifdef CONFIG_IEEE80211BE
        if (params->eht_capab) {
            wpa_hexdump(MSG_DEBUG, "  * eht_capab", params->eht_capab,
                        params->eht_capab_len);
            if (nla_put(msg, NL80211_ATTR_EHT_CAPABILITY, params->eht_capab_len,
                        params->eht_capab)) {
                goto fail;
            }
        }
#endif /* CONFIG_IEEE80211BE */
        if (params->ext_capab) {
            wpa_hexdump(MSG_DEBUG, "  * ext_capab",
                        params->ext_capab, params->ext_capab_len);
            if (nla_put(msg, NL80211_ATTR_STA_EXT_CAPABILITY,
                        params->ext_capab_len, params->ext_capab)) {
                goto fail;
            }
        }

        if ( nla_put_u8(msg, NL80211_ATTR_STA_SUPPORT_P2P_PS,
                        params->support_p2p_ps ?
                        NL80211_P2P_PS_SUPPORTED :
                        NL80211_P2P_PS_UNSUPPORTED)) {
            goto fail;
        }
    }
    if (!params->set) {
        if (params->aid) {
            wifi_hal_dbg_print("%s:%d: aid=%u\n", __func__, __LINE__, params->aid);
            if (nla_put_u16(msg, NL80211_ATTR_STA_AID, params->aid)) {
                goto fail;
            }
        } else {
            /*
                   * cfg80211 validates that AID is non-zero, so we have
                   * to make this a non-zero value for the TDLS case where
                   * a dummy STA entry is used for now and for a station
                   * that is still not associated.
                   */
            wifi_hal_dbg_print("%s:%d: aid=1 (%s workaround)\n", __func__, __LINE__,
                (params->flags & WPA_STA_TDLS_PEER) ? "TDLS" : "UNASSOC_STA");
            if (nla_put_u16(msg, NL80211_ATTR_STA_AID, 1)) {
                goto fail;
            }
        }
        wifi_hal_dbg_print("%s:%d: listen_interval=%u\n", __func__, __LINE__,
            params->listen_interval);
        if (nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
                        params->listen_interval)) {
            goto fail;
        }
    } else if (params->aid && (params->flags & WPA_STA_TDLS_PEER)) {
        wifi_hal_dbg_print("%s:%d: peer_aid=%u\n", __func__, __LINE__, params->aid);
        if (nla_put_u16(msg, NL80211_ATTR_PEER_AID, params->aid)) {
            goto fail;
        }
    } else if (FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags) &&
               (params->flags & WPA_STA_ASSOCIATED)) {
        wifi_hal_dbg_print("%s:%d: aid=%u\n", __func__, __LINE__, params->aid);
        wifi_hal_dbg_print("%s:%d: listen_interval=%u\n", __func__, __LINE__,
            params->listen_interval);
        if (nla_put_u16(msg, NL80211_ATTR_STA_AID, params->aid) ||
            nla_put_u16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
                        params->listen_interval)) {
            goto fail;
        }
    }

    if (params->vht_opmode_enabled) {
        wifi_hal_dbg_print("%s:%d: pmode=%u\n", __func__, __LINE__, params->vht_opmode);
        if (nla_put_u8(msg, NL80211_ATTR_OPMODE_NOTIF,
                       params->vht_opmode)) {
            goto fail;
        }
    }

    if (params->supp_channels) {
        wpa_hexdump(MSG_DEBUG, "  * supported channels",
                    params->supp_channels, params->supp_channels_len);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_CHANNELS,
                    params->supp_channels_len, params->supp_channels)) {
            goto fail;
        }
    }

    if (params->supp_oper_classes) {
        wpa_hexdump(MSG_DEBUG, "  * supported operating classes",
                    params->supp_oper_classes,
                    params->supp_oper_classes_len);
        if (nla_put(msg, NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES,
                    params->supp_oper_classes_len,
                    params->supp_oper_classes)) {
            goto fail;
        }
    }

    os_memset(&upd, 0, sizeof(upd));
    upd.set = sta_flags_nl80211(params->flags);
    upd.mask = upd.set | sta_flags_nl80211(params->flags_mask);

    /*
     * If the driver doesn't support full AP client state, ignore ASSOC/AUTH
     * flags, as nl80211 driver moves a new station, by default, into
     * associated state.
     *
     * On the other hand, if the driver supports that feature and the
     * station is added in unauthenticated state, set the
     * authenticated/associated bits in the mask to prevent moving this
     * station to associated state before it is actually associated.
     *
     * This is irrelevant for mesh mode where the station is added to the
     * driver as authenticated already, and ASSOCIATED isn't part of the
     * nl80211 API.
     */
    if (!FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags)) {
        wifi_hal_dbg_print(
            "%s:%d: Ignore ASSOC/AUTH flags since driver doesn't support full AP client state\n",
            __func__, __LINE__);
        upd.mask &= ~(BIT(NL80211_STA_FLAG_ASSOCIATED) |
                      BIT(NL80211_STA_FLAG_AUTHENTICATED));
    } else if (!params->set &&
               !(params->flags & WPA_STA_TDLS_PEER)) {
        if (!(params->flags & WPA_STA_AUTHENTICATED))
          upd.mask |= BIT(NL80211_STA_FLAG_AUTHENTICATED);
        if (!(params->flags & WPA_STA_ASSOCIATED))
          upd.mask |= BIT(NL80211_STA_FLAG_ASSOCIATED);
    }

    wifi_hal_dbg_print("%s:%d: flags set=0x%x mask=0x%x\n", __func__, __LINE__, upd.set, upd.mask);
    if (nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd)) {
        goto fail;
    }

    if ((!params->set || (params->flags & WPA_STA_TDLS_PEER) ||
          FULL_AP_CLIENT_STATE_SUPP(drv->capa.flags)) &&
          (params->flags & WPA_STA_WMM)) {
        struct nlattr *wme = nla_nest_start(msg, NL80211_ATTR_STA_WME);

        wifi_hal_dbg_print("%s:%d: qosinfo=0x%x\n", __func__, __LINE__, params->qosinfo);
        if (!wme ||
            nla_put_u8(msg, NL80211_STA_WME_UAPSD_QUEUES,
                       params->qosinfo & WMM_QOSINFO_STA_AC_MASK) ||
            nla_put_u8(msg, NL80211_STA_WME_MAX_SP,
                       (params->qosinfo >> WMM_QOSINFO_STA_SP_SHIFT) &
                       WMM_QOSINFO_STA_SP_MASK)) {
            goto fail;
        }
        nla_nest_end(msg, wme);
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    msg = NULL;
    if (ret) {
        wifi_hal_info_print("%s:%d: failed to send NL80211_CMD_%s_STATION, "
                            "result: %d (%s)\n",
            __func__, __LINE__, params->set ? "SET" : "NEW", ret, strerror(-ret));
    }
    if (ret == -EEXIST) {
        ret = 0;
    }
fail:
    nlmsg_free(msg);
    return ret;
}

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
static int cw2ecw(unsigned int cw)
{
    int bit;

    if (cw == 0) {
        return 0;
    }

    for (bit = 1; cw != 1; bit++) {
        cw >>= 1;
    }

    return bit;
}

static void phy_info_freq(struct hostapd_hw_modes *mode,
              struct hostapd_channel_data *chan,
              struct nlattr *tb_freq[])
{
    u8 channel;

    os_memset(chan, 0, sizeof(*chan));
    chan->freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
    chan->flag = 0;
    chan->allowed_bw = ~0;
    chan->dfs_cac_ms = 0;

    if (ieee80211_freq_to_chan(chan->freq, &channel) != NUM_HOSTAPD_MODES) {
        chan->chan = channel;
    } else {
        wpa_printf(MSG_DEBUG,
               "nl80211: No channel number found for frequency %u MHz",
               chan->freq);
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
        chan->flag |= HOSTAPD_CHAN_DISABLED;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR]) {
        chan->flag |= HOSTAPD_CHAN_NO_IR;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR]) {
        chan->flag |= HOSTAPD_CHAN_RADAR;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_INDOOR_ONLY]) {
        chan->flag |= HOSTAPD_CHAN_INDOOR_ONLY;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_GO_CONCURRENT]) {
        chan->flag |= HOSTAPD_CHAN_GO_CONCURRENT;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_10MHZ]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_10;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_20MHZ]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_20;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40P;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_40M;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_80MHZ]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_80;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_NO_160MHZ]) {
        chan->allowed_bw &= ~HOSTAPD_CHAN_WIDTH_160;
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
        enum nl80211_dfs_state state =
            nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

        switch (state) {
        case NL80211_DFS_USABLE:
            chan->flag |= HOSTAPD_CHAN_DFS_USABLE;
            break;
        case NL80211_DFS_AVAILABLE:
            chan->flag |= HOSTAPD_CHAN_DFS_AVAILABLE;
            break;
        case NL80211_DFS_UNAVAILABLE:
            chan->flag |= HOSTAPD_CHAN_DFS_UNAVAILABLE;
            break;
        }
    }

    if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]) {
        chan->dfs_cac_ms = nla_get_u32(
            tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]);
    }

    chan->wmm_rules_valid = 0;
    if (tb_freq[NL80211_FREQUENCY_ATTR_WMM]) {
        static struct nla_policy wmm_policy[NL80211_WMMR_MAX + 1] = {
            [NL80211_WMMR_CW_MIN] = { .type = NLA_U16 },
            [NL80211_WMMR_CW_MAX] = { .type = NLA_U16 },
            [NL80211_WMMR_AIFSN] = { .type = NLA_U8 },
            [NL80211_WMMR_TXOP] = { .type = NLA_U16 },
        };
        static const u8 wmm_map[4] = {
            [NL80211_AC_BE] = WMM_AC_BE,
            [NL80211_AC_BK] = WMM_AC_BK,
            [NL80211_AC_VI] = WMM_AC_VI,
            [NL80211_AC_VO] = WMM_AC_VO,
        };
        struct nlattr *nl_wmm;
        struct nlattr *tb_wmm[NL80211_WMMR_MAX + 1];
        int rem_wmm, ac, count = 0;

        nla_for_each_nested(nl_wmm, tb_freq[NL80211_FREQUENCY_ATTR_WMM],
                    rem_wmm) {
            if (nla_parse_nested(tb_wmm, NL80211_WMMR_MAX, nl_wmm,
                         wmm_policy)) {
                wpa_printf(MSG_DEBUG,
                       "nl80211: Failed to parse WMM rules attribute");
                return;
            }
            if (!tb_wmm[NL80211_WMMR_CW_MIN] ||
                !tb_wmm[NL80211_WMMR_CW_MAX] ||
                !tb_wmm[NL80211_WMMR_AIFSN] ||
                !tb_wmm[NL80211_WMMR_TXOP]) {
                wpa_printf(MSG_DEBUG,
                       "nl80211: Channel is missing WMM rule attribute");
                return;
            }
            ac = nl_wmm->nla_type;
            if ((unsigned int) ac >= ARRAY_SIZE(wmm_map)) {
                wpa_printf(MSG_DEBUG,
                       "nl80211: Invalid AC value %d", ac);
                return;
            }

            ac = wmm_map[ac];
            chan->wmm_rules[ac].min_cwmin =
                cw2ecw(nla_get_u16(
                           tb_wmm[NL80211_WMMR_CW_MIN]));
            chan->wmm_rules[ac].min_cwmax =
                cw2ecw(nla_get_u16(
                           tb_wmm[NL80211_WMMR_CW_MAX]));
            chan->wmm_rules[ac].min_aifs =
                nla_get_u8(tb_wmm[NL80211_WMMR_AIFSN]);
            chan->wmm_rules[ac].max_txop =
                nla_get_u16(tb_wmm[NL80211_WMMR_TXOP]) / 32;
            count++;
        }

        /* Set valid flag if all the AC rules are present */
        if (count == WMM_AC_NUM) {
            chan->wmm_rules_valid = 1;
        }
    }
}

static int phy_info_freqs_get_hw_features(struct phy_info_arg *phy_info,
              struct hostapd_hw_modes *mode, struct nlattr *tb)
{
    static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
        [NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_DFS_STATE] = { .type = NLA_U32 },
        [NL80211_FREQUENCY_ATTR_NO_10MHZ] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_20MHZ] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_HT40_PLUS] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_HT40_MINUS] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_80MHZ] = { .type = NLA_FLAG },
        [NL80211_FREQUENCY_ATTR_NO_160MHZ] = { .type = NLA_FLAG },
    };
    int new_channels = 0;
    struct hostapd_channel_data *channel;
    struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *nl_freq;
    int rem_freq, idx;

    if (tb == NULL) {
        return NL_OK;
    }

    nla_for_each_nested(nl_freq, tb, rem_freq) {
        nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
              nla_data(nl_freq), nla_len(nl_freq), freq_policy);

        if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ]) {
            continue;
        }

        new_channels++;
    }

    channel = os_realloc_array(mode->channels,
                   mode->num_channels + new_channels,
                   sizeof(struct hostapd_channel_data));

    if (!channel) {
        return NL_STOP;
    }

    mode->channels = channel;
    mode->num_channels += new_channels;

    idx = phy_info->last_chan_idx;

    nla_for_each_nested(nl_freq, tb, rem_freq) {
        nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
              nla_data(nl_freq), nla_len(nl_freq), freq_policy);

        if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ]) {
            continue;
        }

        phy_info_freq(mode, &mode->channels[idx], tb_freq);
        idx++;
    }
    phy_info->last_chan_idx = idx;

    return NL_OK;
}

static int phy_info_edmg_capa(struct hostapd_hw_modes *mode,
                  struct nlattr *bw_config,
                  struct nlattr *channels)
{
    if (!bw_config || !channels) {
        return NL_OK;
    }

    mode->edmg.bw_config = nla_get_u8(bw_config);
    mode->edmg.channels = nla_get_u8(channels);

    if (!mode->edmg.channels || !mode->edmg.bw_config) {
        return NL_STOP;
    }

    return NL_OK;
}

static void nl80211_dump_chan_list(struct hostapd_hw_modes *modes,
                   u16 num_modes)
{
    int i;

    if (!modes) {
        return;
    }

    for (i = 0; i < num_modes; i++) {
        struct hostapd_hw_modes *mode = &modes[i];
        char str[1000];
        char *pos = str;
        char *end = pos + sizeof(str);
        int j, res;

        for (j = 0; j < mode->num_channels; j++) {
            struct hostapd_channel_data *chan = &mode->channels[j];

            res = os_snprintf(pos, end - pos, " %d%s%s%s",
                      chan->freq,
                      (chan->flag & HOSTAPD_CHAN_DISABLED) ?
                      "[DISABLED]" : "",
                      (chan->flag & HOSTAPD_CHAN_NO_IR) ?
                      "[NO_IR]" : "",
                      (chan->flag & HOSTAPD_CHAN_RADAR) ?
                      "[RADAR]" : "");
            if (os_snprintf_error(end - pos, res)) {
                break;
            }

            pos += res;
        }

        *pos = '\0';
    }
}

static struct hostapd_hw_modes *
wpa_driver_nl80211_postprocess_modes(struct hostapd_hw_modes *modes,
                     u16 *num_modes)
{
    u16 m;
    struct hostapd_hw_modes *mode11g = NULL, *nmodes, *mode;
    int i, mode11g_idx = -1;

    /* heuristic to set up modes */
    for (m = 0; m < *num_modes; m++) {
        if (!modes[m].num_channels) {
            continue;
        }

        if (modes[m].channels[0].freq < 2000) {
            modes[m].num_channels = 0;
            continue;
        } else if (modes[m].channels[0].freq < 4000) {
            modes[m].mode = HOSTAPD_MODE_IEEE80211B;
            for (i = 0; i < modes[m].num_rates; i++) {
                if (modes[m].rates[i] > 200) {
                    modes[m].mode = HOSTAPD_MODE_IEEE80211G;
                    break;
                }
            }
        } else if (modes[m].channels[0].freq > 50000) {
            modes[m].mode = HOSTAPD_MODE_IEEE80211AD;
        } else {
            modes[m].mode = HOSTAPD_MODE_IEEE80211A;
        }
    }

    /* Remove unsupported bands */
    m = 0;
    while (m < *num_modes) {
        if (modes[m].mode == NUM_HOSTAPD_MODES) {
            wpa_printf(MSG_DEBUG,
                   "nl80211: Remove unsupported mode");
            os_free(modes[m].channels);
            os_free(modes[m].rates);
            if (m + 1 < *num_modes)
                os_memmove(&modes[m], &modes[m + 1],
                       sizeof(struct hostapd_hw_modes) *
                       (*num_modes - (m + 1)));
            (*num_modes)--;
            continue;
        }
        m++;
    }

    /* If only 802.11g mode is included, use it to construct matching
     * 802.11b mode data. */

    for (m = 0; m < *num_modes; m++) {
        if (modes[m].mode == HOSTAPD_MODE_IEEE80211B) {
            return modes; /* 802.11b already included */
        }

        if (modes[m].mode == HOSTAPD_MODE_IEEE80211G) {
            mode11g_idx = m;
        }
    }

    if (mode11g_idx < 0) {
        return modes; /* 2.4 GHz band not supported at all */
    }

    nmodes = os_realloc_array(modes, *num_modes + 1, sizeof(*nmodes));
    if (nmodes == NULL) {
        return modes; /* Could not add 802.11b mode */
    }

    mode = &nmodes[*num_modes];
    os_memset(mode, 0, sizeof(*mode));
    (*num_modes)++;
    modes = nmodes;

    mode->mode = HOSTAPD_MODE_IEEE80211B;

    mode11g = &modes[mode11g_idx];
    mode->num_channels = mode11g->num_channels;
    mode->channels = os_memdup(mode11g->channels,
                   mode11g->num_channels *
                   sizeof(struct hostapd_channel_data));
    if (mode->channels == NULL) {
        (*num_modes)--;
        return modes; /* Could not add 802.11b mode */
    }

    mode->num_rates = 0;
    mode->rates = os_malloc(4 * sizeof(int));
    if (mode->rates == NULL) {
        os_free(mode->channels);
        (*num_modes)--;
        return modes; /* Could not add 802.11b mode */
    }

    for (i = 0; i < mode11g->num_rates; i++) {
        if (mode11g->rates[i] != 10 && mode11g->rates[i] != 20 &&
             mode11g->rates[i] != 55 && mode11g->rates[i] != 110) {
            continue;
        }

        mode->rates[mode->num_rates] = mode11g->rates[i];
        mode->num_rates++;
        if (mode->num_rates == 4)
            break;
    }

    if (mode->num_rates == 0) {
        os_free(mode->channels);
        os_free(mode->rates);
        (*num_modes)--;
        return modes; /* No 802.11b rates */
    }

    wpa_printf(MSG_DEBUG, "nl80211: Added 802.11b mode based on 802.11g "
           "information");

    return modes;
}

static int phy_info_get_hw_features_band(struct phy_info_arg *phy_info, struct nlattr *nl_band)
{
    struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
    struct hostapd_hw_modes *mode;
#if HOSTAPD_VERSION >= 210 //2.10
    int ret;
#endif

    if (phy_info->last_mode != nl_band->nla_type) {
        mode = os_realloc_array(phy_info->modes,
                    *phy_info->num_modes + 1,
                    sizeof(*mode));
        if (!mode) {
            phy_info->failed = 1;
            return NL_STOP;
        }
        phy_info->modes = mode;

        mode = &phy_info->modes[*(phy_info->num_modes)];
        os_memset(mode, 0, sizeof(*mode));
        mode->mode = NUM_HOSTAPD_MODES;
        mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN |
            HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;

        /*
         * Unsupported VHT MCS stream is defined as value 3, so the VHT
         * MCS RX/TX map must be initialized with 0xffff to mark all 8
         * possible streams as unsupported. This will be overridden if
         * driver advertises VHT support.
         */
        mode->vht_mcs_set[0] = 0xff;
        mode->vht_mcs_set[1] = 0xff;
        mode->vht_mcs_set[4] = 0xff;
        mode->vht_mcs_set[5] = 0xff;

        *(phy_info->num_modes) += 1;
        phy_info->last_mode = nl_band->nla_type;
        phy_info->last_chan_idx = 0;
    } else {
        //mode = &radio->hw_modes[band];
        mode = &phy_info->modes[*(phy_info->num_modes) - 1];
    }

    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
          nla_len(nl_band), NULL);

    phy_info_ht_capa(mode, tb_band[NL80211_BAND_ATTR_HT_CAPA],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
             tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
             tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
    phy_info_vht_capa(mode, tb_band[NL80211_BAND_ATTR_VHT_CAPA],
              tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
#if HOSTAPD_VERSION >= 210 //2.10
    ret = phy_info_edmg_capa(mode,
                 tb_band[NL80211_BAND_ATTR_EDMG_BW_CONFIG],
                 tb_band[NL80211_BAND_ATTR_EDMG_CHANNELS]);

    if (ret == NL_OK) {
        ret = phy_info_freqs_get_hw_features(phy_info, mode,
                     tb_band[NL80211_BAND_ATTR_FREQS]);
    }

    if (ret == NL_OK) {
        ret = phy_info_rates_get_hw_features(mode, tb_band[NL80211_BAND_ATTR_RATES]);
    }

    if (ret != NL_OK) {
        phy_info->failed = 1;
        return ret;
    }

    if (tb_band[NL80211_BAND_ATTR_IFTYPE_DATA]) {
        struct nlattr *nl_iftype;
        int rem_band;

        nla_for_each_nested(nl_iftype,
                    tb_band[NL80211_BAND_ATTR_IFTYPE_DATA],
                    rem_band) {
            ret = phy_info_iftype(mode, nl_iftype);
            if (ret != NL_OK) {
                return ret;
            }
        }
    }
#endif
    return NL_OK;
}

static int phy_info_get_hw_feature_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct phy_info_arg *phy_info = arg;
    struct nlattr *nl_band;
    int rem_band;

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
        return NL_SKIP;
    }

    nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band)
    {
        int res = phy_info_get_hw_features_band(phy_info, nl_band);
        if (res != NL_OK) {
            return res;
        }
    }

    return NL_SKIP;
}

static void nl80211_set_ht40_mode(struct hostapd_hw_modes *mode, int start,
                  int end)
{
    int c;

    for (c = 0; c < mode->num_channels; c++) {
        struct hostapd_channel_data *chan = &mode->channels[c];
        if (chan->freq - 10 >= start && chan->freq + 10 <= end) {
            chan->flag |= HOSTAPD_CHAN_HT40;
        }
    }
}

static void nl80211_reg_rule_ht40(u32 start, u32 end,
                  struct phy_info_arg *results)
{
    u16 m;

    for (m = 0; m < *results->num_modes; m++) {
        if (!(results->modes[m].ht_capab &
              HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET)) {
            continue;
        }
        nl80211_set_ht40_mode(&results->modes[m], start, end);
    }
}

static void nl80211_set_dfs_domain(enum nl80211_dfs_regions region,
                   u8 *dfs_domain)
{
    if (region == NL80211_DFS_FCC) {
        *dfs_domain = HOSTAPD_DFS_REGION_FCC;
    } else if (region == NL80211_DFS_ETSI) {
        *dfs_domain = HOSTAPD_DFS_REGION_ETSI;
    } else if (region == NL80211_DFS_JP) {
        *dfs_domain = HOSTAPD_DFS_REGION_JP;
    } else {
        *dfs_domain = 0;
    }
}

static const char * dfs_domain_name(enum nl80211_dfs_regions region)
{
    switch (region) {
    case NL80211_DFS_UNSET:
        return "DFS-UNSET";
    case NL80211_DFS_FCC:
        return "DFS-FCC";
    case NL80211_DFS_ETSI:
        return "DFS-ETSI";
    case NL80211_DFS_JP:
        return "DFS-JP";
    default:
        return "DFS-invalid";
    }
}

static void nl80211_reg_rule_max_eirp(u32 start, u32 end, u32 max_eirp,
                      struct phy_info_arg *results)
{
    u16 m;

    for (m = 0; m < *results->num_modes; m++) {
        int c;
        struct hostapd_hw_modes *mode = &results->modes[m];

        for (c = 0; c < mode->num_channels; c++) {
            struct hostapd_channel_data *chan = &mode->channels[c];
            if ((u32) chan->freq - 10 >= start &&
                 (u32) chan->freq + 10 <= end) {
                chan->max_tx_power = max_eirp;
            }
        }
    }
}

static void nl80211_set_ht40_mode_sec(struct hostapd_hw_modes *mode, int start,
                      int end)
{
    int c;

    for (c = 0; c < mode->num_channels; c++) {
        struct hostapd_channel_data *chan = &mode->channels[c];
        if (!(chan->flag & HOSTAPD_CHAN_HT40)) {
            continue;
        }
        if (chan->freq - 30 >= start && chan->freq - 10 <= end) {
            chan->flag |= HOSTAPD_CHAN_HT40MINUS;
        }
        if (chan->freq + 10 >= start && chan->freq + 30 <= end) {
            chan->flag |= HOSTAPD_CHAN_HT40PLUS;
        }
    }
}

static void nl80211_reg_rule_sec(struct nlattr *tb[],
                 struct phy_info_arg *results)
{
    u32 start, end, max_bw;
    u16 m;

    if (tb[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
         tb[NL80211_ATTR_FREQ_RANGE_END] == NULL ||
         tb[NL80211_ATTR_FREQ_RANGE_MAX_BW] == NULL) {
        return;
    }

    start = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
    end = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
    max_bw = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;

    if (max_bw < 20) {
        return;
    }

    for (m = 0; m < *results->num_modes; m++) {
        if (!(results->modes[m].ht_capab &
              HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET)) {
            continue;
        }

        nl80211_set_ht40_mode_sec(&results->modes[m], start, end);
    }
}

static void nl80211_set_vht_mode(struct hostapd_hw_modes *mode, int start,
                 int end, int max_bw)
{
    int c;

#if HOSTAPD_VERSION >= 211
    for (c = 0; c < mode->num_channels; c++) {
        struct hostapd_channel_data *chan = &mode->channels[c];

        if (chan->freq - 10 < start || chan->freq + 10 > end)
            continue;

        if (max_bw >= 80)
            chan->flag |= HOSTAPD_CHAN_VHT_80MHZ_SUBCHANNEL;

        if (max_bw >= 160)
            chan->flag |= HOSTAPD_CHAN_VHT_160MHZ_SUBCHANNEL;
    }
#else
    for (c = 0; c < mode->num_channels; c++) {
        struct hostapd_channel_data *chan = &mode->channels[c];
        if (chan->freq - 10 >= start && chan->freq + 70 <= end) {
            chan->flag |= HOSTAPD_CHAN_VHT_10_70;
        }

        if (chan->freq - 30 >= start && chan->freq + 50 <= end) {
            chan->flag |= HOSTAPD_CHAN_VHT_30_50;
        }

        if (chan->freq - 50 >= start && chan->freq + 30 <= end) {
            chan->flag |= HOSTAPD_CHAN_VHT_50_30;
        }

        if (chan->freq - 70 >= start && chan->freq + 10 <= end) {
            chan->flag |= HOSTAPD_CHAN_VHT_70_10;
        }

        if (max_bw >= 160) {
            if (chan->freq - 10 >= start && chan->freq + 150 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_10_150;
            }

            if (chan->freq - 30 >= start && chan->freq + 130 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_30_130;
            }

            if (chan->freq - 50 >= start && chan->freq + 110 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_50_110;
            }

            if (chan->freq - 70 >= start && chan->freq + 90 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_70_90;
            }

            if (chan->freq - 90 >= start && chan->freq + 70 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_90_70;
            }

            if (chan->freq - 110 >= start && chan->freq + 50 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_110_50;
            }

            if (chan->freq - 130 >= start && chan->freq + 30 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_130_30;
            }

            if (chan->freq - 150 >= start && chan->freq + 10 <= end) {
                chan->flag |= HOSTAPD_CHAN_VHT_150_10;
            }
        }
    }
#endif /* HOSTAPD_VERSION >= 211 */
}

static void nl80211_reg_rule_vht(struct nlattr *tb[],
                 struct phy_info_arg *results)
{
    u32 start, end, max_bw;
    u16 m;

    if (tb[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
         tb[NL80211_ATTR_FREQ_RANGE_END] == NULL ||
         tb[NL80211_ATTR_FREQ_RANGE_MAX_BW] == NULL) {
        return;
    }

    start = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
    end = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
    max_bw = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;

    if (max_bw < 80) {
        return;
    }

    for (m = 0; m < *results->num_modes; m++) {
        if (!(results->modes[m].ht_capab &
              HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET)) {
                continue;
        }
        /* TODO: use a real VHT support indication */
        if (!results->modes[m].vht_capab) {
            continue;
        }

        nl80211_set_vht_mode(&results->modes[m], start, end, max_bw);
    }
}

static int nl80211_get_reg(struct nl_msg *msg, void *arg)
{
    struct phy_info_arg *results = arg;
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_rule;
    struct nlattr *tb_rule[NL80211_FREQUENCY_ATTR_MAX + 1];
    int rem_rule;
    static struct nla_policy reg_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
        [NL80211_ATTR_REG_RULE_FLAGS] = { .type = NLA_U32 },
        [NL80211_ATTR_FREQ_RANGE_START] = { .type = NLA_U32 },
        [NL80211_ATTR_FREQ_RANGE_END] = { .type = NLA_U32 },
        [NL80211_ATTR_FREQ_RANGE_MAX_BW] = { .type = NLA_U32 },
        [NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN] = { .type = NLA_U32 },
        [NL80211_ATTR_POWER_RULE_MAX_EIRP] = { .type = NLA_U32 },
    };

    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);
    if (!tb_msg[NL80211_ATTR_REG_ALPHA2] ||
        !tb_msg[NL80211_ATTR_REG_RULES]) {
        wpa_printf(MSG_DEBUG, "nl80211: No regulatory information "
               "available");
        return NL_SKIP;
    }

    if (tb_msg[NL80211_ATTR_DFS_REGION]) {
        enum nl80211_dfs_regions dfs_domain;
        dfs_domain = nla_get_u8(tb_msg[NL80211_ATTR_DFS_REGION]);
        nl80211_set_dfs_domain(dfs_domain, &results->dfs_domain);
        wpa_printf(MSG_DEBUG, "nl80211: Regulatory information - country=%s (%s)",
               (char *) nla_data(tb_msg[NL80211_ATTR_REG_ALPHA2]),
               dfs_domain_name(dfs_domain));
    } else {
        wpa_printf(MSG_DEBUG, "nl80211: Regulatory information - country=%s",
               (char *) nla_data(tb_msg[NL80211_ATTR_REG_ALPHA2]));
    }

    nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
    {
        u32 start, end, max_eirp = 0, max_bw = 0, flags = 0;
        nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
              nla_data(nl_rule), nla_len(nl_rule), reg_policy);
        if (tb_rule[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
             tb_rule[NL80211_ATTR_FREQ_RANGE_END] == NULL) {
            continue;
        }
        start = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
        end = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
        if (tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP]) {
            max_eirp = nla_get_u32(tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP]) / 100;
        }
        if (tb_rule[NL80211_ATTR_FREQ_RANGE_MAX_BW]) {
            max_bw = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;
        }
        if (tb_rule[NL80211_ATTR_REG_RULE_FLAGS]) {
            flags = nla_get_u32(tb_rule[NL80211_ATTR_REG_RULE_FLAGS]);
        }

        wpa_printf(MSG_DEBUG, "nl80211: %u-%u @ %u MHz %u mBm%s%s%s%s%s%s%s%s",
               start, end, max_bw, max_eirp,
               flags & NL80211_RRF_NO_OFDM ? " (no OFDM)" : "",
               flags & NL80211_RRF_NO_CCK ? " (no CCK)" : "",
               flags & NL80211_RRF_NO_INDOOR ? " (no indoor)" : "",
               flags & NL80211_RRF_NO_OUTDOOR ? " (no outdoor)" :
               "",
               flags & NL80211_RRF_DFS ? " (DFS)" : "",
               flags & NL80211_RRF_PTP_ONLY ? " (PTP only)" : "",
               flags & NL80211_RRF_PTMP_ONLY ? " (PTMP only)" : "",
               flags & NL80211_RRF_NO_IR ? " (no IR)" : "");
        if (max_bw >= 40) {
            nl80211_reg_rule_ht40(start, end, results);
        }
        if (tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP]) {
            nl80211_reg_rule_max_eirp(start, end, max_eirp,
                          results);
        }
    }

    nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
    {
        nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
              nla_data(nl_rule), nla_len(nl_rule), reg_policy);
        nl80211_reg_rule_sec(tb_rule, results);
    }

    nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
    {
        nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
              nla_data(nl_rule), nla_len(nl_rule), reg_policy);
        nl80211_reg_rule_vht(tb_rule, results);
    }

    return NL_SKIP;
}

static int nl80211_set_regulatory_flags(struct phy_info_arg *results)
{
    struct nl_msg *msg;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_GET_REG);

    // XXX: Should be implemented
    /* if (drv->capa.flags & WPA_DRIVER_FLAGS_SELF_MANAGED_REGULATORY) {
        if (nla_put_u32(msg, NL80211_ATTR_WIPHY, drv->wiphy_idx)) {
            nlmsg_free(msg);
            return -1;
        }
    } */

    return nl80211_send_and_recv(msg, nl80211_get_reg, results, NULL, NULL);
}
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT

struct hostapd_hw_modes *
wifi_drv_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags, u8 *dfs_domain)
{
#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
    struct nl_msg *msg; 
    struct phy_info_arg result = {
        .num_modes = num_modes,
        .modes = NULL,
        .last_mode = -1,
        .failed = 0,
        .dfs_domain = 0,
    };
    
    *num_modes = 0;
    *flags = 0; 
    *dfs_domain = 0;
#if !defined(VNTXER5_PORT)
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    if (msg == NULL) {
#else
    u32 feat;
    feat = get_nl80211_protocol_features(g_wifi_hal.nl80211_id);

    if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
        *flags = NLM_F_DUMP;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, *flags, NL80211_CMD_GET_WIPHY);
    if (!msg || nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
#endif
        nlmsg_free(msg);
        return NULL;
    }
    
    if (nl80211_send_and_recv(msg, phy_info_get_hw_feature_handler, &result, NULL, NULL) == 0) {
        struct hostapd_hw_modes *modes;
        
        nl80211_set_regulatory_flags(&result);
        
        if (result.failed) {
            int i;
            
            for (i = 0; result.modes && i < *num_modes; i++) {
                os_free(result.modes[i].channels);
                os_free(result.modes[i].rates);
            }
            os_free(result.modes);
            *num_modes = 0;
            return NULL;
        }
        
        *dfs_domain = result.dfs_domain;
        
        modes = wpa_driver_nl80211_postprocess_modes(result.modes,
                                 num_modes);
        nl80211_dump_chan_list(modes, *num_modes);
        return modes;
    }
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT
    return NULL;
}


int wifi_drv_if_remove(void *priv, enum wpa_driver_if_type type, const char *ifname)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if ((interface->vap_configured == true)) {
        if (vap->vap_mode == wifi_vap_mode_ap) {
            close(interface->u.ap.br_sock_fd);
            interface->u.ap.br_sock_fd = 0;
        } else if (vap->vap_mode == wifi_vap_mode_sta) {
            close(interface->u.sta.sta_sock_fd);
            interface->u.sta.sta_sock_fd = 0;
        }

        interface->vap_configured = false;
        interface->bridge_configured = false;
    }

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_if_add(void *priv, enum wpa_driver_if_type type,
                     const char *ifname, const u8 *addr,
                     void *bss_ctx, void **drv_priv,
                     char *force_ifname, u8 *if_addr,
                     const char *bridge, int use_existing,
                     int setup_ap)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int nl80211_put_acl(struct nl_msg *msg, wifi_interface_info_t *interface)
{
    if (!msg || !interface) {
        wifi_hal_error_print("%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    struct nlattr *acl;
    unsigned int i = 0, policy;
    acl_map_t *acl_map = NULL;
    wifi_vap_info_t *vap;
    mac_address_t null_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    vap = &interface->vap_info;
    if (!vap) {
        wifi_hal_error_print("%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }
    if (vap->u.bss_info.mac_filter_enable == true) {
        if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
            policy = NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED;
        } else {
            policy = NL80211_ACL_POLICY_DENY_UNLESS_LISTED;
        }

        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, policy);

        acl = nla_nest_start(msg, NL80211_ATTR_MAC_ADDRS);

        if (acl == NULL) {
            wifi_hal_dbg_print("%s:%d Failed to to add ACL list to msg\n", __func__, __LINE__);
            return -1;
        }

        if (interface->acl_map != NULL) {
            acl_map = hash_map_get_first(interface->acl_map);
            while (acl_map != NULL) {
                if (nla_put(msg, i, ETH_ALEN, acl_map->mac_addr)) {
                    wifi_hal_dbg_print("%s:%d Failed to add MAC to ACL list\n", __func__, __LINE__);
                    return -ENOMEM;
                }
                acl_map = hash_map_get_next(interface->acl_map, acl_map);
                i++;
            }
        }
        if (i == 0) {
            if (nla_put(msg, i, ETH_ALEN, null_mac)) {
                wifi_hal_dbg_print("%s:%d Failed to add MAC to ACL list\n", __func__, __LINE__);
                return -ENOMEM;
            }
        }
        nla_nest_end(msg, acl);

        wifi_hal_dbg_print("%s:%d: ACL count: %d ACL mode: %s \n", __func__, __LINE__, i,
            vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list ? "Blacklist" :
                                                                                 "Whitelist");

    } else {
        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED);
        nla_put_u32(msg, NL80211_ATTR_MAC_ADDRS, 0);
        wifi_hal_dbg_print("%s:%d: Disable ACL\n", __func__, __LINE__);
    }

    return RETURN_OK;
}

int nl80211_set_acl(wifi_interface_info_t *interface)
{
    struct nl_msg *msg;
    struct nlattr *acl;
    unsigned int i = 0, policy;
    int ret;
    acl_map_t *acl_map = NULL;
    wifi_vap_info_t *vap;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    vap = &interface->vap_info;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_MAC_ACL))) {
        wifi_hal_dbg_print("nl80211: Failed to build MAC ACL msg\n");
        return -ENOMEM;
    }

    if (vap->u.bss_info.mac_filter_enable == true) {
        if (vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
            policy = NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED;
        } else {
            policy = NL80211_ACL_POLICY_DENY_UNLESS_LISTED;
        }


        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, policy);

        acl = nla_nest_start(msg, NL80211_ATTR_MAC_ADDRS);

        if (acl == NULL) {
            wifi_hal_dbg_print("nl80211: Failed to to add ACL list to msg\n");
            return -ENOMEM;
        }

        if (interface->acl_map != NULL) {
            acl_map = hash_map_get_first(interface->acl_map);
            while (acl_map != NULL) {
                if (nla_put(msg, i, ETH_ALEN, acl_map->mac_addr)) {
                    wifi_hal_dbg_print("nl80211: Failed to add MAC to ACL list\n");
                    return -ENOMEM;
                }
                acl_map = hash_map_get_next(interface->acl_map, acl_map);
                i++;
            }
        }
        if (i == 0) {
            if (nla_put(msg, i, ETH_ALEN, null_mac)) {
                wifi_hal_dbg_print("nl80211: Failed to add MAC to ACL list\n");
                return -ENOMEM;
            }
        }
        nla_nest_end(msg, acl);

        wifi_hal_dbg_print("%s:%d: ACL count: %d ACL mode: %s \n", __func__, __LINE__, i,
            vap->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list ? "Blacklist" : "Whitelist");

    } else {
        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED);
        nla_put_u32(msg, NL80211_ATTR_MAC_ADDRS, 0);
        wifi_hal_dbg_print("%s:%d: Disable ACL\n", __func__, __LINE__);
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_dbg_print("nl80211: Failed to set MAC ACL: %d (%s)", ret, strerror(-ret));
    }

    return ret;
}

int nl80211_set_acl_mode(wifi_interface_info_t *interface, uint32_t mac_filter_mode)
{
    int ret = RETURN_OK;
    wifi_vap_info_t *vap;
    vap = &interface->vap_info;
#ifdef NL80211_ACL
    struct nl_msg *msg;
    struct nlattr *acl;
    unsigned int policy;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (vap->u.bss_info.enabled != true || vap->u.bss_info.mac_filter_enable == false || vap->vap_mode != wifi_vap_mode_ap) {
         wifi_hal_error_print(":%s:%d mac filter not enabled:%d for vap:%d\n", __func__, __LINE__, vap->u.bss_info.enabled, vap->vap_index);
        return RETURN_ERR;
    } else if (vap->u.bss_info.mac_filter_mode == mac_filter_mode) {
        wifi_hal_error_print(":%s:%d mac filtermode is already set for vap:%d\n", __func__, __LINE__, vap->vap_index);
        return RETURN_OK;
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_MAC_ACL))) {
        wifi_hal_error_print("nl80211: Failed to build MAC ACL msg\n");
        return -ENOMEM;
    }

    if (mac_filter_mode == wifi_mac_filter_mode_black_list) {
        policy = NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED;
    } else {
        policy = NL80211_ACL_POLICY_DENY_UNLESS_LISTED;
    }


    nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, policy);

    acl = nla_nest_start(msg, NL80211_ATTR_MAC_ADDRS);

    if (acl == NULL) {
        wifi_hal_error_print("nl80211: Failed to to add ACL list to msg\n");
        nlmsg_free(msg);
        return -ENOMEM;
    }

    if (nla_put(msg, 0, ETH_ALEN, null_mac)) {
        wifi_hal_error_print("nl80211: Failed to add MAC to ACL list\n");
        nlmsg_free(msg);
        return -ENOMEM;
    }
    nla_nest_end(msg, acl);

    wifi_hal_info_print("%s:%d: vap:%d set mac filter mode:%s\n", __func__, __LINE__, vap->vap_index,
            (mac_filter_mode == wifi_mac_filter_mode_black_list) ? "Blacklist" : "Whitelist");

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Failed to set MAC ACL: %d (%s)", ret, strerror(-ret));
    } else {
        vap->u.bss_info.mac_filter_mode = mac_filter_mode;
    }
#else
    uint32_t filtermode;
    //Call vendor HAL
    if (vap->vap_mode == wifi_vap_mode_ap) {
        if (vap->u.bss_info.mac_filter_enable == TRUE) {
            if (mac_filter_mode == wifi_mac_filter_mode_black_list) {
                //blacklist
                filtermode = 2;
            } else {
                //whitelist
                filtermode = 1;
            }
        } else {
            //disabled
            filtermode  = 0;
        }
        wifi_hal_info_print("%s:%d: vap:%d set mac filter mode:%s\n", __func__, __LINE__, vap->vap_index,
            mac_filter_mode == wifi_mac_filter_mode_black_list ? "Blacklist" : "Whitelist");
        if (wifi_setApMacAddressControlMode(vap->vap_index, filtermode) < 0) {
            wifi_hal_error_print("%s:%d: vap index:%d failed to set mac filter\n", __func__,
                    __LINE__, vap->vap_index);
            return RETURN_ERR;
        } else {
            vap->u.bss_info.mac_filter_mode = mac_filter_mode;
        }
    }
#endif // NL80211_ACL
    return ret;
}

int wifi_drv_set_acl(void *priv, struct hostapd_acl_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;
    struct nl_msg *msg;
    struct nl_msg *acl;
    unsigned int i;
    int ret;
    size_t acl_nla_sz, acl_nlmsg_sz, nla_sz, nlmsg_sz;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)priv;
    acl_nla_sz = nla_total_size(ETH_ALEN) * params->num_mac_acl;
    acl_nlmsg_sz = nlmsg_total_size(acl_nla_sz);
    acl = nlmsg_alloc_size(acl_nlmsg_sz);
    if (!acl) {
        return -ENOMEM;
    }
    for (i = 0; i < params->num_mac_acl; i++) {
        if (nla_put(acl, i + 1, ETH_ALEN, params->mac_acl[i].addr)) {
            nlmsg_free(acl);
            return -ENOMEM;
        }
    }

    /*
     * genetlink message header (Length of user header is 0) +
     * u32 attr: NL80211_ATTR_IFINDEX +
     * u32 attr: NL80211_ATTR_ACL_POLICY +
     * nested acl attr
     */
    nla_sz = GENL_HDRLEN +
          nla_total_size(4) * 2 +
          nla_total_size(acl_nla_sz);
    nlmsg_sz = nlmsg_total_size(nla_sz);
    if (!(msg = nl80211_cmd_msg_build(g_wifi_hal.nl80211_id, interface, 0,
                                      NL80211_CMD_SET_MAC_ACL, nlmsg_alloc_size(nlmsg_sz))) ||
        nla_put_u32(msg, NL80211_ATTR_ACL_POLICY, params->acl_policy ?
                    NL80211_ACL_POLICY_DENY_UNLESS_LISTED :
                    NL80211_ACL_POLICY_ACCEPT_UNLESS_LISTED) ||
        nla_put_nested(msg, NL80211_ATTR_MAC_ADDRS, acl)) {

        nlmsg_free(msg);
        nlmsg_free(acl);
        return -ENOMEM;
    }
    nlmsg_free(acl);

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("nl80211: Failed to set MAC ACL: %d (%s)",
                           ret, strerror(-ret));
    }

    return ret;
}

#if HOSTAPD_VERSION < 210
static int nl80211_put_beacon_rate(struct nl_msg *msg, const u64 flags, struct wpa_driver_ap_params *params)
#else
static int nl80211_put_beacon_rate(struct nl_msg *msg, const u64 flags, u64 flags2, struct wpa_driver_ap_params *params)
#endif
{
    struct nlattr *bands, *band;
    struct nl80211_txrate_vht vht_rate;
#if HOSTAPD_VERSION >= 210
    struct nl80211_txrate_he he_rate;
#endif

    if (!params->freq ||
        (params->beacon_rate == 0 &&
         params->rate_type == BEACON_RATE_LEGACY))
        return 0;

    bands = nla_nest_start(msg, NL80211_ATTR_TX_RATES);
    if (!bands)
        return -1;

    switch (params->freq->mode) {
    case HOSTAPD_MODE_IEEE80211B:
    case HOSTAPD_MODE_IEEE80211G:
        band = nla_nest_start(msg, NL80211_BAND_2GHZ);
        break;
    case HOSTAPD_MODE_IEEE80211A:
#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(params->freq->freq)) {
            band = nla_nest_start(msg, NL80211_BAND_6GHZ);
        } else {
            band = nla_nest_start(msg, NL80211_BAND_5GHZ);
        }
#else
        band = nla_nest_start(msg, NL80211_BAND_5GHZ);
#endif
        break;
    case HOSTAPD_MODE_IEEE80211AD:
        band = nla_nest_start(msg, NL80211_BAND_60GHZ);
        break;
    default:
        return 0;
    }

    if (!band)
        return -1;

    memset(&vht_rate, 0, sizeof(vht_rate));
#if HOSTAPD_VERSION >= 210
    memset(&he_rate, 0, sizeof(he_rate));
#endif

    switch (params->rate_type) {
    case BEACON_RATE_LEGACY:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_LEGACY)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (legacy)\n");
            return -1;
        }

        if (nla_put_u8(msg, NL80211_TXRATE_LEGACY,
                   (u8) params->beacon_rate / 5) ||
            nla_put(msg, NL80211_TXRATE_HT, 0, NULL) ||
            (params->freq->vht_enabled &&
             nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                 &vht_rate)))
            return -1;

        wifi_hal_dbg_print(" * beacon_rate = legacy:%u (* 100 kbps)\n", params->beacon_rate);
        break;
    case BEACON_RATE_HT:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_HT)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (HT)\n");
            return -1;
        }
        if (nla_put(msg, NL80211_TXRATE_LEGACY, 0, NULL) ||
            nla_put_u8(msg, NL80211_TXRATE_HT, params->beacon_rate) ||
            (params->freq->vht_enabled &&
             nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                 &vht_rate)))
            return -1;
        wifi_hal_dbg_print(" * beacon_rate = HT-MCS %u\n", params->beacon_rate);
        break;
    case BEACON_RATE_VHT:
        if (!(flags & WPA_DRIVER_FLAGS_BEACON_RATE_VHT)) {
            wifi_hal_error_print("nl80211: Driver does not support setting Beacon frame rate (VHT)\n");
            return -1;
        }
        vht_rate.mcs[0] = BIT(params->beacon_rate);
        if (nla_put(msg, NL80211_TXRATE_LEGACY, 0, NULL))
            return -1;
        if (nla_put(msg, NL80211_TXRATE_HT, 0, NULL))
            return -1;
        if (nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                &vht_rate))
            return -1;
        wifi_hal_dbg_print(" * beacon_rate = VHT-MCS %u\n", params->beacon_rate);
        break;
#if HOSTAPD_VERSION >= 210
    case BEACON_RATE_HE:
        if (!(flags2 & WPA_DRIVER_FLAGS2_BEACON_RATE_HE)) {
            wifi_hal_info_print("nl80211: Driver does not support setting Beacon frame rate (HE)");
            return -1;
        }
        he_rate.mcs[0] = BIT(params->beacon_rate);
        if (nla_put(msg, NL80211_TXRATE_LEGACY, 0, NULL) ||
            nla_put(msg, NL80211_TXRATE_HT, 0, NULL) ||
            nla_put(msg, NL80211_TXRATE_VHT, sizeof(vht_rate),
                &vht_rate) ||
            nla_put(msg, NL80211_TXRATE_HE, sizeof(he_rate), &he_rate))
            return -1;
        wifi_hal_dbg_print(" * beacon_rate = HE-MCS %u", params->beacon_rate);
        break;
#endif
    default:
        wifi_hal_info_print("nl80211: case not handled %d \n", params->rate_type);
    }

    nla_nest_end(msg, band);
    nla_nest_end(msg, bands);

    return 0;
}

static u32 wpa_alg_to_cipher_suite(enum wpa_alg alg, size_t key_len)
{
    switch (alg) {
    case WPA_ALG_WEP:
        if (key_len == 5)
            return RSN_CIPHER_SUITE_WEP40;
        return RSN_CIPHER_SUITE_WEP104;
    case WPA_ALG_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    case WPA_ALG_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_ALG_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_ALG_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_ALG_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
#if HOSTAPD_VERSION >= 210 //2.10
    case WPA_ALG_BIP_CMAC_128:
#else
    case WPA_ALG_IGTK:
#endif
        return RSN_CIPHER_SUITE_AES_128_CMAC;
    case WPA_ALG_BIP_GMAC_128:
        return RSN_CIPHER_SUITE_BIP_GMAC_128;
    case WPA_ALG_BIP_GMAC_256:
        return RSN_CIPHER_SUITE_BIP_GMAC_256;
    case WPA_ALG_BIP_CMAC_256:
        return RSN_CIPHER_SUITE_BIP_CMAC_256;
    case WPA_ALG_SMS4:
        return RSN_CIPHER_SUITE_SMS4;
    case WPA_ALG_KRK:
        return RSN_CIPHER_SUITE_KRK;
#if HOSTAPD_VERSION < 210 //2.10
    case WPA_ALG_PMK:
#endif
    case WPA_ALG_NONE:
        wpa_printf(MSG_ERROR, "nl80211: Unexpected encryption algorithm %d",
               alg);
        return 0;
    }

    wpa_printf(MSG_ERROR, "nl80211: Unsupported encryption algorithm %d",
           alg);
    return 0;
}

static u32 wpa_cipher_to_cipher_suite(unsigned int cipher)
{
    switch (cipher) {
    case WPA_CIPHER_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_CIPHER_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
    case WPA_CIPHER_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_CIPHER_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_CIPHER_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    case WPA_CIPHER_WEP104:
        return RSN_CIPHER_SUITE_WEP104;
    case WPA_CIPHER_WEP40:
        return RSN_CIPHER_SUITE_WEP40;
    case WPA_CIPHER_GTK_NOT_USED:
        return RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED;
    }

    return 0;
}


static int wpa_cipher_to_cipher_suites(unsigned int ciphers, u32 suites[],
                       int max_suites)
{
    int num_suites = 0;

    if (num_suites < max_suites && ciphers & WPA_CIPHER_CCMP_256)
        suites[num_suites++] = RSN_CIPHER_SUITE_CCMP_256;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_GCMP_256)
        suites[num_suites++] = RSN_CIPHER_SUITE_GCMP_256;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_CCMP)
        suites[num_suites++] = RSN_CIPHER_SUITE_CCMP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_GCMP)
        suites[num_suites++] = RSN_CIPHER_SUITE_GCMP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_TKIP)
        suites[num_suites++] = RSN_CIPHER_SUITE_TKIP;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_WEP104)
        suites[num_suites++] = RSN_CIPHER_SUITE_WEP104;
    if (num_suites < max_suites && ciphers & WPA_CIPHER_WEP40)
        suites[num_suites++] = RSN_CIPHER_SUITE_WEP40;

    return num_suites;
}

static int nl80211_put_basic_rates(struct nl_msg *msg, const int *basic_rates)
{
   u8 rates[NL80211_MAX_SUPP_RATES];
   u8 rates_len = 0;
   int i;

   if (!basic_rates) {
       return 0;
   }

   for (i = 0; i < NL80211_MAX_SUPP_RATES && basic_rates[i] >= 0; i++) {
       rates[rates_len++] = basic_rates[i] / 5;
   }

   return nla_put(msg, NL80211_ATTR_BSS_BASIC_RATES, rates_len, rates);
}

static int nl80211_set_bss(wifi_interface_info_t *interface, int cts, int preamble,
    int slot, int ht_opmode, int ap_isolate, const int *basic_rates)
{
    struct nl_msg *msg;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_BSS)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    if ((cts >= 0 && nla_put_u8(msg, NL80211_ATTR_BSS_CTS_PROT, cts)) ||
        (preamble >= 0 && nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_PREAMBLE, preamble)) ||
        (slot >= 0 && nla_put_u8(msg, NL80211_ATTR_BSS_SHORT_SLOT_TIME, slot)) ||
        (ht_opmode >= 0 && nla_put_u16(msg, NL80211_ATTR_BSS_HT_OPMODE, ht_opmode)) ||
        (ap_isolate >= 0 && nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, ap_isolate)) ||
        nl80211_put_basic_rates(msg, basic_rates)) {
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    return nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
}

int set_bss_param(void *priv, struct wpa_driver_ap_params *params)
{
    struct nl_msg *msg;
    int ret;
    wifi_interface_info_t *interface;
    interface = (wifi_interface_info_t *)priv;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_BSS)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }
    nla_put_u8(msg, NL80211_ATTR_AP_ISOLATE, params->isolate);
    wifi_hal_info_print("Set AP isolate:%d \r\n", params->isolate);
    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Failed to set bss for interface: %s error: %d(%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
        return -1;
    }

    return 0;
}

#ifdef EAPOL_OVER_NL
static void nl80211_control_port_frame (wifi_interface_info_t* interface, struct nlattr **tb)
{
    u8 *src_addr;
    u16 ethertype;

    if (!tb[NL80211_ATTR_MAC] ||
            !tb[NL80211_ATTR_FRAME] ||
            !tb[NL80211_ATTR_CONTROL_PORT_ETHERTYPE]) {
        return;
    }

    src_addr = nla_data(tb[NL80211_ATTR_MAC]);
    ethertype = nla_get_u16(tb[NL80211_ATTR_CONTROL_PORT_ETHERTYPE]);

    switch (ethertype) {
        case ETH_P_RSN_PREAUTH:
            wifi_hal_dbg_print("nl80211: Got pre-auth frame from "
                    MACSTR " over control port unexpectedly",
                    MAC2STR(src_addr));
            break;
        case ETH_P_PAE:
            drv_event_eapol_rx(&interface->u.ap.hapd, src_addr,
                    nla_data(tb[NL80211_ATTR_FRAME]),
                    nla_len(tb[NL80211_ATTR_FRAME]));
            break;
        default:
            wifi_hal_dbg_print("nl80211: Unxpected ethertype 0x%04x from "
                    MACSTR " over control port",
                    ethertype, MAC2STR(src_addr));
            break;
    }
}

int process_bss_frame(struct nl_msg *msg, void *arg)
{
    wifi_interface_info_t *interface;
    struct genlmsghdr *gnlh;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    gnlh = nlmsg_data(nlmsg_hdr(msg));
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    interface = (wifi_interface_info_t *)arg;

    switch(gnlh->cmd) {
        case NL80211_CMD_CONTROL_PORT_FRAME:
            nl80211_control_port_frame(interface, tb);
            break;
        default:
            wifi_hal_dbg_print("%s:%d: BSS Event %d received for %s\n", __func__, __LINE__, gnlh->cmd,  interface->name);
            break;
    }

    wifi_hal_dbg_print("%s:%d: BSS Event %d received for %s\n", __func__, __LINE__, gnlh->cmd,  interface->name);

    return NL_SKIP;
}
#endif

static int nl80211_mbssid(struct nl_msg *msg, struct wpa_driver_ap_params *params)
{
#if HOSTAPD_VERSION >= 210
    struct nlattr *config, *elems;
    int ifidx;

    if (params->mbssid_tx_iface == NULL) {
        return 0;
    }

    config = nla_nest_start(msg, NL80211_ATTR_MBSSID_CONFIG);
    if (config == NULL ||
        nla_put_u8(msg, NL80211_MBSSID_CONFIG_ATTR_INDEX, params->mbssid_index) < 0) {
        wifi_hal_error_print("%s:%d: failed to add mbssid index attr\n", __func__, __LINE__);
        return -1;
    }

    ifidx = if_nametoindex(params->mbssid_tx_iface);
    if (ifidx <= 0 || nla_put_u32(msg, NL80211_MBSSID_CONFIG_ATTR_TX_IFINDEX, ifidx) < 0) {
        wifi_hal_error_print("%s:%d: failed to add mbssid tx ifindex attr\n", __func__, __LINE__);
        return -1;
    }

    if (params->ema && nla_put_flag(msg, NL80211_MBSSID_CONFIG_ATTR_EMA) < 0) {
        wifi_hal_error_print("%s:%d: failed to add mbssid ema attr\n", __func__, __LINE__);
        return -1;
    }

    nla_nest_end(msg, config);

    if (params->mbssid_elem_count != 0 && params->mbssid_elem_len != 0 &&
        params->mbssid_elem_offset != NULL && *params->mbssid_elem_offset != NULL) {
        u8 i, **offs = params->mbssid_elem_offset;

        elems = nla_nest_start(msg, NL80211_ATTR_MBSSID_ELEMS);
        if (elems == NULL) {
            wifi_hal_error_print("%s:%d: failed to add mbssid elems\n", __func__, __LINE__);
            return -1;
        }

        for (i = 0; i < params->mbssid_elem_count - 1; i++) {
            if (nla_put(msg, i + 1, offs[i + 1] - offs[i], offs[i]) < 0) {
                wifi_hal_error_print("%s:%d: failed to add mbssid IEs\n", __func__, __LINE__);
                return -1;
            }
        }

        if (nla_put(msg, i + 1, *offs + params->mbssid_elem_len - offs[i], offs[i]) < 0) {
            wifi_hal_error_print("%s:%d: failed to add mbssid IEs\n", __func__, __LINE__);
            return -1;
        }

        nla_nest_end(msg, elems);
    }
#endif /* HOSTAPD_VERSION >= 210 */

    return 0;
}

int wifi_drv_set_ap(void *priv, struct wpa_driver_ap_params *params)
{
#ifdef CONFIG_IEEE80211BE
    struct nl_msg *msg_mlo;
#endif /* CONFIG_IEEE80211BE */
    struct nl_msg *msg;
    int ret;
    int num_suites;
#if HOSTAPD_VERSION < 210 //2.10
    int smps_mode;
#endif
    u32 suites[10], suite;
    u32 ver;
    wifi_interface_info_t *interface;
    wifi_driver_data_t *drv;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t *radio_param;
    char country[8];
    int beacon_set;
    u8 cmd = NL80211_CMD_NEW_BEACON;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    radio_param = &radio->oper_param;

    drv = &radio->driver_data;

    beacon_set = params->reenable ? 0 : interface->beacon_set;

    wifi_hal_dbg_print("%s:%d:Enter, interface name:%s vap index:%d radio index:%d beacon_set %d\n", __func__, __LINE__,
        interface->name, vap->vap_index, radio->index, beacon_set);

    if (beacon_set) {
        cmd = NL80211_CMD_SET_BEACON;
    }

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, cmd)) == NULL) {
        wifi_hal_error_print("%s:%d: Failed to create message\n", __func__, __LINE__);
        return -1;
    }

    //wifi_hal_dbg_print("%s:%d: beacon head\n", __func__, __LINE__);
    //my_print_hex_dump(params->head_len, params->head);
    //wifi_hal_dbg_print("%s:%d: beacon tail\n", __func__, __LINE__);
    //my_print_hex_dump(params->tail_len, params->tail);

    nla_put(msg, NL80211_ATTR_BEACON_HEAD, params->head_len, params->head);
    nla_put(msg, NL80211_ATTR_BEACON_TAIL, params->tail_len, params->tail);
    if (params->beacon_int > 0) {
        nla_put_u32(msg, NL80211_ATTR_BEACON_INTERVAL, params->beacon_int);
    }
#if HOSTAPD_VERSION < 210
    nl80211_put_beacon_rate(msg, drv->capa.flags, params);
#else
    nl80211_put_beacon_rate(msg, drv->capa.flags, drv->capa.flags2, params);
#endif
    if (params->dtim_period > 0) {
        nla_put_u32(msg, NL80211_ATTR_DTIM_PERIOD, params->dtim_period);
    }
    nla_put(msg, NL80211_ATTR_SSID, params->ssid_len, params->ssid);
    if (params->proberesp && params->proberesp_len) {
        //wifi_hal_dbg_print("%s:%d: probe response (offload)\n", __func__, __LINE__);
        //my_print_hex_dump(params->proberesp_len, params->proberesp);
        nla_put(msg, NL80211_ATTR_PROBE_RESP, params->proberesp_len, params->proberesp);
    }

    switch (params->hide_ssid) {
        case NO_SSID_HIDING:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
            break;

        case HIDDEN_SSID_ZERO_LEN:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_LEN);
            break;

        case HIDDEN_SSID_ZERO_CONTENTS:
            nla_put_u32(msg, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_ZERO_CONTENTS);
            break;
    }

    if (params->privacy) {
        nla_put_flag(msg, NL80211_ATTR_PRIVACY);
    }

    if ((params->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) ==
        (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
        /* Leave out the attribute */
    } else if (params->auth_algs & WPA_AUTH_ALG_SHARED) {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_SHARED_KEY);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    }

    ver = 0;
    if (params->wpa_version & WPA_PROTO_WPA)
        ver |= NL80211_WPA_VERSION_1;
    if (params->wpa_version & WPA_PROTO_RSN)
        ver |= NL80211_WPA_VERSION_2;
    if (ver) {
        nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, ver);
    }

    num_suites = 0;
    if (params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X)
        suites[num_suites++] = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
    if (params->key_mgmt_suites & WPA_KEY_MGMT_PSK)
        suites[num_suites++] = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
    if (params->key_mgmt_suites & WPA_KEY_MGMT_SAE)
        suites[num_suites++] = RSN_AUTH_KEY_MGMT_SAE;

    if (num_suites) {
        nla_put(msg, NL80211_ATTR_AKM_SUITES, num_suites * sizeof(u32), suites);
    }

    if (params->key_mgmt_suites & WPA_KEY_MGMT_IEEE8021X_NO_WPA &&
        (!params->pairwise_ciphers ||
         params->pairwise_ciphers & (WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40))) {
        nla_put_u16(msg, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE);
        nla_put_flag(msg, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    }

    if (drv->device_ap_sme && (params->key_mgmt_suites & WPA_KEY_MGMT_SAE)) {
        nla_put_flag(msg, NL80211_ATTR_EXTERNAL_AUTH_SUPPORT);
    }

    num_suites = wpa_cipher_to_cipher_suites(params->pairwise_ciphers,
                         suites, ARRAY_SIZE(suites));
    if (num_suites) {
        nla_put(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, num_suites * sizeof(u32), suites);
    }

    suite = wpa_cipher_to_cipher_suite(params->group_cipher);
    if (suite) {
       nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, suite);
    }

#if HOSTAPD_VERSION < 210 //2.10
    if (params->ht_opmode != -1) {
        switch (params->smps_mode) {
            case HT_CAP_INFO_SMPS_DYNAMIC:
                smps_mode = NL80211_SMPS_DYNAMIC;
                break;

            case HT_CAP_INFO_SMPS_STATIC:
                smps_mode = NL80211_SMPS_STATIC;
                break;

            default:
                /* invalid - fallback to smps off */
            case HT_CAP_INFO_SMPS_DISABLED:
                smps_mode = NL80211_SMPS_OFF;
                break;
        }
        nla_put_u8(msg, NL80211_ATTR_SMPS_MODE, smps_mode);
    }
#endif

    if (params->beacon_ies) {
        nla_put(msg, NL80211_ATTR_IE, wpabuf_len(params->beacon_ies), wpabuf_head(params->beacon_ies));
    }
    if (params->proberesp_ies) {
        nla_put(msg, NL80211_ATTR_IE_PROBE_RESP, wpabuf_len(params->proberesp_ies), wpabuf_head(params->proberesp_ies));
    }

    if (params->assocresp_ies) {
        nla_put(msg, NL80211_ATTR_IE_ASSOC_RESP, wpabuf_len(params->assocresp_ies), wpabuf_head(params->assocresp_ies));
    }

    if (drv->capa.flags & WPA_DRIVER_FLAGS_INACTIVITY_TIMER)  {
        nla_put_u16(msg, NL80211_ATTR_INACTIVITY_TIMEOUT, params->ap_max_inactivity);
    }

#if (HOSTAPD_VERSION >= 210) 
#if defined (CONFIG_SAE)
    if (params->key_mgmt_suites & WPA_KEY_MGMT_SAE) { 
        u8 sae_pwe;

        if (params->sae_pwe == 0) {
            sae_pwe = NL80211_SAE_PWE_HUNT_AND_PECK;
        } else if (params->sae_pwe == 1) {
            sae_pwe = NL80211_SAE_PWE_HASH_TO_ELEMENT;
        } else if (params->sae_pwe == 2) {
            sae_pwe = NL80211_SAE_PWE_BOTH;
        } else {
            return -1;
        }
        if (nla_put_u8(msg, NL80211_ATTR_SAE_PWE, sae_pwe)) {
            return -1;
        }
    }
#endif /* CONFIG_SAE */
#endif /* HOSTAPD_VERSION */

    if (nl80211_mbssid(msg, params) < 0) {
        return -1;
    }

#ifdef CONFIG_IEEE80211BE
    ret = nl80211_drv_mlo_msg(msg, &msg_mlo, interface, params);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Failed to create mlo msg on interface %s, error: %d\n",
            __func__, __LINE__, interface->name, ret);
        return -1;
    }
#endif /* CONFIG_IEEE80211BE */

    get_coutry_str_from_code(radio_param->countryCode, country);

    if (beacon_set == 0) {
        if (nl80211_fill_chandef(msg, radio, interface) == -1) {
            wifi_hal_error_print("%s:%d: Failed nl80211_fill_chandef\n", __func__, __LINE__);
            return -1;
        }
    }

#if defined(NL80211_ACL) && !defined(PLATFORM_LINUX)
    //Raspberry Pi kernel requires patching to support ACL functionality.
    nl80211_put_acl(msg, interface);
#endif

#ifdef EAPOL_OVER_NL
    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_CONTROL_PORT_FRAME && interface->bss_nl_connect_event_fd > 0 ) {
        ret = nl80211_set_rx_control_port_owner(msg, interface);
        if (ret) {
            wifi_hal_error_print("%s:%d: failed to register for bss frames on interface %s, "
                    "error: %d (%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
            return -1;
        }

    } else {
#endif
    ret = nl80211_send_and_recv(msg, beacon_info_handler, &g_wifi_hal, NULL, NULL);
    if (ret != 0) {
        wifi_hal_error_print("%s:%d: Failed to set beacon parameter for interface: %s error: %d(%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
        if(radio->oper_param.channelWidth != WIFI_CHANNELBANDWIDTH_320MHZ) {
#endif
        return -1;
#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE) && defined(KERNEL_NO_320MHZ_SUPPORT)
        }
#endif
    }
#ifdef EAPOL_OVER_NL
    }
#endif
    interface->beacon_set = 1;

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_SET_BSS) {
        if (nl80211_set_bss(interface, params->cts_protect, params->preamble,
            params->short_slot_time, params->ht_opmode,
            params->isolate, params->basic_rates) != 0) {
            wifi_hal_dbg_print("%s:%d: Failed to set BSS for interface: %s error: %d(%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
            return -1;
        }
    }
    else
    {
        set_bss_param(priv, params);
    }

#ifdef CONFIG_IEEE80211BE
    ret = nl80211_send_mlo_msg(msg_mlo);
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: Failed to send mlo msg on interface %s, error: %d\n", __func__,
            __LINE__, interface->name, ret);
        return -1;
    }
#endif /* CONFIG_IEEE80211BE */

    return 0;
}

int wifi_drv_get_country(void *priv, char *alpha2)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_country(void *priv, const char *alpha2_arg)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_supp_port(void *priv, int authorized)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;
    wifi_bss_info_t *backhaul;
    struct nl_msg *msg;
    struct nl80211_sta_flag_update upd;
    int ret;

    interface = (wifi_interface_info_t *)priv;
    backhaul = &interface->u.sta.backhaul;

#ifdef CONFIG_VENDOR_COMMANDS
    if (interface->u.sta.state <= WPA_ASSOCIATED && !authorized) {
        wifi_hal_error_print("nl80211: Skip set_supp_port(unauthorized) while not associated\n");
        return 0;
    }
#endif

    os_memset(&upd, 0, sizeof(upd));
    upd.mask = BIT(NL80211_STA_FLAG_AUTHORIZED);
    if (authorized)
        upd.set = BIT(NL80211_STA_FLAG_AUTHORIZED);

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_STATION)) ||
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, backhaul->bssid) || nla_put(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd))
    {
        wifi_hal_error_print("Failed to create command SET_STATION\n");
        nlmsg_free(msg);
        return -ENOBUFS;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL); 

    if (ret == 0) {
        return 0;
    }

    wifi_hal_error_print("%s:%d: set supp port command failed: ret=%d (%s)\n", __func__, __LINE__,
        ret, strerror(-ret));

    return ret;
}

int wifi_hal_purgeScanResult(unsigned int vap_index, unsigned char *sta_mac)
{
    wifi_interface_info_t *interface = NULL;
    char *key = NULL;
    mac_addr_str_t sta_mac_str;
#ifndef FEATURE_SINGLE_PHY
    wifi_radio_info_t *radio;
    unsigned char radio_index = 0;

    if ((vap_index % 2) == 0) {
        radio_index = 0;
    } else {
        radio_index = 1;
    }

    if((radio_index >= MAX_NUM_RADIOS) || (vap_index >= MAX_VAP) || sta_mac == NULL)
    {
        return RETURN_ERR;
    }

    radio = get_radio_by_phy_index(radio_index);

    if (radio != NULL) {
        interface = hash_map_get_first(radio->interface_map);
        while (interface != NULL) {
            if (interface->vap_info.vap_index == vap_index) {
                break;
            }
            interface = hash_map_get_next(radio->interface_map, interface);
        }
#else //FEATURE_SINGLE_PHY
    {
        // Get interface from vap_index and use that interface instead of
        // obtaining interface from radio_info.
        interface = get_interface_by_vap_index(vap_index);
        wifi_hal_dbg_print("%s:%d: Obtained interface:%p for vap_index:%d\n",
            __func__, __LINE__, interface, vap_index);
#endif //FEATURE_SINGLE_PHY
        if ((interface != NULL) && (interface->scan_info_map != NULL)) {
            void *free_scan_info_map;
            key = to_mac_str(sta_mac, sta_mac_str);
            wifi_hal_dbg_print("%s:%d: [SCAN] clear old ssid entry %s\r\n", __func__, __LINE__, key);
            pthread_mutex_lock(&interface->scan_info_mutex);
            free_scan_info_map = hash_map_remove(interface->scan_info_map, key);
            pthread_mutex_unlock(&interface->scan_info_mutex);
            free(free_scan_info_map);
        } else {
            return RETURN_ERR;
        }
#ifndef FEATURE_SINGLE_PHY
    } else {
        return RETURN_ERR;
    }
#else //FEATURE_SINGLE_PHY
    }
#endif //FEATURE_SINGLE_PHY
    return RETURN_OK;
}

static int spurious_frame_register_handler(struct nl_msg *msg, void *arg)
{
    wifi_hal_dbg_print("%s:%d:Enter\n", __func__, __LINE__);

    return NL_SKIP;
}

#ifdef EAPOL_OVER_NL
int nl80211_register_bss_frames(wifi_interface_info_t *interface)
{
    int err = 1;

    if (interface->bss_frames_registered == 1) {
        wifi_hal_info_print("%s:%d: bss frames handler already registered for %s\n", __func__,
                __LINE__, interface->name);
        return 0;
    }

    wifi_hal_info_print("%s:%d: register bss frames handler for %s\n", __func__, __LINE__,
            interface->name);

    interface->bss_nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (interface->bss_nl_cb == NULL) {
        wifi_hal_error_print("%s:%d: failed to alloc nl_cb for %s interface\n", __func__, __LINE__,
                interface->name);
        return -1;
    }

    nl_cb_set(interface->bss_nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(interface->bss_nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_bss_frame, interface);
    nl_cb_set(interface->bss_nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    interface->bss_nl_connect_event = nl_create_handle(interface->bss_nl_cb, "connect");
    if (interface->bss_nl_connect_event == NULL) {
        wifi_hal_error_print("%s:%d: failed to create nl handle for %s interface\n", __func__,
                __LINE__, interface->name);
        goto error;
    }

    /*
     * libnl uses a pretty small buffer (32 kB that gets converted to 64 kB)
     * by default. It is possible to hit that limit in some cases where
     * operations are blocked. Try to increase the buffer to make
     * this less likely to occur.
     */
    err = nl_socket_set_buffer_size((struct nl_sock *)interface->bss_nl_connect_event, NL_SOCK_MAX_BUF_SIZE, 0);
    if (err < 0) {
        wifi_hal_error_print("nl80211: Could not set nl_socket RX buffer size: %s",
                nl_geterror(err));
        /* continue anyway with the default (smaller) buffer */
    }

    nl_socket_set_nonblocking((struct nl_sock *)interface->bss_nl_connect_event);

    interface->bss_nl_connect_event_fd = nl_socket_get_fd((struct nl_sock *)
            interface->bss_nl_connect_event);
    wifi_hal_dbg_print("%s:%d: nl80211 bss socket descriptor: %d\n", __func__, __LINE__,
            interface->bss_nl_connect_event_fd);

    interface->bss_frames_registered = 1;

    return 0;

error:
    if (interface->bss_nl_cb) {
        nl_cb_put(interface->bss_nl_cb);
        interface->bss_nl_cb = NULL;
    }
    if (interface->bss_nl_connect_event) {
        nl_destroy_handles(&interface->bss_nl_connect_event);
        interface->bss_nl_connect_event = NULL;
    }
    return -1;
}
#endif

int nl80211_register_spurious_frames(wifi_interface_info_t *interface)
{
    struct nl_msg *msg = NULL;
    int ret = 0;

    if (interface->spurious_frames_registered == 1) {
        wifi_hal_info_print("%s:%d: spurious frames handler already registered for %s\n", __func__,
            __LINE__, interface->name);
        return 0;
    }

    wifi_hal_info_print("%s:%d: register spurious frames handler for %s\n", __func__, __LINE__,
        interface->name);

    interface->spurious_nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (interface->spurious_nl_cb == NULL) {
        wifi_hal_error_print("%s:%d: failed to alloc nl_cb for %s interface\n", __func__, __LINE__,
            interface->name);
        return -1;
    }

    nl_cb_set(interface->spurious_nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(interface->spurious_nl_cb, NL_CB_VALID, NL_CB_CUSTOM, process_mgmt_frame, interface);

    interface->spurious_nl_event = nl_create_handle(g_wifi_hal.nl_cb, "spurious");
    if (interface->spurious_nl_event == NULL) {
        wifi_hal_error_print("%s:%d: failed to create nl handle for %s interface\n", __func__,
            __LINE__, interface->name);
        goto error;
    }

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, NULL, 0, NL80211_CMD_UNEXPECTED_FRAME);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d: failed to create message for %s interface\n", __func__,
            __LINE__, interface->name);
        goto error;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, interface->index) < 0) {
        wifi_hal_error_print("%s:%d: failed set interface index in message for %s interface\n",
            __func__, __LINE__, interface->name);
        goto error;
    }

    ret = execute_send_and_recv(interface->spurious_nl_cb, interface->spurious_nl_event, msg,
        spurious_frame_register_handler, interface, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d: failed to register for spurious frames on interface %s, "
            "error: %d (%s)\n", __func__, __LINE__, interface->name, ret, strerror(-ret));
        goto error;
    }

    interface->spurious_nl_event_fd = nl_socket_get_fd((struct nl_sock *)
        interface->spurious_nl_event);
    wifi_hal_dbg_print("%s:%d: nl80211 spurious socket descriptor: %d\n", __func__, __LINE__,
        interface->spurious_nl_event_fd);

    interface->spurious_frames_registered = 1;

    return 0;

error:
    if (interface->spurious_nl_cb) {
        nl_cb_put(interface->spurious_nl_cb);
        interface->spurious_nl_cb = NULL;
    }
    if (interface->spurious_nl_event) {
        nl_destroy_handles(&interface->spurious_nl_event);
        interface->spurious_nl_event = NULL;
    }
    return -1;
}


int wifi_drv_set_operstate(void *priv, int state)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
#ifndef EAPOL_OVER_NL
    struct sockaddr_ll sockaddr;    
    int sock_fd;
    const char *ifname;
#endif

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_info_print("%s:%d: Enter, interface:%s bridge:%s driver operation state:%d\n",
            __func__, __LINE__, interface->name, vap->bridge_name, state);

#ifndef CONFIG_WIFI_EMULATOR
    if (interface->vap_configured == true) {
        if (state == 1) {
            wifi_hal_dbg_print("%s:%d: VAP already configured\n", __func__, __LINE__);
            return 0;
        }
        else {
            wifi_hal_dbg_print("%s:%d: Configured VAP is being disabled\n", __func__, __LINE__);
            return 0;
        }
    } else {
        if (state == 0) {
            wifi_hal_dbg_print("%s:%d: VAP is not configured\n", __func__, __LINE__);
            return 0;
        }
    }
#endif

    if (vap->u.bss_info.enabled == false && vap->u.sta_info.enabled == false) {
        wifi_hal_dbg_print("%s:%d: VAP not enabled\n", __func__, __LINE__);
        return 0;
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        if (nl80211_register_mgmt_frames(interface) != 0) {
            wifi_hal_error_print("%s:%d: Failed to register for management frames\n", __func__, __LINE__);
            return -1;
        }
        if (nl80211_register_spurious_frames(interface) != 0) {
            wifi_hal_error_print("%s:%d: Failed to register spurious frames\n", __func__, __LINE__);
            return -1;
        }
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        if (interface->acl_map == NULL) {
            interface->acl_map = hash_map_create();
        }
    }
#ifndef EAPOL_OVER_NL
#ifndef CONFIG_WIFI_EMULATOR
    if (vap->vap_mode == wifi_vap_mode_ap) {
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock_fd < 0) {
            wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, vap->bridge_name);
            return -1;
        }
    } else {
        sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
        if (sock_fd < 0) {
            wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, vap->bridge_name);
            return -1;
        }
    }
#else
    if ((interface->vap_configured == true)  && (vap->vap_mode == wifi_vap_mode_sta)) {
	 if (interface->u.sta.sta_sock_fd != 0) {
             close(interface->u.sta.sta_sock_fd);
             interface->u.sta.sta_sock_fd = 0;
         }
    }
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        wifi_hal_error_print("%s:%d: Failed to open raw socket on bridge: %s\n", __func__, __LINE__, vap->bridge_name);
        return -1;
    }
#endif

#ifdef CONFIG_WIFI_EMULATOR
    ifname = vap->bridge_name;
#else
    ifname = (vap->vap_mode == wifi_vap_mode_ap) ? vap->bridge_name:interface->name;
#endif
    memset(&sockaddr, 0, sizeof(struct sockaddr_ll));
    sockaddr.sll_family   = AF_PACKET;
    sockaddr.sll_ifindex  = if_nametoindex(ifname);

    if (vap->vap_mode == wifi_vap_mode_ap) {
        sockaddr.sll_protocol = htons(ETH_P_ALL);
        if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
            wifi_hal_error_print("%s:%d: Error in setting sockopt err:%d\n", __func__, __LINE__, errno);
            close(sock_fd);
            return -1;
        }
    } else {
#ifndef CONFIG_WIFI_EMULATOR
        sockaddr.sll_protocol = htons(ETH_P_EAPOL);
#else
        sockaddr.sll_protocol = htons(ETH_P_ALL);
#endif
    }

    if (bind(sock_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        wifi_hal_error_print("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
        close(sock_fd);
        return -1;
    }

    if (vap->vap_mode == wifi_vap_mode_ap) {
        interface->u.ap.br_sock_fd = sock_fd;
    } else if (vap->vap_mode == wifi_vap_mode_sta) {
        interface->u.sta.sta_sock_fd = sock_fd;
    }

#endif
    interface->bridge_configured = true;
    interface->vap_configured = true;
    wifi_hal_info_print("%s:%d: Exit, interface:%s bridge:%s driver configured for 802.11\n",
            __func__, __LINE__, interface->name, vap->bridge_name);

    return 0;
}

int wifi_drv_get_capa(void *priv, struct wpa_driver_capa *capa)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void wifi_drv_deinit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

}

void wifi_drv_global_deinit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

void *wifi_drv_global_init(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_associate(void *priv, struct wpa_driver_associate_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_authenticate(void *priv, struct wpa_driver_auth_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_deauthenticate(void *priv, const u8 *addr, u16 reason_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_abort_scan(void *priv, u64 scan_cookie)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

struct wpa_scan_results * wifi_drv_get_scan_results(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

int wifi_drv_stop_sched_scan(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sched_scan(void *priv, struct wpa_driver_scan_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_scan2(void *priv,
                struct wpa_driver_scan_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_bssid(void *priv, u8 *bssid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_get_ssid(void *priv, u8 *ssid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
#ifdef CONFIG_WIFI_EMULATOR
    if (ssid == NULL) {
        wifi_hal_dbg_print("%s:%d: NULL Pointer\n", __func__, __LINE__);
        return 0;
    }

    wifi_interface_info_t *interface = NULL;
    interface = (wifi_interface_info_t *)priv;

    if (interface->wpa_s.current_bss == NULL) {
       return -1;
    }
    if (interface->wpa_s.current_bss->ssid != NULL) {
        os_memcpy(ssid, interface->wpa_s.current_ssid->ssid, strlen(interface->wpa_s.current_ssid->ssid) + 1);
    } else {
        return 0;
    }
    return interface->wpa_s.current_bss->ssid_len;
#else
    return 0;
#endif
}

#ifdef CONFIG_WIFI_EMULATOR
int wifi_supplicant_drv_associate(void *priv, struct wpa_driver_associate_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    wifi_interface_info_t *interface = NULL;
    interface = (wifi_interface_info_t *)priv;
    struct nl_msg *msg;
    int ret;
    u32 suite;

    int ver = 0;
    u32 cipher;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_ASSOCIATE)) == NULL) {
        return -1;
    }

    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->bssid);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ,
            params->freq.freq);
    nla_put(msg, NL80211_ATTR_SSID, params->ssid_len,
            params->ssid);

    //If None dont set the NL80211_ATTR_AKM_SUITES
    //else get the NL80211_ATTR_AKM_SUITES
    if (!(params->key_mgmt_suite & WPA_KEY_MGMT_NONE)) {
        cipher = wpa_cipher_to_cipher_suite(params->pairwise_suite);
        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                cipher);
        cipher = wpa_cipher_to_cipher_suite(params->group_suite);
        nla_put_u32(msg, NL80211_ATTR_CIPHER_SUITE_GROUP, cipher);
        if (params->wpa_proto & WPA_PROTO_WPA)
            ver |= NL80211_WPA_VERSION_1;
        if (params->wpa_proto & WPA_PROTO_RSN)
            ver |= NL80211_WPA_VERSION_2;

        nla_put_u32(msg, NL80211_ATTR_WPA_VERSIONS, ver);

        if (params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X)
            suite = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
        if (params->key_mgmt_suite & WPA_KEY_MGMT_PSK)
            suite = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
        if (params->key_mgmt_suite & WPA_KEY_MGMT_SAE)
            suite = RSN_AUTH_KEY_MGMT_SAE;
        if (params->key_mgmt_suite & WPA_KEY_MGMT_IEEE8021X_SHA256)
            suite = RSN_AUTH_KEY_MGMT_802_1X_SHA256;
        if (params->key_mgmt_suite & WPA_KEY_MGMT_PSK_SHA256)
            suite = RSN_AUTH_KEY_MGMT_PSK_SHA256;

        wifi_hal_dbg_print("%s:%d: suite : 0x%x\n", __func__, __LINE__,
                suite);
        nla_put_u32(msg, NL80211_ATTR_AKM_SUITES, suite);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    }

    if (params->rrm_used) {
        nla_put_flag(msg, NL80211_ATTR_USE_RRM);
    }
    nla_put(msg, NL80211_ATTR_IE, params->wpa_ie_len, params->wpa_ie);
    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }
    wifi_hal_error_print("%s:%d: associate command failed: ret=%d (%s)\n", __func__, __LINE__,
            ret, strerror(-ret));

    return -1;
}

int wifi_supplicant_drv_authenticate(void *priv, struct wpa_driver_auth_params *params)
{
    wifi_interface_info_t *interface = NULL;
    interface = (wifi_interface_info_t *)priv;
    struct nl_msg *msg;
    int ret;
    wifi_vap_security_t *security;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    security = &interface->vap_info.u.sta_info.security;

    if ((msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_AUTHENTICATE)) == NULL) {
        return -1;
    }
    nla_put(msg, NL80211_ATTR_SSID, params->ssid_len, params->ssid);
    nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->bssid);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, params->freq);

    if ((security->mode == wifi_security_mode_wpa3_personal) ||
        (security->mode == wifi_security_mode_wpa3_transition) ||
        (security->mode == wifi_security_mode_wpa3_compatibility)) {
        nla_put(msg, NL80211_ATTR_SAE_DATA, params->auth_data_len, params->auth_data);
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_SAE);
    } else {
        nla_put_u32(msg, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    }

    ret = nl80211_send_and_recv(msg, NULL, &g_wifi_hal, NULL, NULL);
    if (ret == 0) {
        return 0;
    }
    wifi_hal_error_print("%s:%d: autheticate command failed: ret=%d (%s)\n", __func__, __LINE__,
            ret, strerror(-ret));
    return -1;
}

int wifi_supplicant_drv_get_bssid(void *priv, u8 *bssid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    wifi_interface_info_t *interface = NULL;
    interface = (wifi_interface_info_t *)priv;

    os_memcpy(bssid, interface->wpa_s.current_bss->bssid, ETH_ALEN);
    return 0;
}
#endif //CONFIG_WIFI_EMULATOR

int     wifi_drv_send_eapol(void *priv, const u8 *addr, const u8 *data,
                    size_t data_len, int encrypt,
                    const u8 *own_addr, u32 flags)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

static void * wifi_driver_nl80211_init(void *ctx, const char *ifname,
                                       void *global_priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return NULL;
}

void* wifi_drv_init(struct hostapd_data *hapd, struct wpa_init_params *params)
{
    wifi_interface_info_t *interface;
    //wifi_driver_data_t *drv;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;

    interface = (wifi_interface_info_t *)params->global_priv;
    vap = &interface->vap_info;

    radio = get_radio_by_rdk_index(vap->radio_index);
    //XXX check wiphy info? wpa_driver_nl80211_get_info hostapd

    wifi_hal_dbg_print("%s:%d: Enter radio index: %d interface: %s vap index: %d\n", __func__, __LINE__,
        radio->index, interface->name, vap->vap_index);

    //drv = (wifi_driver_data_t *)&radio->driver_data;

#ifdef EAPOL_OVER_NL
    if (nl80211_register_bss_frames(interface) != 0) {
        wifi_hal_error_print("%s:%d: Failed to register for bss frames\n", __func__, __LINE__);
        return NULL;
    }
#endif

    return params->global_priv;
}

int     wifi_drv_set_privacy(void *priv, int enabled)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int     wifi_drv_set_ssid(void *priv, const u8 *buf, int len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int     wifi_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int    wifi_drv_send_radius_eap_failure(void *priv, int failure_code)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    //Call the radius_eap callback here to onewifi
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL) {
        return -1;
    }

    for (int i = 0; i < callbacks->num_radius_eap_cbs; i++) {
        if (callbacks->radius_eap_cb[i] != NULL) {
            callbacks->radius_eap_cb[i](vap->vap_index, failure_code);
        }
    }
    return 0;
}

int wifi_drv_send_radius_fallback_and_failover(void *priv, int radius_switch_reason)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL) {
        return -1;
    }

    for (int i = 0; i < callbacks->num_radius_fallback_failover_cbs; i++) {
        if (callbacks->radius_failover_fallback_cbs[i] != NULL) {
            callbacks->radius_failover_fallback_cbs[i](vap->vap_index, radius_switch_reason);
        }
    }
    return 0;
}

#if HOSTAPD_VERSION >= 210 //2.10
int     wifi_drv_set_key(void *priv, struct wpa_driver_set_key_params *params)
#else
int     wifi_drv_set_key(const char *ifname, void *priv, enum wpa_alg alg,
                    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
                    size_t seq_len, const u8 *key, size_t key_len)
#endif
{
    wifi_interface_info_t *interface;
    struct nl_msg *msg = NULL;
    unsigned int suite;
    int ret;
    wifi_vap_info_t *vap;

    interface = (wifi_interface_info_t *)priv;
    vap = &interface->vap_info;

    wifi_hal_dbg_print("%s:%d: ifname:%s vap_index:%d\n", __func__, __LINE__, interface->name, vap->vap_index);
    //wifi_hal_dbg_print("%s:%d: ifname: %s\n", __func__, __LINE__, interface->name);
    //wifi_hal_dbg_print("%s:%d: key Info: index:%d length:%d alg:%s\n", __func__, __LINE__, key_idx, key_len, wpa_alg_to_string(alg));
    //my_print_hex_dump(key_len, key);

#if HOSTAPD_VERSION < 210 //2.10
    if (alg == WPA_ALG_NONE) {
        return -1;
    }

    suite = wpa_alg_to_cipher_suite(alg, key_len);
    if (suite == 0) {
        wifi_hal_error_print("%s:%d: Failed to get cipher suite for alg:%s\n", __func__, __LINE__, wpa_alg_to_string(alg));
        return -1;
    }
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_NEW_KEY);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d:Failed to allocate nl80211 message\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_KEY_DATA, key_len, key);
    nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, suite);
    if (seq && seq_len) {
        nla_put(msg, NL80211_ATTR_KEY_SEQ, seq_len, seq);
    }

    if (addr && !is_broadcast_ether_addr(addr)) {
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);
        if (alg != WPA_ALG_WEP && key_idx && !set_tx) {
            nla_put_u32(msg, NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
        }
    } else if (addr && is_broadcast_ether_addr(addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        if (!types) {
            nl80211_nlmsg_clear(msg);
            nlmsg_free(msg);
        }
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        nla_nest_end(msg, types);
    }

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx);

    if ((ret = nl80211_send_and_recv(msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Failed new key: %d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: new key success for ifname:%s vap_index:%d\n", __func__, __LINE__, interface->name, vap->vap_index);

     if ((addr && !is_broadcast_ether_addr(addr)) && (vap->vap_mode != wifi_vap_mode_sta))
          return 0;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_KEY);

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, key_idx);
    nla_put_flag(msg, (alg == WPA_ALG_IGTK ||
                alg == WPA_ALG_BIP_GMAC_128 ||
                alg == WPA_ALG_BIP_GMAC_256 ||
                alg == WPA_ALG_BIP_CMAC_256) ?
            NL80211_ATTR_KEY_DEFAULT_MGMT :
            NL80211_ATTR_KEY_DEFAULT);

    if (addr && is_broadcast_ether_addr(addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        nla_nest_end(msg, types);
    } else if (addr) {
#else //hostapd 2.10
      int skip_set_key = 1;
    if (params->alg == WPA_ALG_NONE) {
        return -1;
    }
    suite = wpa_alg_to_cipher_suite(params->alg, params->key_len);
    if (suite == 0) {
        wifi_hal_dbg_print("%s:%d: Failed to get cipher suite for alg:%s\n", __func__, __LINE__, wpa_alg_to_string(params->alg));
        return -1;
    }
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_NEW_KEY);
    if (msg == NULL) {
        wifi_hal_dbg_print("%s:%d:Failed to allocate nl80211 message\n", __func__, __LINE__);
        return -1;
    }

    nla_put(msg, NL80211_ATTR_KEY_DATA, params->key_len, params->key);
    nla_put_u32(msg, NL80211_ATTR_KEY_CIPHER, suite);
    if (params->seq && params->seq_len) {
        nla_put(msg, NL80211_ATTR_KEY_SEQ, params->seq_len, params->seq);
    }

    if (params->addr && !is_broadcast_ether_addr(params->addr)) {
        nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr);
        if ((params->key_flag & KEY_FLAG_PAIRWISE_MASK) == KEY_FLAG_PAIRWISE_RX || (params->key_flag & KEY_FLAG_PAIRWISE_MASK) == KEY_FLAG_PAIRWISE_RX_TX_MODIFY) {
          nla_put_u8(msg, NL80211_KEY_MODE, params->key_flag == KEY_FLAG_PAIRWISE_RX ? NL80211_KEY_NO_TX : NL80211_KEY_SET_TX);
        }
        else if ((params->key_flag & KEY_FLAG_GROUP_MASK) == KEY_FLAG_GROUP_RX) {
          nla_put_u32(msg, NL80211_KEY_TYPE, NL80211_KEYTYPE_GROUP);
        }
        else if (!(params->key_flag & KEY_FLAG_PAIRWISE)) {
          wifi_hal_dbg_print("%s:%d: key_flag missing PAIRWISE when setting a pairwise key\n",__func__,__LINE__);
      	  ret = -EINVAL;
        }
        else if (params->alg == WPA_ALG_WEP && (params->key_flag & KEY_FLAG_RX_TX) == KEY_FLAG_RX_TX) {
          wifi_hal_dbg_print("%s:%d:unicast WEP key\n",__func__,__LINE__);
          skip_set_key = 0;
        }
        else {
          wifi_hal_dbg_print("%s:%d:pairwise key\n",__func__,__LINE__);
        }
    }
    else if ((params->key_flag & KEY_FLAG_PAIRWISE) || !(params->key_flag & KEY_FLAG_GROUP)) {
      wifi_hal_dbg_print("%s:%d:invalid key_flag for a broadcast key\n",__func__,__LINE__);
      ret = -EINVAL;
    }
    else {
      wifi_hal_dbg_print("%s:%d:Broadcast key\n",__func__,__LINE__);
      if (params->key_flag & KEY_FLAG_DEFAULT)
        skip_set_key = 0;
    }
    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, params->key_idx);

    if ((ret = nl80211_send_and_recv(msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_dbg_print("%s:%d: Failed new key: %d(%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return -1;
    }

    wifi_hal_dbg_print("%s:%d: new key success for ifname:%s vap_index:%d\n", __func__, __LINE__, interface->name, vap->vap_index);
    if ((ret == -ENOENT || ret == -ENOLINK) && params->alg == WPA_ALG_NONE)
      ret = 0;
    if (ret || skip_set_key)
      return ret;

    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_SET_KEY);

    nla_put_u8(msg, NL80211_ATTR_KEY_IDX, params->key_idx);
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT) || defined (TCHCBRV2_PORT) || defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_BANANAPI_R4_)
    // NL80211_KEY_DEFAULT_BEACON enum is not defined in broadcom nl80211.h header
    nla_put_flag(msg, wpa_alg_bip(params->alg) ? NL80211_ATTR_KEY_DEFAULT_MGMT : NL80211_ATTR_KEY_DEFAULT);
#else
    // NL80211_KEY_DEFAULT_BEACON enum is defined in wave-drv nl80211.h header
    nla_put_flag(msg, wpa_alg_bip(params->alg) ?
                 (params->key_idx == 6 || params->key_idx == 7 ?
                  NL80211_KEY_DEFAULT_BEACON :
                  NL80211_ATTR_KEY_DEFAULT_MGMT) :
                 NL80211_ATTR_KEY_DEFAULT);
#endif

    if (params->addr && is_broadcast_ether_addr(params->addr)) {
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
        nla_nest_end(msg, types);
    } else if (params->addr) {
#endif
        struct nlattr *types;

        types = nla_nest_start(msg, NL80211_ATTR_KEY_DEFAULT_TYPES);
        nla_put_flag(msg, NL80211_KEY_DEFAULT_TYPE_UNICAST);
        nla_nest_end(msg, types);
    }

    if ((ret = nl80211_send_and_recv(msg, NULL, (void *)-1, NULL, NULL))) {
        wifi_hal_error_print("%s:%d: Failed to set key: %d (%s)\n", __func__, __LINE__, ret, strerror(-ret));
        return -1;
    }

    wifi_hal_info_print("%s:%d:key set success for ifname:%s vap_index:%d\n", __func__, __LINE__, interface->name, vap->vap_index);

    return 0;
}

int wifi_drv_set_authmode(void *priv, int auth_algs)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_ieee8021x(void *priv, struct wpa_bss_params *params)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_opt_ie(void *priv, const u8 *ie, size_t ie_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
                int reassoc, u16 status_code, const u8 *ie, size_t len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                      const struct wpabuf *proberesp,
                      const struct wpabuf *assocresp)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_wps_event_notify_cb(void *ctx, unsigned int event, void *data)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_wps_event_t event_data;

    memset(&event_data, 0, sizeof(event_data));

    wifi_hal_dbg_print("%s:%d: Enter wps event:%d\n", __func__, __LINE__, event);
    interface = (wifi_interface_info_t *)ctx;
    if (interface != NULL) {
        vap = &interface->vap_info;
        if (vap != NULL) {
            wifi_hal_dbg_print("%s:%d: Enter wps event vap->vap_index:%d\n", __func__, __LINE__, vap->vap_index);
            event_data.vap_index = vap->vap_index;
        }
    }

    event_data.event = event;
    event_data.wps_data = (unsigned char *)data;
    wifi_hal_wps_event(event_data);

    return 0;
}

int wifi_drv_sta_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx, u8 *seq)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

int wifi_drv_commit(void *priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#if defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT)
//Selects a Non-DFS Channel from the list of available channels
short get_non_dfs_chan(wifi_interface_info_t *interface, u8 *oper_centr_freq_seg0_idx, u8 *oper_centr_freq_seg1_idx,
                                              int *secondary_channel)
{
    struct hostapd_channel_data *chan = NULL;
#if HOSTAPD_VERSION >= 210 // 2.10
    enum dfs_channel_type channel_type = DFS_AVAILABLE;

    chan = dfs_get_valid_channel(&interface->u.ap.iface, secondary_channel,
                                    oper_centr_freq_seg0_idx,
                                    oper_centr_freq_seg1_idx,
                                    channel_type);
#endif /* HOSTAPD_VERSION >= 210 */
    if (chan == NULL) {
        wifi_hal_error_print("%s:%d failed to get new channel, return default\n", __func__,
            __LINE__);
        return 36;
    }

    wifi_hal_info_print("%s:%d Selected non-dfs channel:%u \n", __FUNCTION__, __LINE__, chan->chan);

    return chan->chan;
}
#endif /* defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) */

#if defined(CMXB7_PORT)
//To set a channel in the primary interface of the radio
int prim_interface_set_freq(wifi_radio_info_t *radio, wifi_interface_info_t *interface, int freq, u8 channel, int sec_chan_offset, int ht_enabled, int bw, int cf1, char *country)
{
    wifi_radio_operationParam_t *param;
    int res = 0;
    u8 seg0;
    cf1 = freq;

    param = &radio->oper_param;

    switch (bw) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            cf1 = freq + sec_chan_offset*10;
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_80MHZ);
            cf1 = get_bw80_center_freq(param, country);
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_160MHZ);
            cf1 = get_bw160_center_freq(param, country);
            break;

        default:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            break;
    }

    ieee80211_freq_to_chan(cf1, &seg0);

    wifi_hal_info_print("%s:%d name:%s freq:%d cf1:%d sec_chan:%d radio_index:%u channel:%u bw:%d ht_enabled:%d \n", __func__, __LINE__,
                        interface->name, freq, cf1, sec_chan_offset, radio->index, channel, bw, ht_enabled);

    interface->u.ap.iface.freq = freq;
    hostapd_set_oper_centr_freq_seg1_idx(interface->u.ap.hapd.iconf, 0);
    hostapd_set_oper_centr_freq_seg0_idx(interface->u.ap.hapd.iconf, seg0);

    res = hostapd_set_freq(&interface->u.ap.hapd, interface->u.ap.hapd.iconf->hw_mode, freq,
                channel,
                interface->u.ap.hapd.iconf->enable_edmg,
                interface->u.ap.hapd.iconf->edmg_channel,
                ht_enabled,
                interface->u.ap.hapd.iconf->ieee80211ac,
                interface->u.ap.hapd.iconf->ieee80211ax,
                interface->u.ap.hapd.iconf->ieee80211be,
                sec_chan_offset,
                hostapd_get_oper_chwidth(interface->u.ap.hapd.iconf),
                hostapd_get_oper_centr_freq_seg0_idx(
                interface->u.ap.hapd.iconf),
                hostapd_get_oper_centr_freq_seg1_idx(
                interface->u.ap.hapd.iconf));

    if(res) {
        wifi_hal_error_print("%s:%d hostapd_set_freq failed\n",__FUNCTION__, __LINE__);
    } else{
        wifi_hal_info_print("%s:%d hostapd_set_freq succeeded for freq:%d \n",__FUNCTION__, __LINE__, freq);
    }

    return res;
}

//To enable vap interfaces after CAC Finish/Abort
int nl80211_interface_reenable(wifi_radio_info_t *radio, int freq)
{
    wifi_interface_info_t *dfs_interface;

    dfs_interface = hash_map_get_first(radio->interface_map);

    while(dfs_interface != NULL) {
        if(dfs_interface->bss_started && !dfs_interface->interface_status) {
            if(nl80211_interface_enable(dfs_interface->name, true)) {
                hostapd_set_state(&dfs_interface->u.ap.iface, HAPD_IFACE_DISABLED);
            } else {
                hostapd_set_state(&dfs_interface->u.ap.iface, HAPD_IFACE_ENABLED);
            }

            dfs_interface->u.ap.hapd.iface->freq = freq;
            dfs_interface->u.ap.hapd.reenable_beacon = 1;
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            if(ieee802_11_update_beacons(&dfs_interface->u.ap.iface)) {
                wifi_hal_error_print("%s:%d ieee802_11_update_beacons Failed\n", __func__, __LINE__);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

            dfs_interface->u.ap.hapd.reenable_beacon = 0;
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            if(ieee802_11_update_beacons(&dfs_interface->u.ap.iface)) {
                wifi_hal_error_print("%s:%d ieee802_11_update_beacons Failed for SET_BEACON\n", __func__, __LINE__);
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

            if(NULL != dfs_interface->u.ap.iface.current_mode) {
                wifi_hal_error_print("%s:%d current_mode set for interface:%s \n", __FUNCTION__, __LINE__, dfs_interface->name);
            }
        }
        dfs_interface = hash_map_get_next(radio->interface_map, dfs_interface);
    }
    dfs_interface = NULL;

    return 0;
}
#endif /* defined(CMXB7_PORT) */

#if defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT)
//To Notify OneWiFi about channel change
int dfs_chan_change_event(int radio_index, u8 channel, int bw, u8 op_class) {
    wifi_channel_change_event_t radio_channel_param;
    wifi_device_callbacks_t *callbacks;

    callbacks = get_hal_device_callbacks();
    memset(&radio_channel_param, 0, sizeof(radio_channel_param));

    if ((callbacks != NULL) && (callbacks->channel_change_event_callback)) {
        radio_channel_param.radioIndex = radio_index;
        radio_channel_param.event = WIFI_EVENT_CHANNELS_CHANGED;
        radio_channel_param.channel = channel;
        radio_channel_param.channelWidth = bw;
        radio_channel_param.op_class = op_class;
        callbacks->channel_change_event_callback(radio_channel_param);
    }

    return 0;
}
#endif /* defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) */

//To Disable and enable primary interface of the radio
int reenable_prim_interface(wifi_radio_info_t *radio) {
    wifi_interface_info_t *prim_interface;

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        prim_interface = get_primary_interface(radio);
    }
    else {
        prim_interface = get_private_vap_interface(radio);
    }

    if(prim_interface == NULL) {
        wifi_hal_error_print("%s prim_interface is NULL\n", __FUNCTION__);
        return RETURN_ERR;
    }

    nl80211_enable_ap(prim_interface, false);
    nl80211_interface_enable(prim_interface->name, false);
    wifi_hal_info_print("%s Interface %s is down\n", __FUNCTION__, prim_interface->name);

    nl80211_interface_enable(prim_interface->name, true);
    wifi_hal_info_print("%s Interface %s is added\n", __FUNCTION__, prim_interface->name);

    return 0;
}

//Initiates the call to start CAC. Takes 1 min for CAC to complete
int nl80211_start_dfs_cac(wifi_radio_info_t *radio)
{
#ifdef CMXB7_PORT
    wifi_interface_info_t *interface, *dfs_interface;
    int sec_chan_offset = 0, freq = 5180, freq1 = -1;
    char country[8];
    u8 seg0 = 0, seg1 = 0;
    int res = 0;
    wifi_radio_operationParam_t *param, radio_param;

    param = &radio->oper_param;
    get_coutry_str_from_code(radio->oper_param.countryCode, country);
    freq = ieee80211_chan_to_freq(country, radio->oper_param.op_class, radio->oper_param.channel);
    freq1 = freq;
    sec_chan_offset = get_sec_channel_offset(radio, freq);

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY) {
        interface = get_primary_interface(radio);
    }
    else {
        interface = get_private_vap_interface(radio);
    }

    if(interface == NULL) {
        wifi_hal_error_print("%s:%d Primary interface is NULL \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch (radio->oper_param.channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            freq1 = freq + sec_chan_offset*10;
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_80MHZ);
            freq1 = get_bw80_center_freq(param, country);
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_160MHZ);
            freq1 = get_bw160_center_freq(param, country);
            break;

        default:
            hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_USE_HT);
            break;
    }

    if (freq1 == -1) {
        wifi_hal_error_print("%s:%d - No center frequency found\n", __func__, __LINE__);
        return -1;
    }

    ieee80211_freq_to_chan(freq1, &seg0);

    interface->u.ap.iface.freq = freq;
    interface->u.ap.hapd.iface->conf->secondary_channel = sec_chan_offset;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    hostapd_set_oper_centr_freq_seg1_idx(interface->u.ap.hapd.iconf, seg1);
    hostapd_set_oper_centr_freq_seg0_idx(interface->u.ap.hapd.iconf, seg0);
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d iface_freq:%d freq:%d freq1:%d chan:%u seg0:%u sec_chan_offset:%d opclass:%u \n",__FUNCTION__, __LINE__, interface->u.ap.iface.freq, freq, freq1,
                         radio->oper_param.channel, seg0, sec_chan_offset, radio->oper_param.op_class);

    update_hostap_iface(interface);

    dfs_interface = hash_map_get_first(radio->interface_map);
    while(dfs_interface != NULL) {
        if ( dfs_interface->bss_started && dfs_interface->vap_initialized) {
            nl80211_enable_ap(interface, false);
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            hostapd_bss_deinit_no_free(&interface->u.ap.hapd);
            hostapd_free_hapd_data(&interface->u.ap.hapd);
            if (interface->u.ap.hapd.conf != NULL && interface->u.ap.hapd.conf->ssid.wpa_psk != NULL && !interface->u.ap.hapd.conf->ssid.wpa_psk->next)
                hostapd_config_clear_wpa_psk(&interface->u.ap.hapd.conf->ssid.wpa_psk);
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

            res = nl80211_interface_enable(dfs_interface->name, false);
            if(!res) {
                hostapd_set_state(&dfs_interface->u.ap.iface, HAPD_IFACE_DISABLED);
                wifi_hal_info_print("%s:%d interface:%s Disabled for CAC \n",__FUNCTION__, __LINE__, dfs_interface->name);
            }
            else {
                wifi_hal_error_print("%s:%d Could not disable interface:%s\n",__FUNCTION__, __LINE__, dfs_interface->name);
            }
        }
        dfs_interface = hash_map_get_next(radio->interface_map, dfs_interface);
    }
    dfs_interface = NULL;

    update_hostap_config_params(radio);
    res = hostapd_handle_dfs(&interface->u.ap.iface);
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    interface->u.ap.iface.cac_started = 1;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if(res == 0) {
        wifi_hal_info_print("nl80211-%s:%d hostapd_handle_dfs success \n", __func__, __LINE__);
        dfs_chan_change_event(interface->vap_info.radio_index, radio->oper_param.channel, radio->oper_param.channelWidth, radio->oper_param.op_class);
        nl80211_dfs_cac_started(interface, freq, radio->iconf.ieee80211n, sec_chan_offset, radio->oper_param.channelWidth,
                                hostapd_get_oper_chwidth(interface->u.ap.hapd.iconf), freq1, 0);
        return RETURN_OK;
    } else {
        wifi_hal_error_print("nl80211-%s:%d hostapd_handle_dfs Failed \n", __func__, __LINE__);
        goto Fail;
    }

Fail:
    radio_param = radio->oper_param;
    radio_param.channel = get_non_dfs_chan(interface, &seg0, &seg1, &sec_chan_offset);

    wifi_hal_info_print("Radio will switch to a new channel %d seg0:%u seg1:%u sec_chan_offset:%d \n", radio_param.channel, seg0, seg1, sec_chan_offset);
    if( wifi_hal_setRadioOperatingParameters(interface->vap_info.radio_index, &radio_param) ) {
        wifi_hal_error_print("nl80211-%s:%d wifi_hal_setRadioOperatingParameters Failed \n", __func__, __LINE__);
    }

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    interface->u.ap.iface.cac_started = 0;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
#endif
    return RETURN_ERR;
}

int set_freq_and_interface_enable(wifi_interface_info_t *interface, wifi_radio_info_t *radio) {
#ifdef CMXB7_PORT
    int sec_chan_offset = 0, freq = 5180, cf1 = 0, ht_enabled = 0;
    char country[8];

    get_coutry_str_from_code(radio->oper_param.countryCode, country);
    freq = ieee80211_chan_to_freq(country, radio->oper_param.op_class, radio->oper_param.channel);
    sec_chan_offset = get_sec_channel_offset(radio, freq);

    ht_enabled = radio->iconf.ieee80211n;
    interface->u.ap.hapd.iface->conf->channel = radio->oper_param.channel;
    interface->u.ap.hapd.iface->freq = freq;

    wifi_hal_info_print("%s:%d name:%s freq:%d sec_chan:%d bandwidth:%d chan:%u \n", __func__, __LINE__,
            interface->name, freq, sec_chan_offset, radio->oper_param.channelWidth, radio->oper_param.channel);

    update_hostap_config_params(radio);
    if(( prim_interface_set_freq(radio, interface, freq, radio->oper_param.channel, sec_chan_offset, ht_enabled, radio->oper_param.channelWidth, cf1, country) )) {
        wifi_hal_error_print("nl80211-%s:%d prim_interface_set_freq Failed \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if ( nl80211_interface_reenable(radio, freq) ) {
        wifi_hal_error_print("nl80211-%s:%d nl80211_interface_reenable Failed \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    dfs_chan_change_event(interface->vap_info.radio_index, radio->oper_param.channel, radio->oper_param.channelWidth, radio->oper_param.op_class);
#endif
    return RETURN_OK;
}

//To notify hostapd about CAC start
int nl80211_dfs_cac_started(wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
    wifi_hal_info_print("%s:%d name:%s freq:%d cf1:%d cf2:%d sec_chan:%d bandwidth:%d bw:%d ht_enabled:%d \n", __func__, __LINE__,
                interface->name, freq, cf1, cf2, sec_chan_offset, bandwidth, bw, ht_enabled);

#ifdef CMXB7_PORT
    wifi_device_callbacks_t *callbacks;
    wifi_channel_change_event_t radio_channel_param;
    wifi_radio_info_t *radio =  NULL;

    callbacks = get_hal_device_callbacks();
    memset(&radio_channel_param, 0, sizeof(radio_channel_param));
    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return 0;
    }

    if ((callbacks != NULL) && (callbacks->channel_change_event_callback)) {
       radio_channel_param.radioIndex = interface->vap_info.radio_index;
       radio_channel_param.event = WIFI_EVENT_DFS_RADAR_DETECTED;
       radio_channel_param.sub_event = WIFI_EVENT_RADAR_CAC_STARTED;
       radio_channel_param.channel = radio->oper_param.channel;
       radio_channel_param.channelWidth = radio->oper_param.channelWidth;
       radio_channel_param.op_class = radio->oper_param.op_class;
       callbacks->channel_change_event_callback(radio_channel_param);
    }

    hostapd_dfs_start_cac(&interface->u.ap.iface, freq, ht_enabled, sec_chan_offset, bw, cf1, cf2);
#endif
    return 0;
}

//In case CAC is aborted, Non DFS Channel will be selected and set. Also enables vap interface.
int nl80211_dfs_radar_cac_aborted(wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
#ifdef CMXB7_PORT
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t radio_param;
    u8 oper_centr_freq_seg0_idx = 0;
    u8 oper_centr_freq_seg1_idx = 0;

    sec_chan_offset = 0; freq = 0;
    wifi_hal_info_print("%s:%d name:%s freq:%d cf1:%d cf2:%d sec_chan:%d bandwidth:%d ht_enabled:%d dfs_cac_ms:%u \n", __func__, __LINE__,
            interface->name, freq, cf1, cf2, sec_chan_offset, bw, ht_enabled, interface->u.ap.iface.dfs_cac_ms);

    if(!interface->u.ap.iface.cac_started) {
        return 0;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);

    radio_param = radio->oper_param;
    if(bandwidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_80MHZ);
        interface->u.ap.iface.conf->secondary_channel = get_sec_channel_offset(radio, freq);
    }

    radio_param.channel = get_non_dfs_chan(interface, &oper_centr_freq_seg0_idx, &oper_centr_freq_seg1_idx, &sec_chan_offset);
    radio_param.channelWidth = bandwidth;
    interface->u.ap.iface.dfs_cac_ms = 0;

    if(bandwidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        wifi_channelBandwidth_t Chan_width_80MHz = WIFI_CHANNELBANDWIDTH_80MHZ;
        wifi_hal_info_print("nl80211-%s:%d Setting bandwidth as 80MHz \n", __func__, __LINE__);
        radio_param.channelWidth = Chan_width_80MHz;
    }

    wifi_hal_info_print("Radio will switch to a new channel %d seg0:%u seg1:%u sec_chan_offset:%d dfs_cac_ms:%u \n", radio_param.channel, oper_centr_freq_seg0_idx, oper_centr_freq_seg1_idx, sec_chan_offset,
                        interface->u.ap.iface.dfs_cac_ms);

    if( wifi_hal_setRadioOperatingParameters(interface->vap_info.radio_index, &radio_param) ) {
        wifi_hal_error_print("nl80211-%s:%d wifi_hal_setRadioOperatingParameters Failed \n", __func__, __LINE__);
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    interface->u.ap.iface.cac_started = 0;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (update_channel_flags() != 0) {
        wifi_hal_error_print("%s:%d update_channel_flags failed \n", __func__, __LINE__);
    }

#endif
    return 0;
}

//After CAC is finished, DFS Channel is set and vap interfaces are enabled.
int nl80211_dfs_radar_cac_finished(wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
#ifdef CMXB7_PORT
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t radio_param;
    u8 channel;

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);

    ieee80211_freq_to_chan(freq, &channel);
    wifi_hal_info_print("%s:%d CAC is Over. Setting chan %u to Driver \n", __func__, __LINE__, channel);

    radio_param = radio->oper_param;
    radio_param.channel = channel;
    radio_param.channelWidth = bandwidth;

    if( wifi_hal_setRadioOperatingParameters(interface->vap_info.radio_index, &radio_param) ) {
        wifi_hal_error_print("nl80211-%s:%d wifi_hal_setRadioOperatingParameters Failed \n", __func__, __LINE__);
    }
    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    interface->u.ap.iface.cac_started = 0;
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (update_channel_flags() != 0) {
        wifi_hal_error_print("%s:%d update_channel_flags failed \n", __func__, __LINE__);
    }
#endif

    return 0;
}

/* Updates hostapd about DFS channel status
*/
int nl80211_dfs_pre_cac_expired (wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
#ifdef CMXB7_PORT
    if (update_channel_flags() != 0) {
        wifi_hal_error_print("%s:%d update_channel_flags failed \n", __func__, __LINE__);
    }

    wifi_hal_info_print("%s:%d Pre cac expired for freq:%d \n", __func__, __LINE__, freq);
#endif
    return 0;
}

//Updates hostapd that DFS Channel is available after No Operation Period
int nl80211_dfs_nop_finished (wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
    wifi_hal_info_print("%s:%d name:%s freq:%d cf1:%d cf2:%d sec_chan:%d bandwidth:%d ht_enabled:%d \n", __func__, __LINE__,
                interface->name, freq, cf1, cf2, sec_chan_offset, bw, ht_enabled);
#ifdef CMXB7_PORT
    if (update_channel_flags() != 0) {
        wifi_hal_error_print("%s:%d update_channel_flags failed \n", __func__, __LINE__);
    }
#endif
    return 0;
}

//When radio is operating in a DFS Channel and radar is detected, this function will switch radio to a Non-DFS Channel
int nl80211_dfs_radar_detected (wifi_interface_info_t *interface, int freq, int ht_enabled,
                               int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2)
{
#if defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT)
    wifi_radio_info_t *radio;
    wifi_radio_operationParam_t radio_param;
    u8 oper_centr_freq_seg0_idx = 0;
    u8 oper_centr_freq_seg1_idx = 0;
    int dfs_start = 52, dfs_end = 144;
    u8 orig_chan_width = 0;
    int orig_secondary_chan = 0;

    wifi_hal_info_print("%s:%d name:%s freq:%d cf1:%d cf2:%d sec_chan:%d bandwidth:%d ht_enabled:%d \n", __func__, __LINE__,
                    interface->name, freq, cf1, cf2, sec_chan_offset, bw, ht_enabled);

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);

    if(! ( radio->oper_param.channel >= dfs_start ) && ( radio->oper_param.channel <= dfs_end ) ) {
        wifi_hal_info_print("%s:%d Radio is operating in a non-dfs Channel \n", __FUNCTION__, __LINE__);
        return 0;
    }

#if defined(CMXB7_PORT)
    if (!interface->u.ap.iface.dfs_cac_ms) {
        return 0;
    }
#endif /* defined(CMXB7_PORT) */

    radio->radar_detected = true;

    radio_param = radio->oper_param;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    // downgrade bandwidth since 160MHz may not be available
    if (bandwidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        orig_chan_width = hostapd_get_oper_chwidth(interface->u.ap.hapd.iconf);
        orig_secondary_chan = interface->u.ap.iface.conf->secondary_channel;
        hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, CHANWIDTH_80MHZ);
        interface->u.ap.iface.conf->secondary_channel = get_sec_channel_offset(radio, freq);
    }

    radio_param.channel = get_non_dfs_chan(interface, &oper_centr_freq_seg0_idx,
        &oper_centr_freq_seg1_idx, &sec_chan_offset);
    radio_param.channelWidth = bandwidth;

    if (bandwidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        wifi_channelBandwidth_t Chan_width_80MHz = WIFI_CHANNELBANDWIDTH_80MHZ;
        wifi_hal_info_print("%s:%d Setting bandwidth to 80MHz\n", __func__, __LINE__);
        radio_param.channelWidth = Chan_width_80MHz;
        // restore original bandwidth to avoid beacon change before channel switch
        hostapd_set_oper_chwidth(interface->u.ap.hapd.iconf, orig_chan_width);
        interface->u.ap.iface.conf->secondary_channel = orig_secondary_chan;
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("Radio will switch to a new channel %d seg0:%u seg1:%u sec_chan_offset:%d \n", radio_param.channel, oper_centr_freq_seg0_idx, oper_centr_freq_seg1_idx, sec_chan_offset);

    if ( wifi_hal_setRadioOperatingParameters(interface->vap_info.radio_index, &radio_param) ) {
        wifi_hal_error_print("%s %d wifi_hal_setRadioOperatingParameters failed \n", __FUNCTION__, __LINE__);
    }

    if (update_channel_flags() != 0) {
        wifi_hal_error_print("%s:%d update_channel_flags failed \n", __func__, __LINE__);
    }

    dfs_chan_change_event(interface->vap_info.radio_index, radio->oper_param.channel, radio->oper_param.channelWidth, radio->oper_param.op_class);
#endif /* defined(CMXB7_PORT) || defined(TCXB7_PORT) || defined(TCXB8_PORT) */
    return RETURN_OK;
}

#if !defined(PLATFORM_LINUX)
int wifi_drv_get_aid(void *priv, u16 *aid, const u8 *addr)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_get_aid_t platform_get_aid_fn = get_platform_get_aid_fn();
    if (platform_get_aid_fn != NULL){
        return platform_get_aid_fn(priv, aid, addr);
    } else {
        return 0;
    }
}

int wifi_drv_free_aid(void *priv, u16 *aid)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_free_aid_t platform_free_aid_fn = get_platform_free_aid_fn();
    if (platform_free_aid_fn != NULL){
        return platform_free_aid_fn(priv, aid);
    } else {
        return 0;
    }
}
#endif

#ifdef CONFIG_VENDOR_COMMANDS
int wifi_drv_sync_done(void* priv)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_sync_done_t platform_sync_done_fn = get_platform_sync_done_fn();
    if (platform_sync_done_fn != NULL){
        return platform_sync_done_fn(priv);
    } else {
        return 0;
    }
}

#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
int wifi_drv_get_vap_measurements(void *priv, struct intel_vendor_vap_info *vap_info)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return platform_get_vap_measurements(priv, vap_info);
}

int wifi_drv_get_radio_info(void* priv, struct intel_vendor_radio_info *radio_info)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return platform_get_radio_info(priv, radio_info);
}

int wifi_drv_get_sta_measurements(void* priv, const u8 *sta_addr, struct intel_vendor_sta_info *sta_info)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return platform_get_sta_measurements(priv, sta_addr, sta_info);
}
#endif // CONFIG_USE_HOSTAP_BTM_PATCH

#endif

int wifi_drv_set_txpower(void* priv, uint txpower)
{
#ifdef CONFIG_VENDOR_COMMANDS
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_set_txpower_t platform_set_txpower_fn = get_platform_set_txpower_fn();
    if (platform_set_txpower_fn != NULL){
        return platform_set_txpower_fn(priv, txpower);
    } else {
        return 0;
    }
#else
    return 0;
#endif
}

int wifi_drv_set_offload_mode(void *priv, enum offload_mode offload_mode)
{
#ifdef CONFIG_VENDOR_COMMANDS
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_set_offload_mode_t platform_set_offload_mode_fn = get_platform_set_offload_mode_fn();
    if (platform_set_offload_mode_fn != NULL) {
        return platform_set_offload_mode_fn(priv, offload_mode);
    } else {
        return RETURN_OK;
    }
#else
    return RETURN_OK;
#endif
}

int wifi_drv_getApAclDeviceNum(int vap_index, uint *acl_count)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    platform_get_ApAclDeviceNum_t platform_get_ApAclDeviceNum_fn = get_platform_ApAclDeviceNum_fn();
    if (platform_get_ApAclDeviceNum_fn != NULL){
        return platform_get_ApAclDeviceNum_fn(vap_index, acl_count);
    } else {
        return 0;
    }
}

#ifdef CMXB7_PORT
static int nl80211_set_channel_dfs_state(void *priv,
                                enum nl80211_dfs_state dfs_state,
                                int freq, int dfs_time, int dfs_debug)
{
    struct nl_msg *msg;
    int ret = -1;
    wifi_interface_info_t *interface;
    interface = (wifi_interface_info_t *)priv;

    if (!(interface->u.ap.iface.drv_flags & WPA_DRIVER_FLAGS_RADAR) ) {
        wifi_hal_error_print("%s nl80211: Driver does not support radar \n", __FUNCTION__);
        return RETURN_ERR;
    }

    if (!(msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id,interface, 0, NL80211_CMD_SET_DFS_STATE)) ||
        (nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq)) ||
        (nla_put_u32(msg, NL80211_ATTR_DFS_STATE, dfs_state)) ||
        (nla_put_u32(msg, NL80211_ATTR_DFS_TIME, dfs_time)) ||
        (( dfs_debug && nla_put_flag(msg, NL80211_ATTR_DFS_STATE_FORCE)))) {
        wifi_hal_error_print("%s Set DFS State failed \n", __FUNCTION__);
        nlmsg_free(msg);
        return RETURN_ERR;
    }

    ret = nl80211_send_and_recv(msg, NULL, NULL, NULL, NULL);
    if( ret != 0) {
        wifi_hal_error_print("%s:%d: nl80211 send failed ret=%d (%s)\n", __func__, __LINE__,
        ret, strerror(-ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}
#endif

#if HOSTAPD_VERSION >= 210 // 2.10
static size_t wifi_drv_get_rnr_colocation_len(void *priv, size_t *current_len)
{
    int tbtt_count = 0;
    wifi_radio_info_t *radio;
    struct hostapd_data *hapd;
    size_t i, total_len = 0, len = *current_len;
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return 0;
    }

    if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        return 0;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio && radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
            break;
        }
    }

    if (i == g_wifi_hal.num_radios) {
        return 0;
    }

    interface = hash_map_get_first(radio->interface_map);
    while (interface) {
        if (!len || len + RNR_TBTT_HEADER_LEN + RNR_TBTT_INFO_LEN > 255) {
            len = RNR_HEADER_LEN;
            total_len += RNR_HEADER_LEN;
        }

        len += RNR_TBTT_HEADER_LEN;
        total_len += RNR_TBTT_HEADER_LEN;

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        for (;interface; interface = hash_map_get_next(radio->interface_map, interface)) {

            hapd = &interface->u.ap.hapd;
            if (!hapd->conf || !hapd->started) {
                continue;
            }

            if (len + RNR_TBTT_INFO_LEN > 255 || tbtt_count >= RNR_TBTT_INFO_COUNT_MAX) {
                break;
            }

            len += RNR_TBTT_INFO_LEN;
            total_len += RNR_TBTT_INFO_LEN;
            tbtt_count++;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    }

    if (!tbtt_count) {
        total_len = 0;
    } else {
        *current_len = len;
    }

    return total_len;
}

static u8* wifi_drv_get_rnr_colocation_ie(void *priv, u8 *eid, size_t *current_len)
{
    wifi_radio_info_t *radio;
    struct hostapd_data *hapd;
    size_t i, len = *current_len;
    u8 bss_param, tbtt_count = 0;
    u8 *tbtt_count_pos, *eid_start = eid, *size_offset = eid - len + 1;
    wifi_interface_info_t *interface = (wifi_interface_info_t *)priv;

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return eid_start;
    }

    if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        return eid_start;
    }

    for (i = 0; i < g_wifi_hal.num_radios; i++) {
        radio = get_radio_by_rdk_index(i);
        if (radio && radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
            break;
        }
    }

    if (i == g_wifi_hal.num_radios) {
        return eid_start;
    }

    interface = hash_map_get_first(radio->interface_map);
    while (interface) {
        if (!len || len + RNR_TBTT_HEADER_LEN + RNR_TBTT_INFO_LEN > 255) {
            eid_start = eid;
            *eid++ = WLAN_EID_REDUCED_NEIGHBOR_REPORT;
            size_offset = eid++;
            len = RNR_HEADER_LEN;
            tbtt_count = 0;
        }

        tbtt_count_pos = eid++;
        *eid++ = RNR_TBTT_INFO_LEN;
        *eid++ = radio->oper_param.op_class;
        *eid++ = radio->oper_param.channel;
        len += RNR_TBTT_HEADER_LEN;

        pthread_mutex_lock(&g_wifi_hal.hapd_lock);
        for (;interface; interface = hash_map_get_next(radio->interface_map, interface)) {

            bss_param = 0;
            hapd = &interface->u.ap.hapd;

            if (!hapd->conf || !hapd->started) {
                continue;
            }

            if (len + RNR_TBTT_INFO_LEN > 255 || tbtt_count >= RNR_TBTT_INFO_COUNT_MAX) {
                break;
            }

            *eid++ = RNR_NEIGHBOR_AP_OFFSET_UNKNOWN;
            memcpy(eid, hapd->conf->bssid, ETH_ALEN);
            eid += ETH_ALEN;
            memcpy(eid, &hapd->conf->ssid.short_ssid, 4);
            eid += 4;

            bss_param |= RNR_BSS_PARAM_MULTIPLE_BSSID;

            if (is_wifi_hal_vap_private(interface->vap_info.vap_index)) {
                bss_param |= RNR_BSS_PARAM_TRANSMITTED_BSSID;
            }

            if (is_6ghz_op_class(hapd->iconf->op_class) &&
                hapd->conf->unsol_bcast_probe_resp_interval) {
                bss_param |= RNR_BSS_PARAM_UNSOLIC_PROBE_RESP_ACTIVE;
            }

            bss_param |= RNR_BSS_PARAM_CO_LOCATED | RNR_BSS_PARAM_MEMBER_CO_LOCATED_ESS;

            *eid++ = bss_param;
            *eid++ = RNR_20_MHZ_PSD_MAX_TXPOWER - 1;
            len += RNR_TBTT_INFO_LEN;
            tbtt_count += 1;
        }
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

        *tbtt_count_pos = RNR_TBTT_INFO_COUNT(tbtt_count - 1);
        *size_offset = (eid - size_offset) - 1;
    }

    if (tbtt_count == 0) {
        return eid_start;
    }

    *current_len = len;

    return eid;
}

static size_t wifi_drv_mbssid_get_active_interface_num(wifi_radio_info_t *radio)
{
    wifi_interface_info_t *interface_iter;
    struct hostapd_data *bss;
    size_t num = 0;

    hash_map_foreach(radio->interface_map, interface_iter) {
        if (interface_iter->vap_info.vap_mode != wifi_vap_mode_ap) {
            continue;
        }

        bss = &interface_iter->u.ap.hapd;
        if (bss == NULL || bss->conf == NULL || !bss->started) {
            continue;
        }

        num++;
    }

    return num;
}

static u8 wifi_drv_mbssid_get_max_bssid_indicator(wifi_radio_info_t *radio)
{
    size_t num_bss_nontx;
    u8 max_bssid_ind = 0;

    if (radio->driver_data.capa.mbssid_max_interfaces == 0) {
        return 0;
    }

    num_bss_nontx = radio->driver_data.capa.mbssid_max_interfaces - 1;
    while (num_bss_nontx > 0) {
        max_bssid_ind++;
        num_bss_nontx >>= 1;
    }
    return max_bssid_ind;
}

static int wifi_drv_mbssid_get_interface_index(wifi_radio_info_t *radio,
    wifi_interface_info_t *interface)
{
    unsigned char max_bss_num;
    wifi_interface_info_t *tx_interface;

    tx_interface = wifi_hal_get_mbssid_tx_interface(radio);
    if (tx_interface == NULL) {
        return 0;
    }

    max_bss_num = 1 << wifi_drv_mbssid_get_max_bssid_indicator(radio);

    return (unsigned char)(interface->mac[5] - tx_interface->mac[5]) % max_bss_num;
}

static size_t wifi_drv_mbssid_rm_enabled_capab(struct hostapd_data *bss,
    struct hostapd_data *tx_bss, u8 *buf)
{
    u8 ie_buf[20], tx_ie_buf[20];
    size_t ie_len, tx_ie_len;
    u8 *ie_end, *tx_ie_end;

    ie_end = hostapd_eid_rm_enabled_capab(bss, ie_buf, sizeof(ie_buf));
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }

    tx_ie_end = hostapd_eid_rm_enabled_capab(tx_bss, tx_ie_buf, sizeof(tx_ie_buf));
    tx_ie_len = tx_ie_end - tx_ie_buf;
    if (tx_ie_len == ie_len && memcmp(ie_buf, tx_ie_buf, ie_len) == 0) {
        return 0;
    }

    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_ext_capa(struct hostapd_data *bss, struct hostapd_data *tx_bss,
    u8 *buf)
{
    u8 ie_buf[20], tx_ie_buf[20];
    size_t ie_len, tx_ie_len;
    u8 *ie_end, *tx_ie_end;

    ie_end = hostapd_eid_ext_capab(bss, ie_buf, true);
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }

    tx_ie_end = hostapd_eid_ext_capab(tx_bss, tx_ie_buf, true);
    tx_ie_len = tx_ie_end - tx_ie_buf;
    if (tx_ie_len == ie_len && memcmp(ie_buf, tx_ie_buf, ie_len) == 0) {
        return 0;
    }

    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_rsn(struct hostapd_data *bss, struct hostapd_data *tx_bss, u8 rsn_ie,
    u8 *buf)
{
    const u8 *auth, *tx_auth, *rsn = NULL, *tx_rsn = NULL;
    u8 rsn_len = 0, tx_rsn_len = 0;
    size_t auth_len = 0, tx_auth_len = 0;

    auth = wpa_auth_get_wpa_ie(bss->wpa_auth, &auth_len);
    if (auth == NULL) {
        return 0;
    }

    rsn = get_ie(auth, auth_len, rsn_ie);
    if (rsn == NULL) {
        return 0;
    }

    rsn_len = rsn[1] + 2;

    tx_auth = wpa_auth_get_wpa_ie(tx_bss->wpa_auth, &tx_auth_len);
    if (tx_auth != NULL) {
        tx_rsn = get_ie(tx_auth, tx_auth_len, rsn_ie);
        if (tx_rsn != NULL) {
            tx_rsn_len = tx_rsn[1] + 2;
        }

        if (rsn_len == tx_rsn_len && memcmp(rsn, tx_rsn, rsn_len) == 0) {
            return 0;
        }
    }

    if (buf != NULL) {
        memcpy(buf, rsn, rsn_len);
    }

    return rsn_len;
}

static size_t wifi_drv_mbssid_interworking(struct hostapd_data *bss, struct hostapd_data *tx_bss,
    u8 *buf)
{
    u8 ie_buf[64], tx_ie_buf[64];
    size_t ie_len, tx_ie_len;
    u8 *ie_end, *tx_ie_end;

    ie_end = hostapd_eid_interworking(bss, ie_buf);
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }

    tx_ie_end = hostapd_eid_interworking(tx_bss, tx_ie_buf);
    tx_ie_len = tx_ie_end - tx_ie_buf;
    if (ie_len == tx_ie_len && memcmp(ie_buf, tx_ie_buf, ie_len) == 0) {
        return 0;
    }

    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_adv_proto(struct hostapd_data *bss, struct hostapd_data *tx_bss,
    u8 *buf)
{
    u8 ie_buf[64], tx_ie_buf[64];
    size_t ie_len, tx_ie_len;
    u8 *ie_end, *tx_ie_end;

    ie_end = hostapd_eid_adv_proto(bss, ie_buf);
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }

    tx_ie_end = hostapd_eid_adv_proto(tx_bss, tx_ie_buf);
    tx_ie_len = tx_ie_end - tx_ie_buf;
    if (ie_len == tx_ie_len && memcmp(ie_buf, tx_ie_buf, ie_len) == 0) {
        return 0;
    }

    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_mbo(struct hostapd_data *bss, u8 *buf)
{
    u8 ie_buf[64];
    size_t ie_len;
    u8 *ie_end;

    ie_end = hostapd_eid_mbo(bss, ie_buf, sizeof(ie_buf));
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }

    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_wmm(struct hostapd_data *bss, u8 *buf)
{
    u8 ie_buf[64];
    size_t ie_len;
    u8 *ie_end;

    ie_end = hostapd_eid_wmm(bss, ie_buf);
    ie_len = ie_end - ie_buf;
    if (ie_len == 0) {
        return 0;
    }
    if (buf != NULL) {
        memcpy(buf, ie_buf, ie_len);
    }

    return ie_len;
}

static size_t wifi_drv_mbssid_non_inheritance(struct hostapd_data *bss, struct hostapd_data *tx_bss,
    u8 *buf)
{
    u8 non_inherit_ie[2], ie_count = 0;

    if (hostapd_wpa_ie(bss, WLAN_EID_RSN) == NULL && hostapd_wpa_ie(tx_bss, WLAN_EID_RSN) != NULL) {
        non_inherit_ie[ie_count++] = WLAN_EID_RSN;
    }

    if (hostapd_wpa_ie(bss, WLAN_EID_RSNX) == NULL &&
        hostapd_wpa_ie(tx_bss, WLAN_EID_RSNX) != NULL) {
        non_inherit_ie[ie_count++] = WLAN_EID_RSNX;
    }

    if (ie_count == 0) {
        return 0;
    }

    /*
     * Element ID: 1 octet
     * Length: 1 octet
     * Extension ID: 1 octet
     * List length: 1 octet
     * List of IEs: variable
     * List of IEs extensions: 1 octet for empty
     *
     * Total fixed length: 5 octets
     */

    if (buf != NULL) {
        *buf++ = WLAN_EID_EXTENSION;
        *buf++ = 2 + ie_count + 1;
        *buf++ = WLAN_EID_EXT_NON_INHERITANCE;
        *buf++ = ie_count;
        memcpy(buf, non_inherit_ie, ie_count);
        buf += ie_count;
        *buf++ = 0; /* No Element ID Extension List */
    }

    return 5 + ie_count;
}

#define MAX_IE_LEN 255

static size_t wifi_drv_eid_mbssid_elem_len(wifi_radio_info_t *radio,
    wifi_interface_info_t *tx_interface, wifi_interface_info_t **interface_iter, u32 frame_type)
{
    size_t len;
    struct hostapd_data *bss, *tx_bss;

    tx_bss = &tx_interface->u.ap.hapd;

    /*
     * Element ID: 1 octet
     * Length: 1 octet
     * MaxBSSID Indicator: 1 octet
     * Optional Subelements: variable
     *
     * Total fixed length: 3 octets
     *
     * 1 octet in len for the MaxBSSID Indicator field.
     */

    len = 1;

    for (; *interface_iter != NULL;
         *interface_iter = hash_map_get_next(radio->interface_map, *interface_iter)) {
        size_t nontx_profile_len;

        bss = &(*interface_iter)->u.ap.hapd;
        if (bss->conf == NULL || !bss->started) {
            continue;
        }

        /*
         * Sublement ID: 1 octet
         * Length: 1 octet
         * Nontransmitted capabilities: 4 octets
         * SSID element: 2 + variable
         * Multiple BSSID Index Element: 3 octets (+2 octets in beacons)
         * Fixed length = 1 + 1 + 4 + 2 + 3 = 11
         */
        nontx_profile_len = 11;

        if (!bss->conf->ignore_broadcast_ssid) {
            nontx_profile_len += bss->conf->ssid.ssid_len;
        }

        if (frame_type == WLAN_FC_STYPE_BEACON) {
            nontx_profile_len += 2;
        }

        nontx_profile_len += wifi_drv_mbssid_rsn(bss, tx_bss, WLAN_EID_RSN, NULL);
        nontx_profile_len += wifi_drv_mbssid_rsn(bss, tx_bss, WLAN_EID_RSNX, NULL);

        nontx_profile_len += wifi_drv_mbssid_rm_enabled_capab(bss, tx_bss, NULL);
        nontx_profile_len += wifi_drv_mbssid_ext_capa(bss, tx_bss, NULL);

        nontx_profile_len += wifi_drv_mbssid_interworking(bss, tx_bss, NULL);
        nontx_profile_len += wifi_drv_mbssid_adv_proto(bss, tx_bss, NULL);

        nontx_profile_len += wifi_drv_mbssid_mbo(bss, NULL);
        nontx_profile_len += wifi_drv_mbssid_wmm(bss, NULL);

        nontx_profile_len += wifi_drv_mbssid_non_inheritance(bss, tx_bss, NULL);

        if (len + nontx_profile_len > MAX_IE_LEN) {
            break;
        }

        len += nontx_profile_len;
    }

    /*
     * Add element ID and length fields here since they should not be included in 255 limit
     * calculation.
     */
    return len + 2;
}

static u8 *wifi_drv_eid_mbssid_elem(wifi_radio_info_t *radio, wifi_interface_info_t *tx_interface,
    wifi_interface_info_t **interface_iter, u8 *eid, u8 *end, u32 frame_type,
    u8 max_bssid_indicator, u8 elem_count)
{
    u8 *eid_len_offset, *max_bssid_indicator_offset;
    struct hostapd_data *bss, *tx_bss;
    u16 capab_info;

    tx_bss = &tx_interface->u.ap.hapd;

    *eid++ = WLAN_EID_MULTIPLE_BSSID;
    eid_len_offset = eid++;
    max_bssid_indicator_offset = eid++;

    for (; *interface_iter != NULL;
         *interface_iter = hash_map_get_next(radio->interface_map, *interface_iter)) {
        u8 mbssid_index;
        u8 *eid_len_pos, *nontx_bss_start = eid;

        bss = &(*interface_iter)->u.ap.hapd;
        if (bss->conf == NULL || !bss->started) {
            continue;
        }

        /*
         * Sublement ID: 1 octet
         * Length: 1 octet
         * Nontransmitted capabilities: 4 octets
         * SSID element: 2 + variable
         * Multiple BSSID Index Element: 3 octets (+2 octets in beacons)
         * Fixed length = 1 + 1 + 4 + 2 + 3 = 11
         */

        *eid++ = WLAN_MBSSID_SUBELEMENT_NONTRANSMITTED_BSSID_PROFILE;
        eid_len_pos = eid++;

        capab_info = hostapd_own_capab_info(bss);
        *eid++ = WLAN_EID_NONTRANSMITTED_BSSID_CAPA;
        *eid++ = sizeof(capab_info);
        WPA_PUT_LE16(eid, capab_info);
        eid += sizeof(capab_info);

        *eid++ = WLAN_EID_SSID;
        if (!bss->conf->ignore_broadcast_ssid) {
            *eid++ = bss->conf->ssid.ssid_len;
            memcpy(eid, bss->conf->ssid.ssid, bss->conf->ssid.ssid_len);
            eid += bss->conf->ssid.ssid_len;
        } else {
            *eid++ = 0;
        }

        *eid++ = WLAN_EID_MULTIPLE_BSSID_INDEX;
        mbssid_index = wifi_drv_mbssid_get_interface_index(radio, *interface_iter);
        if (frame_type == WLAN_FC_STYPE_BEACON) {
            *eid++ = 3; /* IE length */
            *eid++ = mbssid_index; /* BSSID Index */
            *eid++ = bss->conf->dtim_period;
            *eid++ = 0; /* DTIM Count, updated by driver */
        } else {
            /* Probe Request frame does not include DTIM Period and DTIM Count fields. */
            *eid++ = 1;
            *eid++ = mbssid_index; /* BSSID Index */
        }

        eid += wifi_drv_mbssid_rsn(bss, tx_bss, WLAN_EID_RSN, eid);
        eid += wifi_drv_mbssid_rsn(bss, tx_bss, WLAN_EID_RSNX, eid);

        eid += wifi_drv_mbssid_rm_enabled_capab(bss, tx_bss, eid);
        eid += wifi_drv_mbssid_ext_capa(bss, tx_bss, eid);

        eid += wifi_drv_mbssid_interworking(bss, tx_bss, eid);
        eid += wifi_drv_mbssid_adv_proto(bss, tx_bss, eid);

        eid += wifi_drv_mbssid_mbo(bss, eid);
        eid += wifi_drv_mbssid_wmm(bss, eid);

        eid += wifi_drv_mbssid_non_inheritance(bss, tx_bss, eid);

        *eid_len_pos = (eid - eid_len_pos) - 1;

        if (((eid - eid_len_offset) - 1) > MAX_IE_LEN) {
            eid = nontx_bss_start;
            break;
        }
    }

    *max_bssid_indicator_offset = max_bssid_indicator;
    if (*max_bssid_indicator_offset < 1)
        *max_bssid_indicator_offset = 1;
    *eid_len_offset = (eid - eid_len_offset) - 1;

    return eid;
}

static u8 *wifi_drv_eid_mbssid(wifi_radio_info_t *radio, wifi_interface_info_t *tx_interface,
    u8 *eid, u8 *end, unsigned int frame_stype, u8 elem_count, u8 **elem_offset)
{
    wifi_interface_info_t *interface_iter;
    u8 elem_index = 0;

    if (frame_stype == WLAN_FC_STYPE_BEACON && elem_offset != NULL) {
        *elem_offset = 0;
    }

    interface_iter = hash_map_get_next(radio->interface_map, tx_interface);
    while (interface_iter != NULL) {
        if (frame_stype == WLAN_FC_STYPE_BEACON) {
            if (elem_index == elem_count) {
                wifi_hal_error_print("%s:%d failed to create mbssid, elements overflow %d %d\n",
                    __func__, __LINE__, elem_index, elem_count);
                break;
            }

            elem_offset[elem_index] = eid;
            elem_index = elem_index + 1;
        }

        eid = wifi_drv_eid_mbssid_elem(radio, tx_interface, &interface_iter, eid, end, frame_stype,
            wifi_drv_mbssid_get_max_bssid_indicator(radio), elem_count);
    }

    return eid;
}

static struct hostapd_data *wifi_drv_get_mbssid_tx_bss(void *priv)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *tx_interface, *interface = priv;

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d interface is null\n", __func__, __LINE__);
        return NULL;
    }

    if (interface->u.ap.hapd.iconf == NULL ||
        interface->u.ap.hapd.iconf->mbssid == MBSSID_DISABLED) {
        return &interface->u.ap.hapd;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return &interface->u.ap.hapd;
    }

    tx_interface = wifi_hal_get_mbssid_tx_interface(radio);
    if (tx_interface == NULL) {
        return &interface->u.ap.hapd;
    }

    return &tx_interface->u.ap.hapd;
}

static int wifi_drv_mbssid_get_bss_index(void *priv)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface = priv;

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d interface is null\n", __func__, __LINE__);
        return 0;
    }

    if (interface->u.ap.hapd.iconf == NULL ||
        interface->u.ap.hapd.iconf->mbssid == MBSSID_DISABLED) {
        return 0;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return 0;
    }

    return wifi_drv_mbssid_get_interface_index(radio, interface);
}

static size_t wifi_drv_get_mbssid_len(void *priv, u32 frame_type, u8 *elem_count)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface_iter, *tx_interface = priv;
    size_t len = 0;

    if (tx_interface == NULL) {
        wifi_hal_error_print("%s:%d interface is null\n", __func__, __LINE__);
        return 0;
    }

    if (tx_interface->u.ap.hapd.iconf == NULL ||
        tx_interface->u.ap.hapd.iconf->mbssid == MBSSID_DISABLED) {
        return 0;
    }

    radio = get_radio_by_rdk_index(tx_interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            tx_interface->vap_info.radio_index);
        return 0;
    }

    if (frame_type == WLAN_FC_STYPE_BEACON && elem_count != NULL) {
        *elem_count = 0;
    }

    interface_iter = hash_map_get_next(radio->interface_map, tx_interface);
    while (interface_iter != NULL) {
        len += wifi_drv_eid_mbssid_elem_len(radio, tx_interface, &interface_iter, frame_type);
        if (frame_type == WLAN_FC_STYPE_BEACON && elem_count != NULL) {
            *elem_count += 1;
        }
    }

    return len;
}

u8 *wifi_drv_get_mbssid_ie(void *priv, u8 *eid, u8 *end, unsigned int frame_stype, u8 elem_count,
    u8 **elem_offset)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *tx_interface = priv;

    if (tx_interface == NULL) {
        wifi_hal_error_print("%s:%d interface is null\n", __func__, __LINE__);
        return eid;
    }

    if (tx_interface->u.ap.hapd.iconf == NULL ||
        tx_interface->u.ap.hapd.iconf->mbssid == MBSSID_DISABLED) {
        return eid;
    }

    radio = get_radio_by_rdk_index(tx_interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            tx_interface->vap_info.radio_index);
        return eid;
    }

    eid = wifi_drv_eid_mbssid(radio, tx_interface, eid, end, frame_stype, elem_count, elem_offset);

    return eid;
}

static u8 *wifi_drv_get_mbssid_config(void *priv, u8 *eid)
{
    wifi_radio_info_t *radio;
    wifi_interface_info_t *interface = priv;

    if (interface == NULL) {
        wifi_hal_error_print("%s:%d mbssid config failed, interface null\n", __func__, __LINE__);
        return eid;
    }

    if (interface->u.ap.hapd.iconf == NULL ||
        interface->u.ap.hapd.iconf->mbssid == MBSSID_DISABLED) {
        return eid;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d failed to get radio for index: %d\n", __func__, __LINE__,
            interface->vap_info.radio_index);
        return eid;
    }

    *eid++ = WLAN_EID_EXTENSION;
    *eid++ = 3;
    *eid++ = WLAN_EID_EXT_MULTIPLE_BSSID_CONFIGURATION;
    *eid++ = wifi_drv_mbssid_get_active_interface_num(radio);
    *eid++ = 1; /* Periodicity, EMA not supported */

    return eid;
}

#endif /* HOSTAPD_VERSION >= 210 */

static int get_radio_txpwr_handler(struct nl_msg *msg, void *arg)
{
    unsigned int tx_pwr = 0;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    unsigned long *tx_pwr_dbm = (unsigned long *)arg;

    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) <
        0) {
        wifi_hal_error_print("%s:%d Failed to parse vendor data\n", __func__, __LINE__);
        return NL_SKIP;
    }

    if (tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL] == NULL) {
        wifi_hal_error_print("%s:%d Radio tx power attribute is missing\n", __func__, __LINE__);
        return NL_SKIP;
    }

    tx_pwr = nla_get_u32(tb[NL80211_ATTR_WIPHY_TX_POWER_LEVEL]);
    *tx_pwr_dbm = tx_pwr / 100; /* mBm to dBm */
    return NL_SKIP;
}

static int get_radio_tx_power(wifi_interface_info_t *interface, ULONG *tx_power)
{
    struct nl_msg *msg;
    int ret = RETURN_ERR;

    wifi_hal_dbg_print("%s:%d Entering\n", __func__, __LINE__);
    msg = nl80211_drv_cmd_msg(g_wifi_hal.nl80211_id, interface, 0, NL80211_CMD_GET_INTERFACE);
    if (msg == NULL) {
        wifi_hal_error_print("%s:%d Failed to create NL command\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    ret = nl80211_send_and_recv(msg, get_radio_txpwr_handler, tx_power, NULL, NULL);
    if (ret) {
        wifi_hal_error_print("%s:%d Failed to send NL message %d %s\n", __func__, __LINE__, ret,
            nl_geterror(ret));
        return RETURN_ERR;
    }

    return RETURN_OK;
}
INT wifi_hal_getRadioTransmitPower(INT radioIndex, ULONG *tx_power)
{
    wifi_interface_info_t *interface = NULL;
    wifi_radio_info_t *radio = NULL;

    wifi_hal_dbg_print("%s:%d: Get radio transmit power for index %d\n", __func__, __LINE__,
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

    if (get_radio_tx_power(interface, tx_power)) {
        wifi_hal_error_print("%s:%d: Failed to get radio tx power for radio %d\n", __func__,
            __LINE__, radioIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int wifi_drv_get_sta_auth_type(void *priv, const u8 *addr, int auth_key,int frame_type)
{
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    mac_address_t sta;
    mac_addr_str_t  sta_mac_str;
    wifi_device_callbacks_t *callbacks;
    int band;
    int mode;
    int key_mgmt;
    if(!addr || !priv) {
        wifi_hal_error_print("%s:%d station/ies info is null\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (auth_key == WPA_KEY_MGMT_PSK) {
        key_mgmt = 2;
    }
    else if (auth_key == WPA_KEY_MGMT_SAE) {
        key_mgmt = 8;
    }
    else if (auth_key == KEY_MGMT_SAE_EXT) {
        key_mgmt = 24;
    }
    else {
        key_mgmt = -1;
    }
    interface = (wifi_interface_info_t *)priv;

    if(interface == NULL) {
        wifi_hal_error_print("%s:%d interface is null\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    memcpy(sta, addr, sizeof(mac_address_t));
    band = vap->radio_index;
    callbacks = get_hal_device_callbacks();

    if (callbacks == NULL) {
        return -1;
    }

    if( vap->u.bss_info.security.mode == wifi_security_mode_wpa3_compatibility || vap->u.bss_info.security.mode == wifi_security_mode_wpa3_personal || vap->u.bss_info.security.mode == wifi_security_mode_wpa3_transition) {
#ifdef CONFIG_IEEE80211BE
        {
            if (wifi_vap_mode_ap == interface->vap_info.vap_mode &&
                !interface->u.ap.conf.disable_11be) {
                mode = 24;
            } else {
               mode = 8;
            }
        }
#else
        mode = 8;
#endif
    }
    else {
        mode = 2;
     }

     for (int i = 0; i < callbacks->num_stamode_cbs; i++) {
         if (callbacks->stamode_cb[i] != NULL) {
             callbacks->stamode_cb[i](vap->vap_index, to_mac_str(sta, sta_mac_str), key_mgmt, frame_type, band, mode);
         }
     }

    return RETURN_OK;
}

const struct wpa_driver_ops g_wpa_driver_nl80211_ops = {
    .name = "nl80211",
    .desc = "Linux nl80211/cfg80211",
    .get_bssid = wifi_drv_get_bssid,
    .get_ssid = wifi_drv_get_ssid,
    .set_key = wifi_drv_set_key,
    .scan2 = wifi_drv_scan2,
    .sched_scan = wifi_drv_sched_scan,
    .stop_sched_scan = wifi_drv_stop_sched_scan,
    .get_scan_results2 = wifi_drv_get_scan_results,
    .abort_scan = wifi_drv_abort_scan,
    .deauthenticate = wifi_drv_deauthenticate,
    .authenticate = wifi_drv_authenticate,
    .associate = wifi_drv_associate,
    .global_init = wifi_drv_global_init,
    .global_deinit = wifi_drv_global_deinit,
    .init2 = wifi_driver_nl80211_init,
    .deinit = wifi_drv_deinit,
    .get_capa = wifi_drv_get_capa,
    .set_operstate = wifi_drv_set_operstate,
    .set_supp_port = wifi_drv_set_supp_port,
    .set_country = wifi_drv_set_country,
    .get_country = wifi_drv_get_country,
    .set_ap = wifi_drv_set_ap,
    .set_acl = wifi_drv_set_acl,
    .if_add = wifi_drv_if_add,
    .if_remove = wifi_drv_if_remove,
    .send_mlme = wifi_drv_send_mlme,
    .get_hw_feature_data = wifi_drv_get_hw_feature_data,
    .sta_add = wifi_drv_sta_add,
    .sta_remove = wifi_drv_sta_remove,
    .hapd_send_eapol = wifi_drv_hapd_send_eapol,
    .sta_set_flags = wifi_drv_sta_set_flags,
    .sta_set_airtime_weight = wifi_drv_sta_set_airtime_weight,
    .hapd_init = wifi_drv_init,
    .hapd_deinit = wifi_drv_deinit,
    .set_wds_sta = wifi_drv_set_wds_sta,
    .get_seqnum = wifi_drv_get_seqnum,
    .flush = wifi_drv_flush,
    .get_inact_sec = wifi_drv_get_inact_sec,
    .sta_clear_stats = wifi_drv_sta_clear_stats,
    .set_rts = wifi_drv_set_rts,
    .set_frag = wifi_drv_set_frag,
    .set_tx_queue_params = wifi_drv_set_tx_queue_params,
    .set_sta_vlan = wifi_drv_set_sta_vlan,
    .sta_deauth = wifi_drv_sta_deauth,
    .sta_notify_deauth = wifi_drv_sta_notify_deauth,
    .wps_event_notify_cb = wifi_drv_wps_event_notify_cb,
    .sta_disassoc = wifi_drv_sta_disassoc,
    .read_sta_data = wifi_drv_read_sta_data,
    .set_freq = wifi_drv_set_freq,
    .send_action = wifi_drv_send_action,
    .send_action_cancel_wait = wifi_drv_send_action_cancel_wait,
    .remain_on_channel = wifi_drv_remain_on_channel,
    .cancel_remain_on_channel = wifi_drv_cancel_remain_on_channel,
    .probe_req_report = wifi_drv_probe_req_report,
    .deinit_ap = wifi_drv_deinit_ap,
    .deinit_p2p_cli = wifi_drv_deinit_p2p_cli,
    .resume = wifi_drv_resume,
    .signal_monitor = wifi_drv_signal_monitor,
    .signal_poll = wifi_drv_signal_poll,
#if HOSTAPD_VERSION < 210 //2.10
    .channel_info = wifi_drv_channel_info,
#endif
    .set_param = wifi_drv_set_param,
    .get_radio_name = wifi_drv_get_radio_name,
    .add_pmkid = wifi_drv_add_pmkid,
    .remove_pmkid = wifi_drv_remove_pmkid,
    .flush_pmkid = wifi_drv_flush_pmkid,
    .set_rekey_info = wifi_drv_set_rekey_info,
    .poll_client = wifi_drv_poll_client,
    .set_p2p_powersave = wifi_drv_set_p2p_powersave,
    .start_dfs_cac = wifi_drv_start_radar_detection,
    .stop_ap = wifi_drv_stop_ap,
#ifdef CONFIG_TDLS
    .send_tdls_mgmt = wifi_drv_send_tdls_mgmt,
    .tdls_oper = wifi_drv_tdls_oper,
    .tdls_enable_channel_switch = wifi_drv_tdls_enable_channel_switch,
    .tdls_disable_channel_switch = wifi_drv_tdls_disable_channel_switch,
#endif /* CONFIG_TDLS */
    .update_ft_ies = wifi_drv_update_ft_ies,
    .update_dh_ie = wifi_drv_update_dh_ie,
    .get_mac_addr = wifi_drv_get_macaddr,
    .get_survey = wifi_drv_get_survey,
    .status = wifi_drv_status,
    .switch_channel = wifi_drv_switch_channel,
#ifdef ANDROID_P2P
    .set_noa = wifi_drv_set_p2p_noa,
    .get_noa = wifi_drv_get_p2p_noa,
    .set_ap_wps_ie = wifi_drv_set_ap_wps_p2p_ie,
#endif /* ANDROID_P2P */
#ifdef ANDROID
#ifndef ANDROID_LIB_STUB
    .driver_cmd = wifi_drv_driver_cmd,
#endif /* !ANDROID_LIB_STUB */
#endif /* ANDROID */
    .vendor_cmd = wifi_drv_vendor_cmd,
    .set_qos_map = wifi_drv_set_qos_map,
    .set_wowlan = wifi_drv_set_wowlan,
    .set_mac_addr = wifi_drv_set_mac_addr,
#ifdef CONFIG_MESH
    .init_mesh = wifi_drv_init_mesh,
    .join_mesh = wifi_drv_join_mesh,
    .leave_mesh = wifi_drv_leave_mesh,
    .probe_mesh_link = wifi_drv_probe_mesh_link,
#endif /* CONFIG_MESH */
    .br_add_ip_neigh = wifi_drv_br_add_ip_neigh,
    .br_delete_ip_neigh = wifi_drv_br_delete_ip_neigh,
    .br_port_set_attr = wifi_drv_br_port_set_attr,
    .br_set_net_param = wifi_drv_br_set_net_param,
    .add_tx_ts = wifi_drv_add_ts,
    .del_tx_ts = wifi_drv_del_ts,
    .get_ifindex = wifi_drv_get_ifindex,
#ifdef CONFIG_DRIVER_NL80211_QCA
    .roaming = wifi_drv_roaming,
    .disable_fils = wifi_drv_disable_fils,
    .do_acs = wifi_drv_do_acs,
    .set_band = wifi_drv_set_band,
    .get_pref_freq_list = wifi_drv_get_pref_freq_list,
    .set_prob_oper_freq = wifi_drv_set_prob_oper_freq,
    .p2p_lo_start = wifi_drv_p2p_lo_start,
    .p2p_lo_stop = wifi_drv_p2p_lo_stop,
    .set_default_scan_ies = wifi_drv_set_default_scan_ies,
    .set_tdls_mode = wifi_drv_set_tdls_mode,
#ifdef CONFIG_MBO
    .get_bss_transition_status = wifi_drv_get_bss_transition_status,
    .ignore_assoc_disallow = wifi_drv_ignore_assoc_disallow,
#endif /* CONFIG_MBO */
    .set_bssid_blacklist = wifi_drv_set_bssid_blacklist,
#endif /* CONFIG_DRIVER_NL80211_QCA */
    .configure_data_frame_filters = wifi_drv_configure_data_frame_filters,
#if defined(CONFIG_HW_CAPABILITIES) || defined(CMXB7_PORT) || defined(VNTXER5_PORT)
    .get_ext_capab = wifi_drv_get_ext_capab,
#if HOSTAPD_VERSION >= 211
#ifdef CONFIG_IEEE80211BE
    .get_mld_capab = wifi_drv_get_mld_capab,
#endif /* CONFIG_IEEE80211BE */
#endif /* HOSTAPD_VERSION >= 211 */
#endif /* CONFIG_HW_CAPABILITIES || CMXB7_PORT || VNTXER5_PORT */
    .update_connect_params = wifi_drv_update_connection_params,
    .send_external_auth_status = wifi_drv_send_external_auth_status,
    .set_4addr_mode = wifi_drv_set_4addr_mode,
#if !defined(PLATFORM_LINUX) && !defined(_PLATFORM_BANANAPI_R4_)
    .get_aid = wifi_drv_get_aid,
    .free_aid = wifi_drv_free_aid,
#endif

#ifdef CONFIG_VENDOR_COMMANDS
#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    /* RRM/BTM support*/
    .get_vap_measurements = wifi_drv_get_vap_measurements,
    .get_radio_info = wifi_drv_get_radio_info,
    .get_sta_measurements = wifi_drv_get_sta_measurements,
#endif // CONFIG_USE_HOSTAP_BTM_PATCH
#endif // CONFIG_VENDOR_COMMANDS
#if !defined(PLATFORM_LINUX)
    .radius_eap_failure = wifi_drv_send_radius_eap_failure,
    .radius_fallback_failover = wifi_drv_send_radius_fallback_and_failover,
#endif // CONFIG_VENDOR_COMMANDS
#ifdef CMXB7_PORT
    .set_chan_dfs_state = nl80211_set_channel_dfs_state,
#endif
#if HOSTAPD_VERSION >= 210 // 2.10
    .get_rnr_colocation_len = wifi_drv_get_rnr_colocation_len,
    .get_rnr_colocation_ie = wifi_drv_get_rnr_colocation_ie,
    .get_mbssid_bss_index = wifi_drv_mbssid_get_bss_index,
    .get_mbssid_tx_bss = wifi_drv_get_mbssid_tx_bss,
    .get_mbssid_len = wifi_drv_get_mbssid_len,
    .get_mbssid_ie = wifi_drv_get_mbssid_ie,
    .get_mbssid_config = wifi_drv_get_mbssid_config,
    .get_sta_auth_type = wifi_drv_get_sta_auth_type,
#endif /* HOSTAPD_VERSION >= 210 */
};

#ifdef CONFIG_WIFI_EMULATOR
const struct wpa_driver_ops g_wpa_supplicant_driver_nl80211_ops = {
    .name = "nl80211",
    .desc = "Linux nl80211/cfg80211",
    .get_bssid = wifi_supplicant_drv_get_bssid,
    .get_ssid = wifi_drv_get_ssid,
    .set_key = wifi_drv_set_key,
    .scan2 = wifi_drv_scan2,
    .sched_scan = wifi_drv_sched_scan,
    .stop_sched_scan = wifi_drv_stop_sched_scan,
    .get_scan_results2 = wifi_drv_get_scan_results,
    .abort_scan = wifi_drv_abort_scan,
    .deauthenticate = wifi_drv_deauthenticate,
    .authenticate = wifi_supplicant_drv_authenticate,
    .associate = wifi_supplicant_drv_associate,
    .global_init = wifi_drv_global_init,
    .global_deinit = wifi_drv_global_deinit,
    .init2 = wifi_driver_nl80211_init,
    .deinit = wifi_drv_deinit,
    .get_capa = wifi_drv_get_capa,
    .set_operstate = wifi_drv_set_operstate,
    .set_supp_port = wifi_drv_set_supp_port,
    .set_country = wifi_drv_set_country,
    .get_country = wifi_drv_get_country,
    .set_ap = wifi_drv_set_ap,
    .set_acl = wifi_drv_set_acl,
    .if_add = wifi_drv_if_add,
    .if_remove = wifi_drv_if_remove,
    .send_mlme = wifi_drv_send_mlme,
    .get_hw_feature_data = wifi_drv_get_hw_feature_data,
    .sta_add = wifi_drv_sta_add,
    .sta_remove = wifi_drv_sta_remove,
    .hapd_send_eapol = wifi_drv_hapd_send_eapol,
    .sta_set_flags = wifi_drv_sta_set_flags,
    .sta_set_airtime_weight = wifi_drv_sta_set_airtime_weight,
    .hapd_init = wifi_drv_init,
    .hapd_deinit = wifi_drv_deinit,
    .set_wds_sta = wifi_drv_set_wds_sta,
    .get_seqnum = wifi_drv_get_seqnum,
    .flush = wifi_drv_flush,
    .get_inact_sec = wifi_drv_get_inact_sec,
    .sta_clear_stats = wifi_drv_sta_clear_stats,
    .set_rts = wifi_drv_set_rts,
    .set_frag = wifi_drv_set_frag,
    .set_tx_queue_params = wifi_drv_set_tx_queue_params,
    .set_sta_vlan = wifi_drv_set_sta_vlan,
    .sta_deauth = wifi_drv_sta_deauth,
    .sta_notify_deauth = wifi_drv_sta_notify_deauth,
    .wps_event_notify_cb = wifi_drv_wps_event_notify_cb,
    .sta_disassoc = wifi_drv_sta_disassoc,
    .read_sta_data = wifi_drv_read_sta_data,
    .set_freq = wifi_drv_set_freq,
    .send_action = wifi_drv_send_action,
    .send_action_cancel_wait = wifi_drv_send_action_cancel_wait,
    .remain_on_channel = wifi_drv_remain_on_channel,
    .cancel_remain_on_channel = wifi_drv_cancel_remain_on_channel,
    .probe_req_report = wifi_drv_probe_req_report,
    .deinit_ap = wifi_drv_deinit_ap,
    .deinit_p2p_cli = wifi_drv_deinit_p2p_cli,
    .resume = wifi_drv_resume,
    .signal_monitor = wifi_drv_signal_monitor,
    .signal_poll = wifi_drv_signal_poll,
#if HOSTAPD_VERSION < 210 //2.10
    .channel_info = wifi_drv_channel_info,
#endif
    .set_param = wifi_drv_set_param,
    .get_radio_name = wifi_drv_get_radio_name,
    .add_pmkid = wifi_drv_add_pmkid,
    .remove_pmkid = wifi_drv_remove_pmkid,
    .flush_pmkid = wifi_drv_flush_pmkid,
    .set_rekey_info = wifi_drv_set_rekey_info,
    .poll_client = wifi_drv_poll_client,
    .set_p2p_powersave = wifi_drv_set_p2p_powersave,
    .start_dfs_cac = wifi_drv_start_radar_detection,
    .stop_ap = wifi_drv_stop_ap,
#ifdef CONFIG_TDLS
    .send_tdls_mgmt = wifi_drv_send_tdls_mgmt,
    .tdls_oper = wifi_drv_tdls_oper,
    .tdls_enable_channel_switch = wifi_drv_tdls_enable_channel_switch,
    .tdls_disable_channel_switch = wifi_drv_tdls_disable_channel_switch,
#endif /* CONFIG_TDLS */
    .update_ft_ies = wifi_drv_update_ft_ies,
    .update_dh_ie = wifi_drv_update_dh_ie,
    .get_mac_addr = wifi_drv_get_macaddr,
    .get_survey = wifi_drv_get_survey,
    .status = wifi_drv_status,
    .switch_channel = wifi_drv_switch_channel,
#ifdef ANDROID_P2P
    .set_noa = wifi_drv_set_p2p_noa,
    .get_noa = wifi_drv_get_p2p_noa,
    .set_ap_wps_ie = wifi_drv_set_ap_wps_p2p_ie,
#endif /* ANDROID_P2P */
#ifdef ANDROID
#ifndef ANDROID_LIB_STUB
    .driver_cmd = wifi_drv_driver_cmd,
#endif /* !ANDROID_LIB_STUB */
#endif /* ANDROID */
    .vendor_cmd = wifi_drv_vendor_cmd,
    .set_qos_map = wifi_drv_set_qos_map,
    .set_wowlan = wifi_drv_set_wowlan,
    .set_mac_addr = wifi_drv_set_mac_addr,
#ifdef CONFIG_MESH
    .init_mesh = wifi_drv_init_mesh,
    .join_mesh = wifi_drv_join_mesh,
    .leave_mesh = wifi_drv_leave_mesh,
    .probe_mesh_link = wifi_drv_probe_mesh_link,
#endif /* CONFIG_MESH */
    .br_add_ip_neigh = wifi_drv_br_add_ip_neigh,
    .br_delete_ip_neigh = wifi_drv_br_delete_ip_neigh,
    .br_port_set_attr = wifi_drv_br_port_set_attr,
    .br_set_net_param = wifi_drv_br_set_net_param,
    .add_tx_ts = wifi_drv_add_ts,
    .del_tx_ts = wifi_drv_del_ts,
    .get_ifindex = wifi_drv_get_ifindex,
#ifdef CONFIG_DRIVER_NL80211_QCA
    .roaming = wifi_drv_roaming,
    .disable_fils = wifi_drv_disable_fils,
    .do_acs = wifi_drv_do_acs,
    .set_band = wifi_drv_set_band,
    .get_pref_freq_list = wifi_drv_get_pref_freq_list,
    .set_prob_oper_freq = wifi_drv_set_prob_oper_freq
    .p2p_lo_start = wifi_drv_p2p_lo_start,
    .p2p_lo_stop = wifi_drv_p2p_lo_stop,
    .set_default_scan_ies = wifi_drv_set_default_scan_ies,
    .set_tdls_mode = wifi_drv_set_tdls_mode,
#ifdef CONFIG_MBO
    .get_bss_transition_status = wifi_drv_get_bss_transition_status,
    .ignore_assoc_disallow = wifi_drv_ignore_assoc_disallow,
#endif /* CONFIG_MBO */
    .set_bssid_blacklist = wifi_drv_set_bssid_blacklist,
#endif /* CONFIG_DRIVER_NL80211_QCA */
    .configure_data_frame_filters = wifi_drv_configure_data_frame_filters,
#if defined(CONFIG_HW_CAPABILITIES) || defined(CMXB7_PORT) || defined(VNTXER5_PORT)
    .get_ext_capab = wifi_drv_get_ext_capab,
#endif /* CONFIG_HW_CAPABILITIES || CMXB7_PORT || VNTXER5_PORT */
    .update_connect_params = wifi_drv_update_connection_params,
    .send_external_auth_status = wifi_drv_send_external_auth_status,
    .set_4addr_mode = wifi_drv_set_4addr_mode,
#ifdef CONFIG_VENDOR_COMMANDS
    .get_aid = wifi_drv_get_aid,
    .free_aid = wifi_drv_free_aid,
#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    /* RRM/BTM support*/
    .get_vap_measurements = wifi_drv_get_vap_measurements,
    .get_radio_info = wifi_drv_get_radio_info,
    .get_sta_measurements = wifi_drv_get_sta_measurements,
#endif // CONFIG_USE_HOSTAP_BTM_PATCH
#endif // CONFIG_VENDOR_COMMANDS
    .radius_eap_failure = wifi_drv_send_radius_eap_failure,
    .radius_fallback_failover = wifi_drv_send_radius_fallback_and_failover,
#ifdef CMXB7_PORT
    .set_chan_dfs_state = nl80211_set_channel_dfs_state,
#endif
#if HOSTAPD_VERSION >= 210
    .get_sta_auth_type = wifi_drv_get_sta_auth_type,
#endif /* HOSTAPD_VERSION >= 210 */
};
#endif //CONFIG_WIFI_EMULATOR
