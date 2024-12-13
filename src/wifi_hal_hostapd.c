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
 * Copyright (c) 2003-2014, Jouni Malinen <j@w1.fi>
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
#include "wifi_hal.h"
#include "wifi_hal_priv.h"
#include "crypto/sha1.h"
#include "eap_peer/eap_methods.h"

#define MACF      "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_TO_MACF(addr)    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#define RADIUS_FALLBACK_TIMER_IN_SECS   12*60*60

extern const struct wpa_driver_ops g_wpa_driver_nl80211_ops;

int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0;

    if ((f = popen(cmd, "r")) == NULL) {
        wpa_printf(MSG_ERROR, "popen %s error\n", cmd);
        return -1;
    }

    while(!feof(f)) {
        *ptr = 0;
        if(bufSize>=128) {
                bufbytes=128;
        } else {
                bufbytes=bufSize-1;
        }
        fgets(ptr,bufbytes,f);
        readbytes=strlen(ptr);
        if( readbytes== 0)
                break;
        bufSize-=readbytes;
        ptr += readbytes;
    }
    pclose(f);
    return 0;
}

void wifi_authenticator_run()
{
    eloop_run();
}

void init_radius_config(wifi_interface_info_t *interface)
{
    if (!interface->vap_initialized) {
        struct hostapd_bss_config *conf;
        char *config_methods = (char *)malloc(WPS_METHODS_SIZE);
        memset(config_methods, '\0', WPS_METHODS_SIZE);

        //wifi_vap_info_t *vap;
        //int ap_index;

        // vap = &interface->vap_info;
        //  ap_index = vap->vap_index;

        conf = &interface->u.ap.conf;
        conf->radius = &interface->u.ap.radius;
        conf->radius->num_acct_servers = 0;

        conf->nas_identifier = interface->u.ap.nas_identifier;
        char *wpa_passphrase = (char *)malloc(256);
        conf->ssid.wpa_passphrase = wpa_passphrase;
#ifdef CONFIG_WPS
        conf->config_methods = config_methods;
        conf->ap_pin = calloc(1, WPS_PIN_SIZE);
#endif
    }
}

void init_hostap_bss(wifi_interface_info_t *interface)
{
    struct hostapd_bss_config *conf;
   // wifi_vap_info_t *vap;
    //int ap_index;

 //   vap = &interface->vap_info;
   // ap_index = vap->vap_index;
    
    conf = &interface->u.ap.conf;
        

    conf->logger_syslog_level = HOSTAPD_LEVEL_DEBUG;
    conf->logger_stdout_level = HOSTAPD_LEVEL_DEBUG;
    conf->logger_syslog =  -1;
    conf->logger_stdout =  -1;

    conf->auth_algs = WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED;

    conf->wep_rekeying_period = 300;
    /* use key0 in individual key and key1 in broadcast key */
    conf->broadcast_key_idx_min = 1;
    conf->broadcast_key_idx_max = 2;
    conf->eap_reauth_period = 3600;

    conf->wpa_group_rekey = 0;
    conf->wpa_gmk_rekey = 0;
    conf->wpa_group_update_count = 4;
    conf->wpa_pairwise_update_count = 4;
    conf->wpa_disable_eapol_key_retries =
        DEFAULT_WPA_DISABLE_EAPOL_KEY_RETRIES;
    conf->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
    conf->wpa_pairwise = WPA_CIPHER_TKIP;
    conf->wpa_group = WPA_CIPHER_TKIP;
    conf->rsn_pairwise = 0;

    conf->max_num_sta = MAX_STA_COUNT;

    conf->dtim_period = 2;

    conf->radius_server_auth_port = 1812;
    //conf->radius->radius_server_retries = RADIUS_CLIENT_MAX_RETRIES;
   // conf->radius->radius_max_retry_wait = RADIUS_CLIENT_MAX_WAIT;
    conf->eap_sim_db_timeout = 1;
    conf->eap_sim_id = 3;
    conf->ap_max_inactivity = AP_MAX_INACTIVITY;
    conf->eapol_version = EAPOL_VERSION;

    conf->max_listen_interval = 65535;

    conf->pwd_group = 19; /* ECC: GF(p=256) */

#ifdef CONFIG_IEEE80211W
//Defined
    conf->assoc_sa_query_max_timeout = 1000;
    conf->assoc_sa_query_retry_timeout = 201;
    conf->group_mgmt_cipher = WPA_CIPHER_AES_128_CMAC;
#endif /* CONFIG_IEEE80211W */
#ifdef EAP_SERVER_FAST
//Defined
    /* both anonymous and authenticated provisioning */
    conf->eap_fast_prov = 3;
    conf->pac_key_lifetime = 7 * 24 * 60 * 60;
    conf->pac_key_refresh_time = 1 * 24 * 60 * 60;
#endif /* EAP_SERVER_FAST */

    /* Set to -1 as defaults depends on HT in setup */
    conf->wmm_enabled = -1;


#ifdef CONFIG_IEEE80211R_AP
//Defined
    conf->ft_over_ds = 1;
    conf->rkh_pos_timeout = 86400;
    conf->rkh_neg_timeout = 60;
    conf->rkh_pull_timeout = 1000;
    conf->rkh_pull_retries = 4;
    conf->r0_key_lifetime = 1209600;
#endif /* CONFIG_IEEE80211R_AP */

    conf->radius_das_time_window = 300;

#if HOSTAPD_VERSION >= 210 //2.10
    conf->anti_clogging_threshold = 5;
#else
    conf->sae_anti_clogging_threshold = 5;
#endif

    conf->sae_sync = 5;

    conf->gas_frag_limit = 1400;

    if (interface->u.ap.conf_initialized == false) {
        dl_list_init(&conf->anqp_elem);
        interface->u.ap.conf_initialized = true;
    }
#ifdef CONFIG_FILS
//Not Defined
    dl_list_init(&conf->fils_realms);
    conf->fils_hlp_wait_time = 30;
    conf->dhcp_server_port = DHCP_SERVER_PORT;
    conf->dhcp_relay_port = DHCP_SERVER_PORT;
#endif /* CONFIG_FILS */

    conf->broadcast_deauth = 1;

#ifdef CONFIG_MBO
    conf->mbo_enabled = 0;
//Not Defined
    conf->mbo_cell_data_conn_pref = -1;
#endif /* CONFIG_MBO */

    /* Disable TLS v1.3 by default for now to avoid interoperability issue.
     * This can be enabled by default once the implementation has been fully
     * completed and tested with other implementations. */
    conf->tls_flags = TLS_CONN_DISABLE_TLSv1_3;

#if HOSTAPD_VERSION >= 210 //2.10
    conf->max_auth_rounds = 100;
    conf->max_auth_rounds_short = 50;
#endif

    conf->send_probe_response = 1;

#ifdef CONFIG_HS20
//Not Defined
    conf->hs20_release = (HS20_VERSION >> 4) + 1;
#endif /* CONFIG_HS20 */

#ifdef CONFIG_MACSEC
//Not Defined
    conf->mka_priority = DEFAULT_PRIO_NOT_KEY_SERVER;
    conf->macsec_port = 1;
#endif /* CONFIG_MACSEC */

    /* Default to strict CRL checking. */
    conf->check_crl_strict = 1;

#ifdef CONFIG_BSS_LOAD
    // updated by driver
    conf->bss_load_update_period = 360000;
#endif

    /* Vendor Specific IE */
    platform_get_vendor_oui_t platform_get_vendor_oui_fn = get_platform_vendor_oui_fn();
    if (platform_get_vendor_oui_fn != NULL) {
        char vendor_oui[128] = {0};
        struct wpabuf *elems = NULL;

        if (platform_get_vendor_oui_fn(vendor_oui, sizeof(vendor_oui)) == 0) {
            wifi_hal_dbg_print("%s:%d: vendor_oui = %s \n", __func__, __LINE__,vendor_oui);
            elems = wpabuf_parse_bin(vendor_oui);

            if (elems) {
                conf->vendor_elements = elems;
            }
        }
    }
}

void init_oem_config(wifi_interface_info_t *interface)
{
#ifdef CONFIG_WPS
    struct hostapd_bss_config *conf;
    wifi_device_info_t device_info;
    conf = &interface->u.ap.conf;
    device_info = get_device_info_details();

    conf->device_name = (char *) &interface->device_name;
    conf->manufacturer = (char *)&interface->manufacturer;
    conf->model_name = (char *)&interface->model_name;
    conf->model_number = (char *)&interface->model_number;
    conf->serial_number = (char *)&interface->serial_number;
    conf->friendly_name = (char *)&interface->friendly_name;
    conf->manufacturer_url = (char *)&interface->manufacturer_url;
    conf->model_description = (char *)&interface->model_description;
    conf->model_url = (char *)&interface->model_url;

    if(wps_dev_type_str2bin("6-0050F204-1", conf->device_type)) {
        wifi_hal_dbg_print("%s:%d: WPS, invalid device_type\n", __func__, __LINE__);
    }

    strcpy(interface->device_name, device_info.device_name);
    strcpy(interface->manufacturer,  device_info.manufacturer);
    strcpy(interface->model_name, device_info.model_name);
    strcpy(interface->model_number, device_info.model_number);
    strcpy(interface->serial_number, device_info.serial_number);
    strcpy(interface->friendly_name, device_info.friendly_name);
    strcpy(interface->manufacturer_url, device_info.manufacturer_url);
    strcpy(interface->model_description, device_info.model_description);
    strcpy(interface->model_url, device_info.model_url);

#if !defined(PLATFORM_LINUX)
    conf->ap_vlan = interface->vlan;
#endif
#endif
}

void driver_init(wifi_interface_info_t *interface)
{
    struct hostapd_data *hapd;
    struct wpa_init_params params;


    hapd = &interface->u.ap.hapd; 

    params.bssid = interface->vap_info.u.bss_info.bssid;
    params.ifname = interface->u.ap.conf.iface;
    params.driver_params = hapd->iconf->driver_params;
    params.own_addr = hapd->own_addr;
    params.num_bridge = 1;
    params.bridge = (char **)&interface->bridge;
    params.global_priv = interface;
    
    hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);
}

void update_hostap_driver(int ap_index, struct hostapd_data *hapd)
{
    hapd->driver = &g_wpa_driver_nl80211_ops;
}

int update_hostap_data(wifi_interface_info_t *interface)
{
    struct hostapd_data *hapd;
    struct hostapd_config *iconf;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;

    vap = &interface->vap_info;

    radio = get_radio_by_rdk_index(vap->radio_index);
    iconf = &radio->iconf;

    hapd = &interface->u.ap.hapd;

    hapd->iface = &interface->u.ap.iface;
    hapd->iconf = iconf;
    hapd->conf = &interface->u.ap.conf;
    hapd->interface_added = true;
    hapd->interface_added = true;
    memcpy(hapd->own_addr, interface->mac, sizeof(mac_address_t));

    hapd->driver = &radio->driver_ops;

    hapd->new_assoc_sta_cb = hostapd_new_assoc_sta;
    hapd->ctrl_sock = -1;

    if (interface->u.ap.hapd_initialized == false) {
        dl_list_init(&hapd->ctrl_dst);
        dl_list_init(&hapd->nr_db);
        interface->u.ap.hapd_initialized = true;
    }
    hapd->dhcp_sock = -1;
#ifdef CONFIG_IEEE80211R_AP
//Defined
    dl_list_init(&hapd->l2_queue);
    dl_list_init(&hapd->l2_oui_queue);
#endif /* CONFIG_IEEE80211R_AP */
#ifdef CONFIG_SAE
//Not Defined
    dl_list_init(&hapd->sae_commit_queue);
#endif /* CONFIG_SAE */

    init_oem_config(interface);
    init_radius_config(interface);
    
    update_hostap_driver(vap->vap_index, hapd);
    driver_init(interface);

    if (hapd->drv_priv == NULL) {
        wifi_hal_error_print("%s:%d:driver params is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static inline bool is_open_sec(wifi_vap_security_t *sec)
{
    return sec->mode == wifi_security_mode_none || sec->mode == wifi_security_mode_enhanced_open;
}

static inline bool is_open_sec_radius_auth(wifi_vap_security_t *sec)
{
    ip_addr_t ipaddr = {}, null_ip = {};

    if (!is_open_sec(sec)) {
        return false;
    }

#ifdef WIFI_HAL_VERSION_3_PHASE2
    if (memcmp(&sec->u.radius.ip, &null_ip, sizeof(ip_addr_t)) == 0) {
        return false;
    }
#else
    if (inet_pton(AF_INET, (const char *)sec->u.radius.ip, &ipaddr.u.IPv4addr) != 1 &&
        inet_pton(AF_INET6, (const char *)sec->u.radius.ip, &ipaddr.u.IPv6addr) != 1) {
        return false;
    }

    if (memcmp(&ipaddr, &null_ip, sizeof(ip_addr_t)) == 0) {
        return false;
    }
#endif

    return true;
}

int update_security_config(wifi_vap_security_t *sec, struct hostapd_bss_config *conf)
{
    char test_ip[45];
    struct in_addr ipaddr;
#ifdef CONFIG_IPV6
    struct in6_addr ipaddrv6;
#endif

    conf->ieee802_1x = 0;
    conf->wpa_key_mgmt = 0;
    conf->wpa = 0;
    memset(&test_ip, 0, sizeof(test_ip));


    switch (sec->mode) {
        case wifi_security_mode_none:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_NONE;
            break;

        case wifi_security_mode_enhanced_open:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_OWE;
            break;
        case wifi_security_mode_wpa_personal:
        case wifi_security_mode_wpa2_personal:
        case wifi_security_mode_wpa_wpa2_personal:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
            break;    

        case wifi_security_mode_wpa_enterprise:
        case wifi_security_mode_wpa2_enterprise:
        case wifi_security_mode_wpa_wpa2_enterprise:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X;
            conf->ieee802_1x = 1;
            break;
        case wifi_security_mode_wpa3_personal:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_SAE;
#ifdef CONFIG_IEEE80211BE
            conf->wpa_key_mgmt |= (conf->disable_11be ? 0 : WPA_KEY_MGMT_SAE_EXT_KEY);
#endif
            conf->auth_algs = WPA_AUTH_ALG_SAE;
#if HOSTAPD_VERSION >= 210 //2.10
            if (is_wifi_hal_6g_radio_from_interfacename(conf->iface) == true) {
                conf->sae_pwe = 1;  /* 0 = Hunt-and-Peck, 1 = Hash-to-Element, 2 = both */
                wifi_hal_info_print("%s:%d: interface_name:%s sae_pwe:%d\n",
                       __func__, __LINE__, conf->iface, conf->sae_pwe);
            } else {
#ifdef CONFIG_IEEE80211BE
                conf->sae_pwe = (1 * !conf->disable_11be);
#else
                conf->sae_pwe = 0;
#endif /* CONFIG_IEEE80211BE */
            }
#endif
            break;
        case wifi_security_mode_wpa3_enterprise:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X_SHA256;
            conf->group_mgmt_cipher= WPA_CIPHER_AES_128_CMAC;
            conf->ieee802_1x = 1;

            break;
        case wifi_security_mode_wpa3_transition:
            conf->wpa_key_mgmt = WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE;
#ifdef CONFIG_IEEE80211BE
//            conf->wpa_key_mgmt |= (conf->disable_11be ? 0 : WPA_KEY_MGMT_SAE_EXT_KEY);
#endif
            conf->auth_algs = WPA_AUTH_ALG_SAE | WPA_AUTH_ALG_SHARED | WPA_AUTH_ALG_OPEN;
#if HOSTAPD_VERSION >= 210 //2.10
#ifdef CONFIG_IEEE80211BE
            conf->sae_pwe = (2 * !conf->disable_11be);
#else
            conf->sae_pwe = 0;
#endif /* CONFIG_IEEE80211BE*/
#endif
            break;
        default:
            conf->wpa_key_mgmt = -1;
            break;
    }

#ifdef CONFIG_SAE
    if (conf->wpa_key_mgmt & WPA_KEY_MGMT_SAE) {
        if (conf->sae_groups == NULL) {
            conf->sae_groups = (int *) os_malloc(sizeof(int) * 3);
            conf->sae_groups[0] = 19;
            conf->sae_groups[1] = 20;
            conf->sae_groups[2] = 21;
            //conf->sae_groups[3] = 0;
        }
    }
#endif

#ifdef CONFIG_IEEE80211W
    conf->ieee80211w = (enum mfp_options)sec->mfp;
    switch (conf->ieee80211w) {
        case MGMT_FRAME_PROTECTION_REQUIRED:
            conf->wpa_key_mgmt &= ~(WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X);
            if (sec->mode == wifi_security_mode_wpa3_transition) {
                conf->wpa_key_mgmt |= WPA_KEY_MGMT_PSK_SHA256;
            }
            /* FALLTHROUGH */
        case MGMT_FRAME_PROTECTION_OPTIONAL:
            switch (sec->mode) {
                case wifi_security_mode_wpa_personal:
                case wifi_security_mode_wpa2_personal:
                case wifi_security_mode_wpa_wpa2_personal:
                    conf->wpa_key_mgmt |= WPA_KEY_MGMT_PSK_SHA256;
                    break;
                case wifi_security_mode_wpa_enterprise:
                case wifi_security_mode_wpa2_enterprise:
                case wifi_security_mode_wpa_wpa2_enterprise:
                    conf->wpa_key_mgmt |= WPA_KEY_MGMT_IEEE8021X_SHA256;
                    break;
                default:
                    break;
            }
            conf->sae_require_mfp = 1;
            break;

        case NO_MGMT_FRAME_PROTECTION:
        default:
            conf->sae_require_mfp = 0;
            break;
    }
#endif

    wifi_hal_dbg_print("%s:%d: security:%d mfp:%d wpa_key_mgmt:%d 11w:%d\n",
                       __func__, __LINE__, sec->mode, sec->mfp, conf->wpa_key_mgmt, conf->ieee80211w);
  
    if (conf->wpa_key_mgmt != -1) {
        const int is_ieee802_1x = !!((WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_IEEE8021X_SHA256) & conf->wpa_key_mgmt);
        conf->ieee802_1x = is_ieee802_1x;
        //eap_server
        conf->eap_server = !is_ieee802_1x;
       
    } else {
        conf->wpa = 0;
    }

    switch (sec->mode) {
        case wifi_security_mode_wpa2_personal:
        case wifi_security_mode_wpa2_enterprise:
        case wifi_security_mode_wpa3_personal:
        case wifi_security_mode_wpa3_enterprise:
        case wifi_security_mode_wpa3_transition:
        case wifi_security_mode_enhanced_open:
            conf->wpa = 2;
            break;

        case wifi_security_mode_wpa_wpa2_personal:
        case wifi_security_mode_wpa_wpa2_enterprise:
            conf->wpa = 1;
            break;

        case wifi_security_mode_none:
            conf->wpa = 0;
            break;

        default:
            break;
    }

    if (sec->mode == wifi_security_mode_none) {
        conf->wpa_pairwise = wpa_parse_cipher("NONE");
    } else {
        switch (sec->encr) {
        case wifi_encryption_tkip:
            conf->wpa_pairwise = wpa_parse_cipher("TKIP");
            break;

        case wifi_encryption_aes:
            conf->wpa_pairwise = WPA_CIPHER_CCMP;
#ifdef CONFIG_IEEE80211BE
            switch (sec->mode) {
                case wifi_security_mode_none:
                case wifi_security_mode_wpa_wpa2_personal:
                case wifi_security_mode_wpa2_personal:
                case wifi_security_mode_wpa3_transition:
                case wifi_security_mode_wpa_enterprise:
                case wifi_security_mode_wpa2_enterprise:
                case wifi_security_mode_wpa_wpa2_enterprise:
                case wifi_security_mode_wpa3_enterprise:
                case wifi_security_mode_enhanced_open:
                    break;
                default:
                    conf->wpa_pairwise |= (conf->disable_11be ? 0 : WPA_CIPHER_GCMP_256);
                    break;
            }
#endif /* CONFIG_IEEE80211BE */
            break;

        case wifi_encryption_aes_tkip:
            conf->wpa_pairwise = wpa_parse_cipher("TKIP CCMP");
            break;

        default:
            wifi_hal_info_print("%s:%d:Invalid encryption mode in VAP setting\n",
                            __func__, __LINE__);
            break;
        }
    }

    conf->wpa_group_rekey = sec->rekey_interval;
    conf->wpa_group_rekey_set = 1;

    wifi_hal_dbg_print("%s:%d: wpa_gmk_rekey:%d wpa_group_rekey:%d\n", __func__, __LINE__, conf->wpa_gmk_rekey, conf->wpa_group_rekey);

    conf->wpa_strict_rekey = sec->strict_rekey;

#if HOSTAPD_VERSION >= 210 //2.10
    conf->transition_disable = sec->wpa3_transition_disable;
#endif

#if 0
    //EAP/EAPOL custom timeout and retry values
    conf->rdkb_eapol_key_timeout = sec->eapol_key_timeout;
    conf->rdkb_eapol_key_retries = sec->eapol_key_retries;
    conf->rdkb_eapidentity_request_timeout = sec->eap_identity_req_timeout;
    conf->rdkb_eapidentity_request_retries = sec->eap_identity_req_retries;
    conf->rdkb_eap_request_timeout = sec->eap_req_timeout;
    conf->rdkb_eap_request_retries = sec->eap_req_retries;
#endif
    if (conf->ieee802_1x || is_open_sec_radius_auth(sec)) {
        conf->disable_pmksa_caching = sec->disable_pmksa_caching;

        if (sec->u.radius.ip == 0) {
            wifi_hal_error_print("%s:%d:Invalid radius server IP configuration in VAP setting\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        if (conf->radius->auth_servers == NULL) {
            static const unsigned int shared_secret_chunk = 64;
            struct hostapd_radius_server *servers;
            char *shared_secrets = NULL;

            if ((shared_secrets = malloc(2 * shared_secret_chunk)) == NULL ||
                (servers = malloc(2 * sizeof(*servers))) == NULL) {
                wifi_hal_error_print(
                    "%s:%d: Failed to allocate memory for radius secret or servers\n", __func__,
                    __LINE__);
                free(shared_secrets);
                return RETURN_ERR;
            }
            memset(servers, 0, 2 * sizeof(*servers));

            conf->radius->num_auth_servers = 2;
            conf->radius->auth_servers = servers;
            conf->radius->auth_server = servers + 1;
            conf->radius->auth_servers[0].shared_secret = shared_secrets;
            conf->radius->auth_servers[1].shared_secret = shared_secrets + shared_secret_chunk;
            conf->radius->fallback_already_done = false;
            conf->radius->retry_primary_interval = RADIUS_FALLBACK_TIMER_IN_SECS;
        }

        char output[256] = {0};
        _syscmd("sh /usr/sbin/deviceinfo.sh -eip", output, sizeof(output));

        //own_ip_addr
        if (inet_aton(output, &conf->own_ip_addr.u.v4)) {
            conf->own_ip_addr.af = AF_INET;
        }

        // nas_identifier
        memset(output, '\0', sizeof(output));
        _syscmd("sh /usr/sbin/deviceinfo.sh -emac", output, sizeof(output));
	if (output[strlen(output) - 1] == '\n') {
           output[strlen(output) - 1] = '\0';
        }
        conf->nas_identifier = strdup(output);
        wifi_hal_dbg_print("%s:%d, Updating NAS identifier %s\n", __func__, __LINE__, output);
        memset(output, '\0', sizeof(output));
        snprintf(output, sizeof(output), "30:s:%s:%s", conf->nas_identifier, conf->ssid.ssid);
        conf->radius_auth_req_attr = hostapd_parse_radius_attr(output);

#ifdef WIFI_HAL_VERSION_3_PHASE2
        if (inet_ntop(AF_INET, &sec->u.radius.ip, test_ip, sizeof(test_ip))) {
            conf->radius->auth_servers[0].addr.af = AF_INET;
            conf->radius->auth_servers[0].addr.u.v4 = sec->u.radius.ip;
        }
#ifdef CONFIG_IPV6
        else if(inet_ntop(AF_INET6, &sec->u.radius.ip, test_ip, sizeof(test_ip))) {
            conf->radius->auth_servers[0].addr.af = AF_INET6;
            conf->radius->auth_servers[0].addr.u.v6 = sec->u.radius.ip;
        }
#endif //CONFIG_IPV6
#else  //WIFI_HAL_VERSION_3_PHASE2
        if (inet_pton(AF_INET, (const char *)sec->u.radius.ip, &ipaddr)) {
            conf->radius->auth_servers[0].addr.af = AF_INET;
            conf->radius->auth_servers[0].addr.u.v4 = ipaddr;
        }
#ifdef CONFIG_IPV6
        else if(inet_pton(AF_INET6, (const char *)sec->u.radius.ip, &ipaddrv6)) {
            conf->radius->auth_servers[0].addr.af = AF_INET6;
            conf->radius->auth_servers[0].addr.u.v6 = ipaddrv6;
        }
#endif //CONFIG_IPV6
#endif //WIFI_HAL_VERSION_3_PHASE2

        strcpy(conf->radius->auth_servers[0].shared_secret, sec->u.radius.key);
        conf->radius->auth_servers[0].shared_secret_len = strlen(conf->radius->auth_servers[0].shared_secret);
        conf->radius->auth_servers[0].port = sec->u.radius.port;


#ifdef WIFI_HAL_VERSION_3_PHASE2
        if (inet_ntop(AF_INET, &sec->u.radius.s_ip, test_ip, sizeof(test_ip))) {
            conf->radius->auth_servers[1].addr.af = AF_INET;
            conf->radius->auth_servers[1].addr.u.v4 = sec->u.radius.s_ip;
        }
#ifdef CONFIG_IPV6
        else if(inet_ntop(AF_INET6, &sec->u.radius.s_ip, test_ip, sizeof(test_ip))) {
            conf->radius->auth_servers[1].addr.af = AF_INET6;
            conf->radius->auth_servers[1].addr.u.v6 = sec->u.radius.s_ip;
        }
#endif //CONFIG_IPV6
#else  //WIFI_HAL_VERSION_3_PHASE2
        if (inet_pton(AF_INET, (const char *)&sec->u.radius.s_ip, &ipaddr)) {
            conf->radius->auth_servers[1].addr.af = AF_INET;
            conf->radius->auth_servers[1].addr.u.v4 = ipaddr;
        }
#ifdef CONFIG_IPV6
        else if(inet_pton(AF_INET6, (const char *)&sec->u.radius.s_ip, &ipaddrv6)) {
            conf->radius->auth_servers[1].addr.af = AF_INET6;
            conf->radius->auth_servers[1].addr.u.v6 = ipaddrv6;
        }
#endif //CONFIG_IPV6
#endif //WIFI_HAL_VERSION_3_PHASE2

        strcpy(conf->radius->auth_servers[1].shared_secret, sec->u.radius.s_key);
        conf->radius->auth_servers[1].shared_secret_len = strlen(conf->radius->auth_servers[1].shared_secret);
        conf->radius->auth_servers[1].port = sec->u.radius.s_port;

        if (is_open_sec_radius_auth(sec)) {
            conf->radius_das_port = sec->u.radius.dasport;
            conf->radius_das_shared_secret = sec->u.radius.daskey;
            conf->radius_das_shared_secret_len = strlen( conf->radius_das_shared_secret);
            getIpStringFromAdrress(test_ip, &sec->u.radius.dasip);

            if (inet_pton(AF_INET, test_ip, &ipaddr)) {
                conf->radius_das_client_addr.af = AF_INET;
                conf->radius_das_client_addr.u.v4 = ipaddr;
            }
#ifdef CONFIG_IPV6
            if (inet_pton(AF_INET6, test_ip,&ipaddrv6 )) {
                conf->radius_das_client_addr.af = AF_INET6;
                conf->radius_das_client_addr.u.v6 = ipaddrv6;
            }
#endif //CONFIG_IPV6
        }
#if 0
        inet_aton(sec->u.radius.ip, &conf->radius->auth_servers->addr.u.v4);
        //conf->radius->auth_servers->addr.u.v4.s_addr = sec->u.radius.ip;
        conf->radius->auth_servers->addr.af = AF_INET;
        conf->radius->auth_servers->port = sec->u.radius.port;
        strcpy(conf->radius->auth_servers->shared_secret, sec->u.radius.key);
        conf->radius->auth_servers->shared_secret_len = strlen(conf->radius->auth_servers->shared_secret);

        if (sec->u.radius.s_ip != 0) {
            inet_aton(sec->u.radius.s_ip, &conf->radius->auth_server->addr.u.v4);
            //conf->radius->auth_server->addr.u.v4.s_addr = sec->u.radius.s_ip;
            conf->radius->auth_server->addr.af = AF_INET;
            conf->radius->auth_server->port = sec->u.radius.s_port;
            strcpy(conf->radius->auth_server->shared_secret, sec->u.radius.s_key);
            conf->radius->auth_server->shared_secret_len = strlen(conf->radius->auth_server->shared_secret);
        }
#endif       
        // # EAP/EAPOL custom timeout and retry values 
        //conf->max_auth_attempts = sec->u.radius.max_auth_attempts;
        //conf->blacklist_timeout = sec->u.radius.blacklist_table_timeout;

        //conf->identity_request_retry_interval = sec->u.radius.identity_req_retry_interval;
        //conf->radius->radius_server_retries = sec->u.radius.server_retries;
    } else {
        if (conf->radius->auth_servers != NULL) {
            free(conf->radius->auth_servers->shared_secret);
            free(conf->radius->auth_servers);
            conf->radius->auth_servers = NULL;
            conf->radius->auth_server = NULL;
            conf->radius->num_auth_servers = 0;
        }

        if (!is_open_sec(sec)) {
            // set wpa passphrase security key and indication flag
            strcpy(conf->ssid.wpa_passphrase, sec->u.key.key);
            conf->ssid.wpa_passphrase_set = true;
            conf->osen = 0;
        }
    }
    return RETURN_OK;
}

wifi_enum_to_str_map_t wps_config_method_table[] = {
    {WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE,  "USBFlashDrive"}, //unable to fins respective string in hapd
    {WIFI_ONBOARDINGMETHODS_ETHERNET,       "ethernet"},
    {WIFI_ONBOARDINGMETHODS_LABEL,      "label"},
    {WIFI_ONBOARDINGMETHODS_DISPLAY,        "display"},
    {WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN,   "ext_nfc_token"},
    {WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN, "int_nfc_token"},
    {WIFI_ONBOARDINGMETHODS_NFCINTERFACE,       "nfc_interface"},
    {WIFI_ONBOARDINGMETHODS_PUSHBUTTON,     "push_button"},
    {WIFI_ONBOARDINGMETHODS_PIN,        "keypad"},
    {WIFI_ONBOARDINGMETHODS_PHYSICALPUSHBUTTON, "physical_push_button"},
    {WIFI_ONBOARDINGMETHODS_PHYSICALDISPLAY,    "physical_display"},
    {WIFI_ONBOARDINGMETHODS_VIRTUALPUSHBUTTON,  "virtual_push_button"},
    {WIFI_ONBOARDINGMETHODS_VIRTUALDISPLAY, "virtual_display"},
    {WIFI_ONBOARDINGMETHODS_EASYCONNECT,        "EASYCONNECT"}, // not expected in WPS APIs
    {0xff,                      NULL}
};

void wps_enum_to_string(unsigned int methods, char *str, int len) {

    int itr = 0, size = 0;
    for (itr = 0; wps_config_method_table[itr].str_val != NULL; ++itr) {
        if (methods & wps_config_method_table[itr].enum_val) {
            if(str[0] == '\0') {
                size = snprintf(str, len, "%s",
                        wps_config_method_table[itr].str_val);
            }
            else {
                size += snprintf(str + size, len - size,
                         ",%s", wps_config_method_table[itr].str_val);
            }
        }
    }
}

#if defined(CONFIG_WPS)
static int wifi_hal_band_to_wps_band(wifi_freq_bands_t hal_band, u8 *wps_band)
{
    switch (hal_band) {
    case WIFI_FREQUENCY_2_4_BAND:
        *wps_band = WPS_RF_24GHZ;
        break;
    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        *wps_band = WPS_RF_50GHZ;
        break;
    case WIFI_FREQUENCY_6_BAND:
        /* WPS is not supported in 6G */
        *wps_band = 0;
        break;
    default:
        wifi_hal_error_print("%s:%d Unsupported frequency band\n", __func__, __LINE__);
        return -1;
    }

    return 0;
}

static bool wifi_hal_is_wps_enabled(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
    struct hostapd_bss_config *conf)
{
    return vap->u.bss_info.wps.enable && !conf->ignore_broadcast_ssid &&
        radio->oper_param.band != WIFI_FREQUENCY_6_BAND;
}

static void wifi_hal_wps_init(wifi_radio_info_t *radio, wifi_vap_info_t *vap,
    struct hostapd_bss_config *conf)
{
    u8 wps_band;
    wifi_vap_type_t vap_type;
    wifi_radio_info_t *radio_iter;
    wifi_interface_info_t *interface_iter;

    conf->wps_state = 0;
    conf->wps_rf_bands = 0;

    if (!wifi_hal_is_wps_enabled(radio, vap, conf)) {
        return;
    }

    if (wifi_hal_get_vap_interface_type(vap->vap_name, vap_type) < 0) {
        wifi_hal_error_print("%s:%d failed to get vap type for %s\n", __func__, __LINE__,
            vap->vap_name);
        return;
    }

    conf->wps_state |= WPS_STATE_CONFIGURED;

    for (int i = 0; i < g_wifi_hal.num_radios; i++) {
        if ((radio_iter = get_radio_by_rdk_index(i)) == NULL) {
            continue;
        }

        if ((interface_iter = wifi_hal_get_vap_interface_by_type(radio_iter, vap_type)) == NULL) {
            continue;
        }

        if (wifi_hal_band_to_wps_band(radio_iter->oper_param.band, &wps_band) < 0) {
            continue;
        }

        // Advertise all bands supported by AP
        conf->wps_rf_bands |= wps_band;

        // Use first interface UUID for all bands
        if (is_nil_uuid(conf->uuid)) {
            uuid_gen_mac_addr(interface_iter->mac, conf->uuid);
        }
    }

    if (vap->u.bss_info.wps.methods ==
        (WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN)) {
        strncpy(conf->config_methods, "label display push_button keypad", WPS_METHODS_SIZE - 1);
    } else if (vap->u.bss_info.wps.methods == WIFI_ONBOARDINGMETHODS_PUSHBUTTON) {
        strncpy(conf->config_methods,
            "display virtual_push_button physical_push_button push_button virtual_display",
            WPS_METHODS_SIZE - 1);
    } else if (vap->u.bss_info.wps.methods == WIFI_ONBOARDINGMETHODS_PIN) {
        strncpy(conf->config_methods, "keypad label display", WPS_METHODS_SIZE - 1);
    }
    wifi_hal_info_print("%s:%d Wi-Fi WPS config methods: %d\n", __func__, __LINE__,
        vap->u.bss_info.wps.methods);

    if (strlen(vap->u.bss_info.wps.pin) != 0) {
        strncpy(conf->ap_pin, vap->u.bss_info.wps.pin, WPS_PIN_SIZE - 1);
    }

    conf->wps_cred_processing = 1;
    conf->pbc_in_m1 = 1;
}
#endif /* defined(CONFIG_WPS) */

#if defined(CONFIG_HW_CAPABILITIES)
static struct hostapd_channel_data *hw_mode_get_channel(struct hostapd_hw_modes *mode, int freq,
    int *chan)
{
    for (int i = 0; i < mode->num_channels; i++) {
        struct hostapd_channel_data *ch = &mode->channels[i];

        if (ch->freq == freq) {
            if (chan) {
                *chan = ch->chan;
            }
            return ch;
        }
    }

    return NULL;
}

static struct hostapd_hw_modes *get_hw_mode(struct hostapd_iface *iface)
{
    enum hostapd_hw_mode hw_mode = iface->conf->hw_mode;

    for (int i = 0; i < iface->num_hw_features; i++) {
        if (iface->hw_features[i].mode == hw_mode && iface->freq > 0 &&
            hw_mode_get_channel(&iface->hw_features[i], iface->freq, NULL)) {
            return &iface->hw_features[i];
        }
    }

    if (hw_mode == HOSTAPD_MODE_IEEE80211G) {
        hw_mode = HOSTAPD_MODE_IEEE80211B;
        for (int i = 0; i < iface->num_hw_features; i++) {
            if (iface->hw_features[i].mode == hw_mode && iface->freq > 0 &&
                hw_mode_get_channel(&iface->hw_features[i], iface->freq, NULL)) {
                return &iface->hw_features[i];
            }
        }
    }

    return NULL;
}
#endif

int update_hostap_bss(wifi_interface_info_t *interface)
{
    struct hostapd_bss_config   *conf;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    mac_addr_str_t  mac_str;
    wifi_radio_operationParam_t *op_param;
    int vlan_id = 0;
    // re-initialize the default parameters
    init_hostap_bss(interface);

    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    op_param = &radio->oper_param;

    conf = &interface->u.ap.conf;

#ifdef CONFIG_IEEE80211BE
    conf->disable_11be = !radio->iconf.ieee80211be;
#endif /* CONFIG_IEEE80211BE */

    strcpy(conf->iface, interface->name);
    strcpy(conf->bridge, interface->bridge);
    sprintf(conf->vlan_bridge, "vlan%d", vap->vap_index);

    conf->ctrl_interface = interface->ctrl_interface;
    strcpy(conf->ctrl_interface, "/var/run/hostapd");
    conf->ctrl_interface_gid_set = 1;

    memcpy(conf->bssid, interface->mac, sizeof(interface->mac));

    memset(conf->ssid.ssid, 0, sizeof(conf->ssid.ssid));
    strcpy(conf->ssid.ssid, vap->u.bss_info.ssid);
    conf->ssid.ssid_len = strlen(vap->u.bss_info.ssid);
    if (!conf->ssid.ssid_len)
        conf->ssid.ssid_set = 0;
    else
        conf->ssid.ssid_set = 1;
        
    conf->ssid.utf8_ssid = 0;

    //dtim_period
    conf->dtim_period = op_param->dtimPeriod;

    //max_num_sta
    conf->max_num_sta = vap->u.bss_info.bssMaxSta;
    //macaddr_acl
    //conf->macaddr_acl = vap->u.bss_info.mac_addr_acl_enabled;

    //ignore_broadcast_ssid
    conf->ignore_broadcast_ssid = (vap->u.bss_info.showSsid == true)?false:true;

    conf->isolate = vap->u.bss_info.isolation;
    wifi_hal_dbg_print("%s:%d: AP isolate:%d \r\n", __func__, __LINE__, conf->isolate);

#if defined(CONFIG_WPS)
    wifi_hal_wps_init(radio, vap, conf);
#endif

    //wme_enabled, uapsd_enabled
    conf->wmm_enabled = vap->u.bss_info.wmm_enabled;
    conf->wmm_uapsd = vap->u.bss_info.UAPSDEnabled;

    if (update_security_config(&vap->u.bss_info.security, conf) == -1) {
        wifi_hal_error_print("%s:%d:update_security_config failed \n", __func__, __LINE__);
        return RETURN_ERR;
    }
#if 0
#ifdef CONFIG_IEEE80211W
    bss->ieee80211w = vap->u.bss_info.mfp;
#endif
#endif
    conf->bss_transition = vap->u.bss_info.bssTransitionActivated;
    /*Enable Beacon passive , Beacon active and Beacon table support by default */
    conf->radio_measurements[0] |=  (WLAN_RRM_CAPS_BEACON_REPORT_PASSIVE | WLAN_RRM_CAPS_BEACON_REPORT_ACTIVE | WLAN_RRM_CAPS_BEACON_REPORT_TABLE);
    if(vap->u.bss_info.nbrReportActivated) {
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_NEIGHBOR_REPORT;
#if defined(CMXB7_PORT) || defined(MXL_WIFI)
        conf->radio_measurements[0] |= WLAN_RRM_CAPS_LINK_MEASUREMENT; 
#endif
#if defined(MXL_WIFI)
        conf->radio_measurements[1] |= WLAN_RRM_CAPS_STATISTICS_MEASUREMENT | WLAN_RRM_CAPS_CHANNEL_LOAD;
#endif
    }
    else {
         conf->radio_measurements[0] &= ~(WLAN_RRM_CAPS_NEIGHBOR_REPORT);
    }

#ifdef CONFIG_USE_HOSTAP_BTM_PATCH
    // - these variables initialized by hostapd code
#else
    interface->wnm_bss_trans_query_auto_resp = false;  /* optonal: set default value for auto response feature */
    interface->bss_transition_token = 0;
#endif

#if !defined(PLATFORM_LINUX)
    // connected_building_enabled
    if (is_wifi_hal_vap_hotspot_from_interfacename(conf->iface)) {
        conf->connected_building_avp = vap->u.bss_info.connected_building_enabled;
        wifi_hal_info_print("%s:%d:connected_building_enabled is %d  and ifacename is %s\n", __func__, __LINE__,conf->connected_building_avp,conf->iface);
    }
   // rdk_greylist
    conf->rdk_greylist = vap->u.bss_info.network_initiated_greylist;
    if(conf->rdk_greylist) {
        wifi_hal_dbg_print("%s:%d:rdk_grey_list is %d  and ifacename is %s\n", __func__, __LINE__,conf->rdk_greylist,conf->iface);
        vlan_id = get_ap_vlan_id(conf->iface);
        wifi_hal_dbg_print(" %s:%d:vlan_id is %d  \n", __func__, __LINE__,vlan_id);
        conf->ap_vlan = vlan_id;
    }
#endif

#if HOSTAPD_VERSION >= 210 
    int preassoc_min_mcs = convert_string_mcs_to_int(vap->u.bss_info.preassoc.minimum_advertised_mcs);
    conf->min_adv_mcs = preassoc_min_mcs;
    wifi_hal_dbg_print("%s:%d:min_adv_mcs is %d  and ifacename is %s\n", __func__, __LINE__,conf->min_adv_mcs,conf->iface);
#endif
    /* IEEE 802.11u - Interworking */
    conf->interworking = vap->u.bss_info.interworking.interworking.interworkingEnabled;
    //access_network_type
    conf->access_network_type = vap->u.bss_info.interworking.interworking.accessNetworkType;
    if (conf->access_network_type < 0 || conf->access_network_type > 15) {
        wifi_hal_error_print("%s:%d:Invalid access network setting in VAP setting : %d\n", __func__, __LINE__, conf->access_network_type);
        return RETURN_ERR;
    }

    //internet
    conf->internet = vap->u.bss_info.interworking.interworking.internetAvailable;
    //asra
    conf->asra = vap->u.bss_info.interworking.interworking.asra;
    //esr
    conf->esr = vap->u.bss_info.interworking.interworking.esr;
    //uesa
    conf->uesa = vap->u.bss_info.interworking.interworking.uesa;
    //venue_group
    conf->venue_group = vap->u.bss_info.interworking.interworking.venueGroup;
    //venue_type
    conf->venue_type = vap->u.bss_info.interworking.interworking.venueType;
    conf->venue_info_set = vap->u.bss_info.interworking.interworking.venueOptionPresent;
    
    //hessid

    strcpy(conf->hessid, to_mac_str(vap->u.bss_info.interworking.interworking.hessid, mac_str));
    to_mac_bytes((vap->u.bss_info.interworking.interworking.hessid), conf->hessid);
    wifi_hal_dbg_print(" %s: %s 802.11u - NEW IW_En=%d access_network_type=%d conf->[venue_info_set=%d venue_group=%d venue_type=%d hessid="MACF"]\n",
                __func__, interface->name, conf->interworking, conf->access_network_type,
                conf->venue_info_set, conf->venue_group, conf->venue_type, MAC_TO_MACF(conf->hessid));
    hostapd_set_security_params(conf, 1);
    if (vap->u.bss_info.interworking.passpoint.enable) {
        wifi_hal_dbg_print("gafDisable %d,p2pDisable %d l2tfi %d\n",vap->u.bss_info.interworking.passpoint.gafDisable,vap->u.bss_info.interworking.passpoint.p2pDisable,vap->u.bss_info.interworking.passpoint.l2tif);
        wifi_hal_dbg_print("%s:%d, Passpoint enabled hence add roaming consortium IE \n", __func__, __LINE__);

#if !defined(PLATFORM_LINUX)
        conf->hs20 = 1;
        conf->hs20_release = 1;
        conf->disable_dgaf = vap->u.bss_info.interworking.passpoint.gafDisable;
#endif
        conf->roaming_consortium_count = 0;
        conf->roaming_consortium = NULL;
        const wifi_roamingConsortiumElement_t *rc_p = &(vap->u.bss_info.interworking.roamingConsortium);
        unsigned char rc_cnt = rc_p->wifiRoamingConsortiumCount;
        wifi_hal_dbg_print("roaming consoritum count = %d\n",rc_cnt);
        rc_cnt = (rc_cnt > 3) ? 3 : rc_cnt;
        wifi_hal_dbg_print("%s:%d, rc_cnt consortium,%d\n", __func__, __LINE__, rc_cnt);
        for(unsigned char j = 0; j < rc_cnt; ++j) {
            struct hostapd_roaming_consortium *rc = os_realloc_array(conf->roaming_consortium, conf->roaming_consortium_count + 1, sizeof(struct hostapd_roaming_consortium));

            if(rc == NULL) {
                wifi_hal_error_print("%s:%d, Failed to add roaming consortium, indx: %d\n", __func__, __LINE__, j);
            } else {
                os_memcpy(rc[conf->roaming_consortium_count].oi, rc_p->wifiRoamingConsortiumOui[j], rc_p->wifiRoamingConsortiumLen[j]);
                rc[conf->roaming_consortium_count].len = rc_p->wifiRoamingConsortiumLen[j];
                conf->roaming_consortium = rc;
                conf->roaming_consortium_count++;
                wifi_hal_error_print("%s:%d, Added roaming consortium, indx: %d\n", __func__, __LINE__, j);
            }
            wifi_hal_dbg_print("%s:%d,  add roaming consortium, indx:\n", __func__, __LINE__);
        }

   }
   else {
        wifi_hal_dbg_print("%s:%d,Passpoint is disabled roaming consoritum and HS beacons are reset:\n", __func__, __LINE__);
        conf->roaming_consortium_count = 0;
        conf->roaming_consortium = NULL;
#if !defined(PLATFORM_LINUX)
        conf->hs20 = 0;
        conf->hs20_release = 0;
        conf->disable_dgaf = 0;
#endif
   }

#if defined(CONFIG_MBO)
    conf->mbo_enabled = vap->u.bss_info.mbo_enabled;
    /* MBO with WPA2 requires PMF */
    if ((conf->wpa & 2) && conf->ieee80211w == NO_MGMT_FRAME_PROTECTION) {
        conf->mbo_enabled = false;
    }
#endif /* defined(CONFIG_MBO) */

    return RETURN_OK;
}

int init_hostap_hw_features(wifi_interface_info_t *interface)
{
    struct hostapd_iface   *iface;
    wifi_vap_info_t        *vap;
    wifi_radio_info_t      *radio;
    enum nl80211_iftype     nlmode;

    if (!interface) {
        return RETURN_ERR;
    }

    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    iface = &interface->u.ap.iface;
    iface->num_bss = 1;
    iface->bss = interface->u.ap.hapds;
    interface->u.ap.hapds[0] = &interface->u.ap.hapd;

    hostapd_get_hw_features(iface);

    if (iface->num_hw_features < 1) {
        return RETURN_ERR;
    }

    nlmode = wpa_driver_nl80211_if_type(WPA_IF_AP_BSS);

    /* Replace the default value if a per-interface type value exists */
    for (unsigned int i = 0; i < radio->driver_data.num_iface_ext_capa; i++) {
        if (nlmode == radio->driver_data.iface_ext_capa[i].iftype) {
            iface->extended_capa = radio->driver_data.iface_ext_capa[i].ext_capa;
            iface->extended_capa_mask = radio->driver_data.iface_ext_capa[i].ext_capa_mask;
            iface->extended_capa_len = radio->driver_data.iface_ext_capa[i].ext_capa_len;
            break;
        }
    }

    return RETURN_OK;
}

int update_hostap_radio_param(wifi_radio_info_t *radio, const wifi_radio_operationParam_t *newParam)
{
    wifi_interface_info_t *interface = NULL;

    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:wifi_radio_info is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (newParam == NULL) {
        wifi_hal_error_print("%s:%d:newParam is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    /* Check if certain radio parameters need to be updated */
    if ((radio->oper_param.dtimPeriod == newParam->dtimPeriod) && (radio->oper_param.stbcEnable == newParam->stbcEnable)) {
        /* no need to update */
        return RETURN_OK;
    }

    /* Update params in radio structure */
    radio->oper_param.dtimPeriod = newParam->dtimPeriod;
    radio->oper_param.stbcEnable = newParam->stbcEnable;

    /* Update settings in all VAPS */


    interface = hash_map_get_first(radio->interface_map);
    if (interface == NULL ) {
        wifi_hal_error_print("%s:%d: Interface map is empty for radio\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    while (interface != NULL) {
        if (interface->vap_info.vap_mode == wifi_vap_mode_ap) {
            pthread_mutex_lock(&g_wifi_hal.hapd_lock);
            struct hostapd_bss_config *conf = &interface->u.ap.conf;
            struct hostapd_iface *iface = &interface->u.ap.iface;

            /* - update dtimPeriod */
            conf->dtim_period = newParam->dtimPeriod;

            /* - update stbc */
            if (iface->conf && iface->current_mode) {
                /* 1. cleanup TX STBC bit in HT_CAPS and VHT_CAPS */
                iface->conf->ht_capab &= ~HT_CAP_INFO_TX_STBC;
                iface->conf->vht_capab &= ~VHT_CAP_TXSTBC;

                /* 2. if stbc support is enabled, copy bit from HW caps */

                if (newParam->stbcEnable) {
                    /* if stbc support is enabled, copy bit from HW caps */
                    iface->conf->ht_capab |= (iface->current_mode->ht_capab & HT_CAP_INFO_TX_STBC);
                    iface->conf->vht_capab |= (iface->current_mode->vht_capab & VHT_CAP_TXSTBC);
                }
            }
            pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }

    return RETURN_OK;
}

int update_hostap_iface_flags(wifi_interface_info_t *interface)
{
    struct hostapd_iface   *iface;
    wifi_radio_info_t *radio;

    if (interface == NULL) {
        return RETURN_ERR;
    }

    radio = get_radio_by_rdk_index(interface->vap_info.radio_index);
    iface = &interface->u.ap.iface;

    iface->drv_flags = radio->driver_data.capa.flags;
    iface->drv_flags |= WPA_DRIVER_FLAGS_EAPOL_TX_STATUS;
    iface->drv_flags |= WPA_DRIVER_FLAGS_AP_MLME;
    iface->drv_flags |= WPA_DRIVER_FLAGS_AP_CSA;
    // XXX: Such ability should be retrieved during NL80211_CMD_GET_WIPHY
    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_PROBE_RESP_OFFLOAD) {
        iface->drv_flags |= WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD;
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_STA_INACTIVITY_TIMER) {
        iface->drv_flags |= WPA_DRIVER_FLAGS_INACTIVITY_TIMER;
    }

    return 0;
}

int update_hostap_iface(wifi_interface_info_t *interface)
{
    struct hostapd_iface   *iface;
    wifi_vap_info_t *vap;
    wifi_radio_info_t *radio;
    //mac_addr_str_t  mac_str;
    wifi_radio_operationParam_t *param;
    char country[8];
    enum nl80211_band band;
    unsigned int i;
    static const int basic_rates_a[] = { 60, 120, 240, -1 };
    static const int basic_rates_b[] = { 10, 20, -1 };
    static const int basic_rates_g[] = { 60, 120, 240, -1 };
    static const int basic_rates_bg[] = { 10, 20, 55, 110, -1 };
    struct hostapd_hw_modes *mode;
    struct hostapd_rate_data *rate;
    unsigned int global_op_class;
    int freq1;
    int cf1;
    u8 seg0;
    int *preassoc_basic_rates={0};
    int *preassoc_supp_rates={0};
    char basic_buf[32] = {0};
    char supp_buf[32] ={0};
#ifdef CONFIG_IEEE80211AX
    struct he_capabilities *drv_he_cap;
#endif

    if (interface == NULL) {
        return RETURN_ERR;
    }
    vap = &interface->vap_info;
    radio = get_radio_by_rdk_index(vap->radio_index);
    param = &radio->oper_param;
    
    iface = &interface->u.ap.iface;
    iface->interfaces = &radio->interfaces;
    iface->conf = &radio->iconf;
    strcpy(iface->phy, radio->name);
    iface->state = HAPD_IFACE_ENABLED;

    iface->num_bss = 1;
    iface->bss = interface->u.ap.hapds;
    interface->u.ap.hapds[0] = &interface->u.ap.hapd;

    wifi_hal_info_print("%s:%d: Interface: %s basic_data_transmit_rates:%s, supported_data_transmit_rates:%s\n", __func__, __LINE__,
        interface->name, vap->u.bss_info.preassoc.basic_data_transmit_rates, vap->u.bss_info.preassoc.supported_data_transmit_rates);
    if ((strlen (vap->u.bss_info.preassoc.basic_data_transmit_rates) > 0) && strcmp(vap->u.bss_info.preassoc.basic_data_transmit_rates, "disabled")) {
        snprintf(basic_buf, sizeof(basic_buf), "%s", vap->u.bss_info.preassoc.basic_data_transmit_rates);
        convert_string_to_int(&preassoc_basic_rates,basic_buf);
    }
    if ((strlen (vap->u.bss_info.preassoc.supported_data_transmit_rates) > 0) && strcmp(vap->u.bss_info.preassoc.supported_data_transmit_rates, "disabled")) {
      snprintf(supp_buf, sizeof(supp_buf), "%s", vap->u.bss_info.preassoc.supported_data_transmit_rates);
      convert_string_to_int(&preassoc_supp_rates,supp_buf);
    }
    
    switch (radio->oper_param.band) {
    case WIFI_FREQUENCY_2_4_BAND:
        band = NL80211_BAND_2GHZ;
        break;

    case WIFI_FREQUENCY_5_BAND:
    case WIFI_FREQUENCY_5L_BAND:
    case WIFI_FREQUENCY_5H_BAND:
        band = NL80211_BAND_5GHZ;
        break;

#if HOSTAPD_VERSION >= 210
    case WIFI_FREQUENCY_6_BAND:
        band = NL80211_BAND_6GHZ;
        break;
#endif

    default:
        wifi_hal_error_print("%s:%d: Unknown band: %d\n", __func__, __LINE__,
            radio->oper_param.band);
        if(preassoc_supp_rates) {
          os_free(preassoc_supp_rates);
          preassoc_supp_rates = NULL;
        }
        if(preassoc_basic_rates) {
          os_free(preassoc_basic_rates);
          preassoc_basic_rates = NULL;
        }
        return RETURN_ERR;
    }

    iface->basic_rates = radio->basic_rates[band];

    get_coutry_str_from_code(param->countryCode, country);
    iface->freq = ieee80211_chan_to_freq(country, param->op_class, param->channel);

#if defined(CONFIG_HW_CAPABILITIES)
    iface->current_mode = get_hw_mode(iface);
    if (iface->current_mode == NULL) {
        wifi_hal_error_print("%s:%d failed to get mode, interface: %s hw mode: %d, freq: %d\n",
            __func__, __LINE__, interface->name, iface->conf->hw_mode, iface->freq);
        return RETURN_ERR;
    }
#else
    iface->current_mode = &radio->hw_modes[band];
#endif
    mode = iface->current_mode;

#if !defined(PLATFORM_LINUX)
    if ((strlen (vap->u.bss_info.preassoc.supported_data_transmit_rates) > 0) && strcmp(vap->u.bss_info.preassoc.supported_data_transmit_rates, "disabled")) {
        if(iface->current_cac_rates) {
            os_free(iface->current_cac_rates);
        }
        iface->current_cac_rates = os_calloc(mode->num_rates, sizeof(struct hostapd_rate_data));
        if (!iface->current_cac_rates) {
            wifi_hal_info_print("%s:%d Failed to allocate memory\n",__func__,__LINE__);
            if(preassoc_supp_rates) {
                os_free(preassoc_supp_rates);
                preassoc_supp_rates = NULL;
            }
            if(preassoc_basic_rates) {
                os_free(preassoc_basic_rates);
                preassoc_basic_rates = NULL;
            }
            return RETURN_ERR;
        }
    }
    else {
        iface->current_rates = radio->rate_data[band];
    }
#endif
    wifi_hal_info_print("%s:%d: Interface: %s band: %d mode:%p (%d) has %d rates\n", __func__,
        __LINE__, interface->name, band, mode, mode->mode, mode->num_rates);

    if ((param->variant & WIFI_80211_VARIANT_G) && !(param->variant & WIFI_80211_VARIANT_B)) {
        memcpy(radio->basic_rates[band], basic_rates_g, sizeof(basic_rates_g));
        mode->mode = HOSTAPD_MODE_IEEE80211G;
    } else if (param->variant & WIFI_80211_VARIANT_B) {
        memcpy(radio->basic_rates[band], basic_rates_b, sizeof(basic_rates_b));
        mode->mode = HOSTAPD_MODE_IEEE80211B;
    } else if (param->variant & WIFI_80211_VARIANT_A) {
        memcpy(radio->basic_rates[band], basic_rates_a, sizeof(basic_rates_a));
        mode->mode = HOSTAPD_MODE_IEEE80211A;
    } else if (band == NL80211_BAND_2GHZ) {
        memcpy(radio->basic_rates[band], basic_rates_bg, sizeof(basic_rates_bg));
        mode->mode = HOSTAPD_MODE_IEEE80211G;
    } else {
        memcpy(radio->basic_rates[band], basic_rates_a, sizeof(basic_rates_a));
        mode->mode = HOSTAPD_MODE_IEEE80211A;
    }
#ifdef FEATURE_IEEE80211BE
    /*
        TODO: need to add rule for ieee80211be variant
    */
#endif

    wifi_hal_info_print("%s:%d: Interface: %s band: %d mode:%p (%d) has %d rates\n", __func__,
        __LINE__, interface->name, band, mode, mode->mode, mode->num_rates);
    iface->num_rates = 0;
#if !defined(PLATFORM_LINUX) 
    for (i = 0; i < mode->num_rates; i++) {
/*
        if (iface->conf->supported_rates &&
            !hostapd_rate_found(iface->conf->supported_rates,
                    mode->rates[i]))
            continue;
*/

        if (preassoc_supp_rates) {
              if (!hostapd_rate_found(preassoc_supp_rates,
                      mode->rates[i])) {
                  continue;
              } else {
                  rate = &iface->current_cac_rates[iface->num_rates];
                  rate->rate = mode->rates[i];
              }
        } else {
            rate = &iface->current_rates[iface->num_rates];
            rate->rate = mode->rates[i];
        }
        if (preassoc_basic_rates) { 
            if (hostapd_rate_found(preassoc_basic_rates, rate->rate)) {
            rate->flags |= HOSTAPD_RATE_BASIC;
            }
            else {
              rate->flags &= ~(HOSTAPD_RATE_BASIC);
            }
        } else {
          if (hostapd_rate_found(iface->basic_rates, rate->rate)) {
              rate->flags |= HOSTAPD_RATE_BASIC;
          }
          else {
            rate->flags &= ~(HOSTAPD_RATE_BASIC);
          }
        }
        wifi_hal_dbg_print("%s:%d: RATE[%d] rate=%d flags=0x%x\n", __func__, __LINE__,
            iface->num_rates, rate->rate, rate->flags);
        iface->num_rates++;
    }
#endif /* !defined(PLATFORM_LINUX) */
    cf1 = iface->freq;
    freq1 = cf1;

    switch (param->channelWidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            break;

        case WIFI_CHANNELBANDWIDTH_40MHZ:
            if ((iface->conf->secondary_channel = get_sec_channel_offset(radio, iface->freq)) == 0) {
                wifi_hal_info_print("%s:%d: Failed to get sec channel offset for dev:%d\n", __func__, __LINE__, radio->index);
            }
            cf1 = iface->freq + iface->conf->secondary_channel*10;
            break;

        case WIFI_CHANNELBANDWIDTH_80MHZ:
            cf1 = get_bw80_center_freq(param, country);
            freq1 = cf1 - 30;
            iface->conf->secondary_channel = (abs(iface->freq - freq1) / 20) % 2 == 0 ? 1 : -1;
            break;

        case WIFI_CHANNELBANDWIDTH_160MHZ:
            cf1 = get_bw160_center_freq(param, country);
            freq1 = cf1 - 70;
            iface->conf->secondary_channel = (abs(iface->freq - freq1) / 20) % 2 == 0 ? 1 : -1;
            break;
#ifdef CONFIG_IEEE80211BE
        case WIFI_CHANNELBANDWIDTH_320MHZ:
            cf1 = get_bw320_center_freq(param, country);
            freq1 = cf1 - 150; //from calculate_chan_offset
            iface->conf->secondary_channel = (abs(iface->freq - freq1) / 20) % 2 == 0 ? 1 : -1;
            break;
#endif /* CONFIG_IEEE80211BE */
        case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            break;
        default:
            break;
    }

    ieee80211_freq_to_chan(cf1, &seg0);

    hostapd_set_oper_centr_freq_seg0_idx(interface->u.ap.hapd.iconf, seg0);

    global_op_class = (unsigned int) country_to_global_op_class(country, (unsigned char)param->op_class);
    wifi_hal_info_print("%s:%d:interface name:%s country:%s op class:%d global op class:%d channel:%d frequency:%d center_freq1:%d\n", __func__, __LINE__, 
        interface->name, country, param->op_class, global_op_class, param->channel, iface->freq, cf1);
    if (interface->u.ap.iface_initialized == false) {
        dl_list_init(&iface->sta_seen);
        interface->u.ap.iface_initialized = true;
    }

#if defined(CONFIG_HW_CAPABILITIES) || defined(VNTXER5_PORT)
    iface->drv_flags = radio->driver_data.capa.flags;
#if HOSTAPD_VERSION >= 210
    iface->drv_flags2 = radio->driver_data.capa.flags2;
#endif /* HOSTAPD_VERSION >= 210 */

    iface->conf->ht_capab = iface->current_mode->ht_capab;
    iface->conf->vht_capab = iface->current_mode->vht_capab;

    /*
     * Override extended capa with per-interface type (AP), if
     * available from the driver.
     */
    hostapd_get_ext_capa(iface);

#if HOSTAPD_VERSION >= 211
#ifdef CONFIG_IEEE80211BE
    hostapd_get_mld_capa(iface);
#endif /* CONFIG_IEEE80211BE */
#endif /* HOSTAPD_VERSION >= 211 */
#endif // CONFIG_HW_CAPABILITIES || VNTXER5_PORT

    iface->drv_flags |= WPA_DRIVER_FLAGS_EAPOL_TX_STATUS;
    iface->drv_flags |= WPA_DRIVER_FLAGS_AP_MLME;
    iface->drv_flags |= WPA_DRIVER_FLAGS_AP_CSA;

    // XXX: Such ability should be retrieved during NL80211_CMD_GET_WIPHY
    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_PROBE_RESP_OFFLOAD) {
        iface->drv_flags |= WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD;
    }

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_STA_INACTIVITY_TIMER) {
        iface->drv_flags |= WPA_DRIVER_FLAGS_INACTIVITY_TIMER;
    }

    iface->conf->ht_capab &= ~HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    if (param->channelWidth >= WIFI_CHANNELBANDWIDTH_40MHZ) {
        iface->conf->ht_capab |= HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    }

    if (iface->current_mode->mode != HOSTAPD_MODE_IEEE80211B &&
        iface->current_mode->mode != HOSTAPD_MODE_IEEE80211G &&
        (iface->conf->ht_capab & HT_CAP_INFO_DSSS_CCK40MHZ)) {
        wifi_hal_info_print("%s:%d Disable HT capability [DSSS_CCK-40] on 5 GHz band\n",__func__,__LINE__);
        iface->conf->ht_capab &= ~HT_CAP_INFO_DSSS_CCK40MHZ;
    }

    iface->conf->vht_capab &= ~VHT_CAP_SUPP_CHAN_WIDTH_MASK;
    if (param->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        iface->conf->vht_capab |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
    }

    if (!param->stbcEnable) {
        // if stbc support is disabled, cleanup this bit in HT_CAPS and VHT_CAPS
        iface->conf->ht_capab &= ~HT_CAP_INFO_TX_STBC;
        iface->conf->vht_capab &= ~VHT_CAP_TXSTBC;
    }

#ifdef CONFIG_IEEE80211AX
    drv_he_cap = &iface->current_mode->he_capab[IEEE80211_MODE_AP];
    iface->conf->he_phy_capab.he_mu_beamformer =
        !!(drv_he_cap->phy_cap[HE_PHYCAP_MU_BEAMFORMER_CAPAB_IDX] & HE_PHYCAP_MU_BEAMFORMER_CAPAB);
    iface->conf->he_phy_capab.he_su_beamformer =
        !!(drv_he_cap->phy_cap[HE_PHYCAP_SU_BEAMFORMER_CAPAB_IDX] & HE_PHYCAP_SU_BEAMFORMER_CAPAB);
    iface->conf->he_phy_capab.he_su_beamformee =
        !!(drv_he_cap->phy_cap[HE_PHYCAP_SU_BEAMFORMEE_CAPAB_IDX] & HE_PHYCAP_SU_BEAMFORMEE_CAPAB);
#if HOSTAPD_VERSION >= 210
    iface->conf->he_6ghz_max_ampdu_len_exp =
        (drv_he_cap->he_6ghz_capa & HE_6GHZ_BAND_CAP_MAX_AMPDU_LEN_EXP_MASK) >>
        HE_6GHZ_BAND_CAP_MAX_AMPDU_LEN_EXP_SHIFT;
    iface->conf->he_6ghz_max_mpdu =
        (drv_he_cap->he_6ghz_capa & HE_6GHZ_BAND_CAP_MAX_MPDU_LEN_MASK) >>
        HE_6GHZ_BAND_CAP_MAX_MPDU_LEN_SHIFT;

    if (radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND) {
        iface->conf->he_2ghz_40mhz_width_allowed =
            param->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ;
    }
#endif
#endif

    if(preassoc_supp_rates) {
      os_free(preassoc_supp_rates);
      preassoc_supp_rates = NULL;
    }
    if(preassoc_basic_rates) {
      os_free(preassoc_basic_rates);
      preassoc_basic_rates = NULL;
    }

    return RETURN_OK;
}

int update_hostap_interfaces(wifi_radio_info_t *radio)
{
    struct hapd_interfaces *interfaces;
    wifi_interface_info_t *interface;
    //struct hostapd_bss_config *conf;
    struct hostapd_config *iconf;
    
    if (radio == NULL) {
        wifi_hal_error_print("%s:%d:wifi_radio_info is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    interfaces = &radio->interfaces;
    interfaces->for_each_interface = hostapd_for_each_interface;
    interfaces->iface = radio->iface;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    iconf = &radio->iconf;
    iconf->num_bss = 0; 
    iconf->bss = radio->bss;
    interfaces->count = 0;

    interface = hash_map_get_first(radio->interface_map);
    while (interface != NULL) {
        if ((interface->vap_initialized == true) && (interface->vap_info.vap_mode == wifi_vap_mode_ap)) {
            radio->iface[interfaces->count] = &interface->u.ap.iface;
            interfaces->count++;

            radio->bss[iconf->num_bss] = &interface->u.ap.conf;
            iconf->num_bss++;
        }
        interface = hash_map_get_next(radio->interface_map, interface);
    }
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    return RETURN_OK;
}


static void print_hw_variants_by_bitmask(uint32_t mask)
{
    static const char* const wifi_mode_strings[] =
    {
        "WIFI_80211_VARIANT_A",
        "WIFI_80211_VARIANT_B",
        "WIFI_80211_VARIANT_G",
        "WIFI_80211_VARIANT_N",
        "WIFI_80211_VARIANT_H",
        "WIFI_80211_VARIANT_AC",
        "WIFI_80211_VARIANT_AD",
        "WIFI_80211_VARIANT_AX",
#ifdef CONFIG_IEEE80211BE
        "WIFI_80211_VARIANT_BE",
#endif /* CONFIG_IEEE80211BE */
    };

    for (unsigned int i = 0; i < ARRAY_SIZE(wifi_mode_strings); i++) {
        if (mask & (1ul << i))
            wifi_hal_dbg_print("WIFI HW MODE SET[%u]: %s\n", i, wifi_mode_strings[i]);
    }
}

static void print_bw_variants_by_bitmask(uint32_t mask)
{
    // According to <@brief Wifi Channel Bandwidth Types> in hal generic interface enums
    static const char* const wifi_bw_strings[] =
    {
        "WIFI_CHANNELBANDWIDTH_20MHZ",
        "WIFI_CHANNELBANDWIDTH_40MHZ",
        "WIFI_CHANNELBANDWIDTH_80MHZ",
        "WIFI_CHANNELBANDWIDTH_160MHZ",
        "WIFI_CHANNELBANDWIDTH_80_80MHZ",
#ifdef CONFIG_IEEE80211BE
        "WIFI_CHANNELBANDWIDTH_320MHZ",
#endif /* CONFIG_IEEE80211BE */
    };

    for (unsigned int i = 0; i < ARRAY_SIZE(wifi_bw_strings); i++) {
        if (mask & (1ul << i))
            wifi_hal_dbg_print("WIFI BW SET[%u]: %s\n", i, wifi_bw_strings[i]);
    }
}

#if defined(MXL_WIFI)
static u8 find_bit_offset(u8 val)
{
    u8 res = 0;
    for (; val; val >>= 1) {
        if (val & 1)
            break;
        res++;
    }
    return res;
}

static u8 set_he_cap(int val, u8 mask)
{
    return (u8) (mask & (val << find_bit_offset(mask)));
}
#endif

int update_hostap_config_params(wifi_radio_info_t *radio)
{
    unsigned char bandwidth;
    const int aCWmin = 4, aCWmax = 10;
    const struct hostapd_wmm_ac_params ac_bk = { aCWmin, aCWmax, 7, 0, 0 }; /* background traffic */
    const struct hostapd_wmm_ac_params ac_be = { aCWmin, aCWmax, 3, 0, 0 }; /* best effort traffic */
    const struct hostapd_wmm_ac_params ac_vi = { aCWmin - 1, aCWmin, 2, 3008 / 32, 0 }; /* video traffic */
    const struct hostapd_wmm_ac_params ac_vo = { aCWmin - 2, aCWmin - 1, 2, 1504 / 32, 0 }; /* voice traffic */
    const struct hostapd_tx_queue_params txq_bk = { 7, ecw2cw(aCWmin), ecw2cw(aCWmax), 0 };
    const struct hostapd_tx_queue_params txq_be = { 3, ecw2cw(aCWmin), 4 * (ecw2cw(aCWmin) + 1) - 1, 0};
    const struct hostapd_tx_queue_params txq_vi = { 1, (ecw2cw(aCWmin) + 1) / 2 - 1, ecw2cw(aCWmin), 30};
    const struct hostapd_tx_queue_params txq_vo = { 1, (ecw2cw(aCWmin) + 1) / 4 - 1, (ecw2cw(aCWmin) + 1) / 2 - 1, 15};

    struct hostapd_config   *iconf;
    wifi_radio_operationParam_t *param;
#ifdef CONFIG_IEEE80211AX
    struct ieee80211_he_mu_edca_parameter_set he_mu_edca = { 0x4, { 0x00, 0xa4, 0x08 },
        { 0x20, 0xa4, 0x08 }, { 0x40, 0x43, 0x08 }, { 0x60, 0x32, 0x08 } };
    struct ieee80211_he_mu_edca_parameter_set he_mu_edca_6g = { 0x8, { 0x00, 0xa4, 0x08 },
        { 0x20, 0xa4, 0x08 }, { 0x40, 0x43, 0x08 }, { 0x60, 0x32, 0x08 } };
#endif

    param = &radio->oper_param;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);

    iconf = &radio->iconf;

    iconf->beacon_int = param->beaconInterval;
    iconf->rts_threshold = 2347; /* use driver default: 2347 */
    iconf->fragm_threshold = 2346; /* user driver default: 2346 */

    if (param->DfsEnabled == true) {
        /* updated by driver */
        iconf->local_pwr_constraint = 0;
        iconf->spectrum_mgmt_required = 1;
    } else {
        iconf->local_pwr_constraint = -1;
        iconf->spectrum_mgmt_required = 0;
    }

    iconf->wmm_ac_params[0] = ac_be;
    iconf->wmm_ac_params[1] = ac_bk;
    iconf->wmm_ac_params[2] = ac_vi;
    iconf->wmm_ac_params[3] = ac_vo;

#if defined(MXL_WIFI)
    iconf->he_mu_edca.he_qos_info |= HE_QOS_INFO_QUEUE_REQUEST;
    iconf->he_mu_edca.he_mu_ac_be_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMIN);
    iconf->he_mu_edca.he_mu_ac_be_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMAX);
    iconf->he_mu_edca.he_mu_ac_be_param[HE_MU_AC_PARAM_TIMER_IDX] =
        5 & 0xff;
    iconf->he_mu_edca.he_mu_ac_bk_param[HE_MU_AC_PARAM_ACI_IDX] |=
        set_he_cap(1, HE_MU_AC_PARAM_ACI);
    iconf->he_mu_edca.he_mu_ac_bk_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMIN);
    iconf->he_mu_edca.he_mu_ac_bk_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMAX);
    iconf->he_mu_edca.he_mu_ac_bk_param[HE_MU_AC_PARAM_TIMER_IDX] =
        5 & 0xff;
    iconf->he_mu_edca.he_mu_ac_vi_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMIN);
    iconf->he_mu_edca.he_mu_ac_vi_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMAX);
    iconf->he_mu_edca.he_mu_ac_vi_param[HE_MU_AC_PARAM_ACI_IDX] |=
        set_he_cap(2, HE_MU_AC_PARAM_ACI);
    iconf->he_mu_edca.he_mu_ac_vi_param[HE_MU_AC_PARAM_TIMER_IDX] =
        5 & 0xff;
    iconf->he_mu_edca.he_mu_ac_vo_param[HE_MU_AC_PARAM_ACI_IDX] |=
        set_he_cap(3, HE_MU_AC_PARAM_ACI);
    iconf->he_mu_edca.he_mu_ac_vo_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMIN);
    iconf->he_mu_edca.he_mu_ac_vo_param[HE_MU_AC_PARAM_ECW_IDX] |=
        set_he_cap(15, HE_MU_AC_PARAM_ECWMAX);
    iconf->he_mu_edca.he_mu_ac_vo_param[HE_MU_AC_PARAM_TIMER_IDX] =
        5 & 0xff;
#endif

    iconf->tx_queue[0] = txq_vo;
    iconf->tx_queue[1] = txq_vi;
    iconf->tx_queue[2] = txq_be;
    iconf->tx_queue[3] = txq_bk;

#if !defined(CONFIG_HW_CAPABILITIES)
    iconf->ht_capab = HT_CAP_INFO_SMPS_DISABLED;
#endif
    iconf->ap_table_max_size = 255;
    iconf->ap_table_expiration_time = 60;
    iconf->track_sta_max_age = 180;

    iconf->acs = 0;
    iconf->acs_ch_list.num = 0;
#ifdef CONFIG_ACS
//Not defined
    iconf->acs_num_scans = 5;
#endif /* CONFIG_ACS */

#ifdef CONFIG_IEEE80211AX
    iconf->he_op.he_rts_threshold = 0;
    iconf->he_op.he_default_pe_duration = 4;
#if HOSTAPD_VERSION >= 210
    iconf->he_op.he_er_su_disable = 1;
    iconf->he_op.he_bss_color_disabled = 1;
    iconf->he_op.he_cohosted_bss = radio->oper_param.band != WIFI_FREQUENCY_6_BAND;
    iconf->he_op.he_max_cohosted_bssid = 3;
    iconf->reg_def_cli_eirp = 24 * 2; // 24 dBm

    /* Set default basic MCS/NSS set to single stream MCS 0-7 */
    iconf->he_op.he_basic_mcs_nss_set = 0xfffc;
#endif
    if (radio->oper_param.band == WIFI_FREQUENCY_6_BAND) {
        memcpy(&iconf->he_mu_edca.he_qos_info, &he_mu_edca_6g, sizeof(he_mu_edca_6g));
    } else {
        memcpy(&iconf->he_mu_edca.he_qos_info, &he_mu_edca, sizeof(he_mu_edca));
    }
#endif /* CONFIG_IEEE80211AX */
#if HOSTAPD_VERSION >= 210
    iconf->vht_oper_basic_mcs_set = 0;

    iconf->ht_rifs = radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND;
#endif
    iconf->obss_interval = radio->oper_param.band == WIFI_FREQUENCY_2_4_BAND ? 300 : 0;

    iconf->rssi_reject_assoc_rssi = 0;
    iconf->rssi_reject_assoc_timeout = 3;

#ifdef CONFIG_AIRTIME_POLICY
//Not defined
    iconf->airtime_update_interval = AIRTIME_DEFAULT_UPDATE_INTERVAL;
    iconf->airtime_mode = AIRTIME_MODE_STATIC;
#endif /* CONFIG_AIRTIME_POLICY */
    iconf->ieee80211h = 1;
    iconf->ieee80211d = 1; // This support includes the addition of a country information element to beacons, probe requests, and probe responses

    iconf->acs = param->autoChannelEnabled;
    iconf->channel = param->channel;
#if HOSTAPD_VERSION >= 210
    iconf->op_class = param->op_class;
#endif

    get_coutry_str_from_oper_params(param, iconf->country);
    // use global operating class in country info
    iconf->country[2] = 0x04;

    wifi_hal_dbg_print("%s:%d: channel: %d country: %.2s\n", __func__, __LINE__, iconf->channel,
        iconf->country);

    iconf->ieee80211n = 0;
    iconf->ieee80211ac = 0;
    iconf->ieee80211ax = 0;
#ifdef CONFIG_IEEE80211BE
    iconf->ieee80211be = 0;
#endif

    print_hw_variants_by_bitmask(param->variant);
    print_bw_variants_by_bitmask(param->channelWidth);

    if (param->variant & WIFI_80211_VARIANT_B) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211B;
    }

    if (param->variant & WIFI_80211_VARIANT_G) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211G;
    }

    if (param->variant & WIFI_80211_VARIANT_A) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
    }

    if (param->variant & WIFI_80211_VARIANT_N) {
        if (param->band == WIFI_FREQUENCY_2_4_BAND) {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211G;
        } else {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
        }
        iconf->ieee80211n = 1;
        //iconf->require_ht = 1;
    }

    if (param->variant & WIFI_80211_VARIANT_H) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211ANY;
    }

    if (param->variant & WIFI_80211_VARIANT_AD) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211AD;
    }

    if (param->variant & WIFI_80211_VARIANT_AC) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
        iconf->ieee80211ac = 1;
        //iconf->require_vht = 1;
        //iconf->ieee80211n = 1;
        //iconf->require_ht = 1;
    }

    if (param->variant & WIFI_80211_VARIANT_AX) {
        if (param->band == WIFI_FREQUENCY_5_BAND) {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
            iconf->ieee80211ac = 1;
        } else if (param->band == WIFI_FREQUENCY_6_BAND) {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
       } else {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211G;
        }
        iconf->ieee80211ax = 1;
        //iconf->ieee80211n = 1;
        //iconf->require_ht = 1;
        //iconf->require_vht = 1;
    }


#ifdef CONFIG_IEEE80211BE
//TODO:TESTME
    bool is_ieee80211be = (param->variant & WIFI_80211_VARIANT_BE);
     if (is_ieee80211be) {
        iconf->hw_mode = HOSTAPD_MODE_IEEE80211A;
        if (param->band == WIFI_FREQUENCY_5_BAND) {
            iconf->ieee80211ac = 1;
        } else if (param->band == WIFI_FREQUENCY_2_4_BAND) {
            iconf->hw_mode = HOSTAPD_MODE_IEEE80211G;
        }
        iconf->ieee80211ax = 1;
        iconf->ieee80211be = 1;
        //iconf->require_he = 1;
        //iconf->require_eht = 1;
    }
#endif /* CONFIG_IEEE80211BE */

    switch (param->channelWidth) {
    case WIFI_CHANNELBANDWIDTH_80MHZ:
        bandwidth = CHANWIDTH_80MHZ;
        break;

    case WIFI_CHANNELBANDWIDTH_160MHZ:
        bandwidth = CHANWIDTH_160MHZ;
        break;

    case WIFI_CHANNELBANDWIDTH_80_80MHZ:
        bandwidth = CHANWIDTH_80P80MHZ;
        break;
#ifdef CONFIG_IEEE80211BE
    case WIFI_CHANNELBANDWIDTH_320MHZ:
        bandwidth = CHANWIDTH_320MHZ;
        break;
#endif /* CONFIG_IEEE80211BE */
    case WIFI_CHANNELBANDWIDTH_20MHZ:
    case WIFI_CHANNELBANDWIDTH_40MHZ:
    default:
        bandwidth = CHANWIDTH_USE_HT;
        break;
    }

    hostapd_set_oper_chwidth(iconf, bandwidth);

#ifdef CONFIG_IEEE80211AX
#if HOSTAPD_VERSION >= 210
    if (param->band == WIFI_FREQUENCY_2_4_BAND) {
        iconf->he_2ghz_40mhz_width_allowed = param->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ;
    }
#endif
#endif

    iconf->ht_capab &= ~HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    if (param->channelWidth >= WIFI_CHANNELBANDWIDTH_40MHZ) {
        iconf->ht_capab |= HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET;
    }

    iconf->vht_capab &= ~VHT_CAP_SUPP_CHAN_WIDTH_MASK;
    if (param->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        iconf->vht_capab |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
    }

    //validate_config_params
    if (hostapd_config_check(iconf, 1) < 0) {
        pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
        wifi_hal_error_print("%s:%d:Invalid config params\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    wifi_hal_info_print("%s:%d:Exit\n", __func__, __LINE__);
    return RETURN_OK;
}

int update_hostap_interface_params(wifi_interface_info_t *interface)
{
    int ret = RETURN_ERR;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);
    // initialize the default params
    if (update_hostap_data(interface) != RETURN_OK) {
        goto exit;
    }
    if (update_hostap_bss(interface) != RETURN_OK) {
#ifdef CONFIG_SAE
        if (interface->u.ap.conf.sae_groups) {
            os_free(interface->u.ap.conf.sae_groups);
            interface->u.ap.conf.sae_groups = NULL;
        }
#endif
        goto exit;
    }
    if (update_hostap_iface(interface) != RETURN_OK) {
#ifdef CONFIG_SAE
        if (interface->u.ap.conf.sae_groups) {
            os_free(interface->u.ap.conf.sae_groups);
            interface->u.ap.conf.sae_groups = NULL;
        }
#endif
        goto exit;
    }
#ifdef CONFIG_IEEE80211BE
    if (update_hostap_mlo(interface) != RETURN_OK) {
        goto exit;
    }
#endif /* CONFIG_IEEE80211BE */

    ret = RETURN_OK;
exit:
    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);
    return ret;
}

#ifdef CONFIG_WIFI_EMULATOR
static enum wpa_states wpa_sm_supplicant_sta_get_state(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)ctx;

    return interface->wpa_s.wpa_state;
}

static void wpa_sm_supplicant_sta_cancel_auth_timeout(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    wifi_interface_info_t *interface;
    interface = (wifi_interface_info_t *)ctx;
    wpa_supplicant_cancel_auth_timeout(&interface->wpa_s);
}
#endif

static void wpa_sm_sta_set_state(void *ctx, enum wpa_states state)
{
    wifi_hal_dbg_print("%s:%d: Enter, state %d\n", __func__, __LINE__, state);

    wifi_device_callbacks_t *callbacks;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    wifi_bss_info_t bss;
    wifi_station_stats_t sta;
    interface = (wifi_interface_info_t *)ctx;
#ifdef CONFIG_WIFI_EMULATOR
    interface->wpa_s.wpa_state = state;
#endif
    interface->u.sta.state = state;
    vap = &interface->vap_info;

    if (state == WPA_COMPLETED) {
        nl80211_get_channel_bw_conn(interface);
    } else if (state == WPA_DISCONNECTED) {
        callbacks = get_hal_device_callbacks();
        
        if (callbacks->sta_conn_status_callback) {
            memcpy(&bss, &interface->u.sta.backhaul, sizeof(wifi_bss_info_t));

            sta.vap_index = vap->vap_index;
            sta.connect_status = wifi_connection_status_disconnected;

            callbacks->sta_conn_status_callback(vap->vap_index, &bss, &sta);
        }
    }
}

static enum wpa_states wpa_sm_sta_get_state(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)ctx;

    return interface->u.sta.state;
}

static void wpa_sm_sta_deauthenticate(void *ctx, u16 reason_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__); 
}

#ifdef HOSTAPD_2_11 //2.11
static int wpa_sm_sta_set_key(void *ctx, int link_id, enum wpa_alg alg,
               const u8 *addr, int key_idx, int set_tx,
               const u8 *seq, size_t seq_len,
               const u8 *key, size_t key_len, enum key_flag key_flag)
#elif HOSTAPD_2_10 //2.10
static int wpa_sm_sta_set_key(void *ctx, enum wpa_alg alg,
               const u8 *addr, int key_idx, int set_tx,
               const u8 *seq, size_t seq_len,
               const u8 *key, size_t key_len, enum key_flag key_flag)
#else
static int wpa_sm_sta_set_key(void *ctx, enum wpa_alg alg,
               const u8 *addr, int key_idx, int set_tx,
               const u8 *seq, size_t seq_len,
               const u8 *key, size_t key_len)
#endif
{
    wifi_interface_info_t *interface;
    //wifi_vap_info_t *vap;
    //wifi_radio_info_t *radio;

    interface = (wifi_interface_info_t *)ctx;
   // vap = &interface->vap_info;
    //radio = get_radio_by_rdk_index(vap->radio_index);
#ifdef HOSTAPD_2_11 // 2.11
    struct wpa_driver_set_key_params params_conversion = {
        interface->name, alg, addr, key_idx, set_tx, seq, seq_len, key, key_len, 0, key_flag, link_id};

    return g_wpa_driver_nl80211_ops.set_key( interface, &params_conversion);
#elif HOSTAPD_2_10 //2.10
    struct wpa_driver_set_key_params params_conversion = {
        interface->name, alg, addr, key_idx, set_tx, seq, seq_len, key, key_len, 0, key_flag};

    return g_wpa_driver_nl80211_ops.set_key( interface, &params_conversion);
#else
    return g_wpa_driver_nl80211_ops.set_key(interface->name, interface, alg, addr, key_idx,
                                                set_tx, seq, seq_len, key, key_len);
#endif
}

static void *wpa_sm_sta_get_network_ctx(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__); 
    return ctx;
}

static int wpa_sm_sta_get_bssid(void *ctx, u8 *bssid)
{
    wifi_interface_info_t *interface;
    wifi_bss_info_t *backhaul;
    mac_addr_str_t bssid_str;

    interface = (wifi_interface_info_t *)ctx;
    backhaul = &interface->u.sta.backhaul;

    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
        to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    memcpy(bssid, backhaul->bssid, sizeof(bssid_t));

    return 0;
}

static unsigned char* wpa_sm_sta_alloc_eapol(void *ctx, unsigned char type,
                const void *data, unsigned short data_len,
                size_t *msg_len, void **data_pos)
{
    struct ieee802_1x_hdr *hdr;
    //wifi_interface_info_t *interface;

    //interface = (wifi_interface_info_t *)ctx;

    *msg_len = sizeof(struct ieee802_1x_hdr) + data_len;
    hdr = os_malloc(*msg_len);
    if (hdr == NULL) {
        return NULL;
    }
    hdr->version = EAPOL_VERSION;
    hdr->type = type;
    hdr->length = host_to_be16(data_len);

    if (data) {
        memcpy(hdr + 1, data, data_len);
    } else {
        memset(hdr + 1, 0, data_len);
    }

    if (data_pos) {
        *data_pos = hdr + 1;
    }

    return (unsigned char *)hdr;
}

static int wpa_sm_sta_ether_send(void *ctx, const u8 *dest, u16 proto, const u8 *buf, size_t len)
{
    struct sockaddr_ll ll;
    int ret;
    wifi_interface_info_t *interface;
    mac_addr_str_t  bssid_str;
    unsigned char buff[2048];
    struct ieee8023_hdr *eth_hdr;

    interface = (wifi_interface_info_t *)ctx;

    if (g_wifi_hal.platform_flags & PLATFORM_FLAGS_CONTROL_PORT_FRAME) {
#if HOSTAPD_VERSION >= 210 //2.10
        int encrypt;
        mac_addr_str_t mac_str;
        encrypt = interface->u.sta.wpa_sm && wpa_sm_has_ptk_installed(interface->u.sta.wpa_sm);
        wifi_hal_info_print("%s:%d: Sending eapol via control port to sta:%s on interface:%s encrypt:%d\n", __func__, __LINE__,
            to_mac_str(dest, mac_str), interface->name, encrypt);
        if ((ret = nl80211_tx_control_port(interface, dest, ETH_P_EAPOL, buf, len, !encrypt))) {
            wifi_hal_error_print("%s:%d: eapol send failed\n", __func__, __LINE__);
            return -1;
        }
        return 0;
#endif // HOSTAPD_VERSION >= 210     
    }
        
    memset(&ll, 0, sizeof(ll));
    //ll.sll_family = AF_PACKET;
    ll.sll_ifindex = if_nametoindex(interface->name);
    //ll.sll_protocol = htons(proto);
    ll.sll_halen = ETH_ALEN;
    memcpy(ll.sll_addr, dest, ETH_ALEN);

    eth_hdr = (struct ieee8023_hdr *)buff;
    memcpy(eth_hdr->dest, dest, sizeof(mac_address_t));
    memcpy(eth_hdr->src, interface->mac, sizeof(mac_address_t));
    eth_hdr->ethertype = host_to_be16(ETH_P_EAPOL);

    memcpy(&buff[sizeof(struct ieee8023_hdr)], buf, len);

    ret = sendto(interface->u.sta.sta_sock_fd, buff, len + sizeof(struct ieee8023_hdr), 0, (struct sockaddr *) &ll, sizeof(ll));
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: error:%s\n", __func__, __LINE__, strerror(errno));
    } else {
        //my_print_hex_dump(len + sizeof(struct ieee8023_hdr), buff);
        wifi_hal_info_print("%s:%d: send eapol key to:%s success, length of payload:%zu\n", __func__, __LINE__, 
            to_mac_str(dest, bssid_str), len); 
    }

    return ret;
}
#if 0
static const u8 * wpa_bss_get_vendor_ie(const u8 *pos, size_t len, u32 vendor_type)
{
    const u8 *end;

    end = pos + len;

    while (end - pos > 1) {
        if (2 + pos[1] > end - pos) {
            break;
        }

        if (pos[0] == WLAN_EID_VENDOR_SPECIFIC && pos[1] >= 4 && vendor_type == WPA_GET_BE32(&pos[2])) {
            return pos;
        }

        pos += 2 + pos[1];
    }

    return NULL;
}
#endif
static int wpa_sm_sta_get_beacon_ie(void *ctx)
{
    wifi_interface_info_t *interface;
    wifi_bss_info_t *backhaul;
    wifi_bss_info_t *bss;

    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    interface = (wifi_interface_info_t *)ctx;
    backhaul = &interface->u.sta.backhaul;

    pthread_mutex_lock(&interface->scan_info_mutex);
    bss = hash_map_get_first(interface->scan_info_map);
    while (bss != NULL) {
        if (memcmp(backhaul->bssid, bss->bssid, sizeof(bssid_t)) == 0) {
            if (bss->ie_len > 0) {
                int ret;
                wifi_hal_dbg_print("SET RSN IE\n");
                ret = wpa_sm_set_ap_rsn_ie(interface->u.sta.wpa_sm, bss->ie, bss->ie_len);
                pthread_mutex_unlock(&interface->scan_info_mutex);
                return ret;
            }
        }
        bss = hash_map_get_next(interface->scan_info_map, bss);
    }
    pthread_mutex_unlock(&interface->scan_info_mutex);

    return -1;
}

static int wpa_sm_sta_mlme_setprotection(void *ctx, const u8 *addr,
                                            int protection_type, int key_type)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

static void wpa_sm_sta_cancel_auth_timeout(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

static int wpa_sm_sta_key_mgmt_set_pmk(void *ctx, const u8 *pmk,
                                            size_t pmk_len)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

#if HOSTAPD_VERSION >= 210 //2.10
static int wpa_sm_sta_add_pmkid(void *ctx, void *network_ctx, const u8 *bssid,
					const u8 *pmkid, const u8 *fils_cache_id,
					const u8 *pmk, size_t pmk_len, u32 pmk_lifetime,
					u8 pmk_reauth_threshold, int akmp)
#else
static int wpa_sm_sta_add_pmkid(void *_wpa_s, void *network_ctx,
                                            const u8 *bssid, const u8 *pmkid,
                                            const u8 *fils_cache_id,
                                            const u8 *pmk, size_t pmk_len)
#endif
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
    return 0;
}

void update_wpa_sm_params(wifi_interface_info_t *interface)
{
    wifi_vap_info_t *vap;
    wifi_vap_security_t *sec;
    wifi_bss_info_t *backhaul;
    struct wpa_sm_ctx *ctx;
    struct wpa_ie_data data;
    unsigned char pmk[PMK_LEN];
    struct wpa_sm *sm;
    unsigned char *assoc_req;
    unsigned char *ie = NULL;
    unsigned short ie_len;
    mac_addr_str_t bssid_str;
    int sel, key_mgmt = 0;
    int wpa_key_mgmt_11w = 0;

    vap = &interface->vap_info;
    sec = &vap->u.sta_info.security;
    backhaul = &interface->u.sta.backhaul;

    sec = &vap->u.sta_info.security;
    assoc_req = interface->u.sta.assoc_req;

    wifi_hal_dbg_print("%s:%d:bssid:%s frequency:%d ssid:%s\n", __func__, __LINE__,
        to_mac_str(backhaul->bssid, bssid_str), backhaul->freq, backhaul->ssid);

    if (interface->u.sta.wpa_sm == NULL) {
        ctx = os_zalloc(sizeof(struct wpa_sm_ctx));
        if (ctx == NULL) {
            wifi_hal_error_print("%s:%d: Failed to alloc ctx\n", __func__, __LINE__);
            return;
        }
        ctx->ctx = interface;
        ctx->msg_ctx = interface;
        ctx->set_state = wpa_sm_sta_set_state;
        ctx->get_state = wpa_sm_sta_get_state;
        ctx->cancel_auth_timeout = wpa_sm_sta_cancel_auth_timeout;
#ifdef CONFIG_WIFI_EMULATOR
        if((sec->mode == wifi_security_mode_wpa3_personal) || (sec->mode == wifi_security_mode_wpa3_enterprise) ||
                (sec->mode == wifi_security_mode_wpa3_transition)) {
            ctx->get_state = wpa_sm_supplicant_sta_get_state;
            ctx->cancel_auth_timeout = wpa_sm_supplicant_sta_cancel_auth_timeout;
        }
#endif
        ctx->deauthenticate = wpa_sm_sta_deauthenticate;
        ctx->set_key = wpa_sm_sta_set_key;
        ctx->get_network_ctx = wpa_sm_sta_get_network_ctx;
        ctx->get_bssid = wpa_sm_sta_get_bssid;
        ctx->alloc_eapol = wpa_sm_sta_alloc_eapol;
        ctx->ether_send = wpa_sm_sta_ether_send;
        ctx->get_beacon_ie = wpa_sm_sta_get_beacon_ie;
        ctx->mlme_setprotection = wpa_sm_sta_mlme_setprotection;
        ctx->key_mgmt_set_pmk = wpa_sm_sta_key_mgmt_set_pmk;
        ctx->add_pmkid = wpa_sm_sta_add_pmkid;

        interface->u.sta.wpa_sm = wpa_sm_init(ctx);
    }
#ifdef CONFIG_WIFI_EMULATOR
    interface->wpa_s.wpa = interface->u.sta.wpa_sm;
#ifdef CONFIG_IEEE80211W
    unsigned int ieee80211w;
    ieee80211w = (enum mfp_options)sec->mfp;
    switch (ieee80211w) {
    case MGMT_FRAME_PROTECTION_REQUIRED:
        wpa_key_mgmt_11w &= ~(WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X);
        if (sec->mode == wifi_security_mode_wpa3_transition) {
            wpa_key_mgmt_11w |= WPA_KEY_MGMT_PSK_SHA256;
        }

        if (sec->mode == wifi_security_mode_wpa2_personal) {
            wpa_key_mgmt_11w |= WPA_KEY_MGMT_PSK_SHA256;
        }
        /* FALLTHROUGH */
    case MGMT_FRAME_PROTECTION_OPTIONAL:
        switch (sec->mode) {
        case wifi_security_mode_wpa_personal:
        case wifi_security_mode_wpa2_personal:
        case wifi_security_mode_wpa_wpa2_personal:
            wpa_key_mgmt_11w |= WPA_KEY_MGMT_PSK_SHA256;
            break;
        case wifi_security_mode_wpa_enterprise:
        case wifi_security_mode_wpa2_enterprise:
        case wifi_security_mode_wpa_wpa2_enterprise:
            wpa_key_mgmt_11w |= WPA_KEY_MGMT_IEEE8021X_SHA256;
            break;
        default:
            break;
        }
        break;

    case NO_MGMT_FRAME_PROTECTION:
    default:
        break;
    }
#endif
#endif

    sm = interface->u.sta.wpa_sm;

    memcpy(sm->bssid, backhaul->bssid, sizeof(mac_address_t));

    pbkdf2_sha1(sec->u.key.key, backhaul->ssid, strlen(backhaul->ssid), 
        4096, pmk, PMK_LEN);

    wpa_sm_set_own_addr(sm, interface->mac);
    wpa_sm_set_pmk(sm, pmk, PMK_LEN, NULL, NULL);
    wpa_sm_set_param(sm, WPA_PARAM_RSN_ENABLED, 1);
    wpa_sm_set_param(sm, WPA_PARAM_PROTO, WPA_PROTO_RSN);

    if (backhaul->ie_len && (wpa_parse_wpa_ie_rsn(backhaul->ie, backhaul->ie_len, &data) == 0)) {
	wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_CCMP);
        wpa_sm_set_param(sm, WPA_PARAM_GROUP, data.group_cipher);

        if (data.key_mgmt & WPA_KEY_MGMT_NONE) {
            wpa_sm_set_param(sm, WPA_PARAM_KEY_MGMT, WPA_KEY_MGMT_NONE);
            wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_NONE);
            wpa_sm_set_param(sm, WPA_PARAM_GROUP, WPA_CIPHER_NONE);
        } else {
            sel = (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_PSK_SHA256 | wpa_key_mgmt_11w) & data.key_mgmt;
            key_mgmt = pick_akm_suite(sel); 

            if (key_mgmt == -1) {
                wifi_hal_error_print("Unsupported AKM suite: 0x%x\n", data.key_mgmt);
                return;
            }

            wpa_sm_set_param(sm, WPA_PARAM_KEY_MGMT, key_mgmt);
        }

        wifi_hal_dbg_print("update_wpa_sm_params%x %x %x\n", data.group_cipher, data.pairwise_cipher,
            key_mgmt);
    } else {
        if (sec->mode == wifi_security_mode_none) {
            wpa_sm_set_param(sm, WPA_PARAM_KEY_MGMT, WPA_KEY_MGMT_NONE);
            wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_NONE);
            wpa_sm_set_param(sm, WPA_PARAM_GROUP, WPA_CIPHER_NONE);
        } else {
            if (sec->encr == wifi_encryption_aes) {
                wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_CCMP);
                wpa_sm_set_param(sm, WPA_PARAM_GROUP, WPA_CIPHER_CCMP);
            } else if (sec->encr == wifi_encryption_tkip) {
                wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_TKIP);
                wpa_sm_set_param(sm, WPA_PARAM_GROUP, WPA_CIPHER_TKIP);
            } else { /* TKIP_AES */
                wpa_sm_set_param(sm, WPA_PARAM_PAIRWISE, WPA_CIPHER_CCMP);
                wpa_sm_set_param(sm, WPA_PARAM_GROUP, WPA_CIPHER_TKIP);
            }

            if (sec->mode == wifi_security_mode_wpa2_personal) {
                sel = (WPA_KEY_MGMT_PSK | wpa_key_mgmt_11w);
            } else if (sec->mode == wifi_security_mode_wpa2_enterprise) {
                sel = (WPA_KEY_MGMT_IEEE8021X | wpa_key_mgmt_11w);
            } else if (sec->mode == wifi_security_mode_wpa3_transition) {
                sel = (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE | wpa_key_mgmt_11w);
            } else if (sec->mode == wifi_security_mode_wpa3_personal) {
                sel = (WPA_KEY_MGMT_SAE | wpa_key_mgmt_11w);
            } else if (sec->mode == wifi_security_mode_wpa3_enterprise) {
                sel = (WPA_KEY_MGMT_IEEE8021X_SHA256 | wpa_key_mgmt_11w);
            } else {
                wifi_hal_error_print("Unsupported security mode : 0x%x\n", sec->mode);
                return;
            }
            key_mgmt = pick_akm_suite(sel);
            if (key_mgmt == -1) {
                wifi_hal_error_print("Unsupported AKM suite: 0x%x\n", sel);
                return;
            }
            wpa_sm_set_param(sm, WPA_PARAM_KEY_MGMT, key_mgmt);
        }
    }

    if (get_ie_by_eid(WLAN_EID_RSN, assoc_req, interface->u.sta.assoc_req_len, &ie, &ie_len)
                == true) {
        wpa_sm_set_assoc_wpa_ie(sm, ie, ie_len);
    }
    wpa_sm_notify_assoc(sm, sm->bssid);
}

static void wpa_sm_eapol_notify_done(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

static int wpa_sm_eapol_send(void *ctx, int type, const u8 *buf,
                                            size_t len)
{
    struct sockaddr_ll ll;
    wifi_interface_info_t *interface;
    wifi_vap_info_t *vap;
    unsigned char buff[2048];
    struct ieee8023_hdr *eth_hdr;
    mac_addr_str_t bssid_str;
    int ret;
    int buff_size = 0;
    u16 data_len = htons(len);

    unsigned char eapol_version_buff[] = { 0x01, 0x00 };

    interface = (wifi_interface_info_t *)ctx;
    vap = &interface->vap_info;

    memset(&ll, 0, sizeof(ll));
    ll.sll_ifindex = if_nametoindex(interface->name);
    ll.sll_halen = ETH_ALEN;
    memcpy(ll.sll_addr, vap->u.sta_info.bssid, ETH_ALEN);

    eth_hdr = (struct ieee8023_hdr *)buff;
    memcpy(eth_hdr->dest, vap->u.sta_info.bssid, sizeof(mac_address_t));
    memcpy(eth_hdr->src, interface->mac, sizeof(mac_address_t));
    eth_hdr->ethertype = host_to_be16(ETH_P_EAPOL);

    buff_size += sizeof(struct ieee8023_hdr); 
    memcpy(&buff[buff_size], eapol_version_buff, sizeof(eapol_version_buff));
    buff_size += sizeof(eapol_version_buff);
    memcpy(&buff[buff_size], &data_len, sizeof(data_len));
    buff_size += sizeof(data_len);
    memcpy(&buff[buff_size], buf, len);
    buff_size += len;

    ret = sendto(interface->u.sta.sta_sock_fd, buff, buff_size, 0, (struct sockaddr *) &ll, sizeof(ll));
    if (ret < 0) {
        wifi_hal_error_print("%s:%d: error:%s\n", __func__, __LINE__, strerror(errno));
    } else {
        //my_print_hex_dump(buff_size, buff);
        wifi_hal_info_print("%s:%d: send eapol to:%s success, length of payload:%d\n", __func__, __LINE__, 
                           to_mac_str(vap->u.sta_info.bssid, bssid_str), buff_size); 
    }

    return ret;
}

static void wpa_sm_eapol_aborted_cached(void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

static void wpa_sm_eapol_port_cb(void *ctx, int authorized)
{
    wifi_interface_info_t *interface;

    interface = (wifi_interface_info_t *)ctx;
    wifi_hal_dbg_print("%s:%d: EAPOL: Supplicant port status: %s\n", __func__, __LINE__, authorized ? "Authorized" : "Unauthorized");

    g_wpa_driver_nl80211_ops.set_supp_port(interface, authorized);
}

static void wpa_sm_eapol_cb(struct eapol_sm *eapol,
                                    enum eapol_supp_result result,
                                    void *ctx)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

static void wpa_sm_eapol_status_cb(void *ctx, const char *status,
                                    const char *parameter)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

static void wpa_sm_eapol_eap_error_cb(void *ctx, int error_code)
{
    wifi_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);
}

#define MAX_STR_LEN 64
#define SUPPORTED_CIPHERS \
        "DEFAULT:@SECLEVEL=0"
void update_eapol_sm_params(wifi_interface_info_t *interface)
{
    struct eapol_ctx *ctx;
    wifi_vap_info_t *vap;
    wifi_vap_security_t *sec;

    vap = &interface->vap_info;
    sec = &vap->u.sta_info.security;

    if (interface->u.sta.wpa_sm->eapol == NULL) {
        ctx = os_zalloc(sizeof(struct eapol_ctx));

        ctx->ctx = interface;
        ctx->msg_ctx = interface;
        ctx->eapol_send_ctx = interface;
        ctx->preauth = 0;
        ctx->eapol_done_cb = wpa_sm_eapol_notify_done;
        ctx->eapol_send = wpa_sm_eapol_send;
        ctx->aborted_cached = wpa_sm_eapol_aborted_cached;
        ctx->port_cb = wpa_sm_eapol_port_cb;
        ctx->cb = wpa_sm_eapol_cb;
        ctx->status_cb = wpa_sm_eapol_status_cb;
        ctx->eap_error_cb = wpa_sm_eapol_eap_error_cb;
        ctx->cb_ctx = interface;

        interface->u.sta.wpa_sm->eapol = eapol_sm_init(ctx);
#ifdef CONFIG_WIFI_EMULATOR
        interface->wpa_s.wpa->eapol = interface->u.sta.wpa_sm->eapol;
        interface->wpa_s.eapol = interface->u.sta.wpa_sm->eapol;
#endif
        eapol_sm_notify_eap_success(interface->u.sta.wpa_sm->eapol, 1);
        eapol_sm_notify_eap_fail(interface->u.sta.wpa_sm->eapol, 0);
#ifndef CONFIG_WIFI_EMULATOR
        eapol_sm_notify_portControl(interface->u.sta.wpa_sm->eapol, ForceAuthorized);
#else
        if ((sec->mode == wifi_security_mode_wpa2_enterprise) ||
            (sec->mode == wifi_security_mode_wpa3_enterprise)) {
            eapol_sm_notify_portControl(interface->u.sta.wpa_sm->eapol, Auto);
        } else {
            eapol_sm_notify_portControl(interface->u.sta.wpa_sm->eapol, ForceAuthorized);
        }
#endif // CONFIG_WIFI_EMULATOR
        if (sec->mode == wifi_security_mode_wpa2_enterprise ||
            sec->mode == wifi_security_mode_wpa3_enterprise) {
            switch (sec->u.radius.eap_type) {
            case WIFI_EAP_TYPE_PWD:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_PWD;
                eap_peer_pwd_register();
                break;
            case WIFI_EAP_TYPE_MD5:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_MD5;
                eap_peer_md5_register();
                break;
            case WIFI_EAP_TYPE_TLS:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_TLS;
                eap_peer_tls_register();
                break;
            case WIFI_EAP_TYPE_MSCHAPV2:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_MSCHAPV2;
                eap_peer_mschapv2_register();
                break;
            case WIFI_EAP_TYPE_PEAP:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_PEAP;
                eap_peer_peap_register();
                break;
            case WIFI_EAP_TYPE_TTLS:
                interface->u.sta.wpa_eapol_method.method = EAP_TYPE_TTLS;
                eap_peer_ttls_register();
                break;
            default:
                wifi_hal_error_print("%s:%d: Unsupported EAP method :%d\n", __func__, __LINE__,
                    sec->u.radius.eap_type);
                return;
            }
#ifdef CONFIG_WIFI_EMULATOR
            if (vap->vap_mode == wifi_vap_mode_sta) {
                if (interface->u.sta.wpa_eapol_config.openssl_ciphers == NULL) {
                    interface->u.sta.wpa_eapol_config.openssl_ciphers = (char *)malloc(MAX_STR_LEN);
                    if (interface->u.sta.wpa_eapol_config.openssl_ciphers == NULL) {
                        wifi_hal_error_print("%s:%d: NULL Pointer\n", __func__, __LINE__);
                        return;
                    }
                }
                memset(interface->u.sta.wpa_eapol_config.openssl_ciphers, 0, MAX_STR_LEN);
                strncpy(interface->u.sta.wpa_eapol_config.openssl_ciphers, SUPPORTED_CIPHERS,
                        MAX_STR_LEN - 1);
                if (interface->u.sta.wpa_eapol_config.phase2 == NULL) {
                    interface->u.sta.wpa_eapol_config.phase2 = (char *)malloc(MAX_STR_LEN);
                    if (interface->u.sta.wpa_eapol_config.phase2 == NULL) {
                        wifi_hal_error_print("%s:%d: NULL Pointer\n", __func__, __LINE__);
                        return;
                    }
                }
                memset(interface->u.sta.wpa_eapol_config.phase2, 0, MAX_STR_LEN);
                switch (sec->u.radius.phase2) {
                case WIFI_EAP_PHASE2_PAP:
                    strncpy(interface->u.sta.wpa_eapol_config.phase2, "auth=PAP", MAX_STR_LEN - 1);
                    break;
                default:
                    // using PAP as default value.
                    strncpy(interface->u.sta.wpa_eapol_config.phase2, "auth=PAP", MAX_STR_LEN - 1);
                    break;
                }
            }
            interface->u.sta.wpa_eapol_config.fragment_size = 400;
            eapol_sm_notify_portControl(interface->u.sta.wpa_sm->eapol, Auto);
#endif // CONFIG_WIFI_EMULATOR
            interface->u.sta.wpa_eapol_method.vendor = EAP_VENDOR_IETF;
            interface->u.sta.wpa_eapol_config.identity = (unsigned char *)&sec->u.radius.identity;
            interface->u.sta.wpa_eapol_config.identity_len = strlen(sec->u.radius.identity);
            interface->u.sta.wpa_eapol_config.password = (unsigned char *)&sec->u.radius.key;
            interface->u.sta.wpa_eapol_config.password_len = strlen(sec->u.radius.key);

            interface->u.sta.wpa_eapol_config.eap_methods = &interface->u.sta.wpa_eapol_method;
            eapol_sm_notify_config(interface->u.sta.wpa_sm->eapol, &interface->u.sta.wpa_eapol_config, NULL);
        }
    }
}

void start_bss(wifi_interface_info_t *interface)
{
    int ret;
    struct hostapd_data     *hapd;
    struct hostapd_bss_config *conf;
    //struct hostapd_iface *iface;
    //struct hostapd_config *iconf;

    pthread_mutex_lock(&g_wifi_hal.hapd_lock);

    hapd = &interface->u.ap.hapd;
    conf = hapd->conf;
    //iconf = hapd->iconf;
    //iface = hapd->iface;

    wifi_hal_dbg_print("%s:%d:ssid info ssid len:%zu\n", __func__, __LINE__, conf->ssid.ssid_len);
    //my_print_hex_dump(conf->ssid.ssid_len, conf->ssid.ssid);
#if HOSTAPD_VERSION >= 211 //2.11
    ret = hostapd_setup_bss(hapd, 1, true);
#elif defined(VNTXER5_PORT) && (HOSTAPD_VERSION == 210) //2.10
    ret = hostapd_setup_bss(hapd, 1, true);
#else
    ret = hostapd_setup_bss(hapd, 1);
#endif

    pthread_mutex_unlock(&g_wifi_hal.hapd_lock);

    if (ret < 0) {
        wifi_hal_error_print("%s:%d: interface:%s failed to start bss\n",  __func__, __LINE__,
            interface->name);
    }
}
