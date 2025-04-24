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


#ifndef _WIFI_HAL_RDK_H_
#define _WIFI_HAL_RDK_H_

#include "wifi_hal.h"

typedef struct
{
    unsigned char cat;
    unsigned char action;
} __attribute__((packed)) wifi_actionFrameHdr_t;

typedef wifi_actionFrameHdr_t wifi_publicActionFrameHdr_t;

typedef struct
{
    unsigned char query_rsp_info;
    unsigned char adv_proto_id;
    unsigned char len;
    unsigned char oui[0];
} __attribute__((packed)) wifi_advertisementProtoTuple_t;

typedef struct
{
    unsigned char id;
    unsigned char len;
    wifi_advertisementProtoTuple_t proto_tuple;
} __attribute__((packed)) wifi_advertisementProtoElement_t;

typedef struct
{
    unsigned char token;
    wifi_advertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasInitialRequestFrame_t;

typedef struct
{
    unsigned char token;
    unsigned short status;
    unsigned short comeback_delay;
    wifi_advertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasInitialResponseFrame_t;

/* DPP structure definitions */
typedef struct
{
    unsigned char oui[3];
    unsigned char oui_type;
} __attribute__((packed)) wifi_dppOUI;

typedef struct
{
    wifi_dppOUI dpp_oui;
    unsigned char crypto;
    unsigned char frame_type;
    unsigned char attrib[0];
} __attribute__((packed)) wifi_dppPublicActionFrameBody_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_dppPublicActionFrameBody_t public_action_body;
} __attribute__((packed)) wifi_dppPublicActionFrame_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_gasInitialResponseFrame_t gas_resp_body;
    wifi_dppOUI dpp_oui;
    unsigned char dpp_proto;
    unsigned short rsp_len;
    unsigned char rsp_body[0];
} __attribute__((packed)) wifi_dppConfigResponseFrame_t;
/* //END OF DPP structure definitions */

/* ANQP structure definitions */
typedef struct
{
    unsigned char query_rsp_info;
    unsigned char adv_proto_id;
} __attribute__((packed)) wifi_AnqpAdvertisementProtoTuple_t;

typedef struct
{
    unsigned char id;
    unsigned char len;
    wifi_AnqpAdvertisementProtoTuple_t proto_tuple;
} __attribute__((packed)) wifi_AnqpAdvertisementProtoElement_t;

typedef struct
{
    unsigned char token;
    unsigned short status;
    unsigned short comeback_delay;
    wifi_AnqpAdvertisementProtoElement_t proto_elem;
} __attribute__((packed)) wifi_gasAnqpInitialResponseFrame_t;

typedef struct
{
    wifi_publicActionFrameHdr_t public_action_hdr;
    wifi_gasAnqpInitialResponseFrame_t gas_resp_body;
    unsigned short rsp_len;
    unsigned char rsp_body[0];
} __attribute__((packed)) wifi_anqpResponseFrame_t;

typedef struct
{
    unsigned short info_id;
    unsigned short len;
    unsigned char info[0];
} __attribute__((packed)) wifi_anqp_element_format_t;

typedef struct
{
    unsigned short info_id;
    unsigned short len;
    unsigned char oi[3];
    unsigned char type;
    unsigned char subtype;
    unsigned char reserved;
    unsigned char payload[0];
} __attribute__((packed)) wifi_hs_2_anqp_element_format_t;
/* //END OF ANQP structure definitions */

typedef struct _wifi_HS2Settings_t
{
    BOOL countryIe;
    BOOL layer2TIF;
    BOOL downStreamGroupAddress;
    BOOL bssLoad;
    BOOL proxyArp;
}wifi_HS2Settings_t;

//Eap Stats
typedef struct _wifi_EapStats_t{    // Passpoint stats defined rdkb-1317
    unsigned int EAPOLStartSuccess;
    unsigned int EAPOLStartFailed;
    unsigned int EAPOLStartTimeouts;
    unsigned int EAPOLStartRetries;
    unsigned int EAPOLSuccessSent;
    unsigned int EAPFailedSent;
} wifi_EapStats_t;

#define DPP_SUB_AUTH_REQUEST 0
#define DPP_SUB_AUTH_RESPONSE 1
#define DPP_SUB_AUTH_CONFIRM 2
/* RESERVED 3-4 */
#define DPP_SUB_PEER_DISCOVER_REQ 5
#define DPP_SUB_PEER_DISCOVER_RESP 6
#define PKEX_SUB_EXCH_REQ 7
#define PKEX_SUB_EXCH_RESP 8
#define PKEX_SUB_COM_REV_REQ 9
#define PKEX_SUB_COM_REV_RESP 10
/* RESERVED 11-255 */

#ifndef DPP_OUI_TYPE
#define DPP_OUI_TYPE  0x1a // OUI Type
#endif
#define DPP_CONFPROTO 0x01 // denoting the DPP Configuration protocol

#define WIFI_STATUS_OK 0
#define STATUS_NOT_COMPATIBLE 1
#define STATUS_AUTH_FAILURE 2
#define STATUS_DECRYPT_FAILURE 3
#define STATUS_CONFIGURE_FAILURE 5
#define STATUS_RESPONSE_PENDING 6
#define STATUS_INVALID_CONNECTOR 7

/*
 * Number of stations supported defines.
 * Note, #ifndef is just for defensive code because these identical defines are also present in OneWifi layer as well.
 */
#ifndef BSS_MAX_NUM_STA_COMMON
#define BSS_MAX_NUM_STA_COMMON   75      /**< Max supported stations for all common platforms except following defines... */
#endif

#ifndef BSS_MAX_NUM_STA_SKY
#define BSS_MAX_NUM_STA_SKY      64      /**< Max supported stations for SKY HUB specific platforms */
#endif

#ifndef BSS_MAX_NUM_STA_XB8
#define BSS_MAX_NUM_STA_XB8      100     /**< Max supported stations for TCHX8 specific platform */
#endif

#ifndef BSS_MAX_NUM_STATIONS
#define BSS_MAX_NUM_STATIONS     100     /**< Max supported stations by RDK-B firmware which would varies based on platform */
#endif

typedef enum
{
    wifi_dpp_attrib_id_status	= 	0x1000,
    wifi_dpp_attrib_id_initiator_boot_hash,
    wifi_dpp_attrib_id_responder_boot_hash,
    wifi_dpp_attrib_id_initiator_protocol_key,
    wifi_dpp_attrib_id_wrapped_data,
    wifi_dpp_attrib_id_initiator_nonce,
    wifi_dpp_attrib_id_initiator_cap,
    wifi_dpp_attrib_id_responder_nonce,
    wifi_dpp_attrib_id_responder_cap,
    wifi_dpp_attrib_id_responder_protocol_key,
    wifi_dpp_attrib_id_initiator_auth_tag,
    wifi_dpp_attrib_id_responder_auth_tag,
    wifi_dpp_attrib_id_config_object,
    wifi_dpp_attrib_id_connector,
    wifi_dpp_attrib_id_config_req_object,
    wifi_dpp_attrib_id_bootstrap_key,
    wifi_dpp_attrib_id_reserved_1,
    wifi_dpp_attrib_id_reserved_2,
    wifi_dpp_attrib_id_finite_cyclic_group,
    wifi_dpp_attrib_id_encrypted_key,
    wifi_dpp_attrib_id_enrollee_nonce,
    wifi_dpp_attrib_id_code_id,
    wifi_dpp_attrib_id_transaction_id,
    wifi_dpp_attrib_id_bootstrapping_info,
    wifi_dpp_attrib_id_channel,
    wifi_dpp_attrib_id_proto_version,
    wifi_dpp_attrib_id_enveloped_data,
    wifi_dpp_attrib_id_send_conn_status,
    wifi_dpp_attrib_id_conn_status,
    wifi_dpp_attrib_id_reconfig_flags,
    wifi_dpp_attrib_id_C_sign_key_hash,
} wifi_dpp_attrib_id_t;

#define DPP_STATUS 0x1000
#define INITIATOR_BOOT_HASH 0x1001
#define RESPONDER_BOOT_HASH 0x1002
#define INITIATOR_PROTOCOL_KEY 0x1003
#define WRAPPED_DATA 0x1004
#define INITIATOR_NONCE 0x1005
#define INITIATOR_CAPABILITIES 0x1006
#define RESPONDER_NONCE 0x1007
#define RESPONDER_CAPABILITIES 0x1008
#define RESPONDER_PROTOCOL_KEY 0x1009
#define INITIATOR_AUTH_TAG 0x100a
#define RESPONDER_AUTH_TAG 0x100b
#define CONFIGURATION_OBJECT 0x100c
#define CONNECTOR 0x100d
#define CONFIG_ATTRIBUTES_OBJECT 0x100e
#define BOOTSTRAP_KEY 0x100f
#define HASH_OF_PEER_PK 0x1010
#define HASH_OF_DEVICE_NK 0x1011
#define FINITE_CYCLIC_GROUP 0x1012
#define ENCRYPTED_KEY 0x1013
#define ENROLLEE_NONCE 0x1014
#define CODE_IDENTIFIER 0x1015
#define TRANSACTION_IDENTIFIER 0x1016
#define CHANGE_CHANNEL 0x1018

typedef struct
{
    unsigned char type;
    unsigned char length;
    unsigned char value[0];
} __attribute__((packed)) ieee80211_tlv_t;

typedef struct
{
    unsigned short type;
    unsigned short length;
    unsigned char value[0];
} __attribute__((packed)) wifi_tlv_t;

typedef enum
{
    wifi_adv_proto_id_anqp,
    wifi_adv_proto_id_mih_info_svc,
    wifi_adv_proto_id_mih_cmd_evt_svc_disc,
    wifi_adv_proto_id_eas,
    wifi_adv_proto_id_rlqp,
    wifi_adv_proto_id_vendor_specific = 221,
} wifi_adv_proto_id_t;

typedef enum
{
    wifi_action_frame_type_spectrum_mgmt,
    wifi_action_frame_type_qos,
    wifi_action_frame_type_dls,
    wifi_action_frame_type_block_ack,
    wifi_action_frame_type_public,
    wifi_action_frame_type_radio_msmt,
    wifi_action_frame_type_fast_bss,
    wifi_action_frame_type_ht,
    wifi_action_frame_sa_query,
    wifi_action_frame_protected_dial,
    wifi_action_frame_wnm,
} wifi_action_frame_type_t;

typedef enum
{
    wifi_public_action_type_bss_coex,
    wifi_public_action_type_dse_enable,
    wifi_public_action_type_dse_disable,
    wifi_public_action_type_dse_loc_announce,
    wifi_public_action_type_ext_channel_switch,
    wifi_public_action_type_dse_msmt_req,
    wifi_public_action_type_dse_msmt_rep,
    wifi_public_action_type_msmt_pilot,
    wifi_public_action_type_dse_pwr,
    wifi_public_action_type_vendor,
    wifi_public_action_type_gas_init_req,
    wifi_public_action_type_gas_init_rsp,
    wifi_public_action_type_gas_comeback_req,
    wifi_public_action_type_gas_comeback_rsp,
    wifi_public_action_type_tdls_disc_rsp,
    wifi_public_action_type_loc_track_not,
} wifi_public_action_type_t;

typedef enum {
    wifi_test_command_id_mgmt = 0x1010,
    wifi_test_command_id_action,
    wifi_test_command_id_probe_req,
    wifi_test_command_id_probe_rsp,
    wifi_test_command_id_assoc_req,
    wifi_test_command_id_assoc_rsp,
    wifi_test_command_id_auth,
    wifi_test_command_id_deauth,
    wifi_test_command_id_data = 0x1050,
    wifi_test_command_id_8021x,
    wifi_test_command_id_ctl = 0x10a0,
    wifi_test_command_id_chirp,
    wifi_test_command_id_anqp,
    wifi_test_command_id_reconf_auth_resp,
} wifi_test_command_id_t;

typedef enum
{
    wifi_test_attrib_cmd,
    wifi_test_attrib_vap_name,
    wifi_test_attrib_sta_mac,
    wifi_test_attrib_direction,
    wifi_test_attrib_raw
} wifi_test_attrib_t;

struct ieee80211_radiotap_header {
    unsigned char   it_version;     /* set to 0 */
    unsigned char   it_pad;
    unsigned short  it_len;         /* entire length */
    unsigned int    it_present;     /* fields present */
} __attribute__((__packed__));

typedef struct {
    unsigned char   pad[8];
    unsigned int    caplen;
    unsigned int    len;
} __attribute__((__packed__)) wireshark_pkthdr_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned int    magic;
    unsigned short  major;
    unsigned short  minor;
} __attribute__((__packed__)) section_header_block_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned short  link_type;
    unsigned short  reserved;
    unsigned int    snap_len;
} __attribute__((__packed__)) interface_description_block_t;

typedef struct {
    unsigned int    block_type;
    unsigned int    block_len;
    unsigned int    intf_id;
    unsigned int    time_high;
    unsigned int    time_low;
    unsigned int    caplen;
    unsigned int    len;
} __attribute__((__packed__)) enhanced_packet_block_t;

typedef struct {
    unsigned char   ccmp[8];
} __attribute__((__packed__)) ccmp_hdr_t;

typedef struct {
    unsigned char   dsap;
    unsigned char   ssap;
    unsigned char   control;
    unsigned char   oui[3];
    unsigned char   type[2];
} __attribute__((__packed__)) llc_hdr_t;

typedef struct {
    char            interface_name[32];
    unsigned char   mac[6];
    bool            uplink_downlink;
    unsigned int    num_commands;
    wifi_test_command_id_t cmd[10];
    unsigned int    first_frame_num;
    unsigned int    last_frame_num;
    char            cap_file_name[128];
} frame_test_arg_t;

wifi_tlv_t *get_tlv(unsigned char *buff, unsigned short attrib, unsigned short len);
wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val);

typedef enum
{
    wifi_gas_status_success = 0,
    wifi_gas_advertisement_protocol_not_supported = 59,
    wifi_no_outstanding_gas_request = 60,
    wifi_gas_response_not_received_from_server = 61,
    wifi_gas_query_timeout = 62,
    wifi_gas_query_response_too_large = 63
} wifi_gas_status_code_t;

#if defined(FEATURE_HOSTAP_AUTHENTICATOR)

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
typedef uint64_t  u64;
typedef unsigned int        u32;
typedef unsigned short      u16;
typedef unsigned char       u8;
/** @} */  //END OF GROUP WIFI_HAL_TYPES
 
/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */
/* _wifi_hostap_ioctl_init() function */
 /**
 * Description: This function call will init IOCTL socket to get/set ioctl params from
 *       Lib hostapd to/from driver.
 * Parameters  None:
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if any error is detected
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int _wifi_hostap_ioctl_init();

/* _wifi_hostap_ioctl_fd_get() function */
 /**
 * Description: Return Ioctl socket created. If init was done, init the socket
 *  and return.
 * Parameters  None:
 *
 * @return ioctl FD created..
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int _wifi_hostap_ioctl_fd_get();

/* _wifi_hostap_ioctl() function */
 /**
 * Description: Send command through ioctl socket created.
 *  Parameters :
 *     command - Ioctl command to be sent to driver
 *     data - Value to be get/set for specific operation
 *
 * @return The status of the operation.
 * @retval 0 if Successful
 * @retval -1 if Error
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int _wifi_hostap_ioctl(int command, void *data);

/* wifi_sethostApPrivacy()function */
 /**
 * Description: Enable/Disable privacy settings per vap.
 * Parameters:
 *   iface - Interface name of Vap.
 *   enabled - Defines whether privacy is enabled or no
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApPrivacy(char *iface, int enabled);

/* wifi_sethostApAuthMode()function */
 /**
 * Description: Set Authmode Auto/Open/Shared for a particular Vap.
 * Parameters:
 *   iface - Interface name of Vap.
 *   authmode - Authmode of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApAuthMode(char *iface, int authmode);

/* wifi_sethostApMcastCipher()function */
 /**
 * Description: Set group key cipher to particular Vap.
 * Parameters:
 *   iface - Interface name of Vap.
 *   cipher - Group key cipher of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApMcastCipher(char *iface, int cipher);

/* wifi_sethostApMcastKeyLen()function */
 /**
 * Description: Set group key length to particular Vap.
 * Parameters:
 *   iface - Interface name of Vap.
 *   keylen - Group key length of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApMcastKeyLen(char *iface, int keylen);

/* wifi_sethostApKeyMgmtAlgs() function */
 /**
 * Description: Set key management algorithm to particular Vap.
 *  Eg: PSK/EAP/SAE
 * Parameters:
 *   iface - Interface name of Vap.
 *   keymgmt - key management algorithm of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApKeyMgmtAlgs(char *iface, int keymgmt);

/* wifi_sethostApUcastCiphers() function */
 /**
 * Description: Set pairwise key ciphers to particular Vap.
 *  Eg: AES/TKIP
 * Parameters:
 *   iface - Interface name of Vap.
 *   cipher - key ciphers of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApUcastCiphers(char *iface, int cipher);

/* wifi_sethostApRSNCaps() function */
 /**
 * Description: Set RSN capabilities to particular Vap
 * Parameters:
 *   iface - Interface name of Vap.
 *   capab - RSN capabilities of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApRSNCaps(char *iface, int capab);

/* wifi_sethostApWPA() function */
 /**
 * Description: Set WPA configuration to particular Vap
 * Parameters:
 *   iface - Interface name of Vap.
 *   wpa - WPA configuration of Vap to be set in driver
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApWPA(char *iface, int wpa);

/* wifi_sethostApOsen()function */
 /**
 * Description: Set OSEN authenticated layer for Hotspot 2.0 support.
 * Parameters:
 *   iface - Interface name of Vap.
 *   enable - OSEN enabled/disabled
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApOsen(char *iface, int enable);

/* ioctl_set_80211priv()function */
 /**
 * Description: API for get/set of any ioctl operation to driver.
 * Parameters:
 *   iface - Interface name of Vap.
 *   op - Operation to be performed in driver
 *   data - Data to be passed to driver inorder to perform specified
 *   operation
 *   len - Length of the data
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int ioctl_set_80211priv(char *iface, int op, void *data, int len);

/* wifi_sethostApStaAuthorized()function */
 /**
 * Description: Set if a station is authorized/unauthorized.
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   authorized - 1 - Authorized, 0 - Unauthorized.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaAuthorized(char *iface, unsigned char *addr, int authorized);

/* wifi_sethostApStaDeauth()function */
 /**
 * Description: Set ioctl to Deauth the station.
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   reason_code - Reason why hostap is sending deauth to client.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaDeauth(char *iface, unsigned char *addr, int reason_code);

/* wifi_sethostApStaDisassoc() function */
 /**
 * Description: Set ioctl to Disassoc a station.
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   reason_code - Reason why hostap is sending disassoc to client.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaDisassoc(char *iface, unsigned char *addr, int reason_code);

/* wifi_sethostApStaSendAuthResp() function */
 /**
 * Description: Set ioctl to send auth response to station
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   fils_auth - FILS AAD params, if driver supports FILS configs
 *   fils_en - FILS AAD params, Fils enable/disable
 *   status - Status to be sent to station, Auth success/failure
 *   seq - Sequence number of transaction
 *   len - Length of the ioctl data len
 *   ie - Auth Response IE data
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaSendAuthResp(char *iface, unsigned char *addr, unsigned int fils_auth,
                             unsigned int fils_en, int status, int seq, int len, unsigned char *ie);

/* wifi_sethostApStaSendAssocResp() function */
 /**
 * Description: Set ioctl to send assoc response to station
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   status_code - Assoc success/failure
 *   reassoc - Determines if this is reply for a reassoc request.
 *   len - Length of the ioctl data len
 *   ie - Auth Response IE data
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaSendAssocResp(char *iface, unsigned char *addr, int status_code,
                              int reassoc, int len, unsigned char *ie);

/* wifi_sethostApStaDelKey() function */
 /**
 * Description: Set ioctl to delete key for particular station
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   key_idx - key index to be deleted.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaDelKey(char *iface, unsigned char *addr, int key_idx);

/* wifi_sethostApStaSetKey() function */
 /**
 * Description: Set ioctl to set key for particular station
 * Parameters:
 *   iface - Interface name of Vap.
 *   addr - Mac address of the Station.
 *   key - Key to be set in driver.
 *   key_len - Length of the key.
 *   key_idx - key index to be deleted.
 *   cipher - cipher algorithm to be used
 *   set_tx - set/clear idx.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApStaSetKey(char *iface, unsigned char *addr, unsigned char *key, int key_len,
                       int key_idx, u_int8_t cipher, int set_tx);

/* wifi_sethostApWpsIE() function */
 /**
 * Description: Set WPS Ie to driver for paticular vap interface
 * Parameters:
 *   iface - Interface name of Vap.
 *   wpa_ie - WPA IE to be set in Beacon/ProbeResp.
 *   wpa_ie_len - Len of WPA Ie to be set.
 *   ie - WPS IE
 *   len - WPS IE len.
 *   Frametype - Determines which frame the IE has to be set.
 *      BEACON/PROBE RESP/ASSOC RESP
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApWpsIE(char *iface, const u8 *wpa_ie, const size_t wpa_ie_len, const u8 *ie,
                   size_t len, u32 frametype);

/* wifi_sethostApGenericeElemOptIE() function */
 /**
 * Description: Set Generic element IE's to driver for paticular vap interface
 * Parameters:
 *   iface - Interface name of Vap.
 *   ie - Generic Element IE
 *   ie_len - Generic Element IE len.
 *   resp_ie - IE's to be appended to generic element IE's
 *   resp_ie_len - resp_ie length
 *   Frametype - Determines which frame the IE has to be set.
 *      BEACON/PROBE RESP/ASSOC RESP
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostApGenericeElemOptIE(char *iface, const u8 *ie, const size_t ie_len, const u8 *resp_ie,
                              size_t resp_ie_len, u32 frametype);

/* wifi_gethostIfIndex() function */
 /**
 * Description: To get Interface index mapping for a particular interface.
 *  Parameters :
 *    iface - Interface name of vap.

 * @return The status of the operation.
 * @retval interface index if successful.
 * @retval -1 if any error is detected
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_gethostIfIndex(char *iface);

/* wifi_sendHostApMgmtFrame() function */
 /**
 * Description: To send Mgmt frame from hostap.
 * Parameters :
 *    frame - Mgmt Frame to be sent from hostap.
 *    data_len - Frame data length.
 *    iface - Interface name of vap.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sendHostApMgmtFrame(const u8 *frame, size_t data_len, char *iface);

/* wifi_setHostApIfSSID() function */
 /**
 * Description: Set SSID name for a Vap
 * Parameters :
 *    iface - Interface name of vap.
 *    buf - SSID name to be set
 *    len - SSID Name length
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_setHostApIfSSID(char *iface, const u8 *buf, int len);

/* wifi_setHostApResetAppFilter() function */
 /**
 * Description: Reset application filter set in driver for particular vap interface.
    Application filter determines the types of packet tht driver sends to application.
 * Parameters :
 *    iface - Interface name of vap.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_setHostApResetAppFilter(char *iface);

/* wifi_setHostApSetAppFilter() function */
 /**
 * Description: Set application filter in driver for particular vap interface.
    Application filter determines the types of packet tht driver sends to application.
 * Parameters :
 *    iface - Interface name of vap.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_setHostApSetAppFilter(char *iface);

/* wifi_gethostAuthSeqNum() function */
 /**
 * Description: Get sequence number of a station in particular vap interface
 * Parameters :
 *    iface - Interface name of vap.
 *    addr - Mac address of the station
 *    idx - Index number of station.
 *    seq - address of unsigned char in which sequence number is filled
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 * @note: seq argument should have a valid memory before sending to this
 *  API.
 */
int wifi_gethostAuthSeqNum(char *ifname, const u8 *addr, int idx,
                   u8 *seq);

/* wifi_sethostAddTspec() function */
 /**
 * Description: Add Traffic specification if 8011R is enabled in driver.
 * Parameters :
 *    iface - Interface name of vap.
 *    addr - Mac address of the station
 *    tspec_ie - Traffic specification IE data
 *    tspec_ielen - Traffic specification IE data length
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostAddTspec(char *iface, const u8 *addr, u8 *tspec_ie, size_t tspec_ielen);

/* wifi_sethostAddStaNode() function */
 /**
 * Description: Add station node to driver during 80211R enabled.
 * Parameters :
 *    iface - Interface name of vap.
 *    addr - Mac address of the station
 *    auth_alg - Authentication algorithm used to auth station.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_sethostAddStaNode(char *iface, const u8 *addr, u16 auth_alg);

/* wifi_setIfMode() function */
 /**
 * Description: Update vap interface operation mode to master.
 * Parameters :
 *    iface - Interface name of vap.
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_setIfMode(char *iface);

/* wifi_setIfaceFlags() function */
 /**
 * Description: To set interface state to up or down
 * Parameters :
 *    iface - Interface name of vap.
 *    dev_up - Indicates whether interface has to be switched up or down
 *
 * @return The status of the operation.
 * @retval 0: If ioctl set is successful.
 * @retval -1: If ioctl set is Failed.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_setIfaceFlags(const char *ifname, int dev_up);

/* wifi_hostApIfaceStatusSigHndlr() function */
 /**
 * Description: To set global signal set based on signal number received.
 * Parameters :
 *     sig - Signal number
 *
 * @return None.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
void wifi_hostApIfaceStatusSigHndlr(int sig);

/* wifi_hostApEAPOLRxCallback() function */
 /**
 * Description: Callback to send received eapol packet from raw socket
   to Lib hostapd.
 * Parameters :
 *    apIndex - Vap Index in which Eapol packet is received.
 *    iface - Interface name of corresponding vap.
 *    fd - Socket file descriptor to recv packet from.
 *
 * @return None.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 * @note: Shouldn't call any blocking calls in this callback.
 *
 */
void wifi_hostApEAPOLRxCallback(int apIndex, char *iface, int fd);

/* wifi_hostApEAPOLRxSelectThread() function */
 /**
 * Description: Thread API to wait for Eapol packet from raw socket opened
 *  for particular Vap. pselect will wait indefinitely untill following conditon
 *  occurs
 *     EAPOL packet received: Will se the FD in which packet is received.
 *     Signal(SIGUSR1) - will come out of pselect and re-modify the FD set and max_fd
 *     value.
 *   pselect will have FD set only for enabled VAPs. If a new VAP is enabled during
 *   run-time, then after creating FD for that interface, send SIGUSR1 to update max_fd
 *   and FD_SET.
 *   During RFC switch, thread will be cancelled and joined.
 * Parameters :
 *    ctx - Currently not used.
 *
 * @return None.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 * @note: Thread has to be joined during exit of this API.
 *
 */
void *wifi_hostApEAPOLRxSelectThread(void *ctx);

/* wifi_hostApIfaceUpdateSigPselect() function */
 /**
 * Description: API to update modified FD_SET to Eapol Rx thread
 *  by sending SIGUSR1
 * Parameters :
 *    apIndex - Vap Index in which Eapol packet is received.
 *    is_up - True - Update the Rx thread,
 *             False - Clear the particular FD_SET from global
 *              fd_set and then send signal.
 *
 * @return None.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
void wifi_hostApIfaceUpdateSigPselect(int ap_index, BOOL is_up);

/* wifi_hostApRecvEther() function */
 /**
 * Description: To create EAPOL Raw socket for each interfaces.
 *  Create Thread if it is not created or send update signal to
 *  thread with the newly created FD.
 * Parameters :
 *    ap_index - Vap index parameter
 *    iface - Interface name in which socket is going to bind.
 *    proto - Protocol to be listened
 *
 * @return status of operation
 *  return 0 - On successful.
 *  return -1 - On Failure.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_hostApRecvEther(unsigned int ap_index, const char *iface, unsigned int proto);

/* wifi_hostApCancelRecvEtherThread() function */
 /**
 * Description: To reset global fd_set saved and if the Eapol rx
 *  thread is running, cancel the thread and join.
 * Parameters : None
 *
 * @return None.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
void wifi_hostApCancelRecvEtherThread();

/* wifi_hostApSendEther() function */
 /**
 * Description: Send L2 Frames received from Lib hostap.
 * Parameters :
 *    ifname - Interface name of Vap in which l2 packet is sent
 *    buff - Data to be sent
 *    len - Length of the data.
 *    proto - Protocol to open socket.
 *
 * @return Status of operation
 *  return 0 - On Success.
 *  return -1 - On Failure.
 *
 * @execution Synchronous.
 * @sideeffect None.
 *
 */
int wifi_hostApSendEther(const char *ifname, unsigned char *buff, size_t len, unsigned int proto);

/** @} */  //END OF GROUP WIFI_HAL_APIS

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
typedef enum {
        wifi_hal_cmd_push_ssid,
        wifi_hal_cmd_bss_transition,
        wifi_hal_cmd_interworking,
        wifi_hal_cmd_passpoint,
        wifi_hal_cmd_greylisting,
        wifi_hal_cmd_restart_hostapd,
        wifi_hal_cmd_mesh_reconfig,
        wifi_hal_cmd_start_stop_hostapd,
        wifi_hal_cmd_push_passphrase,
        wifi_hal_cmd_max
} wifi_hal_cmd_t;

typedef struct {
        wifi_hal_cmd_t cmd;
        unsigned int ap_index;
        union {
                char ssid[32];
                BOOL bss_transition;
                BOOL rdk_hs20;
                BOOL greylist_enable;
                BOOL libhostapd_init;
                char passphrase[64];
                BOOL mesh_reconfig;
        } u;
} __attribute__((packed)) wifi_hal_ipc_data_t;

typedef int (*hal_ipc_callback_func_t)(wifi_hal_ipc_data_t *data, BOOL is_ipc);

typedef struct {
    BOOL wifi_agent_hal;
    int fd;
    hal_ipc_callback_func_t hal_ipc_callback;
} wifi_hal_t;
/** @} */  //END OF GROUP WIFI_HAL_TYPES

/**
 * @addtogroup WIFI_HAL_APIS
 * @{
 */

UINT wifi_callback_init();

/* RDKB-30263 Grey List control from RADIUS
This function will add/delete the mac from the mac table
@arg1 -ifname -Interface on which client associates
@arg2 - assoc_cli_mac - MAC address of connected client
@arg3 - add/delete the entry
Return value - success 0 failure -1
*/
int wifi_greylist_acl_mac( int apIndex, const UINT *macaddr, BOOL add );

/* RDKB-30263 Grey List control from RADIUS
This function will disassociate the client forcible
@arg1 -ifname -Interface on which client associates
@arg2 - assoc_cli_mac - MAC address of connected client
*/
void wifi_kick_mac(char *ifname, unsigned char macaddr[6]);
/** @} */  //END OF GROUP WIFI_HAL_APIS
#endif /* FEATURE_HOSTAP_AUTHENTICATOR */


#endif
