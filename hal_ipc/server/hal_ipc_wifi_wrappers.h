/***************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef HAL_IPC_WRAPPERS_H
#define HAL_IPC_WRAPPERS_H

#include "wifi_hal.h"

//--------------------------------------------------------------------------------------------------
INT wifi_hal_setRadioStatsEnable(INT radioIndex, BOOL enabled);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDNumberOfEntries(ULONG *numEntries);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceStats(INT apIndex,
                                        mac_address_t *clientMacAddress,
                                        wifi_associated_dev_stats_t *associated_dev_stats,
                                        ULLONG *handle);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioChannelStats(INT radioIndex,
                                  wifi_channelStats_t *input_output_channelStats_array,
                                  INT array_size);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDTrafficStats2(  INT ssidIndex,
                                    wifi_ssidTrafficStats2_t *output_struct);


//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceRxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_rx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDEnable( INT ssidIndex,
                            BOOL *output_bool);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDRadioIndex( INT ssidIndex,
                                INT *radioIndex);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDNameStatus( INT apIndex,
                                CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApName( INT apIndex,
                        CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getNeighborReportActivation(   UINT apIndex,
                                            BOOL *activate);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getBSSTransitionActivation(UINT apIndex,
                                        BOOL *activate);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedClientDiagnosticResult( INT apIndex,
                                                    char *mac_addr,
                                                    wifi_associated_dev3_t *dev_conn);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioOperatingFrequencyBand(INT radioIndex,
                                            CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioNumberOfEntries(ULONG *output);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApAssociatedDeviceTxStatsResult(INT radioIndex,
                                                mac_address_t *clientMacAddress,
                                                wifi_associated_dev_rate_info_tx_stats_t **stats_array,
                                                UINT *output_array_size,
                                                ULLONG *handle);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getMultiPskClientKey(  INT apIndex,
                                    mac_address_t mac,
                                    wifi_key_multi_psk_t *key);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_setGroup( UINT steeringgroupIndex,
                                wifi_steering_apConfig_t *cfg_2,
                                wifi_steering_apConfig_t *cfg_5);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientSet(UINT steeringgroupIndex,
                                INT apIndex, mac_address_t client_mac,
                                wifi_steering_clientConfig_t *config);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientRemove( UINT steeringgroupIndex,
                                    INT apIndex,
                                    mac_address_t client_mac);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_steering_clientDisconnect( UINT steeringgroupIndex,
                                        INT apIndex,
                                        mac_address_t client_mac,
                                        wifi_disconnectType_t type,
                                        UINT reason);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getSSIDName(   INT apIndex,
                            CHAR *output_string);


//--------------------------------------------------------------------------------------------------
INT wifi_hal_getAssociationReqIEs(  UINT apIndex,
                                    const mac_address_t *clientMacAddress,
                                    CHAR *req_ies,
                                    UINT req_ies_size,
                                    UINT *req_ies_len);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioCountryCode(   INT radioIndex,
                                    CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioOperatingChannelBandwidth( INT radioIndex,
                                                CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioTransmitPower( INT radioIndex,
                                    ULONG *output_ulong);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_setNeighborReportActivation(UINT apIndex, BOOL activate);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getRadioIfName(INT radioIndex,
                            CHAR *output_string);

//--------------------------------------------------------------------------------------------------
INT wifi_hal_getApNumDevicesAssociated( INT apIndex,
                                        ULONG *output_ulong);

#endif // HAL_IPC_WRAPPERS_H
