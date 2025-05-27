##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
AM_CFLAGS += -Wall -Werror -Wextra -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-format-truncation
AM_CPPFLAGS = -Wall -Werror
AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = .
if WITH_GTEST_SUPPORT
SUBDIRS += test
endif
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

if WIFI_EMULATOR
lib_LTLIBRARIES = librdk_wifiemulatorhal.la
librdk_wifiemulatorhal_la_CPPFLAGS = -I$(top_srcdir)/./include $(CPPFLAGS) -I$(top_srcdir)/../util_crypto -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/libnl3 -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(top_srcdir)/../util
librdk_wifiemulatorhal_la_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-format-truncation -Wno-poison-system-directories -Wno-discarded-qualifiers
librdk_wifiemulatorhal_la_SOURCES = wifi_hal_rx_test.c wifi_hal_data_rx.c wifi_hal_dpp.c wifi_hal_anqp.c wifi_hal_frame_test.c ../util_crypto/aes_siv.c wifi_tlv.c wifi_hal_rdk_util.c
librdk_wifiemulatorhal_la_LDFLAGS = -lm -lcjson -lssl -lcrypto

librdk_wifiemulatorhal_la_LDFLAGS += -lhostap -lnl-3 -lnl-genl-3 -lnl-route-3
librdk_wifiemulatorhal_la_SOURCES += wifi_hal.c wifi_hal_hostapd.c wifi_hal_nl80211.c wifi_hal_nl80211_events.c wifi_hal_nl80211_utils.c collection.c wifi_hal_mgmt_rx_one_wifi.c

librdk_wifiemulatorhal_la_CPPFLAGS += -I$(top_srcdir)/../platform/wifi-emulator
librdk_wifiemulatorhal_la_SOURCES += ../platform/wifi-emulator/platform_emulator.c

else
lib_LTLIBRARIES = librdk_wifihal.la
librdk_wifihal_la_CPPFLAGS = -I$(top_srcdir)/./include $(CPPFLAGS) -I$(top_srcdir)/../util_crypto -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/libnl3 -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(top_srcdir)/../util
librdk_wifihal_la_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-format-truncation -Wno-poison-system-directories -Wno-discarded-qualifiers
librdk_wifihal_la_SOURCES = wifi_hal_rx_test.c wifi_hal_data_rx.c wifi_hal_dpp.c wifi_hal_anqp.c wifi_hal_frame_test.c ../util_crypto/aes_siv.c wifi_tlv.c wifi_hal_rdk_util.c
librdk_wifihal_la_LDFLAGS = -lm -lcjson -lssl -lcrypto

if ONE_WIFIBUILD
librdk_wifihal_la_LDFLAGS += -lhostap -lnl-3 -lnl-genl-3 -lnl-route-3
librdk_wifihal_la_SOURCES += wifi_hal.c wifi_hal_hostapd.c wifi_hal_nl80211.c wifi_hal_nl80211_events.c wifi_hal_nl80211_utils.c collection.c wifi_hal_mgmt_rx_one_wifi.c wifi_hal_wnm_rrm.c
else
librdk_wifihal_la_SOURCES += wifi_hal_mgmt_rx.c
endif

if TCXB7_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if VNTXER5_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/qualcomm
librdk_wifihal_la_SOURCES += ../platform/qualcomm/platform_xer5.c
endif

if DEVICE_EXTENDER
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/qualcomm
librdk_wifihal_la_SOURCES += ../platform/qualcomm/platform_ext.c
endif 

if TCXB8_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if XB10_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if SCXER10_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if TCHCBRV2_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if CMXB7_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/intel
librdk_wifihal_la_SOURCES += ../platform/intel/platform.c
librdk_wifihal_la_LDFLAGS += -lrt
# HAL-IPC server sources
if HAL_IPC
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../hal_ipc/server/
librdk_wifihal_la_SOURCES += ../hal_ipc/server/hal_ipc.c ../hal_ipc/server/hal_ipc_processors.c ../hal_ipc/server/server_hal_ipc.c ../hal_ipc/server/hal_ipc_wifi_wrappers.c
endif #HAL_IPC
endif

if SKYSR300_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if XLE_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/xle
librdk_wifihal_la_SOURCES += ../platform/xle/platform_xle.c
librdk_wifihal_la_LDFLAGS += -lrdkconfig
endif

if SKYSR213_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/broadcom
librdk_wifihal_la_SOURCES += ../platform/broadcom/platform.c
endif

if RASPBERRY_PI_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/raspberry-pi
librdk_wifihal_la_SOURCES += ../platform/raspberry-pi/platform_pi.c
endif

if BANANA_PI_PORT
librdk_wifihal_la_CPPFLAGS += -I$(top_srcdir)/../platform/banana-pi -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/wpa_supplicant
librdk_wifihal_la_SOURCES += ../platform/banana-pi/platform.c
endif

include_HEADERS = wifi_hal_rdk.h wifi_hal_rdk_framework.h ieee80211.h hs20.h ../util_crypto/aes_siv.h 

if ONE_WIFIBUILD
include_HEADERS += wifi_hal_priv.h wifi_hal_wnm_rrm.h
endif

endif #WIFI_EMULATOR

