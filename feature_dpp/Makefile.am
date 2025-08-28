##########################################################################
# If not stated otherwise in this file or this component's LICENSE
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
SUBDIRS = .
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libdpp_haldpp.la
libdpp_haldpp_la_CPPFLAGS = -I$(top_srcdir)/./include $(CPPFLAGS)
libdpp_haldpp_la_CFLAGS = -Wall -Werror -Wextra -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-format-truncation
libdpp_haldpp_la_SOURCES = dpp.c
libdpp_haldpp_la_LDFLAGS = -lm -lcjson -lssl -lcrypto
