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
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([hal], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
               case "${enableval}" in
                yes) GTEST_SUPPORT_ENABLED=true
                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([test/Makefile])]);;
                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
               esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])
AM_CONDITIONAL([WIFI_EMULATOR], [test "x$WIFI_EMULATOR" = "xtrue"])
AM_CONDITIONAL([ONE_WIFIBUILD], [test "x$ONE_WIFIBUILD" = "xtrue"])
AM_CONDITIONAL([RASPBERRY_PI_PORT], [test "x$RASPBERRY_PI_PORT" = "xtrue"])
AM_CONDITIONAL([BANANA_PI_PORT], [test "x$BANANA_PI_PORT" = "xtrue"])
AM_CONDITIONAL([TCXB7_PORT], [test "x$TCXB7_PORT" = "xtrue"])
AM_CONDITIONAL([VNTXER5_PORT], [test "x$VNTXER5_PORT" = "xtrue"])
AM_CONDITIONAL([TCHCBRV2_PORT], [test "x$TCHCBRV2_PORT" = "xtrue"])
AM_CONDITIONAL([SKYSR300_PORT], [test "x$SKYSR300_PORT" = "xtrue"])
AM_CONDITIONAL([XLE_PORT], [test "x$XLE_PORT" = "xtrue"])
AM_CONDITIONAL([TCXB8_PORT], [test "x$TCXB8_PORT" = "xtrue"])
AM_CONDITIONAL([XB10_PORT], [test "x$XB10_PORT" = "xtrue"])
AM_CONDITIONAL([SCXER10_PORT], [test "x$SCXER10_PORT" = "xtrue"])
AM_CONDITIONAL([SKYSR213_PORT], [test "x$SKYSR213_PORT" = "xtrue"])
AM_CONDITIONAL([CMXB7_PORT], [test "x$CMXB7_PORT" = "xtrue"])
AM_CONDITIONAL([HAL_IPC], [test "x$HAL_IPC" = "xtrue"])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES(Makefile)

AC_SUBST(GTEST_ENABLE_FLAG)

AC_OUTPUT

