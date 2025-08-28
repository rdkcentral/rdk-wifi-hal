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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <wifi_hal.h>
#include "wifi_hal_rdk.h"
#include "wifi_hal_rdk_framework.h"

int data_frame_received_callback(INT ap_index, mac_address_t sta_mac, UCHAR *frame, UINT len, wifi_dataFrameType_t type, wifi_direction_t dir);

extern unsigned char wifi_common_hal_test_signature[8];

int create_test_socket()
{
    int sockfd;
    struct sockaddr_in sockaddr;
    unsigned short port = 8888;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        printf("%s:%d: Error opening raw socket, err:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family   = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_aton("127.0.0.1" , &sockaddr.sin_addr);

    if (bind(sockfd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        printf("%s:%d: Error binding to interface, err:%d\n", __func__, __LINE__, errno);
        close(sockfd);
        return -1;
    }

    return sockfd;
}

INT start_receiving_test_frames()
{
    int sockfd;
    int ret;
    unsigned char msg[2048];
    wifi_test_command_id_t cmd;
    mac_address_t   bmac;
    unsigned char frame[2048];
    char interface_name[32];
    wifi_tlv_t *tlv;
    fd_set rfds;
    struct timeval tv;
    int retval, ap_index;
    bool exit = false;
    struct sockaddr_in saddr;
    socklen_t slen;
       wifi_direction_t dir;
       unsigned int frame_len;

    wifi_rdk_hal_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    if ((sockfd = create_test_socket()) < 0) {
        wifi_rdk_hal_dbg_print("%s:%d: Socket create failed\n", __func__, __LINE__);
        return RETURN_ERR;

    }

    while (exit == false) {

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == 0) {
            continue;
        } else if (retval == -1) {
            continue;
        }

        if (FD_ISSET(sockfd, &rfds) == 0) {
            continue;
        }
        //wifi_rdk_hal_dbg_print("%s:%d:Socket signaled Receiving data from socket\n", __func__, __LINE__);

        if ((ret = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&saddr, &slen)) < 0) {
            continue;
        }

        //wifi_rdk_hal_dbg_print("%s:%d: Received data: %d, select returned:%d\n", __func__, __LINE__, ret, retval);

        if (memcmp(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature)) != 0) {
            continue;
        }

        //wifi_rdk_hal_dbg_print("%s:%d: Received test signature\n", __func__, __LINE__);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_vap_name, ret)) == NULL) {
               continue;
        }
        memcpy(interface_name, tlv->value, tlv->length);
        sscanf(interface_name, "ath%d", &ap_index);
        //wifi_rdk_hal_dbg_print("%s:%d: Interface Index:%d\n", __func__, __LINE__, ap_index);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_sta_mac, ret)) == NULL) {
            continue;
        }
        memcpy(bmac, tlv->value, tlv->length);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_direction, ret)) == NULL) {
            continue;
        }
        memcpy(&dir, tlv->value, tlv->length);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_raw, ret)) == NULL) {
            continue;
        }
        memcpy(frame, tlv->value, tlv->length);
               frame_len = tlv->length;

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_cmd, ret)) == NULL) {
            continue;
        }
        memcpy((unsigned char *)&cmd, tlv->value, tlv->length);

        switch (cmd) {
            case wifi_test_command_id_action:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_ACTION, dir);
                               break;

            case wifi_test_command_id_probe_req:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_PROBE_REQ, dir);
                               break;

            case wifi_test_command_id_probe_rsp:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_PROBE_RSP, dir);
                               break;

            case wifi_test_command_id_assoc_req:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_ASSOC_REQ, dir);
                               break;

            case wifi_test_command_id_assoc_rsp:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_ASSOC_RSP, dir);
                               break;

                       case wifi_test_command_id_auth:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_AUTH, dir);
                               break;

                       case wifi_test_command_id_deauth:
                mgmt_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_MGMT_FRAME_TYPE_DEAUTH, dir);
                               break;

                       case wifi_test_command_id_8021x:
                data_frame_received_callback(ap_index, bmac, frame, frame_len, WIFI_DATA_FRAME_TYPE_8021x, dir);
                               break;

            default:
                break;
        }
    }

    close(sockfd);


       return RETURN_OK;
}

void wifi_rdk_hal_dbg_print(char *format, ...)
{
    char buff[4096] = {0};
    va_list list;
    static FILE *fpg = NULL;
    
    //get_formatted_time(buff);
    if ((access("/nvram/wifiRdkHal", R_OK)) != 0)
    {
        return;
    }
    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    if (fpg == NULL)
    {
        fpg = fopen("/tmp/wifiRdkHal", "a+");
        if (fpg == NULL)
        {
            return;
        }
        else
        {
            fputs(buff, fpg);
        }
    }
    else
    {
        fputs(buff, fpg);
    }

    fflush(fpg);
}
