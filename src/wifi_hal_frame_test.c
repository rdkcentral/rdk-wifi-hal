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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "wifi_hal.h"
#include "wifi_hal_rdk.h"
#include "wifi_hal_priv.h"
#include "pcap.h"
#include "ieee80211.h"

#if defined(PLATFORM_LINUX)
extern unsigned char wifi_common_hal_test_signature[8];
#else
unsigned char wifi_common_hal_test_signature[8] = {0x11, 0x22, 0x22, 0x33, 0x44, 0x44, 0x55, 0x66};
#endif
bool is_matching_cmd_in_list(wifi_test_command_id_t matching_cmd, frame_test_arg_t *arg)
{
       unsigned int i;
       bool matched = false;

       for (i = 0; i < arg->num_commands; i++) {
               if (arg->cmd[i] == matching_cmd) {
                       matched = true;
                       break;
               }       
       }

       return matched;
}

int wifi_send_test_frame(unsigned char *frame, size_t frame_len, frame_test_arg_t *arg, wifi_test_command_id_t cmd, wifi_direction_t dir)
{
   int ret, sockfd;
   struct sockaddr_in sockaddr;
   unsigned char msg[2048];
   unsigned int len, tlv_len = 0;
   wifi_tlv_t *tlv;
   unsigned short port = 8888;

   //printf("%s:%d: Enter: data length:%d\n", __func__, __LINE__, frame_len);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
       printf("%s:%d: Error opening raw socket, err:%d\n", __func__, __LINE__, errno);
       return RETURN_ERR;
    }

    memset(&sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr.sin_family   = AF_INET;
    sockaddr.sin_port = htons(port);
    inet_aton("127.0.0.1" , &sockaddr.sin_addr);

    memcpy(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature));
    len = sizeof(wifi_common_hal_test_signature);


    tlv = (wifi_tlv_t *)&msg[sizeof(wifi_common_hal_test_signature)];

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_cmd, sizeof(wifi_test_command_id_t), (unsigned char*)&cmd);
    tlv_len += (4 + sizeof(wifi_test_command_id_t));

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, (unsigned char*)arg->interface_name);
    tlv_len += (4 + IFNAMSIZ);


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), arg->mac);
    tlv_len += (4 + sizeof(mac_address_t));

    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_direction, 1, (unsigned char*)&dir);
    tlv_len += (1 + sizeof(mac_address_t));


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, frame_len, frame);
    tlv_len += (4 + frame_len);

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
       printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
       close(sockfd);
       return RETURN_ERR;
    }

    close(sockfd);

    //printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

    return RETURN_OK;
}

int parse_data_frame(struct ieee80211_frame *frame, size_t frame_len, frame_test_arg_t *arg, wifi_direction_t dir)
{
       unsigned int rc = RETURN_ERR; 
    unsigned char *data;
    llc_hdr_t *llc_hdr;
       unsigned int len;
       wifi_test_command_id_t  matching_cmd = wifi_test_command_id_8021x; 

       if (is_matching_cmd_in_list(matching_cmd, arg) == false) {
               return RETURN_ERR;
       }

       len = frame_len;
    
    if (IEEE80211_IS_DSTODS(frame)) {
        // the header has 4 MAC addresses because this is DS to DS
        data = (unsigned char *)frame + sizeof(struct ieee80211_frame_addr4);
        len -= sizeof(struct ieee80211_frame_addr4);
    } else {
        data = (unsigned char *)frame + sizeof(struct ieee80211_frame);
        len -= sizeof(struct ieee80211_frame);
    }
    
    if (IEEE80211_IS_QOSDATA(frame)) {
        data += sizeof(struct ieee80211_qoscntl);
        len -= sizeof(struct ieee80211_qoscntl);
    }
    
    if (frame->i_fc[1] & IEEE80211_FC1_PROTECTED) {
        data += sizeof(ccmp_hdr_t);
        len -= sizeof(ccmp_hdr_t);
    } else {
        // if this is plain text and length of the data is more than LLC check if there is an LLC header
        if (len > sizeof(llc_hdr_t)) {
            llc_hdr = (llc_hdr_t *)data;
            if ((llc_hdr->dsap == 0xaa) && (llc_hdr->ssap == 0xaa)) {
                if ((llc_hdr->type[0] == 0x88) && (llc_hdr->type[1] == 0x8e)) {
                    data += sizeof(llc_hdr_t);
                    len -= sizeof(llc_hdr_t);

                                       // There is a FCS of 4 bytes at the end, take it out
                    rc = wifi_send_test_frame((unsigned char*)frame, frame_len - 4, arg, matching_cmd, dir);
                }
            }
        }
    }
    
    return rc;
}

int parse_mgmt_frame(struct ieee80211_frame *frame, size_t len, frame_test_arg_t *arg, wifi_direction_t dir)
{
       wifi_test_command_id_t  matching_cmd; 
       memset(&matching_cmd, 0, sizeof(wifi_test_command_id_t));
       if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_PROBE_REQ) {
               matching_cmd = wifi_test_command_id_probe_req;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
               matching_cmd = wifi_test_command_id_probe_rsp;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) {
               matching_cmd = wifi_test_command_id_assoc_req;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
               matching_cmd = wifi_test_command_id_assoc_rsp;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_AUTH) {
               matching_cmd = wifi_test_command_id_auth;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_DEAUTH) {
               matching_cmd = wifi_test_command_id_deauth;
       } else if (frame->i_fc[0] == IEEE80211_FC0_SUBTYPE_ACTION) {
               matching_cmd = wifi_test_command_id_action;
       }

       if (is_matching_cmd_in_list(matching_cmd, arg) == false) {
               return RETURN_ERR;
       }


       // There is a FCS of 4 bytes at the end, take it out
       return wifi_send_test_frame((unsigned char*)frame, len - 4, arg, matching_cmd, dir);

}

int parse_ctl_frame(struct ieee80211_frame *frame, size_t len, frame_test_arg_t *arg, wifi_direction_t dir)
{
    return RETURN_ERR;
}

int parse_frame(unsigned char *data, size_t len, frame_test_arg_t *arg, wifi_direction_t *frame_dir)
{
    struct ieee80211_frame *frame;
    struct ieee80211_radiotap_header *radiotap_hdr;
    wifi_direction_t dir = wifi_direction_unknown;
    mac_address_t ap_mac, null_mac = {0x00};
    
    radiotap_hdr = (struct ieee80211_radiotap_header *)data;
    
    // go to the start of the frame
    frame = (struct ieee80211_frame *)(data + radiotap_hdr->it_len);
    len -= radiotap_hdr->it_len;
    memset(&ap_mac, 0, sizeof(mac_address_t));
       get_mac_address(arg->interface_name, ap_mac); 
    if (memcmp(arg->mac, null_mac, sizeof(mac_address_t)) != 0) {
        if (memcmp(frame->i_addr2, arg->mac, sizeof(mac_address_t)) == 0) {
            dir = wifi_direction_uplink;
                       memcpy(frame->i_addr1, ap_mac, sizeof(mac_address_t));
                       memcpy(frame->i_addr3, ap_mac, sizeof(mac_address_t));
        } else if (memcmp(frame->i_addr1, arg->mac, sizeof(mac_address_t)) == 0) {
                       if (arg->uplink_downlink == true) {
                               memcpy(frame->i_addr2, ap_mac, sizeof(mac_address_t));
               dir = wifi_direction_downlink;
                       } else {
               return RETURN_ERR;
                       }
        } else {
            return RETURN_ERR;
        }
    }

       *frame_dir = dir;
    
    if (IEEE80211_IS_MGMT(frame)) {
        return parse_mgmt_frame(frame, len, arg, dir);
        
    } else if (IEEE80211_IS_CTL(frame)) {
        return parse_ctl_frame(frame, len, arg, dir);
        
    } else if (IEEE80211_IS_DATA(frame)) {
        return parse_data_frame(frame, len, arg, dir);
        
    }

    return RETURN_ERR;
}

bool is_ng_file(char *file_name)
{
    if (strstr(file_name, ".pcapng") != NULL) {
        return true;
    }
    
    return false;
}

int test_data_from_pcap(frame_test_arg_t *arg)
{
    FILE *fp;
    struct pcap_file_header  file_hdr;
    size_t sz;
    unsigned char tmp[4096];
       wifi_direction_t dir;

    wireshark_pkthdr_t  pkt_hdr;
    unsigned int frames_parsed = 0, valid_frames_parsed = 0;

    fp = fopen(arg->cap_file_name, "r");
    if (fp == NULL) {
     return RETURN_ERR;
    }



    sz = fread(&file_hdr, 1, sizeof(struct pcap_file_header), fp);
    if (sz != sizeof(struct pcap_file_header)) {
     fclose(fp);
     return RETURN_ERR;
    }

    if (file_hdr.magic !=  0xa1b2c3d4) {
     fclose(fp);
     return RETURN_ERR;
    }


    while ((sz = fread(&pkt_hdr, 1, sizeof(wireshark_pkthdr_t), fp)) == sizeof(wireshark_pkthdr_t)) {
     memset(tmp, 0, 4096);
     sz = fread(tmp, 1, pkt_hdr.caplen, fp);
     
     if (sz == pkt_hdr.caplen) {
         if ((frames_parsed >= (arg->first_frame_num - 1)) && (frames_parsed <= (arg->last_frame_num - 1))) {
             if (parse_frame(tmp, sz, arg, &dir) == RETURN_OK) {
                 valid_frames_parsed++;
                 printf("%s:%d: Accepted frame number:%d Direction:%s\n", __func__, __LINE__, frames_parsed + 1, (dir == wifi_direction_uplink) ? "Uplink":"Downlink");
                 
             }
         }
         frames_parsed++;

         
     } else {
         fclose(fp);
         return RETURN_ERR;
     }
     
     
    }


    fclose(fp);
    return RETURN_OK;
}

int test_data_from_pcapng(frame_test_arg_t *arg)
{
    FILE *fp;
    section_header_block_t sblock;
    interface_description_block_t   iblock;
    enhanced_packet_block_t eblock;
    size_t sz;
    unsigned char tmp[4096];
    unsigned int frames_parsed = 0, valid_frames_parsed = 0;
       wifi_direction_t        dir;

    fp = fopen(arg->cap_file_name, "r");
    if (fp == NULL) {
      return RETURN_ERR;
    }


    sz = fread(&sblock, 1, sizeof(section_header_block_t), fp);
    if (sz != sizeof(section_header_block_t)) {
      fclose(fp);
      return RETURN_ERR;
    }

    if (sblock.block_type != 0x0a0d0d0a) {
      fclose(fp);
      return RETURN_ERR;
    }

    memset(tmp, 0, 4096);
    sz = fread(tmp, 1, sblock.block_len - sizeof(section_header_block_t), fp);
    if (sz != sblock.block_len - sizeof(section_header_block_t)) {
      fclose(fp);
      return RETURN_ERR;
    }

    sz = fread(&iblock, 1, sizeof(interface_description_block_t), fp);
    if (sz != sizeof(interface_description_block_t)) {
      fclose(fp);
      return RETURN_ERR;
    }

    memset(tmp, 0, 4096);
    sz = fread(tmp, 1, iblock.block_len - sizeof(interface_description_block_t), fp);
    if (sz != iblock.block_len - sizeof(interface_description_block_t)) {
      fclose(fp);
      return RETURN_ERR;
    }


    while ((sz = fread(&eblock, 1, sizeof(enhanced_packet_block_t), fp)) == sizeof(enhanced_packet_block_t)) {
        memset(tmp, 0, 4096);
        sz = fread(tmp, 1, eblock.block_len - sizeof(enhanced_packet_block_t), fp);
      
        if (sz == (eblock.block_len - sizeof(enhanced_packet_block_t))) {
            if ((frames_parsed >= (arg->first_frame_num - 1)) && (frames_parsed <= (arg->last_frame_num - 1))) {
                if (parse_frame(tmp, eblock.caplen, arg, &dir) == RETURN_OK) {
                       valid_frames_parsed++;
                       printf("%s:%d: Accepted frame number:%d Direction:%s\n", __func__, __LINE__, frames_parsed + 1, (dir == wifi_direction_uplink) ? "Uplink":"Downlink");
                  
              }
          }
          frames_parsed++;

          
      } else {
          fclose(fp);
          return RETURN_ERR;
      }
      
      
    }


    fclose(fp);
      
    return RETURN_OK;
}


int get_test_data(frame_test_arg_t *arg)
{
  
    
    return (is_ng_file(arg->cap_file_name) == false) ?
        test_data_from_pcap(arg):test_data_from_pcapng(arg);
   
    
}

int test_mgmt_frame_rx (unsigned int ap_index, mac_address_t sta_mac, const char *proto)
{
       unsigned char dpp_config[] = {
                       0x04,0x0a,0x00,0x6c,0x08,0x7f,0xdd,0x05,0x50,0x6f,0x9a,0x1a,0x01,0x60,0x00,0x04,0x10,0x5c,0x00,0x59,0xed,0x0a,
                       0x0e,0x1e,0xe5,0xab,0x1a,0x51,0x9b,0xce,0x25,0x7b,0x8b,0x96,0x30,0xee,0x01,0xe5,0x57,0x57,0x88,0xbf,0xcb,0xd9,
                       0x75,0xf1,0xc8,0x49,0xe8,0x90,0x7f,0x8f,0xe5,0xbb,0xc7,0xb8,0x9b,0x5a,0x8a,0x65,0x1a,0x9a,0x76,0x2c,0x6a,0x7f,
                       0x56,0xdd,0x04,0x5f,0x64,0xec,0x6f,0x8a,0x9a,0x40,0x56,0x1c,0x89,0x4b,0xb2,0xcf,0x8f,0x17,0x05,0xfb,0x5e,0xe0,
                       0xec,0x5f,0xd0,0x5f,0xa9,0xb9,0x4e,0x68,0xf8,0x8f,0xa7,0x79,0x48,0x03,0x51,0xd1,0xb5,0xcf,0x7c,0x8b,0x45,0xa0,0x78
       };

       unsigned char dpp_auth[] = {
                       0x04,0x09,0x50,0x6f,0x9a,0x1a,0x01,0x01,0x00,0x10,0x01,0x00,0x00,0x02,0x10,0x20,
                       0x00,0x58,0x56,0x41,0x0c,0x85,0x51,0x3d,0x50,0x42,0xa0,0x82,0xc5,0x18,0x02,0xe8,
                       0xb9,0xb1,0x51,0x53,0x96,0x68,0x5f,0x83,0xbb,0xc7,0x5d,0xdd,0x98,0x9f,0x04,0xc2,
                       0x9a,0x09,0x10,0x40,0x00,0xe4,0x5b,0xa5,0x91,0x04,0x37,0x89,0x26,0xf3,0x58,0xb3,
                       0x33,0xb5,0xc6,0x92,0x0b,0xe0,0xcc,0xe1,0x0b,0x60,0xcb,0x63,0x6e,0x24,0xcc,0x25,
                       0xb4,0x53,0x43,0xa5,0x70,0xc6,0x33,0x49,0x42,0xc4,0x76,0xe4,0x59,0x1f,0x21,0xf8,
                       0x60,0xf0,0x9c,0xca,0xca,0xd4,0xf2,0xda,0x2e,0x38,0xc9,0x74,0x74,0xb6,0x3d,0xb6,
                       0x42,0x1c,0xa9,0xea,0xcb,0x04,0x10,0x75,0x00,0xa1,0x22,0x98,0xfc,0xac,0xe5,0xac,
                       0xbb,0x29,0x91,0x7f,0x46,0x8a,0xf0,0x29,0xfd,0x9b,0x0a,0x6a,0xf0,0x1c,0x81,0x81,
                       0x61,0x57,0x46,0x37,0x4d,0x6f,0x56,0x7d,0xfa,0x47,0xdc,0xc7,0x94,0xad,0x5a,0xb5,
                       0x4b,0x53,0x8c,0xc0,0xf8,0x79,0x83,0x4c,0x9b,0xe2,0xf5,0x7a,0x40,0x54,0x16,0x60,
                       0x78,0xcc,0x0f,0x53,0x5c,0x56,0x96,0x7f,0x68,0x1c,0x81,0x04,0xc9,0x2c,0x3e,0x6c,
                       0xa3,0x07,0x87,0x3e,0x34,0x85,0x42,0xc8,0x33,0x46,0xcb,0x4a,0xc7,0xc4,0xe1,0x0c,
                       0x4e,0x6c,0x78,0x0c,0xe9,0x45,0x29,0xe3,0x0d,0xca,0xaf,0x3a,0x70,0x1b,0x1f,0x01,
                       0x0b,0xc6,0x65,0xe5,0xde,0xb4,0x50,0xfe,0x4e,0x25,0xfd,0xfc,0x70,0x0b
       };

       unsigned char anqp_query[] = {
               0x04,0x0a,0x00,0x6c,0x02,0x00,0x00,0x0e,0x00,0x00,0x01,0x0a,0x00,0x02,0x01,0x06,
               0x01,0x07,0x01,0x08,0x01,0x0c,0x01
       };

       printf("%s:%d: Start\n", __func__, __LINE__);

       if (strcmp(proto, "dpp_config") == 0) {
               mgmt_frame_received_callback(ap_index, sta_mac, dpp_config, sizeof(dpp_config), WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
       } else if (strcmp(proto, "anqp_query") == 0) {
               mgmt_frame_received_callback(ap_index, sta_mac, anqp_query, sizeof(anqp_query), WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
       } else if (strcmp(proto, "dpp_auth") == 0) {
        mgmt_frame_received_callback(ap_index, sta_mac, dpp_auth, sizeof(dpp_auth), WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
    }
    return RETURN_OK;
}
