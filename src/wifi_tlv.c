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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include "wifi_hal_rdk.h"

wifi_tlv_t *get_tlv(unsigned char *buff, unsigned short attrib, unsigned short len)
{
    unsigned int total_len = 0;
    bool found = false;
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    while (total_len < len) {
        if (tlv->type == attrib) {
            found = true;
            break;
        }

        total_len += (2*sizeof(unsigned short) + tlv->length);
        tlv = (wifi_tlv_t *)((unsigned char *)tlv + 2*sizeof(unsigned short) + tlv->length);
    }

    return (found == true) ? tlv:NULL;
}


wifi_tlv_t *set_tlv(unsigned char *buff, unsigned short attrib, unsigned short len, unsigned char *val)
{
    wifi_tlv_t *tlv = (wifi_tlv_t *)buff;

    tlv->type = attrib;
    tlv->length = len;
    memcpy(tlv->value, val, len);

    return (wifi_tlv_t *)(buff + 2*sizeof(unsigned short) + len);
}
