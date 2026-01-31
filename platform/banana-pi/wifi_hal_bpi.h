/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#define WIFI_ENTRY_EXIT_DEBUG printf
#define SEC_FNAME "/etc/sec_file.txt"
#define MAX_BUF_SIZE 128
#define MAX_CMD_SIZE 1024
#define WIFI_HAL_TOTAL_NO_OF_APS 24
#define WIFI_HAL_RADIO_NUM_RADIOS 3

#define radioIndex_Check(Index) if ((Index >= WIFI_HAL_RADIO_NUM_RADIOS) || (Index < 0)) { \
         printf("%s, INCORRECT radioIndex [%d] \n", __FUNCTION__, Index); \
    return WIFI_HAL_INVALID_ARGUMENTS; \
    }

#define POINTER_CHECK(expr) if(!(expr)) { \
        printf("%s %d, Invalid parameter error!!!\n", __FUNCTION__,__LINE__); \
        return WIFI_HAL_INVALID_ARGUMENTS; \
       }

#define apIndex_Check(Index) if((Index >= WIFI_HAL_TOTAL_NO_OF_APS) || (Index < 0)) { \
        printf("%s, INCORRECT apIndex [%d] \n", __FUNCTION__, Index); \
        return WIFI_HAL_INVALID_ARGUMENTS; \
    }
