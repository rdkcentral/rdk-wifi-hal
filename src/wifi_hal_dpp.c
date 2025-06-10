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
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
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
#include <pthread.h>
#include <sys/prctl.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <aes_siv.h>
#include <wifi_hal_rdk_framework.h>
#include <collection.h>
#include <cJSON.h>

#define printf wifi_dpp_dbg_print

extern unsigned char wifi_common_hal_test_signature[8];

typedef struct {
    const EC_GROUP *group;
    const EVP_MD *hashfcn;
    BIGNUM *x, *y, *prime;
    BIGNUM *m, *n, *l;
    EC_POINT *M, *N;
    BN_CTX *bnctx;
    EC_KEY *initiator_proto_key;
    EC_POINT     *responder_proto_pt;
    EC_POINT     *responder_connector;
    int     group_num;
    int     digestlen;
    int     noncelen;
    int     nid;
    bool    mutual;
    unsigned char initiator_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char responder_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char enrollee_nonce[SHA512_DIGEST_LENGTH/2];
    unsigned char k1[SHA512_DIGEST_LENGTH];
    unsigned char k2[SHA512_DIGEST_LENGTH];
    unsigned char ke[SHA512_DIGEST_LENGTH];
    unsigned char rauth[SHA512_DIGEST_LENGTH];
    unsigned char iauth[SHA512_DIGEST_LENGTH];
} wifi_dpp_instance_t;

typedef struct {
    BN_CTX *bnctx;
	BIGNUM *x, *y, *prime;
	EC_KEY	*key;
    EC_POINT *pt;
	char	crv[16];
} wifi_dpp_reconfig_instance_t;

typedef struct {
	unsigned char kid[SHA512_DIGEST_LENGTH];
    BN_CTX *bnctx;
	BIGNUM *x, *y, *prime;
	EC_KEY	*key;
    EC_POINT *pt;
	EC_GROUP *group;
	char	alg[16];
	unsigned char 	*bn;
} wifi_dpp_csign_instance_t;

void wifi_dpp_dbg_print(char *format, ...)
{
    char buff[2048] = {0};
    va_list list;
    static FILE *fpg = NULL;

    if ((access("/nvram/wifiDppDbg", R_OK)) != 0) {
        return;
    }

    get_formatted_time(buff);
    strcat(buff, " ");

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    if (fpg == NULL) {
        fpg = fopen("/tmp/wifiDPP", "a+");
        if (fpg == NULL) {
            return;
        } else {
            fputs(buff, fpg);
        }
    } else {
        fputs(buff, fpg);
    }

    fflush(fpg);
}

int
base64urlencode (unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;
    printf("%s:%d: HERE\n", __func__, __LINE__);
    octets = EVP_EncodeBlock(burl, data, len);
    for (i = 0; i < octets; i++) {
        if (burl[i] == '+') {
            burl[i] = '-';
        } else if (burl[i] == '/') {
            burl[i] = '_';
        }
    }
    while (burl[octets-1] == '=') {
        burl[octets-1] = '\0';
        octets--;
    }
    printf("%s:%d: HERE EXIT\n", __func__, __LINE__);
    return octets;
}

int
base64urldecode (unsigned char *data, unsigned char *burl, int len)
{
    int res, pad, i;
    unsigned char *b64, *unb64;

    pad = 0;
    switch (len%4) {
        case 2:
            pad = 2;
            break;
        case 3:
            pad = 1;
            break;
        case 0:
            break;
        default:
            return -1;
    }
    if ((b64 = (unsigned char *)malloc(len + pad)) == NULL) {
        return -1;
    }
    if ((unb64 = (unsigned char *)malloc(len)) == NULL) {
        free(b64);
        return -1;
    }
    memset(b64, '=', len + pad);
    memcpy(b64, burl, len);

    for (i = 0; i < len; i++) {
        if (b64[i] == '-') {
            b64[i] = '+';
        } else if (b64[i] == '_') {
            b64[i] = '/';
        }
    }

    res = EVP_DecodeBlock(unb64, b64, len + pad);
    memcpy(data, unb64, res - pad);
    free(b64);
    free(unb64);

    return res - pad;
}

unsigned short channel_to_frequency(unsigned int channel)
{
    unsigned short frequency = 0;

    if (channel <= 14) {
        frequency = 2412 + 5*(channel - 1);
    } else if ((channel >= 36) && (channel <= 64)) {
        frequency = 5180 + 5*(channel - 36);
    } else if ((channel >= 100) && (channel <= 140)) {
        frequency = 5500 + 5*(channel - 100);
    } else if ((channel >= 149) && (channel <= 165)) {
        frequency = 5745 + 5*(channel - 149);
    }

    return frequency;
}

/**
 * freq_to_channel - Convert frequency into channel info
 * for HT40 and VHT. DFS channels are not Supported
 * @freq: Frequency (MHz) to convert
 * Returns: channel on success, NULL on failure
*/
unsigned short freq_to_channel(unsigned int freq)
{
    unsigned int temp = 0;
    int sec_channel = -1;
    unsigned int op_class = 0;
    if(freq)
    {
        if (freq >= 2412 && freq <= 2472)
        {
            if (sec_channel == 1)
                op_class = 83;
            else if (sec_channel == -1)
                op_class = 84;
            else
                op_class = 81;

            temp = ((freq - 2407) / 5);
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

        /** In Japan, 100 MHz of spectrum from 4900 MHz to 5000 MHz 
            can be used for both indoor and outdoor connection
         */
        if (freq >= 4900 && freq < 5000) 
        {
            if ((freq - 4000) % 5)
                return 0;
            temp = (freq - 4000) / 5;
            op_class = 0; /* TODO */
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        if (freq == 2484) 
        {
            op_class = 82; /* channel 14 */
            temp = 14;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 36..48 */
        if (freq >= 5180 && freq <= 5240) 
        {
            if ((freq - 5000) % 5)
                return 0;
 
            if (sec_channel == 1)
                op_class = 116;
            else if (sec_channel == -1)
                op_class = 117;
            else 
                op_class = 115;
 
            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 52..64 */
        if (freq >= 5260 && freq <= 5320) 
        {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 119;
            else if (sec_channel == -1)
                op_class = 120;
            else 
                op_class = 118;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 100..140 */
        if (freq >= 5000 && freq <= 5700) 
        {
            if (sec_channel == 1)
                op_class = 122;
            else if (sec_channel == -1)
                op_class = 123;
            else 
                op_class = 121;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 149..169 */
        if (freq >= 5745 && freq <= 5845) 
        {
            if (sec_channel == 1)
                op_class = 126;
            else if (sec_channel == -1)
                op_class = 127;
            else if (freq <= 5805)
                op_class = 124;
            else
                op_class = 125;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(freq)) {
            if (freq == 5935) {
                temp = 2;
                op_class = 131;
            } else {
                temp = (freq - 5950) % 5;
                op_class = 131 + center_idx_to_bw_6ghz((freq - 5950) / 5);
            }
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
#endif
    }
    printf("error: No case for given Freq\n");
    return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void
ECDSA_SIG_get0(ECDSA_SIG *sig, const BIGNUM **r, const BIGNUM **s)
{
    *r = sig->r;
    *s = sig->s;
    return;
}

void
ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    sig->r = r;
    sig->s = s;
    return;
}
#endif

int dpp_build_csign_object(wifi_device_dpp_context_t *dpp_ctx, cJSON* csign)
{
	unsigned int b64len, bnlen, offset;
	unsigned char b64x[SHA512_DIGEST_LENGTH];
	unsigned char b64y[SHA512_DIGEST_LENGTH];
	unsigned char *bn;
	wifi_dpp_csign_instance_t *sign;
	wifi_dpp_instance_t *instance = dpp_ctx->session_data.instance;
	wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
	
	sign = obj->cSignInstance;

	if (sign == NULL) {
		printf("%s:%d sign does not exist\n", __func__, __LINE__);
		return -1;
	}

    bnlen = BN_num_bytes(instance->prime);
	printf("%s:%d: big number len:%d\n", __func__, __LINE__, bnlen);
    bn = (unsigned char *)malloc(bnlen);
    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(sign->x);
    BN_bn2bin(sign->x, bn + offset);

    b64len = base64urlencode(b64x, bn, bnlen);
    b64x[b64len] = '\0';

    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(sign->y);
    BN_bn2bin(sign->y, bn + offset);
    b64len = base64urlencode(b64y, bn, bnlen);
    b64y[b64len] = '\0';

	free(bn);
			
	cJSON_AddStringToObject(csign, "kty", "EC");
	cJSON_AddStringToObject(csign, "crv", "P-256");
	cJSON_AddStringToObject(csign, "x", b64x);
	cJSON_AddStringToObject(csign, "y", b64y);
	cJSON_AddStringToObject(csign, "kid", sign->kid);

	return 0;

}

EC_POINT *dpp_build_point_from_connector_string(wifi_device_dpp_context_t *ctx, const char *connector)
{
	cJSON *connector_json;
	const cJSON *netaccess_json;
	const cJSON *x_json, *y_json;
	unsigned char x[SHA512_DIGEST_LENGTH], y[SHA512_DIGEST_LENGTH]; 
	char connector_body[1024], connector_encoded[1024], *ptr;
	int len;
	wifi_dpp_instance_t *instance = ctx->session_data.instance;

	printf("%s:%d: Enter\n", __func__, __LINE__);

	if ((ptr = strchr(connector, '.')) == NULL) {
		printf("%s:%d: Wrong connector format\n", __func__, __LINE__);
		return NULL;	
	}

	ptr++;
	strcpy(connector_encoded, ptr);
	if ((ptr = strchr(connector_encoded, '.')) == NULL) {
		printf("%s:%d: Wrong connector format\n", __func__, __LINE__);
		return NULL;	
	}

	*ptr = 0;
	printf("%s:%d: enocded connector:%s\n", __func__, __LINE__, connector_encoded);

	len = base64urldecode((unsigned char *)connector_body, connector_encoded, strlen(connector_encoded));
    if (len == -1) {
        printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
        return NULL;
    }

	connector_json = cJSON_Parse(connector_body);
	if (connector_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		return NULL;
	}

	netaccess_json = cJSON_GetObjectItemCaseSensitive(connector_json, "netAccessKey");
	if (netaccess_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}	
	
	x_json = cJSON_GetObjectItemCaseSensitive(netaccess_json, "x");
	if (x_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}

	y_json = cJSON_GetObjectItemCaseSensitive(netaccess_json, "y");
	if (y_json == NULL) {
		printf("%s:%d: Could not parse connector string into json object\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
		return NULL;
	}

	printf("%s:%d:X:%s\n", __func__, __LINE__, x_json->valuestring);
	printf("%s:%d:Y:%s\n", __func__, __LINE__, y_json->valuestring);

	len = base64urldecode(x, x_json->valuestring, strlen(x_json->valuestring));
	if (len == -1) {
		printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
        return NULL;
	}
	printf("%s:%d: base64 decoded x\n", __func__, __LINE__);

	BN_bin2bn(x, len, instance->x);
	printf("%s:%d: Built big num x\n", __func__, __LINE__);

	len = base64urldecode(y, y_json->valuestring, strlen(y_json->valuestring));
	if (len == -1) {
		printf("%s:%d: Failed in base64 decode\n", __func__, __LINE__);
		cJSON_Delete(connector_json);
        return NULL;
	}
	printf("%s:%d: base64 decoded y\n", __func__, __LINE__);

	BN_bin2bn(y, len, instance->y);
	printf("%s:%d: Built big num y\n", __func__, __LINE__);

	EC_POINT_set_affine_coordinates_GFp(instance->group, instance->responder_connector, instance->x, instance->y, instance->bnctx);

	printf("%s:%d: point built\n", __func__, __LINE__);

       cJSON_Delete(connector_json);

	return instance->responder_connector;
}


int dpp_build_connector(wifi_device_dpp_context_t *dpp_ctx, char* connector, bool responder)
{
#define BIGGEST_POSSIBLE_SIGNATURE      140
    wifi_dpp_reconfig_instance_t *recfg;
    wifi_dpp_csign_instance_t *sign;
    unsigned int bnlen, b64len, len, conn_len = 0, primelen = 0, siglen = 0, offset = 0;
    char buff[1024];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char sig[BIGGEST_POSSIBLE_SIGNATURE];
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX  ctx;
#else
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
#endif
    BIGNUM *x, *y;
    BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG *ecsig;
    unsigned char b64x[SHA512_DIGEST_LENGTH];
    unsigned char b64y[SHA512_DIGEST_LENGTH];
    unsigned char *bn;
    wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
    wifi_dpp_instance_t *instance = dpp_ctx->session_data.instance;

    printf("%s:%d: Enter\n", __func__, __LINE__);

    recfg = (wifi_dpp_reconfig_instance_t *)obj->reconfigCtx;   
    sign = (wifi_dpp_csign_instance_t *)obj->cSignInstance;
    printf("%s:%d: recfg:%p sign:%p instance:%p\n", __func__, __LINE__, recfg, sign, instance);

    if ((sign == NULL) || recfg == NULL) {
        printf("%s:%d: reconfig context or csign instance does not exist, sign:%p recfg:%p\n", __func__, __LINE__, sign, recfg);
        return -1;
    }

    bnlen = BN_num_bytes(instance->prime);
    printf("%s:%d: big number len:%d\n", __func__, __LINE__, bnlen);
    if (responder == false) {
        x = recfg->x;
        y = recfg->y;
    } else {
        EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, instance->y, instance->bnctx);
        x = instance->x;
        y = instance->y;
    }

    printf("%s:%d: Here\n", __func__, __LINE__);
    bn = (unsigned char *)malloc(bnlen);
    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(x);
    BN_bn2bin(x, bn + offset);

    b64len = base64urlencode(b64x, bn, bnlen);
    b64x[b64len] = '\0';

    memset(bn, 0, bnlen);
    offset = bnlen - BN_num_bytes(y);
    BN_bn2bin(y, bn + offset);
    b64len = base64urlencode(b64y, bn, bnlen);
    b64y[b64len] = '\0';

    free(bn);
    printf("%s:%d: Here\n", __func__, __LINE__);

    len = snprintf(buff, sizeof(buff), "{\"typ\":\"dppCon\",\"kid\":\"%s\",\"alg\":\"%s\"}",
            sign->kid, sign->alg);


    conn_len = base64urlencode(connector, (unsigned char *)buff, len);
    printf("%s:%d header:%s\n", __func__, __LINE__, buff);
    connector[conn_len++] = '.';

    len = snprintf(buff, sizeof(buff),
            "{\"groups\":[{\"groupId\":\"interop\",\"netRole\":\"%s\"}],"
            "\"netAccessKey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"%s\",\"y\":\"%s\"},"
            "\"expiry\":\"2020-12-12T01:01:01\"}",
            (responder == false)?"configurator":"sta", b64x, b64y);

    conn_len += base64urlencode(connector + conn_len, buff, len);
    printf("%s:%d header and body:%s\n", __func__, __LINE__, buff);

    switch (EC_GROUP_get_curve_name(sign->group)) {
        case NID_X9_62_prime256v1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha256());
#else
            EVP_DigestInit(ctx, EVP_sha256());
#endif
            primelen = 32;
            break;
        case NID_secp384r1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha384());
#else
            EVP_DigestInit(ctx, EVP_sha384());
#endif
            primelen = 48;
            break;
        case NID_secp521r1:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_DigestInit(&ctx, EVP_sha512());
#else
            EVP_DigestInit(ctx, EVP_sha512());
#endif
            primelen = 66;
            break;
        default:
            return -1;

    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ctx, connector, conn_len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestUpdate(ctx, connector, conn_len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    if ((ecsig = ECDSA_do_sign_ex(digest, mdlen, NULL, NULL, sign->key)) == NULL) {
        return -1;
    }
    ECDSA_SIG_get0(ecsig, (const BIGNUM **)&r, (const BIGNUM **)&s);

    memset(sig, 0, BIGGEST_POSSIBLE_SIGNATURE);
    offset = primelen - BN_num_bytes(r);
    BN_bn2bin(r, sig + offset);
    offset = primelen - BN_num_bytes(s);
    BN_bn2bin(s, sig + primelen + offset);
    siglen = primelen * 2;

    connector[conn_len++] = '.';
    conn_len += base64urlencode(connector + conn_len, sig, siglen);
    printf("%s:%d connector:%s\n", __func__, __LINE__, connector);

    return conn_len;
}

void dpp_build_config(wifi_device_dpp_context_t *ctx, char* str)
{
 	char *out;
	char reconfig_connector[1024];
	wifi_dpp_configuration_object_t *obj = &ctx->config;

	/*No Array, Root only*/
    cJSON *root;
	/*Objects: discovery, cred, csign*/
	cJSON *discovery, *cred, *csign;


	memset(reconfig_connector, 0, 1024);
    printf("%s:%d: HERE ctx->enrollee_version = %d\n", __func__, __LINE__, ctx->enrollee_version);
    if(ctx->enrollee_version == 2)
        dpp_build_connector(ctx, reconfig_connector, true);

    /* check for enrollee_version and keyManagement */
    /* for enrollee_version=1, keyManagement must be *_MGMT_PSK*/
    if((ctx->enrollee_version == 1) && (obj->credentials.keyManagement != WIFI_DPP_KEY_MGMT_PSK)) {
        obj->credentials.keyManagement = WIFI_DPP_KEY_MGMT_PSK;
        printf("mismatch between enrollee_version & keyManagement, hence Now key  = %d\n", obj->credentials.keyManagement);
    }
    root  = cJSON_CreateObject();

	switch(obj->wifiTech)
	{
		case WIFI_DPP_TECH_INFRA:
		cJSON_AddItemToObject(root, "wi-fi_tech", cJSON_CreateString("infra"));
		break;
		default:
		break;
	}

	/*discovery: ssid*/
	cJSON_AddItemToObject(root, "discovery", discovery = cJSON_CreateObject());
	if(obj->discovery)
		cJSON_AddStringToObject(discovery, "ssid", obj->discovery);

	/*cred*/
	cJSON_AddItemToObject(root, "cred", cred = cJSON_CreateObject());

	switch(obj->credentials.keyManagement)
	{
		case WIFI_DPP_KEY_MGMT_PSK:
			cJSON_AddStringToObject(cred, "akm", "psk");
			cJSON_AddStringToObject(cred, "pass", obj->credentials.creds.passPhrase);
			break;

		case WIFI_DPP_KEY_MGMT_DPP:
			cJSON_AddStringToObject(cred, "akm", "dpp");
        	break;

		case WIFI_DPP_KEY_MGMT_SAE:
			cJSON_AddStringToObject(cred, "akm", "sae");
        	break;

		case WIFI_DPP_KEY_MGMT_PSKSAE:
			break;

		case WIFI_DPP_KEY_MGMT_DPPPSKSAE:
			cJSON_AddStringToObject(cred, "akm", "dpp+psk+sae");
			cJSON_AddStringToObject(cred, "pass", obj->credentials.creds.passPhrase);
			/*signedConnector*/
			cJSON_AddStringToObject(cred, "signedConnector", reconfig_connector);
			/*csign*/
			csign = cJSON_CreateObject();	
			dpp_build_csign_object(ctx, csign);

			cJSON_AddItemToObject(cred, "csign", csign);
			break;

		default:
			break;
	}

	out = cJSON_Print(root);
        if (out)
        {
            printf("%s\n",out);
            /*let input string have json */
            strcpy(str, out);
            free(out);
        }
	
	return;
}

void print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}

void
print_bignum (BIGNUM *bn)
{
    unsigned char *buf;
    int len;

    len = BN_num_bytes(bn);
    if ((buf = (unsigned char *)malloc(len)) == NULL) {
        printf("Could not print bignum\n");
        return;
    }
    BN_bn2bin(bn, buf);
    print_hex_dump(len, buf);
    free(buf);
}

void
print_ec_point (const EC_GROUP *group, BN_CTX *bnctx, EC_POINT *point)
{
    BIGNUM *x = NULL, *y = NULL;

    if ((x = BN_new()) == NULL) {
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }

     if ((y = BN_new()) == NULL) {
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;
    }
        
    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bnctx) == 0) {
        BN_free(y);
        BN_free(x);
        printf("%s:%d:Could not print ec_point\n", __func__, __LINE__);
        return;

    }

    printf("POINT.x:\n");
    print_bignum(x);
    printf("POINT.y:\n");
    print_bignum(y);

    BN_free(y);
    BN_free(x);
}

int
hkdf (const EVP_MD *h, int skip,
      unsigned char *ikm, int ikmlen,
      unsigned char *salt, int saltlen,
      unsigned char *info, int infolen,
      unsigned char *okm, int okmlen)
{
    unsigned char *prk, *tweak, ctr, *digest;
    int len;
    unsigned int digestlen, prklen, tweaklen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
#endif

    digestlen = prklen = EVP_MD_size(h);
    if ((digest = (unsigned char *)malloc(digestlen)) == NULL) {
        perror("malloc");
        return 0;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_init(&ctx);
#else
    HMAC_CTX_reset(ctx);
#endif
    
    if (!skip) {
        /*
         * if !skip then do HKDF-extract
         */
        if ((prk = (unsigned char *)malloc(digestlen)) == NULL) {
            free(digest);
            perror("malloc");
            return 0;
        }
        /*
         * if there's no salt then use all zeros
         */
        if (!salt || (saltlen == 0)) {
            if ((tweak = (unsigned char *)malloc(digestlen)) == NULL) {
                free(digest);
                free(prk);
                perror("malloc");
                return 0;
            }
            memset(tweak, 0, digestlen);
            tweaklen = saltlen;
        } else {
            tweak = salt;
            tweaklen = saltlen;
        }
        (void)HMAC(h, tweak, tweaklen, ikm, ikmlen, prk, &prklen);
        if (!salt || (saltlen == 0)) {
            free(tweak);
        }
    } else {
        prk = ikm;
        prklen = ikmlen;
    }
    memset(digest, 0, digestlen);
    digestlen = 0;
    ctr = 0;
    len = 0;
    while (len < okmlen) {
        /*
         * T(0) = all zeros
         * T(n) = HMAC(prk, T(n-1) | info | counter)
         * okm = T(0) | ... | T(n)
         */
        ctr++;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Init_ex(&ctx, prk, prklen, h, NULL);
        HMAC_Update(&ctx, digest, digestlen);
#else
        HMAC_Init_ex(ctx, prk, prklen, h, NULL);
        HMAC_Update(ctx, digest, digestlen);
#endif
        if (info && (infolen != 0)) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            HMAC_Update(&ctx, info, infolen);
#else
            HMAC_Update(ctx, info, infolen);
#endif
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        HMAC_Update(&ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(&ctx, digest, &digestlen);
#else
        HMAC_Update(ctx, &ctr, sizeof(unsigned char));
        HMAC_Final(ctx, digest, &digestlen);
#endif
        if ((len + digestlen) > okmlen) {
            memcpy(okm + len, digest, okmlen - len);
        } else {
            memcpy(okm + len, digest, digestlen);
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_cleanup(&ctx);
#else
        HMAC_CTX_free(ctx);
#endif
        len += digestlen;
    }
    if (!skip) {
        free(prk);
    }
    free(digest);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return okmlen;
}

static int
compute_key_hash (EC_KEY *key, unsigned char *digest)
{
    int asn1len;
    BIO *bio;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ctx;
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#endif
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return -1;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_init(&ctx);
#else
    EVP_MD_CTX_reset(ctx);
#endif
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, asn1, asn1len);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, asn1, asn1len);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif

    BIO_free(bio);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX_cleanup(&ctx);
#else
    EVP_MD_CTX_free(ctx);
#endif
    return mdlen;
}

int
get_config_frame_wrapped_data(unsigned char *ptr, unsigned int attrib_len, wifi_dpp_instance_t *instance, unsigned char *plain, unsigned int len)
{
    siv_ctx ctx;
    wifi_tlv_t *tlv;
    int decrypted_len;

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    if ((tlv = get_tlv(ptr, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        printf("%s:%d: Could not find attribute in buffer\n", __func__, __LINE__);
        return -1;
    }


    decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, tlv->value, 0);
	if (decrypted_len < 0) {
		return -1;
	}

    printf("%s:%d: Decrypted length:%d\n", __func__, __LINE__, decrypted_len);


    return tlv->length - AES_BLOCK_SIZE;
}

int
get_auth_frame_wrapped_data(wifi_dppPublicActionFrameBody_t *frame, unsigned int attrib_len, wifi_dpp_instance_t *instance, unsigned char *plain, unsigned int len, bool reconfig)
{
    siv_ctx ctx;
    wifi_tlv_t *tlv;
    unsigned int non_wrapped_len;;
	int decrypted_len;

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, (reconfig == false) ? instance->k2:instance->ke, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        printf("%s:%d: Could not find attribute in buffer\n", __func__, __LINE__);
        return -1;
    }
    printf("%s:%d: Key:\n", __func__, __LINE__);
    print_hex_dump(SHA512_DIGEST_LENGTH, (reconfig == false) ? instance->k2:instance->ke);
    printf("%s:%d: Cipher Text Length:%d\n", __func__, __LINE__, tlv->length);
    printf("%s:%d: Cipher Text:\n", __func__, __LINE__);
    print_hex_dump(tlv->length, tlv->value);

    non_wrapped_len = (unsigned char *)tlv - frame->attrib;
    printf("%s:%d: Non wrapped length:%d, must match with %d attrib_len:%d\n", __func__, __LINE__, 
        non_wrapped_len, attrib_len - tlv->length, attrib_len);

    decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, tlv->value, 2,
                        frame, sizeof(wifi_dppPublicActionFrameBody_t),
                        frame->attrib, non_wrapped_len);
        
    printf("%s:%d: Decrypted length:%d\n", __func__, __LINE__, decrypted_len);


    return (decrypted_len == -1) ? -1:tlv->length - AES_BLOCK_SIZE;
}

int
set_config_frame_wrapped_data(unsigned char *ptr, unsigned int non_wrapped_len, wifi_dpp_instance_t *instance, wifi_device_dpp_context_t *dpp_ctx)
{
    siv_ctx ctx;
    unsigned char plain[2048];
    wifi_tlv_t *tlv;
    unsigned int wrapped_len = 0;
    wifi_tlv_t *wrapped_tlv;
	char json[1024];

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    tlv = (wifi_tlv_t *)plain;

    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_enrollee_nonce, instance->noncelen, instance->enrollee_nonce);
    wrapped_len += (4 + instance->noncelen);

    if (NULL != dpp_ctx) {
	    memset(json, 0, 1024);
	    dpp_build_config(dpp_ctx, json);
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_config_object, strlen(json), json);
        wrapped_len += (4 + strlen(json));
    }

    wrapped_tlv = (wifi_tlv_t *)(ptr + non_wrapped_len);
    wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;
    wrapped_tlv->length = wrapped_len + AES_BLOCK_SIZE;

    siv_encrypt(&ctx, plain, &wrapped_tlv->value[AES_BLOCK_SIZE], wrapped_len, wrapped_tlv->value, 1,
                    ptr, non_wrapped_len);

    return wrapped_len + AES_BLOCK_SIZE;
}

int
set_auth_frame_wrapped_data(wifi_dppPublicActionFrameBody_t *frame, unsigned int non_wrapped_len, wifi_dpp_instance_t *instance, bool auth_init)
{   
    siv_ctx ctx;
    unsigned char plain[512];
    wifi_tlv_t *tlv;
    unsigned char caps = 2;
    unsigned int wrapped_len = 0;
    wifi_tlv_t *wrapped_tlv;
    unsigned char *key;

    key = (auth_init == true) ? instance->k1:instance->ke;
    
    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }
    

    tlv = (wifi_tlv_t *)plain;
   
    if (auth_init == true) { 
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
        wrapped_len += (4 + instance->noncelen);
    
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_cap, 1, &caps);
        wrapped_len += 5;
    } else {
        tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_auth_tag, instance->digestlen, instance->iauth);
        wrapped_len += (4 + instance->digestlen);

    }

    wrapped_tlv = (wifi_tlv_t *)(frame->attrib + non_wrapped_len);
    wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;
    wrapped_tlv->length = wrapped_len + AES_BLOCK_SIZE;
    
    siv_encrypt(&ctx, plain, &wrapped_tlv->value[AES_BLOCK_SIZE], wrapped_len, wrapped_tlv->value, 2,
                    frame, sizeof(wifi_dppPublicActionFrameBody_t), 
                    frame->attrib, non_wrapped_len);
    
    //printf("%s:%d: Plain text:\n", __func__, __LINE__);
    //print_hex_dump(noncelen, plain);
    
    return wrapped_len + AES_BLOCK_SIZE;
}

int compute_reconfig_encryption_key(wifi_dpp_instance_t *instance)
{
    unsigned char m[2048];
    unsigned int primelen, offset;
    unsigned char salt[SHA512_DIGEST_LENGTH];

	EC_POINT_get_affine_coordinates_GFp(instance->group, instance->M, instance->m, instance->n, instance->bnctx);
    primelen = BN_num_bytes(instance->prime);
    
    memset(m, 0, primelen);
    offset = primelen - BN_num_bytes(instance->m);
    BN_bn2bin(instance->m, m + offset);

    memcpy(salt, instance->initiator_nonce, instance->noncelen);
    
    hkdf(instance->hashfcn, 0, m, primelen, salt, instance->noncelen,
             (unsigned char *)"dpp reconfig key", strlen("dpp reconfig key"), instance->ke, instance->digestlen);

    printf("Encryption Key: \n");
    print_hex_dump(instance->digestlen, instance->ke);

	return 0;
}

int compute_encryption_key(wifi_dpp_instance_t *instance)
{
    unsigned int offset, primelen, bignums;
    unsigned char ikm[1024], *ptr;
    unsigned char salt[SHA512_DIGEST_LENGTH];

    memset(ikm, 0, 1024);
    primelen = BN_num_bytes(instance->prime);

    ptr = ikm;
    offset = primelen - BN_num_bytes(instance->m);
    BN_bn2bin(instance->m, ptr + offset);

    ptr += primelen;
    offset = primelen - BN_num_bytes(instance->n);
    BN_bn2bin(instance->n, ptr + offset);

    ptr += primelen;
    if (instance->mutual == true) {
        bignums = 3;
        offset = primelen - BN_num_bytes(instance->l);
        BN_bn2bin(instance->l, ptr + offset);
    } else {
        bignums = 2;
    }
 
    memcpy(salt, instance->initiator_nonce, instance->noncelen);
    memcpy(&salt[instance->noncelen], instance->responder_nonce, instance->noncelen);
    
    hkdf(instance->hashfcn, 0, ikm, bignums*primelen, salt, 2*instance->noncelen,
             (unsigned char *)"DPP Key", strlen("DPP Key"), instance->ke, instance->digestlen);

    printf("Encryption Key: ");
    print_hex_dump(instance->digestlen, instance->ke);

    return 0;
}

int    compute_intermediate_key(wifi_dpp_instance_t *instance, bool first)
{
    unsigned int primelen, offset, keylen;
    unsigned char m[2048];

	BIGNUM *x = (first == true)?instance->m:instance->n;
	const char *info = (first == true)?"first intermediate key":"second intermediate key";
	unsigned char *key = (first == true)?instance->k1:instance->k2;
    
    primelen = BN_num_bytes(instance->prime);
    
    memset(m, 0, primelen);
    offset = primelen - BN_num_bytes(x);
    BN_bn2bin(x, m + offset);
    if ((keylen = hkdf(instance->hashfcn, 0, m, primelen, NULL, 0, 
             (unsigned char *)info, strlen(info),
             key, instance->digestlen)) == 0) {
        printf("%s:%d: Failed in hashing\n", __func__, __LINE__);
        return -1;
    }

    printf("Key:\n");
    print_hex_dump(instance->digestlen, key);
    
    return 0;
}

int create_auth_tags    (wifi_dpp_instance_t *instance, char *iPubKeyInfoB64, char *rPubKeyInfoB64)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX ictx, rctx;
#else
    EVP_MD_CTX *ictx = EVP_MD_CTX_new();
    EVP_MD_CTX *rctx = EVP_MD_CTX_new();
#endif
    unsigned char final;
    unsigned int offset = 0, primelen = 0, mdlen = 0;
    EC_POINT *pub, *rpt;
    unsigned char keyasn1[1024];
    unsigned char tag[SHA512_DIGEST_LENGTH];
    const unsigned char *key;
    unsigned int asn1len;
    EC_KEY *responder_boot_key, *initiator_boot_key;

    //I-auth’ = H(R-nonce | I-nonce | PR.x | PI.x | BR.x | [ BI.x | ] 1) 
    //R-auth’ = H(I-nonce | R-nonce | PI.x | PR.x | [ BI.x | ] BR.x | 0) 

    memset(instance->rauth, 0, SHA512_DIGEST_LENGTH);
    memset(instance->iauth, 0, SHA512_DIGEST_LENGTH);
    memset(tag, 0, SHA512_DIGEST_LENGTH);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestInit(&ictx, instance->hashfcn);
    EVP_DigestInit(&rctx, instance->hashfcn);

    // nonces for I-auth
    EVP_DigestUpdate(&ictx, instance->responder_nonce, instance->noncelen);
    EVP_DigestUpdate(&ictx, instance->initiator_nonce, instance->noncelen);
     
    // nonces for R-auth
    EVP_DigestUpdate(&rctx, instance->initiator_nonce, instance->noncelen);
    EVP_DigestUpdate(&rctx, instance->responder_nonce, instance->noncelen);
#else
    EVP_DigestInit(ictx, instance->hashfcn);
    EVP_DigestInit(rctx, instance->hashfcn);

    // nonces for I-auth
    EVP_DigestUpdate(ictx, instance->responder_nonce, instance->noncelen);
    EVP_DigestUpdate(ictx, instance->initiator_nonce, instance->noncelen);
     
    // nonces for R-auth
    EVP_DigestUpdate(rctx, instance->initiator_nonce, instance->noncelen);
    EVP_DigestUpdate(rctx, instance->responder_nonce, instance->noncelen);
#endif

    // protocol keys for I-auth
    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
        
    memset(tag, 0, primelen);
    primelen = BN_num_bytes(instance->prime);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    if ((pub = (EC_POINT*)EC_KEY_get0_public_key(instance->initiator_proto_key)) == NULL) {
        printf("%s:%d: Failed to get public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
        
    }
        
    if (EC_POINT_get_affine_coordinates_GFp(instance->group, pub, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
     }
        
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    // protocol keys for R-auth
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->responder_proto_pt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }
        
    memset(tag, 0, primelen);
    primelen = BN_num_bytes(instance->prime);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    // boot keys for I-auth
    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)rPubKeyInfoB64, strlen(rPubKeyInfoB64))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    if ((rpt = (EC_POINT*)EC_KEY_get0_public_key(responder_boot_key)) == NULL) { 
        printf("%s:%d: Failed to get responder boot key point\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, rpt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;

    }
    
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, tag, primelen);
#else
    EVP_DigestUpdate(ictx, tag, primelen);
#endif

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)iPubKeyInfoB64, strlen(iPubKeyInfoB64))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);

    if (instance->mutual == true) {
        memset(tag, 0, primelen);
        offset = primelen - BN_num_bytes(instance->x);
        BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_DigestUpdate(&ictx, tag, primelen);
#else
        EVP_DigestUpdate(ictx, tag, primelen);
#endif
    }

    // boot keys for R-auth
    memset(tag, 0, primelen);
    offset = primelen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, tag, primelen);
#else
    EVP_DigestUpdate(rctx, tag, primelen);
#endif

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, rpt, instance->x, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Failed to get affine coordinates\n", __func__, __LINE__);
#if OPENSSL_VERSION_NUMBER > 0x10100000L
	EVP_MD_CTX_free(ictx);
	EVP_MD_CTX_free(rctx);
#endif
        return RETURN_ERR;

    }
   
    if (instance->mutual == true) { 
        memset(tag, 0, primelen);
        offset = primelen - BN_num_bytes(instance->x);
        BN_bn2bin(instance->x, tag + offset);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_DigestUpdate(&rctx, tag, primelen);
#else
        EVP_DigestUpdate(rctx, tag, primelen);
#endif
    }


    // 1 for I-auth
    final = 1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&ictx, &final, 1);
#else
    EVP_DigestUpdate(ictx, &final, 1);
#endif
    mdlen = instance->digestlen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestFinal(&ictx, instance->iauth, &mdlen);
#else
    EVP_DigestFinal(ictx, instance->iauth, &mdlen);
#endif

    printf("%s:%d: I-auth:\n", __func__, __LINE__);
    print_hex_dump(mdlen, instance->iauth);

    // 0 for R-auth
    final = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestUpdate(&rctx, &final, 1);
#else
    EVP_DigestUpdate(rctx, &final, 1);
#endif
    mdlen = instance->digestlen;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_DigestFinal(&rctx, instance->rauth, &mdlen);
#else
    EVP_DigestFinal(rctx, instance->rauth, &mdlen);
#endif

    printf("%s:%d: R-auth:\n", __func__, __LINE__);
    print_hex_dump(mdlen, instance->rauth);

#if OPENSSL_VERSION_NUMBER > 0x10100000L    
    EVP_MD_CTX_free(ictx);
    EVP_MD_CTX_free(rctx);
#endif
    
    return RETURN_OK;
}

void delete_dpp_session_instance(wifi_device_dpp_context_t *ctx)
{
    wifi_dpp_session_data_t    *data = NULL;
    wifi_dpp_instance_t *instance;

    wifi_dpp_dbg_print("%s:%d Here\n", __func__, __LINE__);

    data = &ctx->session_data;
	instance = data->instance;

    if (instance->N != NULL) {
        EC_POINT_free(instance->N);
    }

    if (instance->M != NULL) {
        EC_POINT_free(instance->M);
    }
    
    if (instance->responder_proto_pt != NULL) {
        EC_POINT_clear_free(instance->responder_proto_pt);
    }

    if (data->session == wifi_dpp_session_type_reconfig) {
        if (instance->responder_connector != NULL) {
            EC_POINT_free(instance->responder_connector);
        }
    }

    if (instance->initiator_proto_key != NULL) {
        EC_KEY_free(instance->initiator_proto_key);
    }

    if (instance->bnctx != NULL) {
        BN_CTX_free(instance->bnctx);
    }

    if (instance->prime != NULL) {
        BN_free(instance->prime);
    }
    
    if (instance->n != NULL) {
        BN_free(instance->n);
    }
    
    if (instance->m != NULL) {
        BN_free(instance->m);
    }
    
    if (instance->y != NULL) {
        BN_free(instance->y);
    }
    
    if (instance->x != NULL) {
        BN_free(instance->x);
    }

	free(instance);
	data->instance = NULL;
}

int delete_dpp_reconfig_context(unsigned int ap_index, wifi_dpp_reconfig_instance_t *instance)
{
	if (instance->bnctx != NULL) {
		BN_CTX_free(instance->bnctx);
	}

	if (instance->key != NULL) {
		EC_KEY_free(instance->key);
	}

	if (instance->x != NULL) {
		BN_free(instance->x);
	}

	if (instance->y != NULL) {
		BN_free(instance->y);
	}

	if (instance->prime != NULL) {
		BN_free(instance->prime);
	}

	if (instance->pt != NULL) {
		EC_POINT_free(instance->pt);
	}
	
	if (instance != NULL) {
		free(instance);
	}

	return RETURN_OK;
}

int wifi_dppCreateReconfigContext(unsigned int ap_index, char *net_access_key, wifi_dpp_reconfig_instance_t **inst, char *pub)
{
	wifi_dpp_reconfig_instance_t *instance;
    unsigned char keyasn1[1024];
    unsigned int asn1len, pub_key_len;
    const unsigned char *key;
	EC_GROUP *group;
	unsigned char *pub_key;

    printf("%s:%d Here\n", __func__, __LINE__);

	if (inst == NULL) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
		return RETURN_ERR;
	}
		
	instance = *inst;

	if (instance != NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
		instance = NULL;
	}

    printf("%s:%d Here\n", __func__, __LINE__);
	instance = (wifi_dpp_reconfig_instance_t *)malloc(sizeof(wifi_dpp_reconfig_instance_t));
	memset(instance, 0, sizeof(wifi_dpp_reconfig_instance_t));
	*inst = instance;

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->bnctx = BN_CTX_new();

	// netaccess key

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)net_access_key, strlen(net_access_key))) < 0) { 
		delete_dpp_reconfig_context(ap_index, instance);
        printf("%s:%d Failed to decode base 64 private access key\n", __func__, __LINE__);
        return RETURN_ERR;
    }    

    key = keyasn1;

    printf("%s:%d Here\n", __func__, __LINE__);

	if ((instance->key = d2i_ECPrivateKey(NULL,  &key, asn1len)) == NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
        printf("%s:%d Failed to create EC key\n", __func__, __LINE__);
        return RETURN_ERR;

	}

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->pt = (EC_POINT*)EC_KEY_get0_public_key(instance->key);
    if (instance->pt == NULL) {
		delete_dpp_reconfig_context(ap_index, instance);
        printf("%s:%d Could not get access public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

	pub_key_len = i2d_EC_PUBKEY(instance->key, &pub_key);
    printf("%s:%d Here public key length:%d\n", __func__, __LINE__, pub_key_len);
	EVP_EncodeBlock(pub, pub_key, pub_key_len);

    instance->x = BN_new();
    instance->y = BN_new();
	instance->prime = BN_new();

	group = (EC_GROUP*)EC_KEY_get0_group(instance->key);

	if (!EC_GROUP_get_curve_GFp(group, instance->prime, NULL, NULL, instance->bnctx)) {
		delete_dpp_reconfig_context(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(instance->key), instance->pt, instance->x, 
				instance->y, instance->bnctx)) {
		delete_dpp_reconfig_context(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

	switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(instance->key))) {
        case NID_X9_62_prime256v1:
			strcpy(instance->crv, "P-256");
            break;
        case NID_secp384r1:
			strcpy(instance->crv, "P-384");
            break;
        case NID_secp521r1:
			strcpy(instance->crv, "P-521");
            break;
        default:
        	return RETURN_ERR;
    }

	return RETURN_OK;
	
}

int delete_dpp_csign_instance(unsigned int ap_index, wifi_dpp_csign_instance_t *instance)
{
	if (instance->bnctx != NULL) {
		BN_CTX_free(instance->bnctx);
	}

	if (instance->key != NULL) {
		EC_KEY_free(instance->key);
	}

	if (instance->x != NULL) {
		BN_free(instance->x);
	}

	if (instance->y != NULL) {
		BN_free(instance->y);
	}

	if (instance->prime != NULL) {
		BN_free(instance->prime);
	}

	if (instance->pt != NULL) {
		EC_POINT_free(instance->pt);
	}

	if (instance->bn != NULL) {
		free(instance->bn);
	}
	
	if (instance != NULL) {
		free(instance);
	}
	
	return RETURN_OK;

}

int wifi_dppCreateCSignIntance(unsigned int ap_index, char *c_sign_key, wifi_dpp_csign_instance_t **inst, unsigned char *sign_key_hash)
{
	wifi_dpp_csign_instance_t *instance;
	int bnlen, offset, b64len;
    unsigned char keyasn1[1024];
    unsigned int asn1len;
    const unsigned char *key;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX  ctx;
#else
    EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
#endif
	unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
	unsigned char *ptr;

    printf("%s:%d Here\n", __func__, __LINE__);

	if (inst == NULL) {
		printf("%s:%d:Invalid parameter\n", __func__, __LINE__);
		return RETURN_ERR;
	}

	instance = *inst;
	
	if (instance != NULL) {
		delete_dpp_csign_instance(ap_index, instance);
		instance = NULL;
	}

	instance = (wifi_dpp_csign_instance_t *)malloc(sizeof(wifi_dpp_csign_instance_t));
	memset(instance, 0, sizeof(wifi_dpp_csign_instance_t));
	*inst = instance;

    instance->bnctx = BN_CTX_new();

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)c_sign_key, strlen(c_sign_key))) < 0) { 
		delete_dpp_csign_instance(ap_index, instance);
        printf("%s:%d Failed to decode base 64 private access key\n", __func__, __LINE__);
        return RETURN_ERR;
    }    

    key = keyasn1;

    printf("%s:%d Here\n", __func__, __LINE__);

	if ((instance->key = d2i_ECPrivateKey(NULL,  &key, asn1len)) == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
        printf("%s:%d Failed to create EC key\n", __func__, __LINE__);
        return RETURN_ERR;

	}

    printf("%s:%d Here\n", __func__, __LINE__);
    instance->pt = (EC_POINT*)EC_KEY_get0_public_key(instance->key);
    if (instance->pt == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
        printf("%s:%d Could not get access public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    instance->x = BN_new();
    instance->y = BN_new();
	instance->prime = BN_new();

	instance->group = (EC_GROUP*)EC_KEY_get0_group(instance->key);

	if (!EC_GROUP_get_curve_GFp(instance->group, instance->prime, NULL, NULL, instance->bnctx)) {
		delete_dpp_csign_instance(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

    if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(instance->key), instance->pt, instance->x, 
				instance->y, instance->bnctx)) {
		delete_dpp_csign_instance(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
	}

	switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(instance->key))) {
        case NID_X9_62_prime256v1:
			strcpy(instance->alg, "ES256");
			bnlen = 32;
            break;
        case NID_secp384r1:
			strcpy(instance->alg, "ES384");
			bnlen = 48;
            break;
        case NID_secp521r1:
			strcpy(instance->alg, "ES521");
			bnlen = 66;
            break;
        default:
        	return RETURN_ERR;
    }
    if ((instance->bn = (unsigned char *)malloc(2*bnlen + 1)) == NULL) {
		delete_dpp_csign_instance(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(instance->bn, 0, (2*bnlen + 1));
    instance->bn[0] = 0x04;
    ptr = &instance->bn[1];
    offset = bnlen - BN_num_bytes(instance->x);
    BN_bn2bin(instance->x, ptr + offset);
    ptr = &instance->bn[1+bnlen];
    offset = bnlen - BN_num_bytes(instance->y);
    BN_bn2bin(instance->y, ptr + offset);

	printf("%s:%d: csign public key\n", __func__, __LINE__);
	print_hex_dump(2*bnlen + 1, instance->bn);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_DigestInit(&ctx, EVP_sha256());
    EVP_DigestUpdate(&ctx, instance->bn, 2*bnlen + 1);
    EVP_DigestFinal(&ctx, digest, &mdlen);
#else	
	EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, instance->bn, 2*bnlen + 1);
    EVP_DigestFinal(ctx, digest, &mdlen);
#endif
	
	compute_key_hash(instance->key, sign_key_hash);
	
	printf("%s:%d: csign public key hash\n", __func__, __LINE__);
	print_hex_dump(SHA256_DIGEST_LENGTH, sign_key_hash);
    
	if ((b64len = base64urlencode(instance->kid, digest, mdlen)) < 0) {
		delete_dpp_csign_instance(ap_index, instance);
		printf("%s:%d Could not get affine coordinates for  private key\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    instance->kid[b64len] = '\0';
		

	printf("%s:%d kid:%s alg:%s\n", __func__, __LINE__, instance->kid, instance->alg);

	return RETURN_OK;
	
}

wifi_dpp_session_data_t *create_dpp_session_instance(wifi_device_dpp_context_t *ctx)
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    wifi_dpp_session_data_t    *data = NULL;
    unsigned int asn1len;
    EC_KEY *responder_key, *initiator_key;
    const EC_POINT *ipt, *rpt = NULL;
    const BIGNUM *proto_priv;
	wifi_dpp_instance_t *instance;


	data = &ctx->session_data;

	if (data->instance != NULL) {
    	wifi_dpp_dbg_print("%s:%d Session already exists\n", __func__, __LINE__);
		return data;
	}

	instance = (wifi_dpp_instance_t *)malloc(sizeof(wifi_dpp_instance_t));
	data->instance = instance;

	if (data->session == wifi_dpp_session_type_config) {
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.rPubKey, strlen(data->u.config_data.rPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	return NULL;
    	}

    	key = keyasn1;
    	responder_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    	EC_KEY_set_conv_form(responder_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(responder_key, OPENSSL_EC_NAMED_CURVE);

    	// get the group from responder's boot strap key information
    	if ((instance->group = EC_KEY_get0_group(responder_key)) == NULL) {
        	printf("%s:%d Failed to get group from ec key\n", __func__, __LINE__);
        	return NULL;
    	}
    
		rpt = EC_KEY_get0_public_key(responder_key);
    	if (rpt == NULL) {
        	printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
        	return NULL;
    	}
    
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.iPubKey, strlen(data->u.config_data.iPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    	EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

	} else if (data->session == wifi_dpp_session_type_reconfig) {
    	memset(keyasn1, 0, sizeof(keyasn1));
    	if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.reconfig_data.iPubKey, strlen(data->u.reconfig_data.iPubKey))) < 0) {
        	printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        	return NULL;
    	}

    	key = keyasn1;
    	initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    	EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
    	EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

		instance->group = EC_KEY_get0_group(initiator_key);
		instance->responder_connector = EC_POINT_new(instance->group);
	}

    instance->x = BN_new();
    instance->y = BN_new();
    instance->m = BN_new();
    instance->n = BN_new();
    instance->prime = BN_new();
    instance->bnctx = BN_CTX_new();

    instance->responder_proto_pt = EC_POINT_new(instance->group);
    instance->nid = EC_GROUP_get_curve_name(instance->group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, instance->nid);
    switch (instance->nid) {
        case NID_X9_62_prime256v1:
            instance->group_num = 19;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        case NID_secp384r1:
            instance->group_num = 20;
            instance->digestlen = 48;
            instance->hashfcn = EVP_sha384();
            break;
        case NID_secp521r1:
            instance->group_num = 21;
            instance->digestlen = 64;
            instance->hashfcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            instance->group_num = 25;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        case NID_secp224r1:
            instance->group_num = 26;
            instance->digestlen = 32;
            instance->hashfcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, instance->nid);
            return NULL;
    }

    instance->noncelen = instance->digestlen/2;

    //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, instance->group_num, instance->digestlen);

    instance->initiator_proto_key = EC_KEY_new_by_curve_name(instance->nid);
    if (instance->initiator_proto_key == NULL) {
        printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
        return NULL;
    }

    if (EC_KEY_generate_key(instance->initiator_proto_key) == 0) {
        printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
        return NULL;
    }

    ipt = EC_KEY_get0_public_key(instance->initiator_proto_key);
    if (ipt == NULL) {
        printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
        return NULL;
    }

    proto_priv = EC_KEY_get0_private_key(instance->initiator_proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
        return NULL;
    }

    if ((instance->N = EC_POINT_new(instance->group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return NULL;
    }


    if ((instance->M = EC_POINT_new(instance->group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return NULL;
    }


    if (EC_POINT_get_affine_coordinates_GFp(instance->group, ipt, instance->x,
            instance->y, instance->bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return NULL;
    }

	if (data->session == wifi_dpp_session_type_config) {

    	if (EC_POINT_mul(instance->group, instance->M, NULL, rpt, proto_priv, instance->bnctx) == 0) {
        	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	return NULL;
    	}

            
    	printf("Point M:\n");
    	print_ec_point(instance->group, instance->bnctx, instance->M);

    	if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->M,
            	instance->m, NULL, instance->bnctx) == 0) {
        	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	return NULL;

    	}
	}

    RAND_bytes(instance->initiator_nonce, instance->noncelen);
    if (EC_GROUP_get_curve_GFp(instance->group, instance->prime, NULL, NULL, 
            instance->bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return NULL;
    }


    return data;
}

INT wifi_dpp_frame_received_callbacks_register(wifi_dppAuthResponse_callback_t dppAuthCallback,
                                    wifi_dppConfigRequest_callback_t dppConfigCallback,
                                    wifi_dppConfigResult_callback_t dppConfigResultCallback,
                                    wifi_dppReconfigAnnounce_callback_t dppReconfigAnnounceCallback,
                                    wifi_dppReconfigAuthResponse_callback_t dppReconfigAuthRspCallback)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();

    callbacks->dpp_auth_rsp_callback = dppAuthCallback;
    callbacks->dpp_config_req_callback = dppConfigCallback;
	callbacks->dpp_config_result_callback = dppConfigResultCallback;
	callbacks->dpp_reconfig_announce_callback = dppReconfigAnnounceCallback;
	callbacks->dpp_reconfig_auth_rsp_callback = dppReconfigAuthRspCallback;

    return RETURN_OK;
}

INT
wifi_dppProcessReconfigAuthResponse(wifi_device_dpp_context_t *dpp_ctx)
{
	unsigned char tran_id;
	wifi_tlv_t *tlv = NULL;
	char connector[1024];
	BIGNUM *priv_bn;
	unsigned char primary[512];
    wifi_dppPublicActionFrameBody_t  *frame;
    unsigned int len, attrib_len, primelen, decrypted_len;
    wifi_dpp_session_data_t *data = NULL;
    wifi_dpp_instance_t *instance;
	wifi_dpp_reconfig_instance_t *recfg;
	wifi_dpp_configuration_object_t *obj = &dpp_ctx->config;
    int i=0;

    wifi_dpp_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    recfg = (wifi_dpp_reconfig_instance_t *)obj->reconfigCtx;

    data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
    len = dpp_ctx->received_frame.length;

    attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_transaction_id, attrib_len)) == NULL) {
		return RETURN_ERR;
    } else {
        memcpy(&tran_id, (unsigned char *)tlv->value, tlv->length);
        for(i=(dpp_ctx->dpp_init_retries); i >= 0; i--){ 
            if (tran_id == data->u.reconfig_data.tran_id[i]){
            	wifi_dpp_dbg_print("%s:%d: transaction id match\n", __func__, __LINE__);
                data->u.reconfig_data.match_tran_id=tran_id;
                break;
            }
            if(i == 0){
                wifi_dpp_dbg_print("%s:%d: transaction id mismatch %d\n", __func__, __LINE__,tran_id);
                return RETURN_ERR;
            }
    	}
    }
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_proto_version, attrib_len)) == NULL) {
		return RETURN_ERR;
    } else {
        memcpy((unsigned char *)&dpp_ctx->enrollee_version, (unsigned char *)tlv->value, tlv->length);
        wifi_dpp_dbg_print("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_connector, attrib_len)) == NULL) {
		return RETURN_ERR;
    } 
		
	memset(connector, 0, 1024);
    memcpy((unsigned char *)connector, (unsigned char *)tlv->value, tlv->length);
	
	if (dpp_build_point_from_connector_string(dpp_ctx, connector) == NULL) {
		wifi_dpp_dbg_print("%s:%d invalid connector\n", __func__, __LINE__);
		return RETURN_ERR;
	}

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_protocol_key, attrib_len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }


    wifi_dpp_dbg_print("%s:%d: Responder Protocol key\n", __func__, __LINE__);
    print_hex_dump(tlv->length, tlv->value);

    primelen = BN_num_bytes(instance->prime);
    printf("primelen: %d\n", primelen);

    BN_bin2bn(tlv->value, primelen, instance->x);
    BN_bin2bn(tlv->value + primelen, primelen, instance->y);
    printf("X: ");
    print_bignum(instance->x);
    printf("Y: ");
    print_bignum(instance->y);

    if (EC_POINT_set_affine_coordinates_GFp(instance->group, instance->responder_proto_pt,
        instance->x, instance->y, instance->bnctx) == 0) {
        wifi_dpp_dbg_print("%s:%d: Failed to set coordinates\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (EC_POINT_is_on_curve(instance->group, instance->responder_proto_pt,
            instance->bnctx) == 0) {
        wifi_dpp_dbg_print("%s:%d: Point is not on curve\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    wifi_dpp_dbg_print("%s:%d: Computing key\n", __func__, __LINE__);

	// compute the Ke
	// M = c * (Cr + Pr)
	// ke = HKDF(I-nonce, "dpp reconfig key", M.x)
	
	EC_POINT_add(instance->group, instance->N, instance->responder_proto_pt, instance->responder_connector, instance->bnctx);

	priv_bn = (BIGNUM*)EC_KEY_get0_private_key(recfg->key);
	if (priv_bn == NULL) {
        printf("%s:%d: Failed to get priv key big number\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
	}
    wifi_dpp_dbg_print("%s:%d: EC point added\n", __func__, __LINE__);

	if (EC_POINT_mul(instance->group, instance->M, NULL, instance->N, priv_bn, instance->bnctx) == 0) {
    	printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_dpp_dbg_print("%s:%d: EC point multiplied\n", __func__, __LINE__);
	compute_reconfig_encryption_key(instance);

    if ((decrypted_len = get_auth_frame_wrapped_data(frame, attrib_len, instance, primary, 512, true)) == -1) {
        wifi_dpp_dbg_print("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

	wifi_dpp_dbg_print("%s:%d: Decrypted length: %d\n", __func__, __LINE__, decrypted_len);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_nonce, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get responder nonce\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("Responder nonce: ");
    print_hex_dump(tlv->length, tlv->value);
    memcpy(instance->responder_nonce, tlv->value, tlv->length);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_cap, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get responder capabilitie\n", __func__, __LINE__);
    } else {
        wifi_dpp_dbg_print("Responder capabilities: ");
        print_hex_dump(tlv->length, tlv->value);
    }


    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_initiator_nonce, decrypted_len)) == NULL) {
        wifi_dpp_dbg_print("%s:%d: Failed to get initiator nonce nonce\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    } else if (memcmp(tlv->value, instance->initiator_nonce, tlv->length) != 0) {
        wifi_dpp_dbg_print("%s:%d: initiator nonce mismatch\n", __func__, __LINE__);
        dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
	}

	return RETURN_OK;
}


INT
wifi_dppProcessReconfigAnnouncement(unsigned char *frame, unsigned int len, unsigned char *key_hash)
{
	wifi_tlv_t *tlv;
	wifi_dppPublicActionFrameBody_t *action;

	action = (wifi_dppPublicActionFrameBody_t *)frame;

	tlv = (wifi_tlv_t *)action->attrib;
        tlv = get_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_C_sign_key_hash, len);
	if (tlv == NULL) {
		return RETURN_ERR;

	}

	printf("%s:%d Matching C-sign\n", __func__, __LINE__);
	print_hex_dump(tlv->length, tlv->value);
	print_hex_dump(tlv->length, key_hash);

	if ((tlv->length != SHA256_DIGEST_LENGTH) || (memcmp(tlv->value, key_hash, SHA256_DIGEST_LENGTH) != 0)) {
		return RETURN_ERR;
	}

	return RETURN_OK;
}


INT
wifi_dppProcessConfigResult(wifi_device_dpp_context_t *dpp_ctx)
{
    unsigned int attrib_len;
	int decrypted_len;
    siv_ctx ctx;
    wifi_tlv_t *tlv = NULL;
    wifi_dppPublicActionFrameBody_t  *frame;
    unsigned int len;
    wifi_dpp_session_data_t *data = NULL;
    wifi_dpp_instance_t *instance;
    unsigned char plain[128], status;
#ifdef CONFIG_RESULT_SIMULATE
    unsigned int tlv_len = 0;
    unsigned char buff[256];
    wifi_tlv_t *wrapped_tlv;
#endif

    data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
    len = dpp_ctx->received_frame.length;

#ifdef CONFIG_RESULT_SIMULATE
	// temporarily simulate a buffer until encryption is fixed
	frame = (wifi_dppPublicActionFrameBody_t *)buff;
    frame->dpp_oui.oui[0] = 0x50;
    frame->dpp_oui.oui[1] = 0x6f;
    frame->dpp_oui.oui[2] = 0x9a;
    frame->dpp_oui.oui_type = DPP_OUI_TYPE;
    frame->crypto = 1;
    frame->frame_type = wifi_dpp_public_action_frame_type_cfg_result;
	wrapped_tlv = (wifi_tlv_t *)frame->attrib;
	wrapped_tlv->type = wifi_dpp_attrib_id_wrapped_data;

	tlv = (wifi_tlv_t *)(&wrapped_tlv->value[AES_BLOCK_SIZE]);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &status);
	tlv_len += 5;
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_enrollee_nonce, instance->noncelen, instance->enrollee_nonce);
	tlv_len += (instance->noncelen + 4);
	print_hex_dump(tlv_len, &wrapped_tlv->value[AES_BLOCK_SIZE]);

	wrapped_tlv->length = tlv_len + AES_BLOCK_SIZE;
	len = sizeof(wifi_dppPublicActionFrameBody_t) + wrapped_tlv->length;
    
	switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;

        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;

        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;

        default:
            printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
            dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
            return RETURN_ERR;
    }

    siv_encrypt(&ctx, &wrapped_tlv->value[AES_BLOCK_SIZE], &wrapped_tlv->value[AES_BLOCK_SIZE], tlv_len, wrapped_tlv->value, 1,
                    frame, sizeof(wifi_dppPublicActionFrameBody_t));

	print_hex_dump(len, frame);
#endif

    attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_wrapped_data, attrib_len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
		return RETURN_ERR;
    }

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;

        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;

        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;

        default:
            printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
            dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
            return RETURN_ERR;
    }

	if ((decrypted_len = siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], plain, tlv->length - AES_BLOCK_SIZE, 
							tlv->value, 1, frame, sizeof(wifi_dppPublicActionFrameBody_t))) < 0) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		return RETURN_ERR;
	}

	len = tlv->length - AES_BLOCK_SIZE;

    if ((tlv = get_tlv(plain, wifi_dpp_attrib_id_status, len)) == NULL) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
		return RETURN_ERR;
	}

	memcpy(&status, tlv->value, tlv->length);
	if (status != 0) {
        dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
		return RETURN_ERR;
	}
        
	dpp_ctx->enrollee_status = RESPONDER_STATUS_OK;

	return RETURN_OK;
}

INT
wifi_dppProcessConfigRequest(wifi_device_dpp_context_t *ctx)
{
    unsigned char buff[1024];
    int decrypted_len;
    wifi_tlv_t *tlv = NULL;
	wifi_dpp_session_data_t *data;
	wifi_dpp_instance_t *instance;
	unsigned char  *attrib;
	unsigned int len;

	data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

	attrib = ctx->received_frame.frame;
	len = ctx->received_frame.length;

    printf("%s:%d:Enter\n", __func__, __LINE__);
    
    if ((decrypted_len = get_config_frame_wrapped_data(attrib, len, instance, buff, 1024)) == -1) {
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    tlv = (wifi_tlv_t *)buff;

    tlv = get_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_enrollee_nonce, decrypted_len);
    if (tlv == NULL) {
		ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    memcpy(instance->enrollee_nonce, tlv->value, tlv->length);
    printf("%s:%d: Enrollee nonce: E noncelen: %d I/R noncelen: %d\n", __func__, __LINE__, tlv->length, instance->noncelen);
    print_hex_dump(tlv->length, tlv->value);
   
	ctx->enrollee_status = RESPONDER_STATUS_OK; 

	return RETURN_OK;
}

INT wifi_dppProcessAuthResponse(wifi_device_dpp_context_t *dpp_ctx)
{
    unsigned char keyasn1[1024];
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    unsigned char *key;
    unsigned int asn1len, attrib_len, primelen;
	int decrypted_len;
    siv_ctx ctx;
    unsigned char   primary[512];
    unsigned char   secondary[512];
    EC_KEY *responder_boot_key;
    BIGNUM  *pi;
    wifi_tlv_t *tlv = NULL;
    unsigned char status;
    ULONG channel;
   	wifi_dppPublicActionFrameBody_t  *frame;
	unsigned int len;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t *instance;

    data = &dpp_ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;
	
	frame = (wifi_dppPublicActionFrameBody_t*)dpp_ctx->received_frame.frame;
	len = dpp_ctx->received_frame.length; 

	attrib_len = len - sizeof(wifi_dppPublicActionFrameBody_t);
    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_proto_version, attrib_len)) == NULL) {
        dpp_ctx->enrollee_version = 1;
        printf("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    } else {
        memcpy((unsigned char *)&dpp_ctx->enrollee_version, (unsigned char *)tlv->value, tlv->length);
        printf("%s:%d dpp_ctx->enrollee_version = %d\n", __func__, __LINE__, dpp_ctx->enrollee_version);
    }

    tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_status, attrib_len);
    if (tlv != NULL) {
        status = *tlv->value;
    } else {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (status != STATUS_OK) {
        // return authentication failure for now
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_boot_hash, attrib_len)) == NULL) {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)data->u.config_data.rPubKey,
            strlen(data->u.config_data.rPubKey))) < 0) {
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, (const unsigned char **)&key, asn1len);

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    if (compute_key_hash(responder_boot_key, keyhash) < 1) {
        printf("%s:%d Computing responder bootstrap key hash failed\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("%s:%d: Comparing Responder boot hash\n", __func__, __LINE__);
    if (memcmp(tlv->value, keyhash, tlv->length) != 0) {
        printf("%s:%d: Comparing Responder boot hash with recived hash failed\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_responder_protocol_key, attrib_len)) == NULL) {
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("%s:%d: Responder Protocol key\n", __func__, __LINE__);
    print_hex_dump(tlv->length, tlv->value);

    primelen = BN_num_bytes(instance->prime);
    printf("primelen: %d\n", primelen);

    BN_bin2bn(tlv->value, primelen, instance->x);
    BN_bin2bn(tlv->value + primelen, primelen, instance->y);
    printf("X: ");
    print_bignum(instance->x);
    printf("Y: ");
    print_bignum(instance->y);

    if (EC_POINT_set_affine_coordinates_GFp(instance->group, instance->responder_proto_pt,
        instance->x, instance->y, instance->bnctx) == 0) {
        printf("%s:%d: Failed to set coordinates\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if (EC_POINT_is_on_curve(instance->group, instance->responder_proto_pt,
            instance->bnctx) == 0) {
        printf("%s:%d: Point is not on curve\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    pi = (BIGNUM*)EC_KEY_get0_private_key(instance->initiator_proto_key);
    if (pi == NULL) {
        printf("%s:%d Could not get initiator protocol private point\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }


    if (EC_POINT_mul(instance->group, instance->N, NULL,
            instance->responder_proto_pt, pi, instance->bnctx) == 0) {
        printf("%s:%d: Multiply error\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    if (EC_POINT_get_affine_coordinates_GFp(instance->group, instance->N,
            instance->n, NULL, instance->bnctx) == 0) {
        printf("%s:%d: Coordinates get failure\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    printf("Point N:\n");
    print_ec_point(instance->group, instance->bnctx, instance->N);

    if (compute_intermediate_key(instance, false) != 0) {
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((decrypted_len = get_auth_frame_wrapped_data(frame, attrib_len, instance, primary, 512, false)) == -1) {
        printf("%s:%d: Failed to decrypt wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_nonce, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get responder nonce\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("Responder nonce: ");
    print_hex_dump(tlv->length, tlv->value);
    memcpy(instance->responder_nonce, tlv->value, tlv->length);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_responder_cap, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get responder capabilitie\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }
    printf("Responder capabilities: ");
    print_hex_dump(tlv->length, tlv->value);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_initiator_nonce, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get initiator nonce nonce\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    if ((tlv = get_tlv(frame->attrib, wifi_dpp_attrib_id_initiator_boot_hash, attrib_len)) == NULL) {
        printf("%s:%d: Mutual authentication not required\n", __func__, __LINE__);
        instance->mutual = false;
    } else {
        printf("%s:%d: Initiator boot hash\n", __func__, __LINE__);
        print_hex_dump(tlv->length, tlv->value);
        instance->mutual = true;
    }

    compute_encryption_key(instance);

    if ((tlv = get_tlv(primary, wifi_dpp_attrib_id_wrapped_data, decrypted_len)) == NULL) {
        printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            break;

        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;

        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;

        default:
            printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
			dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        	return RETURN_ERR;
    }

    if (siv_decrypt(&ctx, &tlv->value[AES_BLOCK_SIZE], secondary,
            tlv->length - AES_BLOCK_SIZE, tlv->value, 0) < 1) {
        printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    if ((tlv = get_tlv(secondary, wifi_dpp_attrib_id_responder_auth_tag, tlv->length - AES_BLOCK_SIZE)) == NULL) {
        printf("%s:%d: Failed to get responder tag from secondary wrapped data\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;
    }

    printf("Responder Auth Tag: ");
    print_hex_dump(tlv->length, tlv->value);

    if (create_auth_tags(instance, data->u.config_data.iPubKey, data->u.config_data.rPubKey) == RETURN_ERR) {
        printf("%s:%d: Failed to get create auth tags\n", __func__, __LINE__);
		dpp_ctx->enrollee_status = RESPONDER_STATUS_AUTH_FAILURE;
        return RETURN_ERR;

    }

    // success, we should change the channel to current operating channel
    wifi_getRadioChannel(dpp_ctx->ap_index%2, &channel);
    data->channel = channel_to_frequency(channel);

	dpp_ctx->enrollee_status = RESPONDER_STATUS_OK;
    return RETURN_OK;
}

void callback_dpp_config_req_frame_received(int ap_index, mac_address_t sta, unsigned char token, unsigned char  *attrib, unsigned int len)
{
    wifi_device_callbacks_t *callbacks;

    callbacks = get_device_callbacks();
    callbacks->dpp_config_req_callback(ap_index, sta, token, attrib, len);
}

void callback_dpp_public_action_frame_received(int ap_index, mac_address_t sta, wifi_dppPublicActionFrameBody_t  *frame, unsigned int len)
{
    wifi_device_callbacks_t *callbacks;
    
    callbacks = get_device_callbacks();
	printf("%s:%d frame->frame_type=%d\n", __func__, __LINE__, frame->frame_type);
	
	if (frame->frame_type == wifi_dpp_public_action_frame_type_auth_rsp) {
    	callbacks->dpp_auth_rsp_callback(ap_index, sta, (unsigned char*)frame, len);
	} else if (frame->frame_type == wifi_dpp_public_action_frame_type_cfg_result) {
    	callbacks->dpp_config_result_callback(ap_index, sta, (unsigned char*)frame, len);
	} else if (frame->frame_type == wifi_dpp_public_action_frame_type_recfg_announcement) {
    	callbacks->dpp_reconfig_announce_callback(ap_index, sta, (unsigned char*)frame, len);
	} else if (frame->frame_type == wifi_dpp_public_action_frame_type_recfg_auth_rsp) {
    	callbacks->dpp_reconfig_auth_rsp_callback(ap_index, sta, (unsigned char*)frame, len);
	}
}

INT wifi_dppSendConfigResponse(wifi_device_dpp_context_t *ctx) 
{
    wifi_dppConfigResponseFrame_t    *config_response_frame;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t *instance;
    unsigned char buff[2048], dpp_status = STATUS_OK;
    wifi_tlv_t *tlv;
    unsigned int tlv_len = 0, wrapped_len = 0;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement %u\n", __func__, __LINE__, ctx->config.credentials.keyManagement);
   
    ctx->activation_status = ActStatus_In_Progress; 
    data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;


    config_response_frame = (wifi_dppConfigResponseFrame_t *)buff;

    config_response_frame->public_action_hdr.cat = 0x04;
    config_response_frame->public_action_hdr.action = 0x0b;
    config_response_frame->gas_resp_body.token = ctx->token; //add same token
    config_response_frame->gas_resp_body.status = 0;
    config_response_frame->gas_resp_body.comeback_delay = 0;
    config_response_frame->gas_resp_body.proto_elem.id = 0x6c;
    config_response_frame->gas_resp_body.proto_elem.len = 0x08;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.query_rsp_info = 0x7f;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.adv_proto_id = wifi_adv_proto_id_vendor_specific;
    config_response_frame->gas_resp_body.proto_elem.proto_tuple.len = sizeof(wifi_dppOUI) + 1;
	config_response_frame->dpp_oui.oui[0] = 0x50;
	config_response_frame->dpp_oui.oui[1] = 0x6f;
	config_response_frame->dpp_oui.oui[2] = 0x9a;

   	config_response_frame->dpp_oui.oui_type = DPP_OUI_TYPE;

    config_response_frame->dpp_proto = DPP_CONFPROTO;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)config_response_frame->rsp_body;

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &dpp_status);
    tlv_len += 5;

    wrapped_len = set_config_frame_wrapped_data(config_response_frame->rsp_body, tlv_len, instance, ctx);
    tlv_len += (wrapped_len + 4);

    config_response_frame->rsp_len = tlv_len;

    printf("%s:%d: Sending frame\n", __func__, __LINE__);
    printf("%s:%d: Sending frame freqency/channel:%u len:%u\n", __func__, __LINE__, data->channel, sizeof(wifi_dppConfigResponseFrame_t) + tlv_len);
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, data->channel, (unsigned char *)config_response_frame, 
                    sizeof(wifi_dppConfigResponseFrame_t) + tlv_len);

    printf("%s:%d: credentials.keyManagement %u\n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    printf("%s:%d Send Config Response success\n", __func__, __LINE__);

    return RETURN_OK;

}

int
wifi_dppSendReconfigAuthCnf(wifi_device_dpp_context_t *dpp_ctx)
{
	siv_ctx ctx;
    unsigned char buff[2048];
    wifi_dppPublicActionFrame_t    *public_action_frame;
    ULONG ch_freq = 0;
    wifi_dpp_session_data_t    *data = NULL;
    wifi_tlv_t *tlv, *wrapped_tlv;
    unsigned int tlv_len, len, flags = 0;
    wifi_dpp_instance_t *instance;
    ULONG channel;

    wifi_dpp_dbg_print("%s:%d Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u\n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);

	data = &dpp_ctx->session_data;
    instance = (wifi_dpp_instance_t *)data->instance;

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
    public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;
    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_recfg_auth_cnf;

    wifi_dpp_dbg_print("%s:%d Building TLVs\n", __func__, __LINE__);

    wrapped_tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;
    wrapped_tlv->type =  wifi_dpp_attrib_id_wrapped_data;

    tlv_len = 0;
    wifi_dpp_dbg_print("%s:%d tlv_len:%zu\n", __func__, __LINE__, tlv_len);

    tlv = (wifi_tlv_t *)&wrapped_tlv->value[AES_BLOCK_SIZE];

    wifi_dpp_dbg_print("%s:%d Building TLV transaction id %d\n", __func__, __LINE__,data->u.reconfig_data.match_tran_id);
  
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_transaction_id, sizeof(unsigned char), &data->u.reconfig_data.match_tran_id);
    tlv_len += (sizeof(unsigned char) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV protocol version\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(dpp_ctx->configurator_version), &dpp_ctx->configurator_version);
    tlv_len += (sizeof(dpp_ctx->configurator_version) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV initiator nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
    tlv_len += (instance->noncelen + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV responder nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_nonce, instance->noncelen, instance->responder_nonce);
    tlv_len += (instance->noncelen + 4);

    wifi_dpp_dbg_print("%s:%d Building TLV reconfig flags\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_reconfig_flags, sizeof(unsigned int), (unsigned char*)&flags);
    tlv_len += (sizeof(unsigned int) + 4);

    wifi_dpp_dbg_print("%s:%d Building TLVs done\n", __func__, __LINE__);

    wrapped_tlv->length = tlv_len + AES_BLOCK_SIZE; // wrapped tlv length = 58 + 16 = 74
    wifi_dpp_dbg_print("%s:%d wrapped_tlv->length:%zu\n", __func__, __LINE__, wrapped_tlv->length); 
    wifi_dpp_dbg_print("%s:%d digestlen:%d\n", __func__, __LINE__, instance->digestlen);

    switch(instance->digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_256);
            printf("Encryption Key reconfig_cnf: \n");
            print_hex_dump(instance->digestlen, instance->ke);
            break;

        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_384);
            break;

        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, instance->ke, SIV_512);
            break;

        default:
            printf("%s:%d: Failed to get secondary wrapped data\n", __func__, __LINE__);
            dpp_ctx->enrollee_status = RESPONDER_STATUS_CONFIGURATION_FAILURE;
            return RETURN_ERR;
    }

    siv_encrypt(&ctx, &wrapped_tlv->value[AES_BLOCK_SIZE], &wrapped_tlv->value[AES_BLOCK_SIZE], tlv_len, wrapped_tlv->value, 1,
                    (unsigned char *)&public_action_frame->public_action_body, sizeof(wifi_dppPublicActionFrameBody_t));

    ch_freq = (unsigned long) channel_to_frequency(data->channel);
    wifi_dpp_dbg_print("%s:%d Trying sending frame on channel:%d\n", __func__, __LINE__, data->channel);

    len = sizeof(wifi_dppPublicActionFrame_t) + 4 +  wrapped_tlv->length;
    wifi_dpp_dbg_print("%s:%d Over the air len:%zu\n", __func__, __LINE__, len);
    wifi_sendActionFrame(dpp_ctx->ap_index, data->sta_mac, ch_freq, (unsigned char *)public_action_frame, len);

    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);
 // success, we should change the channel to current operating channel
    wifi_getRadioChannel(dpp_ctx->ap_index%2, &channel);
    data->channel = channel_to_frequency(channel);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, dpp_ctx->config.credentials.keyManagement);
    data->u.reconfig_data.match_tran_id=0;
    return RETURN_OK;
}

int
wifi_dppSendAuthCnf(wifi_device_dpp_context_t *ctx)       
{
    unsigned char keyasn1[1024];
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    const unsigned char *key;
    unsigned char buff[2048], dpp_status = STATUS_OK;
    unsigned int asn1len, tlv_len = 0, wrapped_len = 0;
    wifi_dppPublicActionFrame_t    *public_action_frame;
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t	*instance;
    EC_KEY *responder_boot_key, *initiator_boot_key;
    wifi_tlv_t *tlv;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    ctx->activation_status = ActStatus_In_Progress;

    data = &ctx->session_data;
	instance = (wifi_dpp_instance_t *)data->instance;

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, data->u.config_data.rPubKey, strlen(data->u.config_data.rPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, data->u.config_data.iPubKey, strlen(data->u.config_data.iPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;

   	public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;

    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_auth_cnf;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;
    
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_status, 1, &dpp_status);
    tlv_len += 5;

    if (instance->mutual == true) {

        if (compute_key_hash(initiator_boot_key, keyhash) < 1) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        	ctx->activation_status = ActStatus_Failed;
            return RETURN_ERR;
        }

        tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_boot_hash, SHA256_DIGEST_LENGTH, keyhash);
        tlv_len += (SHA256_DIGEST_LENGTH + 4);
    }

    printf("%s:%d: Computing bootstrap key hash\n", __func__, __LINE__);
    if (compute_key_hash(responder_boot_key, keyhash) < 1) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_boot_hash, SHA256_DIGEST_LENGTH, keyhash);
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

    printf("%s:%d: Setting wrapped data\n", __func__, __LINE__);
    wrapped_len = set_auth_frame_wrapped_data(&public_action_frame->public_action_body, tlv_len, instance, false);
    tlv_len += (wrapped_len + 4);

    printf("%s:%d: Sending frame\n", __func__, __LINE__);
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, data->channel, (unsigned char *)public_action_frame, 
            sizeof(wifi_dppPublicActionFrame_t) + tlv_len);

    data->state = STATE_DPP_AUTHENTICATED;
    printf("%s:%d Send Auth Confirmation success\n", __func__, __LINE__);
    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);

    return RETURN_OK;
}

int 
wifi_dppCancel(wifi_device_dpp_context_t *ctx)
{
	delete_dpp_session_instance(ctx);

    return RETURN_OK;
}

wifi_dpp_session_data_t *create_dpp_reconfig_session_instance(wifi_device_dpp_context_t *ctx)
{
        wifi_dpp_session_data_t    *data = NULL;
	time_t t;

	data = &ctx->session_data;

	srand((unsigned int) time(&t));

	data->u.reconfig_data.tran_id[0] = rand();

        return data;
}

int
wifi_dppReconfigInitiate(wifi_device_dpp_context_t *ctx)
{
	unsigned char buff[2048];
	char 	reconfig_connector[1024];
	wifi_dppPublicActionFrame_t    *public_action_frame;
	ULONG ch_freq = 0;
	wifi_dpp_session_data_t    *data = NULL;
    wifi_tlv_t *tlv;
	unsigned short tlv_len;
	wifi_dpp_instance_t *instance;
	int conn_len = 0;
	wifi_dpp_configuration_object_t *obj = &ctx->config;

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
	wifi_dpp_dbg_print("%s:%d Enter recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		obj->reconfigCtx, obj->cSignInstance);
    
	data = create_dpp_session_instance(ctx);
	instance = (wifi_dpp_instance_t *)data->instance;
    int retry_cnt= ctx->dpp_init_retries;
	
	wifi_dpp_dbg_print("%s:%d Created session instance instance:%p recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		instance, obj->reconfigCtx, obj->cSignInstance);

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff;

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
    public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE;
    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_recfg_auth_req;

	wifi_dpp_dbg_print("%s:%d Building TLVs instance:%p recfg ctx:%p csign instance:%p\n", __func__, __LINE__,
		instance, obj->reconfigCtx, obj->cSignInstance);


    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;

	data->u.reconfig_data.tran_id[retry_cnt] = rand();
	wifi_dpp_dbg_print("%s:%d Building TLV transaction id: %d \n", __func__, __LINE__,data->u.reconfig_data.tran_id[retry_cnt]);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_transaction_id, sizeof(unsigned char), &data->u.reconfig_data.tran_id[retry_cnt]);
    tlv_len += (sizeof(unsigned char) + 4);

	wifi_dpp_dbg_print("%s:%d Building TLV protocol version\n", __func__, __LINE__);
	tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(ctx->configurator_version), &ctx->configurator_version);
    tlv_len += (sizeof(ctx->configurator_version) + 4);
	
	memset(reconfig_connector, 0, 1024);
	if (dpp_build_connector(ctx, reconfig_connector, false) < 0) {
		return RETURN_ERR;
	}

	conn_len = strlen(reconfig_connector);
	wifi_dpp_dbg_print("%s:%d Building TLV connector\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_connector, conn_len, reconfig_connector);
	tlv_len += (conn_len + 4);

	wifi_dpp_dbg_print("%s:%d Building TLV nonce\n", __func__, __LINE__);
    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_initiator_nonce, instance->noncelen, instance->initiator_nonce);
    tlv_len += (4 + instance->noncelen);
	
	wifi_dpp_dbg_print("%s:%d Building TLVs done\n", __func__, __LINE__);


    ch_freq = (unsigned long) channel_to_frequency(data->channel);
	wifi_dpp_dbg_print("%s:%d Trying sending frame on channel:%d\n", __func__, __LINE__, data->channel);

	wifi_sendActionFrame(ctx->ap_index, data->sta_mac, ch_freq, (unsigned char *)public_action_frame, sizeof(wifi_dppPublicActionFrame_t) + tlv_len);

    printf("%s:%d: credentials.keyManagement:%u \n", __func__, __LINE__, ctx->config.credentials.keyManagement);
    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    return RETURN_OK;
}

int
wifi_dppInitiate(wifi_device_dpp_context_t *ctx)
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    unsigned int asn1len;
    EC_KEY *responder_boot_key, *initiator_boot_key;
    unsigned char buff[2048];
    unsigned int wrapped_len;
    unsigned char keyhash[SHA512_DIGEST_LENGTH];
    wifi_dppPublicActionFrame_t    *public_action_frame;
    wifi_tlv_t *tlv;
    unsigned short tlv_len, chann_attr;;
    unsigned char protocol_key_buff[1024];
    wifi_dpp_session_data_t *data = NULL;
	wifi_dpp_instance_t	*instance;
    ULONG hm_channel = 0;
    ULONG ch_freq = 0;

    wifi_dpp_dbg_print("%s:%d Enter\n", __func__, __LINE__);
    wifi_getRadioChannel(ctx->ap_index%2, &hm_channel);
    ctx->activation_status = ActStatus_In_Progress; 

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)ctx->session_data.u.config_data.rPubKey, strlen(ctx->session_data.u.config_data.rPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    responder_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    EC_KEY_set_conv_form(responder_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(responder_boot_key, OPENSSL_EC_NAMED_CURVE);

    memset(keyasn1, 0, sizeof(keyasn1));
    if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)ctx->session_data.u.config_data.iPubKey, strlen(ctx->session_data.u.config_data.iPubKey))) < 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    key = keyasn1;
    initiator_boot_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

    EC_KEY_set_conv_form(initiator_boot_key, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_asn1_flag(initiator_boot_key, OPENSSL_EC_NAMED_CURVE);

    data = create_dpp_session_instance(ctx);
	instance = (wifi_dpp_instance_t *)data->instance;
    
    if (compute_intermediate_key(instance, true) != 0) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d failed to generate key\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    public_action_frame = (wifi_dppPublicActionFrame_t *)buff; 

    public_action_frame->public_action_hdr.cat = 0x04;
    public_action_frame->public_action_hdr.action = 0x09;
    public_action_frame->public_action_body.dpp_oui.oui[0] = 0x50;
    public_action_frame->public_action_body.dpp_oui.oui[1] = 0x6f;
    public_action_frame->public_action_body.dpp_oui.oui[2] = 0x9a;
	
   	public_action_frame->public_action_body.dpp_oui.oui_type = DPP_OUI_TYPE; 

    public_action_frame->public_action_body.crypto = 1; // Cryptographic suite 1 consists of the SHA2 family of hash algorithms and AES-SIV
    public_action_frame->public_action_body.frame_type = wifi_dpp_public_action_frame_type_auth_req;

    tlv_len = 0;

    tlv = (wifi_tlv_t *)public_action_frame->public_action_body.attrib;

    if (compute_key_hash(initiator_boot_key, keyhash) < 1) {
        ctx->activation_status = ActStatus_Failed;
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_boot_hash, SHA256_DIGEST_LENGTH, keyhash);    
    tlv_len += (SHA256_DIGEST_LENGTH + 4);
    
    if (compute_key_hash(responder_boot_key, keyhash) < 1) {
        ctx->activation_status = ActStatus_Failed;
        wifi_dpp_dbg_print("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_responder_boot_hash, SHA256_DIGEST_LENGTH, keyhash);    
    tlv_len += (SHA256_DIGEST_LENGTH + 4);

	if (ctx->configurator_version > 1) {
		tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_proto_version, sizeof(ctx->configurator_version), &ctx->configurator_version);
    	tlv_len += (sizeof(ctx->configurator_version) + 4);
	}

    BN_bn2bin((const BIGNUM *)instance->x, 
        &protocol_key_buff[BN_num_bytes(instance->prime) - BN_num_bytes(instance->x)]);
    BN_bn2bin((const BIGNUM *)instance->y, 
        &protocol_key_buff[2*BN_num_bytes(instance->prime) - BN_num_bytes(instance->x)]);
    tlv = set_tlv((unsigned char *)tlv, wifi_dpp_attrib_id_initiator_protocol_key, 2*BN_num_bytes(instance->prime), protocol_key_buff);
    tlv_len += (2*BN_num_bytes(instance->prime) + 4);

    chann_attr = freq_to_channel(channel_to_frequency(hm_channel)); //channel attrib shall be home channel
    tlv = set_tlv((unsigned char*)tlv, wifi_dpp_attrib_id_channel, sizeof(unsigned short), (unsigned char *)&chann_attr);
    tlv_len += 6;
    
    wrapped_len = set_auth_frame_wrapped_data(&public_action_frame->public_action_body, tlv_len, instance, true);
    tlv_len += (wrapped_len + 4);

    //printf("\n\n");
    //printf("%s:%d: Frame buffer:\n", __func__, __LINE__);
    //print_hex_dump(tlv_len, buff);
    ch_freq = (unsigned long) channel_to_frequency(data->channel);
    wifi_sendActionFrame(ctx->ap_index, data->sta_mac, ch_freq/*data->channel*/, (unsigned char *)public_action_frame, sizeof(wifi_dppPublicActionFrame_t) + tlv_len);
    data->state = STATE_DPP_AUTH_RSP_PENDING;
        

    wifi_dpp_dbg_print("%s:%d Exit\n", __func__, __LINE__);

    return RETURN_OK;
}
#if 0
static unsigned char *set_mac_hdr(unsigned int ap_index, unsigned char *buff, char *dst)
{
	unsigned char *tmp = buff;
	struct ifreq ifr;
	size_t if_name_len; 
	char interface_name[32];
	mac_address_t	dst_mac;
	int fd;
	unsigned short eth_type = htons(0x0800);

	sprintf(interface_name, "ath%d", ap_index);
 	if_name_len = strlen(interface_name);

    memcpy(ifr.ifr_name, interface_name, if_name_len);
    ifr.ifr_name[if_name_len] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		return NULL;
	}

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		printf("%s:%d: Failed in ioctl error:%d\n", __func__, __LINE__, errno);
		close(fd);
		return NULL;
	}	

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {	
		printf("%s:%d: Failed in ioctl error:%d\n", __func__, __LINE__, errno);
		close(fd);
		return NULL;
	}


	close(fd);

	memcpy(buff, (unsigned char *)ifr.ifr_hwaddr.sa_data, sizeof(mac_address_t));
	tmp += sizeof(mac_address_t);

	to_mac_bytes(dst, dst_mac);
	memcpy(&buff[sizeof(mac_address_t)], &dst_mac, sizeof(mac_address_t));
	tmp += sizeof(mac_address_t);

	memcpy(&buff[2*sizeof(mac_address_t)], (unsigned char *)&eth_type, sizeof(unsigned short));
	tmp += sizeof(unsigned short);
	
	return tmp;
}
#endif

static void *wifi_dppTestFrameHandler(void *arg)
{
    int sockfd;
    int ret;
    unsigned char msg[1024];
    wifi_test_command_id_t cmd;
    mac_address_t   bmac;
    unsigned char frame[1024];
	char interface_name[32];
    wifi_tlv_t *tlv;
    fd_set rfds;
    struct timeval tv;
    int retval, ap_index;
    bool exit = false;
	struct sockaddr_in saddr;
	socklen_t slen;

    wifi_dpp_dbg_print("%s:%d: Enter\n", __func__, __LINE__);

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    if ((access("/nvram/wifiDppTest", R_OK)) != 0) {
        wifi_dpp_dbg_print("%s:%d: Not a debug build exiting\n", __func__, __LINE__);
        return NULL;
    }

	if ((sockfd = create_test_socket()) < 0) {
        wifi_dpp_dbg_print("%s:%d: Socket create failed\n", __func__, __LINE__);
        return NULL;

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
    	wifi_dpp_dbg_print("%s:%d:Socket signaled Receiving data from socket\n", __func__, __LINE__);
        
        if ((ret = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&saddr, &slen)) < 0) {
            continue;
        }

		wifi_dpp_dbg_print("%s:%d: Received data: %d, select returned:%d\n", __func__, __LINE__, ret, retval);

        if (memcmp(msg, wifi_common_hal_test_signature, sizeof(wifi_common_hal_test_signature)) != 0) {
            continue;
        }

        wifi_dpp_dbg_print("%s:%d: Received test signature\n", __func__, __LINE__);

        if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_cmd, ret)) == NULL) {
            continue;
        }
        memcpy((unsigned char *)&cmd, tlv->value, tlv->length);

        switch (cmd) {
            case wifi_test_command_id_chirp:
			case wifi_test_command_id_reconf_auth_resp:
                wifi_dpp_dbg_print("%s:%d: Received chirp test command\n", __func__, __LINE__);
                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_vap_name, ret)) == NULL) {
                    continue;
                }
                memcpy(interface_name, tlv->value, tlv->length);
                sscanf(interface_name, "ath%d", &ap_index);

                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_sta_mac, ret)) == NULL) {
                    continue;
                }
                memcpy(bmac, tlv->value, tlv->length);

                if ((tlv = get_tlv(&msg[sizeof(wifi_common_hal_test_signature)], wifi_test_attrib_raw, ret)) == NULL) {
                    continue;
                }
                memcpy(frame, tlv->value, tlv->length);
                wifi_dpp_dbg_print("%s:%d: Calling mgmt frame receive\n", __func__, __LINE__);

                mgmt_frame_received_callback(ap_index, bmac, frame, tlv->length, WIFI_MGMT_FRAME_TYPE_ACTION, wifi_direction_uplink);
                break;

            default:
                break;
        }
    }

    close(sockfd);

	return NULL;
}

void wifi_dppStartReceivingTestFrame()
{
	pthread_t frame_recv_tid;

	pthread_create(&frame_recv_tid, NULL, wifi_dppTestFrameHandler, NULL);
}

int wifi_dppTestReconfigAuthResponse(unsigned int apIndex, mac_address_t sta)
{
	int ret, sockfd;
	struct sockaddr_in sockaddr;
    unsigned char msg[1024];
    char interface_name[32];
	unsigned int len, tlv_len = 0;
    wifi_tlv_t *tlv;
	unsigned short port = 8888;

    unsigned char test_data[] = {
			0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x10, 0x16, 0x10, 0x01, 0x00, 0x78, 0x19, 0x10, 0x01,
			0x00, 0x02, 0x0d, 0x10, 0xf0, 0x01, 0x65, 0x79, 0x4a, 0x30, 0x65, 0x58, 0x41, 0x69, 0x4f, 0x69,
			0x4a, 0x6b, 0x63, 0x48, 0x42, 0x44, 0x62, 0x32, 0x34, 0x69, 0x4c, 0x43, 0x4a, 0x72, 0x61, 0x57,
			0x51, 0x69, 0x4f, 0x69, 0x4a, 0x4f, 0x52, 0x6b, 0x70, 0x74, 0x65, 0x58, 0x70, 0x6b, 0x56, 0x31,
			0x6f, 0x32, 0x56, 0x6b, 0x35, 0x34, 0x56, 0x45, 0x6c, 0x30, 0x61, 0x48, 0x56, 0x61, 0x4f, 0x47,
			0x59, 0x30, 0x63, 0x57, 0x64, 0x35, 0x63, 0x47, 0x67, 0x30, 0x4d, 0x58, 0x5a, 0x33, 0x63, 0x46,
			0x42, 0x78, 0x58, 0x31, 0x4e, 0x33, 0x5a, 0x32, 0x64, 0x6f, 0x4e, 0x56, 0x5a, 0x76, 0x49, 0x69,
			0x77, 0x69, 0x59, 0x57, 0x78, 0x6e, 0x49, 0x6a, 0x6f, 0x69, 0x52, 0x56, 0x4d, 0x79, 0x4e, 0x54,
			0x59, 0x69, 0x66, 0x51, 0x2e, 0x65, 0x79, 0x4a, 0x6e, 0x63, 0x6d, 0x39, 0x31, 0x63, 0x48, 0x4d,
			0x69, 0x4f, 0x6c, 0x74, 0x37, 0x49, 0x6d, 0x64, 0x79, 0x62, 0x33, 0x56, 0x77, 0x53, 0x57, 0x51,
			0x69, 0x4f, 0x69, 0x4a, 0x70, 0x62, 0x6e, 0x52, 0x6c, 0x63, 0x6d, 0x39, 0x77, 0x49, 0x69, 0x77,
			0x69, 0x62, 0x6d, 0x56, 0x30, 0x55, 0x6d, 0x39, 0x73, 0x5a, 0x53, 0x49, 0x36, 0x49, 0x6e, 0x4e,
			0x30, 0x59, 0x53, 0x4a, 0x39, 0x58, 0x53, 0x77, 0x69, 0x62, 0x6d, 0x56, 0x30, 0x51, 0x57, 0x4e,
			0x6a, 0x5a, 0x58, 0x4e, 0x7a, 0x53, 0x32, 0x56, 0x35, 0x49, 0x6a, 0x70, 0x37, 0x49, 0x6d, 0x74,
			0x30, 0x65, 0x53, 0x49, 0x36, 0x49, 0x6b, 0x56, 0x44, 0x49, 0x69, 0x77, 0x69, 0x59, 0x33, 0x4a,
			0x32, 0x49, 0x6a, 0x6f, 0x69, 0x55, 0x43, 0x30, 0x79, 0x4e, 0x54, 0x59, 0x69, 0x4c, 0x43, 0x4a,
			0x34, 0x49, 0x6a, 0x6f, 0x69, 0x53, 0x33, 0x6c, 0x53, 0x62, 0x6d, 0x78, 0x4f, 0x62, 0x56, 0x5a,
			0x79, 0x61, 0x55, 0x68, 0x79, 0x4d, 0x30, 0x4e, 0x5a, 0x53, 0x6c, 0x70, 0x35, 0x63, 0x6b, 0x5a,
			0x78, 0x54, 0x47, 0x74, 0x59, 0x61, 0x6d, 0x30, 0x7a, 0x4e, 0x31, 0x56, 0x4e, 0x63, 0x6c, 0x56,
			0x33, 0x62, 0x30, 0x4a, 0x4b, 0x57, 0x56, 0x46, 0x35, 0x52, 0x54, 0x52, 0x66, 0x57, 0x53, 0x49,
			0x73, 0x49, 0x6e, 0x6b, 0x69, 0x4f, 0x69, 0x4a, 0x69, 0x51, 0x32, 0x52, 0x45, 0x53, 0x6c, 0x42,
			0x31, 0x5a, 0x45, 0x78, 0x32, 0x52, 0x56, 0x70, 0x35, 0x53, 0x48, 0x6c, 0x54, 0x54, 0x30, 0x64,
			0x6e, 0x53, 0x55, 0x52, 0x6e, 0x4c, 0x58, 0x42, 0x78, 0x56, 0x6d, 0x39, 0x68, 0x52, 0x56, 0x52,
			0x6a, 0x56, 0x6a, 0x4e, 0x66, 0x58, 0x30, 0x39, 0x35, 0x51, 0x57, 0x56, 0x75, 0x4d, 0x7a, 0x4a,
			0x5a, 0x49, 0x6e, 0x30, 0x73, 0x49, 0x6d, 0x56, 0x34, 0x63, 0x47, 0x6c, 0x79, 0x65, 0x53, 0x49,
			0x36, 0x49, 0x6a, 0x49, 0x77, 0x4d, 0x6a, 0x41, 0x74, 0x4d, 0x54, 0x49, 0x74, 0x4d, 0x54, 0x4a,
			0x55, 0x4d, 0x44, 0x45, 0x36, 0x4d, 0x44, 0x45, 0x36, 0x4d, 0x44, 0x45, 0x69, 0x66, 0x51, 0x2e,
			0x6b, 0x51, 0x42, 0x6c, 0x58, 0x44, 0x74, 0x73, 0x6c, 0x48, 0x76, 0x44, 0x6d, 0x36, 0x69, 0x6b,
			0x50, 0x6b, 0x50, 0x57, 0x63, 0x73, 0x35, 0x35, 0x5f, 0x64, 0x41, 0x72, 0x6d, 0x31, 0x66, 0x6e,
			0x6c, 0x72, 0x6d, 0x63, 0x43, 0x76, 0x4f, 0x65, 0x4f, 0x5f, 0x58, 0x6c, 0x65, 0x56, 0x4d, 0x61,
			0x78, 0x38, 0x7a, 0x50, 0x6d, 0x56, 0x72, 0x70, 0x61, 0x30, 0x72, 0x54, 0x6e, 0x4a, 0x52, 0x4f,
			0x61, 0x47, 0x6d, 0x67, 0x7a, 0x6b, 0x74, 0x5a, 0x4d, 0x67, 0x7a, 0x33, 0x35, 0x63, 0x75, 0x66,
			0x70, 0x6d, 0x63, 0x76, 0x57, 0x51, 0x09, 0x10, 0x40, 0x00, 0x4f, 0x0a, 0x95, 0xb9, 0x78, 0x6c,
			0x05, 0x5b, 0x0c, 0xc0, 0xce, 0x8d, 0x96, 0xfe, 0x8c, 0xc1, 0x39, 0x0d, 0xb8, 0x65, 0x7e, 0x3a,
			0x60, 0x7c, 0xe6, 0xc1, 0x13, 0x6e, 0xbd, 0x17, 0xcb, 0xcf, 0xb7, 0x8a, 0xe1, 0x41, 0x64, 0xfd,
			0x7c, 0x6d, 0x58, 0xb5, 0x75, 0x44, 0x7b, 0xfc, 0x81, 0xb4, 0x54, 0xbd, 0xff, 0xf8, 0x80, 0x11,
			0xf5, 0x01, 0x66, 0x28, 0xa1, 0x10, 0xee, 0xa9, 0x83, 0x87, 0x04, 0x10, 0x3d, 0x00, 0x65, 0x66,
			0xcb, 0x1d, 0x45, 0x7d, 0x66, 0xaf, 0x7b, 0x6e, 0x6c, 0x9e, 0x49, 0x16, 0x5a, 0x5c, 0xac, 0x8f,
			0xca, 0x05, 0xf9, 0xce, 0xe2, 0x1a, 0x08, 0x29, 0xc6, 0x58, 0x56, 0xe7, 0x72, 0xc5, 0x5e, 0x17,
			0xd6, 0xf3, 0x41, 0xee, 0x4a, 0x86, 0x4f, 0x5e, 0xd5, 0x7b, 0xcd, 0xb4, 0x25, 0x8a, 0xd8, 0xf7,
			0xd5, 0xe9, 0xba, 0xf9, 0x0d, 0x35, 0x14, 0xa7, 0x30, 0x29, 0x12
    };

    wifi_test_command_id_t cmd = wifi_test_command_id_reconf_auth_resp;

    printf("%s:%d: Enter\n", __func__, __LINE__);

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

    sprintf(interface_name, "ath%d", apIndex);
    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, interface_name);
    tlv_len += (4 + IFNAMSIZ);


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), sta);
    tlv_len += (4 + sizeof(mac_address_t));


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, sizeof(test_data), test_data);
    tlv_len += (4 + sizeof(test_data));

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
        printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

	return RETURN_OK;
}

int wifi_dppChirp(unsigned int apIndex, mac_address_t sta)
{
	int ret, sockfd;
	struct sockaddr_in sockaddr;
    unsigned char msg[1024];
    char interface_name[32];
	unsigned int len, tlv_len = 0;
    wifi_tlv_t *tlv;
	unsigned short port = 8888;

    unsigned char test_data[] = {
		0x04, 0x09, 0x50, 0x6f, 0x9a, 0x1a, 0x01, 0x0e, 0x1e, 0x10, 0x20, 0x00, 0xa8, 0x21, 0x0b, 0x0f,
		0xb0, 0xc8, 0x98, 0x96, 0x4a, 0xa0, 0xa6, 0xdf, 0xfa, 0x62, 0x62, 0x7f, 0xbd, 0x6d, 0xaa, 0x60,
		0xf8, 0x04, 0x82, 0xf8, 0xd6, 0x36, 0x98, 0x97, 0x61, 0xa2, 0x27, 0x0a
    };

    wifi_test_command_id_t cmd = wifi_test_command_id_chirp;

    printf("%s:%d: Enter\n", __func__, __LINE__);
   
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

    sprintf(interface_name, "ath%d", apIndex);
    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_vap_name, IFNAMSIZ, interface_name);
    tlv_len += (4 + IFNAMSIZ);


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_sta_mac, sizeof(mac_address_t), sta);
    tlv_len += (4 + sizeof(mac_address_t));


    tlv = set_tlv((unsigned char*)tlv, wifi_test_attrib_raw, sizeof(test_data), test_data);
    tlv_len += (4 + sizeof(test_data));

    len += tlv_len;

    if ((ret = sendto(sockfd, msg, len, 0, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) < 0) {
        printf("%s:%d: Error in sending errno: %d\n", __func__, __LINE__, errno);
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);

    printf("%s:%d: Exit, bytes sent: %d\n", __func__, __LINE__, ret);

	return RETURN_OK;
}

//only for TCHXB6
/*
 * generic definitions for IEEE 802.11 frames
 */
typedef struct __attribute__((packed)){
    u_int8_t    i_fc[2];
    u_int8_t    i_dur[2];
    union {
        struct {
            u_int8_t    i_addr1[6];
            u_int8_t    i_addr2[6];
            u_int8_t    i_addr3[6];
        };
        u_int8_t    i_addr_all[3 * 6];
    };
    u_int8_t    i_seq[2];
    /* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
    /* see below */
} _ieee80211_frame;

typedef struct __attribute__((packed)){
    unsigned char ia_category;
    unsigned char ia_action;
} _ieee80211_action;
//end
