#ifndef PLATFORM_BPI_H
#define PLATFORM_BPI_H

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_ALEN 6

#define MAX_CSI_DATA_POLLING_PERIOD_MS 400
#define MAX_READ_CSI_PKT_INTERVAL 100
#define MAX_CSI_DUMP_PKT_CNT 3000
#define CSI_DUMP_PER_NUM 3

#define RDKB_OUI_MTK    0x0ce7

#define CSI_BW320_DATA_COUNT	1024

#define COMBINE_SHORTS_TO_UINT(short1, short2) \
    (((unsigned int)((unsigned short)(short1))) << 16 | ((unsigned int)((unsigned short)(short2))))

#define EXTRACT_HIGH_SHORT(combined_uint) \
    ((signed short)((combined_uint) >> 16))

#define EXTRACT_LOW_SHORT(combined_uint) \
    ((signed short)((combined_uint) & 0xFFFF))

typedef enum nl80211_mtk_vendor_sub_cmds {
    NL80211_MTK_VENDOR_SUB_CMD_CSI = 0xc2,
} nl80211_mtk_vendor_sub_cmds_t;

typedef enum nl_mtk_vendor_attr_csi_t {
    NL_MTK_VENDOR_ATTR_CSI_CTRL_UNSPEC, 
                        
    NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_MODE,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_TYPE,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL1,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_CFG_VAL2,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_MAC_ADDR,
        
    NL_MTK_VENDOR_ATTR_CSI_CTRL_DUMP_NUM,
        
    NL_MTK_VENDOR_ATTR_CSI_CTRL_DATA,
                
    NL_MTK_VENDOR_ATTR_CSI_CTRL_BAND_IDX,
        
        /* keep last */ 
    NL_NUM_MTK_VENDOR_ATTRS_CSI_CTRL,
    NL_MTK_VENDOR_ATTR_CSI_CTRL_MAX = NL_NUM_MTK_VENDOR_ATTRS_CSI_CTRL - 1
} nl_mtk_vendor_attr_csi_t;

typedef enum nl_mtk_vendor_attr_csi_data {
    NL_MTK_VENDOR_ATTR_CSI_DATA_UNSPEC,
    NL_MTK_VENDOR_ATTR_CSI_DATA_PAD,

    NL_MTK_VENDOR_ATTR_CSI_DATA_VER,
    NL_MTK_VENDOR_ATTR_CSI_DATA_TS,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RSSI,
    NL_MTK_VENDOR_ATTR_CSI_DATA_SNR,
    NL_MTK_VENDOR_ATTR_CSI_DATA_BW,
    NL_MTK_VENDOR_ATTR_CSI_DATA_CH_IDX,
    NL_MTK_VENDOR_ATTR_CSI_DATA_TA,
    NL_MTK_VENDOR_ATTR_CSI_DATA_NUM,
    NL_MTK_VENDOR_ATTR_CSI_DATA_I,
    NL_MTK_VENDOR_ATTR_CSI_DATA_Q,
    NL_MTK_VENDOR_ATTR_CSI_DATA_INFO,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RSVD1,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RSVD2,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RSVD3,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RSVD4,
    NL_MTK_VENDOR_ATTR_CSI_DATA_TX_ANT,
    NL_MTK_VENDOR_ATTR_CSI_DATA_RX_ANT,
    NL_MTK_VENDOR_ATTR_CSI_DATA_MODE,
    NL_MTK_VENDOR_ATTR_CSI_DATA_CHAIN_INFO,

    /* keep last */
    NL_NUM_MTK_VENDOR_ATTRS_CSI_DATA,
    NL_MTK_VENDOR_ATTR_CSI_DATA_MAX = NL_NUM_MTK_VENDOR_ATTRS_CSI_DATA - 1
} nl_mtk_vendor_attr_csi_data_t;

typedef struct csi_data {
    uint8_t ch_bw;       
    uint16_t data_num;
    int16_t data_i[CSI_BW320_DATA_COUNT];
    int16_t data_q[CSI_BW320_DATA_COUNT];
    uint8_t band;
    int8_t rssi;
    uint8_t snr;         
    uint32_t ts;
    uint8_t data_bw;
    uint8_t pri_ch_idx;
    uint8_t ta[ETH_ALEN];
    uint32_t ext_info;
    uint8_t rx_mode;
    uint32_t chain_info;
    uint16_t tx_idx;
    uint16_t rx_idx;
    uint32_t segment_num;
    uint8_t remain_last;
    uint16_t pkt_sn;
    uint8_t tr_stream;
} csi_data_t;
                
typedef struct csi_resp_data {
    uint16_t usr_need_cnt;
    uint16_t buf_cnt;
    csi_data_t *csi_buf;
} csi_resp_data_t;

typedef struct csi_param_cfg {
    uint8_t mode;
    uint8_t cfg;
    uint8_t param_value1;
    uint32_t param_value2;
    bool is_mac_addr_used;
} csi_param_cfg_t;

typedef struct link_element {
    void     *data;
    struct link_element *next;
} link_element_t;

typedef struct csi_info_map {
    bool csi_active_radio;
    link_element_t *sta_info;
} csi_info_map_t;

#endif //PLATFORM_BPI_H
