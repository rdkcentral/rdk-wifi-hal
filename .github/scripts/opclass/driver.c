/*
 * Sweep every (country, band, channel, bandwidth) through the HAL's real op-class
 * selection, then through the linked hostap's ieee80211_chan_to_freq() -- the same
 * round trip the HAL does in scan, chandef, CSA and DFS paths.
 *
 * One line per case the HAL accepts:  OK|BADFREQ cc band ch bw op freq want
 * and one per case it rejects:        REJECT  cc band ch bw
 */
#include "extracted.c"

static int expected_freq(wifi_freq_bands_t band, unsigned int ch)
{
    switch (band) {
    case WIFI_FREQUENCY_2_4_BAND: return ch == 14 ? 2484 : 2407 + 5 * (int)ch;
    case WIFI_FREQUENCY_5_BAND:   return 5000 + 5 * (int)ch;
    case WIFI_FREQUENCY_6_BAND:   return ch == 2 ? 5935 : 5950 + 5 * (int)ch;
    default:                      return -1;
    }
}

static void sweep(wifi_countrycode_type_t cc, const char *cc_str, wifi_freq_bands_t band,
    const unsigned int *chans, size_t nchans, const wifi_channelBandwidth_t *bws, size_t nbws)
{
    for (size_t c = 0; c < nchans; c++) {
        for (size_t b = 0; b < nbws; b++) {
            wifi_radio_operationParam_t p;
            memset(&p, 0, sizeof(p));
            p.band = band;
            p.channel = chans[c];
            p.channelWidth = bws[b];
            p.countryCode = cc;

            int op = get_op_class_from_radio_params(&p);
            if (op <= 0) {
                printf("REJECT %s %d %u %d\n", cc_str, band, chans[c], bws[b]);
                continue;
            }
            int freq = ieee80211_chan_to_freq(cc_str, (unsigned char)op, (unsigned char)chans[c]);
            int want = expected_freq(band, chans[c]);
            printf("%s %s %d %u %d %d %d %d\n", freq == want ? "OK" : "BADFREQ", cc_str, band,
                chans[c], bws[b], op, freq, want);
        }
    }
}

int main(void)
{
    static const unsigned int ch24[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
    static const unsigned int ch5[] = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
        116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177 };
    unsigned int ch6[60];
    size_t n6 = 0;
    static const wifi_channelBandwidth_t bw24[] = { WIFI_CHANNELBANDWIDTH_20MHZ,
        WIFI_CHANNELBANDWIDTH_40MHZ };
    static const wifi_channelBandwidth_t bw5[] = { WIFI_CHANNELBANDWIDTH_20MHZ,
        WIFI_CHANNELBANDWIDTH_40MHZ, WIFI_CHANNELBANDWIDTH_80MHZ,
        WIFI_CHANNELBANDWIDTH_160MHZ };

    ch6[n6++] = 2;
    for (unsigned int ch = 1; ch <= 233; ch += 4) {
        ch6[n6++] = ch;
    }

    for (size_t i = 0; i < ARRAY_SZ(wifi_country_map); i++) {
        wifi_countrycode_type_t cc = wifi_country_map[i].countryCode;
        char cc_str[8] = { 0 };

        get_coutry_str_from_code(cc, cc_str);
        sweep(cc, cc_str, WIFI_FREQUENCY_2_4_BAND, ch24, ARRAY_SZ(ch24), bw24, ARRAY_SZ(bw24));
        sweep(cc, cc_str, WIFI_FREQUENCY_5_BAND, ch5, ARRAY_SZ(ch5), bw5, ARRAY_SZ(bw5));
        sweep(cc, cc_str, WIFI_FREQUENCY_6_BAND, ch6, n6, bw5, ARRAY_SZ(bw5));
    }
    return 0;
}
