/* tap-dis-common.h
 * DIS streams handler functions used by tshark and wireshark.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_DIS_COMMON_H__
#define __TAP_DIS_COMMON_H__

#include <stdio.h>

#include <glib.h>

#include <epan/address.h>
#include <epan/epan_dissect.h>
#include <epan/packet_info.h>
#include <epan/tap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _disstream_id {
    address src_addr;
    uint16_t src_port;
    address dst_addr;
    uint16_t dst_port;
    uint16_t radio_id;
    uint16_t entity_id_site;
    uint16_t entity_id_appl;
    uint16_t entity_id_entity;
} disstream_id_t;

typedef struct _disstream_packet {
    uint32_t frame_num;
    nstime_t rel_time;
    uint8_t payload_type;
    guint payload_len;
    guint8 *payload_data;
    double delta_ms;
    double jitter_ms;
    uint32_t estimated_lost_added;
    bool problem;
} disstream_packet_t;

typedef struct _disstream_info {
    disstream_id_t id;

    uint8_t payload_type;
    const char *payload_type_str;
    uint8_t radio_input_source;
    uint8_t transmit_state;

    uint32_t packet_count;
    uint32_t signal_packet_count;
    uint32_t transmitter_packet_count;
    uint64_t total_payload_bytes;
    uint32_t estimated_lost_packets;

    uint32_t first_packet_num;
    uint32_t last_packet_num;
    uint32_t first_signal_frame_num;
    uint32_t last_signal_frame_num;
    nstime_t start_rel_time;
    nstime_t stop_rel_time;

    double max_delta_ms;
    double mean_delta_ms;
    double max_jitter_ms;
    double mean_jitter_ms;

    bool transmission_stopped;
    bool problem;

    GPtrArray *signal_packets;

    /* Internal running analysis state. */
    bool first_timing_packet;
    uint32_t timing_packet_count;
    double start_arrival_ms;
    double prev_arrival_ms;
    double prev_nominal_ms;
    double first_tx_ms;
    double prev_tx_ms;
    double filtered_jitter_ms;
    double excess_codec_time_ms;
} disstream_info_t;

typedef enum {
    DISSTREAM_TAP_ANALYSE,
    DISSTREAM_TAP_SAVE,
    DISSTREAM_TAP_MARK
} disstream_tap_mode_t;

struct _disstream_tapinfo;
typedef void (*disstream_tap_draw_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_reset_cb)(struct _disstream_tapinfo *tapinfo);
typedef void (*disstream_tap_error_cb)(GString *error);

typedef struct _disstream_tapinfo {
    GList *strinfo_list;
    GHashTable *strinfo_hash;
    uint32_t nstreams;
    uint32_t npackets;

    disstream_tap_mode_t mode;
    disstream_info_t *filter_stream;
    FILE *save_file;

    disstream_tap_draw_cb tap_draw;
    disstream_tap_reset_cb tap_reset;
    bool is_registered;
} disstream_tapinfo_t;

void disstream_id_copy(const disstream_id_t *src, disstream_id_t *dst);
void disstream_id_copy_pinfo(const packet_info *pinfo, disstream_id_t *dst);
void disstream_id_copy_pinfo_shallow(const packet_info *pinfo, disstream_id_t *dst);
void disstream_id_free(disstream_id_t *id);
unsigned disstream_id_to_hash(const disstream_id_t *id);
bool disstream_id_equal(const disstream_id_t *id1, const disstream_id_t *id2);

void disstream_info_init(disstream_info_t *info);
disstream_info_t *disstream_info_malloc_and_init(void);
void disstream_info_free_data(disstream_info_t *info);
void disstream_info_free_all(disstream_info_t *info);
void disstream_packet_free(disstream_packet_t *packet);

void register_tap_listener_disstream(disstream_tapinfo_t *tapinfo, const char *fstring,
    disstream_tap_error_cb tap_error);
void remove_tap_listener_disstream(disstream_tapinfo_t *tapinfo);
void disstream_reset(disstream_tapinfo_t *tapinfo);
void disstream_reset_cb(void *arg);
tap_packet_status disstream_packet_cb(void *arg, packet_info *pinfo, epan_dissect_t *edt,
    const void *arg2, tap_flags_t flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_DIS_COMMON_H__ */