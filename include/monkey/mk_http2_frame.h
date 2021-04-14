#ifndef MK_HTTP2_FRAME_H
#define MK_HTTP2_FRAME_H

#include <monkey/mk_core.h>

/* Frame types */
#define MK_HTTP2_DATA_FRAME               0x0
#define MK_HTTP2_HEADERS_FRAME            0x1
#define MK_HTTP2_PRIORITY_FRAME           0x2
#define MK_HTTP2_RST_STREAM_FRAME         0x3
#define MK_HTTP2_SETTINGS_FRAME           0x4
#define MK_HTTP2_PUSH_PROMISE_FRAME       0x5
#define MK_HTTP2_PING_FRAME               0x6
#define MK_HTTP2_GOAWAY_FRAME             0x7
#define MK_HTTP2_WINDOW_UPDATE_FRAME      0x8
#define MK_HTTP2_CONTINUATION_FRAME       0x9

/* Flags */
#define MK_HTTP2_DATA_END_STREAM          0x1
#define MK_HTTP2_DATA_PADDED              0x8

#define MK_HTTP2_HEADERS_END_STREAM       0x1
#define MK_HTTP2_HEADERS_END_HEADERS      0x4
#define MK_HTTP2_HEADERS_PADDED           0x8
#define MK_HTTP2_HEADERS_PRIORITY         0x20

#define MK_HTTP2_SETTINGS_ACK             0x1

#define MK_HTTP2_PUSH_PROMISE_END_HEADERS 0x4
#define MK_HTTP2_PUSH_PROMISE_PADDED      0x8

#define MK_HTTP2_PING_ACK                 0x1

#define MK_HTTP2_CONTINUATION_END_HEADERS 0x4

/* Structures (they are not 1:1 with the wire format)*/

struct mk_http2_data_frame_payload {
    uint8_t   pad_length;
    size_t    data_length;
    uint8_t  *data_block;
    uint8_t  *padding_block;
};

struct mk_http2_headers_frame_payload {
    uint8_t   pad_length;
    uint32_t  stream_dependency;
    uint8_t   weight;
    size_t    data_length;
    uint8_t  *data_block;
    uint8_t  *padding_block;
};

struct mk_http2_priority_frame_payload {
    uint8_t   exclusive_dependency_flag;
    uint32_t  stream_dependency;
    uint8_t   weight;
};

struct mk_http2_continuation_frame_payload {
    size_t    data_length;
    uint8_t  *data_block;
};

struct mk_http2_rst_stream_frame_payload {
    uint32_t  error_code;
};

struct mk_http2_settings_frame_payload {
    struct mk_http2_setting *entries;
    size_t                   entry_count;
};

struct mk_http2_push_promise_frame_payload {
    uint8_t   pad_length;
    uint32_t  promised_stream_id;
    size_t    data_length;
    uint8_t  *data_block;
    uint8_t  *padding_block;
};

struct mk_http2_ping_frame_payload {
    uint64_t data;
};

struct mk_http2_goaway_frame_payload {
    uint32_t  last_stream_id;
    uint32_t  error_code;
    uint8_t  *additional_debug_data;
    size_t    additional_debug_data_length;
};

struct mk_http2_window_update_frame_payload {
    uint32_t  window_size_increment;
};

struct mk_http2_frame {
    uint32_t  length;
    uint8_t   type;
    uint8_t   flags;
    uint32_t  stream_id;
    uint8_t  *raw_payload;
    union
    {
        struct mk_http2_data_frame_payload          data;
        struct mk_http2_headers_frame_payload       headers;
        struct mk_http2_priority_frame_payload      priority;
        struct mk_http2_rst_stream_frame_payload    rst_stream;
        struct mk_http2_settings_frame_payload      settings;
        struct mk_http2_push_promise_frame_payload  push_promise;
        struct mk_http2_ping_frame_payload          ping;
        struct mk_http2_goaway_frame_payload        goaway;
        struct mk_http2_window_update_frame_payload window_update;
        struct mk_http2_continuation_frame_payload  continuation;
    } payload;
};

#endif