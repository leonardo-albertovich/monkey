/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MK_HTTP2_H
#define MK_HTTP2_H

#include <stdint.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_http2_dynamic_table.h>

/* Constants */ 
#define MK_HTTP2_PREFACE                     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/* Connection states */
#define MK_HTTP2_UNINITIALIZED                0
#define MK_HTTP2_AWAITING_PREFACE             1
#define MK_HTTP2_UPGRADED                     2 /* Connection was just upgraded */
#define MK_HTTP2_SERVER_SETTINGS_SENT         3 /* Mostly something administrative */
#define MK_HTTP2_AWAITING_CLIENT_SETTINGS     4
#define MK_HTTP2_AWAITING_CLIENT_FRAMES       5
#define MK_HTTP2_AWAITING_CONTINUATION_FRAME  6

/* Frame runner return codes */
#define MK_HTTP2_INCOMPLETE_FRAME -1
#define MK_HTTP2_FRAME_ERROR      -2
#define MK_HTTP2_FRAME_PROCESSED   0

/* A buffer chunk size */
#define MK_HTTP2_CHUNK                            4096
#define MK_HTTP2_DEFAULT_FLOW_CONTROL_WINDOW_SIZE 65535
#define MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE     2147483647
#define MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT        MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE
#define MK_HTTP2_MAX_FRAME_SIZE                   16777215
#define MK_HTTP2_DEFAULT_MAX_FRAME_SIZE           16384
#define MK_HTTP2_MINIMUM_FRAME_SIZE               9 /* Frame header size */


/* HTTP/2 General flags */
/* SETTINGS flags*/
#define MK_HTTP2_SETTINGS_ACK        0x1

/* HEADERS flags*/
#define MK_HTTP2_HEADERS_END_STREAM  0x1
#define MK_HTTP2_HEADERS_END_HEADERS 0x4
#define MK_HTTP2_HEADERS_PADDED      0x8
#define MK_HTTP2_HEADERS_PRIORITY    0x20

/* HTTP/2 Frame types */
#define MK_HTTP2_DATA_FRAME          0x0
#define MK_HTTP2_HEADERS_FRAME       0x1
#define MK_HTTP2_PRIORITY_FRAME      0x2
#define MK_HTTP2_RST_STREAM_FRAME    0x3
#define MK_HTTP2_SETTINGS_FRAME      0x4
#define MK_HTTP2_PUSH_PROMISE_FRAME  0x5
#define MK_HTTP2_PING_FRAME          0x6
#define MK_HTTP2_GOAWAY_FRAME        0x7
#define MK_HTTP2_WINDOW_UPDATE_FRAME 0x8
#define MK_HTTP2_CONTINUATION_FRAME  0x9

/* HTTP/2 Error codes */
#define MK_HTTP2_NO_ERROR            0x0
#define MK_HTTP2_PROTOCOL_ERROR      0x1
#define MK_HTTP2_INTERNAL_ERROR      0x2
#define MK_HTTP2_FLOW_CONTROL_ERROR  0x3
#define MK_HTTP2_SETTINGS_TIMEOUT    0x4
#define MK_HTTP2_STREAM_CLOSED       0x5
#define MK_HTTP2_FRAME_SIZE_ERROR    0x6
#define MK_HTTP2_REFUSED_STREAM      0x7
#define MK_HTTP2_CANCEL              0x8
#define MK_HTTP2_COMPRESSION_ERROR   0x9
#define MK_HTTP2_CONNECT_ERROR       0xa
#define MK_HTTP2_ENHANCE_YOUR_CALM   0xb
#define MK_HTTP2_INADEQUATE_SECURITY 0xc
#define MK_HTTP2_HTTP_1_1_REQUIRED   0xd

/* Structures */
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

struct mk_http2_header_pair {
    char *name;
    char *value;
};

struct mk_http2_session {
    int status;

    /* Buffer used to read data */
    unsigned int buffer_size;
    unsigned int buffer_length;
    uint8_t     *buffer;
    uint8_t      buffer_fixed[MK_HTTP2_CHUNK];

    /* Session Settings */
    struct mk_http2_settings remote_settings;
    struct mk_http2_settings local_settings;

    struct mk_stream stream;

    /* Protocol specific metadata */
    uint32_t       expected_continuation_stream;
    uint32_t       response_stream_id_sequence;

    struct mk_list http2_streams;

    uint32_t       locally_initiated_open_stream_count;
    uint32_t       remotely_initiated_open_stream_count;

    uint32_t       maximum_locally_initiated_stream_id;
    uint32_t       maximum_remotely_initiated_stream_id;
};

/* Macros */

/* a=target variable, b=bit number to act upon 0-n */
#define BIT_CHECK(a,b) (0 != ((a) & (1<<(b))))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))

static inline uint32_t mk_http2_bitdec_32u(uint8_t *b) {
    return (uint32_t) ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static inline uint32_t mk_http2_bitdec_stream_id(uint8_t *b) {
    uint32_t sid = mk_http2_bitdec_32u(b);

    BIT_CLEAR(sid, 31);

    return sid;
}

#define mk_http2_send_raw(conn, buf, length)            \
    mk_stream_set(NULL, MK_STREAM_RAW, &conn->channel,  \
                  buf, length, NULL, NULL, NULL, NULL)


#define mk_http2_session_get(conn)               \
    (struct mk_http2_session *)                  \
    (((void *) conn) + sizeof(struct mk_sched_conn))

#ifdef TRACE
#define MK_H2_TRACE(conn, fmt, ...)                                     \
    mk_utils_trace("mk",                                                \
                   MK_TRACE_CORE,                                       \
                   __FUNCTION__, __FILENAME__, __LINE__,                \
                   "[%sH2%s] (fd=%i) " fmt,                             \
                   ANSI_RESET ANSI_WHITE, ANSI_RED,                     \
                   conn->event.fd, ##__VA_ARGS__)
#else
#define MK_H2_TRACE(...) do {} while (0)
#endif

/* Protocol :
 *
 * 4.1 HTTP2 Frame format
 *
 * +-----------------------------------------------+
 * |                 Length (24)                   |
 * +---------------+---------------+---------------+
 * |   Type (8)    |   Flags (8)   |
 * +-+-------------+---------------+-------------------------------+
 * |R|                 Stream Identifier (31)                      |
 * +=+=============================================================+
 * |                   Frame Payload (0...)                      ...
 * +---------------------------------------------------------------+
 *
 * 6.1 DATA Frame format
 *
 * +---------------+
 * |Pad Length? (8)|
 * +---------------+-----------------------------------------------+
 * |                            Data (*)                         ...
 * +---------------------------------------------------------------+
 * |                           Padding (*)                       ...
 * +---------------------------------------------------------------+
 *
 * 6.2 HEADERS Frame format
 *
 * +---------------+
 * |Pad Length? (8)|
 * +-+-------------+-----------------------------------------------+
 * |E|                 Stream Dependency? (31)                     |
 * +-+-------------+-----------------------------------------------+
 * |  Weight? (8)  |
 * +-+-------------+-----------------------------------------------+
 * |                   Header Block Fragment (*)                 ...
 * +---------------------------------------------------------------+
 * |                           Padding (*)                       ...
 * +---------------------------------------------------------------+
 *
 *
 * 6.3 PRIORITY Frame format
 *
 * +-+-------------------------------------------------------------+
 * |E|                  Stream Dependency (31)                     |
 * +-+-------------+-----------------------------------------------+
 * |   Weight (8)  |
 * +-+-------------+
 *
 *
 * 6.4 RST_STREAM Frame format
 *
 * +---------------------------------------------------------------+
 * |                        Error Code (32)                        |
 * +---------------------------------------------------------------+
 *
 *
 * 6.5 SETTINGS Frame Format
 *
 * +-------------------------------+
 * |       Identifier (16)         |
 * +-------------------------------+-------------------------------+
 * |                        Value (32)                             |
 * +---------------------------------------------------------------+
 *
 *
 * 6.6 PUSH_PROMISE Frame Format
 *
 * +---------------+
 * |Pad Length? (8)|
 * +-+-------------+-----------------------------------------------+
 * |R|                  Promised Stream ID (31)                    |
 * +-+-----------------------------+-------------------------------+
 * |                   Header Block Fragment (*)                 ...
 * +---------------------------------------------------------------+
 * |                           Padding (*)                       ...
 * +---------------------------------------------------------------+
 *
 *
 * 6.7 PING Frame Format
 *
 * +---------------------------------------------------------------+
 * |                                                               |
 * |                      Opaque Data (64)                         |
 * |                                                               |
 * +---------------------------------------------------------------+
 *
 *
 * 6.8 GOAWAY Frame Format
 *
 * +-+-------------------------------------------------------------+
 * |R|                  Last-Stream-ID (31)                        |
 * +-+-------------------------------------------------------------+
 * |                      Error Code (32)                          |
 * +---------------------------------------------------------------+
 * |                  Additional Debug Data (*)                    |
 * +---------------------------------------------------------------+
 *
 */

 /*
  *  Error codes :
  *
  *  MK_HTTP2_NO_ERROR
  *    The associated condition is not a result of an error
  *
  *  MK_HTTP2_PROTOCOL_ERROR
  *    The endpoint detected an unspecific protocol error 
  *
  *  MK_HTTP2_INTERNAL_ERROR
  *    The endpoint encountered an unexpected internal error 
  *
  *  MK_HTTP2_FLOW_CONTROL_ERROR
  *    The endpoint detected that its peer violated the flow-control protocol 
  *
  *  MK_HTTP2_SETTINGS_TIMEOUT
  *    The endpoint sent a SETTINGS frame but did not receive a response 
  *
  *  MK_HTTP2_STREAM_CLOSED
  *    The endpoint received a frame after a stream was half-closed 
  *
  *  MK_HTTP2_FRAME_SIZE_ERROR
  *    The endpoint received a frame with an invalid size 
  *
  *  MK_HTTP2_REFUSED_STREAM
  *    The endpoint refused the stream prior to performing any application processing 
  *
  *  MK_HTTP2_CANCEL
  *    Used by the endpoint to indicate that the stream is no longer needed 
  *
  *  MK_HTTP2_COMPRESSION_ERROR
  *    The endpoint is unable to maintain the header compression context for the 
  *    connection 
  *
  *  MK_HTTP2_CONNECT_ERROR
  *    The connection established in response to a CONNECT request was reset 
  *
  *  MK_HTTP2_ENHANCE_YOUR_CALM
  *    The endpoint detected that its peer is exhibiting a behavior that might be 
  *    generating excessive load 
  *
  *  MK_HTTP2_INADEQUATE_SECURITY
  *    The underlying transport has properties that do not meet minimum security 
  *    requirements (see Section 9.2) 
  *
  *  MK_HTTP2_HTTP_1_1_REQUIRED
  *    The endpoint requires that HTTP/1.1 be used instead of HTTP/2 
  *
*/



#endif
