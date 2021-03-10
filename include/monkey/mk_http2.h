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

#define MK_HTTP2_UNINITIALIZED                0
#define MK_HTTP2_AWAITING_PREFACE             1
#define MK_HTTP2_UPGRADED                     2 /* Connection was just upgraded */
#define MK_HTTP2_SERVER_SETTINGS_SENT         3 /* Mostly something administrative */
#define MK_HTTP2_AWAITING_CLIENT_SETTINGS     4
#define MK_HTTP2_AWAITING_CLIENT_FRAMES       5
#define MK_HTTP2_AWAITING_CONTINUATION_FRAME  6

#define MK_HTTP2_OK                       9999


#define MK_HTTP2_INCOMPLETE_FRAME         -1
#define MK_HTTP2_FRAME_ERROR              -2
#define MK_HTTP2_FRAME_PROCESSED           0

/*
 * The Client 'sent' the SETTINGS frame according to Section 6.5:
 *
 * https://httpwg.github.io/specs/rfc7540.html#ConnectionHeader
 * https://httpwg.github.io/specs/rfc7540.html#SETTINGS
 */



/* A buffer chunk size */
#define MK_HTTP2_CHUNK                            4096

#define MK_HTTP2_DEFAULT_FLOW_CONTROL_WINDOW_SIZE 65535

#define MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE     2147483647

#define MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT        MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE

#define MK_HTTP2_MAX_FRAME_SIZE                   16777215

#define MK_HTTP2_DEFAULT_MAX_FRAME_SIZE           16384

#define MK_HTTP2_MINIMUM_FRAME_SIZE               9 /* Frame header size */

/*
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
 */

/* Structure to represent a frame, not the wire format */
struct mk_http2_frame {
    uint32_t  length;
    uint8_t   type;
    uint8_t   flags;
    uint32_t  stream_id;
    void     *payload;
};

/* a=target variable, b=bit number to act upon 0-n */
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))

static inline uint32_t mk_http2_bitdec_32u(uint8_t *b) {
    return (uint32_t) ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static inline uint32_t mk_http2_bitdec_stream_id(uint8_t *b) {
    uint32_t sid = mk_http2_bitdec_32u(b);

    BIT_CLEAR(sid, 31);

    return sid;
}

/*
 * 6.0 SETTINGS Frame format
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
 */

struct mk_http2_headers_frame_payload {
    uint8_t   pad_length;
    uint32_t  stream_dependency;
    uint8_t   weight;
    uint8_t   header_block_fragment[];
};

/* HTTP/2 General flags */

/* SETTINGS flags*/
#define MK_HTTP2_SETTINGS_ACK        0x1

/* HEADERS flags*/
#define MK_HTTP2_HEADERS_END_STREAM  0x1
#define MK_HTTP2_HEADERS_END_HEADERS 0x4
#define MK_HTTP2_HEADERS_PADDED      0x8
#define MK_HTTP2_HEADERS_PRIORITY    0x20


/*
 * HTTP/2 Frame types
 */
#define MK_HTTP2_DATA_FRAME                0x0   /* Section 6.1  */
#define MK_HTTP2_HEADERS_FRAME             0x1   /* Section 6.2  */
#define MK_HTTP2_PRIORITY_FRAME            0x2   /* Section 6.3  */
#define MK_HTTP2_RST_STREAM_FRAME          0x3   /* Section 6.4  */
#define MK_HTTP2_SETTINGS_FRAME            0x4   /* Section 6.5  */
#define MK_HTTP2_PUSH_PROMISE_FRAME        0x5   /* Section 6.6  */
#define MK_HTTP2_PING_FRAME                0x6   /* Section 6.7  */
#define MK_HTTP2_GOAWAY_FRAME              0x7   /* Section 6.8  */
#define MK_HTTP2_WINDOW_UPDATE_FRAME       0x8   /* Section 6.9  */
#define MK_HTTP2_CONTINUATION_FRAME        0x9   /* Section 6.10 */

/*
 * HTTP/2 Settings Parameters (Section 6.5.2)
 * ------------------------------------------
 */
#define MK_HTTP2_STREAM_STATUS_IDLE               0x0 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_RESERVED_LOCAL     0x1 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_RESERVED_REMOTE    0x2 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_OPEN               0x3 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_HALF_CLOSED_LOCAL  0x4 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE 0x5 /* Section 5.1*/
#define MK_HTTP2_STREAM_STATUS_CLOSED             0x6 /* Section 5.1*/

/*
 * HTTP/2 Error codes
 * ------------------
 */

/* The associated condition is not a result of an error */
#define MK_HTTP2_NO_ERROR            0x0
/* The endpoint detected an unspecific protocol error */
#define MK_HTTP2_PROTOCOL_ERROR      0x1
/* The endpoint encountered an unexpected internal error */
#define MK_HTTP2_INTERNAL_ERROR      0x2
/* The endpoint detected that its peer violated the flow-control protocol */
#define MK_HTTP2_FLOW_CONTROL_ERROR  0x3
/* The endpoint sent a SETTINGS frame but did not receive a response */
#define MK_HTTP2_SETTINGS_TIMEOUT    0x4
/* The endpoint received a frame after a stream was half-closed */
#define MK_HTTP2_STREAM_CLOSED       0x5
/* The endpoint received a frame with an invalid size */
#define MK_HTTP2_FRAME_SIZE_ERROR    0x6
/* The endpoint refused the stream prior to performing any application processing */
#define MK_HTTP2_REFUSED_STREAM      0x7
/* Used by the endpoint to indicate that the stream is no longer needed */
#define MK_HTTP2_CANCEL              0x8
/* The endpoint is unable to maintain the header compression context for the connection */
#define MK_HTTP2_COMPRESSION_ERROR   0x9
/* The connection established in response to a CONNECT request was reset */
#define MK_HTTP2_CONNECT_ERROR       0xa
/* The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load */
#define MK_HTTP2_ENHANCE_YOUR_CALM   0xb
/* The underlying transport has properties that do not meet minimum security requirements (see Section 9.2) */
#define MK_HTTP2_INADEQUATE_SECURITY 0xc
/* The endpoint requires that HTTP/1.1 be used instead of HTTP/2 */
#define MK_HTTP2_HTTP_1_1_REQUIRED   0xd


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

#define mk_http2_send_raw(conn, buf, length)            \
    mk_stream_set(NULL, MK_STREAM_RAW, &conn->channel,  \
                  buf, length, NULL, NULL, NULL, NULL)


struct mk_http2_dynamic_table_entry {
    struct mk_list _head;
    uint32_t       id;
    char          *name;
    char          *value;
    size_t         size;
};

struct mk_http2_dynamic_table {
    struct mk_list entries;      /* list of dynamic table entries */
    size_t         size;         /* pre-computed size of the entire table */
};

struct mk_http2_stream {
    struct mk_list                 _head;
    int                            id;
    uint32_t                       status;
    uint8_t                        rst_stream_received;
    uint8_t                        end_stream_received;
    struct mk_http2_dynamic_table *dynamic_table;
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
    uint32_t       response_stream_sequence;
    struct mk_list http2_streams;
};

#define mk_http2_session_get(conn)               \
    (struct mk_http2_session *)                  \
    (((void *) conn) + sizeof(struct mk_sched_conn))

#endif
