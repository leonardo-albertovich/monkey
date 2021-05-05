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

#include <monkey/mk_core.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_http_base.h>
#include <monkey/mk_http2_settings.h>

/* Constants */ 
#define MK_HTTP2_PREFACE                     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

/* Connection states */
#define MK_HTTP2_UNINITIALIZED               0
#define MK_HTTP2_AWAITING_PREFACE            1
#define MK_HTTP2_UPGRADED                    2 /* Connection was just upgraded */
#define MK_HTTP2_SERVER_SETTINGS_SENT        3 /* Mostly something administrative */
#define MK_HTTP2_AWAITING_CLIENT_SETTINGS    4
#define MK_HTTP2_AWAITING_CLIENT_FRAMES      5
#define MK_HTTP2_AWAITING_CONTINUATION_FRAME 6
#define MK_HTTP2_DISPATCHING_REQUEST_HANDLER 7
#define MK_HTTP2_EXECUTING_REQUEST_HANDLER   8

/* Frame runner return codes */
#define MK_HTTP2_INCOMPLETE_FRAME -1
#define MK_HTTP2_FRAME_ERROR      -2
#define MK_HTTP2_UNKNOWN_FRAME    -3
#define MK_HTTP2_FRAME_PROCESSED   0

/* A buffer chunk size */
#define MK_HTTP2_CHUNK                            4096
#define MK_HTTP2_DEFAULT_FLOW_CONTROL_WINDOW_SIZE 65535
#define MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE     2147483647
#define MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT        MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE
#define MK_HTTP2_MAX_FRAME_SIZE                   16777215
#define MK_HTTP2_DEFAULT_MAX_FRAME_SIZE           16384
#define MK_HTTP2_MINIMUM_FRAME_SIZE               9 /* Frame header size */

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

/* Macros */

/* a=target variable, b=bit number to act upon 0-n */
#define BIT_CHECK(a,b) (0 != ((a) & (1<<(b))))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_SET(a,b) ((a) |= (1<<(b)))

static inline void mk_http2_bitenc_32u(uint8_t *o, uint32_t v) {
    o[0] = (uint8_t)((v & 0xFF000000) >> 24);
    o[1] = (uint8_t)((v & 0x00FF0000) >> 16);
    o[2] = (uint8_t)((v & 0x0000FF00) >> 8);
    o[3] = (uint8_t)((v & 0x000000FF) >> 0);
}

static inline uint32_t mk_http2_bitdec_32u(uint8_t *b) {
    return (uint32_t) ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static inline uint32_t mk_http2_bitdec_stream_id(uint8_t *b) {
    uint32_t sid = mk_http2_bitdec_32u(b);

    BIT_CLEAR(sid, 31);

    return sid;
}

static inline void mk_http2_bitenc_stream_id(uint8_t *o, uint32_t v) {
    BIT_CLEAR(v, 31);

    mk_http2_bitenc_32u(o, v);
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


struct mk_http2_session {
    struct mk_http_base_session base;

    int status;

    /* Buffer used to read data */
    unsigned int buffer_size;
    unsigned int buffer_length;
    uint8_t     *buffer;
    uint8_t      buffer_fixed[MK_HTTP2_CHUNK];

    /* Session Settings */
    struct mk_http2_settings remote_settings;
    struct mk_http2_settings local_settings;

    struct mk_sched_conn *connection;
    struct mk_server *server;
    struct mk_stream  stream;

    /* Protocol specific metadata */
    uint32_t       expected_continuation_stream;
    uint32_t       response_stream_id_sequence;

    int32_t        flow_control_window_size;

    struct mk_list http2_streams;

    uint32_t       locally_initiated_open_stream_count;
    uint32_t       remotely_initiated_open_stream_count;

    uint32_t       maximum_locally_initiated_stream_id;
    uint32_t       maximum_remotely_initiated_stream_id;
};

int mk_http2_request_end(struct mk_http2_session *cs, struct mk_server *server);
int mk_http2_error(int http_status, 
                   struct mk_http2_session *cs,
                   struct mk_http2_request *sr,
                   struct mk_server *server);

#endif

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
