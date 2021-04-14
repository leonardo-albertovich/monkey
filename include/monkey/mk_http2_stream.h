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

#ifndef MK_HTTP2_STREAM_H
#define MK_HTTP2_STREAM_H

#include <monkey/mk_core.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_http2_request.h>

/* Constants */
/* Stream flags */
#define MK_HTTP2_LOCALLY_INITIATED_STREAM         0x0
#define MK_HTTP2_REMOTELY_INITIATED_STREAM        0x1

/* Stream states */
#define MK_HTTP2_STREAM_STATUS_IDLE               0x0
#define MK_HTTP2_STREAM_STATUS_RESERVED_LOCAL     0x1
#define MK_HTTP2_STREAM_STATUS_RESERVED_REMOTE    0x2
#define MK_HTTP2_STREAM_STATUS_OPEN               0x3
#define MK_HTTP2_STREAM_STATUS_HALF_CLOSED_LOCAL  0x4
#define MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE 0x5
#define MK_HTTP2_STREAM_STATUS_CLOSED             0x6

/* Structures */
struct mk_http2_stream {
    struct mk_list                 _head;
    int                            id;
    uint32_t                       status;
    uint8_t                        initiator;
    struct mk_http2_dynamic_table *dynamic_table;

    int32_t                        flow_control_window_size;

    uint8_t                       *data_buffer;
    size_t                         data_buffer_size;
    size_t                         data_buffer_length;

    uint8_t                       *header_buffer;
    size_t                         header_buffer_size;
    size_t                         header_buffer_length;

    uint8_t                        rst_stream_received;
    uint8_t                        end_stream_received;
    uint8_t                        end_headers_received;

    struct mk_http2_header_table  *outgoing_headers;

    struct mk_http2_request        request;
};

/* Prototypes */
int mk_http2_stream_create(struct mk_http2_session *ctx, 
                           uint8_t initiator,
                           uint32_t id);

int mk_http2_stream_destroy(struct mk_http2_session *ctx,
                            struct mk_http2_stream *entry);


int mk_http2_stream_destroy_all(struct mk_http2_session *ctx);

struct mk_http2_stream *mk_http2_stream_get(struct mk_http2_session *ctx, 
                                            uint8_t initiator, int id);

int mk_http2_stream_apply_initial_window_size_delta(struct mk_http2_session *ctx, 
                                                    int32_t window_size_delta);

#endif
