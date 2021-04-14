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


#define _GNU_SOURCE

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_request.h>
#include <monkey/mk_http2_dynamic_table.h>

int mk_http2_stream_create(struct mk_http2_session *ctx, 
                           uint8_t initiator,
                           uint32_t id)
{
    struct mk_http2_stream *new_entry;

    /* Allocate and register queue */
    new_entry = mk_mem_alloc_z(sizeof(struct mk_http2_stream));
    if (NULL == new_entry) {
        perror("malloc");
        return -1;
    }

    /* Metadata */
    new_entry->id = id;
    new_entry->status = MK_HTTP2_STREAM_STATUS_IDLE;
    new_entry->initiator = initiator;

    new_entry->rst_stream_received = 0;
    new_entry->end_stream_received = 0;
    new_entry->end_headers_received = 0;

    new_entry->flow_control_window_size = ctx->remote_settings.initial_window_size;

    new_entry->data_buffer = NULL;
    new_entry->data_buffer_size = 0;
    new_entry->data_buffer_length = 0;

    new_entry->header_buffer = NULL;
    new_entry->header_buffer_size = 0;
    new_entry->header_buffer_length = 0;

    /* Lists */
    new_entry->dynamic_table = mk_http2_dynamic_table_create(
                                ctx->local_settings.max_header_list_size);
    if (NULL == new_entry->dynamic_table) {
        mk_mem_free(new_entry);
        perror("malloc");
        return -1;
    }

    mk_http2_request_init(&new_entry->request, new_entry, ctx);

    mk_list_add(&new_entry->_head, &ctx->http2_streams);

    return id;
}

int mk_http2_stream_destroy(struct mk_http2_session *ctx,
                            struct mk_http2_stream *entry)
{
    (void) ctx;

    mk_http2_dynamic_table_destroy(entry->dynamic_table);
    mk_list_del(&entry->_head);
    mk_mem_free(entry);

    return 0;
}

int mk_http2_stream_destroy_all(struct mk_http2_session *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http2_stream *entry;

    mk_list_foreach_safe(head, tmp, &ctx->http2_streams) {
        entry = mk_list_entry(head, struct mk_http2_stream, _head);
        mk_http2_stream_destroy(ctx, entry);
        c++;
    }

    return c;
}

struct mk_http2_stream *mk_http2_stream_get(struct mk_http2_session *ctx, 
                                            uint8_t initiator, int id)
{
    struct mk_list *head;
    struct mk_http2_stream *q = NULL;

    mk_list_foreach(head, &ctx->http2_streams) {
        q = mk_list_entry(head, struct mk_http2_stream, _head);
        if (q->id == id &&
            q->initiator == initiator) {

            return q;
        }
    }

    return NULL;
}

int mk_http2_stream_apply_initial_window_size_delta(struct mk_http2_session *ctx, 
                                                    int32_t window_size_delta)
{
    struct mk_list *head;
    struct mk_http2_stream *q = NULL;

    if (0 == mk_list_is_empty(&ctx->http2_streams)) {
        return -1;
    }

    mk_list_foreach(head, &ctx->http2_streams) {
        q = mk_list_entry(head, struct mk_http2_stream, _head);

        q->flow_control_window_size += window_size_delta;
    }

    return 0;
}
