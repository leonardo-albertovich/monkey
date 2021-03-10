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

#include <inttypes.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_header.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_scheduler.h>

/* HTTP/2 Connection Preface */
#define MK_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
static mk_ptr_t http2_preface = {
    .data = MK_HTTP2_PREFACE,
    .len  = sizeof(MK_HTTP2_PREFACE) - 1
};


int mk_http2_dynamic_table_entry_destroy(struct mk_http2_dynamic_table *ctx, 
                                         struct mk_http2_dynamic_table_entry *entry)
{
    (void) ctx;

    mk_mem_free(entry->name);
    mk_mem_free(entry->value);

    mk_list_del(&entry->_head);
    mk_mem_free(entry);

    return 0;
}

static int mk_http2_dynamic_table_entry_destroy_all(struct mk_http2_dynamic_table *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http2_dynamic_table_entry *entry;

    mk_list_foreach_safe(head, tmp, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);
        mk_http2_dynamic_table_entry_destroy(ctx, entry);
        c++;
    }

    return c;
}

/* NOTE: This list is a fifo, older entries will be evicted as needed */
int mk_http2_dynamic_table_entry_create(struct mk_http2_dynamic_table *ctx, 
                                        char *name,
                                        char *value)
{
    struct mk_http2_dynamic_table_entry *new_entry;
    struct mk_http2_dynamic_table_entry *first_entry;
    struct mk_list                      *insertion_point;
    int id;

    id = -1;

    /* Get ID for the new entry */
    if (mk_list_is_empty(&ctx->entries) == 0) {
        id = 0;
        insertion_point = &ctx->entries;
    }
    else {
        first_entry = mk_list_entry_first(&ctx->entries, 
                                          struct mk_http2_dynamic_table_entry, _head);

        insertion_point = &first_entry->_head;

        id = first_entry->id + 1;
    }


    /* Allocate and register queue */
    new_entry = mk_mem_alloc(sizeof(struct mk_http2_dynamic_table_entry));
    if (NULL == new_entry) {
        perror("malloc");
        return -1;
    }

    new_entry->id = id;

    new_entry->name = mk_mem_alloc(strlen(name) + 1);
    if (NULL == new_entry->name) {
        perror("malloc");
        return -2;
    }

    new_entry->value = mk_mem_alloc(strlen(value) + 1);
    if (NULL == new_entry->value) {
        perror("malloc");
        return -2;
    }

    /* We are using strlen to measure it previously, there is no reason to explicitly
     * use it here
    */
    strcpy(new_entry->name,  name);
    strcpy(new_entry->value, value);

    new_entry->size = strlen(name) + strlen(value) + 2;

    ctx->size += new_entry->size;

    /* TODO : verify that this is the correct way to prepend to a list (even though
     *        it works)
     */
    mk_list_add(&new_entry->_head, insertion_point);

    return id;
}

struct mk_http2_dynamic_table *mk_http2_dynamic_table_create()
{
    struct mk_http2_dynamic_table *ctx;

    ctx = mk_mem_alloc(sizeof(struct mk_http2_dynamic_table));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    /* Metadata */
    ctx->size = 0;

    /* Lists */
    mk_list_init(&ctx->entries);

    return ctx;
}

int mk_http2_dynamic_table_destroy(struct mk_http2_dynamic_table *ctx)
{
    mk_http2_dynamic_table_entry_destroy_all(ctx);
    mk_mem_free(ctx);
    return 0;
}

int mk_http2_stream_create(struct mk_http2_session *ctx, 
                           uint32_t id)
{
    struct mk_http2_stream *new_entry;

    /* Allocate and register queue */
    new_entry = mk_mem_alloc(sizeof(struct mk_http2_stream));
    if (NULL == new_entry) {
        perror("malloc");
        return -1;
    }

    /* Metadata */
    new_entry->id = id;
    new_entry->status = MK_HTTP2_STREAM_STATUS_IDLE;

    /* Lists */
    new_entry->dynamic_table = mk_http2_dynamic_table_create();
    if (NULL == new_entry->dynamic_table) {
        mk_mem_free(new_entry);
        perror("malloc");
        return -1;
    }

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

static int mk_http2_stream_destroy_all(struct mk_http2_session *ctx)
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

struct mk_http2_stream *mk_http2_stream_get(struct mk_http2_session *ctx, int id)
{
    struct mk_list *head;
    struct mk_http2_stream *q = NULL;

    mk_list_foreach(head, &ctx->http2_streams) {
        q = mk_list_entry(head, struct mk_http2_stream, _head);
        if (q->id == id) {
            return q;
        }
    }

    return NULL;
}




static inline void buffer_consume(struct mk_http2_session *h2s, int bytes) {
    memmove(h2s->buffer,
            h2s->buffer + bytes,
            h2s->buffer_length - bytes);

    MK_TRACE("[h2] consume buffer length from %i to %i",
             h2s->buffer_length, h2s->buffer_length - bytes);

    h2s->buffer_length -= bytes;
}

/* Enqueue an error response. This function always returns MK_EXIT_OK */
/* TODO : Define and implement this function properly */
int mk_http2_error(int error_code, 
                   struct mk_server *server) {
    (void) error_code;
    (void) server;

    return 0;
}

/* Handle an upgraded session */
static int mk_http2_upgrade(void *cs, void *sr, struct mk_server *server) {
    struct mk_http_session *s = cs;
    struct mk_http_request *r = sr;
    struct mk_http2_session *h2s;

    mk_header_set_http_status(r, MK_INFO_SWITCH_PROTOCOL);
    r->headers.connection = MK_HEADER_CONN_UPGRADED;
    r->headers.upgrade = MK_HEADER_UPGRADED_H2C;
    mk_header_prepare(s, r, server);

    h2s = mk_http2_session_get(s->conn);

    h2s->status = MK_HTTP2_UPGRADED;

    s->conn->data = h2s;

    return MK_HTTP_OK;
}

static inline void mk_http2_frame_decode_header(uint8_t *buf,
                                                struct mk_http2_frame *frame) {
    frame->length    = mk_http2_bitdec_32u(buf) >> 8;
    frame->type      = mk_http2_bitdec_32u(buf) &  0xFF;
    frame->flags     = buf[4];
    frame->stream_id = mk_http2_bitdec_stream_id(&buf[5]);
    frame->payload   = &buf[MK_HTTP2_MINIMUM_FRAME_SIZE];

#ifdef MK_HAVE_TRACE
    MK_TRACE("Frame Header");

    printf(" length=%i, type=%i, stream_id=%i\n",
           frame->length,
           frame->type,
           frame->stream_id);
#endif
}

static inline int mk_http2_handle_continuation_frame(struct mk_sched_conn *conn,
                                                     struct mk_http2_frame *frame) {
    // struct mk_http2_session *h2s;
    // struct mk_http2_headers_frame_payload *headers;

    (void) conn;
    (void) frame;

    return 0;
}

static inline int mk_http2_handle_headers_frame(struct mk_sched_conn *conn,
                                                struct mk_http2_frame *frame,
                                                struct mk_http2_stream *stream
                                                ) {
    struct mk_http2_session               *h2s;
    struct mk_http2_headers_frame_payload *headers;
    int                                    result;

    (void) conn;
    (void) frame;
    (void) stream;

    if (0 == frame->stream_id) {
        MK_TRACE("HEADERS ERROR, ZERO STREAM ID : %i\n", frame->stream_id);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    h2s = mk_http2_session_get(conn);

    stream->status = MK_HTTP2_STREAM_STATUS_OPEN;

    if (0 == (MK_HTTP2_HEADERS_END_HEADERS & frame->flags)) {
        /*
         * If we don't receive the END_HEADERS flag we need
         * to signal the session to expect a CONTINUATION 
         * frame for this stream.
         * 
         */

        h2s->status = MK_HTTP2_AWAITING_CONTINUATION_FRAME;

        h2s->expected_continuation_stream = frame->stream_id;
    }

    if (0 != (MK_HTTP2_HEADERS_END_STREAM & frame->flags)) {
        stream->status = MK_HTTP2_STREAM_STATUS_HALF_CLOSED;
    }

    headers = (struct mk_http2_headers_frame_payload *) frame->payload;

    printf("HEADERS FOR STREAM : %i\n", frame->stream_id);
    printf("FLAGS : %i\n", frame->flags);
    printf("END_HEADERS PRESENT? : %i\n", frame->flags & MK_HTTP2_HEADERS_END_HEADERS);
    printf("\n\n");

    return MK_HTTP2_NO_ERROR;
}

static inline int mk_http2_handle_window_update_frame(struct mk_sched_conn *conn,
                                                      struct mk_http2_frame *frame) {
    uint32_t window_size_increment;

    (void) conn;
    (void) frame;

    // struct mk_http2_session *h2s;

    // h2s = mk_http2_session_get(conn);

    if (4 != frame->length) {
        MK_TRACE("WINDOW UPDATE FRAME WITH A SIZE THAT IS NOT 4 : %i\n",
                 frame->length);

        return MK_HTTP2_FRAME_SIZE_ERROR;
    }

    window_size_increment = mk_http2_bitdec_32u((uint8_t *)frame->payload);
    BIT_CLEAR(window_size_increment, 31);

    if (0 == window_size_increment ||
       MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT < window_size_increment) {
        MK_H2_TRACE(conn, "INVALID VALUE FOR WINDOW_SIZE_INCREMENT %i",
                    window_size_increment);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    /* TODO : Actually handle this, at the moment nothing related to it is implemented
              but getting it out of the frame queue is the goal*/
    /*
    if (0 == frame->stream_id) {
    }
    */

    return MK_HTTP2_NO_ERROR;
}

static inline int mk_http2_handle_settings(struct mk_sched_conn *conn,
                                           struct mk_http2_frame *frame) {
    size_t                   setting_entry_list_length;
    size_t                   setting_entry_list_index;
    struct mk_http2_setting *setting_entry_list;
    struct mk_http2_setting *setting_entry;
    struct mk_http2_session *h2s;

    h2s = mk_http2_session_get(conn);

    if (0 != frame->stream_id) {
        MK_TRACE("SETTINGS ERROR, NON ZERO STREAM ID : %i\n", frame->stream_id);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    if (MK_HTTP2_SETTINGS_ACK == frame->flags) {
        /*
         * Nothing to do, the peer just received our SETTINGS and it's
         * sending an acknowledge.
         *
         * note: validate that frame length is zero.
         */

        if (0 != frame->length) {
            /*
             * This must he handled as a connection error, we must reply
             * with a FRAME_SIZE_ERROR. ref:
             *
             *  https://httpwg.github.io/specs/rfc7540.html#SETTINGS
             */

            MK_TRACE("SETTINGS ERROR, ACK FRAME WITH NON ZERO SIZE : %i\n", 
                     frame->length);

            return MK_HTTP2_FRAME_SIZE_ERROR;
        }

        h2s->remote_settings.acknowledgement_flag = 1;

        return MK_HTTP2_NO_ERROR;
    }

    setting_entry_list = (struct mk_http2_setting *) frame->payload;

    setting_entry_list_length = \
        mk_http2_frame_size_to_setting_entry_count(frame->length);

    for(setting_entry_list_index = 0,
        setting_entry = &setting_entry_list[0] ;
        setting_entry_list_index < setting_entry_list_length ;
        setting_entry_list_index++,
        setting_entry++) {

       MK_H2_TRACE(conn, "[Setting] Id=%i Value=%i",
                   setting_entry->identifier,
                   setting_entry->value);

       switch (setting_entry->identifier) {
       case MK_HTTP2_SETTINGS_HEADER_TABLE_SIZE:
            h2s->remote_settings.header_table_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_ENABLE_PUSH:
           if (setting_entry->value != 0 && 
               setting_entry->value != 1) {
               MK_H2_TRACE(conn, "INVALID VALUE FOR SETTINGS_ENABLE_PUSH L %i",
                           setting_entry->value);

               return MK_HTTP2_PROTOCOL_ERROR;
           }

           h2s->remote_settings.enable_push = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
           h2s->remote_settings.max_concurrent_streams = setting_entry->value;

           MK_H2_TRACE(conn, "SETTINGS MAX_CONCURRENT_STREAMS=%i",
                       setting_entry->value);

           break;

       case MK_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
           if (MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE < setting_entry->value) {
               MK_H2_TRACE(conn, "INVALID INITIAL_WINDOW_SIZE : %i",
                           setting_entry->value);

               return MK_HTTP2_FLOW_CONTROL_ERROR;
           }

           h2s->remote_settings.initial_window_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_FRAME_SIZE:
           if (MK_HTTP2_MAX_FRAME_SIZE < setting_entry->value) {
               MK_H2_TRACE(conn, "INVALID SETTINGS_MAX_FRAME_SIZE : %i",
                           setting_entry->value);

               return MK_HTTP2_PROTOCOL_ERROR;
           }

           h2s->remote_settings.max_frame_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
           h2s->remote_settings.max_header_list_size = setting_entry->value;

           break;

       default:
           /*
            * 5.5 Extending HTTP/2: ...Implementations MUST ignore unknown
            * or unsupported values in all extensible protocol elements...
            */
           break;
       }
    }

    mk_stream_in_raw(&h2s->stream,
                     NULL,
                     MK_HTTP2_SETTINGS_ACK_FRAME,
                     sizeof(MK_HTTP2_SETTINGS_ACK_FRAME) - 1,
                     NULL, NULL);

    mk_channel_flush(h2s->stream.channel);

    return 0;
}


static inline int mk_http2_frame_run(struct mk_sched_conn *conn,
                                     struct mk_sched_worker *worker,
                                     struct mk_server *server) {
    struct mk_http2_stream  *stream;
    struct mk_http2_frame    frame;
    struct mk_http2_session *h2s;
    int    result;

    (void) worker;

    stream = NULL;
    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_MINIMUM_FRAME_SIZE <= h2s->buffer_length) {
        MK_H2_TRACE(conn, "HTTP/2 SESSION SETTINGS RECEIVED");

        /* Decode the frame header */
        mk_http2_frame_decode_header(h2s->buffer, &frame);

        if (frame.length > h2s->local_settings.max_frame_size) {
            MK_TRACE("[FD %i] Frame size exceeds the one agreed upon", 
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_FRAME_SIZE_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }

        if ((MK_HTTP2_MINIMUM_FRAME_SIZE + frame.length) > h2s->buffer_length) {
            return MK_HTTP2_INCOMPLETE_FRAME; /* We need more data */
        }
    }
    else {
        return MK_HTTP2_INCOMPLETE_FRAME; /* We need more data */
    }

    printf("FRAME TYPE = %d\n", frame.type);
    printf("FRAME DATA\n\n");
    mk_utils_hexdump(frame.payload, frame.length, 16);
    printf("\n\n");

    if (MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status) {
        if (MK_HTTP2_SETTINGS_FRAME != frame.type) {
            MK_TRACE("[FD %i] First frame received should be a settings frame",
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }
    }

    if (MK_HTTP2_AWAITING_CONTINUATION_FRAME == h2s->status) {
        if (MK_HTTP2_CONTINUATION_FRAME != frame.type) {
            MK_TRACE("[FD %i] Wrong frame type received while awaiting a CONTINUATION " 
                     " frame",
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }

        if (frame.stream_id != h2s->expected_continuation_stream) {
            MK_TRACE("[FD %i] Wrong stream id [%i] received while awaiting a " 
                     " CONTINUATION frame for stream [%i]",
                     conn->event.fd, 
                     frame.stream_id,
                     h2s->expected_continuation_stream);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }
    }

    if(0 != frame.stream_id) {
        stream = mk_http2_stream_get(h2s, frame.stream_id);

        if(NULL == stream) {
            result = mk_http2_stream_create(h2s, frame.stream_id);

            if(0 > result) {
                /* TRACE ERROR */
                return MK_HTTP2_INTERNAL_ERROR;
            }

            stream = mk_http2_stream_get(h2s, frame.stream_id);

            if(NULL == stream) {
                /* TRACE ERROR */
                return MK_HTTP2_INTERNAL_ERROR;
            }
        }
    }

    if (NULL != stream) {
        if (MK_HTTP2_STREAM_STATUS_IDLE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME   != frame.type &&
                MK_HTTP2_PRIORITY_FRAME     != frame.type &&
                MK_HTTP2_CONTINUATION_FRAME != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_RESERVED_LOCAL == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_RESERVED_REMOTE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME != frame.type &&
                MK_HTTP2_PRIORITY_FRAME   != frame.type &&
                MK_HTTP2_HEADERS_FRAME    != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                return MK_HTTP2_STREAM_CLOSED;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_CLOSED == stream->status) {
            if(1 == stream->rst_stream_received) {
                if (MK_HTTP2_PRIORITY_FRAME      != frame.type) {
                    return MK_HTTP2_STREAM_CLOSED;
                }
            }
            else if(1 == stream->end_stream_received) {
                /* This actually depends on the time after a DATA or HEADERS frame
                 * was sent with the END_STREAM flag toggled, since we are not 
                 * saving that timestamp, it needs further improvement to be
                 * compliant. Section 5.1
                 */
                if (MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                    MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                    MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                    return MK_HTTP2_PROTOCOL_ERROR;
                }
            }
        }
    }
    
    if (MK_HTTP2_SETTINGS_FRAME == frame.type) {
        result = mk_http2_handle_settings(conn, &frame);

        if (MK_HTTP2_FRAME_PROCESSED == result) {
            if (MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status) {
                h2s->status = MK_HTTP2_AWAITING_CLIENT_FRAMES;
            }
        }
    }
    else if (MK_HTTP2_WINDOW_UPDATE_FRAME == frame.type) {
        result = mk_http2_handle_window_update_frame(conn, &frame);
    }
    else if (MK_HTTP2_HEADERS_FRAME == frame.type) {
        result = mk_http2_handle_headers_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_CONTINUATION_FRAME == frame.type) {
        result = mk_http2_handle_continuation_frame(conn, &frame);
    }

    buffer_consume(h2s, MK_HTTP2_MINIMUM_FRAME_SIZE + frame.length);

    if (MK_HTTP2_NO_ERROR != result) {
        mk_http2_error(result, server);

        return MK_HTTP2_FRAME_ERROR;
    }


    return MK_HTTP2_FRAME_PROCESSED;
}

static int mk_http2_sched_read(struct mk_sched_conn *conn,
                               struct mk_sched_worker *worker,
                               struct mk_server *server) {
    int                      frame_result;
    int                      new_size;
    int                      bytes;
    uint8_t                 *tmp;
    struct mk_http2_session *h2s;

    (void) worker;
    (void) server;

// {
//     static int test_flag = 0;

//     if(0 == test_flag)
//     {
//         struct mk_http2_dynamic_table *dt;

//         test_flag = 1;

//         dt = mk_http2_dynamic_table_create();

//         printf("DT = %p\n", dt);


//         if(NULL != dt)
//         {
//             int c;
//             struct mk_list *head;
//             struct mk_http2_dynamic_table_entry *q;

//             mk_http2_dynamic_table_entry_create(dt, "entry 1", "value 1");
//             mk_http2_dynamic_table_entry_create(dt, "entry 2", "value 2");
//             mk_http2_dynamic_table_entry_create(dt, "entry 3", "value 3");
//             mk_http2_dynamic_table_entry_create(dt, "entry 4", "value 4");

//             c = 0;
//             mk_list_foreach(head, &dt->entries) {
//                 q = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);

//                 printf("ENTRY %02d : [%d] [%s] - [%s]\n", c, q->id, q->name, q->value);

//                 c++;
//             }


//         }

//         printf("\n\n");
//     }

// }

    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_UNINITIALIZED == h2s->status ||
       MK_HTTP2_UPGRADED == h2s->status) {
        h2s->buffer = h2s->buffer_fixed;
        h2s->buffer_size = MK_HTTP2_CHUNK;
        h2s->buffer_length = 0;

        h2s->response_stream_sequence = 2;

        mk_list_init(&h2s->http2_streams);

        mk_stream_set(&h2s->stream,
                      &conn->channel,
                      NULL,
                      NULL, NULL, NULL);

        h2s->status = MK_HTTP2_AWAITING_PREFACE;
    }

    if (0 == (h2s->buffer_size - h2s->buffer_length)) {
        new_size = h2s->buffer_size + MK_HTTP2_CHUNK;

        if (h2s->buffer == h2s->buffer_fixed) {
            h2s->buffer = mk_mem_alloc(new_size);

            /* FIXME: send internal server error ? */
            if (NULL == h2s->buffer) {
                return -1;
            }

            memcpy(h2s->buffer, h2s->buffer_fixed, h2s->buffer_length);

            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer new size: %i, length: %i",
                     conn->event.fd, new_size, h2s->buffer_length);
        }
        else {
            tmp = (uint8_t *) mk_mem_realloc(h2s->buffer, new_size);

            /* FIXME: send internal server error ? */
            if (NULL == tmp) {
                return -1;
            }

            h2s->buffer = tmp;
            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer realloc from %i to %i",
                     conn->event.fd, h2s->buffer_size, new_size);
        }
    }

    /* Read the incoming data */
    bytes = mk_sched_conn_read(conn,
                               &h2s->buffer[h2s->buffer_length],
                               h2s->buffer_size - h2s->buffer_length);

    if (0 == bytes) {
        errno = 0;
        return -1;
    }
    else if (-1 == bytes) {
        return -1;
    }

    h2s->buffer_length += bytes;

    printf("JUST READ %d BYTES\n", bytes);

    mk_utils_hexdump(h2s->buffer, h2s->buffer_length, 16);

    printf("h2s->status = %d\n", h2s->status);

    if (MK_HTTP2_AWAITING_PREFACE == h2s->status || /* This is either a prior
                                                       knowledge plaintext or
                                                       direct TLS HTTP/2
                                                       request */
        MK_HTTP2_UPGRADED == h2s->status) { /* Upgraded connections from HTTP/1.x
                                               requires the preface */
        if (h2s->buffer_length >= http2_preface.len) {
            if (0 != memcmp(h2s->buffer,
                            http2_preface.data, http2_preface.len)) {
                MK_H2_TRACE(conn, "Invalid HTTP/2 preface");

                return 0;
            }

            MK_H2_TRACE(conn, "HTTP/2 preface OK");

            buffer_consume(h2s, http2_preface.len);

            h2s->local_settings = MK_HTTP2_SETTINGS_DEFAULT;

            /* Send out our default settings */
            /* TODO: Do we really want to send a pre serialized structure?
                     what's the performance vs readability relationship here? */

            mk_stream_in_raw(&h2s->stream,
                             NULL,
                             MK_HTTP2_SETTINGS_DEFAULT_FRAME,
                             sizeof(MK_HTTP2_SETTINGS_DEFAULT_FRAME) - 1,
                             NULL, NULL);

            /* Ideally we won't flush the channel every time, this is a
               crutch */
            mk_channel_flush(h2s->stream.channel);

            // mk_event_add(mk_sched_loop(),
            //              h2s->stream.channel->fd,
            //              MK_EVENT_CONNECTION,
            //              MK_EVENT_WRITE,
            //              h2s->stream.channel->event);

            h2s->status = MK_HTTP2_AWAITING_CLIENT_SETTINGS;
        }
        else {
            return 0; /* We need more data */
        }
    }

    do {
        frame_result = mk_http2_frame_run(conn, worker, server);
    }
    while (MK_HTTP2_FRAME_PROCESSED == frame_result);

    if (MK_HTTP2_FRAME_ERROR == frame_result) {
        return -1;
    }

    return 0;
}

/* The scheduler got a connection close event from the remote client */
int mk_http2_sched_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type, struct mk_server *server)
{
    struct mk_http2_session *h2s;

    (void) server;
    (void) sched;
    (void) type;

    /* Release resources of the requests and session */
    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_UNINITIALIZED != h2s->status) {
        if (h2s->buffer != h2s->buffer_fixed &&
            NULL != h2s->buffer) {
            mk_mem_free(h2s->buffer);
        }

        h2s->buffer = NULL;
        h2s->buffer_size = 0;
        h2s->buffer_length = 0;

        mk_http2_stream_destroy_all(h2s);

        h2s->status = MK_HTTP2_UNINITIALIZED;
    }

    return 0;
}


struct mk_sched_handler mk_http2_handler = {
    .name             = "http2",
    .cb_read          = mk_http2_sched_read,
    .cb_close         = mk_http2_sched_close,
    .cb_done          = NULL,
    .cb_upgrade       = mk_http2_upgrade,
    .sched_extra_size = sizeof(struct mk_http2_session),
    .capabilities     = MK_CAP_HTTP2
};
