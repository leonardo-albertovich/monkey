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
#include <monkey/mk_scheduler.h>

/* HTTP/2 Connection Preface */
#define MK_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
static mk_ptr_t http2_preface = {
    .data = MK_HTTP2_PREFACE,
    .len  = sizeof(MK_HTTP2_PREFACE) - 1
};

static inline void buffer_consume(struct mk_http2_session *h2s, int bytes)
{
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
                   struct mk_server *server)
{
    (void) error_code;
    (void) server;

    return 0;
}

/* Handle an upgraded session */
static int mk_http2_upgrade(void *cs, void *sr, struct mk_server *server)
{
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

/* FIXME Decode a frame header, no more... no less */
static inline void mk_http2_settings_frame_encode(uint8_t *buf, size_t buf_len,
                                                  struct mk_http2_settings *
                                                  settings)
{
    (void) buf;
    (void) buf_len;
    (void) settings;
}

static inline void mk_http2_frame_decode_header(uint8_t *buf,
                                                struct mk_http2_frame *frame)
{
    frame->length    = mk_http2_bitdec_32u(buf) >> 8;
    frame->type      = mk_http2_bitdec_32u(buf) &  0xFF;
    frame->flags     = buf[4];
    frame->stream_id = mk_http2_bitdec_stream_id(&buf[5]);
    frame->payload   = &buf[9];

#ifdef MK_HAVE_TRACE
    MK_TRACE("Frame Header");
    printf(" length=%i, type=%i, stream_id=%i\n",
           frame->length,
           frame->type,
           frame->stream_id);
#endif
}

static inline int mk_http2_handle_settings(struct mk_sched_conn *conn,
                                           struct mk_http2_frame *frame)
{
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
        setting_entry++)
    {

       MK_H2_TRACE(conn, "[Setting] Id=%i Value=%i",
                   setting_entry->identifier,
                   setting_entry->value);

       switch (setting_entry->identifier)
       {
       case MK_HTTP2_SETTINGS_HEADER_TABLE_SIZE:
            h2s->remote_settings.header_table_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_ENABLE_PUSH:
           if (setting_entry->value != 0 && 
               setting_entry->value != 1)
           {
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
           if (MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE < setting_entry->value)
           {
               MK_H2_TRACE(conn, "INVALID INITIAL_WINDOW_SIZE : %i",
                           setting_entry->value);

               return MK_HTTP2_FLOW_CONTROL_ERROR;
           }

           h2s->remote_settings.initial_window_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_FRAME_SIZE:
           if (MK_HTTP2_MAX_FRAME_SIZE < setting_entry->value)
           {
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
                                     struct mk_server *server)
{
    struct mk_http2_frame frame;
    struct mk_http2_session *h2s;
    int    result;

    (void) worker;

    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_MINIMUM_FRAME_SIZE <= h2s->buffer_length) {
        MK_H2_TRACE(conn, "HTTP/2 SESSION SETTINGS RECEIVED");

        /* Decode the frame header */
        mk_http2_frame_decode_header(h2s->buffer, &frame);

        if(frame.length > h2s->local_settings.max_frame_size)
        {
            MK_TRACE("[FD %i] Frame size exceeds the one agreed upon", 
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_FRAME_SIZE_ERROR, server);

            return -1;
        }

        if(frame.length > h2s->buffer_length)
        {
            /* We need more data */
            return 0;
        }
    }
    else
    {
        /* We need more data */
        return 0;
    }

    if(MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status)
    {
        if(MK_HTTP2_SETTINGS_FRAME == frame.type)
        {
            result = mk_http2_handle_settings(conn, &frame);

            buffer_consume(h2s, frame.length);

            if(MK_HTTP2_NO_ERROR != result)
            {
                mk_http2_error(result, server);
            }
        }
        else
        {
            MK_TRACE("[FD %i] First frame received should be a settings frame",
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return -1;
        }
    }

    return 0;
}

static int mk_http2_sched_read(struct mk_sched_conn *conn,
                               struct mk_sched_worker *worker,
                               struct mk_server *server)
{
    int                      new_size;
    int                      bytes;
    uint8_t                 *tmp;
    struct mk_http2_session *h2s;

    (void) worker;
    (void) server;

    h2s = mk_http2_session_get(conn);

    if(MK_HTTP2_UNINITIALIZED == h2s->status ||
       MK_HTTP2_UPGRADED == h2s->status)
    {
        h2s->buffer = h2s->buffer_fixed;
        h2s->buffer_size = MK_HTTP2_CHUNK;
        h2s->buffer_length = 0;

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

            if (NULL == h2s->buffer) /* FIXME: send internal server error ? */
            {
                return -1;
            }

            memcpy(h2s->buffer, h2s->buffer_fixed, h2s->buffer_length);

            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer new size: %i, length: %i",
                     conn->event.fd, new_size, h2s->buffer_length);
        }
        else
        {
            tmp = (uint8_t *) mk_mem_realloc(h2s->buffer, new_size);

            if (NULL == tmp) /* FIXME: send internal server error ? */
            {
                return -1;
            }

            h2s->buffer = tmp;
            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer realloc from %i to %i",
                     conn->event.fd, h2s->buffer_size, new_size);
        }
    }

    /* Read the incoming data */
    printf("TRYING TO READ : %d\n", h2s->buffer_size - h2s->buffer_length);
    bytes = mk_sched_conn_read(conn,
                               &h2s->buffer[h2s->buffer_length],
                               h2s->buffer_size - h2s->buffer_length);
    printf("AFTER READ : %d\n", bytes);

    if (0 == bytes)
    {
        errno = 0;
        return -1;
    }
    else if (-1 == bytes)
    {
        return -1;
    }

    h2s->buffer_length += bytes;

    printf("JUST READ %d BYTES\n", bytes);

    /* hex dump */
    {
        int zzz;
        int yyy;
        int qqq;

        yyy = 0;
        qqq = 0;

        for(zzz = 0 ; zzz < bytes ; zzz++)
        {
            printf("%02X ", (unsigned char) h2s->buffer[zzz]);

            if((0 == ((zzz+1) % 16) && zzz != 0) || zzz == (bytes - 1))
            {
                for(qqq = yyy ; qqq < zzz ; qqq++)
                {
                    if(0 != isprint(h2s->buffer[qqq]))
                    {
                        printf("%c", h2s->buffer[qqq]);
                    }
                    else
                    {
                        printf("%c", '.');
                    }
                }

                printf("\n");
                yyy = zzz + 1;
            }
        }

        printf("\n");
    }

    printf("h2s->status = %d\n", h2s->status);

    if (MK_HTTP2_AWAITING_PREFACE == h2s->status || /* This is either a prior
                                                       knowledge plaintext or
                                                       direct TLS HTTP/2
                                                       request */
        MK_HTTP2_UPGRADED == h2s->status) /* Upgraded connections from HTTP/1.x
                                             requires the preface */
    {
        if (h2s->buffer_length >= http2_preface.len) {
printf("TESTING IF THE PREFACE IS PRESENT\n");

            if (memcmp(h2s->buffer,
                       http2_preface.data, http2_preface.len) != 0) {
                MK_H2_TRACE(conn, "Invalid HTTP/2 preface");
printf("PREFACE NOT PRESENT\n");

                return 0;
            }

printf("PREFACE IS PRESENT\n");

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
        else
        {
            /* We need more data */
            return 0;
        }
    }

    printf("REMAINDER %i/%i\n",
           h2s->buffer_length, MK_HTTP2_MINIMUM_FRAME_SIZE);

    /* Check that we have a minimum header size */
    if (MK_HTTP2_MINIMUM_FRAME_SIZE > h2s->buffer_length) {
        // MK_TRACE("HEADER FRAME incomplete %i/%i bytes",
        //          h2s->buffer_length, MK_HTTP2_MINIMUM_FRAME_SIZE);
        return 0;
    }

    /*
    Disabled to isolate the missing data issue

    return mk_http2_frame_run(conn, worker, server);
    */

    return 0;
}


struct mk_sched_handler mk_http2_handler = {
    .name             = "http2",
    .cb_read          = mk_http2_sched_read,
    .cb_close         = NULL,
    .cb_done          = NULL,
    .cb_upgrade       = mk_http2_upgrade,
    .sched_extra_size = sizeof(struct mk_http2_session),
    .capabilities     = MK_CAP_HTTP2
};
