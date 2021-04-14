#include <monkey/mk_core.h>
#include <monkey/mk_scheduler.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_hpack.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_frame_handlers.h>

int mk_http2_handle_data_frame(struct mk_sched_conn *conn,
                               struct mk_http2_frame *frame,
                               struct mk_http2_stream *stream)
{
    size_t   new_data_buffer_size;
    uint8_t *new_data_buffer;
    // struct mk_http2_session *h2s;

    (void) conn;

    // h2s = mk_http2_session_get(conn);

    printf("DATA frame flags : %x\n\n", frame->flags);

    if(NULL == stream->data_buffer) {
        new_data_buffer_size = frame->payload.data.data_length;

        new_data_buffer = mk_mem_alloc_z(new_data_buffer_size);

        if (NULL == new_data_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;
        }

        stream->data_buffer = new_data_buffer;
        stream->data_buffer_size = new_data_buffer_size;

        memcpy(stream->data_buffer, frame->payload.data.data_block, 
               stream->data_buffer_size);

        stream->data_buffer_length = stream->data_buffer_size;
    }
    else {
        new_data_buffer_size = stream->data_buffer_size + frame->payload.data.data_length;

        new_data_buffer = mk_mem_realloc(stream->data_buffer, new_data_buffer_size);

        if (NULL == new_data_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;
        }

        stream->data_buffer = new_data_buffer;
        stream->data_buffer_size = new_data_buffer_size;

        memcpy(&stream->data_buffer[stream->data_buffer_length], 
               frame->payload.data.data_block, 
               frame->payload.data.data_length);

        stream->data_buffer_length = stream->data_buffer_size;
    }

    if (0 != (MK_HTTP2_DATA_END_STREAM & frame->flags)) {
        stream->end_stream_received = 1;
    }
    
    return MK_HTTP2_NO_ERROR;
}

int mk_http2_handle_continuation_frame(struct mk_sched_conn *conn,
                                       struct mk_http2_frame *frame,
                                       struct mk_http2_stream *stream)
{
    size_t                   new_header_buffer_size;
    uint8_t                 *new_header_buffer;
    int                      result;
    struct mk_http2_session *h2s;

    (void) conn;
    (void) frame;

    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_AWAITING_CONTINUATION_FRAME != h2s->status) {
        MK_TRACE("CONTINUATION FRAME RECEIVED ON A CONNECTION THAT WAS NOT EXPECTING ONE\n");

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    if (h2s->expected_continuation_stream != frame->stream_id) {
        MK_TRACE("CONTINUATION FRAME RECEIVED ON A CONNECTION THAT WAS EXPECTING ONE FOR A DIFFERENT STREAM\n");

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    /* There's no way we should get here without a preexisting header buffer (according
     * to the spec rules)
    */
    if(NULL == stream->header_buffer) {
        return MK_HTTP2_INTERNAL_ERROR;            
    }

    new_header_buffer_size = stream->header_buffer_size + frame->payload.headers.data_length;

    new_header_buffer = mk_mem_realloc(stream->header_buffer, new_header_buffer_size);

    /* FIXME: send internal server error ? */
    if (NULL == new_header_buffer) {
        return MK_HTTP2_INTERNAL_ERROR;
    }

    stream->header_buffer = new_header_buffer;
    stream->header_buffer_size = new_header_buffer_size;

    memcpy(&stream->header_buffer[stream->header_buffer_length], 
           frame->payload.headers.data_block, 
           frame->payload.headers.data_length);

    stream->header_buffer_length = stream->header_buffer_size;

    if (0 != (MK_HTTP2_CONTINUATION_END_HEADERS & frame->flags)) {
        stream->end_headers_received = 1;

        h2s->status = MK_HTTP2_AWAITING_CLIENT_FRAMES;

        h2s->expected_continuation_stream = 0;

        result = mk_http2_hpack_decompress_stream_headers(h2s, stream, 
                                                          &stream->request.headers);

        free(stream->header_buffer);

        stream->header_buffer = NULL;
        stream->header_buffer_size = 0;
        stream->header_buffer_length = 0;

        if (0 != result) {
            return MK_HTTP2_COMPRESSION_ERROR;
        }
    }
    else {
        /*
         * If we don't receive the END_HEADERS flag we need
         * to continue waiting for CONTINUATION 
         * frames for this stream so we don't touch the session data.
         */
    }

    return 0;
}

int mk_http2_handle_push_promise_frame(struct mk_sched_conn *conn,
                                       struct mk_http2_frame *frame,
                                       struct mk_http2_stream *stream)
{
    (void) conn;
    (void) frame;
    (void) stream;

    /* PUSH frames are not supported yet */

    return MK_HTTP2_REFUSED_STREAM;
}

int mk_http2_handle_priority_frame(struct mk_sched_conn *conn,
                                   struct mk_http2_frame *frame,
                                   struct mk_http2_stream *stream)
{
    (void) conn;
    (void) frame;
    (void) stream;

    /* Guess what? crutch! */

    return 0;
}

int mk_http2_handle_headers_frame(struct mk_sched_conn *conn,
                                  struct mk_http2_frame *frame,
                                  struct mk_http2_stream *stream)
{
    int                      result;
    struct mk_http2_session *h2s;

    (void) conn;
    (void) frame;
    (void) stream;

    if (0 == frame->stream_id) {
        MK_TRACE("HEADERS ERROR, ZERO STREAM ID : %i\n", frame->stream_id);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    h2s = mk_http2_session_get(conn);

    if(h2s->remotely_initiated_open_stream_count == 
       h2s->local_settings.max_concurrent_streams) {
        /* The error code for this situation is based on the intention of the server,
         * in our case we do want the client to automatically retry thus we return
         * the most benevolent code.
         */
        return MK_HTTP2_REFUSED_STREAM;
    }

    stream->status = MK_HTTP2_STREAM_STATUS_OPEN;

    if (0 != (MK_HTTP2_HEADERS_END_HEADERS & frame->flags)) {
        stream->end_headers_received = 1;

        stream->header_buffer = frame->payload.headers.data_block;
        stream->header_buffer_size = frame->payload.headers.data_length;
        stream->header_buffer_length = stream->header_buffer_size;

        result = mk_http2_hpack_decompress_stream_headers(h2s, stream, 
                                                          &stream->request.headers);

        if (0 != result) {
            return MK_HTTP2_COMPRESSION_ERROR;
        }

        h2s->status = MK_HTTP2_AWAITING_CLIENT_FRAMES;

        h2s->expected_continuation_stream = 0;
    }
    else {
        /*
         * If we don't receive the END_HEADERS flag we need
         * to signal the session to expect a CONTINUATION 
         * frame for this stream.
         * 
         */
        if(NULL != stream->header_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;            
        }

        stream->header_buffer_size = frame->payload.headers.data_length;

        stream->header_buffer = mk_mem_alloc_z(stream->header_buffer_size);

        /* FIXME: send internal server error ? */
        if (NULL == stream->header_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;
        }

        memcpy(stream->header_buffer, frame->payload.headers.data_block, 
               stream->header_buffer_size);

        stream->header_buffer_length = stream->header_buffer_size;

        h2s->status = MK_HTTP2_AWAITING_CONTINUATION_FRAME;

        h2s->expected_continuation_stream = frame->stream_id;
    }

    if (0 != (MK_HTTP2_HEADERS_END_STREAM & frame->flags)) {
        stream->end_stream_received = 1;
        stream->status = MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE;
    }

    h2s->remotely_initiated_open_stream_count++;

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_handle_window_update_frame(struct mk_sched_conn *conn,
                                        struct mk_http2_frame *frame,
                                        struct mk_http2_stream *stream)
{
    struct mk_http2_session *h2s;

    (void) conn;
    (void) frame;

    h2s = mk_http2_session_get(conn);

    if (0 == frame->payload.window_update.window_size_increment ||
        MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT < 
            frame->payload.window_update.window_size_increment) {
        MK_H2_TRACE(conn, "INVALID VALUE FOR WINDOW_SIZE_INCREMENT %i",
                    frame->payload.window_update.window_size_increment);

        return MK_HTTP2_PROTOCOL_ERROR;
    }
    
    if (0 == frame->stream_id) {
        h2s->flow_control_window_size += 
            frame->payload.window_update.window_size_increment;
    }
    else {
        stream->flow_control_window_size += 
            frame->payload.window_update.window_size_increment;
    }
    
    return MK_HTTP2_NO_ERROR;
}

int mk_http2_handle_settings_frame(struct mk_sched_conn *conn,
                                   struct mk_http2_frame *frame)
{
    // size_t                   setting_entry_list_length;
    size_t                   setting_entry_list_index;
    struct mk_http2_setting *setting_entry_list;
    int32_t                  window_size_delta;
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

    setting_entry_list = (struct mk_http2_setting *) frame->raw_payload;

    for(setting_entry_list_index = 0,
        setting_entry = &setting_entry_list[0] ;
        setting_entry_list_index < frame->payload.settings.entry_count ;
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

            window_size_delta = h2s->remote_settings.initial_window_size - 
                                setting_entry->value;

            /* NOTE : According to https://tools.ietf.org/html/rfc7540#section-6.9.2
             *        the value for the new flow control window could end up being 
             *        negative after this step and that's OK.
             *        Also, we're just adding because this way we negative deltas 
             *        that are a result of initial window size shrinkage are automatically
             *        handled. 
             */

            h2s->flow_control_window_size += window_size_delta;

            mk_http2_stream_apply_initial_window_size_delta(h2s, window_size_delta);

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

    if (MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status) {
        h2s->status = MK_HTTP2_AWAITING_CLIENT_FRAMES;
    }

    return MK_HTTP2_NO_ERROR;
}





//static void dump_header_table_and_dynamic_table()
//{

/*
        {
            struct mk_list *head;
            struct mk_http2_header_table_entry *entry;

            printf("INCOMING HEADER LIST :\n");

            mk_list_foreach(head, &stream->incoming_headers->entries) {
                entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);

                printf("NAME  : [%s]\n", entry->name);
                printf("VALUE : [%s]\n", entry->value);
            }            

            printf("\n");
        }
        
        printf("\n");
        printf("\n");
        printf("\n");

        {
            struct mk_list *head;
            struct mk_http2_dynamic_table_entry *entry;

            printf("DYNAMIC TABLE : %lu\n", stream->dynamic_table->size);

            mk_list_foreach(head, &stream->dynamic_table->entries) {
                entry = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);

                printf("NAME  : [%s]\n", entry->name);
                printf("VALUE : [%s]\n", entry->value);
                printf("SIZE  : [%lu]\n", entry->size);
                printf("\n");
            }            

            printf("\n");
        }
*/
//}
