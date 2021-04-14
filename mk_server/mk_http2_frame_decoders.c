#include <monkey/mk_http2.h>
#include <monkey/mk_http2_frame_decoders.h>

void mk_http2_decode_frame_header(uint8_t *buf, struct mk_http2_frame *frame)
{
    frame->length      = mk_http2_bitdec_32u(buf) >> 8;
    frame->type        = mk_http2_bitdec_32u(buf) &  0xFF;
    frame->flags       = buf[4];
    frame->stream_id   = mk_http2_bitdec_stream_id(&buf[5]);
    frame->raw_payload = &buf[MK_HTTP2_MINIMUM_FRAME_SIZE];

#ifdef MK_HAVE_TRACE
    MK_TRACE(" length=%i, type=%i, stream_id=%i\n",
             frame->length,
             frame->type,
             frame->stream_id);
#endif
}

int mk_http2_decode_data_frame_payload(struct mk_http2_frame *frame)
{
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_DATA_PADDED & frame->flags)) {
        frame->payload.data.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.data.pad_length = 0;
    }

    frame->payload.data.data_length = frame->length - 
                                      optional_fields_size - 
                                      frame->payload.data.pad_length;

    frame->payload.data.data_block = payload_buffer;

    frame->payload.data.padding_block = \
        &payload_buffer[frame->payload.data.data_length];

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_headers_frame_payload(struct mk_http2_frame *frame)
{
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        frame->payload.headers.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.headers.pad_length = 0;
    }

    if (0 != (MK_HTTP2_HEADERS_PRIORITY & frame->flags)) {
        frame->payload.headers.stream_dependency = mk_http2_bitdec_stream_id(&payload_buffer[0]);
        frame->payload.headers.weight = payload_buffer[4];

        payload_buffer += 5;
        optional_fields_size += 5;
    }
    else {
        frame->payload.headers.stream_dependency = 0;
        frame->payload.headers.weight = 0;
    }

    frame->payload.headers.data_length = frame->length - 
                                         optional_fields_size - 
                                         frame->payload.headers.pad_length;

    frame->payload.headers.data_block = payload_buffer;

    frame->payload.headers.padding_block = \
        &payload_buffer[frame->payload.headers.data_length];

    /* Need to validate that the padding size doesn't exceed the remaining frame size */

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_priority_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.priority.stream_dependency = \
    mk_http2_bitdec_32u(frame->raw_payload);
    
    frame->payload.priority.exclusive_dependency_flag = \
        BIT_CHECK(frame->payload.priority.stream_dependency, 31);

    BIT_CLEAR(frame->payload.priority.stream_dependency, 31);

    frame->payload.priority.weight = frame->raw_payload[4];

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_rst_stream_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.rst_stream.error_code = mk_http2_bitdec_32u(frame->raw_payload);

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_settings_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.settings.entries = (struct mk_http2_setting *) frame->raw_payload;
    frame->payload.settings.entry_count = \
        mk_http2_frame_size_to_setting_entry_count(frame->length);

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_push_promise_frame_payload(struct mk_http2_frame *frame)
{
    size_t   mandatory_fields_size;
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    mandatory_fields_size = 4; /* Promised Stream ID */
    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_PUSH_PROMISE_PADDED & frame->flags)) {
        frame->payload.push_promise.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.push_promise.pad_length = 0;
    }

    frame->payload.push_promise.promised_stream_id = \
        mk_http2_bitdec_stream_id(payload_buffer);
    
    BIT_CLEAR(frame->payload.push_promise.promised_stream_id, 31);

    payload_buffer += mandatory_fields_size;

    frame->payload.push_promise.data_length = frame->length - 
                                              optional_fields_size - 
                                              mandatory_fields_size - 
                                              frame->payload.push_promise.pad_length;

    frame->payload.push_promise.data_block = payload_buffer;

    frame->payload.push_promise.padding_block = \
        &payload_buffer[frame->payload.push_promise.data_length];

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_ping_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.ping.data = mk_http2_bitdec_32u(frame->raw_payload);

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_goaway_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.goaway.last_stream_id = \
    mk_http2_bitdec_stream_id(frame->raw_payload);

    frame->payload.goaway.error_code = *((uint32_t *)&frame->raw_payload[4]);
    frame->payload.goaway.additional_debug_data = &frame->raw_payload[8];
    frame->payload.goaway.additional_debug_data_length = frame->length - 8;

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_window_update_frame_payload(struct mk_http2_frame *frame)
{
    if (4 != frame->length) {
        return MK_HTTP2_NO_ERROR;
    }

    frame->payload.window_update.window_size_increment = \
        mk_http2_bitdec_stream_id(frame->raw_payload);

    BIT_CLEAR(frame->payload.window_update.window_size_increment, 31);

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_continuation_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.continuation.data_length = frame->length;
    frame->payload.continuation.data_block = frame->raw_payload;

    return MK_HTTP2_NO_ERROR;
}

int mk_http2_decode_frame_payload(struct mk_http2_frame *frame)
{
    int result;

    switch(frame->type) {
    case MK_HTTP2_DATA_FRAME:
        result = mk_http2_decode_data_frame_payload(frame);
        break;
    case MK_HTTP2_HEADERS_FRAME:
        result = mk_http2_decode_headers_frame_payload(frame);
        break;
    case MK_HTTP2_PRIORITY_FRAME:
        result = mk_http2_decode_priority_frame_payload(frame);
        break;
    case MK_HTTP2_RST_STREAM_FRAME:
        result = mk_http2_decode_rst_stream_frame_payload(frame);
        break;
    case MK_HTTP2_SETTINGS_FRAME:
        result = mk_http2_decode_settings_frame_payload(frame);
        break;
    case MK_HTTP2_PUSH_PROMISE_FRAME:
        result = mk_http2_decode_push_promise_frame_payload(frame);
        break;
    case MK_HTTP2_PING_FRAME:
        result = mk_http2_decode_ping_frame_payload(frame);
        break;
    case MK_HTTP2_GOAWAY_FRAME:
        result = mk_http2_decode_goaway_frame_payload(frame);
        break;
    case MK_HTTP2_WINDOW_UPDATE_FRAME:
        result = mk_http2_decode_window_update_frame_payload(frame);
        break;
    case MK_HTTP2_CONTINUATION_FRAME:
        result = mk_http2_decode_continuation_frame_payload(frame);
        break;
    }

    return result;
}

int mk_http2_decode_frame(uint8_t *buffer, size_t buffer_length, 
                          struct mk_http2_frame *frame, size_t max_frame_size)
{
    if (MK_HTTP2_MINIMUM_FRAME_SIZE > buffer_length) {
        return MK_HTTP2_INCOMPLETE_FRAME;
    }

    mk_http2_decode_frame_header(buffer, frame);

    if (frame->length > max_frame_size) {
        return MK_HTTP2_FRAME_SIZE_ERROR;
    }

    if ((MK_HTTP2_MINIMUM_FRAME_SIZE + frame->length) > buffer_length) {
        return MK_HTTP2_INCOMPLETE_FRAME; /* We need more data */
    }

    return mk_http2_decode_frame_payload(frame);
}
