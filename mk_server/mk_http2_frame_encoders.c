#include <monkey/mk_http2.h>
#include <monkey/mk_http2_frame_encoders.h>

void mk_http2_encode_frame_header(struct mk_http2_frame *frame, uint8_t *output_buffer)
{   
    mk_http2_bitenc_32u(output_buffer, ((frame->length << 8) | frame->type));

    output_buffer[4] = frame->flags;

    mk_http2_bitenc_stream_id(&output_buffer[5], frame->stream_id);
}

int mk_http2_encode_data_frame(struct mk_http2_frame *frame, 
                               uint8_t **output_buffer,
                               size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 != (MK_HTTP2_DATA_PADDED & frame->flags)) {
        required_size += 1;
        required_size += frame->payload.data.pad_length;
    }

    required_size += frame->payload.data.data_length;

    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 != (MK_HTTP2_DATA_PADDED & frame->flags)) {
        result_buffer[0] = frame->payload.data.pad_length;
        payload_buffer += 1;
    }

    memcpy(payload_buffer, 
           frame->payload.data.data_block, 
           frame->payload.data.data_length);

    payload_buffer += frame->payload.data.data_length;

    if (0 != (MK_HTTP2_DATA_PADDED & frame->flags)) {
        memcpy(payload_buffer, 
               frame->payload.data.padding_block, 
               frame->payload.data.pad_length);

        payload_buffer += frame->payload.data.pad_length;
    }

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_headers_frame(struct mk_http2_frame *frame, 
                                  uint8_t **output_buffer,
                                  size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        required_size += 1;
        required_size += frame->payload.headers.pad_length;
    }

    if (0 != (MK_HTTP2_HEADERS_PRIORITY & frame->flags)) {
        required_size += 5;
    }

    required_size += frame->payload.headers.data_length;

    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        result_buffer[0] = frame->payload.headers.pad_length;
        payload_buffer += 1;
    }

    if (0 != (MK_HTTP2_HEADERS_PRIORITY & frame->flags)) {
        mk_http2_bitenc_stream_id(&payload_buffer[0], 
                                  frame->payload.headers.stream_dependency);

        payload_buffer[4] = frame->payload.headers.weight;
        payload_buffer += 5;
    }

    memcpy(payload_buffer, 
           frame->payload.headers.data_block, 
           frame->payload.headers.data_length);

    payload_buffer += frame->payload.headers.data_length;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        memcpy(payload_buffer, 
               frame->payload.headers.padding_block, 
               frame->payload.headers.pad_length);

        payload_buffer += frame->payload.headers.pad_length;
    }

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_priority_frame(struct mk_http2_frame *frame, 
                                   uint8_t **output_buffer,
                                   size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;
    uint32_t stream_id;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 5;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    stream_id = frame->payload.priority.stream_dependency;

    if (1 == frame->payload.priority.exclusive_dependency_flag) {
        BIT_SET(stream_id, 31);
    }

    mk_http2_bitenc_32u(payload_buffer, stream_id);

    payload_buffer[1] = frame->payload.priority.weight;

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_rst_stream_frame(struct mk_http2_frame *frame, 
                                     uint8_t **output_buffer,
                                     size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 4;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    mk_http2_bitenc_32u(payload_buffer, frame->payload.rst_stream.error_code);

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_settings_frame(struct mk_http2_frame *frame, 
                                   uint8_t **output_buffer,
                                   size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + \
                    mk_http2_setting_entry_count_to_frame_size(frame->payload.settings.entry_count);

    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    memcpy(payload_buffer, frame->payload.settings.entries, frame->length);
    
    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_push_promise_frame(struct mk_http2_frame *frame, 
                                       uint8_t **output_buffer,
                                       size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 4; /* Promised Stream ID */

    if (0 != (MK_HTTP2_PUSH_PROMISE_PADDED & frame->flags)) {
        required_size += 1;
        required_size += frame->payload.push_promise.pad_length;
    }

    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 != (MK_HTTP2_PUSH_PROMISE_PADDED & frame->flags)) {
        result_buffer[0] = frame->payload.push_promise.pad_length;
        payload_buffer += 1;
    }

    mk_http2_bitenc_stream_id(&payload_buffer[0], 
                              frame->payload.push_promise.promised_stream_id);

    payload_buffer += 4;

    if (0 != (MK_HTTP2_PUSH_PROMISE_PADDED & frame->flags)) {
        memcpy(payload_buffer, 
               frame->payload.push_promise.data_block, 
               frame->payload.push_promise.pad_length);

        payload_buffer += frame->payload.push_promise.pad_length;
    }

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_ping_frame(struct mk_http2_frame *frame, 
                               uint8_t **output_buffer,
                               size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 4;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    mk_http2_bitenc_32u(payload_buffer, frame->payload.ping.data);

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_goaway_frame(struct mk_http2_frame *frame, 
                                 uint8_t **output_buffer,
                                 size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 8;
    required_size = frame->payload.goaway.additional_debug_data_length;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    mk_http2_bitenc_32u(payload_buffer, frame->payload.goaway.last_stream_id);
    payload_buffer += 4;

    mk_http2_bitenc_32u(payload_buffer, frame->payload.goaway.error_code);
    payload_buffer += 4;

    if (0 < frame->payload.goaway.additional_debug_data_length) {
        memcpy(payload_buffer, 
               frame->payload.goaway.additional_debug_data, 
               frame->payload.goaway.additional_debug_data_length);

        payload_buffer += frame->payload.goaway.additional_debug_data_length;
    }

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_window_update_frame(struct mk_http2_frame *frame, 
                                        uint8_t **output_buffer,
                                        size_t *output_buffer_length)
{
    size_t    required_size;
    uint8_t  *result_buffer;
    uint8_t  *payload_buffer;
    uint32_t  window_size_increment;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE + 4;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    window_size_increment = frame->payload.window_update.window_size_increment;

    BIT_CLEAR(window_size_increment, 31);

    mk_http2_bitenc_32u(payload_buffer, window_size_increment);

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_continuation_frame(struct mk_http2_frame *frame, 
                                       uint8_t **output_buffer,
                                       size_t *output_buffer_length)
{
    size_t   required_size;
    uint8_t *result_buffer;
    uint8_t *payload_buffer;

    required_size = MK_HTTP2_MINIMUM_FRAME_SIZE;
    
    result_buffer = mk_mem_alloc_z(required_size);

    if (NULL == result_buffer) {
        return -1;
    }

    payload_buffer = result_buffer;

    if (0 == frame->length) {
        frame->length = required_size - MK_HTTP2_MINIMUM_FRAME_SIZE;
    }

    mk_http2_encode_frame_header(frame, payload_buffer);

    payload_buffer += MK_HTTP2_MINIMUM_FRAME_SIZE;

    if (0 < frame->payload.continuation.data_length) {
        memcpy(payload_buffer, 
               frame->payload.continuation.data_block, 
               frame->payload.continuation.data_length);

        payload_buffer += frame->payload.continuation.data_length;
    }

    *output_buffer = result_buffer;
    *output_buffer_length = required_size;    

    return 0;
}

int mk_http2_encode_frame(struct mk_http2_frame *frame,
                          uint8_t **output_buffer,
                          size_t *output_buffer_length)
{
    int result;

    switch(frame->type) {
    case MK_HTTP2_DATA_FRAME:
        result = mk_http2_encode_data_frame(frame, output_buffer, 
                                            output_buffer_length);
        break;
    case MK_HTTP2_HEADERS_FRAME:
        result = mk_http2_encode_headers_frame(frame, output_buffer, 
                                               output_buffer_length);
        break;
    case MK_HTTP2_PRIORITY_FRAME:
        result = mk_http2_encode_priority_frame(frame, output_buffer, 
                                                output_buffer_length);
        break;
    case MK_HTTP2_RST_STREAM_FRAME:
        result = mk_http2_encode_rst_stream_frame(frame, output_buffer, 
                                                  output_buffer_length);
        break;
    case MK_HTTP2_SETTINGS_FRAME:
        result = mk_http2_encode_settings_frame(frame, output_buffer, 
                                                output_buffer_length);
        break;
    case MK_HTTP2_PUSH_PROMISE_FRAME:
        result = mk_http2_encode_push_promise_frame(frame, output_buffer, 
                                                    output_buffer_length);
        break;
    case MK_HTTP2_PING_FRAME:
        result = mk_http2_encode_ping_frame(frame, output_buffer, 
                                            output_buffer_length);
        break;
    case MK_HTTP2_GOAWAY_FRAME:
        result = mk_http2_encode_goaway_frame(frame, output_buffer, 
                                              output_buffer_length);
        break;
    case MK_HTTP2_WINDOW_UPDATE_FRAME:
        result = mk_http2_encode_window_update_frame(frame, output_buffer, 
                                                     output_buffer_length);
        break;
    case MK_HTTP2_CONTINUATION_FRAME:
        result = mk_http2_encode_continuation_frame(frame, output_buffer, 
                                                    output_buffer_length);
        break;
    }

    return result;
}
