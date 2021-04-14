#ifndef MK_HTTP2_FRAME_ENCODERS_H
#define MK_HTTP2_FRAME_ENCODERS_H

#include <monkey/mk_core.h>
#include <monkey/mk_http2_frame.h>

void mk_http2_encode_frame_header(struct mk_http2_frame *frame,
                                  uint8_t *output_buffer);

int mk_http2_encode_data_frame(struct mk_http2_frame *frame, 
                               uint8_t **output_buffer,
                               size_t *output_buffer_length);

int mk_http2_encode_headers_frame(struct mk_http2_frame *frame, 
                                  uint8_t **output_buffer,
                                  size_t *output_buffer_length);

int mk_http2_encode_priority_frame(struct mk_http2_frame *frame, 
                                   uint8_t **output_buffer,
                                   size_t *output_buffer_length);

int mk_http2_encode_rst_stream_frame(struct mk_http2_frame *frame, 
                                     uint8_t **output_buffer,
                                     size_t *output_buffer_length);

int mk_http2_encode_settings_frame(struct mk_http2_frame *frame, 
                                   uint8_t **output_buffer,
                                   size_t *output_buffer_length);

int mk_http2_encode_push_promise_frame(struct mk_http2_frame *frame, 
                                       uint8_t **output_buffer,
                                       size_t *output_buffer_length);

int mk_http2_encode_ping_frame(struct mk_http2_frame *frame, 
                               uint8_t **output_buffer,
                               size_t *output_buffer_length);

int mk_http2_encode_goaway_frame(struct mk_http2_frame *frame, 
                                 uint8_t **output_buffer,
                                 size_t *output_buffer_length);

int mk_http2_encode_window_update_frame(struct mk_http2_frame *frame, 
                                        uint8_t **output_buffer,
                                        size_t *output_buffer_length);

int mk_http2_encode_continuation_frame(struct mk_http2_frame *frame, 
                                       uint8_t **output_buffer,
                                       size_t *output_buffer_length);

int mk_http2_encode_frame(struct mk_http2_frame *frame,
                          uint8_t **output_buffer,
                          size_t *output_buffer_length);
#endif