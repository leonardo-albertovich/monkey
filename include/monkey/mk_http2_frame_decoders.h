#ifndef MK_HTTP2_FRAME_DECODERS_H
#define MK_HTTP2_FRAME_DECODERS_H

#include <monkey/mk_http2_frame.h>

void mk_http2_decode_frame_header(uint8_t *buf, struct mk_http2_frame *frame);

int mk_http2_decode_data_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_headers_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_priority_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_rst_stream_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_settings_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_push_promise_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_ping_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_goaway_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_window_update_frame_payload(struct mk_http2_frame *frame);
int mk_http2_decode_continuation_frame_payload(struct mk_http2_frame *frame);

int mk_http2_decode_frame_payload(struct mk_http2_frame *frame);

int mk_http2_decode_frame(uint8_t *buffer, size_t buffer_length, 
                          struct mk_http2_frame *frame, size_t max_frame_size);

#endif
