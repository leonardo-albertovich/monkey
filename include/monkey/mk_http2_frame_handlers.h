#ifndef MK_HTTP2_FRAME_HANDLERS_H
#define MK_HTTP2_FRAME_HANDLERS_H

#include <monkey/mk_core.h>
#include <monkey/mk_http2_frame.h>

int mk_http2_handle_data_frame(struct mk_sched_conn *conn,
                               struct mk_http2_frame *frame,
                               struct mk_http2_stream *stream);

int mk_http2_handle_continuation_frame(struct mk_sched_conn *conn,
                                       struct mk_http2_frame *frame,
                                       struct mk_http2_stream *stream);

int mk_http2_handle_push_promise_frame(struct mk_sched_conn *conn,
                                       struct mk_http2_frame *frame,
                                       struct mk_http2_stream *stream);

int mk_http2_handle_headers_frame(struct mk_sched_conn *conn,
                                  struct mk_http2_frame *frame,
                                  struct mk_http2_stream *stream);

int mk_http2_handle_window_update_frame(struct mk_sched_conn *conn,
                                        struct mk_http2_frame *frame,
                                        struct mk_http2_stream *stream);

int mk_http2_handle_priority_frame(struct mk_sched_conn *conn,
                                   struct mk_http2_frame *frame,
                                   struct mk_http2_stream *stream);

int mk_http2_handle_settings_frame(struct mk_sched_conn *conn,
                                   struct mk_http2_frame *frame);

#endif