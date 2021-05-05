#ifndef MK_HTTP2_REQUEST_H
#define MK_HTTP2_REQUEST_H

#include <stdint.h>
#include <monkey/mk_core.h>
#include <monkey/mk_server.h>
#include <monkey/mk_http2_response.h>


#define MK_HTTP2_REQUEST_PREPARATION_SUCCESS              0
#define MK_HTTP2_REQUEST_PREPARATION_UNAVAILABLE_FEATURE -1
#define MK_HTTP2_REQUEST_PREPARATION_MISSING_HOST        -2
#define MK_HTTP2_REQUEST_PREPARATION_MISSING_METHOD      -3
#define MK_HTTP2_REQUEST_PREPARATION_MISSING_URI         -4
#define MK_HTTP2_REQUEST_PREPARATION_MISSING_SCHEME      -5
#define MK_HTTP2_REQUEST_PREPARATION_UNRECOGNIZED_METHOD -6
#define MK_HTTP2_REQUEST_PREPARATION_INVALID_URI         -7
#define MK_HTTP2_REQUEST_PREPARATION_PLUGIN_ERROR        -8

/* Forward declarations are used here to cope with the circular dependency 
 * in the stream <-> request relationship and they're used for the session as well
 * just for consistency.
 */

struct mk_http2_stream;
struct mk_http2_session;

struct mk_http2_request
{
    struct mk_http_base_request base;

    struct mk_http2_stream *stream;

    struct mk_http2_header_table *headers;

    struct mk_http2_response response;
};

void mk_http2_request_init(struct mk_http2_request *request,
                           struct mk_http2_stream *stream,
                           struct mk_http2_session *session);

int mk_http2_request_prepare(struct mk_http2_request *request);

#endif