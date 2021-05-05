#ifndef MK_HTTP2_RESPONSE_H
#define MK_HTTP2_RESPONSE_H

#include <monkey/mk_core.h>
#include <monkey/mk_server.h>

struct mk_http2_response
{
    struct mk_http2_header_table *headers;
};

#endif