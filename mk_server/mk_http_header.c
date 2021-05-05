#include <monkey/mk_http_header.h>

int mk_http_header_prepare(struct mk_http_base_session *cs, 
                           struct mk_http_base_request *sr,
                           struct mk_server *server)
{
    (void) cs;
    (void) sr;
    (void) server;

    return 0;
}

void mk_http_header_response_reset(struct mk_http_base_response *header)
{
    (void) header;
}

void mk_http_header_set_http_status(struct mk_http_base_request *sr, int status)
{
    (void) sr;
    (void) status;
}

void mk_http_header_set_content_length(struct mk_http_base_request *sr, long len)
{
    (void) sr;
    (void) len;
}
