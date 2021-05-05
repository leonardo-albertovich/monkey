#ifndef MK_HEADER_H
#define MK_HEADER_H

#include <monkey/mk_http_base.h>

int mk_header_prepare(struct mk_http_base_session *cs, 
                      struct mk_http_base_request *sr,
                      struct mk_server *server);

void mk_header_response_reset(struct mk_http_base_response *header);
void mk_header_set_http_status(struct mk_http_base_request *sr, int status);
void mk_header_set_content_length(struct mk_http_base_request *sr, long len);

#endif