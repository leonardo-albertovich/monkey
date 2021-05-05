#include <monkey/mk_http_base.h>
#include <monkey/mk_http2.h>
#include <monkey/mk_http1.h>

inline int mk_http_error(int http_status, 
                  struct mk_http_base_session *cs,
                  struct mk_http_base_request *sr,
                  struct mk_server *server)
{ 
    if (HTTP_2 > sr->protocol_version) {
        return mk_http1_error(http_status,
                              cs->additional_data.http_1,
                              sr->additional_data.http_1,
                              server);
    }
    else if (HTTP_2 == sr->protocol_version) {
        return mk_http2_error(http_status,
                              cs->additional_data.http_2,
                              sr->additional_data.http_2,
                              server);
    }
    else {
        return -1; /* WE DO'T SUPPORT QUIC SO WHAT HAPPENED! TRACE THE ERROR! */
    }
}
