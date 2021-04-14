#ifndef MK_HTTP2_REQUEST_H
#define MK_HTTP2_REQUEST_H

#include <stdint.h>
#include <monkey/mk_core.h>
#include <monkey/mk_server.h>


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
    int status;

    /* is it serving a user's home directory ? */
    int user_home;

    long port;


    /* Streams handling: headers and static file */
    struct mk_stream_input in_file;
    struct mk_stream_input page_stream;

    /* decoded uri */
    mk_ptr_t uri;
    mk_ptr_t uri_processed;

    /*---Request headers--*/
    int method;

    int content_length;

    mk_ptr_t _content_length;
    mk_ptr_t content_type;
    mk_ptr_t connection;

    mk_ptr_t _method;
    mk_ptr_t scheme;

    mk_ptr_t host;
    mk_ptr_t host_port;
    mk_ptr_t if_modified_since;
    mk_ptr_t last_modified_since;
    mk_ptr_t range;
    /*---------------------*/

    /* POST/PUT data */
    mk_ptr_t data;
    /*-----------------*/

    /*-Internal-*/
    mk_ptr_t real_path;        /* Absolute real path */

    /*
     * If a full URL length is less than MAX_PATH_BASE (defined in limits.h),
     * it will be stored here and real_path will point this buffer
     */
    char real_path_static[MK_PATH_BASE];

    /* Query string: ?.... */
    mk_ptr_t query_string;


    /*
     * STAGE_30 block flag: in mk_http_init() when the file is not found, it
     * triggers the plugin STAGE_30 to look for a plugin handler. In some
     * cases the plugin would overwrite the real path of the requested file
     * and make Monkey handle the new path for the static file. At this point
     * we need to block STAGE_30 calls from mk_http_init().
     *
     * For short.. if a plugin overwrites the real_path, let Monkey handle that
     * and do not trigger more STAGE_30's.
     */
    int stage30_blocked;

    /*
     * If the connection is being managed by a plugin (e.g: CGI), associate the
     * plugin reference to the stage30_handler field. This is useful to handle
     * protocol exception and notify the handlers about it.
     */
    void *stage30_handler;

    /* Static file information */
    int file_fd;
    struct file_info file_info;

    /* Vhost */
    int vhost_fdt_id;
    unsigned int vhost_fdt_hash;
    int vhost_fdt_enabled;

    struct mk_vhost   *host_conf;      /* root vhost config */
    struct mk_vhost_alias *host_alias; /* specific vhost matched */

    /*
     * Reference used outside of Monkey Core, e.g: Plugins. It can be used
     * to store some relevant information associated to a request.
     */
    void *handler_data;

    struct mk_http2_stream *stream;
    /* Parent Session */
    struct mk_http2_session *session;

    /* coroutine thread (if any) */
    void *thread;

    struct mk_http2_header_table *headers;
};

void mk_http2_request_init(struct mk_http2_request *request,
                           struct mk_http2_stream *stream,
                           struct mk_http2_session *session);

int mk_http2_request_prepare(struct mk_http2_request *request);

#endif