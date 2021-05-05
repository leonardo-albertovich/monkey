#include <monkey/mk_core.h>
#include <monkey/mk_server.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_plugin_stage.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_request.h>
#include <monkey/mk_http2_header_table.h>


const mk_ptr_t mk_http2_dummy_protocol_value = mk_ptr_init("HTTP/2");
const mk_ptr_t mk_http2_dummy_keepalive_value = mk_ptr_init("Keep-Alive");

/* Create a memory allocation in order to handle the request data */
void mk_http2_request_init(struct mk_http2_request *request,
                           struct mk_http2_stream *stream,
                           struct mk_http2_session *session)
{
    struct mk_list *host_list = &session->server->hosts;

    /* Set up the link between the base and specific objects */
    request->base.additional_data.http_2 = request;
    request->base.response.additional_data.http_2 = &request->response;

    request->base.protocol_version = HTTP_2;

    request->base.port = 0;
    request->base.status = MK_TRUE;
    request->base.uri.data = NULL;
    request->base.method = MK_METHOD_UNKNOWN;
    request->base.connection.len = -1;
    request->base.file_fd = -1;
    request->base.file_info.size = -1;
    request->base.vhost_fdt_id = 0;
    request->base.vhost_fdt_hash = 0;
    request->base.vhost_fdt_enabled = MK_FALSE;
    request->base.host.data = NULL;
    request->base.stage30_blocked = MK_FALSE;
    request->base.session = &session->base;
    request->base.host_conf = mk_list_entry_first(host_list, struct mk_vhost, _head);
    request->base.uri_processed.data = NULL;
    request->base.real_path.data = NULL;
    request->base.handler_data = NULL;
    request->base.in_file.fd = -1;
    request->stream = stream;
}

static int mk_http2_request_extract_header(struct mk_http2_request *request, 
                                           char *header_name, 
                                           mk_ptr_t *container)
{
    struct mk_http2_header_table_entry *entry;

    entry = mk_http2_header_table_entry_get_by_name(request->headers, header_name);

    if (NULL == entry) {
        return -1;
    }

    container->data = entry->value;
    container->len = strlen(entry->value);

    return 0;
}

int mk_http2_request_prepare(struct mk_http2_request *request)
{
    // struct mk_list                     *head;
    // struct mk_http2_header_table_entry *entry;
    int                                 result;
    struct mk_list                     *alias;

/*
    printf("INCOMING HEADER LIST :\n");

    mk_list_foreach(head, &request->headers->entries) {
        entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);

        printf("NAME  : [%s]\n", entry->name);
        printf("VALUE : [%s]\n", entry->value);
    }            

    printf("\n");
*/

    result = mk_http2_request_extract_header(request, ":authority", &request->base.host);

    if (0 != result) {
        return MK_HTTP2_REQUEST_PREPARATION_MISSING_HOST;
    }

    result = mk_http2_request_extract_header(request, ":method", &request->base.method_p);

    if (0 != result) {
        return MK_HTTP2_REQUEST_PREPARATION_MISSING_METHOD;
    }

    result = mk_http2_request_extract_header(request, ":path", &request->base.uri);

    if (0 != result) {
        return MK_HTTP2_REQUEST_PREPARATION_MISSING_URI;
    }

    // result = mk_http2_request_extract_header(request, ":scheme", &request->scheme);

    // if (0 != result) {
    //     return MK_HTTP2_REQUEST_PREPARATION_MISSING_SCHEME;
    // }
    
    /* This header doesn't exist in HTTP/2 because connections are kept alive naturally.
     * However, to simply and homogenize the base http request interface I am hardcoding
     * it to a sane yet synthetic value.
     */

    request->base.connection.data = mk_http2_dummy_keepalive_value.data;
    request->base.connection.len = mk_http2_dummy_keepalive_value.len;

    /* Same as connection, just there for compatibility.
     */
    request->base.protocol_p.data = mk_http2_dummy_protocol_value.data;
    request->base.protocol_p.len = mk_http2_dummy_protocol_value.len;

    mk_http2_request_extract_header(request, "if-modified-since", 
                                    &request->base.if_modified_since);

    mk_http2_request_extract_header(request, "last-modified", 
                                    &request->base.last_modified_since);

    mk_http2_request_extract_header(request, "range", 
                                    &request->base.range);

    mk_http2_request_extract_header(request, "content-length", 
                                    &request->base._content_length);

    mk_http2_request_extract_header(request, "content-type", 
                                    &request->base.content_type);


    if (0 == strcasecmp("GET", request->base.method_p.data)) {
        request->base.method = MK_METHOD_GET;
    }
    else if (0 == strcasecmp("POST", request->base.method_p.data)) {
        request->base.method = MK_METHOD_POST;
    }
    else if (0 == strcasecmp("PUT", request->base.method_p.data)) {
        request->base.method = MK_METHOD_PUT;
    }
    else if (0 == strcasecmp("HEAD", request->base.method_p.data)) {
        request->base.method = MK_METHOD_HEAD;
    }
    else if (0 == strcasecmp("DELETE", request->base.method_p.data)) {
        request->base.method = MK_METHOD_DELETE;
    }
    else if (0 == strcasecmp("OPTIONS", request->base.method_p.data)) {
        request->base.method = MK_METHOD_OPTIONS;
    }
    else {
        return MK_HTTP2_REQUEST_PREPARATION_UNRECOGNIZED_METHOD;
    }

    if (NULL != request->base._content_length.data) {
        request->base.content_length = strtol(request->base._content_length.data, NULL, 10);
    }

    request->base.uri_processed.data = mk_utils_url_decode(request->base.uri);

    if (NULL == request->base.uri_processed.data) {
        request->base.uri_processed.data = request->base.uri.data;
        request->base.uri_processed.len  = request->base.uri.len;
    }
    else {
        request->base.uri_processed.len = strlen(request->base.uri_processed.data);
    }

    /* This is based in mk_http_prepare_request from mk_http.c */

    /* Always assign the default vhost' */
    request->base.host_conf = mk_list_entry_first(&request->base.session->server->hosts, 
                                                  struct mk_vhost, _head);
    request->base.user_home = MK_FALSE;

    if (request->base.uri_processed.data[0] != '/') {
        return MK_HTTP2_REQUEST_PREPARATION_INVALID_URI;
    }

    /* Assign the first node alias */
    alias = &request->base.host_conf->server_names;
    request->base.host_alias = mk_list_entry_first(alias,
                                              struct mk_vhost_alias, _head);


    if (NULL != request->base.host.data) {
        /* Set the given port */
         request->base.port = strtol(request->base.session->additional_data.http_2->connection->server_listen->listen->port, 
                                     NULL, 10);
         // * should get the port number from there
         
        // request->port = request->session->stream->channel; 

        /* Match the virtual host */
        mk_vhost_get(request->base.host, &request->base.host_conf, 
                     &request->base.host_alias, 
                     request->base.session->additional_data.http_2->server);

        /* Check if this virtual host have some redirection */
        if (request->base.host_conf->header_redirect.data) {
            // // mk_header_set_http_status(sr, MK_REDIR_MOVED);
            // // sr->headers.location = mk_string_dup(sr->host_conf->header_redirect.data);
            // // sr->headers.content_length = 0;
            // // sr->headers.location = NULL;
            // // mk_header_prepare(cs, sr, server);
            // return 0;
            MK_TRACE("NEED TO HANDLE REDIRECTS!\n");
            return MK_HTTP2_REQUEST_PREPARATION_UNAVAILABLE_FEATURE;
        }
    }

    /* Is requesting an user home directory ? */
    if (request->base.session->additional_data.http_2->server->conf_user_pub &&
        request->base.uri_processed.len > 2 &&
        request->base.uri_processed.data[1] == MK_USER_HOME) {

        MK_TRACE("SERVING A HOME DIRECTORY IS NOT SUPPORTED IN HTTP/2 YET\n");

        return MK_HTTP2_REQUEST_PREPARATION_UNAVAILABLE_FEATURE;
    }

    /* Plugins Stage 20 */
    result = mk_plugin_stage_run_20(request->base.session, 
                                    &request->base, 
                                    request->base.session->additional_data.http_2->server);
    if (MK_PLUGIN_RET_CLOSE_CONX == result) {
        MK_TRACE("STAGE 20 requested close conexion");
        return MK_HTTP2_REQUEST_PREPARATION_PLUGIN_ERROR;
    }

    MK_TRACE("[FD %i] HTTP2 Init returning 0", request->session->stream.channel->fd);

    return MK_HTTP2_REQUEST_PREPARATION_SUCCESS;
}