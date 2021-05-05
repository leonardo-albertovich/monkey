/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

#include <monkey/monkey.h>
#include <monkey/mk_user.h>
#include <monkey/mk_core.h>
#include <monkey/mk_http1.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_http1_thread.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_mimetype.h>
// #include <monkey/mk_header.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin_stage.h>

const mk_ptr_t mk_http_method_get_p = mk_ptr_init(MK_METHOD_GET_STR);
const mk_ptr_t mk_http_method_post_p = mk_ptr_init(MK_METHOD_POST_STR);
const mk_ptr_t mk_http_method_head_p = mk_ptr_init(MK_METHOD_HEAD_STR);
const mk_ptr_t mk_http_method_put_p = mk_ptr_init(MK_METHOD_PUT_STR);
const mk_ptr_t mk_http_method_delete_p = mk_ptr_init(MK_METHOD_DELETE_STR);
const mk_ptr_t mk_http_method_options_p = mk_ptr_init(MK_METHOD_OPTIONS_STR);
const mk_ptr_t mk_http_method_null_p = { NULL, 0 };

const mk_ptr_t mk_http_protocol_09_p = mk_ptr_init(MK_HTTP_PROTOCOL_09_STR);
const mk_ptr_t mk_http_protocol_10_p = mk_ptr_init(MK_HTTP_PROTOCOL_10_STR);
const mk_ptr_t mk_http_protocol_11_p = mk_ptr_init(MK_HTTP_PROTOCOL_11_STR);
const mk_ptr_t mk_http_protocol_null_p = { NULL, 0 };

/* Create a memory allocation in order to handle the request data */
void mk_http1_request_init(struct mk_http1_session *session,
                           struct mk_http1_request *request,
                           struct mk_server *server)
{
    struct mk_list *host_list = &server->hosts;

    /* Set up the link between the base and specific objects */
    request->base.additional_data.http_1 = request;
    request->base.response.additional_data.http_1 = &request->response;

    request->base.protocol_version = HTTP_1;

    request->base.port = 0;
    request->base.status = MK_TRUE;
    request->base.uri.data = NULL;
    request->base.method = MK_METHOD_UNKNOWN;
    request->base.protocol = MK_HTTP_PROTOCOL_UNKNOWN;
    request->base.connection.len = -1;
    request->base.file_fd        = -1;
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

    mk_http_header_response_reset(&request->base.response);

    /* Reset callbacks for headers stream */
    mk_stream_set(&request->base.stream,
                  session->base.channel,
                  NULL,
                  NULL, NULL, NULL);
}

static inline int mk_http1_point_header(mk_ptr_t *h,
                                        struct mk_http_parser *parser, int key)
{
    struct mk_http_header *header;

    header = &parser->headers[key];
    if (header->type == key) {
        h->data = header->val.data;
        h->len  = header->val.len;
        return 0;
    }
    else {
        h->data = NULL;
        h->len  = -1;
    }

    return -1;
}

static int mk_http1_request_prepare(struct mk_http1_session *cs,
                                    struct mk_http1_request *sr,
                                    struct mk_server *server)
{
    int ret;
    int status = 0;
    char *temp;
    struct mk_list *hosts = &server->hosts;
    struct mk_list *alias;
    struct mk_http_header *header;

    /*
     * Process URI, if it contains ASCII encoded strings like '%20',
     * it will return a new memory buffer with the decoded string, otherwise
     * it returns NULL
     */
    temp = mk_utils_url_decode(sr->base.uri);

    if (temp) {
        sr->base.uri_processed.data = temp;
        sr->base.uri_processed.len  = strlen(temp);
    }
    else {
        sr->base.uri_processed.data = sr->base.uri.data;
        sr->base.uri_processed.len  = sr->base.uri.len;
    }

    /* Always assign the default vhost' */
    sr->base.host_conf = mk_list_entry_first(hosts, struct mk_vhost, _head);
    sr->base.user_home = MK_FALSE;

    /* Valid request URI? */
    if (sr->base.uri_processed.data[0] != '/') {
        mk_http1_error(MK_CLIENT_BAD_REQUEST, cs, sr, server);
        return MK_EXIT_OK;
    }

    /* Check if we have a Host header: Hostname ; port */
    mk_http1_point_header(&sr->base.host, &cs->parser, MK_HEADER_HOST);

    /* Header: Connection */
    mk_http1_point_header(&sr->base.connection, &cs->parser, MK_HEADER_CONNECTION);

    /* Header: Range */
    mk_http1_point_header(&sr->base.range, &cs->parser, MK_HEADER_RANGE);

    /* Header: If-Modified-Since */
    mk_http1_point_header(&sr->base.if_modified_since,
                         &cs->parser,
                         MK_HEADER_IF_MODIFIED_SINCE);

    /* HTTP/1.1 needs Host header */
    if (!sr->base.host.data && sr->base.protocol == MK_HTTP_PROTOCOL_11) {
        mk_http1_error(MK_CLIENT_BAD_REQUEST, cs, sr, server);
        return MK_EXIT_OK;
    }

    /* Should we close the session after this request ? */
    mk_http1_keepalive_check(cs, sr, server);

    /* Content Length */
    header = &cs->parser.headers[MK_HEADER_CONTENT_LENGTH];
    if (header->type == MK_HEADER_CONTENT_LENGTH) {
        sr->base._content_length.data = header->val.data;
        sr->base._content_length.len  = header->val.len;
    }
    else {
        sr->base._content_length.data = NULL;
    }

    /* Assign the first node alias */
    alias = &sr->base.host_conf->server_names;
    sr->base.host_alias = mk_list_entry_first(alias,
                                              struct mk_vhost_alias, _head);

    if (sr->base.host.data) {
        /* Set the given port */
        if (cs->parser.header_host_port > 0) {
            sr->base.port = cs->parser.header_host_port;
        }

        /* Match the virtual host */
        mk_vhost_get(sr->base.host, &sr->base.host_conf, &sr->base.host_alias, server);

        /* Check if this virtual host have some redirection */
        if (sr->base.host_conf->header_redirect.data) {
            mk_http_header_set_http_status(&sr->base, MK_REDIR_MOVED);
            sr->response.location = mk_string_dup(sr->base.host_conf->header_redirect.data);
            sr->response.content_length = 0;
            sr->response.location = NULL;
            mk_http_header_prepare(&cs->base, &sr->base, server);
            return 0;
        }
    }

    /* Is requesting an user home directory ? */
    if (server->conf_user_pub &&
        sr->base.uri_processed.len > 2 &&
        sr->base.uri_processed.data[1] == MK_USER_HOME) {

        if (mk_user_init(&cs->base, &sr->base, server) != 0) {
            mk_http1_error(MK_CLIENT_NOT_FOUND, cs, sr, server);
            return MK_EXIT_ABORT;
        }
    }

    /* Plugins Stage 20 */
    ret = mk_plugin_stage_run_20(&cs->base, &sr->base, server);
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        MK_TRACE("STAGE 20 requested close conexion");
        return MK_EXIT_ABORT;
    }

    /* Normal HTTP process */
    status = mk_http1_init(cs, sr, server);

    MK_TRACE("[FD %i] HTTP Init returning %i", cs->socket, status);
    return status;
}

/*
 * This function allow the core to invoke the closing connection process
 * when some connection was not proceesed due to a premature close or similar
 * exception, it also take care of invoke the STAGE_40 and STAGE_50 plugins events
 */
static void mk_http1_request_premature_close(int http_status, struct mk_http1_session *cs,
                                             struct mk_server *server)
{
    struct mk_http1_request *sr;
    struct mk_list *sr_list = &cs->base.request_list;
    struct mk_list *host_list = &server->hosts;

    /*
     * If the connection is too premature, we need to allocate a temporal session_request
     * to do not break the plugins stages
     */
    if (mk_list_is_empty(sr_list) == 0) {
        sr = &cs->sr_fixed;
        memset(sr, 0, sizeof(struct mk_http1_request));
        mk_http1_request_init(cs, sr, server);
        mk_list_add(&sr->base._head, &cs->base.request_list);
    }
    else {
        sr = mk_list_entry_first(sr_list, struct mk_http1_request, base._head);
    }

    /* Raise error */
    if (http_status > 0) {
        if (!sr->base.host_conf) {
            sr->base.host_conf = mk_list_entry_first(host_list,
                                                     struct mk_vhost, _head);
        }
        mk_http1_error(http_status, cs, sr, server);

        /* STAGE_40, request has ended */
        mk_plugin_stage_run_40(&cs->base, &sr->base, server);
    }

    /* STAGE_50, connection closed and remove the http_session */
    mk_plugin_stage_run_50(cs->base.socket, server);
    mk_http1_session_remove(cs, server);
}

int mk_http1_handler_read(struct mk_sched_conn *conn, struct mk_http1_session *cs,
                          struct mk_server *server)
{
    int bytes;
    int max_read;
    int available = 0;
    int new_size;
    int total_bytes = 0;
    char *tmp = 0;

#ifdef MK_HAVE_TRACE
    int socket = conn->event.fd;
#endif

    MK_TRACE("MAX REQUEST SIZE: %i", server->max_request_size);

 try_pending:

    available = cs->body_size - cs->body_length;
    if (available <= 0) {
        /* Reallocate buffer size if pending data does not have space */
        new_size = cs->body_size + conn->net->buffer_size;
        if (new_size > server->max_request_size) {
            MK_TRACE("Requested size is > mk_config->max_request_size");
            mk_http1_request_premature_close(MK_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs,
                                             server);
            return -1;
        }

        /*
         * Check if the body field still points to the initial body_fixed, if so,
         * allow the new space required in body, otherwise perform a realloc over
         * body.
         */
        if (cs->body == cs->body_fixed) {
            cs->body = mk_mem_alloc(new_size + 1);
            cs->body_size = new_size;
            memcpy(cs->body, cs->body_fixed, cs->body_length);
            MK_TRACE("[FD %i] New size: %i, length: %i",
                     socket, new_size, cs->body_length);
        }
        else {
            MK_TRACE("[FD %i] Realloc from %i to %i",
                     socket, cs->body_size, new_size);
            tmp = mk_mem_realloc(cs->body, new_size + 1);
            if (tmp) {
                cs->body = tmp;
                cs->body_size = new_size;
            }
            else {
                mk_http1_request_premature_close(MK_SERVER_INTERNAL_ERROR, cs,
                                           server);
                return -1;
            }
        }
    }

    /* Read content */
    max_read = (cs->body_size - cs->body_length);
    bytes = mk_sched_conn_read(conn, cs->body + cs->body_length, max_read);
    MK_TRACE("[FD %i] read %i", socket, bytes);

    if (bytes == 0) {
        MK_TRACE("[FD %i] broken pipe?", socket);
        errno = 0;
        return -1;
    }
    else if (bytes == -1) {
        return -1;
    }

    if (bytes > max_read) {
        MK_TRACE("[FD %i] Buffer still have data: %i",
                 socket, bytes - max_read);
        cs->body_length += max_read;
        cs->body[cs->body_length] = '\0';
        total_bytes += max_read;

        goto try_pending;
    }
    else {
        cs->body_length += bytes;
        cs->body[cs->body_length] = '\0';

        total_bytes += bytes;
    }

    MK_TRACE("[FD %i] Retry total bytes: %i", socket, total_bytes);
    return total_bytes;
}

/* Build error page */
static int mk_http1_error_page(char *title, mk_ptr_t *message, char *signature,
                              char **out_buf, unsigned long *out_size)
{
    char *temp;

    *out_buf = NULL;

    if (message) {
        temp = mk_ptr_to_buf(*message);
    }
    else {
        temp = mk_string_dup("");
    }

    mk_string_build(out_buf, out_size,
                    MK_REQUEST_DEFAULT_PAGE, title, temp, signature);
    mk_mem_free(temp);
    return 0;
}

static int mk_http1_range_set(struct mk_http1_request *sr, size_t file_size,
                              struct mk_server *server)
{
    struct mk_http1_response *sh = &sr->response;
    struct mk_stream_input *in;

    in = &sr->base.in_file;
    in->bytes_total  = file_size;
    in->bytes_offset = 0;

    if (server->resume == MK_TRUE && sr->base.range.data) {
        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            in->bytes_offset = sh->ranges[0];
            in->bytes_total = file_size - in->bytes_offset;
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            in->bytes_offset = sh->ranges[0];
            in->bytes_total  = labs(sh->ranges[1] - sh->ranges[0]) + 1;
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            in->bytes_total = sh->ranges[1];
            in->bytes_offset = file_size - sh->ranges[1];
        }

        if ((size_t) in->bytes_offset >= file_size ||
            in->bytes_total > file_size) {
            return -1;
        }

        lseek(in->fd, in->bytes_offset, SEEK_SET);
    }
    return 0;
}

static int mk_http1_range_parse(struct mk_http1_request *sr)
{
    int eq_pos, sep_pos, len;
    char *buffer = 0;
    struct mk_http1_response *sh;

    if (!sr->base.range.data)
        return -1;

    if ((eq_pos = mk_string_char_search(sr->base.range.data, '=', sr->base.range.len)) < 0)
        return -1;

    if (strncasecmp(sr->base.range.data, "Bytes", eq_pos) != 0)
        return -1;

    if ((sep_pos = mk_string_char_search(sr->base.range.data, '-', sr->base.range.len)) < 0)
        return -1;

    len = sr->base.range.len;
    sh = &sr->response;

    /* =-xxx */
    if (eq_pos + 1 == sep_pos) {
        sh->ranges[0] = -1;
        sh->ranges[1] = (unsigned long) atol(sr->base.range.data + sep_pos + 1);

        if (sh->ranges[1] <= 0) {
            return -1;
        }

        sh->content_length = sh->ranges[1];
        return 0;
    }

    /* =yyy-xxx */
    if ((eq_pos + 1 != sep_pos) && (len > sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->base.range.data, eq_pos + 1, sep_pos);
        sh->ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        buffer = mk_string_copy_substr(sr->base.range.data, sep_pos + 1, len);
        sh->ranges[1] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        if (sh->ranges[1] < 0 || (sh->ranges[0] > sh->ranges[1])) {
            return -1;
        }

        sh->content_length = abs(sh->ranges[1] - sh->ranges[0]) + 1;
        return 0;
    }
    /* =yyy- */
    if ((eq_pos + 1 != sep_pos) && (len == sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->base.range.data, eq_pos + 1, len);
        sr->response.ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        sh->content_length = (sh->content_length - sh->ranges[0]);
        return 0;
    }

    return -1;
}

static int mk_http1_directory_redirect_check(struct mk_http1_session *cs,
                                             struct mk_http1_request *sr,
                                             struct mk_server *server)
{
    int port_redirect = 0;
    char *host;
    char *location = 0;
    char *real_location = 0;
    char *protocol = "http";
    unsigned long len;

    /*
     * We have to check if there is a slash at the end of
     * this string. If it doesn't exist, we send a redirection header.
     */
    if (sr->base.uri_processed.data[sr->base.uri_processed.len - 1] == '/') {
        return 0;
    }

    host = mk_ptr_to_buf(sr->base.host);

    /*
     * Add ending slash to the location string
     */
    location = mk_mem_alloc(sr->base.uri_processed.len + 2);
    memcpy(location, sr->base.uri_processed.data, sr->base.uri_processed.len);
    location[sr->base.uri_processed.len] = '/';
    location[sr->base.uri_processed.len + 1] = '\0';

    /* FIXME: should we done something similar for SSL = 443 */
    if (sr->base.host.data && sr->base.port > 0) {
        if (sr->base.port != server->standard_port) {
            port_redirect = sr->base.port;
        }
    }

    if (MK_SCHED_CONN_PROP(cs->base.conn) & MK_CAP_SOCK_TLS) {
        protocol = "https";
    }

    if (port_redirect > 0) {
        mk_string_build(&real_location, &len, "%s://%s:%i%s\r\n",
                        protocol, host, port_redirect, location);
    }
    else {
        mk_string_build(&real_location, &len, "%s://%s%s\r\n",
                        protocol, host, location);
    }

    MK_TRACE("Redirecting to '%s'", real_location);
    mk_mem_free(host);

    mk_http_header_set_http_status(&sr->base, MK_REDIR_MOVED);
    sr->response.content_length = 0;

    mk_ptr_reset(&sr->response.content_type);
    sr->response.location = real_location;
    sr->response.cgi = SH_NOCGI;
    sr->response.pconnections_left =
        (server->max_keep_alive_request - cs->counter_connections);

    mk_http_header_prepare(&cs->base, &sr->base, server);

    /* we do not free() real_location as it's freed by iov */
    mk_mem_free(location);
    sr->response.location = NULL;
    return -1;
}

/* Look for some  index.xxx in pathfile */
static inline char *mk_http1_index_lookup(mk_ptr_t *path_base,
                                          char *buf, size_t buf_size,
                                          size_t *out, size_t *bytes,
                                          struct mk_server *server)
{
    off_t off = 0;
    size_t len;
    struct mk_string_line *entry;
    struct mk_list *head;

    if (!server->index_files) {
        return NULL;
    }

    off = path_base->len;
    memcpy(buf, path_base->data, off);

    mk_list_foreach(head, server->index_files) {
        entry = mk_list_entry(head, struct mk_string_line, _head);

        len = off + entry->len + 1;
        if (len >= buf_size) {
            continue;
        }

        memcpy(buf + off, entry->val, entry->len);
        buf[off + entry->len] = '\0';

        if (access(buf, F_OK) == 0) {
            MK_TRACE("Index lookup OK '%s'", buf);
            *out = off + entry->len;
            *bytes = path_base->len - 1;
            return buf;
        }
    }

    return NULL;
}

/* Turn CORK_OFF once headers are sent */
#if defined (__linux__)
static inline void mk_http1_cb_file_on_consume(struct mk_stream_input *in,
                                               long bytes)
{
    int ret;
    (void) bytes;

    /*
     * This callback is invoked just once as we want to turn off
     * the TCP Cork. We do this just overriding the callback for
     * the file stream.
     */
    ret = mk_server_cork_flag(in->stream->channel->fd, TCP_CORK_OFF);
    if (ret == -1) {
        mk_warn("Could not set TCP_CORK/TCP_NOPUSH off");
    }
    MK_TRACE("[FD %i] Disable TCP_CORK/TCP_NOPUSH",
             in->stream->channel->fd);
    in->cb_consumed = NULL;
}
#endif

int mk_http1_init(struct mk_http1_session *cs, struct mk_http1_request *sr,
                  struct mk_server *server)
{
    int ret;
    int ret_file;
    struct mk_mimetype *mime;
    struct mk_list *head;
    struct mk_list *handlers;
    struct mk_plugin *plugin;
    struct mk_vhost_handler *h_handler;
    struct mk_http_thread *mth = NULL;
    size_t index_length;
    size_t index_bytes;
    char *index_path = NULL;

    MK_TRACE("[FD %i] HTTP Protocol Init, session %p", cs->socket, sr);

    /* Request to root path of the virtualhost in question */
    if (sr->base.uri_processed.len == 1 && sr->base.uri_processed.data[0] == '/') {
        sr->base.real_path.data = sr->base.host_conf->documentroot.data;
        sr->base.real_path.len = sr->base.host_conf->documentroot.len;
    }

    /* Compose real path */
    if (sr->base.user_home == MK_FALSE) {
        int len;

        len = sr->base.host_conf->documentroot.len + sr->base.uri_processed.len;
        if (len < MK_PATH_BASE) {
            memcpy(sr->base.real_path_static,
                   sr->base.host_conf->documentroot.data,
                   sr->base.host_conf->documentroot.len);
            memcpy(sr->base.real_path_static + sr->base.host_conf->documentroot.len,
                   sr->base.uri_processed.data,
                   sr->base.uri_processed.len);
            sr->base.real_path_static[len] = '\0';
            sr->base.real_path.data = sr->base.real_path_static;
            sr->base.real_path.len = len;
        }
        else {
            ret = mk_buffer_cat(&sr->base.real_path,
                                sr->base.host_conf->documentroot.data,
                                sr->base.host_conf->documentroot.len,
                                sr->base.uri_processed.data,
                                sr->base.uri_processed.len);

            if (ret < 0) {
                MK_TRACE("Error composing real path");
                return MK_EXIT_ERROR;
            }
        }
    }

    /* Check if this is related to a protocol upgrade */
#ifdef MK_HAVE_HTTP2
    if (cs->parser.header_connection & MK_HTTP_PARSER_CONN_UPGRADE) {
        /* HTTP/2.0 upgrade ? */
        if (cs->parser.header_connection & MK_HTTP_PARSER_CONN_HTTP2_SE) {
            MK_TRACE("Connection Upgrade request: HTTP/2.0");
            /*
             * This is a HTTP/2.0 upgrade, we need to validate that we
             * have at least the 'Upgrade' and 'HTTP2-Settings' headers.
             */
            struct mk_http_header *p;
            p = &cs->parser.headers[MK_HEADER_HTTP2_SETTINGS];
            if (cs->parser.header_upgrade == MK_HTTP_PARSER_UPGRADE_H2C &&
                p->key.data) {
                /*
                 * Switch protocols and invoke the callback upgrade to prepare
                 * the new protocol internals.
                 */
                mk_sched_switch_protocol(cs->base.conn, MK_CAP_HTTP2);
                return cs->base.conn->protocol->cb_upgrade(cs, sr, server);
            }
            else {
                MK_TRACE("Invalid client upgrade request, skip it");
            }
        }
    }
#endif

    /* Check backward directory request */
    if (memmem(sr->base.uri_processed.data, sr->base.uri_processed.len,
               MK_HTTP_DIRECTORY_BACKWARD,
               sizeof(MK_HTTP_DIRECTORY_BACKWARD) - 1)) {
        return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
    }

    if (sr->base._content_length.data &&
        (sr->base.method != MK_METHOD_POST &&
         sr->base.method != MK_METHOD_PUT)) {
        sr->base._content_length.data = NULL;
        sr->base._content_length.len = 0;
    }

    ret_file = mk_file_get_info(sr->base.real_path.data, &sr->base.file_info, MK_FILE_READ);

    /* Manually set the headers input streams */
    sr->in_headers.type        = MK_STREAM_IOV;
    sr->in_headers.dynamic     = MK_FALSE;
    sr->in_headers.cb_consumed = NULL;
    sr->in_headers.cb_finished = NULL;
    sr->in_headers.stream      = &sr->base.stream;
    mk_list_add(&sr->in_headers._head, &sr->base.stream.inputs);

    /* Plugin Stage 30: look for handlers for this request */
    if (sr->base.stage30_blocked == MK_FALSE) {
        sr->base.uri_processed.data[sr->base.uri_processed.len] = '\0';
        handlers = &sr->base.host_conf->handlers;
        mk_list_foreach(head, handlers) {
            h_handler = mk_list_entry(head, struct mk_vhost_handler, _head);

            if (regexec(h_handler->match,
                        sr->base.uri_processed.data, 0, NULL, 0) != 0) {
                continue;
            }

            if (h_handler->cb) {
                /* Create coroutine/thread context */
                sr->response.content_length = 0;
                mth = mk_http_thread_create(MK_HTTP_THREAD_LIB,
                                            h_handler,
                                            cs, sr,
                                            0, NULL);
                if (!mth) {
                    return -1;
                }

                mk_http_thread_start(mth);
                return MK_EXIT_OK;
            }
            else {
                if (!h_handler->handler) {
                    return mk_http1_error(MK_SERVER_INTERNAL_ERROR, cs, sr,
                                         server);
                }
                plugin = h_handler->handler;
                sr->base.stage30_handler = h_handler->handler;
                ret = plugin->stage->stage30(plugin, &cs->base, &sr->base,
                                             h_handler->n_params,
                                             &h_handler->params);
                mk_http_header_prepare(&cs->base, &sr->base, server);
            }

            MK_TRACE("[FD %i] STAGE_30 returned %i", cs->socket, ret);
            switch (ret) {
            case MK_PLUGIN_RET_CONTINUE:
                /* FIXME: PLUGINS DISABLED
                if ((plugin->flags & MK_PLUGIN_THREAD) &&
                    plugin->stage->stage30_thread) {
                    mth = mk_http_thread_new(MK_HTTP_THREAD_PLUGIN,
                                             plugin, cs, sr,
                                             h_handler->n_params,
                                             &h_handler->params);
                    printf("[http thread] %p\n", mth);
                    mk_http_thread_resume(mth->parent);
                }
                */
                return MK_PLUGIN_RET_CONTINUE;
            case MK_PLUGIN_RET_CLOSE_CONX:
                if (sr->response.status > 0) {
                    return mk_http1_error(sr->response.status, cs, sr, server);
                }
                else {
                    return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
                }
            case MK_PLUGIN_RET_END:
                return MK_EXIT_OK;
            }
        }
    }

    /* If there is no handler and the resource don't exists, raise a 404 */
    if (ret_file == -1) {
        return mk_http1_error(MK_CLIENT_NOT_FOUND, cs, sr, server);
    }

    /* is it a valid directory ? */
    if (sr->base.file_info.is_directory == MK_TRUE) {
        /* Send redirect header if end slash is not found */
        if (mk_http1_directory_redirect_check(cs, sr, server) == -1) {
            MK_TRACE("Directory Redirect");

            /* Redirect has been sent */
            return -1;
        }

        /* looking for an index file */
        char tmppath[MK_MAX_PATH];
        index_path = mk_http1_index_lookup(&sr->base.real_path,
                                           tmppath, MK_MAX_PATH,
                                           &index_length, &index_bytes,
                                           server);
        if (index_path) {
            if (sr->base.real_path.data != sr->base.real_path_static) {
                mk_ptr_free(&sr->base.real_path);
                sr->base.real_path.data = mk_string_dup(index_path);
            }
            /* If it's static and it still fits */
            else if (index_length < MK_PATH_BASE) {
                memcpy(sr->base.real_path_static, index_path, index_length);
                sr->base.real_path_static[index_length] = '\0';
            }
            /* It was static, but didn't fit */
            else {
                sr->base.real_path.data = mk_string_dup(index_path);
            }
            sr->base.real_path.len  = index_length;

            ret = mk_file_get_info(sr->base.real_path.data,
                                   &sr->base.file_info, MK_FILE_READ);
            if (ret != 0) {
                return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
            }

        }
    }

    /* Check symbolic link file */
    if (sr->base.file_info.is_link == MK_TRUE) {
        if (server->symlink == MK_FALSE) {
            return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
        }
        else {
            int n;
            char linked_file[MK_MAX_PATH];
            n = readlink(sr->base.real_path.data, linked_file, MK_MAX_PATH);
            if (n < 0) {
                return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
            }
        }
    }

    /* Plugin Stage 30: look for handlers for this request */
    if (sr->base.stage30_blocked == MK_FALSE) {
        char *uri;

        if (!index_path) {
            sr->base.uri_processed.data[sr->base.uri_processed.len] = '\0';
            uri = sr->base.uri_processed.data;
        }
        else {
            uri = sr->base.real_path.data + index_bytes;
        }

        handlers = &sr->base.host_conf->handlers;
        mk_list_foreach(head, handlers) {
            h_handler = mk_list_entry(head, struct mk_vhost_handler, _head);
            if (regexec(h_handler->match,
                        uri, 0, NULL, 0) != 0) {
                continue;
            }

            plugin = h_handler->handler;
            sr->base.stage30_handler = h_handler->handler;
            ret = plugin->stage->stage30(plugin, &cs->base, &sr->base,
                                         h_handler->n_params,
                                         &h_handler->params);

            MK_TRACE("[FD %i] STAGE_30 returned %i", cs->socket, ret);
            switch (ret) {
            case MK_PLUGIN_RET_CONTINUE:
                return MK_PLUGIN_RET_CONTINUE;
            case MK_PLUGIN_RET_CLOSE_CONX:
                if (sr->response.status > 0) {
                    return mk_http1_error(sr->response.status, cs, sr, server);
                }
                else {
                    return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
                }
            case MK_PLUGIN_RET_END:
                return MK_EXIT_OK;
            }
        }
    }

    /*
     * Monkey listens for PUT and DELETE methods in addition to GET, POST and
     * HEAD, but it does not care about them, so if any plugin did not worked
     * on it, Monkey will return error 501 (501 Not Implemented).
     */
    if (sr->base.method == MK_METHOD_PUT || sr->base.method == MK_METHOD_DELETE) {
        return mk_http1_error(MK_CLIENT_METHOD_NOT_ALLOWED, cs, sr, server);
    }
    else if (sr->base.method == MK_METHOD_UNKNOWN) {
        return mk_http1_error(MK_SERVER_NOT_IMPLEMENTED, cs, sr, server);
    }

    /* counter connections */
    sr->response.pconnections_left = (int)
        (server->max_keep_alive_request - cs->counter_connections);

    /* Set default value */
    mk_http_header_set_http_status(&sr->base, MK_HTTP_OK);
    sr->response.location = NULL;
    sr->response.content_length = 0;

    /*
     * For OPTIONS method, we let the plugin handle it and
     * return without any content.
     */
    if (sr->base.method == MK_METHOD_OPTIONS) {
        /* FIXME: OPTIONS NOT WORKING */
        //sr->response.allow_methods.data = MK_METHOD_AVAILABLE;
        //sr->response.allow_methods.len = strlen(MK_METHOD_AVAILABLE);

        mk_ptr_reset(&sr->response.content_type);
        mk_http_header_prepare(&cs->base, &sr->base, server);
        return MK_EXIT_OK;
    }
    else {
        mk_ptr_reset(&sr->response.allow_methods);
    }

    /* read permissions and check file */
    if (sr->base.file_info.read_access == MK_FALSE) {
        return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
    }

    /* Matching MimeType  */
    mime = mk_mimetype_find(server, &sr->base.real_path);
    if (!mime) {
        mime = server->mimetype_default;
    }

    if (sr->base.file_info.is_directory == MK_TRUE) {
        return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
    }

    /* get file size */
    if (sr->base.file_info.size == 0) {
        return mk_http1_error(MK_CLIENT_NOT_FOUND, cs, sr, server);
    }

    /* Configure some headers */
    sr->response.last_modified = sr->base.file_info.last_modification;
    sr->response.etag_len = snprintf(sr->response.etag_buf,
                                     MK_HEADER_ETAG_SIZE,
                                     "ETag: \"%x-%zx\"\r\n",
                                     (unsigned int) sr->base.file_info.last_modification,
                                     sr->base.file_info.size);

    if (sr->base.if_modified_since.data && sr->base.method == MK_METHOD_GET) {
        time_t date_client;       /* Date sent by client */
        time_t date_file_server;  /* Date server file */

        date_client = mk_utils_gmt2utime(sr->base.if_modified_since.data);
        date_file_server = sr->base.file_info.last_modification;

        if (date_file_server <= date_client &&
            date_client > 0) {
            mk_http_header_set_http_status(&sr->base, MK_NOT_MODIFIED);
            mk_http_header_prepare(&cs->base, &sr->base, server);
            return MK_EXIT_OK;
        }
    }

    /* Object size for log and response headers */
    sr->response.content_length = sr->base.file_info.size;
    sr->response.real_length = sr->base.file_info.size;

    /* Open file */
    if (mk_likely(sr->base.file_info.size > 0)) {
        sr->base.file_fd = mk_vhost_open(&sr->base, server);
        if (sr->base.file_fd == -1) {
            MK_TRACE("open() failed");
            return mk_http1_error(MK_CLIENT_FORBIDDEN, cs, sr, server);
        }
        sr->base.in_file.fd           = sr->base.file_fd;
        sr->base.in_file.bytes_offset = 0;
        sr->base.in_file.bytes_total  = sr->base.file_info.size;
        sr->base.in_file.stream       = &sr->base.stream;
    }

    /* Process methods */
    if (sr->base.method == MK_METHOD_GET || sr->base.method == MK_METHOD_HEAD) {
        if (mime) {
            sr->response.content_type = mime->header_type;
        }

        /* HTTP Ranges */
        if (sr->base.range.data != NULL && server->resume == MK_TRUE) {
            if (mk_http1_range_parse(sr) < 0) {
                sr->response.ranges[0] = -1;
                sr->response.ranges[1] = -1;
                return mk_http1_error(MK_CLIENT_BAD_REQUEST, cs, sr, server);
            }
            if (sr->response.ranges[0] >= 0 || sr->response.ranges[1] >= 0) {
                mk_http_header_set_http_status(&sr->base, MK_HTTP_PARTIAL);
            }

            /* Calc bytes to send & offset */
            if (mk_http1_range_set(sr, sr->base.file_info.size, server) != 0) {
                sr->response.content_length = -1;
                sr->response.ranges[0] = -1;
                sr->response.ranges[1] = -1;
                return mk_http1_error(MK_CLIENT_REQUESTED_RANGE_NOT_SATISF,
                                     cs, sr, server);
            }
        }
    }
    else {
        /* without content-type */
        mk_ptr_reset(&sr->response.content_type);
    }

    /* Send headers */
    mk_http_header_prepare(&cs->base, &sr->base, server);
    if (mk_unlikely(sr->response.content_length == 0)) {
        return 0;
    }
    /* Send file content */
    if (sr->base.method == MK_METHOD_GET || sr->base.method == MK_METHOD_POST) {
        /* Note: bytes and offsets are set after the Range check */
        sr->base.in_file.type = MK_STREAM_FILE;
        mk_stream_append(&sr->base.in_file, &sr->base.stream);
    }

    /*
     * Enable TCP Cork for the remote socket. It will be disabled
     * later by the file stream on the channel after send the first
     * file bytes.
     */
#if defined(__linux__)
    sr->base.in_file.cb_consumed = mk_http1_cb_file_on_consume;
#endif

    /*
     * Enable CORK/NO_PUSH
     * -------------------
     * If it was compiled for Linux, it will turn the Cork off after
     * send the first round of bytes from the target static file.
     *
     * For OSX, it sets TCP_NOPUSH off after send all HTTP headers. Refer
     * to mk_header.c for more details.
     */
    //mk_server_cork_flag(cs->socket, TCP_CORK_ON);

    /* Start sending data to the channel */
    return MK_EXIT_OK;
}

/*
 * Check if a connection can stay open using
 * the keepalive headers vars and Monkey configuration as criteria
 */
int mk_http1_keepalive_check(struct mk_http1_session *cs,
                             struct mk_http1_request *sr,
                             struct mk_server *server)
{
    if (server->keep_alive == MK_FALSE) {
        return -1;
    }

    /* Default Keepalive is off */
    if (sr->base.protocol == MK_HTTP_PROTOCOL_10) {
        cs->base.close_now = MK_TRUE;
    }
    else if (sr->base.protocol == MK_HTTP_PROTOCOL_11) {
        cs->base.close_now = MK_FALSE;
    }

    if (sr->base.connection.data) {
        if (cs->parser.header_connection == MK_HTTP_PARSER_CONN_KA &&
            sr->base.protocol == MK_HTTP_PROTOCOL_11) {
            cs->base.close_now  = MK_FALSE;
        }
        else if (cs->parser.header_connection == MK_HTTP_PARSER_CONN_CLOSE) {
            cs->base.close_now  = MK_TRUE;
        }
    }

    /* Client has reached keep-alive connections limit */
    if (cs->counter_connections >= server->max_keep_alive_request) {
        cs->base.close_now = MK_TRUE;
        return -1;
    }

    return 0;
}

static inline void mk_http1_request_ka_next(struct mk_http1_session *cs)
{
    cs->body_length = 0;
    cs->counter_connections++;

    /* Update data for scheduler */
    cs->init_time = log_current_utime;
    cs->base.status = MK_REQUEST_STATUS_INCOMPLETE;

    /* Initialize parser */
    mk_http_parser_init(&cs->parser);
}

int mk_http1_request_end(struct mk_http1_session *cs, struct mk_server *server)
{
    int ret;
    int status;
    int len;
    struct mk_http1_request *sr = NULL;

    if (server->max_keep_alive_request <= cs->counter_connections) {
        cs->base.close_now = MK_TRUE;
        goto shutdown;
    }

    /* Check if we have some enqueued pipeline requests */
    ret = mk_http_parser_more(&cs->parser, cs->body_length);
    if (ret == MK_TRUE) {
        /* Our pipeline request limit is the same that our keepalive limit */
        cs->counter_connections++;
        len = (cs->body_length - cs->parser.i) -1;
        memmove(cs->body,
                cs->body + cs->parser.i + 1,
                len);
        cs->body_length = len;

        /* Prepare for next one */
        sr = mk_list_entry_first(&cs->base.request_list, struct mk_http1_request, base._head);
        mk_http1_request_free(sr, server);
        mk_http1_request_init(cs, sr, server);
        mk_http_parser_init(&cs->parser);
        status = mk_http_parser(sr, &cs->parser, cs->body, cs->body_length,
                                server);
        if (status == MK_HTTP_PARSER_OK) {
            ret = mk_http1_request_prepare(cs, sr, server);
            if (ret == MK_EXIT_ABORT) {
                return -1;
            }

            /*
             * Return 1 means, we still have more data to send in a different
             * scheduler round.
             */
            return 1;
        }
        else if (status == MK_HTTP_PARSER_PENDING) {
            return 0;
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            cs->base.close_now = MK_TRUE;
        }
    }

 shutdown:
    /*
     * We need to ask to http_keepalive if this
     * connection can continue working or we must
     * close it.
     */
    if (cs->base.close_now == MK_TRUE) {
        MK_TRACE("[FD %i] No KeepAlive mode, remove", cs->base.conn->event.fd);
        mk_http1_session_remove(cs, server);
        return -1;
    }
    else {
        mk_http1_request_free_list(cs, server);
        mk_http1_request_ka_next(cs);
        mk_sched_conn_timeout_add(cs->base.conn, mk_sched_get_thread_conf());
        return 0;
    }

    return -1;
}

void cb_stream_page_finished(struct mk_stream_input *in)
{
    mk_ptr_t *page = in->buffer;

    mk_ptr_free(page);
    mk_mem_free(page);
}

/* Enqueue an error response. This function always returns MK_EXIT_OK */
int mk_http1_error(int http_status, struct mk_http1_session *cs,
                  struct mk_http1_request *sr,
                  struct mk_server *server)
{
    int ret, fd;
    size_t count;
    mk_ptr_t message;
    mk_ptr_t page;
    struct mk_vhost_error_page *entry;
    struct mk_list *head;
    struct file_info finfo;
    struct mk_iov *iov;

    mk_http_header_set_http_status(&sr->base, http_status);
    mk_ptr_reset(&page);

    /*
     * We are nice sending error pages for clients who at least respect
     * the especification
     */
    if (http_status != MK_CLIENT_LENGTH_REQUIRED &&
        http_status != MK_CLIENT_BAD_REQUEST &&
        http_status != MK_CLIENT_REQUEST_ENTITY_TOO_LARGE) {

        /* Lookup a customized error page */
        mk_list_foreach(head, &sr->base.host_conf->error_pages) {
            entry = mk_list_entry(head, struct mk_vhost_error_page, _head);
            if (entry->status != http_status) {
                continue;
            }

            /* validate error file */
            ret = mk_file_get_info(entry->real_path, &finfo, MK_FILE_READ);
            if (ret == -1) {
                break;
            }

            /* open file */
            fd = open(entry->real_path, server->open_flags);
            if (fd == -1) {
                break;
            }

            /* Outgoing headers */
            sr->response.content_length = finfo.size;
            sr->response.real_length    = finfo.size;
            mk_http_header_prepare(&cs->base, &sr->base, server);

            /* Stream setup */
            mk_stream_in_file(&sr->base.stream, &sr->base.in_file, sr->base.file_fd,
                              finfo.size, 0, NULL, NULL);

            return MK_EXIT_OK;
        }
    }

    mk_ptr_reset(&message);

    switch (http_status) {
    case MK_CLIENT_FORBIDDEN:
        mk_http1_error_page("Forbidden",
                           &sr->base.uri,
                           server->server_signature,
                           &page.data, &page.len);
        break;
    case MK_CLIENT_NOT_FOUND:
        mk_string_build(&message.data, &message.len,
                        "The requested URL was not found on this server.");
        mk_http1_error_page("Not Found",
                           &message,
                           server->server_signature,
                           &page.data, &page.len);
        mk_ptr_free(&message);
        break;
    case MK_CLIENT_REQUEST_ENTITY_TOO_LARGE:
        mk_string_build(&message.data, &message.len,
                        "The request entity is too large.");
        mk_http1_error_page("Entity too large",
                           &message,
                           server->server_signature,
                           &page.data, &page.len);
        mk_ptr_free(&message);
        break;
    case MK_CLIENT_METHOD_NOT_ALLOWED:
        mk_http1_error_page("Method Not Allowed",
                           &sr->base.uri,
                           server->server_signature,
                           &page.data, &page.len);
        break;
    case MK_SERVER_NOT_IMPLEMENTED:
        mk_http1_error_page("Method Not Implemented",
                           &sr->base.uri,
                           server->server_signature,
                           &page.data, &page.len);
        break;
    case MK_SERVER_INTERNAL_ERROR:
        mk_http1_error_page("Internal Server Error",
                           &sr->base.uri,
                           server->server_signature,
                           &page.data, &page.len);
        break;
    }

    if (page.len > 0 && 
        sr->base.method != MK_METHOD_HEAD && 
        sr->base.method != MK_METHOD_UNKNOWN) {
        sr->response.content_length = page.len;
    }
    else {
        sr->response.content_length = 0;
    }

    sr->response.location = NULL;
    sr->response.cgi = SH_NOCGI;
    sr->response.pconnections_left = 0;
    sr->response.last_modified = -1;

    if (!page.data) {
        mk_ptr_reset(&sr->response.content_type);
    }
    else {
        mk_ptr_set(&sr->response.content_type, "Content-Type: text/html\r\n");
    }

    mk_http_header_prepare(&cs->base, &sr->base, server);
    if (page.data) {
        if (sr->base.method != MK_METHOD_HEAD) {
            if (sr->response._extra_rows) {
                iov = sr->response._extra_rows;
                sr->in_headers_extra.bytes_total += page.len;
            }
            else {
                iov = &sr->response.headers_iov;
                sr->in_headers.bytes_total += page.len;
            }
            mk_iov_add(iov, page.data, page.len, MK_TRUE);
        }
        else {
            mk_mem_free(page.data);
        }
    }

    mk_channel_write(cs->base.channel, &count);
    mk_http1_request_end(cs, server);

    return MK_EXIT_OK;
}

/*
 * From thread mk_sched_worker "list", remove the http_session
 * struct information
 */
void mk_http1_session_remove(struct mk_http1_session *cs,
                             struct mk_server *server)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_plugin *handler;
    struct mk_http1_request *sr;

    MK_TRACE("[FD %i] HTTP Session remove", cs->socket);
    if (cs->base._sched_init == MK_FALSE) {
        return;
    }

    /* On session remove, make sure to cleanup any handler */
    mk_list_foreach_safe(head, tmp, &cs->base.request_list) {
        sr = mk_list_entry(head, struct mk_http1_request, base._head);
        if (sr->base.stage30_handler) {
            MK_TRACE("Hangup stage30 handler");
            handler = sr->base.stage30_handler;
            if (mk_unlikely(!handler->stage->stage30_hangup)) {
                mk_warn("Plugin %s, do not implement stage30_hangup", handler->name);
                continue;
            }
            handler->stage->stage30_hangup(handler, &cs->base, &sr->base);
        }
    }

    if (cs->body != cs->body_fixed) {
        mk_mem_free(cs->body);
    }
    mk_http1_request_free_list(cs, server);
    mk_list_del(&cs->base.request_list);

    cs->base._sched_init = MK_FALSE;
}

/* FIXME: nobody is using this */
struct mk_http1_session *mk_http1_session_lookup(int socket)
{
    (void) socket;
	return NULL;
}


/* Initialize a HTTP session (just created) */
int mk_http1_session_init(struct mk_http1_session *cs, struct mk_sched_conn *conn,
                          struct mk_server *server)
{
    /* Set up the link between the base and specific objects */
    cs->base.additional_data.http_1 = cs;

    cs->base.protocol_version = HTTP_1;

    /* Alloc memory for node */
    cs->base._sched_init = MK_TRUE;
    cs->pipelined = MK_FALSE;
    cs->counter_connections = 0;
    cs->base.close_now = MK_FALSE;
    cs->base.socket = conn->event.fd;
    cs->base.status = MK_REQUEST_STATUS_INCOMPLETE;
    cs->base.server = server;

    /* Map the channel, just for protocol-handler internal stuff */
    cs->base.channel = &conn->channel;

    /* Map the connection instance, required to handle exceptions */
    cs->base.conn = conn;

    /* creation time in unix time */
    cs->init_time = conn->arrive_time;

    /* alloc space for body content */
    if (conn->net->buffer_size > MK_REQUEST_CHUNK) {
        cs->body = mk_mem_alloc(conn->net->buffer_size);
        cs->body_size = conn->net->buffer_size;
    }
    else {
        /* Buffer size based in Chunk bytes */
        cs->body = cs->body_fixed;
        cs->body_size = MK_REQUEST_CHUNK;
    }

    /* Current data length */
    cs->body_length = 0;

    /* Init session request list */
    mk_list_init(&cs->base.request_list);

    /* Initialize the parser */
    mk_http_parser_init(&cs->parser);

    return 0;
}


void mk_http1_request_free(struct mk_http1_request *sr, struct mk_server *server)
{
    /* Let the vhost interface to handle the session close */
    mk_vhost_close(&sr->base, server);

    if (sr->response.location) {
        mk_mem_free(sr->response.location);
    }

    if (sr->base.uri_processed.data != sr->base.uri.data) {
        mk_ptr_free(&sr->base.uri_processed);
    }

    if (sr->base.real_path.data != sr->base.real_path_static) {
        mk_ptr_free(&sr->base.real_path);
    }

    if (sr->base.stream.channel) {
        mk_stream_release(&sr->base.stream);
    }
}

void mk_http1_request_free_list(struct mk_http1_session *cs,
                                struct mk_server *server)
{
    struct mk_list *head, *tmp;
    struct mk_http1_request *request;

    /* sr = last node */
    MK_TRACE("[FD %i] Free struct client_session", cs->socket);
    mk_list_foreach_safe(head, tmp, &cs->base.request_list) {
        request = mk_list_entry(head, struct mk_http1_request, base._head);
        mk_list_del(&request->base._head);

        mk_http1_request_free(request, server);
        if (request != &cs->sr_fixed) {
            mk_mem_free(request);
        }
    }
}

/*
 * Lookup a known header or a non-known header. For unknown headers
 * set the 'key' value wth a lowercase string
 */
struct mk_http_header *mk_http1_header_get(int name, struct mk_http1_request *req,
                                           const char *key, unsigned int len)
{
    int i;
    struct mk_http_parser *parser = &req->base.session->additional_data.http_1->parser;
    struct mk_http_header *header;

    /* Known header */
    if (name >= 0 && name < MK_HEADER_SIZEOF) {
        return &parser->headers[name];
    }

    /* Check if want to retrieve a custom header */
    if (name == MK_HEADER_OTHER) {
        /* Iterate over the extra headers identified by the parser */
        for (i = 0; i < parser->headers_extra_count; i++) {
            header = &parser->headers_extra[i];
            if (header->key.len != len) {
                continue;
            }

            if (strncmp(header->key.data, key, len) == 0) {
                return header;
            }
        }
        return NULL;
    }

    return NULL;
}

/*
 * Main callbacks for the Scheduler
 */
int mk_http1_sched_read(struct mk_sched_conn *conn,
                        struct mk_sched_worker *worker,
                        struct mk_server *server)
{
    int ret;
    int status;
    size_t count;
    (void) worker;
    struct mk_http1_session *cs;
    struct mk_http1_request *sr;

#ifdef MK_HAVE_TRACE
    int socket = conn->event.fd;
#endif

    cs = mk_http1_session_get(conn);
    if (cs->base._sched_init == MK_FALSE) {
        /* Create session for the client */
        MK_TRACE("[FD %i] Create HTTP session", socket);
        ret  = mk_http1_session_init(cs, conn, server);
        if (ret == -1) {
            return -1;
        }
    }

    /* Invoke the read handler, on this case we only support HTTP (for now :) */
    ret = mk_http1_handler_read(conn, cs, server);
    if (ret > 0) {
        if (mk_list_is_empty(&cs->base.request_list) == 0) {
            /* Add the first entry */
            sr = &cs->sr_fixed;
            mk_list_add(&sr->base._head, &cs->base.request_list);
            mk_http1_request_init(cs, sr, server);
        }
        else {
            sr = mk_list_entry_first(&cs->base.request_list, struct mk_http1_request, base._head);
        }
        status = mk_http_parser(sr, &cs->parser, cs->body,
                                cs->body_length, server);
        if (status == MK_HTTP_PARSER_OK) {
            MK_TRACE("[FD %i] HTTP_PARSER_OK", socket);
            if (mk_http_status_completed(cs, conn) == -1) {
                mk_http1_session_remove(cs, server);
                return -1;
            }
            mk_sched_conn_timeout_del(conn);
            ret = mk_http1_request_prepare(cs, sr, server);
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            /* The HTTP parser may enqueued some response error */
            if (mk_channel_is_empty(cs->base.channel) != 0) {
                mk_channel_write(cs->base.channel, &count);
            }
            mk_http1_session_remove(cs, server);
            MK_TRACE("[FD %i] HTTP_PARSER_ERROR", socket);
            return -1;
        }
        else {
            MK_TRACE("[FD %i] HTTP_PARSER_PENDING", socket);
        }
    }

    return ret;
}

/* The scheduler got a connection close event from the remote client */
int mk_http1_sched_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type, struct mk_server *server)
{
    struct mk_http1_session *session;
    (void) sched;

#ifdef MK_HAVE_TRACE
    MK_TRACE("[FD %i] HTTP sched close (type=%i)", conn->event.fd, type);
#else
    (void) type;
#endif

    /* Release resources of the requests and session */
    session = mk_http1_session_get(conn);
    mk_http1_session_remove(session, server);
    return 0;
}

int mk_http1_sched_done(struct mk_sched_conn *conn,
                        struct mk_sched_worker *worker,
                        struct mk_server *server)
{
    (void) worker;
    struct mk_http1_session *session;
    struct mk_http1_request *sr;

    session = mk_http1_session_get(conn);
    sr = mk_list_entry_first(&session->base.request_list,
                             struct mk_http1_request, base._head);
    mk_plugin_stage_run_40(&session->base, &sr->base, server);

    return mk_http1_request_end(session, server);
}

struct mk_sched_handler mk_http_handler = {
    .name             = "http",
    .cb_read          = mk_http1_sched_read,
    .cb_close         = mk_http1_sched_close,
    .cb_done          = mk_http1_sched_done,
    .sched_extra_size = sizeof(struct mk_http1_session),
    .capabilities     = MK_CAP_HTTP
};
