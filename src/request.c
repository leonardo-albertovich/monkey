/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <time.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "request.h"
#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "string.h"
#include "str.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"
#include "utils.h"
#include "header.h"
#include "user.h"
#include "method.h"
#include "memory.h"
#include "socket.h"
#include "cache.h"
#include "clock.h"
#include "plugin.h"
#include "macros.h"

/* Create a memory allocation in order to handle the request data */
static struct session_request *mk_request_alloc()
{
    struct session_request *request = 0;

    request = mk_mem_malloc(sizeof(struct session_request));
    request->status = MK_FALSE;  /* Request not processed yet */
    request->close_now = MK_FALSE;

    mk_pointer_reset(&request->body);
    request->status = MK_TRUE;
    request->method = METHOD_NOT_FOUND;

    mk_pointer_reset(&request->uri);
    request->uri_processed.data = NULL;

    request->content_length = 0;
    request->content_type.data = NULL;
    request->connection.data = NULL;
    request->host.data = NULL;
    request->if_modified_since.data = NULL;
    request->last_modified_since.data = NULL;
    request->range.data = NULL;

    request->post_variables.data = NULL;
    mk_pointer_reset(&request->query_string);

    request->file_info = NULL;
    request->virtual_user = NULL;

    mk_pointer_reset(&request->real_path);
    request->host_conf = config->hosts;

    request->loop = 0;
    request->bytes_to_send = -1;
    request->bytes_offset = 0;
    request->fd_file = -1;

    /* Response Headers */
    request->headers = mk_header_create();

    /* Plugin handler */
    request->handled_by = NULL;

    /* 
     * FIXME: these fields will be dropped once plugins
     * uses the new headers ToC interface
     */
    request->accept.data = NULL;
    request->accept_language.data = NULL;
    request->accept_encoding.data = NULL;
    request->accept_charset.data = NULL;
    request->cookies.data = NULL;
    request->referer.data = NULL;
    request->resume.data = NULL;
    request->user_agent.data = NULL;

    return request;
}


static void mk_request_free(struct session_request *sr)
{
    if (sr->fd_file > 0) {
        close(sr->fd_file);
    }

    if (sr->headers) {
        mk_mem_free(sr->headers->location);
        mk_mem_free(sr->headers);
    }

    if (sr->uri_processed.data != sr->uri.data) {
        mk_pointer_free(&sr->uri_processed);
    }

    mk_pointer_reset(&sr->body);
    mk_pointer_reset(&sr->uri);
    mk_pointer_reset(&sr->query_string);

    mk_mem_free(sr->file_info);
    mk_mem_free(sr->virtual_user);

    mk_pointer_free(&sr->real_path);
    mk_mem_free(sr);
}

static void mk_request_header_toc_parse(struct header_toc *toc, const char *data, int len)
{
    char *p, *l = 0;
    int i;

    p = (char *)data;
    for (i = 0; i < MK_HEADERS_TOC_LEN && p && l < data + len; i++) {
        l = strstr(p, MK_CRLF);
        if (l) {
            toc[i].init = p;
            toc[i].end = l;
            p = l + mk_crlf.len;
        }
        else {
            break;
        }
    }
}

/* Return a struct with method, URI , protocol version
and all static headers defined here sent in request */
static int mk_request_header_process(struct session_request *sr)
{
    int uri_init = 0, uri_end = 0;
    int query_init = 0;
    int prot_init = 0, prot_end = 0, pos_sep = 0;
    int fh_limit;
    char *port = 0;
    char *headers;
    char *temp = 0;
    mk_pointer host;

    /* Method */
    sr->method_p = mk_http_method_check_str(sr->method);

    /* Request URI */
    uri_init = (index(sr->body.data, ' ') - sr->body.data) + 1;
    fh_limit = (index(sr->body.data, '\n') - sr->body.data);

    uri_end = mk_string_char_search_r(sr->body.data, ' ', fh_limit) - 1;

    if (uri_end <= 0) {
        MK_TRACE("Error, first header bad formed");
        return -1;
    }
    
    prot_init = uri_end + 2;

    if (uri_end < uri_init) {
        return -1;
    }

    /* Query String */
    query_init = mk_string_char_search(sr->body.data + uri_init, '?', prot_init);
    if (query_init > 0) {
        int init, end;

        init = query_init + uri_init;
        if (init <= uri_end) {
            end = uri_end;
            uri_end = init - 1;

            sr->query_string = mk_pointer_create(sr->body.data,
                                                 init + 1, end + 1);
        }
    }
    
    /* Request URI Part 2 */
    sr->uri = mk_pointer_create(sr->body.data, uri_init, uri_end + 1);
    if (sr->uri.len < 1) {
        return -1;
    }

    /* HTTP Version */
    prot_end = fh_limit - 1;
    if (prot_init == prot_end) {
        return  -1;
    }
    
    if (prot_end != prot_init && prot_end > 0) {
        sr->protocol = mk_http_protocol_check(sr->body.data + prot_init,
                                              prot_end - prot_init);
        sr->protocol_p = mk_http_protocol_check_str(sr->protocol);
    }

    headers = sr->body.data + prot_end + mk_crlf.len;

    /* 
     * Process URI, if it contains ASCII encoded strings like '%20', 
     * it will return a new memory buffer with the decoded string, otherwise
     * it returns NULL
     */
    temp = mk_utils_url_decode(sr->uri);
    if (temp) {
        sr->uri_processed.data = temp;
        sr->uri_processed.len  = strlen(temp);
    }
    else {
        sr->uri_processed.data = sr->uri.data;
        sr->uri_processed.len  = sr->uri.len;
    }

    /* Creating Table of Content (index) for HTTP headers */
    sr->headers_len = sr->body.len - (prot_end + mk_crlf.len);
    mk_request_header_toc_init(sr->headers_toc);
    mk_request_header_toc_parse(sr->headers_toc, headers, sr->headers_len);

    /* Host */
    host = mk_request_header_get(sr->headers_toc, mk_rh_host);

    if (host.data) {
        if ((pos_sep = mk_string_char_search(host.data, ':', host.len)) >= 0) {
            /* just the host */
            sr->host.data = host.data;
            sr->host.len = pos_sep;

            /* including the port */
            sr->host_port = host;

            port = mk_string_copy_substr(host.data, pos_sep + 1, host.len);
            sr->port = strtol(port, (char **) NULL, 10);
            mk_mem_free(port);
        }
        else {
            sr->host = host;    /* maybe null */
            sr->port = config->standard_port;
        }
    }
    else {
        sr->host.data = NULL;
    }

    /* Looking for headers that ONLY Monkey uses */
    sr->connection = mk_request_header_get(sr->headers_toc, mk_rh_connection);
    sr->range = mk_request_header_get(sr->headers_toc, mk_rh_range);
    sr->if_modified_since = mk_request_header_get(sr->headers_toc, mk_rh_if_modified_since);

    /* FIXME: this headers pointers should not be here, just keeping the reference
     * to avoid problems with Palm plugin
     */
    sr->accept = mk_request_header_get(sr->headers_toc, mk_rh_accept);
    sr->accept_charset = mk_request_header_get(sr->headers_toc, mk_rh_accept_charset);
    sr->accept_encoding = mk_request_header_get(sr->headers_toc, mk_rh_accept_encoding);

    sr->accept_language = mk_request_header_get(sr->headers_toc, mk_rh_accept_language);
    sr->cookies = mk_request_header_get(sr->headers_toc, mk_rh_cookie);

    /* Default Keepalive is off */
    if (sr->protocol == HTTP_PROTOCOL_10) {
        sr->keep_alive = MK_FALSE;
        sr->close_now = MK_TRUE;
    }
    else if(sr->protocol == HTTP_PROTOCOL_11) {
        sr->keep_alive = MK_TRUE;
        sr->close_now = MK_FALSE;
    }

    if (sr->connection.data) {
        if (mk_string_search_n(sr->connection.data, "Keep-Alive",
                               MK_STR_INSENSITIVE, sr->connection.len) >= 0) {
            sr->keep_alive = MK_TRUE;
            sr->close_now = MK_FALSE;
        }
        else if(mk_string_search_n(sr->connection.data, "Close",
                                   MK_STR_INSENSITIVE, sr->connection.len) >= 0) {
            sr->keep_alive = MK_FALSE;
            sr->close_now = MK_TRUE;
        }
        else {
            /* Set as a non-valid connection header value */
            sr->connection.len = 0;
        }
    }

    return 0;
}

static int mk_request_parse(struct client_session *cs)
{
    int i, end;
    int blocks = 0;
    struct session_request *sr_node;
    struct mk_list *sr_list, *sr_head;

    for (i = 0; i <= cs->body_pos_end; i++) {
        /* Look for CRLFCRLF (\r\n\r\n), maybe some pipelining
         * request can be involved.
         */
        end = mk_string_search(cs->body + i, mk_endblock.data, MK_STR_SENSITIVE) + i;

        if (end <  0) {
            return -1;
        }

        /* Allocating request block */
        sr_node = mk_request_alloc();

        /* We point the block with a mk_pointer */
        sr_node->body.data = cs->body + i;
        sr_node->body.len = end - i;

        /* Method, previous catch in mk_http_pending_request */
        if (i == 0) {
            sr_node->method = cs->first_method;
        }
        else {
            sr_node->method = mk_http_method_get(sr_node->body.data);
        }

        /* Looking for POST data */
        if (sr_node->method == HTTP_METHOD_POST) {
            int offset;
            offset = end + mk_endblock.len;
            sr_node->post_variables = mk_method_post_get_vars(cs->body + offset,
                                                              cs->body_length - offset);
            if (sr_node->post_variables.len >= 0) {
                i += sr_node->post_variables.len;
            }
        }

        /* Increase index to the end of the current block */
        i = (end + mk_endblock.len) - 1;

        /* Link block */
        mk_list_add(&sr_node->_head, &cs->request_list);

        /* Update counter */
        blocks++;
    }


    /* DEBUG BLOCKS
    cr_search = cs->request;
    while(cr_search){
        printf("\n");
        MK_TRACE("BLOCK INIT");
        mk_pointer_print(cr_search->body);
        MK_TRACE("BLOCK_END");

        cr_search = cr_search->next;
    }
    */

    /* Checking pipelining connection */
    if (blocks > 1) {
        sr_list = &cs->request_list;
        mk_list_foreach(sr_head, sr_list) {
            sr_node = mk_list_entry(sr_head, struct session_request, _head);
            /* Pipelining request must use GET or HEAD methods */
            if (sr_node->method != HTTP_METHOD_GET &&
                sr_node->method != HTTP_METHOD_HEAD) {
                return -1;
            }
        }

        cs->pipelined = MK_TRUE;
    }

    return 0;
}

/* This function allow the core to invoke the closing connection process
 * when some connection was not proceesed due to a premature close or similar
 * exception, it also take care of invoke the STAGE_40 and STAGE_50 plugins events
 */
static void mk_request_premature_close(int http_status, struct client_session *cs)
{
    struct session_request *sr;
    struct mk_list *sr_list = &cs->request_list;

    if (mk_list_is_empty(sr_list) == 0) {
        sr = mk_request_alloc();
        mk_list_add(&sr->_head, &cs->request_list);
    }
    else {
        sr = mk_list_entry_first(sr_list, struct session_request, _head);
    }

    /* Raise error */
    if (http_status > 0) {
        mk_request_error(http_status, cs, sr);

        /* STAGE_40, request has ended */
        mk_plugin_stage_run(MK_PLUGIN_STAGE_40, cs->socket,
                            NULL, cs, sr);
    }

    /* STAGE_50, connection closed */
    mk_plugin_stage_run(MK_PLUGIN_STAGE_50, cs->socket, NULL, NULL, NULL);
    mk_session_remove(cs->socket);
}

static int mk_request_process(struct client_session *cs, struct session_request *sr)
{
    int status = 0;
    struct host *host;

    status = mk_request_header_process(sr);
    if (status < 0) {
        mk_header_set_http_status(sr, MK_CLIENT_BAD_REQUEST);
        mk_request_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_ABORT;
    }

    switch (sr->method) {
    case METHOD_NOT_ALLOWED:
        mk_request_error(MK_CLIENT_METHOD_NOT_ALLOWED, cs, sr);
        return EXIT_NORMAL;
    case METHOD_NOT_FOUND:
        mk_request_error(MK_SERVER_NOT_IMPLEMENTED, cs, sr);
        return EXIT_NORMAL;
    }

    sr->user_home = MK_FALSE;

    /* Valid request URI? */
    if (sr->uri_processed.data[0] != '/') {
        mk_request_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* HTTP/1.1 needs Host header */
    if (!sr->host.data && sr->protocol == HTTP_PROTOCOL_11) {
        mk_request_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* Method not allowed ? */
    if (sr->method == METHOD_NOT_ALLOWED) {
        mk_request_error(MK_CLIENT_METHOD_NOT_ALLOWED, cs, sr);
        return EXIT_NORMAL;
    }

    /* Validating protocol version */
    if (sr->protocol == HTTP_PROTOCOL_UNKNOWN) {
        mk_request_error(MK_SERVER_HTTP_VERSION_UNSUP, cs, sr);
        return EXIT_ABORT;
    }

    if (sr->host.data) {
        host = mk_config_host_find(sr->host);
        if (host) {
            sr->host_conf = host;
        }
        else {
            sr->host_conf = config->hosts;
        }
    }
    else {
        sr->host_conf = config->hosts;
    }

    /* Is requesting an user home directory ? */
    if (config->user_dir && 
        sr->uri_processed.len > 2 &&
        sr->uri_processed.data[1] == MK_USER_HOME) {

        if (mk_user_init(cs, sr) != 0) {
            mk_request_error(MK_CLIENT_NOT_FOUND, cs, sr);
            return EXIT_ABORT;
        }
    }

    /* Handling method requested */
    if (sr->method == HTTP_METHOD_POST) {
        if ((status = mk_method_post(cs, sr)) == -1) {
            return status;
        }
    }

    /* Plugins Stage 20 */
    int ret;
    ret = mk_plugin_stage_run(MK_PLUGIN_STAGE_20, cs->socket, NULL, 
                              cs, sr);
    
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        MK_TRACE("STAGE 20 requested close conexion");
        return EXIT_ABORT;
    }

    /* Normal HTTP process */
    status = mk_http_init(cs, sr);

    MK_TRACE("[FD %i] HTTP Init returning %i", cs->socket, status);
    return status;
}

/* Build error page */
static mk_pointer *mk_request_set_default_page(char *title, mk_pointer message,
                                        char *signature)
{
    char *temp;
    mk_pointer *p;

    p = mk_mem_malloc(sizeof(mk_pointer));
    p->data = NULL;

    temp = mk_pointer_to_buf(message);
    mk_string_build(&p->data, &p->len,
                    MK_REQUEST_DEFAULT_PAGE, title, temp, signature);
    mk_mem_free(temp);

    return p;
}

int mk_handler_read(int socket, struct client_session *cs)
{
    int bytes;
    int pending = 0;
    int available = 0;
    int ret;
    int new_size;
    char *tmp = 0;

    /* Check amount of data reported */
    ret = ioctl(socket, FIONREAD, &pending);
    if (ret == -1) {
        mk_request_premature_close(MK_SERVER_INTERNAL_ERROR, cs);
        return -1;
    }

    /* Reallocate buffer size if pending data does not have space */
    if (pending > 0 && (pending >= (cs->body_size - (cs->body_length - 1)))) {
        /* check available space */
        available = (cs->body_size - cs->body_length) + MK_REQUEST_CHUNK;
        if (pending < available) {
            new_size = cs->body_size + MK_REQUEST_CHUNK + 1;
        }
        else {    
            new_size = cs->body_size + pending + 1;
        }

        if (new_size > config->max_request_size) {
            mk_request_premature_close(MK_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs);
            return -1;
        }

        tmp = mk_mem_realloc(cs->body, new_size);
        if (tmp) {
            cs->body = tmp;
            cs->body_size = new_size;
        }
        else {
            mk_request_premature_close(MK_SERVER_INTERNAL_ERROR, cs);
            return -1;
        }
    }

    /* Read content */
    bytes = mk_socket_read(socket, cs->body + cs->body_length, 
                           (cs->body_size - cs->body_length) );

    if (bytes < 0) {
        if (errno == EAGAIN) {
            return 1;
        }
        else {
            mk_session_remove(socket);
            return -1;
        }
    }
    if (bytes == 0) {
        mk_session_remove(socket);
        return -1;
    }

    if (bytes >= 0) {
        cs->body_length += bytes;
        cs->body[cs->body_length] = '\0';
    }

    return bytes;
}

int mk_handler_write(int socket, struct client_session *cs)
{
    int bytes, final_status = 0;
    struct session_request *sr_node;
    struct mk_list *sr_list, *sr_head;

    /*
     * Get node from schedule list node which contains
     * the information regarding to the current thread
     */
    if (!cs) {
        return -1;
    }

    if (mk_list_is_empty(&cs->request_list) == 0) {
        if (mk_request_parse(cs) != 0) {
            return -1;
        }
    }

    sr_list = &cs->request_list;
    mk_list_foreach(sr_head, sr_list) {
        sr_node = mk_list_entry(sr_head, struct session_request, _head);

        /* Request not processed also no plugin has take some action */
        if (sr_node->bytes_to_send < 0 && !sr_node->handled_by) {
            final_status = mk_request_process(cs, sr_node);
        }
        /* Request with data to send by static file sender */
        else if (sr_node->bytes_to_send > 0 && !sr_node->handled_by) {
            final_status = bytes = mk_http_send_file(cs, sr_node);
        }

        /*
         * If we got an error, we don't want to parse
         * and send information for another pipelined request
         */
        if (final_status > 0) {
            return final_status;
        }
        else if (final_status <= 0) {
            /* STAGE_40, request has ended */
            mk_plugin_stage_run(MK_PLUGIN_STAGE_40, cs->socket,
                                NULL, cs, sr_node);
            switch (final_status) {
            case EXIT_NORMAL:
            case EXIT_ERROR:
                 if (sr_node->close_now == MK_TRUE) {
                    return -1;
                }
                break;
            case EXIT_ABORT:
                  return -1;
            }
        }
    }

    /* If we are here, is because all pipelined request were
     * processed successfully, let's return 0;
     */
    return 0;
}

/* Look for some  index.xxx in pathfile */
mk_pointer mk_request_index(char *pathfile)
{
    unsigned long len;
    char *file_aux = NULL;
    mk_pointer f;
    struct mk_string_line *aux_index;

    mk_pointer_reset(&f);
    aux_index = config->index_files;

    while (aux_index) {
        mk_string_build(&file_aux, &len, "%s%s",
                        pathfile, aux_index->val);

        if (access(file_aux, F_OK) == 0) {
            f.data = file_aux;
            f.len = len;
            return f;
        }
        mk_mem_free(file_aux);
        file_aux = NULL;

        aux_index = aux_index->next;
    }

    return f;
}

/* Send error responses */
void mk_request_error(int http_status, struct client_session *cs, 
                      struct session_request *sr) {
    char *aux_message = 0;
    mk_pointer message, *page = 0;
    long n;

    mk_pointer_reset(&message);

    switch (http_status) {
    case MK_CLIENT_BAD_REQUEST:
        page = mk_request_set_default_page("Bad Request",
                                           sr->uri,
                                           sr->host_conf->host_signature);
        break;

    case MK_CLIENT_FORBIDDEN:
        page = mk_request_set_default_page("Forbidden",
                                           sr->uri,
                                           sr->host_conf->host_signature);
        break;

    case MK_CLIENT_NOT_FOUND:
        mk_string_build(&message.data, &message.len,
                        "The requested URL was not found on this server.");
        page = mk_request_set_default_page("Not Found",
                                           message,
                                           sr->host_conf->host_signature);
        mk_pointer_free(&message);
        break;

    case MK_CLIENT_REQUEST_ENTITY_TOO_LARGE:
        mk_string_build(&message.data, &message.len,
                        "The request entity is too large.");
        page = mk_request_set_default_page("Entity too large",
                                           message,
                                           sr->host_conf->host_signature);
        mk_pointer_free(&message);
        break;

    case MK_CLIENT_METHOD_NOT_ALLOWED:
        page = mk_request_set_default_page("Method Not Allowed",
                                           sr->uri,
                                           sr->host_conf->host_signature);
        break;

    case MK_CLIENT_REQUEST_TIMEOUT:
    case MK_CLIENT_LENGTH_REQUIRED:
        break;

    case MK_SERVER_NOT_IMPLEMENTED:
        page = mk_request_set_default_page("Method Not Implemented",
                                           sr->uri,
                                           sr->host_conf->host_signature);
        break;

    case MK_SERVER_INTERNAL_ERROR:
        page = mk_request_set_default_page("Internal Server Error",
                                           sr->uri,
                                           sr->host_conf->host_signature);
        break;

    case MK_SERVER_HTTP_VERSION_UNSUP:
        mk_pointer_reset(&message);
        page = mk_request_set_default_page("HTTP Version Not Supported",
                                           message,
                                           sr->host_conf->host_signature);
        break;
    }

    mk_header_set_http_status(sr, http_status);
    if (page) {
        sr->headers->content_length = page->len;
    }

    sr->headers->location = NULL;
    sr->headers->cgi = SH_NOCGI;
    sr->headers->pconnections_left = 0;
    sr->headers->last_modified = -1;

    if (aux_message) {
        mk_mem_free(aux_message);
    }

    if (!page) {
        mk_pointer_reset(&sr->headers->content_type);
    }
    else {
        mk_pointer_set(&sr->headers->content_type, "text/html\r\n");
    }

    mk_header_send(cs->socket, cs, sr);

    if (page && sr->method != HTTP_METHOD_HEAD) {
        n = mk_socket_send(cs->socket, page->data, page->len);
        mk_pointer_free(page);
        mk_mem_free(page);
    }

    /* Turn off TCP_CORK */
    mk_socket_set_cork_flag(cs->socket, TCP_CORK_OFF);
}

void mk_request_free_list(struct client_session *cs)
{
    struct session_request *sr_node;
    struct mk_list *sr_head, *temp;

    /* sr = last node */
    MK_TRACE("[FD %i] Free struct client_session", cs->socket);

    mk_list_foreach_safe(sr_head, temp, &cs->request_list) {
        sr_node = mk_list_entry(sr_head, struct session_request, _head);
        mk_list_del(sr_head);
        mk_request_free(sr_node);
    }
}

/* Create a client request struct and put it on the
 * main list
 */
struct client_session *mk_session_create(int socket)
{
    struct client_session *cs;
    struct sched_connection *sc;
    struct sched_list_node *sched;
    struct mk_list *cs_list;

    sched= mk_sched_get_thread_conf();
    sc = mk_sched_get_connection(sched, socket);
    if (!sc) {
        MK_TRACE("FAILED SOCKET: %i", socket);
        mk_warn("Sched connection not found");
        return NULL;
    }

    /* Alloc memory for node */
    cs = mk_mem_malloc(sizeof(struct client_session));

    /* IPv4 Address */
    cs->ipv4 = &sc->ipv4;

    cs->pipelined = MK_FALSE;
    cs->counter_connections = 0;
    cs->socket = socket;
    cs->status = MK_REQUEST_STATUS_INCOMPLETE;

    /* creation time in unix time */
    cs->init_time = sc->arrive_time;

    /* alloc space for body content */
    cs->body = mk_mem_malloc(MK_REQUEST_CHUNK);

    /* Buffer size based in Chunk bytes */
    cs->body_size = MK_REQUEST_CHUNK;
    /* Current data length */
    cs->body_length = 0;

    cs->body_pos_end = -1;
    cs->first_method = HTTP_METHOD_UNKNOWN;

    /* Init session request list */
    mk_list_init(&cs->request_list);

    /* Add this SESSION to the thread list */
    cs_list = mk_sched_get_request_list();

    /* Add node to list */
    mk_list_add(&cs->_head, cs_list);

    /* Set again the global list */
    mk_sched_set_request_list(cs_list);

    return cs;
}

struct client_session *mk_session_get(int socket)
{
    struct client_session *cs_node = NULL;
    struct mk_list *cs_list, *cs_head;

    cs_list = mk_sched_get_request_list();
    mk_list_foreach(cs_head, cs_list) {
        cs_node = mk_list_entry(cs_head, struct client_session, _head);
        if (cs_node->socket == socket) {
            return cs_node;
        }
    }

    return NULL;
}

/*
 * From thread sched_list_node "list", remove the client_session
 * struct information
 */
void mk_session_remove(int socket)
{
    struct client_session *cs_node;
    struct mk_list *cs_list, *cs_head, *temp;

    cs_list = mk_sched_get_request_list();
    
    mk_list_foreach_safe(cs_head, temp, cs_list) {
        cs_node = mk_list_entry(cs_head, struct client_session, _head);
        if (cs_node->socket == socket) {
            mk_list_del(cs_head);
            mk_mem_free(cs_node->body);
            mk_mem_free(cs_node);
            break;
        }
    }

    /* Update thread index */
    mk_sched_set_request_list(cs_list);
}

void mk_request_header_toc_init(struct header_toc *toc)
{
    int i;
    for (i=0; i < MK_HEADERS_TOC_LEN; i++) {
        toc[i].init = NULL;
        toc[i].end = NULL;
        toc[i].status = 0;
    }
}

/* Return value of some variable sent in request */
mk_pointer mk_request_header_get(struct header_toc *toc, mk_pointer header)
{
    int i;
    mk_pointer var;

    var.data = NULL;
    var.len = 0;

    if (toc) {
        for (i = 0; i < MK_HEADERS_TOC_LEN; i++) {
            /* status = 1 means that the toc entry was already
             * checked by Monkey
             */
            if (toc[i].status == 1) {
                continue;
            }

            if (!toc[i].init)
                break;

            if (strncasecmp(toc[i].init, header.data, header.len) == 0) {
                var.data = toc[i].init + header.len + 1;
                var.len = toc[i].end - var.data;
                toc[i].status = 1;
                return var;
            }
        }
    }

    return var;
}

void mk_request_ka_next(struct client_session *cs)
{
    memset(cs->body, '\0', sizeof(cs->body));
    cs->first_method = -1;
    cs->body_pos_end = -1;
    cs->body_length = 0;
    cs->counter_connections++;

    /* Update data for scheduler */
    cs->init_time = log_current_utime;
    cs->status = MK_REQUEST_STATUS_INCOMPLETE;
}
