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

#ifndef MK_HTTP_BASE_H
#define MK_HTTP_BASE_H

#include <monkey/mk_core.h>
#include <monkey/mk_stream.h>

/* HTTP 0.9 */
#define HTTP_0 0
/* HTTP 1.x */
#define HTTP_1 1
/* HTTP 2   */
#define HTTP_2 2

struct mk_http1_request;
struct mk_http2_request;

struct mk_http1_session;
struct mk_http2_session;

struct mk_http1_response;
struct mk_http2_response;

struct mk_http_base_session
{
    /*
     * The first field of the struct appended to the sched_conn memory
     * space needs to be an integer, the scheduler will set this flag
     * to MK_FALSE to indicate it was just created. This work as a helper
     * to the protocol handler.
     *
     * C rule: a pointer to a structure always points to it's first member.
     */
    int _sched_init;           /* initialized ?     */

    unsigned int protocol_version;

    int status;                 /* Request status */
    int close_now;              /* Close the session ASAP */

    struct mk_channel *channel;
    struct mk_sched_conn *conn;

    /* head for mk_http1_request list nodes, each request is linked here */
    struct mk_list request_list;

    int socket;               /* socket associated */

    /* Server context */
    struct mk_server *server;

    union {
        struct mk_http1_session *http_1;
        struct mk_http2_session *http_2;
    } additional_data;
};

struct mk_http_base_response
{
    unsigned int protocol_version;

    int status;

    /* Length of the content to send */
    long content_length;

    int transfer_encoding;

    /* Flag to track if the response headers were sent */
    int sent;

    union {
        struct mk_http1_response *http_1;
        struct mk_http2_response *http_2;
    } additional_data;
};

struct mk_http_base_request
{
    unsigned int protocol_version;

    int status;

    /* 1.x specific sub version (needs to be refactored) */
    int protocol;

    /* Version agnostic fields */

    /* is it serving a user's home directory ? */
    int user_home;

    long port;

    /*----First header of client request--*/
    int method;
    mk_ptr_t method_p;
    mk_ptr_t uri;                  /* original request */
    mk_ptr_t uri_processed;        /* processed request (decoded) */

    mk_ptr_t protocol_p;

    int content_length;
    mk_ptr_t _content_length;
    mk_ptr_t content_type;
    mk_ptr_t connection;

    mk_ptr_t host;
    mk_ptr_t if_modified_since;
    mk_ptr_t last_modified_since;
    mk_ptr_t range;

    /* Body Stream size */
    uint64_t stream_size;

    /*-Internal-*/
    mk_ptr_t real_path;        /* Absolute real path */

    /*
     * If a full URL length is less than MAX_PATH_BASE (defined in limits.h),
     * it will be stored here and real_path will point this buffer
     */
    char real_path_static[MK_PATH_BASE];

    struct mk_stream stream;
    /* Streams handling: static file */
    struct mk_stream_input in_file;

    /* POST/PUT data */
    mk_ptr_t data;
    /*-----------------*/

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

    struct mk_vhost *host_conf;      /* root vhost config */
    struct mk_vhost_alias *host_alias; /* specific vhost matched */

    /*
     * Reference used outside of Monkey Core, e.g: Plugins. It can be used
     * to store some relevant information associated to a request.
     */
    void *handler_data;

    struct mk_http_base_session *session;

    /* coroutine thread (if any) */
    void *thread;

    /* Response */
    struct mk_http_base_response response;

    /* Head to list of requests */
    struct mk_list _head;

    union {
        struct mk_http1_request *http_1;
        struct mk_http2_request *http_2;
    } additional_data ;
};

int mk_http_error(int http_status, 
                  struct mk_http_base_session *cs,
                  struct mk_http_base_request *sr,
                  struct mk_server *server);

#endif
