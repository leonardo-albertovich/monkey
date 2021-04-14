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

#include <inttypes.h>
#include <regex.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_frame.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_request.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_http2_hpack.h>
#include <monkey/mk_http2_huffman.h>
#include <monkey/mk_http2_thread.h>
#include <monkey/mk_http2_frame_decoders.h>
#include <monkey/mk_http2_frame_encoders.h>
#include <monkey/mk_http2_frame_handlers.h>
#include <monkey/mk_http2_dynamic_table.h>
#include <monkey/mk_http2_header_table.h>
#include <monkey/mk_http_thread.h>
#include <monkey/mk_header.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_vhost.h>



static inline void buffer_consume(struct mk_http2_session *h2s, int bytes)
{
    memmove(h2s->buffer,
            h2s->buffer + bytes,
            h2s->buffer_length - bytes);

    MK_TRACE("[h2] consume buffer length from %i to %i",
             h2s->buffer_length, h2s->buffer_length - bytes);

    h2s->buffer_length -= bytes;
}

/* Enqueue an error response. This function always returns MK_EXIT_OK */
/* TODO : Define and implement this function properly */
static inline int mk_http2_error(int error_code, struct mk_server *server)
{
    (void) error_code;
    (void) server;

    return 0;
}

/*
int mk_http2_directory_redirect_check(struct mk_http2_request *request)
{

    return 0;
}

// Look for some  index.xxx in pathfile
static inline char *mk_http2_index_lookup(mk_ptr_t *path_base,
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


// Turn CORK_OFF once headers are sent
#if defined (__linux__)
static inline void mk_http2_cb_file_on_consume(struct mk_stream_input *in,
                                               long bytes)
{
    int ret;
    (void) bytes;

    // This callback is invoked just once as we want to turn off
    // the TCP Cork. We do this just overriding the callback for
    // the file stream.

    ret = mk_server_cork_flag(in->stream->channel->fd, TCP_CORK_OFF);
    if (ret == -1) {
        mk_warn("Could not set TCP_CORK/TCP_NOPUSH off");
    }
    MK_TRACE("[FD %i] Disable TCP_CORK/TCP_NOPUSH",
             in->stream->channel->fd);
    in->cb_consumed = NULL;
}
#endif

static int mk_http2_range_parse(struct mk_http2_request *sr)
{
//    int eq_pos, sep_pos, len;
//    char *buffer = 0;
//    struct response_headers *sh;
//
//    if (!sr->range.data)
//        return -1;
//
//    if ((eq_pos = mk_string_char_search(sr->range.data, '=', sr->range.len)) < 0)
//        return -1;
//
//    if (strncasecmp(sr->range.data, "Bytes", eq_pos) != 0)
//        return -1;
//
//    if ((sep_pos = mk_string_char_search(sr->range.data, '-', sr->range.len)) < 0)
//        return -1;
//
//    len = sr->range.len;
//    sh = &sr->headers;
//
//    // =-xxx
//    if (eq_pos + 1 == sep_pos) {
//        sh->ranges[0] = -1;
//        sh->ranges[1] = (unsigned long) atol(sr->range.data + sep_pos + 1);
//
//        if (sh->ranges[1] <= 0) {
//            return -1;
//        }
//
//        sh->content_length = sh->ranges[1];
//        return 0;
//    }
//
//    // =yyy-xxx
//    if ((eq_pos + 1 != sep_pos) && (len > sep_pos + 1)) {
//        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, sep_pos);
//        sh->ranges[0] = (unsigned long) atol(buffer);
//        mk_mem_free(buffer);
//
//        buffer = mk_string_copy_substr(sr->range.data, sep_pos + 1, len);
//        sh->ranges[1] = (unsigned long) atol(buffer);
//        mk_mem_free(buffer);
//
//        if (sh->ranges[1] < 0 || (sh->ranges[0] > sh->ranges[1])) {
//            return -1;
//        }
//
//        sh->content_length = abs(sh->ranges[1] - sh->ranges[0]) + 1;
//        return 0;
//    }
//    // =yyy- 
//    if ((eq_pos + 1 != sep_pos) && (len == sep_pos + 1)) {
//        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, len);
//
//
//        //sr->headers.ranges[0] = (unsigned long) atol(buffer);
//
//
//        mk_mem_free(buffer);
//
//        sh->content_length = (sh->content_length - sh->ranges[0]);
//        return 0;
//    }

    return -1;
}

int mk_http2_request_end(struct mk_http2_session *cs, struct mk_server *server)
{
    printf("IN mk_http_request_end\n");

    return 0;
}

int mk_http2_handle_request(struct mk_http2_request *request)
{
    int ret;
    int ret_file;
    struct mk_mimetype *mime;
    struct mk_list *head;
    struct mk_list *handlers;
    struct mk_plugin *plugin;
    struct mk_vhost_handler *h_handler;
    struct mk_http2_thread *mth = NULL;
    size_t index_length;
    size_t index_bytes;
    char *index_path = NULL;

    MK_TRACE("[FD %i] HTTP2 Protocol Init session %p", request->session->stream.channel->fd, 
             request->session);

    // Request to root path of the virtualhost in question
    if (request->uri_processed.len == 1 && 
        request->uri_processed.data[0] == '/') {
        request->real_path.data = request->host_conf->documentroot.data;
        request->real_path.len = request->host_conf->documentroot.len;
    }

    // Compose real path
    if (request->user_home == MK_FALSE) {
        int len;

        len = request->host_conf->documentroot.len + request->uri_processed.len;
        if (len < MK_PATH_BASE) {
            memcpy(request->real_path_static,
                   request->host_conf->documentroot.data,
                   request->host_conf->documentroot.len);
            memcpy(request->real_path_static + request->host_conf->documentroot.len,
                   request->uri_processed.data,
                   request->uri_processed.len);
            request->real_path_static[len] = '\0';
            request->real_path.data = request->real_path_static;
            request->real_path.len = len;
        }
        else {
            ret = mk_buffer_cat(&request->real_path,
                                request->host_conf->documentroot.data,
                                request->host_conf->documentroot.len,
                                request->uri_processed.data,
                                request->uri_processed.len);

            if (ret < 0) {
                MK_TRACE("Error composing real path");
                return MK_EXIT_ERROR;
            }
        }
    }

    // Check backward directory request
    if (memmem(request->uri_processed.data, 
               request->uri_processed.len,
               MK_HTTP_DIRECTORY_BACKWARD,
               sizeof(MK_HTTP_DIRECTORY_BACKWARD) - 1)) {
        return -1; // Forbidden
    }

    if (request->_content_length.data &&
        (request->method != MK_METHOD_POST &&
         request->method != MK_METHOD_PUT)) {
        request->_content_length.data = NULL;
        request->_content_length.len = 0;
    }

    ret_file = mk_file_get_info(request->real_path.data, &request->file_info, MK_FILE_READ);

    // Plugin Stage 30: look for handlers for this request
    if (request->stage30_blocked == MK_FALSE) {
        request->uri_processed.data[request->uri_processed.len] = '\0';
        handlers = &request->host_conf->handlers;
        mk_list_foreach(head, handlers) {
            h_handler = mk_list_entry(head, struct mk_vhost_handler, _head);

            if (regexec(h_handler->match,
                        request->uri_processed.data, 0, NULL, 0) != 0) {
                continue;
            }

            if (h_handler->cb) {
                // Create coroutine/thread context
                
                // request->headers.content_length = 0;
                mth = mk_http2_thread_create(MK_HTTP_THREAD_LIB,
                                             h_handler,
                                             request->session, request,
                                             0, NULL);
                if (!mth) {
                    return -1;
                }

                mk_http2_thread_start(mth);

                printf("SHOULD HAVE DONE SOMETHING\n");
                return MK_EXIT_OK;
            }
            else {
                if (!h_handler->handler) {
                    return -1; // MK_SERVER_INTERNAL_ERROR
                }
                plugin = h_handler->handler;
                request->stage30_handler = h_handler->handler;
                ret = plugin->stage->stage30(plugin, request->session, request,
                                             h_handler->n_params,
                                             &h_handler->params);
                // mk_header_prepare(cs, sr, server);
            }

            MK_TRACE("[FD %i] STAGE_30 returned %i", request->session->stream.channel->fd, 
                     ret);

            switch (ret) {
            case MK_PLUGIN_RET_CONTINUE:
                // FIXME: PLUGINS DISABLED

                return MK_PLUGIN_RET_CONTINUE;
            case MK_PLUGIN_RET_CLOSE_CONX:
                // if (sr->headers.status > 0) {
                //     return -1; // request->headers.status 
                // }
                // else {
                    return -1; // forbidden
                // }
            case MK_PLUGIN_RET_END:
                return MK_EXIT_OK;
            }
        }
    }

    // If there is no handler and the resource don't exists, raise a 404
    if (ret_file == -1) {
        // return mk_http_error(MK_CLIENT_NOT_FOUND, cs, sr, server);
        return -1;
    }

    // is it a valid directory ?
    if (request->file_info.is_directory == MK_TRUE) {
        // Send redirect header if end slash is not found 
        if (mk_http2_directory_redirect_check(request) == -1) {
            MK_TRACE("Directory Redirect");

            // Redirect has been sent
            return -1;
        }

        // looking for an index file 
        char tmppath[MK_MAX_PATH];
        index_path = mk_http2_index_lookup(&request->real_path,
                                          tmppath, MK_MAX_PATH,
                                          &index_length, &index_bytes,
                                          request->session->server);
        if (index_path) {
            if (request->real_path.data != request->real_path_static) {
                mk_ptr_free(&request->real_path);
                request->real_path.data = mk_string_dup(index_path);
            }
            // If it's static and it still fits
            else if (index_length < MK_PATH_BASE) {
                memcpy(request->real_path_static, index_path, index_length);
                request->real_path_static[index_length] = '\0';
            }
            // It was static, but didn't fit
            else {
                request->real_path.data = mk_string_dup(index_path);
            }
            request->real_path.len  = index_length;

            ret = mk_file_get_info(request->real_path.data,
                                   &request->file_info, MK_FILE_READ);
            if (ret != 0) {
                return -1; // forbidden
            }
        }
    }

    // Check symbolic link file 
    if (request->file_info.is_link == MK_TRUE) {
        if (request->session->server->symlink == MK_FALSE) {
            return -1; // forbidden
        }
        else {
            int n;
            char linked_file[MK_MAX_PATH];
            n = readlink(request->real_path.data, linked_file, MK_MAX_PATH);
            if (n < 0) {
                return -1; // forbidden 
            }
        }
    }

    // Plugin Stage 30: look for handlers for this request
    if (request->stage30_blocked == MK_FALSE) {
        char *uri;

        if (!index_path) {
            request->uri_processed.data[request->uri_processed.len] = '\0';
            uri = request->uri_processed.data;
        }
        else {
            uri = request->real_path.data + index_bytes;
        }

        handlers = &request->host_conf->handlers;
        mk_list_foreach(head, handlers) {
            h_handler = mk_list_entry(head, struct mk_vhost_handler, _head);
            if (regexec(h_handler->match,
                        uri, 0, NULL, 0) != 0) {
                continue;
            }

            plugin = h_handler->handler;
            request->stage30_handler = h_handler->handler;
            ret = plugin->stage->stage30(plugin, request->session, request,
                                         h_handler->n_params,
                                         &h_handler->params);

            MK_TRACE("[FD %i] STAGE_30 returned %i", request->session->stream.channel->fd, 
                     ret);
            switch (ret) {
            case MK_PLUGIN_RET_CONTINUE:
                return MK_PLUGIN_RET_CONTINUE;
            case MK_PLUGIN_RET_CLOSE_CONX:
                // if (request->headers.status > 0) {
                //     return -1; // sr->headers.status  
                // }
                // else {
                //     return -1; // forbidden
                // }
            case MK_PLUGIN_RET_END:
                return MK_EXIT_OK;
            }
        }
    }

    //
    // Monkey listens for PUT and DELETE methods in addition to GET, POST and
    // HEAD, but it does not care about them, so if any plugin did not worked
    // on it, Monkey will return error 501 (501 Not Implemented).
    //
    if (request->method == MK_METHOD_PUT || request->method == MK_METHOD_DELETE) {
        return -1; // method not allowed 
    }
    else if (request->method == MK_METHOD_UNKNOWN) {
        return -1; // not implemented 
    }

    // Set default value 
    // mk_header_set_http_status(sr, MK_HTTP_OK);

    //
    // For OPTIONS method, we let the plugin handle it and
    // return without any content.
    //
    if (request->method == MK_METHOD_OPTIONS) {
        // FIXME: OPTIONS NOT WORKING 
        //sr->headers.allow_methods.data = MK_METHOD_AVAILABLE;
        //sr->headers.allow_methods.len = strlen(MK_METHOD_AVAILABLE);

        // mk_ptr_reset(&sr->headers.content_type);
        // mk_header_prepare(cs, sr, server);
        return MK_EXIT_OK;
    }
    else {
        // mk_ptr_reset(&sr->headers.allow_methods);
    }

    // read permissions and check file 
    if (request->file_info.read_access == MK_FALSE) {
        return -1; // forbidden 
    }

    // Matching MimeType  
    mime = mk_mimetype_find(request->session->server, &request->real_path);
    if (!mime) {
        mime = request->session->server->mimetype_default;
    }

    if (request->file_info.is_directory == MK_TRUE) {
        return -1; // forbidden 
    }

    // get file size 
    if (request->file_info.size == 0) {
        return -1; // forbidden 
    }

    // Configure some headers 
    // sr->headers.last_modified = sr->file_info.last_modification;
    // sr->headers.etag_len = snprintf(sr->headers.etag_buf,
    //                                 MK_HEADER_ETAG_SIZE,
    //                                 "ETag: \"%x-%zx\"\r\n",
    //                                 (unsigned int) sr->file_info.last_modification,
    //                                 sr->file_info.size);

    if (request->if_modified_since.data && request->method == MK_METHOD_GET) {
        time_t date_client;       // Date sent by client 
        time_t date_file_server;  // Date server file 

        date_client = mk_utils_gmt2utime(request->if_modified_since.data);
        date_file_server = request->file_info.last_modification;

        if (date_file_server <= date_client &&
            date_client > 0) {
            return -1; // not modified 
        }
    }


    // Object size for log and response headers 
    // sr->headers.content_length = sr->file_info.size;
    // sr->headers.real_length = sr->file_info.size;

    // Open file 
    if (mk_likely(request->file_info.size > 0)) {
        request->file_fd = mk_vhost_open_http2(request, request->session->server);
        if (request->file_fd == -1) {
            MK_TRACE("open() failed");
            return -1; // forbidden 
        }

        request->in_file.fd           = request->file_fd;
        request->in_file.bytes_offset = 0;
        request->in_file.bytes_total  = request->file_info.size;
        request->in_file.stream       = &request->session->stream;
    }


    // Process methods 
    if (request->method == MK_METHOD_GET || request->method == MK_METHOD_HEAD) {
        // if (mime) {
        //     sr->headers.content_type = mime->header_type;
        // }

        // HTTP Ranges 
        if (request->range.data != NULL && request->session->server->resume == MK_TRUE) {
            if (mk_http2_range_parse(request) < 0) {
                // request->headers.ranges[0] = -1;
                // request->headers.ranges[1] = -1;
                return -1; // bad request 
            }
            // if (request->headers.ranges[0] >= 0 || request->headers.ranges[1] >= 0) {
                // mk_header_set_http_status(sr, MK_HTTP_PARTIAL);
            // }

            // Calc bytes to send & offset 
            // if (mk_http_range_set(sr, sr->file_info.size, server) != 0) {
            //     sr->headers.content_length = -1;
            //     sr->headers.ranges[0] = -1;
            //     sr->headers.ranges[1] = -1;
            //     return mk_http_error(MK_CLIENT_REQUESTED_RANGE_NOT_SATISF,
            //                          cs, sr, server);
            // }
        }
    }
    else {
        // without content-type 
        // mk_ptr_reset(&sr->headers.content_type);
    }


    // Send headers 
    // mk_header_prepare(cs, sr, server);
    // if (mk_unlikely(request->headers.content_length == 0)) {
    //     return 0;
    // }
    // Send file content 
    if (request->method == MK_METHOD_GET || request->method == MK_METHOD_POST) {
         // Note: bytes and offsets are set after the Range check 
        request->in_file.type = MK_STREAM_FILE;
        mk_stream_append(&request->in_file, &request->session->stream);
    }

    //
    // Enable TCP Cork for the remote socket. It will be disabled
    // later by the file stream on the channel after send the first
    // file bytes.
    ///

#if defined(__linux__)
    request->in_file.cb_consumed = mk_http2_cb_file_on_consume;
#endif

    return 0;
}
*/

int mk_http2_handle_request(struct mk_http2_request *request)
{
    size_t                        compressed_header_buffer_length;
    uint8_t                      *compressed_header_buffer;
    size_t                        output_buffer_length;
    uint8_t                      *output_buffer;
    struct mk_http2_header_table *headers;
    int                           result;
    struct mk_http2_frame         frame;
    struct mk_http2_session      *h2s;

    h2s = mk_http2_session_get(request->session->connection);

    headers = mk_http2_header_table_create();

    if (NULL == headers) {
        return -1;
    }

    // mk_http2_header_table_entry_create_debug(headers, ":status", "200");
    // mk_http2_header_table_entry_create_debug(headers, "date", "Wed, 14 Apr 2021 21:02:56 GMT");
    // mk_http2_header_table_entry_create_debug(headers, "expires", "-1");
    // mk_http2_header_table_entry_create_debug(headers, "cache-control", "private, max-age=0");
    // mk_http2_header_table_entry_create_debug(headers, "content-type", "text/html; charset=ISO-8859-1");
    // mk_http2_header_table_entry_create_debug(headers, "p3p", "CP=\"This is not a P3P policy! See g.co/p3phelp for more info.\"");
    // mk_http2_header_table_entry_create_debug(headers, "content-encoding", "gzip");
    // mk_http2_header_table_entry_create_debug(headers, "server", "gws");
    // mk_http2_header_table_entry_create_debug(headers, "content-length", "5966");
    // mk_http2_header_table_entry_create_debug(headers, "x-xss-protection", "0");
    // mk_http2_header_table_entry_create_debug(headers, "x-frame-options", "SAMEORIGIN");
    // mk_http2_header_table_entry_create_debug(headers, "set-cookie", "1P_JAR=2021-04-14-21; expires=Fri, 14-May-2021 21:02:56 GMT; path=/; domain=.google.com; Secure");
    // mk_http2_header_table_entry_create_debug(headers, "set-cookie", "NID=213=G9imymfgCAVfIINZ6fBouozumANP6dE__V7O8lhgr9AUOZdAyu-muCS0kInZYEXhMoyjGmmwMORq0DvMVdsGHvg8e-EFgEjZ_wuIAXweqrYzuJWHpjIWxa3UlNDG85hYcXel3g2DIMw5sfUZPqj1sF4mq85lNrUj0PnkaO2__sw; expires=Thu, 14-Oct-2021 21:02:56 GMT; path=/; domain=.google.com; HttpOnly");
    // mk_http2_header_table_entry_create_debug(headers, "alt-svc", "h3-29=\":443\"; ma=2592000,h3-T051=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"");


    mk_http2_header_table_entry_create_debug(headers, 
                                             ":status", 
                                             "200");

    mk_http2_header_table_entry_create_debug(headers, 
                                             "content-type", 
                                             "text/html; charset=UTF-8");

    mk_http2_header_table_entry_create_debug(headers, 
                                             "content-length", 
                                             "16");

    
    result = mk_http2_hpack_compress_stream_headers(h2s,
                                                    request->stream, 
                                                    headers,
                                                    &compressed_header_buffer,
                                                    &compressed_header_buffer_length);

    if (0 != result) {
        return -2;
    }

printf("RESPONDING ON STREAM ID : %d\n", request->stream->id);
    memset(&frame, 0, sizeof(struct mk_http2_frame));

    frame.type = MK_HTTP2_HEADERS_FRAME;
    frame.flags = MK_HTTP2_HEADERS_END_HEADERS;
    frame.stream_id = request->stream->id;
    frame.payload.headers.data_block = compressed_header_buffer;
    frame.payload.headers.data_length = compressed_header_buffer_length;

    result = mk_http2_encode_frame(&frame,
                                   &output_buffer,
                                   &output_buffer_length);

    if (0 != result) {
        return -3;
    }

    printf("RESPONSE HEADERS FRAME GENERATED");
    printf("\n\n");
    mk_utils_hexdump(output_buffer, output_buffer_length, 16);
    printf("\n\n");

    mk_stream_in_raw(&h2s->stream,
                     NULL,
                     output_buffer,
                     output_buffer_length,
                     NULL, NULL);

    mk_channel_flush(h2s->stream.channel);

    printf("RESPONSE HEADERS FRAME SENT");

sleep(1000);
sleep(1);

    memset(&frame, 0, sizeof(struct mk_http2_frame));

    frame.type = MK_HTTP2_DATA_FRAME;
    frame.flags = MK_HTTP2_DATA_END_STREAM;
    frame.stream_id = request->stream->id;
    frame.payload.data.data_block = "WE COME IN PEACE";
    frame.payload.data.data_length = 16;
    frame.payload.data.padding_block = NULL;
    frame.payload.data.pad_length = 0;

    result = mk_http2_encode_frame(&frame,
                                   &output_buffer,
                                   &output_buffer_length);

    if (0 != result) {
        return -3;
    }


    printf("RESPONSE DATA FRAME GENERATED");
    printf("\n\n");
    mk_utils_hexdump(output_buffer, output_buffer_length, 16);
    printf("\n\n");

    mk_stream_in_raw(&h2s->stream,
                     NULL,
                     output_buffer,
                     output_buffer_length,
                     NULL, NULL);

    mk_channel_flush(h2s->stream.channel);

    printf("RESPONSE DATA FRAME SENT");

sleep(1);

    memset(&frame, 0, sizeof(struct mk_http2_frame));

    frame.type = MK_HTTP2_RST_STREAM_FRAME;
    frame.flags = 0;
    frame.stream_id = request->stream->id;
    frame.payload.rst_stream.error_code = 0;

    result = mk_http2_encode_frame(&frame,
                                   &output_buffer,
                                   &output_buffer_length);

    if (0 != result) {
        return -3;
    }


    printf("RESPONSE RST STREAM FRAME GENERATED");
    printf("\n\n");
    mk_utils_hexdump(output_buffer, output_buffer_length, 16);
    printf("\n\n");

    mk_stream_in_raw(&h2s->stream,
                     NULL,
                     output_buffer,
                     output_buffer_length,
                     NULL, NULL);

    mk_channel_flush(h2s->stream.channel);

    printf("RESPONSE RST STREAM FRAME SENT");

sleep(1000);

exit(0);

}


static inline int mk_http2_frame_run(struct mk_sched_conn *conn,
                                     struct mk_sched_worker *worker,
                                     struct mk_server *server,
                                     size_t *consumed_frame_length)
{
    int                      result;
    struct mk_http2_stream  *stream;
    struct mk_http2_frame    frame;
    struct mk_http2_session *h2s;

    (void) worker;

    stream = NULL;
    h2s = mk_http2_session_get(conn);

    result = mk_http2_decode_frame(h2s->buffer, h2s->buffer_length, 
                                   &frame, h2s->local_settings.max_frame_size);

    if (MK_HTTP2_NO_ERROR != result)
    {
        return result;
    }

    *consumed_frame_length = MK_HTTP2_MINIMUM_FRAME_SIZE + frame.length;

    printf("FRAME TYPE = %d\n", frame.type);
    printf("FRAME DATA\n\n");
    mk_utils_hexdump(h2s->buffer, frame.length + 9, 16);
    printf("\n\n");

    if (MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status) {
        if (MK_HTTP2_SETTINGS_FRAME != frame.type) {
            MK_TRACE("[FD %i] First frame received should be a settings frame",
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }
    }

    if (MK_HTTP2_AWAITING_CONTINUATION_FRAME == h2s->status) {
        if (MK_HTTP2_CONTINUATION_FRAME != frame.type) {
            MK_TRACE("[FD %i] Wrong frame type received while awaiting a CONTINUATION " 
                     " frame",
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }

        if (frame.stream_id != h2s->expected_continuation_stream) {
            MK_TRACE("[FD %i] Wrong stream id [%i] received while awaiting a " 
                     " CONTINUATION frame for stream [%i]",
                     conn->event.fd, 
                     frame.stream_id,
                     h2s->expected_continuation_stream);

            mk_http2_error(MK_HTTP2_PROTOCOL_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }
    }

    if(0 != frame.stream_id) {
        stream = mk_http2_stream_get(h2s, MK_HTTP2_REMOTELY_INITIATED_STREAM, frame.stream_id);

        if(NULL == stream) {
            /* Trying to initiate a stream with an ID that's not higher than the last
             * one should return a protocol error according to 5.1.1
             */
            if(h2s->maximum_remotely_initiated_stream_id >= frame.stream_id)
            {
                return MK_HTTP2_PROTOCOL_ERROR;
            }

            result = mk_http2_stream_create(h2s, MK_HTTP2_REMOTELY_INITIATED_STREAM, frame.stream_id);

            if(0 > result) {
                /* TRACE ERROR */
                return MK_HTTP2_INTERNAL_ERROR;
            }

            stream = mk_http2_stream_get(h2s, MK_HTTP2_REMOTELY_INITIATED_STREAM, frame.stream_id);

            if(NULL == stream) {
                /* TRACE ERROR */
                return MK_HTTP2_INTERNAL_ERROR;
            }

            h2s->maximum_remotely_initiated_stream_id = frame.stream_id;

            /* According to 5.1.1 when a stream id enters the OPEN statue we need to 
             * transition any lower id streams that are still in the IDLE state to
             * the closed state, this will be implemented later on. 
            */
        }
    }

    if (NULL != stream) {
        if (MK_HTTP2_STREAM_STATUS_IDLE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME   != frame.type &&
                MK_HTTP2_PRIORITY_FRAME     != frame.type &&
                MK_HTTP2_HEADERS_FRAME      != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_RESERVED_LOCAL == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_RESERVED_REMOTE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME != frame.type &&
                MK_HTTP2_PRIORITY_FRAME   != frame.type &&
                MK_HTTP2_HEADERS_FRAME    != frame.type) {
                return MK_HTTP2_PROTOCOL_ERROR;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE == stream->status) {
            if (MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                return MK_HTTP2_STREAM_CLOSED;
            }
        }
        else if (MK_HTTP2_STREAM_STATUS_CLOSED == stream->status) {
            if(1 == stream->rst_stream_received) {
                if (MK_HTTP2_PRIORITY_FRAME      != frame.type) {
                    return MK_HTTP2_STREAM_CLOSED;
                }
            }
            else if(1 == stream->end_stream_received) {
                /* This actually depends on the time after a DATA or HEADERS frame
                 * was sent with the END_STREAM flag toggled, since we are not 
                 * saving that timestamp, it needs further improvement to be
                 * compliant. Section 5.1
                 */
                if (MK_HTTP2_PRIORITY_FRAME      != frame.type &&
                    MK_HTTP2_RST_STREAM_FRAME    != frame.type &&
                    MK_HTTP2_WINDOW_UPDATE_FRAME != frame.type) {
                    return MK_HTTP2_PROTOCOL_ERROR;
                }
            }
        }
    }

    if (MK_HTTP2_SETTINGS_FRAME == frame.type) {
        result = mk_http2_handle_settings_frame(conn, &frame);
    }
    else if (MK_HTTP2_DATA_FRAME == frame.type) {
        result = mk_http2_handle_data_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_WINDOW_UPDATE_FRAME == frame.type) {
        result = mk_http2_handle_window_update_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_HEADERS_FRAME == frame.type) {
        result = mk_http2_handle_headers_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_PUSH_PROMISE_FRAME == frame.type) {
        result = mk_http2_handle_push_promise_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_CONTINUATION_FRAME == frame.type) {
        result = mk_http2_handle_continuation_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_PRIORITY_FRAME == frame.type) {
        result = mk_http2_handle_priority_frame(conn, &frame, stream);
    }
    else {
        result = MK_HTTP2_UNKNOWN_FRAME;
    }

    printf("Frame error? %d\n", result);

    if (MK_HTTP2_NO_ERROR != result) {
        mk_http2_error(result, server);

        return MK_HTTP2_FRAME_ERROR;
    }

    if (NULL != stream) {
        printf("ID     : [%d]\n", stream->id);
        printf("STATUS : [%x]\n", stream->status);
        printf("\n");

        if (1 == stream->end_headers_received && 
            1 == stream->end_stream_received) {
            printf("READY TO DISPATCH HANDLER!\n");
            printf("\n");

            result = mk_http2_request_prepare(&stream->request);

            if (MK_HTTP2_REQUEST_PREPARATION_SUCCESS != result) {
                return MK_HTTP2_FRAME_ERROR;
            }

            printf("PREPARE RESULT : %d\n", result);

            result = mk_http2_handle_request(&stream->request);

            printf("INIT RESULT : %d\n", result);
        }
    }

    return MK_HTTP2_FRAME_PROCESSED;
}


/* Handle an upgraded session 
 *
 * TODO : Verify this function as many things changed since it was checked and 
 *        it's probably outdated and broken.
 */
static int mk_http2_upgrade(void *cs, void *sr, struct mk_server *server)
{
    struct mk_http_session *s = cs;
    struct mk_http_request *r = sr;
    struct mk_http2_session *h2s;

    mk_header_set_http_status(r, MK_INFO_SWITCH_PROTOCOL);
    r->headers.connection = MK_HEADER_CONN_UPGRADED;
    r->headers.upgrade = MK_HEADER_UPGRADED_H2C;
    mk_header_prepare(s, r, server);

    h2s = mk_http2_session_get(s->conn);

    h2s->status = MK_HTTP2_UPGRADED;

    s->conn->data = h2s;

    return MK_HTTP_OK;
}

static int mk_http2_sched_read(struct mk_sched_conn *conn,
                               struct mk_sched_worker *worker,
                               struct mk_server *server)
{
    size_t                   consumed_frame_length;
    int                      frame_result;
    int                      new_size;
    int                      bytes;
    uint8_t                 *tmp;
    struct mk_http2_session *h2s;

    (void) worker;
    (void) server;

    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_UNINITIALIZED == h2s->status ||
       MK_HTTP2_UPGRADED == h2s->status) {
        h2s->server = server;
        h2s->connection = conn;

        h2s->buffer = h2s->buffer_fixed;
        h2s->buffer_size = MK_HTTP2_CHUNK;
        h2s->buffer_length = 0;

        /* This is specified in https://tools.ietf.org/html/rfc7540#section-6.9.2 */
        h2s->remote_settings.initial_window_size = MK_HTTP2_DEFAULT_FLOW_CONTROL_WINDOW_SIZE;

        h2s->flow_control_window_size = h2s->remote_settings.initial_window_size;
        h2s->response_stream_id_sequence = 0;

        h2s->locally_initiated_open_stream_count = 0;
        h2s->remotely_initiated_open_stream_count = 0;

        h2s->maximum_locally_initiated_stream_id = 0;
        h2s->maximum_remotely_initiated_stream_id = 0;

        mk_list_init(&h2s->http2_streams);

        mk_stream_set(&h2s->stream,
                      &conn->channel,
                      NULL,
                      NULL, NULL, NULL);

        h2s->status = MK_HTTP2_AWAITING_PREFACE;
    }

    if (0 == (h2s->buffer_size - h2s->buffer_length)) {
        new_size = h2s->buffer_size + MK_HTTP2_CHUNK;

        if (h2s->buffer == h2s->buffer_fixed) {
            h2s->buffer = mk_mem_alloc_z(new_size);

            /* FIXME: send internal server error ? */
            if (NULL == h2s->buffer) {
                return -1;
            }

            memcpy(h2s->buffer, h2s->buffer_fixed, h2s->buffer_length);

            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer new size: %i, length: %i",
                     conn->event.fd, new_size, h2s->buffer_length);
        }
        else {
            tmp = (uint8_t *) mk_mem_realloc(h2s->buffer, new_size);

            /* FIXME: send internal server error ? */
            if (NULL == tmp) {
                return -1;
            }

            h2s->buffer = tmp;
            h2s->buffer_size = new_size;

            MK_TRACE("[FD %i] Buffer realloc from %i to %i",
                     conn->event.fd, h2s->buffer_size, new_size);
        }
    }

    /* Read the incoming data */
    bytes = mk_sched_conn_read(conn,
                               &h2s->buffer[h2s->buffer_length],
                               h2s->buffer_size - h2s->buffer_length);

    if (0 == bytes) {
        errno = 0;
        return -1;
    }
    else if (-1 == bytes) {
        return -1;
    }

    h2s->buffer_length += bytes;

    printf("JUST READ %d BYTES\n", bytes);

    mk_utils_hexdump(h2s->buffer, h2s->buffer_length, 16);

    printf("\nh2s->status = %d\n", h2s->status);

    if (MK_HTTP2_AWAITING_PREFACE == h2s->status || /* This is either a prior
                                                       knowledge plaintext or
                                                       direct TLS HTTP/2
                                                       request */
        MK_HTTP2_UPGRADED == h2s->status) { /* Upgraded connections from HTTP/1.x
                                               requires the preface */
        if (h2s->buffer_length >= sizeof(MK_HTTP2_PREFACE) - 1) {
            if (0 != memcmp(h2s->buffer,
                            MK_HTTP2_PREFACE, sizeof(MK_HTTP2_PREFACE) - 1)) {
                MK_H2_TRACE(conn, "Invalid HTTP/2 preface");

                return 0;
            }

            MK_H2_TRACE(conn, "HTTP/2 preface OK");

            buffer_consume(h2s, sizeof(MK_HTTP2_PREFACE) - 1);

            h2s->local_settings = MK_HTTP2_SETTINGS_DEFAULT;

            /* Send out our default settings */
            /* TODO: Do we really want to send a pre serialized structure?
                     what's the performance vs readability relationship here? */

            mk_stream_in_raw(&h2s->stream,
                             NULL,
                             MK_HTTP2_SETTINGS_DEFAULT_FRAME,
                             sizeof(MK_HTTP2_SETTINGS_DEFAULT_FRAME) - 1,
                             NULL, NULL);

            /* Ideally we won't flush the channel every time, this is a
               crutch */
            mk_channel_flush(h2s->stream.channel);

            // mk_event_add(mk_sched_loop(),
            //              h2s->stream.channel->fd,
            //              MK_EVENT_CONNECTION,
            //              MK_EVENT_WRITE,
            //              h2s->stream.channel->event);

            h2s->status = MK_HTTP2_AWAITING_CLIENT_SETTINGS;
        }
        else {
            return 0; /* We need more data */
        }
    }

    do {
        consumed_frame_length = 0;
        frame_result = mk_http2_frame_run(conn, worker, server, &consumed_frame_length);

        if (0 != consumed_frame_length) {
            buffer_consume(h2s, consumed_frame_length);
        }
    }
    while (MK_HTTP2_FRAME_PROCESSED == frame_result && 
           0 < h2s->buffer_length);

    if (MK_HTTP2_FRAME_ERROR == frame_result) {
        return -1;
    }

    return 0;
}

/* The scheduler got a connection close event from the remote client */
int mk_http2_sched_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type, struct mk_server *server)
{
    struct mk_http2_session *h2s;

    (void) server;
    (void) sched;
    (void) type;

    /* Release resources of the requests and session */
    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_UNINITIALIZED != h2s->status) {
        if (h2s->buffer != h2s->buffer_fixed &&
            NULL != h2s->buffer) {
            mk_mem_free(h2s->buffer);
        }

        h2s->buffer = NULL;
        h2s->buffer_size = 0;
        h2s->buffer_length = 0;

        mk_http2_stream_destroy_all(h2s);

        h2s->status = MK_HTTP2_UNINITIALIZED;
    }

    return 0;
}

struct mk_sched_handler mk_http2_handler = {
    .name             = "http2",
    .cb_read          = mk_http2_sched_read,
    .cb_close         = mk_http2_sched_close,
    .cb_done          = NULL,
    .cb_upgrade       = mk_http2_upgrade,
    .sched_extra_size = sizeof(struct mk_http2_session),
    .capabilities     = MK_CAP_HTTP2
};
