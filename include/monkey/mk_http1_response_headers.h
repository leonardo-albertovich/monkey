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

#ifndef MK_HTTP1_RESPONSE_HEADERS_H
#define MK_HTTP1_RESPONSE_HEADERS_H

#include <monkey/mk_http_base.h>
#include <monkey/mk_stream.h>

#define MK_HEADER_IOV         32
#define MK_HEADER_ETAG_SIZE   32

struct mk_http1_response_headers
{
    int status;

    /* Connection flag, if equal -1, the connection header is ommited */
    int connection;

    /*
     * If some plugins wants to set a customized HTTP status, here
     * is the 'how and where'
     */
    mk_ptr_t custom_status;

    /* Length of the content to send */
    long content_length;

    /* Private value, real length of the file requested */
    long real_length;

    int cgi;
    int pconnections_left;
    int breakline;

    int transfer_encoding;

    int upgrade;

    int ranges[2];

    time_t last_modified;
    mk_ptr_t allow_methods;
    mk_ptr_t content_type;
    mk_ptr_t content_encoding;
    char *location;

    int  etag_len;
    char etag_buf[MK_HEADER_ETAG_SIZE];

    /*
     * This field allow plugins to add their own response
     * headers
     */
    struct mk_iov *_extra_rows;

    /* Flag to track if the response headers were sent */
    int sent;

    /* IOV dirty hack */
    struct mk_iov headers_iov;
    struct iovec __iov_io[MK_HEADER_IOV];
    void *__iov_buf[MK_HEADER_IOV];
};

#endif
