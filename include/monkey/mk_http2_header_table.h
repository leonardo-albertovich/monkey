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

#ifndef MK_HTTP2_HEADER_TABLE_H
#define MK_HTTP2_HEADER_TABLE_H

#include <monkey/mk_core.h>

struct mk_http2_header_table_entry {
    struct mk_list _head;
    char          *name;
    char          *value;
};

struct mk_http2_header_table {
    struct mk_list entries;      /* list of dynamic table entries */
};

#define mk_http2_header_table_entry_create_debug(ctx, name, value) \
    mk_http2_header_table_entry_create(ctx, name, strlen(name), value, strlen(value));

int mk_http2_header_table_entry_create(struct mk_http2_header_table *ctx, 
                                       char *name,
                                       size_t name_length,
                                       char *value,
                                       size_t value_length);

int mk_http2_header_table_entry_destroy(struct mk_http2_header_table *ctx, 
                                        struct mk_http2_header_table_entry *entry);

int mk_http2_header_table_entry_destroy_all(struct mk_http2_header_table *ctx);

struct mk_http2_header_table_entry *mk_http2_header_table_entry_get_by_name_and_index(
                                        struct mk_http2_header_table *ctx, 
                                        char *name,
                                        size_t index);

struct mk_http2_header_table *mk_http2_header_table_create();

int mk_http2_header_table_destroy(struct mk_http2_header_table *ctx);

#define mk_http2_header_table_entry_get_by_name(ctx, name) \
    mk_http2_header_table_entry_get_by_name_and_index(ctx, name, 0)

#endif
