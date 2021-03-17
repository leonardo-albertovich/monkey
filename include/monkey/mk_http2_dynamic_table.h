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

#ifndef MK_HTTP2_DYNAMIC_TABLE_H
#define MK_HTTP2_DYNAMIC_TABLE_H

#include <monkey/mk_core.h>

struct mk_http2_dynamic_table_entry {
    struct mk_list _head;
    uint32_t       id;
    char          *name;
    char          *value;
    size_t         size;
};

struct mk_http2_dynamic_table {
    struct mk_list entries;      /* list of dynamic table entries */
    size_t         size;         /* pre-computed size of the entire table */
};

int mk_http2_dynamic_table_entry_create(struct mk_http2_dynamic_table *ctx, 
                                        char *name,
                                        char *value);

int mk_http2_dynamic_table_entry_destroy(struct mk_http2_dynamic_table *ctx, 
                                         struct mk_http2_dynamic_table_entry *entry);

int mk_http2_dynamic_table_entry_destroy_all(struct mk_http2_dynamic_table *ctx);

struct mk_http2_dynamic_table_entry *mk_http2_dynamic_table_entry_get_by_id(
                                        struct mk_http2_dynamic_table *ctx, 
                                        uint32_t id);

struct mk_http2_dynamic_table *mk_http2_dynamic_table_create();

int mk_http2_dynamic_table_destroy(struct mk_http2_dynamic_table *ctx);

#endif
