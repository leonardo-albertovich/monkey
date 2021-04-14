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

#include <monkey/mk_http2_header_table.h>


/* NOTE: We need o make both lengths explicit to avoid innecesary allocations that would
 * be needed when any of them are passed as uncompressed string literals in the packet
 */
int mk_http2_header_table_entry_create(struct mk_http2_header_table *ctx, 
                                        char *name,
                                        size_t name_length,
                                        char *value,
                                        size_t value_length)
{
    struct mk_http2_header_table_entry *new_entry;
    struct mk_http2_header_table_entry *last_entry;
    struct mk_list                     *insertion_point;

    /* Get ID for the new entry */
    if (mk_list_is_empty(&ctx->entries) == 0) {
        insertion_point = &ctx->entries;
    }
    else {
        last_entry = mk_list_entry_last(&ctx->entries, 
                                        struct mk_http2_header_table_entry, _head);

        insertion_point = &last_entry->_head;
    }

    /* Allocate and register queue */
    new_entry = mk_mem_alloc_z(sizeof(struct mk_http2_header_table_entry));
    if (NULL == new_entry) {
        perror("malloc");
        return -1;
    }

    new_entry->name = mk_mem_alloc_z(name_length + 1);
    if (NULL == new_entry->name) {
        perror("malloc");
        return -2;
    }

    new_entry->value = mk_mem_alloc_z(value_length + 1);
    if (NULL == new_entry->value) {
        perror("malloc");
        return -3;
    }

    strncpy(new_entry->name,  name, name_length);
    strncpy(new_entry->value, value, value_length);

    mk_list_add(&new_entry->_head, insertion_point);

    return 0;
}

int mk_http2_header_table_entry_destroy(struct mk_http2_header_table *ctx, 
                                         struct mk_http2_header_table_entry *entry)
{
    (void) ctx;

    mk_mem_free(entry->name);
    mk_mem_free(entry->value);

    mk_list_del(&entry->_head);
    mk_mem_free(entry);

    return 0;
}

int mk_http2_header_table_entry_destroy_all(struct mk_http2_header_table *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http2_header_table_entry *entry;

    mk_list_foreach_safe(head, tmp, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);
        mk_http2_header_table_entry_destroy(ctx, entry);
        c++;
    }

    return c;
}

struct mk_http2_header_table_entry *mk_http2_header_table_entry_get_by_name_and_index(
                                        struct mk_http2_header_table *ctx, 
                                        char *name,
                                        size_t index)
{
    struct mk_list *head;
    struct mk_http2_header_table_entry *entry;
    size_t match_index;

    match_index = 0;
    mk_list_foreach(head, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);

        /* Do we want to do it caseless? Also, headers could repeat so this might
         * not end up being as useful as planned.
         */
        if(0 == strcasecmp(entry->name, name))
        {
            if (match_index == index) {
                return entry;
            }

            match_index++;
        }
    }

    return NULL;
}

struct mk_http2_header_table *mk_http2_header_table_create()
{
    struct mk_http2_header_table *ctx;

    ctx = mk_mem_alloc(sizeof(struct mk_http2_header_table));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    /* Lists */
    mk_list_init(&ctx->entries);

    return ctx;
}

int mk_http2_header_table_destroy(struct mk_http2_header_table *ctx) {
    mk_http2_header_table_entry_destroy_all(ctx);
    mk_mem_free(ctx);
    return 0;
}
