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

#include <monkey/mk_http2_dynamic_table.h>


/* NOTE: This list is a fifo, older entries will be evicted as needed */
int mk_http2_dynamic_table_entry_create(struct mk_http2_dynamic_table *ctx, 
                                        char *name,
                                        char *value)
{
    struct mk_http2_dynamic_table_entry *new_entry;
    struct mk_http2_dynamic_table_entry *first_entry;
    struct mk_list                      *insertion_point;
    int id;

    id = -1;

    /* Get ID for the new entry */
    if (mk_list_is_empty(&ctx->entries) == 0) {
        id = 0;
        insertion_point = &ctx->entries;
    }
    else {
        first_entry = mk_list_entry_first(&ctx->entries, 
                                          struct mk_http2_dynamic_table_entry, _head);

        insertion_point = &first_entry->_head;

        id = first_entry->id + 1;
    }


    /* Allocate and register queue */
    new_entry = mk_mem_alloc(sizeof(struct mk_http2_dynamic_table_entry));
    if (NULL == new_entry) {
        perror("malloc");
        return -1;
    }

    new_entry->id = id;

    new_entry->name = mk_mem_alloc(strlen(name) + 1);
    if (NULL == new_entry->name) {
        perror("malloc");
        return -2;
    }

    new_entry->value = mk_mem_alloc(strlen(value) + 1);
    if (NULL == new_entry->value) {
        perror("malloc");
        return -2;
    }

    /* We are using strlen to measure it previously, there is no reason to explicitly
     * use it here
    */
    strcpy(new_entry->name,  name);
    strcpy(new_entry->value, value);

    new_entry->size = strlen(name) + strlen(value) + 2;

    ctx->size += new_entry->size;

    /* TODO : verify that this is the correct way to prepend to a list (even though
     *        it works)
     */
    mk_list_add(&new_entry->_head, insertion_point);

    return id;
}

int mk_http2_dynamic_table_entry_destroy(struct mk_http2_dynamic_table *ctx, 
                                         struct mk_http2_dynamic_table_entry *entry)
{
    (void) ctx;

    mk_mem_free(entry->name);
    mk_mem_free(entry->value);

    mk_list_del(&entry->_head);
    mk_mem_free(entry);

    return 0;
}

int mk_http2_dynamic_table_entry_destroy_all(struct mk_http2_dynamic_table *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http2_dynamic_table_entry *entry;

    mk_list_foreach_safe(head, tmp, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);
        mk_http2_dynamic_table_entry_destroy(ctx, entry);
        c++;
    }

    return c;
}

struct mk_http2_dynamic_table_entry *mk_http2_dynamic_table_entry_get_by_id(
                                        struct mk_http2_dynamic_table *ctx, 
                                        uint32_t id)
{
    struct mk_list *head;
    struct mk_http2_dynamic_table_entry *entry;

    mk_list_foreach(head, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);

        if(id == entry->id)
        {
            return entry;
        }
    }

    return NULL;
}

struct mk_http2_dynamic_table *mk_http2_dynamic_table_create()
{
    struct mk_http2_dynamic_table *ctx;

    ctx = mk_mem_alloc(sizeof(struct mk_http2_dynamic_table));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    /* Metadata */
    ctx->size = 0;

    /* Lists */
    mk_list_init(&ctx->entries);

    return ctx;
}

int mk_http2_dynamic_table_destroy(struct mk_http2_dynamic_table *ctx) {
    mk_http2_dynamic_table_entry_destroy_all(ctx);
    mk_mem_free(ctx);
    return 0;
}
