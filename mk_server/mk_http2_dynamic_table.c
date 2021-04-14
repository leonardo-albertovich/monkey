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


/* NOTE 1 : This list is a fifo, older entries will be evicted as needed
 * NOTE 2 : We need o make both lengths explicit to avoid innecesary allocations that 
 *          would be needed when any of them are passed as uncompressed string literals 
 *          in the packet
 */
int mk_http2_dynamic_table_entry_create(struct mk_http2_dynamic_table *ctx, 
                                        char *name,
                                        size_t name_length,
                                        char *value, 
                                        size_t value_length)
{
    struct mk_http2_dynamic_table_entry *new_entry;
    struct mk_http2_dynamic_table_entry *first_entry;
    size_t                               new_entry_size;
    struct mk_list                      *insertion_point;

    new_entry_size = (name_length + value_length + 32);

    if (0 != mk_list_is_empty(&ctx->entries)) {
        if (new_entry_size > ctx->size_limit) {
            mk_http2_dynamic_table_enforce_size_limit(ctx, 0);

            return -1;
        }

        mk_http2_dynamic_table_enforce_size_limit(ctx, ctx->size_limit - new_entry_size);

        /* This was moved here because we take this path whenever new_entry_size is
         * smaller or equal to the dynamic table size limit which could leave us with
         * an empty table
         */
    }

    /* Allocate and register queue */
    new_entry = mk_mem_alloc_z(sizeof(struct mk_http2_dynamic_table_entry));
    if (NULL == new_entry) {
        perror("malloc");
        return -2;
    }

    new_entry->id = ctx->next_id;

    new_entry->name = mk_mem_alloc_z(name_length + 1);
    if (NULL == new_entry->name) {
        perror("malloc");
        return -3;
    }

    new_entry->value = mk_mem_alloc_z(value_length + 1);
    if (NULL == new_entry->value) {
        perror("malloc");
        return -4;
    }

    strncpy(new_entry->name,  name, name_length);
    strncpy(new_entry->value, value, value_length);

    new_entry->size = new_entry_size;

    ctx->size += new_entry->size;

    /* TODO : verify that this is the correct way to prepend to a list (even though
     *        it works)
     */
    if (0 == mk_list_is_empty(&ctx->entries)) {
        insertion_point = &ctx->entries;
    }
    else {
        first_entry = mk_list_entry_first(&ctx->entries, 
                                          struct mk_http2_dynamic_table_entry, _head);

        insertion_point = &first_entry->_head;
    }

    mk_list_add(&new_entry->_head, insertion_point);

    ctx->next_id++;

    return new_entry->id;
}

int mk_http2_dynamic_table_entry_destroy(struct mk_http2_dynamic_table *ctx, 
                                         struct mk_http2_dynamic_table_entry *entry)
{
    (void) ctx;

    ctx->size -= entry->size;

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

struct mk_http2_dynamic_table_entry *mk_http2_dynamic_table_entry_get_by_name(
                                        struct mk_http2_dynamic_table *ctx, 
                                        char *name)
{
    struct mk_list *head;
    struct mk_http2_dynamic_table_entry *entry;

    mk_list_foreach(head, &ctx->entries) {
        entry = mk_list_entry(head, struct mk_http2_dynamic_table_entry, _head);

        if(strcasecmp(name, entry->name))
        {
            return entry;
        }
    }

    return NULL;

}

/* Explicitly stating the size_limit here allows us to evict before appending
 * as specified in https://www.rfc-editor.org/rfc/rfc7541.html#section-4.1
 */
int mk_http2_dynamic_table_enforce_size_limit(struct mk_http2_dynamic_table *ctx,
                                              size_t size_limit)
{
    struct mk_http2_dynamic_table_entry *last_entry;

    while (ctx->size > size_limit) {
        if (0 != mk_list_is_empty(&ctx->entries)) {
            last_entry = mk_list_entry_last(&ctx->entries, 
                                              struct mk_http2_dynamic_table_entry, _head);

            mk_http2_dynamic_table_entry_destroy(ctx, 
                                                 last_entry);
        }
    }

    return 0;
}

void mk_http2_dynamic_table_set_size_limit(struct mk_http2_dynamic_table *ctx, 
                                          uint32_t size_limit)
{
    ctx->size_limit = size_limit;

    mk_http2_dynamic_table_enforce_size_limit(ctx, ctx->size_limit);
}

struct mk_http2_dynamic_table *mk_http2_dynamic_table_create(uint32_t size_limit)
{
    struct mk_http2_dynamic_table *ctx;

    ctx = mk_mem_alloc_z(sizeof(struct mk_http2_dynamic_table));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }

    /* Metadata */
    ctx->size = 0;
    ctx->size_limit = size_limit;
    ctx->next_id = 1;

    /* Lists */
    mk_list_init(&ctx->entries);

    return ctx;
}

int mk_http2_dynamic_table_destroy(struct mk_http2_dynamic_table *ctx) {
    mk_http2_dynamic_table_entry_destroy_all(ctx);
    mk_mem_free(ctx);
    return 0;
}
