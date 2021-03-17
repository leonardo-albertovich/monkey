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

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_http2_huffman.h>
#include <monkey/mk_header.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_scheduler.h>

static const struct mk_http2_header_pair mk_http2_static_table[] = {
    {NULL,                          NULL},
    {":authority",                  NULL},
    {":method",                     "GET"},
    {":method",                     "POST"},
    {":path",                       "/"},
    {":path",                       "/index.html"},
    {":scheme",                     "http"},
    {":scheme",                     "https"},
    {":status",                     "200"},
    {":status",                     "204"},
    {":status",                     "206"},
    {":status",                     "304"},
    {":status",                     "400"},
    {":status",                     "404"},
    {":status",                     "500"},
    {"accept-charset",              NULL},
    {"accept-encoding",             "gzip, deflate"},
    {"accept-language",             NULL},
    {"accept-ranges",               NULL},
    {"accept",                      NULL},
    {"access-control-allow-origin", NULL},
    {"age",                         NULL},
    {"allow",                       NULL},
    {"authorization",               NULL},
    {"cache-control",               NULL},
    {"content-disposition",         NULL},
    {"content-encoding",            NULL},
    {"content-language",            NULL},
    {"content-length",              NULL},
    {"content-location",            NULL},
    {"content-range",               NULL},
    {"content-type",                NULL},
    {"cookie",                      NULL},
    {"date",                        NULL},
    {"etag",                        NULL},
    {"expect",                      NULL},
    {"expires",                     NULL},
    {"from",                        NULL},
    {"host",                        NULL},
    {"if-match",                    NULL},
    {"if-modified-since",           NULL},
    {"if-none-match",               NULL},
    {"if-range",                    NULL},
    {"if-unmodified-since",         NULL},
    {"last-modified",               NULL},
    {"link",                        NULL},
    {"location",                    NULL},
    {"max-forwards",                NULL},
    {"proxy-authenticate",          NULL},
    {"proxy-authorization",         NULL},
    {"range",                       NULL},
    {"referer",                     NULL},
    {"refresh",                     NULL},
    {"retry-after",                 NULL},
    {"server",                      NULL},
    {"set-cookie",                  NULL},
    {"strict-transport-security",   NULL},
    {"transfer-encoding",           NULL},
    {"user-agent",                  NULL},
    {"vary",                        NULL},
    {"via",                         NULL},
    {"www-authenticate",            NULL},
};



struct mk_http2_header_string {
    uint8_t length:7;
    uint8_t compression_flag:1;
    uint8_t data[];
};

// struct mk_http2_indexed_header {
//     uint8_t index:7;
//     uint8_t entry_type:1;
// };

// struct mk_http2_literal_header_with_incremental_indexing {
//     uint8_t index:6;
//     uint8_t entry_type:2;
// };

// struct mk_http2_dynamic_table_size_update {
//     uint8_t max_size:5;
//     uint8_t entry_type:3;
// };

// struct mk_http2_literal_header_without_indexing {
//     uint8_t index:4;
//     uint8_t entry_type:4;
// };

// struct mk_http2_literal_header_never_indexed {
//     uint8_t index:4;
//     uint8_t entry_type:4;
// };

// struct mk_http2_header {
//     union {
//         struct mk_http2_indexed_header 
//             indexed_header;

//         struct mk_http2_literal_header_with_incremental_indexing 
//             literal_header_with_incremental_indexing;

//         struct mk_http2_dynamic_table_size_update 
//             dynamic_table_size_update;

//         struct mk_http2_literal_header_never_indexed 
//             literal_header_never_indexed;

//         struct mk_http2_literal_header_without_indexing 
//             literal_header_without_indexing;
//     } d;
// };

#define MK_HTTP2_HEADER_COMPRESSION_FLAG                             0x80
#define MK_HTTP2_HEADER_STRING_LENGTH_BITS                           7

#define MK_HTTP2_INDEXED_HEADER_INDEX_BITS                           7
#define MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_INDEX_BITS 6
#define MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_MAX_SIZE_BITS             5
#define MK_HTTP2_LITERAL_HEADER_WITHOUT_INDEXING_INDEX_BITS          4
#define MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_INDEX_BITS             4

#define MK_HTTP2_INDEXED_HEADER_TYPE                                 0x80
#define MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE       0x40
#define MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_TYPE                      0x20
#define MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_TYPE                   0x10
#define MK_HTTP2_LITERAL_HEADER_WITHOUT_INDEXING_TYPE                0x00


#define MK_HTTP2_HEADER_STRING_SIZE                                  1
#define MK_HTTP2_INDEXED_HEADER_SIZE                                 1
#define MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_SIZE       1
#define MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_SIZE                      1
#define MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_SIZE                   1
#define MK_HTTP2_LITERAL_HEADER_WITHOUT_INDEXING_SIZE                1

#define MK_HTTP2_IS_HEADER_STRING_COMPRESSED(x) \
            (MK_HTTP2_HEADER_COMPRESSION_FLAG == (MK_HTTP2_HEADER_COMPRESSION_FLAG & x))

#define MK_HTTP2_IS_INDEXED_HEADER(x) \
            (MK_HTTP2_INDEXED_HEADER_TYPE == (MK_HTTP2_INDEXED_HEADER_TYPE & x))

#define MK_HTTP2_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(x) \
            (MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE == \
                (MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE & x))

#define MK_HTTP2_IS_DYNAMIC_TABLE_SIZE_UPDATE(x) \
            (MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_TYPE == \
                (MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_TYPE & x))

#define MK_HTTP2_IS_LITERAL_HEADER_NEVER_INDEXED(x) \
            (MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_TYPE == \
                (MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_TYPE & x))

#define MK_HTTP2_IS_LITERAL_HEADER_WITHOUT_INDEXING(x) \
            (MK_HTTP2_LITERAL_HEADER_WITHOUT_INDEXING_TYPE == \
                (MK_HTTP2_LITERAL_HEADER_WITHOUT_INDEXING_TYPE & x))

int mk_http2_fetch_entry_from_header_table(struct mk_http2_stream *stream,
                                           uint32_t index, char **name, char **value)
{
    size_t                               static_table_length;
    struct mk_http2_dynamic_table_entry *dynamic_table_entry;

    if(NULL == name)
    {
        return -2;
    }

    if(NULL == value)
    {
        return -3;
    }

    if(1 > index)
    {
        return -4;
    }

    static_table_length = sizeof(mk_http2_static_table) / 
                          sizeof(struct mk_http2_header_pair);

    if(static_table_length >= index) {
        *name  = mk_http2_static_table[index].name;
        *value = mk_http2_static_table[index].value;
    }
    else {
        dynamic_table_entry = mk_http2_dynamic_table_entry_get_by_id(stream->dynamic_table, 
                                                                     index);

        if(NULL == dynamic_table_entry) {
            return -1;
        }

        *name  = dynamic_table_entry->name;
        *value = dynamic_table_entry->value;
    }

    return 0;
}

static inline int mk_http2_hpack_encode_int_is_onebyte(int64_t value, 
                                                       uint8_t prefix_bits)
{
    return ((1 << prefix_bits) - 1) > value;
}

/* A slight refactor of h2o_hpack_encode_int */
int mk_http2_hpack_encode_int(uint8_t *dst, int64_t value, unsigned prefix_bits)
{
    size_t dst_idx;

    dst_idx = 0;

    if (mk_http2_hpack_encode_int_is_onebyte(value, prefix_bits)) {
        dst[dst_idx++] |= value;
    }
    else {
        value          -= (1 << prefix_bits) - 1;
        dst[dst_idx++] |= (1 << prefix_bits) - 1;

        for (; value >= 128; value >>= 7) {
            dst[dst_idx++] = 0x80 | value;
        }

        dst[dst_idx++] = value;
    }

    return dst_idx;
}

/* Heavily based in h2o_hpack_decode_int */
int64_t mk_http2_hpack_decode_int(uint8_t *src, 
                                  size_t   src_len, 
                                  size_t  *octet_count, 
                                  unsigned prefix_bits)
{
    uint8_t  prefix_max; 
    size_t   src_idx;
    uint64_t value;

    if(NULL != octet_count) {
        *octet_count = 0;
    }

    prefix_max = (1 << prefix_bits) - 1;

    value = src[0] & prefix_max;

    if (value != prefix_max) {
        if(NULL != octet_count) {
            *octet_count = 1;
        }

        return (int64_t) value;
    }

    value = 0;

    /* There could be a bug in here while processing the last 2 octets, I will test it 
     * throughly later on
     */
    for(src_idx = 1 ; src_idx < src_len && src_idx < 10 ; src_idx++) {
        value |= (uint64_t)(src[src_idx] & 0x7F) << (7 * (src_idx - 1));

        if (0 == (src[src_idx] & 0x80)) {
            if(NULL != octet_count) {
                *octet_count = src_idx + 1;
            }

            return (int64_t) value + prefix_max;
        }
    }

    /* Either we exceeded the amount of continuation bytes or the buffer lenght, either
     * way it's not the expected outcome.
    */

    if(NULL != octet_count) {
        *octet_count = 0;
    }

    return 0;
}




static inline int mk_http2_consume_hpack_encoded_integer(size_t   *header_buffer_index,
                                                         size_t   *header_buffer_remainder,
                                                         uint8_t  *header_buffer,
                                                         uint8_t   prefix_bits,
                                                         int64_t  *integer_value,
                                                         uint8_t  *integer_flags)
{
    size_t  octet_count;
    uint8_t prefix_mask; 

    prefix_mask = (1 << prefix_bits) - 1;

    *integer_flags = header_buffer[*header_buffer_index] & prefix_mask;

    *integer_value = mk_http2_hpack_decode_int(&header_buffer[*header_buffer_index], 
                                               *header_buffer_remainder, 
                                               &octet_count, 
                                               prefix_bits);

    if(0 == octet_count) {
        /* Garbled integer, not a good sign */
        return -1;
    }

    *header_buffer_index += octet_count;
    *header_buffer_remainder -= octet_count;

    return 0;
}

static inline int mk_http2_consume_hpack_header_string(size_t   *header_buffer_index,
                                                       size_t   *header_buffer_remainder,
                                                       uint8_t  *header_buffer,
                                                       uint8_t **string_buffer,
                                                       size_t   *string_length,
                                                       uint8_t  *compression_flag)
{
    size_t octet_count;

    *compression_flag = MK_HTTP2_IS_HEADER_STRING_COMPRESSED(
                            header_buffer[*header_buffer_index]);

    *string_length = mk_http2_hpack_decode_int(&header_buffer[*header_buffer_index], 
                                               *header_buffer_remainder, 
                                               &octet_count, 
                                               MK_HTTP2_HEADER_STRING_LENGTH_BITS);

    /* Garbled integer? */
    if(0 == octet_count) {
        return -1;
    }

    *header_buffer_index += octet_count;
    *header_buffer_remainder -= octet_count;

    *string_buffer = &header_buffer[*header_buffer_index];

    *header_buffer_index += *string_length;
    *header_buffer_remainder -= *string_length;

    return 0;
}

int mk_http2_decompress_header_string(uint8_t **output_buffer, size_t *output_length,
                                      uint8_t *input_buffer, size_t input_length)
{
    int output_buffer_allocated;
    int result;

    if(NULL == *output_buffer) {
        if(0 == input_length) {
            printf("%s:%d\n", __FILE__, __LINE__);

            return -1; /* Bogus input length, decompression won't work either */
        }

        /* In a way it doesn't make sense to allocate the same amount of memory 
         * because it defeats the purpose but optimizing this at this point makes no 
         * sense
         * TODO: Allocate a smaller stack buffer for some cases and allocate the final
         *       buffer after decompressing or something to avoid fragmentation and waste 
        */
        *output_buffer = malloc(input_length);

        if(NULL == *output_buffer) {
            printf("%s:%d\n", __FILE__, __LINE__);

            return -2; /* Memory allocation error, bad stuff is going to happen */
        }

        *output_length = input_length;

        output_buffer_allocated = 1;
    }
    else {
        output_buffer_allocated = 0;
    }

    memset(*output_buffer, 0, *output_length);

    result = h2o_hpack_decode_huffman(*output_buffer, 
                                      *output_length, 
                                      input_buffer, 
                                      input_length);

    if(0 > result) {
        printf("%s:%d\n", __FILE__, __LINE__);

        if(1 == output_buffer_allocated) {
            printf("%s:%d\n", __FILE__, __LINE__);

            free(*output_buffer);

            *output_buffer = NULL;
            *output_length = 0;
        }

        return -3;
    }

    *output_length = (size_t) result;

    return 0;
}

int mk_http2_decompress_stream_headers(struct mk_http2_stream *stream)
{
    struct mk_http2_dynamic_table_entry *dynamic_table_entry;
    size_t                               header_buffer_index;
    size_t                               header_buffer_remainder;
    uint8_t                             *header_buffer;
    uint8_t                              header_type;
    char                                *header_name;
    size_t                               header_name_length;
    uint8_t                              header_name_compression_flag;
    char                                *header_value;
    size_t                               header_value_length;
    uint8_t                              header_value_compression_flag;
    int64_t                              dynamic_table_max_size;
    int64_t                              integer_value;
    uint8_t                              integer_flags;
    int                                  result;
    int64_t                              index;

    printf("LEN [%lu]\n", stream->header_buffer_length);

    header_buffer = stream->header_buffer;
    header_buffer_remainder = stream->header_buffer_length;

    for (header_buffer_index = 0 ; header_buffer_index < stream->header_buffer_length ; ) {
        // save_header_value_to_dynamic_table = 0;
        // save_header_name_to_dynamic_table  = 0;

        // header_entry = (struct mk_http2_header *) 
        //                     &stream->header_buffer[header_buffer_index];

        header_type = header_buffer[header_buffer_index];

        if (MK_HTTP2_IS_INDEXED_HEADER(header_type)) {
            result = mk_http2_consume_hpack_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_INDEXED_HEADER_INDEX_BITS,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                return -111; /* Garbled integer */
            }

            index = integer_value;

            printf("HPACK indexed header : %lux\n", index);

            result = mk_http2_fetch_entry_from_header_table(stream, 
                                                            index,
                                                            &header_name, 
                                                            &header_value);

            if (-1 > result) {
                return -1; /* Argument related error */
            }
            else if (0 > result) {
                return -2; /* Entry not found in dynamic table */
            }

            printf("NAME  : [%s]\n"
                   "VALUE : [%s]\n", 
                    header_name,
                    header_value);

            // header_buffer_index += MK_HTTP2_INDEXED_HEADER_SIZE;
        }
        else if (MK_HTTP2_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(header_type)) {
            result = mk_http2_consume_hpack_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_INDEX_BITS,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                return -111; /* Garbled integer */
            }

            index = integer_value;

            printf("HPACK literal header with incremental indexing : %lx\n", index);

            // header_buffer_index += MK_HTTP2_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_SIZE;

            if(0 == index) {
                result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                              &header_buffer_remainder,
                                                              header_buffer,
                                                  (uint8_t **)&header_name,
                                                              &header_name_length,
                                                              &header_name_compression_flag);

                if(0 != result) {
                    /* Garbled length error*/
                    return -111;
                }

                if(1 == header_name_compression_flag) {
                    uint8_t *outb;
                    size_t   outl;

                    outb = NULL;
                    outl = 0;

                    result = mk_http2_decompress_header_string(&outb, &outl, (uint8_t *)header_name, header_name_length);

                    if(0 != result) {
                        return -111; /* Decompression failure? */
                    }

                    printf("NAME1 : [%s]\n", outb);
                }

            }
            else {
                header_name_compression_flag = 0;

                result = mk_http2_fetch_entry_from_header_table(stream, index,
                                                                &header_name,
                                                                &header_value);

                if (result < -1) {
                    return -1; /* Argument related error */
                }
                else if (result < 0) {
                    return -2; /* Entry not found in dynamic table */
                }

                printf("NAME2 : [%s]\n", header_name);
            }

            // printf("\n\n");
            // mk_utils_hexdump((uint8_t *)&header_buffer[header_buffer_index], 32, 16);
            // printf("\n\n");

            result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_value,
                                                          &header_value_length,
                                                          &header_value_compression_flag);

            if(0 != result) {
                /* Garbled length error*/
                return -111;
            }

            printf("COMPRESSED? : %d\n", header_value_compression_flag);

            if(1 == header_value_compression_flag) {
                uint8_t *outb;
                size_t   outl;

                outb = NULL;
                outl = 0;

                result = mk_http2_decompress_header_string(&outb, &outl, (uint8_t *)header_value, header_value_length);

                if(0 != result) {
                    return -111; /* Decompression failure? */
                }

                printf("VALUE1: [%s]\n", outb);
            }
            else {
                printf("VALUE2: [%.*s]\n", header_value_length, header_value);
            }

        }
        else if (MK_HTTP2_IS_DYNAMIC_TABLE_SIZE_UPDATE(header_type)) {
            result = mk_http2_consume_hpack_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_SIZE,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                return -111; /* Garbled integer */
            }

            dynamic_table_max_size = integer_value;

            printf("HPACK dynamic table size update %lux\n", dynamic_table_max_size);

            // header_buffer_index += MK_HTTP2_DYNAMIC_TABLE_SIZE_UPDATE_SIZE;

            /* Decode the value, it's a packed integer */
            // stream->dynamic_table_size_limit = h2s->remote_settings.header_table_size;
        }
        else if(MK_HTTP2_IS_LITERAL_HEADER_NEVER_INDEXED(header_type)) {
            result = mk_http2_consume_hpack_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_SIZE,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                return -111; /* Garbled integer */
            }

            index = integer_value;

            printf("HPACK literal header never indexed %lux\n", index);

            result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_name,
                                                          &header_name_length,
                                                          &header_name_compression_flag);

            if(0 != result) {
                /* Garbled length error*/
                return -111;
            }

            result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_value,
                                                          &header_value_length,
                                                          &header_value_compression_flag);

            if(0 != result) {
                /* Garbled length error*/
                return -111;
            }
        }
        else if(MK_HTTP2_IS_LITERAL_HEADER_WITHOUT_INDEXING(header_type)) {
            result = mk_http2_consume_hpack_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_LITERAL_HEADER_NEVER_INDEXED_SIZE,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                return -111; /* Garbled integer */
            }

            index = integer_value;

            printf("HPACK literal header without indexing %lux\n",index);

            if (0 != index) {
                return -3; /* Index has to be 0000 in this type of entry */ 
            }

            result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_name,
                                                          &header_name_length,
                                                          &header_name_compression_flag);

            if(0 != result) {
                /* Garbled length error*/
                return -111;
            }

            result = mk_http2_consume_hpack_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_value,
                                                          &header_value_length,
                                                          &header_value_compression_flag);

            if(0 != result) {
                /* Garbled length error*/
                return -111;
            }

        }
        else {
            // return -1;
        }
    }

    return 0;   
}

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

static inline void mk_http2_decode_frame_header(uint8_t *buf,
                                                struct mk_http2_frame *frame)
{
    frame->length      = mk_http2_bitdec_32u(buf) >> 8;
    frame->type        = mk_http2_bitdec_32u(buf) &  0xFF;
    frame->flags       = buf[4];
    frame->stream_id   = mk_http2_bitdec_stream_id(&buf[5]);
    frame->raw_payload = &buf[MK_HTTP2_MINIMUM_FRAME_SIZE];

#ifdef MK_HAVE_TRACE
    MK_TRACE("Frame Header");

    printf(" length=%i, type=%i, stream_id=%i\n",
           frame->length,
           frame->type,
           frame->stream_id);
#endif
}

static inline void mk_http2_decode_data_frame_payload(struct mk_http2_frame *frame)
{
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        frame->payload.data.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.data.pad_length = 0;
    }

    frame->payload.data.data_length = frame->length - 
                                      optional_fields_size - 
                                      frame->payload.data.pad_length;

    frame->payload.data.data_block = payload_buffer;

    frame->payload.data.padding_block = \
        &payload_buffer[frame->payload.data.data_length];
}

static inline void mk_http2_decode_headers_frame_payload(struct mk_http2_frame *frame)
{
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        frame->payload.headers.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.headers.pad_length = 0;
    }

    if (0 != (MK_HTTP2_HEADERS_PRIORITY & frame->flags)) {
        frame->payload.headers.stream_dependency = ((uint32_t *)payload_buffer)[0];
        frame->payload.headers.weight = payload_buffer[4];

        payload_buffer += 5;
        optional_fields_size += 5;
    }
    else {
        frame->payload.headers.stream_dependency = 0;
        frame->payload.headers.weight = 0;
    }

    frame->payload.headers.data_length = frame->length - 
                                         optional_fields_size - 
                                         frame->payload.headers.pad_length;

    frame->payload.headers.data_block = payload_buffer;

    frame->payload.headers.padding_block = \
        &payload_buffer[frame->payload.headers.data_length];
}

static inline void mk_http2_decode_priority_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.priority.stream_dependency = \
    mk_http2_bitdec_stream_id(frame->raw_payload);
    
    frame->payload.priority.exclusive_dependency_flag = \
        BIT_CHECK(frame->payload.priority.stream_dependency, 31);

    BIT_CLEAR(frame->payload.priority.stream_dependency, 31);

    frame->payload.priority.weight = frame->raw_payload[4];
}

static inline void mk_http2_decode_rst_stream_frame_payload(struct mk_http2_frame *
                                                            frame)
{

    frame->payload.rst_stream.error_code = ((uint32_t *)frame->raw_payload)[0];
}

static inline void mk_http2_decode_settings_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.settings.entries = (struct mk_http2_setting *) frame->raw_payload;
}

static inline void mk_http2_decode_push_promise_frame_payload(struct mk_http2_frame *
                                                              frame)
{
    size_t   mandatory_fields_size;
    size_t   optional_fields_size;
    uint8_t *payload_buffer;

    mandatory_fields_size = 4; /* Promised Stream ID */
    optional_fields_size = 0;
    payload_buffer = frame->raw_payload;

    if (0 != (MK_HTTP2_HEADERS_PADDED & frame->flags)) {
        frame->payload.push_promise.pad_length = payload_buffer[0];

        payload_buffer += 1;
        optional_fields_size += 1;
    }
    else {
        frame->payload.push_promise.pad_length = 0;
    }

    frame->payload.push_promise.promised_stream_id = \
        mk_http2_bitdec_stream_id(frame->raw_payload);
    
    BIT_CLEAR(frame->payload.push_promise.promised_stream_id, 31);

    frame->payload.push_promise.data_length = frame->length - 
                                              optional_fields_size - 
                                              mandatory_fields_size - 
                                              frame->payload.push_promise.pad_length;

    frame->payload.push_promise.data_block = payload_buffer;

    frame->payload.push_promise.padding_block = \
        &payload_buffer[frame->payload.push_promise.data_length];
}

static inline void mk_http2_decode_ping_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.ping.data = ((uint64_t *)frame->raw_payload)[0];
}

static inline void mk_http2_decode_goaway_frame_payload(struct mk_http2_frame *frame)
{
    frame->payload.goaway.last_stream_id = \
    mk_http2_bitdec_stream_id(frame->raw_payload);

    BIT_CLEAR(frame->payload.goaway.last_stream_id, 31);

    frame->payload.goaway.error_code = *((uint32_t *)&frame->raw_payload[4]);
    frame->payload.goaway.additional_debug_data = &frame->raw_payload[8];
}

static inline void mk_http2_decode_window_update_frame_payload(struct mk_http2_frame *
                                                               frame)
{
    frame->payload.window_update.window_size_increment = \
        ((uint32_t *)frame->raw_payload)[0];

    BIT_CLEAR(frame->payload.window_update.window_size_increment, 31);
}

static inline void mk_http2_decode_continuation_frame_payload(struct mk_http2_frame *
                                                              frame)
{

    frame->payload.continuation.data_length = frame->length;
    frame->payload.continuation.data_block = frame->raw_payload;
}

static inline void mk_http2_decode_frame_payload(struct mk_http2_frame *frame)
{
    switch(frame->type) {
    case MK_HTTP2_DATA_FRAME:
        mk_http2_decode_data_frame_payload(frame);
        break;
    case MK_HTTP2_HEADERS_FRAME:
        mk_http2_decode_headers_frame_payload(frame);
        break;
    case MK_HTTP2_PRIORITY_FRAME:
        mk_http2_decode_priority_frame_payload(frame);
        break;
    case MK_HTTP2_RST_STREAM_FRAME:
        mk_http2_decode_rst_stream_frame_payload(frame);
        break;
    case MK_HTTP2_SETTINGS_FRAME:
        mk_http2_decode_settings_frame_payload(frame);
        break;
    case MK_HTTP2_PUSH_PROMISE_FRAME:
        mk_http2_decode_push_promise_frame_payload(frame);
        break;
    case MK_HTTP2_PING_FRAME:
        mk_http2_decode_ping_frame_payload(frame);
        break;
    case MK_HTTP2_GOAWAY_FRAME:
        mk_http2_decode_goaway_frame_payload(frame);
        break;
    case MK_HTTP2_WINDOW_UPDATE_FRAME:
        mk_http2_decode_window_update_frame_payload(frame);
        break;
    case MK_HTTP2_CONTINUATION_FRAME:
        mk_http2_decode_continuation_frame_payload(frame);
        break;
    }
}

static inline int mk_http2_handle_continuation_frame(struct mk_sched_conn *conn,
                                                     struct mk_http2_frame *frame)
{
    // struct mk_http2_session *h2s;
    // struct mk_http2_headers_frame_payload *headers;

    (void) conn;
    (void) frame;

    return 0;
}

static inline int mk_http2_handle_headers_frame(struct mk_sched_conn *conn,
                                                struct mk_http2_frame *frame,
                                                struct mk_http2_stream *stream
                                                )
{
    struct mk_http2_session *h2s;

    (void) conn;
    (void) frame;
    (void) stream;

    if (0 == frame->stream_id) {
        MK_TRACE("HEADERS ERROR, ZERO STREAM ID : %i\n", frame->stream_id);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    h2s = mk_http2_session_get(conn);

    if(h2s->remotely_initiated_open_stream_count == 
       h2s->local_settings.max_concurrent_streams) {
        /* The error code for this situation is based on the intention of the server,
         * in our case we do want the client to automatically retry thus we return
         * the most benevolent code.
         */
        return MK_HTTP2_REFUSED_STREAM;
    }

    stream->status = MK_HTTP2_STREAM_STATUS_OPEN;

    if (0 == (MK_HTTP2_HEADERS_END_HEADERS & frame->flags)) {
        /*
         * If we don't receive the END_HEADERS flag we need
         * to signal the session to expect a CONTINUATION 
         * frame for this stream.
         * 
         */
        if(NULL != stream->header_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;            
        }

        stream->header_buffer_size = frame->payload.headers.data_length;

        stream->header_buffer = mk_mem_alloc(stream->header_buffer_size);

        /* FIXME: send internal server error ? */
        if (NULL == stream->header_buffer) {
            return MK_HTTP2_INTERNAL_ERROR;
        }

        memcpy(stream->header_buffer, frame->payload.headers.data_block, 
               stream->header_buffer_size);

        stream->header_buffer_length = stream->header_buffer_size;

        h2s->status = MK_HTTP2_AWAITING_CONTINUATION_FRAME;

        h2s->expected_continuation_stream = frame->stream_id;
    }
    else {
        /* Process the headers! */
        printf("I SHOULD PROCESS THE HEADERS NOW!\n");

        /* No need to copy the buffer because we'll just use it now */
        stream->header_buffer = frame->payload.headers.data_block;
        stream->header_buffer_size = frame->payload.headers.data_length;
        stream->header_buffer_length = stream->header_buffer_size;

        mk_http2_decompress_stream_headers(stream);
    }

    if (0 != (MK_HTTP2_HEADERS_END_STREAM & frame->flags)) {
        stream->status = MK_HTTP2_STREAM_STATUS_HALF_CLOSED_REMOTE;
    }

    h2s->remotely_initiated_open_stream_count++;

    return MK_HTTP2_NO_ERROR;
}

static inline int mk_http2_handle_window_update_frame(struct mk_sched_conn *conn,
                                                      struct mk_http2_frame *frame)
{
    uint32_t window_size_increment;

    (void) conn;
    (void) frame;

    // struct mk_http2_session *h2s;

    // h2s = mk_http2_session_get(conn);

    if (4 != frame->length) {
        MK_TRACE("WINDOW UPDATE FRAME WITH A SIZE THAT IS NOT 4 : %i\n",
                 frame->length);

        return MK_HTTP2_FRAME_SIZE_ERROR;
    }

    window_size_increment = mk_http2_bitdec_32u((uint8_t *)frame->raw_payload);
    BIT_CLEAR(window_size_increment, 31);

    if (0 == window_size_increment ||
       MK_HTTP2_MAX_WINDOW_SIZE_INCREMENT < window_size_increment) {
        MK_H2_TRACE(conn, "INVALID VALUE FOR WINDOW_SIZE_INCREMENT %i",
                    window_size_increment);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    /* TODO : Actually handle this, at the moment nothing related to it is implemented
              but getting it out of the frame queue is the goal*/
    /*
    if (0 == frame->stream_id) {
    }
    */

    return MK_HTTP2_NO_ERROR;
}

static inline int mk_http2_handle_settings_frame(struct mk_sched_conn *conn,
                                                 struct mk_http2_frame *frame)
{
    size_t                   setting_entry_list_length;
    size_t                   setting_entry_list_index;
    struct mk_http2_setting *setting_entry_list;
    struct mk_http2_setting *setting_entry;
    struct mk_http2_session *h2s;

    h2s = mk_http2_session_get(conn);

    if (0 != frame->stream_id) {
        MK_TRACE("SETTINGS ERROR, NON ZERO STREAM ID : %i\n", frame->stream_id);

        return MK_HTTP2_PROTOCOL_ERROR;
    }

    if (MK_HTTP2_SETTINGS_ACK == frame->flags) {
        /*
         * Nothing to do, the peer just received our SETTINGS and it's
         * sending an acknowledge.
         *
         * note: validate that frame length is zero.
         */

        if (0 != frame->length) {
            /*
             * This must he handled as a connection error, we must reply
             * with a FRAME_SIZE_ERROR. ref:
             *
             *  https://httpwg.github.io/specs/rfc7540.html#SETTINGS
             */

            MK_TRACE("SETTINGS ERROR, ACK FRAME WITH NON ZERO SIZE : %i\n", 
                     frame->length);

            return MK_HTTP2_FRAME_SIZE_ERROR;
        }

        h2s->remote_settings.acknowledgement_flag = 1;

        return MK_HTTP2_NO_ERROR;
    }

    setting_entry_list = (struct mk_http2_setting *) frame->raw_payload;

    setting_entry_list_length = \
        mk_http2_frame_size_to_setting_entry_count(frame->length);

    for(setting_entry_list_index = 0,
        setting_entry = &setting_entry_list[0] ;
        setting_entry_list_index < setting_entry_list_length ;
        setting_entry_list_index++,
        setting_entry++) {

       MK_H2_TRACE(conn, "[Setting] Id=%i Value=%i",
                   setting_entry->identifier,
                   setting_entry->value);

       switch (setting_entry->identifier) {
       case MK_HTTP2_SETTINGS_HEADER_TABLE_SIZE:
            h2s->remote_settings.header_table_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_ENABLE_PUSH:
           if (setting_entry->value != 0 && 
               setting_entry->value != 1) {
               MK_H2_TRACE(conn, "INVALID VALUE FOR SETTINGS_ENABLE_PUSH L %i",
                           setting_entry->value);

               return MK_HTTP2_PROTOCOL_ERROR;
           }

           h2s->remote_settings.enable_push = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
           h2s->remote_settings.max_concurrent_streams = setting_entry->value;

           MK_H2_TRACE(conn, "SETTINGS MAX_CONCURRENT_STREAMS=%i",
                       setting_entry->value);

           break;

       case MK_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
           if (MK_HTTP2_MAX_FLOW_CONTROL_WINDOW_SIZE < setting_entry->value) {
               MK_H2_TRACE(conn, "INVALID INITIAL_WINDOW_SIZE : %i",
                           setting_entry->value);

               return MK_HTTP2_FLOW_CONTROL_ERROR;
           }

           h2s->remote_settings.initial_window_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_FRAME_SIZE:
           if (MK_HTTP2_MAX_FRAME_SIZE < setting_entry->value) {
               MK_H2_TRACE(conn, "INVALID SETTINGS_MAX_FRAME_SIZE : %i",
                           setting_entry->value);

               return MK_HTTP2_PROTOCOL_ERROR;
           }

           h2s->remote_settings.max_frame_size = setting_entry->value;

           break;

       case MK_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
           h2s->remote_settings.max_header_list_size = setting_entry->value;

           break;

       default:
           /*
            * 5.5 Extending HTTP/2: ...Implementations MUST ignore unknown
            * or unsupported values in all extensible protocol elements...
            */
           break;
       }
    }

    mk_stream_in_raw(&h2s->stream,
                     NULL,
                     MK_HTTP2_SETTINGS_ACK_FRAME,
                     sizeof(MK_HTTP2_SETTINGS_ACK_FRAME) - 1,
                     NULL, NULL);

    mk_channel_flush(h2s->stream.channel);

    return 0;
}


static inline int mk_http2_frame_run(struct mk_sched_conn *conn,
                                     struct mk_sched_worker *worker,
                                     struct mk_server *server)
{
    int                      result;
    struct mk_http2_stream  *stream;
    struct mk_http2_frame    frame;
    struct mk_http2_session *h2s;

    (void) worker;

    stream = NULL;
    h2s = mk_http2_session_get(conn);

    if (MK_HTTP2_MINIMUM_FRAME_SIZE <= h2s->buffer_length) {
        MK_H2_TRACE(conn, "HTTP/2 SESSION SETTINGS RECEIVED");

        /* Decode the frame header */
        mk_http2_decode_frame_header(h2s->buffer, &frame);

        if (frame.length > h2s->local_settings.max_frame_size) {
            MK_TRACE("[FD %i] Frame size exceeds the one agreed upon", 
                     conn->event.fd);

            mk_http2_error(MK_HTTP2_FRAME_SIZE_ERROR, server);

            return MK_HTTP2_FRAME_ERROR;
        }

        if ((MK_HTTP2_MINIMUM_FRAME_SIZE + frame.length) > h2s->buffer_length) {
            return MK_HTTP2_INCOMPLETE_FRAME; /* We need more data */
        }
    }
    else {
        return MK_HTTP2_INCOMPLETE_FRAME; /* We need more data */
    }

    printf("FRAME TYPE = %d\n", frame.type);
    printf("FRAME DATA\n\n");
    mk_utils_hexdump(frame.raw_payload, frame.length, 16);
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
            stream->dynamic_table_size_limit = h2s->remote_settings.header_table_size;

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
    
    /* All checks passed, time to decode the payload */
    mk_http2_decode_frame_payload(&frame);    

    if (MK_HTTP2_SETTINGS_FRAME == frame.type) {
        result = mk_http2_handle_settings_frame(conn, &frame);

        if (MK_HTTP2_FRAME_PROCESSED == result) {
            if (MK_HTTP2_AWAITING_CLIENT_SETTINGS == h2s->status) {
                h2s->status = MK_HTTP2_AWAITING_CLIENT_FRAMES;
            }
        }
    }
    else if (MK_HTTP2_WINDOW_UPDATE_FRAME == frame.type) {
        result = mk_http2_handle_window_update_frame(conn, &frame);
    }
    else if (MK_HTTP2_HEADERS_FRAME == frame.type) {
        result = mk_http2_handle_headers_frame(conn, &frame, stream);
    }
    else if (MK_HTTP2_CONTINUATION_FRAME == frame.type) {
        result = mk_http2_handle_continuation_frame(conn, &frame);
    }

    buffer_consume(h2s, MK_HTTP2_MINIMUM_FRAME_SIZE + frame.length);

    if (MK_HTTP2_NO_ERROR != result) {
        mk_http2_error(result, server);

        return MK_HTTP2_FRAME_ERROR;
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
        h2s->buffer = h2s->buffer_fixed;
        h2s->buffer_size = MK_HTTP2_CHUNK;
        h2s->buffer_length = 0;

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
            h2s->buffer = mk_mem_alloc(new_size);

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

    printf("h2s->status = %d\n", h2s->status);

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
        frame_result = mk_http2_frame_run(conn, worker, server);
        // frame_result = MK_HTTP2_FRAME_PROCESSED;
    }
    while (MK_HTTP2_FRAME_PROCESSED == frame_result);

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
