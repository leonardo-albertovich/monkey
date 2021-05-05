#include <monkey/mk_core.h>
#include <monkey/mk_http2.h>
#include <monkey/mk_http2_hpack.h>
#include <monkey/mk_http2_stream.h>
#include <monkey/mk_http2_huffman.h>
#include <monkey/mk_http2_header_table.h>
#include <monkey/mk_http2_dynamic_table.h>

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

/* HPACK integer and string primitives */

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

        for (; value >= 128 ; value >>= 7) {
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

int mk_http2_hpack_write_encoded_integer(size_t   *header_buffer_index,
                                         size_t   *header_buffer_remainder,
                                         uint8_t  *header_buffer,
                                         uint8_t   prefix_bits,
                                         int64_t   integer_value)
{
    size_t  octet_count;

    octet_count = (size_t) mk_http2_hpack_encode_int(&header_buffer[*header_buffer_index], 
                                                     integer_value, 
                                                     prefix_bits);

    *header_buffer_index += octet_count;
    *header_buffer_remainder -= octet_count;

    return octet_count;
}

int mk_http2_hpack_consume_encoded_integer(size_t   *header_buffer_index,
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

int mk_http2_hpack_write_header_string(size_t   *header_buffer_index,
                                       size_t   *header_buffer_remainder,
                                       uint8_t  *header_buffer,
                                       uint8_t  *string_buffer,
                                       size_t    string_length,
                                       uint8_t   compression_flag)
{
    size_t octet_count;

    octet_count = mk_http2_hpack_write_encoded_integer(header_buffer_index,
                                                       header_buffer_remainder,
                                                       header_buffer,
                                                       MK_HTTP2_HPACK_HEADER_STRING_LENGTH_BITS,
                                                       string_length);

    if (0 != compression_flag) {
        header_buffer[*header_buffer_index - octet_count] = \
            MK_HTTP2_HPACK_HEADER_STRING_IS_COMPRESSED(header_buffer[*header_buffer_index - octet_count]);
    }

    memcpy(&header_buffer[*header_buffer_index], string_buffer, string_length);

    *header_buffer_index += string_length;
    *header_buffer_remainder -= string_length;

    return 0;
}

int mk_http2_hpack_consume_header_string(size_t   *header_buffer_index,
                                         size_t   *header_buffer_remainder,
                                         uint8_t  *header_buffer,
                                         uint8_t **string_buffer,
                                         size_t   *string_length,
                                         uint8_t  *compression_flag)
{
    size_t octet_count;

    *compression_flag = MK_HTTP2_HPACK_IS_HEADER_STRING_COMPRESSED(
                            header_buffer[*header_buffer_index]);

    *string_length = mk_http2_hpack_decode_int(&header_buffer[*header_buffer_index], 
                                               *header_buffer_remainder, 
                                               &octet_count, 
                                               MK_HTTP2_HPACK_HEADER_STRING_LENGTH_BITS);

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

/* HPACK integer and string primitives */

int mk_http2_hpack_fetch_entry_index_from_header_table(struct mk_http2_stream *stream,
                                                       char *name, uint32_t *index)
{
    size_t                               static_table_length;
    struct mk_http2_dynamic_table_entry *dynamic_table_entry;
    uint32_t                             local_index;

    if(NULL == name) {
        return -2;
    }

    if(NULL == index) {
        return -3;
    }

    static_table_length = sizeof(mk_http2_static_table) / 
                          sizeof(struct mk_http2_header_pair);


    for (local_index = 0 ; local_index < static_table_length ; local_index++) {
        if (NULL != mk_http2_static_table[local_index].name) {
            if (0 == strcasecmp(mk_http2_static_table[local_index].name, name)) {
                *index = local_index;

                return 0;
            }
        }
    }

    dynamic_table_entry = mk_http2_dynamic_table_entry_get_by_name(stream->dynamic_table, 
                                                                   name);

    if(NULL == dynamic_table_entry) {
        return -1;
    }

    *index = dynamic_table_entry->id;

    return 0;
}

int mk_http2_hpack_fetch_entry_from_header_table(struct mk_http2_stream *stream,
                                                 uint32_t index, char **name, 
                                                 char **value)
{
    size_t                               static_table_length;
    struct mk_http2_dynamic_table_entry *dynamic_table_entry;

    if(NULL == name) {
        return -2;
    }

    if(NULL == value) {
        return -3;
    }

    if(1 > index) {
        return -4;
    }

    static_table_length = sizeof(mk_http2_static_table) / 
                          sizeof(struct mk_http2_header_pair);

    if(static_table_length > index) {
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

int mk_http2_hpack_decompress_header_string(uint8_t **output_buffer, 
                                            size_t *output_length,
                                            uint8_t *input_buffer, 
                                            size_t input_length)
{
    int      output_buffer_allocated;
    uint8_t *real_output_buffer;
    int      result;

    if(NULL == output_buffer) {
        return -1; /* A place to save the output buffer address is mandatory */
    }

    if(NULL == output_length) {
        return -2; /* A place to save the output buffer length is mandatory */
    }

    if(NULL == *output_buffer) {
        if(0 == input_length) {
            printf("%s:%d\n", __FILE__, __LINE__);

            return -3; /* Bogus input length, decompression won't work either */
        }

        /* TODO : Find out the meximum compression ratio for the huffman variation 
         *        implemented and determine if we want to use the stack for this or not
         *        which depends on the maximum expected size and minimum expected
         *        hardware specifications or add a fallback mechanism using a session
         *        buffer for larger payloads (what's the limit here?) 
        */

        *output_buffer = alloca(input_length * 10);

        if(NULL == *output_buffer) {
            return -4; /* Memory allocation error, bad stuff is going to happen */
        }

        *output_length = input_length * 10;

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

            *output_buffer = NULL;
            *output_length = 0;
        }

        return -5;
    }

    if(1 == output_buffer_allocated) {
        /* We allocate one additional byte to act as NULL terminator for strings, 
         * it is however, not counted in the output_length output parameter
         */

        real_output_buffer = mk_mem_alloc_z(result + 1);

        if(NULL == real_output_buffer) {
            *output_buffer = NULL;
            *output_length = 0;        

            return -6;            
        }

        memset(real_output_buffer, 0, result + 1);
        memcpy(real_output_buffer, *output_buffer, result);

        *output_buffer = real_output_buffer;
    }

    *output_length = (size_t) result;

    return 0;
}

int mk_http2_hpack_compress_stream_headers(struct mk_http2_session *h2s,
                                           struct mk_http2_stream *stream, 
                                           struct mk_http2_header_table *headers,
                                           uint8_t **compressed_header_buffer,
                                           size_t *compressed_header_buffer_length)
{
    struct mk_http2_header_table_entry *entry;
    struct mk_list *head;
    size_t required_size;
    uint8_t *output_buffer;
    size_t previous_output_buffer_index;
    size_t output_buffer_index;
    size_t output_buffer_remainder;
    uint32_t header_index;
    int result;
    char *table_header_name;
    char *table_header_value;

    (void) h2s;

    required_size = 0;

    mk_list_foreach(head, &headers->entries) {
        entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);

        required_size += 1;
        required_size += 4 + strlen(entry->name);
        required_size += 4 + strlen(entry->value);

        /* 4 additional bytes per string means the length integer can take up to 32 bits
         * which is obviously not realistic but this whole function is a crutch
         *
         * NOTE : we're allocating enough for the worst case scenario (once again, crutch!)
        */
    }

    output_buffer = mk_mem_alloc_z(required_size);

    if (NULL == output_buffer) {
        return -1; /* memory allocation error, we're in trouble */
    }

    output_buffer_index = 0;
    output_buffer_remainder = required_size;

    mk_list_foreach(head, &headers->entries) {
        entry = mk_list_entry(head, struct mk_http2_header_table_entry, _head);

        // printf("ENCODING [%s] - [%s] @ %d\n", entry->name, entry->value, output_buffer_index);

        result = mk_http2_hpack_fetch_entry_index_from_header_table(stream, entry->name, 
                                                                    &header_index);

        if (0 == result) {
            result = mk_http2_hpack_fetch_entry_from_header_table(stream, header_index, 
                                                                  &table_header_name, 
                                                                  &table_header_value);
        }

        if (0 == result) {
            if (NULL != table_header_name &&
                NULL != table_header_value) {
                if (0 == strcasecmp(entry->value, table_header_value)) {
                    previous_output_buffer_index = output_buffer_index;

                    mk_http2_hpack_write_encoded_integer(&output_buffer_index,
                                                         &output_buffer_remainder,
                                                         output_buffer,
                                                         MK_HTTP2_HPACK_INDEXED_HEADER_INDEX_BITS,
                                                         header_index);

                    output_buffer[previous_output_buffer_index] |= MK_HTTP2_HPACK_INDEXED_HEADER_TYPE;

                }
            }
            else {
                previous_output_buffer_index = output_buffer_index;

                mk_http2_hpack_write_encoded_integer(&output_buffer_index,
                                                     &output_buffer_remainder,
                                                     output_buffer,
                                                     MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_INDEX_BITS,
                                                     header_index);

                output_buffer[previous_output_buffer_index] |= MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_TYPE;

                mk_http2_hpack_write_header_string(&output_buffer_index,
                                                   &output_buffer_remainder,
                                                   output_buffer,
                                                   (uint8_t *)entry->value,
                                                   strlen(entry->value),
                                                   0);
            }
        }
        else {
            previous_output_buffer_index = output_buffer_index;

            mk_http2_hpack_write_encoded_integer(&output_buffer_index,
                                                 &output_buffer_remainder,
                                                 output_buffer,
                                                 MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_INDEX_BITS,
                                                 0);

            output_buffer[previous_output_buffer_index] |= MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_TYPE;

            mk_http2_hpack_write_header_string(&output_buffer_index,
                                               &output_buffer_remainder,
                                               output_buffer,
                                               (uint8_t *)entry->name,
                                               strlen(entry->name),
                                               0);

            mk_http2_hpack_write_header_string(&output_buffer_index,
                                               &output_buffer_remainder,
                                               output_buffer,
                                               (uint8_t *)entry->value,
                                               strlen(entry->value),
                                               0);
        }
    }

    *compressed_header_buffer = output_buffer;
    *compressed_header_buffer_length = output_buffer_index;

    return 0;
}

/*
{
    int ress;

    size_t   header_buffer_index = 0;
    size_t   header_buffer_remainder = 1024;
    uint8_t  header_buffer[1024];
    uint8_t  string_buffer[256];
    size_t   string_length;
    uint8_t  compression_flag = 1;

    memset(header_buffer, 0, sizeof(header_buffer));
 
    strcpy(string_buffer, "test!");
    string_length = 5;

    ress = mk_http2_hpack_write_header_string(&header_buffer_index,
                                              &header_buffer_remainder,
                                              header_buffer,
                                              string_buffer,
                                              string_length,
                                              compression_flag);
    strcpy(string_buffer, "casa perro 123");
    string_length = 14;

    ress = mk_http2_hpack_write_header_string(&header_buffer_index,
                                              &header_buffer_remainder,
                                              header_buffer,
                                              string_buffer,
                                              string_length,
                                              compression_flag);

    printf("RESS = %d\n\n", ress);

    printf("\n\n");

    mk_utils_hexdump(header_buffer, 32, 16);

    printf("\n\n");

    exit(0);
}
*/

int mk_http2_hpack_decompress_stream_headers(struct mk_http2_session *h2s,
                                             struct mk_http2_stream *stream, 
                                             struct mk_http2_header_table **parsed_headers)
{
    size_t                        header_buffer_index;
    size_t                        header_buffer_remainder;
    uint8_t                      *header_buffer;
    uint8_t                       header_type;
    char                         *header_name;
    size_t                        header_name_length;
    uint8_t                       header_name_compression_flag;
    char                         *header_value;
    size_t                        header_value_length;
    uint8_t                       header_value_compression_flag;
    int64_t                       integer_value;
    uint8_t                       integer_flags;
    struct mk_http2_header_table *headers;
    int                           result;
    int64_t                       index;
    int64_t                       index_bit_prefix_length;
    int                           fatal_error_encountered;
    uint8_t                      *decompresion_output_buffer;
    size_t                        decompresion_output_buffer_length;

    // printf("LEN [%lu]\n", stream->header_buffer_length);

    header_buffer = stream->header_buffer;
    header_buffer_remainder = stream->header_buffer_length;

    headers = mk_http2_header_table_create();

    if (NULL == headers) {
        return MK_HTTP2_HPACK_HEADER_TABLE_ALLOCATION_ERROR;
    }

    fatal_error_encountered = 0;

    for (header_buffer_index = 0 ; header_buffer_index < stream->header_buffer_length ; ) {
        header_type = header_buffer[header_buffer_index];

        if (MK_HTTP2_HPACK_IS_INDEXED_HEADER(header_type)) {
            result = mk_http2_hpack_consume_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_HPACK_INDEXED_HEADER_INDEX_BITS,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                /* Malformed integer */

                fatal_error_encountered = MK_HTTP2_HPACK_MALFORMED_INTEGER;

                break;
            }

            index = integer_value;

            // printf("HPACK indexed header : %lu\n", index);

            result = mk_http2_hpack_fetch_entry_from_header_table(stream, 
                                                                  index,
                                                                  &header_name, 
                                                                  &header_value);

            if (-1 > result) {
                /* Invalid argument passed to mk_http2_hpack_fetch_entry_from_header_table */

                fatal_error_encountered = MK_HTTP2_HPACK_INVALID_ARGUMENT;

                break;
            }
            else if (0 > result) {
                /* Entry not found in dynamic table */

                fatal_error_encountered = MK_HTTP2_HPACK_INVALID_DYNAMIC_TABLE_INDEX;

                break;
            }

            // printf("NAME  : [%s]\n"
            //        "VALUE : [%s]\n", 
            //         header_name,
            //         header_value);

            mk_http2_header_table_entry_create(headers, header_name, strlen(header_name), 
                                               header_value, strlen(header_value));
        }
        else if (MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(header_type) ||
                 MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITHOUT_INDEXING(header_type) ||
                 MK_HTTP2_HPACK_IS_LITERAL_HEADER_NEVER_INDEXED(header_type)) {

            if (MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(header_type)) {
                index_bit_prefix_length = \
                    MK_HTTP2_HPACK_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_INDEX_BITS;
                // printf("HPACK literal header with incremental indexing : ");
            }
            else if (MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITHOUT_INDEXING(header_type)) {
                index_bit_prefix_length = \
                    MK_HTTP2_HPACK_LITERAL_HEADER_WITHOUT_INDEXING_INDEX_BITS;
                // printf("HPACK literal header without incremental indexing : ");
            }
            else if (MK_HTTP2_HPACK_IS_LITERAL_HEADER_NEVER_INDEXED(header_type)) {
                index_bit_prefix_length = \
                    MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_INDEX_BITS;
                // printf("HPACK literal header never indexed : ");
            }

            result = mk_http2_hpack_consume_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        index_bit_prefix_length,
                        &integer_value,
                        &integer_flags);

            if (0 != result) {
                /* Malformed integer */

                fatal_error_encountered = MK_HTTP2_HPACK_MALFORMED_INTEGER;

                break;
            }

            index = integer_value;

            // printf("%lu\n", index);

            if(0 == index) { 
                /* Header name is literal */

                result = mk_http2_hpack_consume_header_string(&header_buffer_index,
                                                              &header_buffer_remainder,
                                                              header_buffer,
                                                  (uint8_t **)&header_name,
                                                              &header_name_length,
                                                              &header_name_compression_flag);

                if(0 != result) {
                    /* Malformed integer used as length */

                    fatal_error_encountered = MK_HTTP2_HPACK_MALFORMED_INTEGER;

                    break;
                }

                if(1 == header_name_compression_flag) {
                    decompresion_output_buffer = NULL;
                    decompresion_output_buffer_length = 0;

                    result = mk_http2_hpack_decompress_header_string(
                                &decompresion_output_buffer, 
                                &decompresion_output_buffer_length, 
                                (uint8_t *)header_name, 
                                header_name_length);

                    if(0 != result) {
                        /* Decompression failure */

                        fatal_error_encountered = MK_HTTP2_HPACK_DECOMPRESSION_FAILURE;

                        break;
                    }

                    header_name = (char *) decompresion_output_buffer;
                    header_name_length = decompresion_output_buffer_length;
                }
            }
            else {
                /* header name is indexed */

                header_name_compression_flag = 0;

                result = mk_http2_hpack_fetch_entry_from_header_table(stream, index,
                                                                      &header_name,
                                                                      &header_value);

                if (result < -1) {
                    /* Invalid argument passed to mk_http2_hpack_fetch_entry_from_header_table */

                    fatal_error_encountered = MK_HTTP2_HPACK_INVALID_ARGUMENT;

                    break;
                }
                else if (result < 0) {
                    /* Entry not found in dynamic table */

                    fatal_error_encountered = MK_HTTP2_HPACK_INVALID_DYNAMIC_TABLE_INDEX;

                    break;
                }

                if (NULL == header_name) {
                    /* The header name cannot be NULL in this case */

                    fatal_error_encountered = MK_HTTP2_HPACK_INVALID_STATIC_TABLE_ENTRY;

                    break;
                }

                header_name_length = strlen(header_name);
            }

            result = mk_http2_hpack_consume_header_string(&header_buffer_index,
                                                          &header_buffer_remainder,
                                                          header_buffer,
                                              (uint8_t **)&header_value,
                                                          &header_value_length,
                                                          &header_value_compression_flag);

            if (0 != result) {
                /* Malformed integer used as length */

                fatal_error_encountered = MK_HTTP2_HPACK_MALFORMED_INTEGER;

                break;
            }


            if (1 == header_value_compression_flag) {
                decompresion_output_buffer = NULL;
                decompresion_output_buffer_length = 0;

                result = mk_http2_hpack_decompress_header_string(
                            &decompresion_output_buffer, 
                            &decompresion_output_buffer_length, 
                            (uint8_t *)header_value, 
                            header_value_length);

                if (0 != result) {
                    /* Decompression error */

                    fatal_error_encountered = MK_HTTP2_HPACK_DECOMPRESSION_FAILURE;

                    break;
                }

                header_value = (char *) decompresion_output_buffer;
                header_value_length = decompresion_output_buffer_length;
            }

            // printf("NAME COMPRESSED?  : %d\n", header_name_compression_flag);
            // printf("VALUE COMPRESSED? : %d\n", header_value_compression_flag);

            // printf("NAME  : [%.*s]\n", (int) header_name_length, header_name);
            // printf("NAMEl : [%lu]\n", header_name_length);
            // printf("VALUE : [%.*s]\n", (int) header_value_length, header_value);
            // printf("VALUEl: [%lu]\n", header_value_length);

            /* Yes, we're treating them as NULL terminated strings here,
             * in order to do that the decompression routine allocates one additional
             * byte for the string terminator which is not accounted for (wouldn't affect
             * binary contents)
            */

            /* TODO : VERY IMPORTANT!
             *        According to https://tools.ietf.org/html/rfc7540#section-8.1.2.5
             *        cookie management requires for individual cookie headers to be 
             *        manually joined into a single buffer even if they are sent as 
             *        individual headers because that's how it's done not to ruin the
             *        compression ratio.
             *        If left as it is this code will completely break that.!
            */
            #warning "Cookie processing logic needs to be added!"

            mk_http2_header_table_entry_create(headers, header_name, header_name_length, 
                                               header_value, header_value_length);

            if (MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(header_type)) {
                result = mk_http2_dynamic_table_entry_create(stream->dynamic_table, 
                                                             header_name, 
                                                             header_name_length,
                                                             header_value,
                                                             header_value_length);

                if (-1 > result) {
                    /* Memory allocation issue */

                    fatal_error_encountered = MK_HTTP2_HPACK_MEMORY_ALLOCATION_ISSUE;

                    break;
                }
            }

            if(header_name_compression_flag) {
                mk_mem_free(header_name);
            }

            if(header_value_compression_flag) {
                mk_mem_free(header_value);
            }
        }
        else if (MK_HTTP2_HPACK_IS_DYNAMIC_TABLE_SIZE_UPDATE(header_type)) {
            result = mk_http2_hpack_consume_encoded_integer(
                        &header_buffer_index,
                        &header_buffer_remainder,
                        header_buffer,
                        MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_MAX_SIZE_BITS,
                        &integer_value,
                        &integer_flags);

            if(0 != result) {
                /* Malformed integer used as new table size */

                fatal_error_encountered = MK_HTTP2_HPACK_MALFORMED_INTEGER;

                break;
            }

            if (h2s->local_settings.max_header_list_size < integer_value) {
                /* The new table size exceeds the maximum size we chose */

                fatal_error_encountered = MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_EXCEEDS_LIMITS;

                break;
            }

            // printf("HPACK dynamic table size update %lu\n", integer_value);

            mk_http2_dynamic_table_set_size_limit(stream->dynamic_table, integer_value);
        }
        else {
            fatal_error_encountered = MK_HTTP2_HPACK_INCORRECT_HEADER_TYPE;

            break;
        }
    }

    if (0 != fatal_error_encountered) {
        if (NULL != headers) {
            mk_http2_header_table_destroy(headers);

            headers = NULL;
        }

        return fatal_error_encountered;
    }

    *parsed_headers = headers;

    return 0;   
}

