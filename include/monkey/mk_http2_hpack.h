#ifndef MK_HTTP2_HPACK_H
#define MK_HTTP2_HPACK_H

#include <monkey/mk_core.h>
#include <monkey/mk_http2.h>
#include <monkey/mk_http2_stream.h>

#define MK_HTTP2_HPACK_HEADER_TABLE_ALLOCATION_ERROR                       -1
#define MK_HTTP2_HPACK_MALFORMED_INTEGER                                   -2
#define MK_HTTP2_HPACK_INVALID_ARGUMENT                                    -3
#define MK_HTTP2_HPACK_INVALID_DYNAMIC_TABLE_INDEX                         -4
#define MK_HTTP2_HPACK_DECOMPRESSION_FAILURE                               -5
#define MK_HTTP2_HPACK_INVALID_STATIC_TABLE_ENTRY                          -6
#define MK_HTTP2_HPACK_MEMORY_ALLOCATION_ISSUE                             -7
#define MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_EXCEEDS_LIMITS                   -8
#define MK_HTTP2_HPACK_INCORRECT_HEADER_TYPE                               -9

#define MK_HTTP2_HPACK_HEADER_COMPRESSION_FLAG                             0x80
#define MK_HTTP2_HPACK_HEADER_STRING_LENGTH_BITS                           7

#define MK_HTTP2_HPACK_INDEXED_HEADER_INDEX_BITS                           7
#define MK_HTTP2_HPACK_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_INDEX_BITS 6
#define MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_MAX_SIZE_BITS             5
#define MK_HTTP2_HPACK_LITERAL_HEADER_WITHOUT_INDEXING_INDEX_BITS          4
#define MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_INDEX_BITS             4

#define MK_HTTP2_HPACK_INDEXED_HEADER_TYPE                                 0x80
#define MK_HTTP2_HPACK_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE       0x40
#define MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_TYPE                      0x20
#define MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_TYPE                   0x10
#define MK_HTTP2_HPACK_LITERAL_HEADER_WITHOUT_INDEXING_TYPE                0x00

#define MK_HTTP2_HPACK_HEADER_STRING_IS_COMPRESSED(x) \
            (MK_HTTP2_HPACK_HEADER_COMPRESSION_FLAG | x)

#define MK_HTTP2_HPACK_IS_HEADER_STRING_COMPRESSED(x) \
            (MK_HTTP2_HPACK_HEADER_COMPRESSION_FLAG == \
                (MK_HTTP2_HPACK_HEADER_COMPRESSION_FLAG & x))

#define MK_HTTP2_HPACK_IS_INDEXED_HEADER(x) \
            (MK_HTTP2_HPACK_INDEXED_HEADER_TYPE == \
                (MK_HTTP2_HPACK_INDEXED_HEADER_TYPE & x))

#define MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING(x) \
            (MK_HTTP2_HPACK_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE == \
                (MK_HTTP2_HPACK_LITERAL_HEADER_WITH_INCREMENTAL_INDEXING_TYPE & x))

#define MK_HTTP2_HPACK_IS_DYNAMIC_TABLE_SIZE_UPDATE(x) \
            (MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_TYPE == \
                (MK_HTTP2_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_TYPE & x))

#define MK_HTTP2_HPACK_IS_LITERAL_HEADER_NEVER_INDEXED(x) \
            (MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_TYPE == \
                (MK_HTTP2_HPACK_LITERAL_HEADER_NEVER_INDEXED_TYPE & x))

#define MK_HTTP2_HPACK_IS_LITERAL_HEADER_WITHOUT_INDEXING(x) \
            (MK_HTTP2_HPACK_LITERAL_HEADER_WITHOUT_INDEXING_TYPE == \
                (MK_HTTP2_HPACK_LITERAL_HEADER_WITHOUT_INDEXING_TYPE & x))

struct mk_http2_header_pair {
    char *name;
    char *value;
};

int mk_http2_hpack_encode_int(uint8_t *dst, int64_t value, unsigned prefix_bits);

int64_t mk_http2_hpack_decode_int(uint8_t *src, 
                                  size_t   src_len, 
                                  size_t  *octet_count, 
                                  unsigned prefix_bits);

int mk_http2_hpack_write_encoded_integer(size_t   *header_buffer_index,
                                         size_t   *header_buffer_remainder,
                                         uint8_t  *header_buffer,
                                         uint8_t   prefix_bits,
                                         int64_t   integer_value);

int mk_http2_hpack_consume_encoded_integer(size_t   *header_buffer_index,
                                           size_t   *header_buffer_remainder,
                                           uint8_t  *header_buffer,
                                           uint8_t   prefix_bits,
                                           int64_t  *integer_value,
                                           uint8_t  *integer_flags);

int mk_http2_hpack_write_header_string(size_t   *header_buffer_index,
                                       size_t   *header_buffer_remainder,
                                       uint8_t  *header_buffer,
                                       uint8_t  *string_buffer,
                                       size_t    string_length,
                                       uint8_t   compression_flag);

int mk_http2_hpack_consume_header_string(size_t   *header_buffer_index,
                                         size_t   *header_buffer_remainder,
                                         uint8_t  *header_buffer,
                                         uint8_t **string_buffer,
                                         size_t   *string_length,
                                         uint8_t  *compression_flag);

int mk_http2_hpack_fetch_entry_index_from_header_table(struct mk_http2_stream *stream,
                                                       char *name, uint32_t *index);

int mk_http2_hpack_fetch_entry_from_header_table(struct mk_http2_stream *stream,
                                                 uint32_t index, char **name, 
                                                 char **value);

int mk_http2_hpack_decompress_header_string(uint8_t **output_buffer, 
                                            size_t *output_length,
                                            uint8_t *input_buffer, 
                                            size_t input_length);

int mk_http2_hpack_decompress_stream_headers(struct mk_http2_session *h2s,
                                             struct mk_http2_stream *stream, 
                                             struct mk_http2_header_table **parsed_headers);

#endif
