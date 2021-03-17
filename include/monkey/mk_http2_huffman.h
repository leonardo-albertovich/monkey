#ifndef MK_HTTP2_HUFFMAN_H
#define MK_HTTP2_HUFFMAN_H

int h2o_hpack_decode_huffman(uint8_t *output_buffer, size_t output_buffer_size, 
                             uint8_t *input_buffer, size_t input_length);

int h2o_hpack_encode_huffman(uint8_t *output_buffer, size_t output_buffer_size, 
                             const char *input_buffer, size_t input_length);

#endif