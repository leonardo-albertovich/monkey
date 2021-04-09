/*
This code is a very slightly refactored version of : 
https://github.com/h2o/h2o/blob/master/lib/http2/hpack.c

I don't even claim to properly understand the design, the changes are limited to the
style and behavior in terms of verification offloading and error reporting
*/

#define _GNU_SOURCE

#include <inttypes.h>

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_huffman.h>
#include <monkey/mk_http2_huffman_table.h>


static uint8_t *huffdecode4(uint8_t *output_buffer, size_t *output_length, 
                            uint8_t input_nibble, 
                            uint8_t *state, int *maybe_eos)
{
    const nghttp2_huff_decode *entry;

    entry = huff_decode_table[*state] + input_nibble;

    if ((entry->flags & NGHTTP2_HUFF_FAIL) != 0) {
        return NULL;
    }

    if ((entry->flags & NGHTTP2_HUFF_SYM) != 0) {
        *output_buffer++ = entry->sym;
        *output_length += 1;
    }

    *state = entry->state;
    *maybe_eos = (0 != (entry->flags & NGHTTP2_HUFF_ACCEPTED));

    return output_buffer;
}

int h2o_hpack_decode_huffman(uint8_t *output_buffer, size_t output_buffer_size, 
                             uint8_t *input_buffer, size_t input_length)
{
    size_t   output_length;
    int      eos_detected;
    size_t   input_index;
    uint8_t  state;

    output_length = 0;
    eos_detected = 1;
    state = 0;

    for (input_index = 0 ; input_index < input_length ; input_index++) {
        if(output_length >= output_buffer_size) {
            return -1;
        }

        output_buffer = huffdecode4(output_buffer, &output_length, input_buffer[input_index] >> 4, 
                                    &state, &eos_detected);

        if (NULL == output_buffer) {
            return -2;
        }

        if(output_length >= output_buffer_size) {
            return -1;
        }

        output_buffer = huffdecode4(output_buffer, &output_length, input_buffer[input_index] & 0xf, 
                                    &state, &eos_detected);

        if (NULL == output_buffer) {
            return -3;
        }
    }

    if (0 == eos_detected) {
        return -4;
    }

    return (int) output_length;
}


int h2o_hpack_encode_huffman(uint8_t *output_buffer, size_t output_buffer_size, 
                             const char *input_buffer, size_t input_length)
{
    size_t                  output_length;
    size_t                  output_index;
    size_t                  input_index;
    int                     bits_left; /* If so, do we need to consider embedded platforms? */
    uint64_t                bits;      /* Does this need to be 64 bit wide? */
    const nghttp2_huff_sym *sym;

    bits = 0;
    bits_left = 40;

    output_index = 0;
    output_length = 0;

    for(input_index = 0 ; input_index < input_length ; input_index++) {
        if (output_buffer_size == output_length) {
            /* This shouldn't be needed but we do it just in case,
             * the idea is to check the output buffer size before writing
             * and it's done before writting rather than after incrementing
             * to be able to skip the verification at the start of the function
            */
            return -3;
        }

        sym = &huff_sym_table[(size_t)input_buffer[input_index]];

        bits |= (uint64_t) sym->code << (bits_left - sym->nbits);
        bits_left -= sym->nbits;

        while (32 >= bits_left) {
            output_buffer[output_index] = bits >> 32;

            bits <<= 8;
            bits_left += 8;
            
            if (output_length == input_length) {
                return -1;
            }

            output_index++;
            output_length++;
        }
    }

    if (bits_left != 40) {
        if (output_buffer_size == output_length) {
            return -3;
        }

        bits |= ((uint64_t)1 << bits_left) - 1;

        output_buffer[output_index] = bits >> 32;

        output_index++;
        output_length++;
    }

    if (output_length == input_length) {
        return -2;
    }

    return (int) output_length;
}
