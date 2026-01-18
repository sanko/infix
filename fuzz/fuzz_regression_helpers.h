#pragma once
/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */

/**
 * @file fuzz_regression_helpers.h
 * @brief Helper functions specifically for running regression tests from saved fuzzer inputs.
 * @ingroup internal_fuzz
 *
 * @internal
 * This header provides a self-contained Base64 decoding function. Its sole
 * purpose is to allow the regression test suite (`850_regression_cases.c`) to
 * decode hardcoded, Base64-encoded strings that represent fuzzer inputs that
 * previously caused a crash, timeout, or memory error.
 *
 * By embedding these inputs directly into a standard unit test, we can ensure
 * that past bugs do not reappear in future versions of the library. This file
 * is not used by the live fuzzing targets themselves.
 * @endinternal
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * @internal
 * @brief Decodes a Base64-encoded string into a raw byte buffer.
 *
 * @param data The null-terminated, Base64-encoded input string.
 * @param[out] out_len A pointer to a `size_t` that will receive the length of the decoded data.
 * @return A dynamically allocated `unsigned char*` buffer containing the decoded
 *         data. The caller is responsible for freeing this buffer with `free()`.
 *         Returns `NULL` on allocation failure or if the input is not valid Base64.
 */
static unsigned char * infix_b64_decode(const char * data, size_t * out_len) {
    // A standard lookup table for Base64 decoding. -1 represents an invalid character.
    // Size padded to 256 to prevent out-of-bounds access on invalid input.
    static const int infix_b64_decode_table[] = {-1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 62,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 63,
                                                 52,
                                                 53,
                                                 54,
                                                 55,
                                                 56,
                                                 57,
                                                 58,
                                                 59,
                                                 60,
                                                 61,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 0,
                                                 1,
                                                 2,
                                                 3,
                                                 4,
                                                 5,
                                                 6,
                                                 7,
                                                 8,
                                                 9,
                                                 10,
                                                 11,
                                                 12,
                                                 13,
                                                 14,
                                                 15,
                                                 16,
                                                 17,
                                                 18,
                                                 19,
                                                 20,
                                                 21,
                                                 22,
                                                 23,
                                                 24,
                                                 25,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 26,
                                                 27,
                                                 28,
                                                 29,
                                                 30,
                                                 31,
                                                 32,
                                                 33,
                                                 34,
                                                 35,
                                                 36,
                                                 37,
                                                 38,
                                                 39,
                                                 40,
                                                 41,
                                                 42,
                                                 43,
                                                 44,
                                                 45,
                                                 46,
                                                 47,
                                                 48,
                                                 49,
                                                 50,
                                                 51,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 // Padding to 256 elements
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1,
                                                 -1};

    size_t in_len = strlen(data);
    if (in_len % 4 != 0)
        return NULL;  // Base64 strings must have a length that is a multiple of 4.

    // Calculate the output length, accounting for padding characters.
    *out_len = in_len / 4 * 3;
    if (data[in_len - 1] == '=')
        (*out_len)--;
    if (data[in_len - 2] == '=')
        (*out_len)--;

    unsigned char * out = (unsigned char *)malloc(*out_len);
    if (out == NULL)
        return NULL;

    // Process the input string in 4-character chunks.
    for (size_t i = 0, j = 0; i < in_len;) {
        int sextet_a = infix_b64_decode_table[(unsigned char)data[i++]];
        int sextet_b = infix_b64_decode_table[(unsigned char)data[i++]];
        int sextet_c = infix_b64_decode_table[(unsigned char)data[i++]];
        int sextet_d = infix_b64_decode_table[(unsigned char)data[i++]];

        // Validate the characters and handle padding.
        if (sextet_a == -1 || sextet_b == -1 || (data[i - 2] != '=' && sextet_c == -1) ||
            (data[i - 1] != '=' && sextet_d == -1)) {
            free(out);
            return NULL;
        }

        // Combine the four 6-bit sextets into a 24-bit triple.
        unsigned int triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        // Extract the three 8-bit bytes from the triple.
        if (j < *out_len)
            out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *out_len)
            out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *out_len)
            out[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return out;
}
