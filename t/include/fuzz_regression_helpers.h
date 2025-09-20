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
 * @brief Helpers for creating regression tests from fuzzer-discovered inputs.
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/**
 * @internal
 * @brief A robust, self-contained Base64 decoder.
 * @details This function correctly decodes Base64 strings, properly handling
 *          the '=' padding characters. It is used to convert the text-based
 *          crash artifacts from libFuzzer into the raw byte sequences needed
 *          to reproduce a failure.
 *
 *          This implementation is based on a well-known public domain algorithm
 *          to ensure correctness and avoid the bugs present in previous naive
 *          implementations.
 *
 * @param data The null-terminated Base64 string to decode.
 * @param[out] out_len A pointer to a size_t that will receive the length of the
 *                     decoded binary data.
 * @return A dynamically allocated `unsigned char*` buffer containing the decoded
 *         binary data. The caller is responsible for freeing this memory. Returns
 *         `NULL` on allocation failure or if the input string is malformed.
 */
static unsigned char * b64_decode(const char * data, size_t * out_len) {
    static const int b64_decode_table[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

    size_t in_len = strlen(data);
    if (in_len % 4 != 0)
        return NULL;

    *out_len = in_len / 4 * 3;
    if (data[in_len - 1] == '=')
        (*out_len)--;
    if (data[in_len - 2] == '=')
        (*out_len)--;

    unsigned char * out = (unsigned char *)malloc(*out_len);
    if (out == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < in_len;) {
        int sextet_a = b64_decode_table[(unsigned char)data[i++]];
        int sextet_b = b64_decode_table[(unsigned char)data[i++]];
        int sextet_c = b64_decode_table[(unsigned char)data[i++]];
        int sextet_d = b64_decode_table[(unsigned char)data[i++]];

        if (sextet_a == -1 || sextet_b == -1 || (data[i - 2] != '=' && sextet_c == -1) ||
            (data[i - 1] != '=' && sextet_d == -1)) {
            free(out);
            return NULL;
        }

        unsigned int triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        if (j < *out_len)
            out[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *out_len)
            out[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *out_len)
            out[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return out;
}
