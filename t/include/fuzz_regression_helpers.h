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
 * @brief A simple Base64 decoder to make regression tests self-contained.
 * @details This function is used to decode the Base64-encoded crash/timeout
 *          inputs provided by the libFuzzer engine. This allows us to store the
 *          raw, potentially non-printable byte sequences as simple C strings
 *          within the regression test file, making it self-contained and easy
 *          to manage without checking in binary artifact files.
 * @param data The null-terminated Base64 string to decode.
 * @param[out] out_len A pointer to a size_t that will receive the length of the
 *                     decoded binary data.
 * @return A dynamically allocated `unsigned char*` buffer containing the decoded
 *         binary data. The caller is responsible for freeing this memory. Returns
 *         `NULL` on allocation failure or if the input string is malformed.
 */
static unsigned char * b64_decode(const char * data, size_t * out_len) {
    // A mapping from an ASCII character to its 6-bit value.
    // Invalid characters are mapped to 0. '=' is mapped to -1 for special handling.
    static const int b64_index[256] = {
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 0,  0,  0,  63, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 0,  0,  0,  -1, 0,  0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  0,  0,  26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0,
    };

    size_t len = strlen(data);
    if (len % 4 != 0)
        return NULL;  // Input must be a multiple of 4

    // Calculate the output length, accounting for padding.
    *out_len = len / 4 * 3;
    if (data[len - 1] == '=')
        (*out_len)--;
    if (data[len - 2] == '=')
        (*out_len)--;

    unsigned char * decoded = (unsigned char *)malloc(*out_len);
    if (!decoded)
        return NULL;

    // Process the string in 4-character chunks.
    for (size_t i = 0, j = 0; i < len; i += 4) {
        // Look up the 6-bit value for each character in the chunk.
        int sextet_a = b64_index[(int)data[i]];
        int sextet_b = b64_index[(int)data[i + 1]];
        // Handle padding characters for the last two sextets correctly.
        int sextet_c = (data[i + 2] == '=') ? 0 : b64_index[(int)data[i + 2]];
        int sextet_d = (data[i + 3] == '=') ? 0 : b64_index[(int)data[i + 3]];

        // Combine the four 6-bit sextets into a 24-bit triple.
        unsigned int triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        // Extract the three 8-bit bytes from the triple, respecting the calculated output length.
        if (j < *out_len)
            decoded[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len)
            decoded[j++] = (triple >> 8) & 0xFF;
        if (j < *out_len)
            decoded[j++] = triple & 0xFF;
    }
    return decoded;
}
