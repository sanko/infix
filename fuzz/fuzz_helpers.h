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
 * @file fuzz_helpers.h
 * @brief Common definitions, structures, and helpers for all fuzzer targets.
 * @ingroup internal_fuzz
 *
 * @internal
 * This header provides the essential building blocks for the `infix` fuzzing suite.
 * It defines:
 * - **`fuzzer_input`**: A simple struct to manage the fuzzer's raw data stream.
 * - **Consumption Macros/Inlines**: A set of helpers (`consume_uint8_t`, etc.) to
 *   safely read typed data from the input stream.
 * - **Fuzzing Constraints**: Defines constants like `MAX_RECURSION_DEPTH` and
 *   `MAX_TOTAL_FUZZ_FIELDS` to prevent the fuzzers from generating impractically
 *   large or complex inputs, which could lead to timeouts or excessive memory use.
 * - **Function Prototypes**: Declares the main `generate_random_type` function,
 *   which is the core of the structure-aware type generation logic.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <infix/infix.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @brief A hard limit on the recursion depth for `generate_random_type` to prevent stack overflows. */
#define MAX_RECURSION_DEPTH 32
/** @brief A limit on the number of members in a randomly generated struct or union. */
#define MAX_MEMBERS 16
/** @brief A limit on the number of elements in a randomly generated array. */
#define MAX_ARRAY_ELEMENTS 128
/** @brief The number of random types to generate and place in the pool for constructing signatures. */
#define MAX_TYPES_IN_POOL 16
/** @brief A limit on the number of arguments in a randomly generated function signature. */
#define MAX_ARGS_IN_SIGNATURE 16
/** @brief A global limit on the total number of primitive fields in a single generated type graph to prevent timeouts.
 */
#define MAX_TOTAL_FUZZ_FIELDS 256

/**
 * @struct fuzzer_input
 * @brief Represents the fuzzer's input data as a consumable stream.
 */
typedef struct {
    const uint8_t * data; /**< A pointer to the current position in the input data buffer. */
    size_t size;          /**< The number of bytes remaining in the buffer. */
} fuzzer_input;

/**
 * @internal
 * @brief Consumes `n` bytes from the fuzzer input stream.
 *
 * @details This is the fundamental building block for reading data from the fuzzer.
 * It safely checks if enough data is available before advancing the data pointer
 * and decrementing the remaining size.
 *
 * @param in A pointer to the fuzzer input stream.
 * @param n The number of bytes to consume.
 * @return A pointer to the consumed block of bytes, or `NULL` if not enough data is available.
 */
static inline const uint8_t * consume_bytes(fuzzer_input * in, size_t n) {
    if (in->size < n)
        return NULL;
    const uint8_t * ptr = in->data;
    in->data += n;
    in->size -= n;
    return ptr;
}

/**
 * @internal
 * @def DEFINE_CONSUME_T(type)
 * @brief A macro to generate type-safe consumer functions (e.g., `consume_uint8_t`).
 *
 * This macro creates a static inline function `consume_##type` that safely reads
 * a value of the given `type` from the fuzzer input stream.
 */
#define DEFINE_CONSUME_T(type)                                         \
    static inline bool consume_##type(fuzzer_input * in, type * out) { \
        const uint8_t * bytes = consume_bytes(in, sizeof(type));       \
        if (!bytes)                                                    \
            return false;                                              \
        memcpy(out, bytes, sizeof(type));                              \
        return true;                                                   \
    }

// Generate consumer functions for common types used in the fuzzers.
DEFINE_CONSUME_T(uint8_t)
DEFINE_CONSUME_T(size_t)

/**
 * @brief Recursively generates a random `infix_type` graph from a fuzzer input stream.
 *
 * This is the core of the structure-aware type fuzzer. It consumes bytes from the
 * input to probabilistically build a complex, potentially nested type.
 *
 * @param arena The memory arena for allocating the generated types.
 * @param in The fuzzer input stream.
 * @param depth The current recursion depth.
 * @param total_fields A counter for the total number of primitive fields generated.
 * @return A pointer to a newly generated `infix_type`, or `nullptr` on failure.
 */
infix_type * generate_random_type(infix_arena_t * arena, fuzzer_input * in, int depth, size_t * total_fields);
