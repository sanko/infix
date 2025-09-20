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
 * @brief Shared helper functions and types for infix FFI fuzzing harnesses.
 *
 * @details This header provides the common infrastructure needed to build fuzzers
 * for the infix library, including a structure for managing fuzzer input and
 * a powerful recursive generator for creating complex, randomized `ffi_type` objects.
 * By centralizing this logic, individual fuzzing harnesses can be kept clean and
 * focused on their specific targets.
 */

#include <infix.h>
#include <infix_internals.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Configuration Constants
// These values control the complexity and depth of the generated types to
// prevent excessively long or deep recursion, which could slow down fuzzing.
#define MAX_RECURSION_DEPTH 32
#define MAX_MEMBERS 16
#define MAX_ARRAY_ELEMENTS 128
#define MAX_TYPES_IN_POOL 16
#define MAX_ARGS_IN_SIGNATURE 16
#define MAX_TOTAL_FUZZ_FIELDS 256  // Prevents DoS in the generator itself.

// Fuzzer Input Management

/**
 * @struct fuzzer_input
 * @brief A helper structure to safely consume bytes from the fuzzer's input buffer.
 */
typedef struct {
    const uint8_t * data;
    size_t size;
} fuzzer_input;

/**
 * @brief Safely consume 'n' bytes from the input buffer.
 * @details This is a security-critical helper. It checks if enough data is available
 * before advancing the pointer, preventing the fuzzer from reading out of bounds.
 *
 * @param in A pointer to the fuzzer_input struct.
 * @param n The number of bytes to consume.
 * @return A pointer to the consumed bytes, or NULL if insufficient data.
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
 * @def DEFINE_CONSUME_T(type)
 * @brief A macro to create a type-safe consumer for any given Plain Old Data (POD) type.
 * @details This macro generates a static inline function `consume_<type>()` that safely
 * reads bytes from the fuzzer input and copies them into the provided output variable.
 */
#define DEFINE_CONSUME_T(type)                                         \
    static inline bool consume_##type(fuzzer_input * in, type * out) { \
        const uint8_t * bytes = consume_bytes(in, sizeof(type));       \
        if (!bytes)                                                    \
            return false;                                              \
        memcpy(out, bytes, sizeof(type));                              \
        return true;                                                   \
    }

// Define consumer functions for the primitive types needed by the harnesses.
DEFINE_CONSUME_T(uint8_t)
DEFINE_CONSUME_T(size_t)

// Complex Type Generation

/**
 * @brief Recursively generates a randomized ffi_type from the fuzzer's input data.
 *
 * @details This is the core generator used by all harnesses. It can create simple
 * primitives or deeply-nested aggregate types (structs, unions, arrays). It is
 * responsible for its own memory management: if it returns a non-NULL `ffi_type`,
 * the caller owns that type and must eventually call `ffi_type_destroy` on it. If
 * it returns NULL, all intermediate memory will have been cleaned up correctly.
 *
 * @param in A pointer to the fuzzer input buffer.
 * @param depth The current recursion depth (used to prevent stack overflows).
 * @param total_fields [in,out] A pointer to a counter for the total fields generated for this one type.
 * @return A new, dynamically-allocated `ffi_type*`, or NULL on failure or if data runs out.
 */
ffi_type * generate_random_type(fuzzer_input * in, int depth, size_t * total_fields);
