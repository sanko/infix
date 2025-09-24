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
 * @file fuzz_signature.c
 * @brief A libFuzzer-based harness for the infix FFI signature parser.
 *
 * @details This harness is a critical security and stability component for the
 * library. It targets the main entry points of the high-level signature API,
 * which are responsible for parsing arbitrary user-provided strings.
 *
 * The fuzzer's primary goal is to find inputs that cause memory safety violations
 * (buffer overflows, use-after-free, memory leaks), crashes (segmentation faults,
 * assertion failures from integer overflows), or hangs (infinite loops) within
 * the parser logic.
 *
 * ### Fuzzing Targets
 *
 * This harness tests two key public API functions:
 *
 * 1.  **`infix_signature_parse()`**: This function parses a full function signature
 *     (arguments and return type). A successful parse results in a complex graph
 *     of `infix_type` objects allocated within a dedicated memory arena. The test
 *     verifies that if parsing succeeds, the entire arena can be safely destroyed
 *     without leaking memory.
 *
 * 2.  **`infix_type_from_signature()`**: This function parses a string representing
 *     a single data type. It follows the same test-and-destroy pattern as the
 *     full signature parser.
 *
 * By fuzzing both functions, we ensure that all code paths within the
 * recursive-descent parser are exercised with a wide variety of valid, invalid,
 * and malicious inputs. This harness is intended to be compiled with Clang and
 * run with AddressSanitizer (`-fsanitize=address,fuzzer`) to automatically
 * detect memory errors.
 */

#include <infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_helpers.h"

/**
 * @brief The entry point called by the libFuzzer engine for each test case.
 * @details The fuzzer engine repeatedly calls this function, providing a
 * buffer of pseudo-random data. The function treats this data as a potential
 * signature string and feeds it to the target functions. The fuzzer's goal is to
 * find a data input that causes a crash or triggers a sanitizer error.
 *
 * @param data A pointer to the raw byte buffer provided by the fuzzer.
 * @param size The size of the data buffer in bytes.
 * @return An integer, which is unused by libFuzzer but required by the function signature.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    if (size == 0)  // The parser expects a non-empty string.
        return 0;

    // The input data from the fuzzer is not null-terminated. We must create
    // a proper C string from it to safely pass it to our parser.
    char * signature = malloc(size + 1);
    if (!signature)  // If malloc fails, we can't proceed.
        goto cleanup;

    memcpy(signature, data, size);
    signature[size] = '\0';

    // Target 1: The full function signature parser
    // This is the most complex target, as it involves parsing multiple types
    // and handling special separators like `=>` and `;`.
    infix_arena_t * arena = NULL;
    infix_type * ret_type = NULL;
    infix_type ** arg_types = NULL;
    size_t num_args, num_fixed_args;

    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed_args);

    // The core of the test: If parsing was successful, we must prove that we
    // can destroy the resulting arena and all the infix_type objects it contains
    // without any memory errors (leaks, double-frees, etc.).
    if (status == INFIX_SUCCESS)
        infix_arena_destroy(arena);
    else
        goto cleanup;

    // Target 2: The single type signature parser
    // This targets the same underlying parsing logic but through a different
    // entry point, ensuring it handles single types and correctly rejects
    // full function signatures.
    infix_arena_t * type_arena = NULL;
    infix_type * type_only = NULL;
    status = infix_type_from_signature(&type_only, &type_arena, signature);

    // As with the first target, a successful parse must be followed by a clean
    // destruction to pass the test under AddressSanitizer.
    if (status == INFIX_SUCCESS)
        infix_arena_destroy(type_arena);

cleanup:
    // Clean up the temporary string we allocated.
    free(signature);

    // A return value of 0 indicates that this specific input was processed
    // without a crash. The fuzzer continues to generate new inputs.
    return 0;
}
