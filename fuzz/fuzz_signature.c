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
 * @brief Fuzzer target for the high-level signature parsing API.
 * @ingroup internal_fuzz
 *
 * @internal
 * This file defines a fuzz target that focuses on the public-facing signature
 * parsing functions: `infix_signature_parse` and `infix_type_from_signature`.
 * It is designed to be compiled with a fuzzing engine like libFuzzer or AFL.
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * The strategy is straightforward but effective:
 * 1.  Take the raw, unmodified input data from the fuzzer.
 * 2.  Treat this data as a null-terminated C string.
 * 3.  Feed this string directly into `infix_signature_parse` and
 *     `infix_type_from_signature`.
 *
 * The goal is to discover security vulnerabilities and stability issues within the
 * entire "Parse -> Copy -> Resolve -> Layout" pipeline that these high-level
 * functions orchestrate. This includes:
 * - **Parser Crashes:** Invalid syntax causing segmentation faults or other crashes.
 * - **Memory Errors:** Buffer overflows, use-after-free, or memory leaks detected by ASan.
 * - **Hangs/Timeouts:** Pathological inputs that cause excessive recursion or looping
 *   in any stage of the pipeline.
 * - **Incorrect Error Handling:** Situations where the library fails to return an
 *   error status for a clearly invalid signature.
 *
 * This fuzzer complements the other targets by testing the full, integrated system
 * from the user's perspective, whereas other fuzzers might focus on specific internal
 * components like the ABI classifier or the type generator in isolation.
 * @endinternal
 */

#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_helpers.h"

/**
 * @brief The entry point for libFuzzer.
 *
 * This function is called by the libFuzzer runtime for each test case. It takes
 * the raw fuzzer data, treats it as a signature string, and passes it to the
 * main `infix` parsing APIs.
 *
 * @param data A pointer to the fuzzer-generated input data.
 * @param size The size of the data.
 * @return 0 on completion.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    if (size == 0)
        return 0;

    // Allocate a buffer and copy the fuzzer data, then null-terminate it to
    // create a valid C string.
    char * signature = malloc(size + 1);
    if (!signature)
        goto cleanup;

    memcpy(signature, data, size);
    signature[size] = '\0';

    // Target 1: Full Function Signature Parsing
    infix_arena_t * arena = NULL;
    infix_type * ret_type = NULL;
    infix_function_argument * args = NULL;
    size_t num_args, num_fixed_args;

    // Call the high-level API that handles the full "Parse->Copy->Resolve->Layout" pipeline.
    infix_status status =
        infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed_args, nullptr);

    // If parsing succeeds, we must clean up the resources that were allocated.
    // If it fails, the function is responsible for its own cleanup.
    if (status == INFIX_SUCCESS) {
        infix_arena_destroy(arena);

        // Target 2: Single Type Signature Parsing
        infix_arena_t * type_arena = NULL;
        infix_type * type_only = NULL;
        status = infix_type_from_signature(&type_only, &type_arena, signature, nullptr);

        if (status == INFIX_SUCCESS)
            infix_arena_destroy(type_arena);
    }
cleanup:
    // We only allocated the signature string, so that's all we need to free.
    free(signature);

    return 0;
}
