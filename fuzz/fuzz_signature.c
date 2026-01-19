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
 * parsing functions: `infix_signature_parse`, `infix_type_from_signature`, and
 * the now-growable `infix_register_types`.
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * The strategy has two parts for each input:
 * 1.  **Direct Parsing:** The raw fuzzer input is treated as a C string and fed
 *     directly into `infix_signature_parse` and `infix_type_from_signature`. This
 *     is a "dumb" fuzzing approach that is excellent at finding parser crashes,
 *     hangs, and memory errors from malformed syntax.
 *
 * 2.  **Growable Arena Stress Test:** The fuzzer input is used to construct a very
 *     long, repetitive, but syntactically valid string of type definitions. This
 *     string is then fed to `infix_register_types`. The goal of this test is to
 *     force the registry's internal arena to grow multiple times, stress-testing
 *     the new block-chaining logic to find bugs in the resizing mechanism.
 *
 * The goal is to discover vulnerabilities in the entire "Parse -> Copy -> Resolve -> Layout"
 * pipeline, including parser bugs, memory leaks (via ASan), and hangs from pathological inputs.
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
        return 0;  // Cannot proceed without memory

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
    if (status == INFIX_SUCCESS)
        infix_arena_destroy(arena);

    infix_arena_t * type_arena = NULL;
    infix_type * type_only = NULL;
    status = infix_type_from_signature(&type_only, &type_arena, signature, nullptr);
    if (status == INFIX_SUCCESS)
        infix_arena_destroy(type_arena);

    // Target 2: Stress test the growable registry arena
    if (size > 10) {
        infix_registry_t * registry = infix_registry_create();
        if (registry) {
            // Create a very large definition string to force the arena to resize.
            // Use the fuzzer input to add some variability.
            size_t num_defs = 200 + (data[0] % 200);  // 200-399 definitions
            size_t required_size = num_defs * 64;     // Approximate size
            char * large_def_string = malloc(required_size);
            if (large_def_string) {
                char * p = large_def_string;
                for (size_t i = 0; i < num_defs; ++i) {
                    p += sprintf(p,
                                 "@FuzzType%zu = { a:%c, b:%c, c:%c, d:%c };",
                                 i,
                                 (data[i % size] % 26) + 'a',
                                 (data[(i + 1) % size] % 26) + 'a',
                                 (data[(i + 2) % size] % 26) + 'a',
                                 (data[(i + 3) % size] % 26) + 'a');
                }
                // This call should not crash, even if it runs out of system memory.
                // It stresses the block-chaining logic of the arena.
                if (infix_register_types(registry, large_def_string) != INFIX_SUCCESS) {
                }
                free(large_def_string);
            }
            infix_registry_destroy(registry);
        }
    }
    // We only allocated the signature string, so that's all we need to free.

    free(signature);
    return 0;
}
