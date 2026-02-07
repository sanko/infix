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
 * @file fuzz_abi.c
 * @brief Fuzzer target for the ABI classification layer.
 * @ingroup internal_fuzz
 *
 * @internal
 * This file defines a fuzz target that specifically stresses the ABI classification
 * logic (`prepare_forward_call_frame` and `prepare_reverse_call_frame`). It is
 * designed to be compiled with a fuzzing engine like libFuzzer or AFL.
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * The fuzzer operates by:
 * 1.  **Generating Random Types:** It consumes the raw input data from the fuzzer
 *     to generate a pool of randomized `infix_type` objects using the `generate_random_type`
 *     helper. This produces a wide variety of valid, invalid, and deeply nested
 *     aggregate structures.
 *
 * 2.  **Generating Random Signatures:** It then consumes more data to construct a
 *     random function signature (return type, argument count, and argument types)
 *     by picking types from the generated pool.
 *
 * 3.  **Exercising the ABI Classifier:** Finally, it calls the `prepare_*_call_frame`
 *     functions from the ABI v-table for the current platform, passing them the
 *     randomly generated signature.
 *
 * The goal is to trigger crashes, hangs (timeouts), or memory errors (e.g., as detected
 * by ASan) within the ABI classification code, which is some of the most complex and
 * bug-prone logic in the library. This target does not generate or execute any JIT
 * code; it focuses solely on the analysis and layout phase.
 *
 * @note This fuzzer was instrumental in finding numerous bugs, including infinite
 * loops in the classification of zero-sized arrays, stack overflows from deep
 * recursion, and out-of-bounds reads when classifying malformed aggregates.
 * @endinternal
 */

#include "fuzz_helpers.h"

extern void _infix_clear_error(void);

/**
 * @internal
 * @brief Main fuzzing logic for a single input.
 *
 * This function takes a block of fuzzer-generated data and uses it to construct
 * random types and function signatures, which are then fed into the ABI
 * classification functions to test for robustness and correctness.
 *
 * @param in The fuzzer input data stream.
 */
static void FuzzTest(fuzzer_input in) {
    _infix_clear_error();  // Clear stale context

    infix_type * type_pool[MAX_TYPES_IN_POOL] = {0};
    int type_count = 0;

    // Use a single, large arena for all type generation to simplify cleanup.
    infix_arena_t * type_arena = infix_arena_create(65536);
    if (!type_arena)
        return;

    // Generate a pool of random types based on the input data.
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;
        infix_type * new_type = generate_random_type(type_arena, &in, 0, &total_fields);
        if (new_type)
            type_pool[type_count++] = new_type;
        else
            break;  // Stop if we run out of data or hit a generation limit.
    }

    // We need at least one valid type to proceed.
    if (type_count == 0)
        goto cleanup;

    // Construct a random function signature from the type pool.
    uint8_t arg_count_byte;
    if (consume_uint8_t(&in, &arg_count_byte)) {
        size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;
        uint8_t fixed_arg_byte = 0;
        consume_uint8_t(&in, &fixed_arg_byte);
        size_t num_fixed_args = num_args > 0 ? (fixed_arg_byte % (num_args + 1)) : 0;

        infix_type ** arg_types = (infix_type **)calloc(num_args, sizeof(infix_type *));
        if (!arg_types)
            goto cleanup;

        uint8_t idx_byte = 0;
        consume_uint8_t(&in, &idx_byte);
        infix_type * return_type = type_pool[idx_byte % type_count];

        for (size_t i = 0; i < num_args; ++i)
            arg_types[i] = type_pool[i % type_count];

        // Exercise the ABI classification functions with the random signature.
        // Test the forward call classifier.
        const infix_forward_abi_spec * fwd_spec = get_current_forward_abi_spec();
        if (fwd_spec) {
            infix_arena_t * fwd_arena = infix_arena_create(16384);
            if (fwd_arena) {
                infix_call_frame_layout * layout = NULL;
                // Call it once for an unbound trampoline.
                fwd_spec->prepare_forward_call_frame(
                    fwd_arena, &layout, return_type, arg_types, num_args, num_fixed_args, nullptr);
                // Call it again for a bound trampoline to test both paths.
                fwd_spec->prepare_forward_call_frame(
                    fwd_arena, &layout, return_type, arg_types, num_args, num_fixed_args, (void *)0x1);
                infix_arena_destroy(fwd_arena);
            }
        }

        // Test the reverse call classifier.
        const infix_reverse_abi_spec * rev_spec = get_current_reverse_abi_spec();
        if (rev_spec) {
            // Create a mock context object with the generated signature.
            infix_reverse_t mock_context = {.return_type = return_type,
                                            .arg_types = arg_types,
                                            .num_args = num_args,
                                            .num_fixed_args = num_fixed_args};

            infix_arena_t * rev_arena = infix_arena_create(16384);
            if (rev_arena) {
                infix_reverse_call_frame_layout * rev_layout = NULL;
                rev_spec->prepare_reverse_call_frame(rev_arena, &rev_layout, &mock_context);
                infix_arena_destroy(rev_arena);
            }
        }

        free(arg_types);
    }

cleanup:
    infix_arena_destroy(type_arena);
}

/**
 * @brief The entry point for libFuzzer.
 *
 * This function is called by the libFuzzer runtime for each test case. It wraps
 * the raw input data in a `fuzzer_input` struct and passes it to the main
 * test logic.
 *
 * @param data A pointer to the fuzzer-generated input data.
 * @param size The size of the data.
 * @return 0 on completion.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
