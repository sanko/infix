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
 * @brief A fuzzer targeting the ABI-specific classification logic.
 *
 * @details This harness is a highly-focused stress test of the `prepare_*_call_frame`
 * functions. It uses the shared helpers to generate a pool of random `infix_type`
 * objects within a single memory arena. It then constructs random function
 * signatures from this pool and calls the ABI classification logic directly.
 *
 * The test's only goal is to find inputs that cause crashes, hangs, or sanitizer
 * errors within the ABI classifiers.
 */

#include "fuzz_helpers.h"

// Fuzzing Logic Core
static void FuzzTest(fuzzer_input in) {
    infix_type * type_pool[MAX_TYPES_IN_POOL] = {0};
    int type_count = 0;

    // Create a single arena to hold all generated types for this fuzz case.
    infix_arena_t * type_arena = infix_arena_create(65536);
    if (!type_arena)
        return;

    // Phase 1: Generate a pool of complex types to build signatures from.
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;
        // All types are now allocated from the same arena.
        infix_type * new_type = generate_random_type(type_arena, &in, 0, &total_fields);
        if (new_type)
            type_pool[type_count++] = new_type;
        else
            break;
    }

    if (type_count == 0)
        goto cleanup;

    // Phase 2: Construct a random signature from the type pool.
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

        // Target 1: Fuzz the forward call ABI classifier
        const infix_forward_abi_spec * fwd_spec = get_current_forward_abi_spec();
        if (fwd_spec) {
            infix_arena_t * fwd_arena = infix_arena_create(16384);
            if (fwd_arena) {
                infix_call_frame_layout * layout = NULL;
                // Fuzz both bound and unbound classifiers
                fwd_spec->prepare_forward_call_frame(
                    fwd_arena, &layout, return_type, arg_types, num_args, num_fixed_args, nullptr);
                fwd_spec->prepare_forward_call_frame(
                    fwd_arena, &layout, return_type, arg_types, num_args, num_fixed_args, (void *)0x1);
                infix_arena_destroy(fwd_arena);
            }
        }

        // Target 2: Fuzz the reverse call ABI classifier
        const infix_reverse_abi_spec * rev_spec = get_current_reverse_abi_spec();
        if (rev_spec) {
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
    // A single call destroys the arena and all types generated within it.
    infix_arena_destroy(type_arena);
}

// libFuzzer Entry Point
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
