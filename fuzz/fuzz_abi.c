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
 * @details This harness is designed to be a highly-focused stress test of the
 * most complex logic in the library: the `prepare_*_call_frame` functions for
 * each supported ABI. These functions are responsible for recursively analyzing
 * `ffi_type` structures and creating a "blueprint" for a function call, a task
 * that is ripe for integer overflows, infinite recursion, and other logic bugs.
 *
 * ### Fuzzing Strategy
 * 1.  It uses the shared `fuzz_helpers.c` to generate a pool of random,
 *     potentially pathological `ffi_type` objects.
 * 2.  It constructs a random function signature by picking types from this pool.
 * 3.  It calls the `prepare_forward_call_frame` and `prepare_reverse_call_frame`
 *     functions directly.
 * 4.  The test's only goal is to see if these calls crash, hang, or are caught
 *     by a sanitizer. If they succeed, the resulting layout and its arena are
 *     simply destroyed.
 *
 * This provides a more direct and less noisy signal for bugs in the ABI
 * classifiers than the more general `fuzz_trampoline` harness.
 */

#include "fuzz_helpers.h"

// Fuzzing Logic Core
static void FuzzTest(fuzzer_input in) {
    ffi_type * type_pool[MAX_TYPES_IN_POOL] = {0};
    int type_count = 0;

    // Phase 1: Generate a pool of complex types to build signatures from.
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;  // Initialize counter for each new type
        ffi_type * new_type = generate_random_type(&in, 0, &total_fields);
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
        size_t num_fixed_args = num_args > 0 ? (fixed_arg_byte % num_args) : 0;

        ffi_type ** arg_types = (ffi_type **)calloc(num_args, sizeof(ffi_type *));
        if (!arg_types)
            goto cleanup;

        uint8_t idx_byte = 0;
        consume_uint8_t(&in, &idx_byte);
        ffi_type * return_type = type_pool[idx_byte % type_count];

        for (size_t i = 0; i < num_args; ++i)
            arg_types[i] = type_pool[i % type_count];

        // Target 1: Fuzz the forward call ABI classifier
        const ffi_forward_abi_spec * fwd_spec = get_current_forward_abi_spec();
        if (fwd_spec) {
            arena_t * fwd_arena = arena_create(16384);
            if (fwd_arena) {
                ffi_call_frame_layout * layout = NULL;
                // Directly call the classifier. The fuzzer checks for crashes here.
                fwd_spec->prepare_forward_call_frame(
                    fwd_arena, &layout, return_type, arg_types, num_args, num_fixed_args);
                // If it succeeds, we just clean up.
                arena_destroy(fwd_arena);
            }
        }

        // Target 2: Fuzz the reverse call ABI classifier
        const ffi_reverse_abi_spec * rev_spec = get_current_reverse_abi_spec();
        if (rev_spec) {
            // Reverse spec needs a ffi_reverse_trampoline_t context. We can create a mock one.
            ffi_reverse_trampoline_t mock_context = {.return_type = return_type,
                                                     .arg_types = arg_types,
                                                     .num_args = num_args,
                                                     .num_fixed_args = num_fixed_args};

            arena_t * rev_arena = arena_create(16384);
            if (rev_arena) {
                ffi_reverse_call_frame_layout * rev_layout = NULL;
                rev_spec->prepare_reverse_call_frame(rev_arena, &rev_layout, &mock_context);
                arena_destroy(rev_arena);
            }
        }

        free(arg_types);
    }

cleanup:
    // Final Cleanup: Destroy all types generated in the pool.
    for (int i = 0; i < type_count; ++i)
        ffi_type_destroy(type_pool[i]);
}

// libFuzzer Entry Point
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
