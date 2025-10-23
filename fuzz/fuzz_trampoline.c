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
 * @file fuzz_trampoline.c
 * @brief Fuzzer target for the trampoline generation functions.
 * @ingroup internal_fuzz
 *
 * @internal
 * This file defines a fuzz target that focuses on the JIT code generation pipeline,
 * specifically the `infix_*_create_*_manual` functions. It is designed to be compiled
 * with a fuzzing engine like libFuzzer or AFL.
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * This fuzzer employs a structure-aware approach to thoroughly test the trampoline
 * creation process:
 *
 * 1.  **Generate Random Types:** It first consumes the fuzzer's input data to
 *     generate a pool of random `infix_type` objects using the `generate_random_type`
 *     helper. This creates a diverse set of valid, invalid, and complex aggregate
 *     types to serve as building blocks.
 *
 * 2.  **Construct a Random Signature:** It then consumes more data to construct a
 *     random function signature (return type, argument count, and argument types)
 *     by selecting types from the generated pool.
 *
 * 3.  **Exercise Trampoline Creation:** Finally, it passes this randomly generated
 *     signature to all four manual-API trampoline creation functions:
 *     - `infix_forward_create_unbound_manual`
 *     - `infix_forward_create_manual` (bound)
 *     - `infix_reverse_create_callback_manual`
 *     - `infix_reverse_create_closure_manual`
 *
 * The primary goal is to find bugs in the complete JIT pipeline, from ABI
 * classification through to the final machine code emission. By generating valid
 * `infix_type` objects first and then passing them to the manual API, this fuzzer
 * can create more complex and valid inputs for the JIT engine than a simple
 * string-based fuzzer might. This helps uncover deeper bugs in the code generation
 * and memory management logic that might not be triggered by parser errors.
 * @endinternal
 */

#include "fuzz_helpers.h"

/** @internal A dummy C function to serve as a valid target for bound trampolines. */
void dummy_target_for_fuzzing(void) {}

/** @internal A dummy generic handler for creating reverse trampoline closures. */
void dummy_closure_handler(infix_context_t * ctx, void * ret, void ** args) {
    (void)ctx;
    (void)ret;
    (void)args;
}

/**
 * @internal
 * @brief Main fuzzing logic for a single input.
 *
 * This function takes a block of fuzzer-generated data and uses it to construct
 * random types and function signatures, which are then fed into all four of the
 * manual-API trampoline creation functions.
 *
 * @param in The fuzzer input data stream.
 */
static void FuzzTest(fuzzer_input in) {
    infix_type * type_pool[MAX_TYPES_IN_POOL] = {0};
    int type_count = 0;

    infix_arena_t * arena = infix_arena_create(65536);
    if (!arena)
        return;

    // 1. Generate a pool of random types from the input data.
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;
        infix_type * new_type = generate_random_type(arena, &in, 0, &total_fields);
        if (new_type)
            type_pool[type_count++] = new_type;
        else
            break;  // Stop if input data is exhausted or a generation limit is hit.
    }

    if (type_count == 0) {
        infix_arena_destroy(arena);
        return;
    }

    // 2. Construct a random function signature using types from the pool.
    uint8_t arg_count_byte;
    if (consume_uint8_t(&in, &arg_count_byte)) {
        size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;

        uint8_t fixed_arg_byte = 0;
        consume_uint8_t(&in, &fixed_arg_byte);
        size_t num_fixed_args = num_args > 0 ? (fixed_arg_byte % (num_args + 1)) : 0;

        infix_type ** arg_types = (infix_type **)calloc(num_args, sizeof(infix_type *));
        if (arg_types) {
            uint8_t idx_byte = 0;
            consume_uint8_t(&in, &idx_byte);
            infix_type * return_type = type_pool[idx_byte % type_count];

            for (size_t i = 0; i < num_args; ++i)
                arg_types[i] = type_pool[i % type_count];

            // 3. Exercise all four manual trampoline creation APIs.
            // We check the return status but are primarily interested in whether the
            // calls crash, hang, or leak memory (as detected by sanitizers).

            infix_forward_t * unbound_trampoline = NULL;
            if (infix_forward_create_unbound_manual(
                    &unbound_trampoline, return_type, arg_types, num_args, num_fixed_args) == INFIX_SUCCESS)
                infix_forward_destroy(unbound_trampoline);

            infix_forward_t * bound_trampoline = NULL;
            if (infix_forward_create_manual(&bound_trampoline,
                                            return_type,
                                            arg_types,
                                            num_args,
                                            num_fixed_args,
                                            (void *)dummy_target_for_fuzzing) == INFIX_SUCCESS)
                infix_forward_destroy(bound_trampoline);

            infix_reverse_t * reverse_callback = NULL;
            if (infix_reverse_create_callback_manual(&reverse_callback,
                                                     return_type,
                                                     arg_types,
                                                     num_args,
                                                     num_fixed_args,
                                                     (void *)dummy_target_for_fuzzing) == INFIX_SUCCESS)
                infix_reverse_destroy(reverse_callback);

            infix_reverse_t * reverse_closure = NULL;
            if (infix_reverse_create_closure_manual(
                    &reverse_closure, return_type, arg_types, num_args, num_fixed_args, dummy_closure_handler, NULL) ==
                INFIX_SUCCESS)
                infix_reverse_destroy(reverse_closure);

            free(arg_types);
        }
    }

    infix_arena_destroy(arena);
}

#ifndef USE_AFL
/**
 * @brief The entry point for libFuzzer.
 * @param data A pointer to the fuzzer-generated input data.
 * @param size The size of the data.
 * @return 0 on completion.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
#else  // Integration for American Fuzzy Lop (AFL)

#include <AFL-fuzz-init.h>
#include <unistd.h>

int main(void) {
    unsigned char buf[1024 * 16];  // 16KB input buffer

    // __AFL_LOOP is the main macro for AFL's persistent mode.
    while (__AFL_LOOP(10000)) {
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len < 0)
            return 1;

        fuzzer_input in = {(const uint8_t *)buf, (size_t)len};
        FuzzTest(in);
    }

    return 0;
}
#endif
