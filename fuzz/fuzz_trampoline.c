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
 * @brief A dual-purpose fuzzing harness for libFuzzer (Clang) and AFL++ (GCC),
 *        focused on the infix FFI trampoline generation API.
 *
 * @details This harness uses the shared recursive generator (`fuzz_helpers.h`) to
 * create a pool of complex `infix_type` objects within a memory arena. It then uses
 * these types to construct randomized function signatures which are passed to
 * `infix_forward_create_manual` and `infix_reverse_create_manual`.
 *
 * The goal is to find bugs in the ABI classification and JIT code generation stages.
 * This harness now tests the fully arena-based workflow.
 */

#include "fuzz_helpers.h"

// Fuzzing Logic Core
// This function contains the actual test logic, shared by both entry points.
static void FuzzTest(fuzzer_input in) {
    infix_type * type_pool[MAX_TYPES_IN_POOL] = {0};
    int type_count = 0;

    // Create a single arena for the entire type pool.
    infix_arena_t * arena = infix_arena_create(65536);
    if (!arena)
        return;

    // Phase 1: Generate a pool of complex types to build signatures from.
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;  // Initialize counter for each new type
        infix_type * new_type = generate_random_type(arena, &in, 0, &total_fields);
        if (new_type)
            type_pool[type_count++] = new_type;
        else
            break;
    }

    if (type_count == 0) {
        infix_arena_destroy(arena);
        return;
    }

    // Phase 2: Fuzz the trampoline generators using the generated type pool.
    uint8_t arg_count_byte;
    if (consume_uint8_t(&in, &arg_count_byte)) {
        size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;

        uint8_t fixed_arg_byte = 0;
        consume_uint8_t(&in, &fixed_arg_byte);
        size_t num_fixed_args = num_args > 0 ? (fixed_arg_byte % (num_args + 1)) : 0;

        // Note: arg_types is allocated on the heap because the trampoline generator
        // doesn't take ownership of it, and it's simpler than using the arena here.
        infix_type ** arg_types = (infix_type **)calloc(num_args, sizeof(infix_type *));
        if (arg_types) {
            uint8_t idx_byte = 0;
            consume_uint8_t(&in, &idx_byte);
            infix_type * return_type = type_pool[idx_byte % type_count];

            for (size_t i = 0; i < num_args; ++i)
                arg_types[i] = type_pool[i % type_count];

            // Fuzz the forward trampoline generator.
            infix_forward_t * trampoline = NULL;
            if (infix_forward_create_manual(&trampoline, return_type, arg_types, num_args, num_fixed_args) ==
                INFIX_SUCCESS)
                infix_forward_destroy(trampoline);

            // Fuzz the reverse trampoline generator.
            infix_reverse_t * reverse_trampoline = NULL;
            if (infix_reverse_create_manual(
                    &reverse_trampoline, return_type, arg_types, num_args, num_fixed_args, NULL, NULL) == INFIX_SUCCESS)
                infix_reverse_destroy(reverse_trampoline);

            free(arg_types);
        }
    }

    // Phase 3: Final Cleanup.
    // A single call destroys the arena and all types created within it.
    infix_arena_destroy(arena);
}

#ifndef USE_AFL
// libFuzzer Entry Point
/**
 * @brief The entry point called by the libFuzzer engine.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;  // Return value is unused.
}
#else  // NOT USE_AFL
// AFL++ Entry Point
#include <AFL-fuzz-init.h>
#include <unistd.h>  // For read()

/**
 * @brief The main entry point for the AFL++ fuzzer.
 */
int main(void) {
    unsigned char buf[1024 * 16];  // 16 KB buffer.

    while (__AFL_LOOP(10000)) {
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len < 0)
            return 1;

        fuzzer_input in = {(const uint8_t *)buf, (size_t)len};
        FuzzTest(in);
    }

    return 0;
}
#endif               // USE_AFL
