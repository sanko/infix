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
 * @brief Fuzzer target for the trampoline generation functions, including shared arena logic.
 * @ingroup internal_fuzz
 *
 * @internal
 * This fuzzer targets the full JIT compilation pipeline, from type graph to executable
 * code. It has been updated to specifically stress both the default memory model (deep-copying)
 * and the new shared arena optimization (pointer-sharing).
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * The fuzzer uses a structure-aware and probabilistic approach:
 * 1.  **Generate Base Types:** A pool of random base types is generated.
 * 2.  **Create a Registry:** These base types are registered with names (e.g., `@FuzzType0`).
 * 3.  **Generate Referencing Types:** A second pool of types is generated, which can
 *     include references (`@FuzzTypeN`) to the types in the registry.
 * 4.  **Probabilistic Path Selection:** A byte is consumed from the fuzzer input to
 *     decide which memory model to test:
 *     a. **Deep-Copy Path:** The registry and trampolines are created in *separate* arenas.
 *        This forces the default, safe behavior where all named type metadata is deep-copied
 *        into each trampoline.
 *     b. **Pointer-Sharing Path:** The registry and trampolines are created in the *same*
 *        shared arena. This forces the optimized behavior where trampolines share pointers
 *        to the canonical named types, saving memory.
 * 5.  **Exercise Trampoline Creation:** A random function signature is constructed using
 *     the referencing types, and all four `infix_*_create_*` functions are called.
 *
 * This strategy ensures that both memory management code paths are continuously fuzzed
 * for crashes, memory leaks, use-after-free errors, and other vulnerabilities.
 * @endinternal
 */

#include "fuzz_helpers.h"

// Access internal error clearing function
extern void _infix_clear_error(void);

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
    _infix_clear_error();  // Clear stale context

    uint8_t path_selector;
    if (!consume_uint8_t(&in, &path_selector))
        return;

    bool use_shared_arena = (path_selector % 2 == 0);

    infix_arena_t * main_arena = infix_arena_create(65536);
    if (!main_arena)
        return;

    infix_registry_t * registry = NULL;
    infix_arena_t * trampoline_arena = NULL;
    infix_arena_t * registry_arena = NULL;

    if (use_shared_arena) {
        // Path A: Test pointer-sharing. Registry and trampolines use the same arena.
        registry = infix_registry_create_in_arena(main_arena);
        trampoline_arena = main_arena;
        registry_arena = main_arena;
    }
    else {
        // Path B: Test deep-copying. Registry and trampolines use different arenas.
        registry = infix_registry_create();
        trampoline_arena = infix_arena_create(16384);
        // We need the internal arena pointer to generate types into it.
        if (registry)
            registry_arena = registry->arena;
    }

    if (!registry || !trampoline_arena || !registry_arena)
        goto cleanup;

    // 1. Generate a pool of base types and register them.
    infix_type * base_type_pool[MAX_TYPES_IN_POOL] = {0};
    int base_type_count = 0;
    char def_buffer[256];
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;
        base_type_pool[i] = generate_random_type(registry_arena, &in, 0, &total_fields);
        if (base_type_pool[i]) {
            base_type_count++;
            char type_body_str[1024];
            if (_infix_type_print_body_only(
                    type_body_str, sizeof(type_body_str), base_type_pool[i], INFIX_DIALECT_SIGNATURE) ==
                INFIX_SUCCESS) {
                snprintf(def_buffer, sizeof(def_buffer), "@FuzzType%d = %s;", i, type_body_str);
                (void)infix_register_types(registry, def_buffer);
            }
        }
        else
            break;
    }
    if (base_type_count == 0)
        goto cleanup;

    // 2. Generate a second pool of types that can reference the named types.
    infix_type * final_type_pool[MAX_TYPES_IN_POOL] = {0};
    int final_type_count = 0;
    for (int i = 0; i < MAX_TYPES_IN_POOL; ++i) {
        size_t total_fields = 0;
        uint8_t choice;
        if (consume_uint8_t(&in, &choice) && (choice % 4 == 0)) {  // 25% chance of being a named ref
            uint8_t name_idx;
            if (consume_uint8_t(&in, &name_idx)) {
                snprintf(def_buffer, sizeof(def_buffer), "@FuzzType%d", name_idx % base_type_count);
                infix_type * raw_type = NULL;
                infix_arena_t * temp_parser_arena = NULL;
                // 1. Parse into a new temporary arena.
                if (_infix_parse_type_internal(&raw_type, &temp_parser_arena, def_buffer) == INFIX_SUCCESS)
                    // 2. Copy the result from the temporary arena into our main trampoline arena.
                    final_type_pool[i] = _copy_type_graph_to_arena(trampoline_arena, raw_type);
                // 3. Always destroy the temporary arena created by the parser.
                infix_arena_destroy(temp_parser_arena);
            }
        }
        else
            final_type_pool[i] = generate_random_type(trampoline_arena, &in, 0, &total_fields);
        if (final_type_pool[i])
            final_type_count++;
        else
            break;
    }
    if (final_type_count == 0)
        goto cleanup;

    // 3. Construct a random function signature.
    uint8_t arg_count_byte;
    if (consume_uint8_t(&in, &arg_count_byte)) {
        size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;
        size_t num_fixed_args = num_args > 0 ? (arg_count_byte % (num_args + 1)) : 0;
        infix_type ** arg_types = (infix_type **)calloc(num_args, sizeof(infix_type *));
        if (arg_types) {
            infix_type * return_type = final_type_pool[arg_count_byte % final_type_count];
            for (size_t i = 0; i < num_args; ++i)
                arg_types[i] = final_type_pool[i % final_type_count];

            (void)_infix_resolve_type_graph_inplace(&return_type, registry);
            for (size_t i = 0; i < num_args; ++i)
                (void)_infix_resolve_type_graph_inplace(&arg_types[i], registry);

            // 4. Exercise all trampoline creation functions.
            infix_forward_t * t1 = NULL;
            (void)infix_forward_create_unbound_manual(&t1, return_type, arg_types, num_args, num_fixed_args);
            infix_forward_destroy(t1);

            infix_forward_t * t2 = NULL;
            (void)infix_forward_create_manual(
                &t2, return_type, arg_types, num_args, num_fixed_args, (void *)dummy_target_for_fuzzing);
            infix_forward_destroy(t2);

            infix_reverse_t * t3 = NULL;
            (void)infix_reverse_create_callback_manual(
                &t3, return_type, arg_types, num_args, num_fixed_args, (void *)dummy_target_for_fuzzing);
            infix_reverse_destroy(t3);

            infix_reverse_t * t4 = NULL;
            (void)infix_reverse_create_closure_manual(
                &t4, return_type, arg_types, num_args, num_fixed_args, dummy_closure_handler, NULL);
            infix_reverse_destroy(t4);

            free(arg_types);
        }
    }

cleanup:
    infix_registry_destroy(registry);
    if (use_shared_arena)  // In the shared path, main_arena is the only other arena to clean up.
        infix_arena_destroy(main_arena);
    else {
        // In the deep-copy path, we must clean up both the unused main_arena
        // and the separately allocated trampoline_arena.
        infix_arena_destroy(trampoline_arena);
        infix_arena_destroy(main_arena);  // This line fixes the leak.
    }
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
