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
 * create a pool of complex `ffi_type` objects. It then uses these types to construct
 * randomized function signatures which are passed to `generate_forward_trampoline`
 * and `generate_reverse_trampoline`.
 *
 * The goal is to find bugs in the ABI classification and JIT code generation stages:
 *  - Crashes or assertion failures in the ABI classification logic (`abi_*.c` files).
 *  - Memory errors in the trampoline generator's complex error-handling paths.
 *  - Generation of invalid machine code from edge-case types.
 *
 * This harness is compiled in either libFuzzer mode or AFL++ mode, controlled by
 * the `USE_AFL` macro from the build script.
 */

#include "fuzz_helpers.h"

// Fuzzing Logic Core
// This function contains the actual test logic, shared by both entry points.
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
            // Stop if we run out of fuzzer data or hit a generation failure.
            break;
    }

    if (type_count == 0)
        // If we couldn't even generate one type, there's nothing to test.
        return;

    // Phase 2: Fuzz the trampoline generators using the generated type pool.
    uint8_t arg_count_byte;
    if (consume_uint8_t(&in, &arg_count_byte)) {
        size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;

        uint8_t fixed_arg_byte = 0;
        consume_uint8_t(&in, &fixed_arg_byte);
        // Ensure num_fixed_args is always <= num_args.
        size_t num_fixed_args = num_args > 0 ? (fixed_arg_byte % num_args) : 0;

        ffi_type ** arg_types = (ffi_type **)calloc(num_args, sizeof(ffi_type *));
        if (arg_types) {
            // Pick a return type and argument types by indexing into our generated pool.
            uint8_t idx_byte = 0;
            consume_uint8_t(&in, &idx_byte);  // Use one more byte to randomize selection.
            ffi_type * return_type = type_pool[idx_byte % type_count];

            for (size_t i = 0; i < num_args; ++i)
                // Reuse types from the pool to create interesting signatures.
                arg_types[i] = type_pool[i % type_count];

            // Fuzz the forward trampoline generator.
            ffi_trampoline_t * trampoline = NULL;
            if (generate_forward_trampoline(&trampoline, return_type, arg_types, num_args, num_fixed_args) ==
                FFI_SUCCESS)
                // On success, we must free the object to check for memory leaks.
                ffi_trampoline_free(trampoline);

            // Fuzz the reverse trampoline generator.
            // Note: `user_callback_fn` is NULL, which is fine for testing generation logic.
            ffi_reverse_trampoline_t * reverse_trampoline = NULL;
            if (generate_reverse_trampoline(
                    &reverse_trampoline, return_type, arg_types, num_args, num_fixed_args, NULL, NULL) == FFI_SUCCESS)
                ffi_reverse_trampoline_free(reverse_trampoline);

            free(arg_types);
        }
    }

    // Phase 3: Final Cleanup.
    // We must destroy all types successfully generated in the pool to prevent leaks.
    for (int i = 0; i < type_count; ++i)
        ffi_type_destroy(type_pool[i]);
}

// libFuzzer Entry Point
#ifndef USE_AFL
/**
 * @brief The entry point called by the libFuzzer engine.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;  // Return value is unused.
}
#endif  // NOT USE_AFL

// AFL++ Entry Point
#ifdef USE_AFL
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
#endif  // USE_AFL
