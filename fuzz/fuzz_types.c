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
 * @file fuzz_types.c
 * @brief Fuzzer target for the random type generation logic.
 * @ingroup internal_fuzz
 *
 * @internal
 * This file defines a fuzz target that focuses exclusively on the `generate_random_type`
 * helper function. It is designed to be compiled with a fuzzing engine like
 * libFuzzer or AFL.
 *
 * @section fuzz_strategy Fuzzing Strategy
 *
 * The strategy of this fuzzer is to test the type generator itself for robustness.
 * It operates by:
 * 1.  Taking the raw input data from the fuzzer.
 * 2.  Feeding this data into the `generate_random_type` function.
 * 3.  Ignoring the generated type and simply cleaning up the memory arena.
 *
 * The goal is to find inputs that cause `generate_random_type` to crash, hang
 * (enter an infinite loop), or leak memory (as detected by ASan). This is a
 * "meta-fuzzer" in that it tests the core of the structure-aware fuzzing logic
 * used by the other, more complex targets (`fuzz_abi.c`, `fuzz_trampoline.c`).
 *
 * By isolating the type generator, we can more easily debug issues within its
 * recursive logic without the added complexity of the ABI or JIT layers. This
 * target was particularly useful for finding bugs related to zero-sized types
 * and deep recursion limits.
 * @endinternal
 */

#include "fuzz_helpers.h"

extern void _infix_clear_error(void);

/**
 * @internal
 * @brief Main fuzzing logic for a single input.
 *
 * This function takes a block of fuzzer-generated data and calls the core
 * type generator, then immediately cleans up.
 *
 * @param in The fuzzer input data stream.
 */
static void FuzzTest(fuzzer_input in) {
    _infix_clear_error();  // Clear stale context

    infix_arena_t * arena = infix_arena_create(65536);
    if (!arena)
        return;

    size_t total_fields = 0;
    // Call the function under test. We don't need to do anything with the
    // result; we are just checking if the call itself triggers a bug.
    (void)generate_random_type(arena, &in, 0, &total_fields);

    // Clean up all memory used during type generation.
    infix_arena_destroy(arena);
}

#ifndef USE_AFL
/**
 * @brief The entry point for libFuzzer.
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
#endif

#ifdef USE_AFL
/**
 * @brief The entry point for AFL in persistent mode.
 */
#include <AFL-fuzz-init.h>
#include <unistd.h>

int main(void) {
    unsigned char buf[1024 * 16];  // 16KB input buffer
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
