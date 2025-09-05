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
 * @brief A dual-purpose fuzzing harness for libFuzzer (Clang) and AFL++ (GCC),
 *        focused on the infix FFI type creation API's integrity.
 *
 * @details This harness uses a shared recursive generator (`fuzz_helpers.h`) to
 * create complex, deeply-nested `ffi_type` objects and immediately destroys them.
 * Its goal is to find memory safety bugs (leaks, overflows, use-after-free) in the
 * type creation (`ffi_type_create_*`) and destruction (`ffi_type_destroy`) logic.
 *
 * It compiles in one of two modes:
 * - **libFuzzer mode (default)**: Exposes the `LLVMFuzzerTestOneInput` entry point.
 * - **AFL++ mode**: Exposes a `main` function that uses a persistent mode loop.
 *   This is enabled by passing `-DUSE_AFL=1` during compilation, which is handled
 *   automatically by the build script when using GCC.
 */

#include "fuzz_helpers.h"

// Fuzzing Logic Core
// This function contains the actual test logic, shared by both libFuzzer and AFL++ entry points.
static void FuzzTest(fuzzer_input in) {
    // The entire test is to attempt to generate one maximally complex type
    // and then successfully destroy it without AddressSanitizer (or other tools)
    // finding any memory corruption, leaks, or crashes.
    ffi_type * generated_type = generate_random_type(&in, 0);

    if (generated_type) {
        // If we successfully created a complex type, the most important part of
        // the test is to ensure it can be destroyed without ASan finding any leaks,
        // use-after-frees, or double-frees.
        ffi_type_destroy(generated_type);
    }
}


// libFuzzer Entry Point
#ifndef USE_AFL
/**
 * @brief The entry point called by the libFuzzer engine.
 */
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;  // The return value is unused by libFuzzer.
}
#endif  // NOT USE_AFL


// AFL++ Entry Point
#ifdef USE_AFL
#include <AFL-fuzz-init.h>
#include <unistd.h>  // For read()
/**
 * @brief The main entry point for the AFL++ fuzzer.
 * @details It reads data from stdin and runs in a persistent mode loop for performance.
 */
int main(void) {
    // A buffer to hold the input from AFL++. Sized to hold a reasonable test case.
    unsigned char buf[1024 * 16];

    // This is the standard AFL++ persistent mode loop. It is much faster than
    // restarting the process for every single input.
    while (__AFL_LOOP(10000)) {  // Process up to 10000 inputs before a clean restart.
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len < 0) {
            return 1;
        }

        fuzzer_input in = {(const uint8_t *)buf, (size_t)len};
        FuzzTest(in);
    }

    return 0;
}
#endif  // USE_AFL
