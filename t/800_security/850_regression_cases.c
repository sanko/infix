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
 * @file 850_regression_cases.c
 * @brief Contains deterministic unit tests for specific bugs found by fuzzing.
 * @details This file is a crucial part of the development lifecycle. When a
 * fuzzer discovers a crash or a timeout, the minimal input that triggers the
 * bug is captured and added to this file as a permanent regression test. This
 * ensures that once a bug is fixed, it can never be accidentally reintroduced
 * without causing an immediate and obvious CI failure.
 *
 * ### How to Add a New Regression Test
 *
 * This process turns a temporary fuzzer artifact into a permanent, valuable test.
 *
 * **Step 1: Locate the Fuzzer Artifact**
 *
 *    After a fuzzing job fails in CI, go to the "Artifacts" section of the run.
 *    Download the `crash-artifact-*` zip file. Inside, you will find one or more
 *    `crash-*` or `timeout-*` files. Open one in a text editor.
 *
 * **Step 2: Copy the Base64 Input**
 *
 *    Near the bottom of the artifact file, you will find a `Base64:` line. Copy the
 *    long string of characters that follows it. This is the fuzzer input.
 *    Example: `Base64: e3t7aX19fQ==`
 *
 * **Step 3: Create a New Subtest**
 *
 *    In the `TEST` block of this file, add a new `subtest()` block. Give it a
 *    descriptive name that includes the type of bug and which fuzzer found it.
 *    For example: `subtest("Stack overflow in signature parser (from fuzz_signature)")`
 *
 * **Step 4: Implement the Test Logic**
 *
 *    Inside the subtest, follow this pattern:
 *    a. Paste the Base64 string into a `const char*` variable.
 *    b. Use the `b64_decode()` helper to convert it back into raw bytes.
 *    c. **Replicate the logic of the fuzzer that found the bug.**
 *       - If `fuzz_signature` found it, you need to call `ffi_signature_parse` or `ffi_type_from_signature`.
 *       - If `fuzz_types`, `fuzz_abi`, or `fuzz_trampoline` found it, you need to use the `generate_random_type`
 *         function.
 *    d. **Assert the correct, *fixed* behavior.**
 *       - For a former crash bug, the test should now assert that the function returns a specific error code (e.g.,
 *         `FFI_ERROR_INVALID_ARGUMENT`).
 *       - For a former timeout bug, the test should now assert that the function completes successfully (`FFI_SUCCESS`
 *         or `pass()`). e. Free any memory you allocated (like the decoded data).
 *
 * **Step 5: Update the Plan**
 *
 *    Increment the number in the `plan()` call at the top of the main `TEST` block
 *    to account for your new subtest.
 */

#define DBLTAP_IMPLEMENTATION
#include "fuzz_regression_helpers.h"  // The Base64 decoder helper
#include <../../fuzz/fuzz_helpers.h>  // From the fuzz/ directory
#include <double_tap.h>
#include <infix.h>

TEST {
    // Each subtest represents one fuzzer-discovered bug.
    plan(2);

    subtest("Timeout in SysV ABI Classifier (Fuzzer-discovered)") {
        plan(2);

        // This is the Base64 string from one of the fuzzer's timeout artifacts.
        // This input creates a "wide" struct that caused exponential complexity
        // in the original abi_sysv_x64.c classifier.
        const char * timeout_input_b64 = "T09PT09OT/////8I//////////9sbARsbGwAbGxsbGxPT09PT09PT09PT+8=";
        size_t data_size;

        // Decode the input.
        unsigned char * data = b64_decode(timeout_input_b64, &data_size);
        ok(data != NULL, "Base64 decoded successfully");

        if (data) {
            fuzzer_input in = {(const uint8_t *)data, data_size};

            // Replicate the logic of the fuzzer that found the bug (fuzz_abi).
            // It uses generate_random_type to build ffi_type objects.
            ffi_type * generated_type = generate_random_type(&in, 0);

            // Assert the correct, fixed behavior.
            // A timeout bug is fixed when the function now completes successfully and quickly.
            if (generated_type) {
                ffi_type_destroy(generated_type);
                pass("Successfully generated and destroyed the pathological type without timing out.");
            }
            else
                fail("Failed to generate the pathological type from the regression input.");
        }
        else
            fail("Skipping test due to Base64 decode failure.");

        // Clean up.
        free(data);
    }

    subtest("Stack overflow in signature parser (Fuzzer-discovered)") {
        plan(2);

        // STEP 1: This Base64 string decodes to `{{{{...i...}}}}` repeated 33 times.
        // This input caused a stack overflow before the recursion depth limit was added.
        const char * stack_overflow_input_b64 =
            "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7aX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX"
            "19fX19fX19fX19fX19fX19fX19fX19fQ==";
        size_t data_size;

        // Decode the input.
        unsigned char * data = b64_decode(stack_overflow_input_b64, &data_size);
        ok(data != NULL, "Base64 decoded successfully");

        if (data) {
            // Replicate the logic of the fuzzer (fuzz_signature).
            ffi_type * type = NULL;
            arena_t * arena = NULL;

            char * signature = malloc(data_size + 1);
            memcpy(signature, data, data_size);
            signature[data_size] = '\0';

            ffi_status status = ffi_type_from_signature(&type, &arena, signature);

            // Assert the correct, fixed behavior.
            // The parser should now fail gracefully with an error, not crash.
            ok(status == FFI_ERROR_INVALID_ARGUMENT, "Parser correctly fails on excessive recursion");

            arena_destroy(arena);
            free(signature);
        }
        else
            fail("Skipping test due to Base64 decode failure.");

        // Clean up.
        free(data);
    }
}
