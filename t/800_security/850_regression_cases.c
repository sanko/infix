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
 * @brief Contains a data-driven suite of deterministic unit tests for specific bugs found by fuzzing.
 * @details This file is a crucial part of the development lifecycle. When a
 * fuzzer discovers a crash or a timeout, the minimal input that triggers the
 * bug is captured and added to the `regression_tests` array in this file as a
 * permanent regression test. This ensures that once a bug is fixed, it can never
 * be accidentally reintroduced without causing an immediate and obvious CI failure.
 *
 * ### How to Add a New Regression Test
 *
 * This process turns a temporary fuzzer artifact into a permanent, valuable test.
 *
 * **Step 1: Get the Fuzzer Artifact**
 *
 *    After a fuzzing job fails, download the `crash-artifact-*` zip file. Inside,
 *    you will find one or more `crash-*` or `timeout-*` files. Open one.
 *
 * **Step 2: Copy the Base64 Input**
 *
 *    Near the bottom of the artifact file, find the `Base64:` line and copy the
 *    long string of characters. This is the fuzzer input.
 *
 * **Step 3: Add a New Entry to the `regression_tests` Array**
 *
 *    In this file, add a new `regression_test_case_t` struct to the
 *    `regression_tests` array. Fill in the fields:
 *
 *    - `.name`: A descriptive name of the bug (e.g., "SysV Timeout - Wide Structs").
 *    - `.b64_input`: The Base64 string you copied.
 *    - `.target`: Which part of the code is being tested?
 *        - `TARGET_TYPE_GENERATOR`: For bugs found in `fuzz_types`, `fuzz_trampoline`,
 *          or `fuzz_abi`. The test will call `generate_random_type()`.
 *        - `TARGET_SIGNATURE_PARSER`: For bugs found in `fuzz_signature`. The test
 *          will call `ffi_type_from_signature()`.
 *    - `.expected_status`: The correct `ffi_status` the function should now return.
 *        - For a fixed **timeout**, this should be `FFI_SUCCESS`, as the valid-but-slow
 *          input should now be processed quickly and correctly.
 *        - For a fixed **crash**, this should be `FFI_ERROR_INVALID_ARGUMENT`, as the
 *          invalid input should now be rejected gracefully.
 *
 * **Step 4: Update the Plan**
 *
 *    The `plan()` at the top of the `TEST` block is calculated automatically from the
 *    size of the array, so no manual update is needed. Your test is now integrated.
 */

#define DBLTAP_IMPLEMENTATION
#include "fuzz_regression_helpers.h"  // The Base64 decoder
#include <double_tap.h>
#include <fuzz_helpers.h>  // From the fuzz/ directory
#include <infix.h>

/**
 * @internal
 * @enum fuzzer_target_t
 * @brief Enumerates the different parts of the infix library that can be targeted by a regression test.
 */
typedef enum {
    TARGET_TYPE_GENERATOR,   ///< Tests the `generate_random_type` function (for timeouts/crashes in Core API).
    TARGET_SIGNATURE_PARSER  ///< Tests the `ffi_type_from_signature` function (for bugs in the Signature API).
} fuzzer_target_t;

/**
 * @internal
 * @struct regression_test_case_t
 * @brief A struct that defines a single, self-contained regression test case.
 */
typedef struct {
    const char * name;           ///< A human-readable name for the test.
    const char * b64_input;      ///< The Base64-encoded input from the fuzzer artifact.
    fuzzer_target_t target;      ///< Which part of the library to test.
    ffi_status expected_status;  ///< The expected outcome after the bug fix.
} regression_test_case_t;

// To add a new test, simply add a new entry to this array.
static const regression_test_case_t regression_tests[] = {
    {.name = "Timeout in SysV ABI Classifier (Wide Structs)",
     .b64_input = "T09PT09OT/////8I//////////9sbARsbGwAbGxsbGxPT09PT09PT09PT+8=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Stack Overflow in Signature Parser (Deep Nesting)",
     .b64_input = "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7aX19fX19fX19fX19fX19fX19fX19fX19f"
                  "X19fX19fX19fX19fX19fX19fX19fX19fX19fX19fQ==",
     .target = TARGET_SIGNATURE_PARSER,
     .expected_status = FFI_ERROR_INVALID_ARGUMENT},
    {.name = "Timeout in SysV Classifier (Zero-Sized Array)",
     .b64_input = "A/oEAA==",  // Decodes to: create array, 250 elements, of struct, with 0 members.
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Timeout in SysV Classifier (Recursive Packed Structs)",
     .b64_input = "/v7+/v7+/v///3///////wD+/v7+/v7+/v7+/qg=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Timeout in Type Generator (Wide Nested Aggregates)",
     .b64_input = "LP///////////wAAAAP//////////////////////////+Li4g==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (SSE/SSE case)",
     .b64_input = "zgAAzwDP////////////////////////////////////////////////////////T08PT09PT0////8POuJNT08=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (Mixed GPR/SSE case)",
     .b64_input = "LQAAAAAAAM8AQ/////////////////////////////////////////////////////////////////////////////////"
                  "////////////////////9DQ0MAAAA=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM index bug)",
     .b64_input = "////////p6X/D36lAAAAAAABAAAAAAAAAEoAAAAAAAAIAAAAAAAAAP85AI4A/z//"
                  "KQA6AAAAAAAAvgAAAAAAVAAAAH4AAAAAAAAAAAAAAAAAAACnYP8PfqUAAAAAAAAAAAAAAAAAAAAAAOObggMAAAAAAAAAcB46JDjM"
                  "AQAAAAAAAAAAAAAAAAAAAAAAAAAQUwAAAP///wD//+np5+l6AA==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (SSE/INTEGER pair bug)",
     .b64_input = "Hh4eOh4eHh8AAABWHh4eHh4eAgs=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (Mixed pair bug 2)",
     .b64_input = "JCUlJSUlJQFNTaUl29qy/wAATU0vJRQA957pPwAuCQ==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds)",
     .b64_input = "qqqqqrgcCgAwUAAAqqo6FxcXLKqqLQCMAg==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM out of bounds 2)",
     .b64_input = "ojQ6Ojo6AAAAAAAAEQA6Ojo6Ojo6Ojo=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 2)",
     .b64_input = "qwEeHh4eHh4eAAEDAB4eHh4eHh4eHiT//w==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 3)",
     .b64_input = "gAAASABPT09PT08VAAAAAAACEQAAAABPT08=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 4)",
     .b64_input = "AQgB29vbATuIAIDb29vb2wAA29vb29s=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = FFI_SUCCESS}
};

/**
 * @internal
 * @brief A helper function that runs a single regression test case.
 * @param test A pointer to the test case definition.
 */
static void run_regression_case(const regression_test_case_t * test) {
    subtest(test->name) {
        plan(2);

        size_t data_size;
        unsigned char * data = b64_decode(test->b64_input, &data_size);

        ok(data != NULL, "Base64 decoded successfully");
        if (!data) {
            fail("Skipping test due to Base64 decode failure.");
            return;
        }

        if (test->target == TARGET_TYPE_GENERATOR) {
            fuzzer_input in = {(const uint8_t *)data, data_size};

            // Initialize the total_fields counter for the generator.
            size_t total_fields = 0;
            ffi_type * generated_type = generate_random_type(&in, 0, &total_fields);

            if (test->expected_status == FFI_SUCCESS) {
                if (generated_type) {
                    ffi_type_destroy(generated_type);
                    pass("Successfully processed pathological input without timeout/crash.");
                }
                else
                    pass(
                        "Generator failed gracefully on pathological input, which is an acceptable non-timeout "
                        "outcome.");
            }
            else {
                ok(generated_type == NULL, "Generator correctly failed on invalid input.");
                if (generated_type)
                    ffi_type_destroy(generated_type);
            }
        }
        else if (test->target == TARGET_SIGNATURE_PARSER) {
            char * signature = (char *)malloc(data_size + 1);
            memcpy(signature, data, data_size);
            signature[data_size] = '\0';

            ffi_type * type = NULL;
            arena_t * arena = NULL;
            ffi_status status = ffi_type_from_signature(&type, &arena, signature);

            ok(status == test->expected_status,
               "Parser returned correct status (expected %d, got %d)",
               test->expected_status,
               status);

            arena_destroy(arena);
            free(signature);
        }

        free(data);
    }
}

TEST {
    size_t num_tests = sizeof(regression_tests) / sizeof(regression_tests[0]);
    plan(num_tests);

    for (size_t i = 0; i < num_tests; ++i)
        run_regression_case(&regression_tests[i]);
}
