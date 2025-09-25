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
 * @file 002_simple_calls.c
 * @brief Tests basic FFI calls with simple function signatures.
 *
 * @details This test suite verifies the FFI for the most common and fundamental
 * function signatures, ensuring that the library correctly handles basic integer
 * and floating-point arguments, void returns, and proper sign-extension of
 * integer types.
 *
 * It consolidates several smaller, single-purpose tests into one cohesive file
 * with the following subtests:
 * - `int(int, int)`: Verifies multiple integer arguments and an integer return.
 * - `float(float, float)`: Verifies multiple float arguments and a float return.
 * - `void(void)`: Verifies calls to functions with no arguments and no return value.
 * - `bool(int)`: Specifically tests that signed integer arguments are correctly
 *   sign-extended across the FFI boundary, a crucial requirement for ABI correctness.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>  // For fabs

// Native C Target Functions

/** @brief A simple function that adds two integers. */
int add_ints(int a, int b) {
    return a + b;
}

/** @brief A simple function that multiplies two floats. */
float multiply_floats(float a, float b) {
    return a * b;
}

/** @brief A simple function with no arguments or return value. */
void do_nothing() {
    // This function is called for its side effect, which is verified by `pass()`.
    pass("void(void) function was successfully called.");
}

/** @brief A function to check if an integer is negative. Used for sign-extension tests. */
bool is_negative(int val) {
    note("is_negative() received value: %d", val);
    return val < 0;
}

TEST {
    plan(4);  // One subtest for each simple signature.

    subtest("int(int, int)") {
        plan(2);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
        int a = 10, b = 25;
        int result = 0;
        void * args[] = {&a, &b};
        cif_func((void *)add_ints, &result, args);
        ok(result == 35, "add_ints(10, 25) returned 35");

        infix_forward_destroy(trampoline);
    }

    subtest("float(float, float)") {
        plan(2);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
        float a = 2.5f, b = 4.0f;
        float result = 0.0f;
        void * args[] = {&a, &b};
        cif_func((void *)multiply_floats, &result, args);
        ok(fabs(result - 10.0f) < 0.001, "multiply_floats(2.5, 4.0) returned 10.0");

        infix_forward_destroy(trampoline);
    }

    subtest("void(void)") {
        plan(2);  // One for creation, one for the side-effect `pass()` in the target.
        infix_type * ret_type = infix_type_create_void();
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, NULL, 0, 0);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
        cif_func((void *)do_nothing, NULL, NULL);

        infix_forward_destroy(trampoline);
    }

    subtest("Argument Sign-Extension: bool(int)") {
        plan(3);
        note("Verifying that negative integers are correctly sign-extended.");
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);

        // Test case 1: Negative number
        int neg_val = -100;
        bool neg_result = false;
        void * neg_args[] = {&neg_val};
        cif_func((void *)is_negative, &neg_result, neg_args);
        ok(neg_result == true, "is_negative(-100) returned true");

        // Test case 2: Positive number
        int pos_val = 100;
        bool pos_result = true;
        void * pos_args[] = {&pos_val};
        cif_func((void *)is_negative, &pos_result, pos_args);
        ok(pos_result == false, "is_negative(100) returned false");

        infix_forward_destroy(trampoline);
    }
}
