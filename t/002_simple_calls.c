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
        plan(4);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        int a = 10, b = 25;
        void * args[] = {&a, &b};

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        int unbound_result = 0;
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)add_ints, &unbound_result, args);
        ok(unbound_result == 35, "Unbound call correct");
        infix_forward_destroy(unbound_t);

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)add_ints) == INFIX_SUCCESS,
           "Bound created");
        int bound_result = 0;
        infix_bound_cif_func bound_cif = infix_forward_get_bound_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result == 35, "Bound call correct");
        infix_forward_destroy(bound_t);
    }

    subtest("float(float, float)") {
        plan(4);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};
        float a = 2.5f, b = 4.0f;
        void * args[] = {&a, &b};

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        float unbound_result = 0.0f;
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)multiply_floats, &unbound_result, args);
        ok(fabs(unbound_result - 10.0f) < 0.001, "Unbound call correct");
        infix_forward_destroy(unbound_t);

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)multiply_floats) == INFIX_SUCCESS,
           "Bound created");
        float bound_result = 0.0f;
        infix_bound_cif_func bound_cif = infix_forward_get_bound_code(bound_t);
        bound_cif(&bound_result, args);
        ok(fabs(bound_result - 10.0f) < 0.001, "Bound call correct");
        infix_forward_destroy(bound_t);
    }

    subtest("void(void)") {
        plan(4);  // Two for creation, two for the side-effect `pass()` calls.
        infix_type * ret_type = infix_type_create_void();

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Unbound created");
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)do_nothing, nullptr, nullptr);
        infix_forward_destroy(unbound_t);

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, nullptr, 0, 0, (void *)do_nothing) == INFIX_SUCCESS,
           "Bound created");
        infix_bound_cif_func bound_cif = infix_forward_get_bound_code(bound_t);
        bound_cif(nullptr, nullptr);
        infix_forward_destroy(bound_t);
    }

    subtest("Argument Sign-Extension: bool(int)") {
        plan(6);
        note("Verifying that negative integers are correctly sign-extended.");
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        int neg_val = -100, pos_val = 100;
        void * neg_args[] = {&neg_val};
        void * pos_args[] = {&pos_val};

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 1, 1) == INFIX_SUCCESS,
           "Unbound created");
        bool neg_result_u = false, pos_result_u = true;
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)is_negative, &neg_result_u, neg_args);
        ok(neg_result_u == true, "Unbound is_negative(-100) returned true");
        unbound_cif((void *)is_negative, &pos_result_u, pos_args);
        ok(pos_result_u == false, "Unbound is_negative(100) returned false");
        infix_forward_destroy(unbound_t);

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 1, 1, (void *)is_negative) == INFIX_SUCCESS,
           "Bound created");
        bool neg_result_b = false, pos_result_b = true;
        infix_bound_cif_func bound_cif = infix_forward_get_bound_code(bound_t);
        bound_cif(&neg_result_b, neg_args);
        ok(neg_result_b == true, "Bound is_negative(-100) returned true");
        bound_cif(&pos_result_b, pos_args);
        ok(pos_result_b == false, "Bound is_negative(100) returned false");
        infix_forward_destroy(bound_t);
    }
}
