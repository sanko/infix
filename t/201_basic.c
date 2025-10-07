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
 * @file 201_basic.c
 * @brief Tests fundamental FFI operations involving pointers.
 *
 * @details This test suite verifies that the library can correctly handle
 * pointers as both arguments and return values. It covers three essential
 * scenarios:
 *
 * 1.  **Passing and Returning Pointers:** A function similar to `strchr` is
 *     called to ensure that a pointer passed into a function and a pointer
 *     returned from a function both retain their correct values.
 *
 * 2.  **Modifying Data Via Pointers:** A function is called with pointers to
 *     local variables. The test verifies that the native function can
 *     dereference these pointers and modify the original data in the caller's
 *     stack frame, a common C idiom.
 *
 * 3.  **Passing nullptr Pointers:** A `nullptr` pointer is passed to a native
 *     function to ensure it is transmitted correctly without being corrupted
 *     or causing a crash.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>    // Added for fabs()
#include <string.h>  // For strcmp and strchr

// Native C Target Functions
/** @brief A `strchr`-like function to test pointer arguments and return values. */
const char * find_char_in_string(const char * s, int c) {
    note("find_char_in_string received: s=\"%s\", c='%c'", s ? s : "(null)", (char)c);
    if (s == nullptr)
        return nullptr;
    return strchr(s, c);
}
/** @brief Modifies the data pointed to by its arguments. */
void modify_data_via_pointers(int * a, double * b) {
    note("modify_data_via_pointers received pointers: a=%p, b=%p", (void *)a, (void *)b);
    if (a)
        *a = 123;
    if (b)
        *b = 456.7;
}

/** @brief Checks if the pointer it received is nullptr. */
bool check_if_null(void * ptr) {
    return ptr == nullptr;
}

TEST {
    plan(3);

    subtest("Passing and returning pointers") {
        plan(4);
        infix_type * ret_type = infix_type_create_pointer();
        infix_type * arg_types[] = {infix_type_create_pointer(), infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        const char * str = "Hello, FFI World!";
        int char_to_find = 'F';
        void * args[] = {&str, &char_to_find};

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        const char * unbound_result = nullptr;
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)find_char_in_string, &unbound_result, args);
        ok(unbound_result && strcmp(unbound_result, "FFI World!") == 0, "Unbound call correct");

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)find_char_in_string) ==
               INFIX_SUCCESS,
           "Bound created");
        const char * bound_result = nullptr;
        infix_bound_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result && strcmp(bound_result, "FFI World!") == 0, "Bound call correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }

    subtest("Modifying data via pointer arguments") {
        plan(4);
        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_pointer(), infix_type_create_pointer()};
        int val_a = 1;
        double val_b = 2.0;
        int * ptr_a = &val_a;
        double * ptr_b = &val_b;
        void * args[] = {&ptr_a, &ptr_b};

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)modify_data_via_pointers, nullptr, args);
        ok(val_a == 123 && fabs(val_b - 456.7) < 0.001, "Unbound call correct");
        val_a = 1;
        val_b = 2.0;  // Reset for next test

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)modify_data_via_pointers) ==
               INFIX_SUCCESS,
           "Bound created");
        infix_bound_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(nullptr, args);
        ok(val_a == 123 && fabs(val_b - 456.7) < 0.001, "Bound call correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }

    subtest("Passing nullptr pointers") {
        plan(6);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_type * arg_types[] = {infix_type_create_pointer()};
        void * null_ptr = nullptr;
        int dummy_data = 42;
        void * valid_ptr = &dummy_data;
        void * args_null[] = {&null_ptr};
        void * args_valid[] = {&valid_ptr};
        bool res_null, res_valid;

        // Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 1, 1) == INFIX_SUCCESS,
           "Unbound created");
        infix_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)check_if_null, &res_null, args_null);
        ok(res_null == true, "Unbound nullptr correct");
        unbound_cif((void *)check_if_null, &res_valid, args_valid);
        ok(res_valid == false, "Unbound non-nullptr correct");

        // Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 1, 1, (void *)check_if_null) == INFIX_SUCCESS,
           "Bound created");
        infix_bound_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&res_null, args_null);
        ok(res_null == true, "Bound nullptr correct");
        bound_cif(&res_valid, args_valid);
        ok(res_valid == false, "Bound non-nullptr correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
}
