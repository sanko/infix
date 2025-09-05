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
 * 3.  **Passing NULL Pointers:** A `NULL` pointer is passed to a native
 *     function to ensure it is transmitted correctly without being corrupted
 *     or causing a crash.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <math.h>    // Added for fabs()
#include <string.h>  // For strcmp and strchr

// Native C Target Functions
/** @brief A `strchr`-like function to test pointer arguments and return values. */
const char * find_char_in_string(const char * s, int c) {
    note("find_char_in_string received: s=\"%s\", c='%c'", s ? s : "(null)", (char)c);
    if (s == NULL)
        return NULL;
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

/** @brief Checks if the pointer it received is NULL. */
bool check_if_null(void * ptr) {
    return ptr == NULL;
}

TEST {
    plan(3);

    subtest("Passing and returning pointers") {
        plan(2);
        ffi_type * ret_type = ffi_type_create_pointer();
        ffi_type * arg_types[] = {ffi_type_create_pointer(), ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)};
        ffi_trampoline_t * trampoline = NULL;
        ffi_status status = generate_forward_trampoline(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == FFI_SUCCESS, "Trampoline created successfully");

        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        const char * str = "Hello, FFI World!";
        int char_to_find = 'F';
        const char * result = NULL;
        // The `args` array must contain pointers to the actual arguments.
        void * args[] = {&str, &char_to_find};

        cif_func((void *)find_char_in_string, &result, args);

        ok(result != NULL && strcmp(result, "FFI World!") == 0,
           "find_char_in_string returned the correct pointer offset");
        diag("Returned substring: \"%s\"", result ? result : "(null)");

        ffi_trampoline_free(trampoline);
    }

    subtest("Modifying data via pointer arguments") {
        plan(2);
        ffi_type * ret_type = ffi_type_create_void();
        ffi_type * arg_types[] = {ffi_type_create_pointer(), ffi_type_create_pointer()};
        ffi_trampoline_t * trampoline = NULL;
        ffi_status status = generate_forward_trampoline(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == FFI_SUCCESS, "Trampoline created successfully");

        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        int val_a = 1;
        double val_b = 2.0;
        int * ptr_a = &val_a;
        double * ptr_b = &val_b;

        // The arguments are the pointers themselves (ptr_a, ptr_b).
        // The `args` array must hold the addresses of these pointers.
        void * args[] = {&ptr_a, &ptr_b};

        cif_func((void *)modify_data_via_pointers, NULL, args);

        ok(val_a == 123 && fabs(val_b - 456.7) < 0.001, "Data was correctly modified by the callee via pointers");
        diag("After call: val_a = %d, val_b = %f", val_a, val_b);

        ffi_trampoline_free(trampoline);
    }

    subtest("Passing NULL pointers") {
        plan(3);
        ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_BOOL);
        ffi_type * arg_types[] = {ffi_type_create_pointer()};
        ffi_trampoline_t * trampoline = NULL;
        ffi_status status = generate_forward_trampoline(&trampoline, ret_type, arg_types, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline created successfully");

        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

        // Case 1: Pass a NULL pointer
        void * null_ptr = NULL;
        bool result_is_null = false;
        void * args_null[] = {&null_ptr};
        cif_func((void *)check_if_null, &result_is_null, args_null);
        ok(result_is_null == true, "NULL pointer was correctly passed as NULL");

        // Case 2: Pass a valid pointer
        int dummy_data = 42;
        void * valid_ptr = &dummy_data;
        bool result_is_valid = true;
        void * args_valid[] = {&valid_ptr};
        cif_func((void *)check_if_null, &result_is_valid, args_valid);
        ok(result_is_valid == false, "Non-NULL pointer was correctly passed as non-NULL");

        ffi_trampoline_free(trampoline);
    }
}
