/**
 * @file 201_basic.c
 * @brief Unit test for FFI calls involving pointer types.
 * @ingroup test_suite
 *
 * @details This test file verifies that the `infix` library correctly handles
 * pointer arguments and return values. Pointers are fundamental to C, and their
 * correct handling (passing by value, dereferencing) is critical for any FFI library.
 *
 * The test covers three key scenarios:
 *
 * 1.  **Passing and Returning Pointers:** A call is made to a C function that
 *     takes a `const char*` and returns a `const char*` (the result of `strchr`).
 *     This validates that pointer values themselves are passed and returned correctly.
 *
 * 2.  **Modifying Data Via Pointers:** A call is made to a C function that takes
 *     pointers to an `int` and a `double` (`int*`, `double*`) and modifies the
 *     data at those addresses. This verifies that the JIT-compiled code correctly
 *     passes the pointers, allowing the callee to dereference them and modify the
 *     caller's original data.
 *
 * 3.  **Passing `nullptr`:** Verifies that a `NULL` pointer can be correctly
 *     passed through the FFI boundary and is received as `NULL` by the callee.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>
// Native C Functions for Testing
/** @brief A C function that takes a string and a character, and returns a pointer into the string. */
const char * find_char_in_string(const char * s, int c) {
    note("find_char_in_string received: s=\"%s\", c='%c'", s ? s : "(null)", (char)c);
    if (s == nullptr)
        return nullptr;
    return strchr(s, c);
}
/** @brief A C function that modifies the caller's data through pointers. */
void modify_data_via_pointers(int * a, double * b) {
    note("modify_data_via_pointers received pointers: a=%p, b=%p", (void *)a, (void *)b);
    if (a)
        *a = 123;
    if (b)
        *b = 456.7;
}
/** @brief A simple helper to check if a received pointer is NULL. */
bool check_if_null(void * ptr) { return ptr == nullptr; }
TEST {
    plan(3);
    subtest("Passing and returning pointers") {
        plan(4);
        // Signature: "(*char, int) -> *char"
        infix_type * ret_type = infix_type_create_pointer();
        infix_type * arg_types[] = {infix_type_create_pointer(), infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        const char * str = "Hello, FFI World!";
        int char_to_find = 'F';
        void * args[] = {&str, &char_to_find};
        // Test Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        const char * unbound_result = nullptr;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)find_char_in_string, &unbound_result, args);
        ok(unbound_result && strcmp(unbound_result, "FFI World!") == 0, "Unbound call correct");
        // Test Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)find_char_in_string) ==
               INFIX_SUCCESS,
           "Bound created");
        const char * bound_result = nullptr;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result && strcmp(bound_result, "FFI World!") == 0, "Bound call correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
    subtest("Modifying data via pointer arguments") {
        plan(4);
        // Signature: "(void*, void*) -> void"
        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_pointer(), infix_type_create_pointer()};
        int val_a = 1;
        double val_b = 2.0;
        int * ptr_a = &val_a;
        double * ptr_b = &val_b;
        void * args[] = {&ptr_a, &ptr_b};
        // Test Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)modify_data_via_pointers, nullptr, args);
        ok(val_a == 123 && fabs(val_b - 456.7) < 0.001, "Unbound call correct");
        val_a = 1;
        val_b = 2.0;  // Reset for next test
        // Test Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)modify_data_via_pointers) ==
               INFIX_SUCCESS,
           "Bound created");
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(nullptr, args);
        ok(val_a == 123 && fabs(val_b - 456.7) < 0.001, "Bound call correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
    subtest("Passing nullptr pointers") {
        plan(6);
        // Signature: "(*void) -> bool"
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_type * arg_types[] = {infix_type_create_pointer()};
        void * null_ptr = nullptr;
        int dummy_data = 42;
        void * valid_ptr = &dummy_data;
        void * args_null[] = {&null_ptr};
        void * args_valid[] = {&valid_ptr};
        bool res_null, res_valid;
        // Test Unbound
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 1, 1) == INFIX_SUCCESS,
           "Unbound created");
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)check_if_null, &res_null, args_null);
        ok(res_null == true, "Unbound nullptr correct");
        unbound_cif((void *)check_if_null, &res_valid, args_valid);
        ok(res_valid == false, "Unbound non-nullptr correct");
        // Test Bound
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 1, 1, (void *)check_if_null) == INFIX_SUCCESS,
           "Bound created");
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&res_null, args_null);
        ok(res_null == true, "Bound nullptr correct");
        bound_cif(&res_valid, args_valid);
        ok(res_valid == false, "Bound non-nullptr correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
}
