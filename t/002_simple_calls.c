/**
 * @file 002_simple_calls.c
 * @brief Unit test for basic forward trampoline calls with simple function signatures.
 * @ingroup test_suite
 *
 * @details This test file verifies that the `infix` library can correctly create and
 * execute forward trampolines for functions with simple, primitive arguments and
 * return types. It covers:
 * - `int(int, int)`: Basic integer arithmetic.
 * - `float(float, float)`: Basic floating-point arithmetic.
 * - `void(void)`: Functions with no arguments or return value.
 * - `bool(int)`: A test to specifically verify correct sign-extension of integer
 *   arguments that are smaller than a full register.
 *
 * For each signature, it tests both **bound** and **unbound** trampolines to ensure
 * both creation paths and calling conventions are working correctly.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>

// C Functions to be Called via FFI
/** @internal @brief A simple C function for testing integer arguments and return values. */
int add_ints(int a, int b) { return a + b; }
/** @internal @brief A simple C function for testing float arguments and return values. */
float multiply_floats(float a, float b) { return a * b; }
/** @internal @brief A C function with no arguments or return value, for testing void calls. */
void do_nothing() { pass("void(void) function was successfully called."); }
/** @internal @brief A C function to test that integer arguments are correctly sign-extended by the ABI. */
bool is_negative(int val) {
    note("is_negative() received value: %d", val);
    return val < 0;
}
TEST {
    plan(4);
    subtest("int(int, int)") {
        plan(4);
        // 1. Define the signature programmatically using the Manual API.
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        int a = 10, b = 25;
        void * args[] = {&a, &b};
        // 2. Test the unbound trampoline.
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        int unbound_result = 0;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)add_ints, &unbound_result, args);
        ok(unbound_result == 35, "Unbound call correct");
        infix_forward_destroy(unbound_t);
        // 3. Test the bound trampoline.
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)add_ints) == INFIX_SUCCESS,
           "Bound created");
        int bound_result = 0;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
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
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Unbound created");
        float unbound_result = 0.0f;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)multiply_floats, &unbound_result, args);
        ok(fabs(unbound_result - 10.0f) < 0.001, "Unbound call correct");
        infix_forward_destroy(unbound_t);
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)multiply_floats) == INFIX_SUCCESS,
           "Bound created");
        float bound_result = 0.0f;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(fabs(bound_result - 10.0f) < 0.001, "Bound call correct");
        infix_forward_destroy(bound_t);
    }
    subtest("void(void)") {
        plan(4);
        infix_type * ret_type = infix_type_create_void();
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Unbound created");
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)do_nothing, nullptr, nullptr);
        infix_forward_destroy(unbound_t);
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, nullptr, 0, 0, (void *)do_nothing) == INFIX_SUCCESS,
           "Bound created");
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(nullptr, nullptr);
        infix_forward_destroy(bound_t);
    }
    subtest("Argument Sign-Extension: bool(int)") {
        plan(6);
        note("Verifying that negative integers are correctly sign-extended when passed as arguments.");
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        int neg_val = -100, pos_val = 100;
        void * neg_args[] = {&neg_val};
        void * pos_args[] = {&pos_val};
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 1, 1) == INFIX_SUCCESS,
           "Unbound created");
        bool neg_result_u = false, pos_result_u = true;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)is_negative, &neg_result_u, neg_args);
        ok(neg_result_u == true, "Unbound is_negative(-100) returned true");
        unbound_cif((void *)is_negative, &pos_result_u, pos_args);
        ok(pos_result_u == false, "Unbound is_negative(100) returned false");
        infix_forward_destroy(unbound_t);
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, ret_type, arg_types, 1, 1, (void *)is_negative) == INFIX_SUCCESS,
           "Bound created");
        bool neg_result_b = false, pos_result_b = true;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&neg_result_b, neg_args);
        ok(neg_result_b == true, "Bound is_negative(-100) returned true");
        bound_cif(&pos_result_b, pos_args);
        ok(pos_result_b == false, "Bound is_negative(100) returned false");
        infix_forward_destroy(bound_t);
    }
}
