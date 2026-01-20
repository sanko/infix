/**
 * @file 203_complex.c
 * @brief Unit test for FFI calls involving C99 `_Complex` types.
 * @ingroup test_suite
 *
 * @details This test verifies that `infix` correctly handles the C99 `_Complex`
 * number types, which are not supported by all compilers (notably MSVC). The
 * entire test is conditionally compiled to run only on platforms that support
 * this feature.
 *
 * A `_Complex double` is typically treated by the ABI as a struct of two doubles:
 * `struct { double real; double imag; }`. Therefore, this test is an important
 * validation of the aggregate classification and handling logic for a specific,
 * standardized C type.
 *
 * The test covers:
 * - **Signature Parsing:** Verifying that the `c[double]` signature is parsed correctly.
 * - **Forward Calls:** Passing `_Complex double` arguments to a C function and
 *   receiving a `_Complex double` return value.
 * - **Reverse Calls:** Creating a callback with a `_Complex double` signature and
 *   verifying that it can be called correctly from C.
 *
 * @note This test is skipped entirely on MSVC.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "types.h"
#include <complex.h>
#include <infix/infix.h>
#include <math.h>

#if !defined(_MSC_VER)  // MSVC does not support the _Complex keyword.
typedef double _Complex complex_double_t;
// Native C Functions for Testing
complex_double_t c_add(complex_double_t a, complex_double_t b) { return a + b; }
complex_double_t c_mul(complex_double_t a, complex_double_t b) { return a * b; }
complex_double_t callback_c_add(complex_double_t a, complex_double_t b) { return a + b; }
/** @brief A C harness to call a complex-number callback and verify the result. */
void execute_complex_callback(complex_double_t (*func_ptr)(complex_double_t, complex_double_t),
                              complex_double_t val_a,
                              complex_double_t val_b,
                              complex_double_t expected_val) {
    complex_double_t result_val = func_ptr(val_a, val_b);
    ok(cabs(result_val - expected_val) < 1e-9, "Callback returned correct complex value");
}
TEST {
    plan(4);
    infix_arena_t * arena = infix_arena_create(4096);
    // 1. Create the `infix_type` for `double _Complex`.
    infix_type * complex_double_type = NULL;
    infix_status status =
        infix_type_create_complex(arena, &complex_double_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE));
    if (!ok(status == INFIX_SUCCESS, "Successfully created infix_type for double _Complex")) {
        skip(3, "Cannot proceed without complex type");
        infix_arena_destroy(arena);
        return;
    }
    subtest("Forward call with _Complex arguments and return") {
        plan(4);
        infix_type * arg_types[] = {complex_double_type, complex_double_type};
        infix_forward_t *t_add = NULL, *t_mul = NULL;
        ok(infix_forward_create_unbound_manual(&t_add, complex_double_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Trampoline for c_add created");
        ok(infix_forward_create_unbound_manual(&t_mul, complex_double_type, arg_types, 2, 2) == INFIX_SUCCESS,
           "Trampoline for c_mul created");
        complex_double_t val_a = 1.0 + 2.0 * I;
        complex_double_t val_b = 3.0 - 4.0 * I;
        void * args[] = {&val_a, &val_b};
        complex_double_t add_result, mul_result;
        infix_unbound_cif_func cif_add = infix_forward_get_unbound_code(t_add);
        cif_add((void *)c_add, &add_result, args);
        ok(cabs(add_result - (4.0 - 2.0 * I)) < 1e-9, "c_add call correct");
        infix_unbound_cif_func cif_mul = infix_forward_get_unbound_code(t_mul);
        cif_mul((void *)c_mul, &mul_result, args);
        ok(cabs(mul_result - (11.0 + 2.0 * I)) < 1e-9, "c_mul call correct");
        infix_forward_destroy(t_add);
        infix_forward_destroy(t_mul);
    }
    subtest("Reverse call (callback) with _Complex types") {
        plan(2);
        infix_type * arg_types[] = {complex_double_type, complex_double_type};
        infix_reverse_t * rt_add = NULL;
        status =
            infix_reverse_create_callback_manual(&rt_add, complex_double_type, arg_types, 2, 2, (void *)callback_c_add);
        if (ok(status == INFIX_SUCCESS, "Reverse trampoline for c_add created")) {
            typedef complex_double_t (*ComplexFunc)(complex_double_t, complex_double_t);
            ComplexFunc cb = (ComplexFunc)infix_reverse_get_code(rt_add);
            execute_complex_callback(cb, 5.0 + 2.0 * I, 1.0 + 1.0 * I, 6.0 + 3.0 * I);
        }
        infix_reverse_destroy(rt_add);
    }
    subtest("Round trip signature parsing") {
        plan(2);
        infix_type * parsed_type = NULL;
        infix_arena_t * parse_arena = NULL;
        status = infix_type_from_signature(&parsed_type, &parse_arena, "c[double]", NULL);
        ok(status == INFIX_SUCCESS && parsed_type != NULL, "Signature 'c[double]' parsed successfully");
        if (parsed_type)
            ok(parsed_type->category == INFIX_TYPE_COMPLEX && parsed_type->size == sizeof(double _Complex),
               "Parsed type has correct category and size");
        else
            fail("Parsed type check failed");
        infix_arena_destroy(parse_arena);
    }
    infix_arena_destroy(arena);
}
#else  // If on MSVC, skip the entire test file.
TEST {
    plan(1);
    skip_all("MSVC does not support the C99 _Complex keyword.");
}
#endif
