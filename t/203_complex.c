/**
 * @file 203_complex.c
 * @brief Tests FFI calls with _Complex number types.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>

#if defined(_MSC_VER)
// MSVC uses non-standard names and functions for complex numbers and does not
// support infix operators. We define macros to abstract the arithmetic.
#include <complex.h>
typedef _Dcomplex double_complex;
typedef _Fcomplex float_complex;
#define create_complex_double(r, i) _Cbuild(r, i)
#define create_complex_float(r, i) _FCbuild(r, i)
#define complex_abs(a) cabs(a)
#define complex_absf(a) cabsf(a)

// Operator replacements for MSVC
#define ADD_CX_DOUBLE(a, b) _Cbuild(creal(a) + creal(b), cimag(a) + cimag(b))
#define SUB_CX_DOUBLE(a, b) _Cbuild(creal(a) - creal(b), cimag(a) - cimag(b))
#define MUL_CX_DOUBLE(a, b) \
    _Cbuild(creal(a) * creal(b) - cimag(a) * cimag(b), creal(a) * cimag(b) + cimag(a) * creal(b))

#define ADD_CX_FLOAT(a, b) _FCbuild(crealf(a) + crealf(b), cimagf(a) + cimagf(b))
#define SUB_CX_FLOAT(a, b) _FCbuild(crealf(a) - crealf(b), cimagf(a) - cimagf(b))

#else
// Standard C99 and later for GCC/Clang which supports infix operators
#include <complex.h>
#include <math.h>
typedef double complex double_complex;
typedef float complex float_complex;
#define create_complex_double(r, i) ((r) + (i) * I)
#define create_complex_float(r, i) ((r) + (i) * I)
#define complex_abs(a) cabs(a)
#define complex_absf(a) cabsf(a)

// On standard compilers, macros map directly to the operators.
#define ADD_CX_DOUBLE(a, b) (a + b)
#define SUB_CX_DOUBLE(a, b) (a - b)
#define MUL_CX_DOUBLE(a, b) (a * b)
#define ADD_CX_FLOAT(a, b) (a + b)
#define SUB_CX_FLOAT(a, b) (a - b)

#endif

// Native C functions to be called via FFI
double_complex multiply_complex_double(double_complex a, double_complex b) {
    return MUL_CX_DOUBLE(a, b);
}

float_complex add_complex_float(float_complex a, float_complex b) {
    return ADD_CX_FLOAT(a, b);
}

// Callback handler
double_complex complex_callback_handler(infix_context_t * context, double_complex a) {
    (void)context;
    return ADD_CX_DOUBLE(a, create_complex_double(1.0, 2.0));
}

TEST {
    plan(3);

    subtest("Forward call with double complex") {
        plan(2);
        const char * signature = "(c[double], c[double]) -> c[double]";
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create(&trampoline, signature);
        ok(status == INFIX_SUCCESS, "Trampoline created for double complex");

        if (trampoline) {
            double_complex a = create_complex_double(2.0, 3.0);
            double_complex b = create_complex_double(4.0, -5.0);
            double_complex expected = MUL_CX_DOUBLE(a, b);
            double_complex result = create_complex_double(0, 0);
            void * args[] = {&a, &b};

            ((infix_cif_func)infix_forward_get_code(trampoline))((void *)multiply_complex_double, &result, args);

            ok(complex_abs(SUB_CX_DOUBLE(result, expected)) < 1e-9, "double complex multiplication is correct");
        }
        else {
            skip(1, "Test skipped");
        }
        infix_forward_destroy(trampoline);
    }

    subtest("Forward call with float complex") {
        plan(2);
        const char * signature = "(c[float], c[float]) -> c[float]";
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create(&trampoline, signature);
        ok(status == INFIX_SUCCESS, "Trampoline created for float complex");

        if (trampoline) {
            float_complex a = create_complex_float(1.5f, 2.5f);
            float_complex b = create_complex_float(3.0f, 4.0f);
            float_complex expected = ADD_CX_FLOAT(a, b);
            float_complex result = create_complex_float(0, 0);
            void * args[] = {&a, &b};

            ((infix_cif_func)infix_forward_get_code(trampoline))((void *)add_complex_float, &result, args);
            ok(complex_absf(SUB_CX_FLOAT(result, expected)) < 1e-6, "float complex addition is correct");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(trampoline);
    }

    subtest("Reverse call (callback) with double complex") {
        plan(2);
        const char * signature = "(c[double]) -> c[double]";
        infix_reverse_t * rt = NULL;
        infix_status status = infix_reverse_create(&rt, signature, (void *)complex_callback_handler, NULL);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created for double complex");

        if (rt) {
            typedef double_complex (*my_callback_t)(double_complex);
            my_callback_t func_ptr = (my_callback_t)infix_reverse_get_code(rt);
            double_complex input = create_complex_double(5.0, 5.0);
            double_complex expected = ADD_CX_DOUBLE(input, create_complex_double(1.0, 2.0));
            double_complex result = func_ptr(input);
            ok(complex_abs(SUB_CX_DOUBLE(result, expected)) < 1e-9, "Callback returned correct double complex value");
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
    }
}
