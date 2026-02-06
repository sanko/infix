/**
 * @file 405_simd_vectors_avx.c
 * @brief Unit test for 256-bit (AVX) SIMD vector support.
 * @ingroup test_suite
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "common/platform.h"
#include <infix/infix.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>

#if defined(__AVX__)
// AVX (256-bit)
typedef __m256 v8f;

void v8f_add_handler(infix_reverse_t * ctx, void * ret, void ** args) {

    (void)ctx;

    // On Windows, 256-bit vectors are always passed by reference

    v8f a = _mm256_loadu_ps((float *)args[0]);

    v8f b = _mm256_loadu_ps((float *)args[1]);

    _mm256_storeu_ps((float *)ret, _mm256_add_ps(a, b));
}

void execute_v8f_callback(infix_type * vec_type, void * cb_code) {

    v8f * a = (v8f *)_mm_malloc(sizeof(v8f), 32);

    v8f * b = (v8f *)_mm_malloc(sizeof(v8f), 32);

    if (!a || !b)
        tap_bail_out("Allocation failed");

    float a_vals[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};

    float b_vals[8] = {10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f};

    *a = _mm256_loadu_ps(a_vals);

    *b = _mm256_loadu_ps(b_vals);

    infix_type * arg_types[] = {vec_type, vec_type};

    infix_forward_t * call_stub = NULL;

    infix_status status = infix_forward_create_manual(&call_stub, vec_type, arg_types, 2, 2, cb_code);

    ok(status == INFIX_SUCCESS, "Created forward trampoline for AVX call");

    if (call_stub) {

        v8f result;

        void * call_args[] = {a, b};

        infix_cif_func call_fn = infix_forward_get_code(call_stub);

        call_fn(&result, call_args);

        float res_data[8];

        _mm256_storeu_ps(res_data, result);

        bool pass = true;

        for (int i = 0; i < 8; i++) {

            float expected = (float)(i + 1) + (float)((i + 1) * 10);

            if (fabs(res_data[i] - expected) > 1e-6)

                pass = false;
        }

        ok(pass, "AVX (v8f) reverse callback returned correct sum");

        infix_forward_destroy(call_stub);
    }

    _mm_free(a);

    _mm_free(b);
}
#endif

#endif

TEST {
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__AVX__)
    if (infix_cpu_has_avx2()) {
        plan(1);
        subtest("AVX (256-bit) Reverse Callback") {
            plan(4);
            infix_arena_t * arena = infix_arena_create(2048);
            infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
            infix_type * vec_type = NULL;
            infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 8);
            ok(status == INFIX_SUCCESS, "Created vector type (8x float)");

            infix_type * args[] = {vec_type, vec_type};
            infix_reverse_t * ctx = NULL;
            status = infix_reverse_create_closure_manual(&ctx, vec_type, args, 2, 2, v8f_add_handler, NULL);
            ok(status == INFIX_SUCCESS, "Created reverse closure for AVX v8f function");

            if (ctx)
                execute_v8f_callback(vec_type, infix_reverse_get_code(ctx));
            infix_reverse_destroy(ctx);
            infix_arena_destroy(arena);
        }
    }
    else {
        plan(1);
        skip(1, "CPU does not support AVX2");
    }
#else
    plan(1);
    skip(1, "AVX support not enabled at compile-time (missing flags?)");
#endif
#else
    plan(1);
    skip(1, "SIMD tests only implemented for x86-64");
#endif
}
