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

// --- AVX (256-bit) ---
typedef __m256 v8f;
static v8f v8f_set(float f0, float f1, float f2, float f3, float f4, float f5, float f6, float f7) {
    return _mm256_setr_ps(f0, f1, f2, f3, f4, f5, f6, f7);
}
static float v8f_get(v8f v, int idx) {
    union {
        __m256 m;
        float f[8];
    } u;
    u.m = v;
    return u.f[idx];
}
static v8f v8f_add(v8f a, v8f b) { return _mm256_add_ps(a, b); }

void v8f_add_handler(infix_reverse_t * ctx, void * ret, void ** args) {
    (void)ctx;
    // On Windows, 256-bit vectors are always passed by reference
    v8f a = _mm256_loadu_ps((float *)args[0]);
    v8f b = _mm256_loadu_ps((float *)args[1]);
    v8f sum = v8f_add(a, b);
    _mm256_storeu_ps((float *)ret, sum);
}

void execute_v8f_callback(v8f (*cb)(v8f, v8f)) {
    note("Setting up vectors a and b");
    v8f a = v8f_set(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f);
    v8f b = v8f_set(10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f);
    note("Calling JIT-compiled callback");
    v8f result = cb(a, b);
    note("Callback returned successfully");
    bool pass = true;
    for (int i = 0; i < 8; i++) {
        float expected = (float)(i + 1) + (float)((i + 1) * 10);
        if (fabs(v8f_get(result, i) - expected) > 1e-6)
            pass = false;
    }
    ok(pass, "AVX (v8f) reverse callback returned correct sum");
}

#endif

TEST {
#if defined(__x86_64__) || defined(_M_X64)
    if (infix_cpu_has_avx2()) {
        plan(1);
        subtest("AVX (256-bit) Reverse Callback") {
            plan(3);
            infix_arena_t * arena = infix_arena_create(2048);
            infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
            infix_type * vec_type = NULL;
            infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 8);
            ok(status == INFIX_SUCCESS, "Created vector type (8x float)");

            infix_type * args[] = {vec_type, vec_type};
            infix_reverse_t * ctx = NULL;
            status = infix_reverse_create_closure_manual(&ctx, vec_type, args, 2, 2, v8f_add_handler, NULL);
            ok(status == INFIX_SUCCESS, "Created reverse closure for AVX v8f function");

            if (ctx) {
                typedef v8f (*v8f_add_fn)(v8f, v8f);
                execute_v8f_callback((v8f_add_fn)infix_reverse_get_code(ctx));
            }
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
    skip(1, "SIMD tests only implemented for x86-64");
#endif
}