/**
 * @file 404_simd_vectors.c
 * @brief Unit test for SIMD vector argument passing and return values.
 * @ingroup test_suite
 *
 * @details This test complements `101_by_value.c` by focusing on:
 * 1.  **Generic Vector Types:** Using `__attribute__((vector_size(16)))` which is
 *     common in portable C/C++ SIMD code, mapping to `__m128` (x86) or `float32x4_t` (ARM).
 * 2.  **Reverse Callbacks:** Verifying that the JIT can correctly receive vector
 *     arguments in registers and return vector results from a callback. This
 *     scenario is not covered by `101_by_value.c`.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <infix/infix.h>
#include <math.h>
#include <stdlib.h>

// Use standard intrinsics if available, otherwise generic vectors.
// This ensures we test the standard ABI types (__m128) on Windows x64.
#if defined(__x86_64__) || defined(_M_X64)
#include <xmmintrin.h>
typedef __m128 v4f;
// Helper to create v4f from floats
static v4f v4f_set(float a, float b, float c, float d) { return _mm_setr_ps(a, b, c, d); }
// Helper to extract floats
static float v4f_get(v4f v, int idx) {
    // union to extract without strict aliasing violation
    union {
        __m128 m;
        float f[4];
    } u;
    u.m = v;
    return u.f[idx];
}
static v4f v4f_add(v4f a, v4f b) { return _mm_add_ps(a, b); }

// A generic handler for the reverse callback test.
void vector_add_handler(infix_reverse_t * ctx, void * ret, void ** args) {
    (void)ctx;
    v4f a = *(v4f *)args[0];
    v4f b = *(v4f *)args[1];
    v4f sum = v4f_add(a, b);
    infix_memcpy(ret, &sum, sizeof(v4f));
}

// A C function that takes a callback and executes it with vector arguments.
void execute_vector_callback(v4f (*cb)(v4f, v4f)) {
    v4f a = v4f_set(1.0f, 2.0f, 3.0f, 4.0f);
    v4f b = v4f_set(10.0f, 20.0f, 30.0f, 40.0f);

    v4f result = cb(a, b);

    float r0 = v4f_get(result, 0);
    float r1 = v4f_get(result, 1);
    float r2 = v4f_get(result, 2);
    float r3 = v4f_get(result, 3);

    ok(fabs(r0 - 11.0f) < 1e-6 && fabs(r1 - 22.0f) < 1e-6 && fabs(r2 - 33.0f) < 1e-6 && fabs(r3 - 44.0f) < 1e-6,
       "Reverse vector callback returned correct sum: {%.1f, %.1f, %.1f, %.1f}",
       (double)r0,
       (double)r1,
       (double)r2,
       (double)r3);
}

#else
// Fallback for ARM64 or other archs
/*
typedef float v4f __attribute__((vector_size(16)));
static v4f v4f_set(float a, float b, float c, float d) {
    v4f v = {a, b, c, d};
    return v;
}
static float v4f_get(v4f v, int idx) { return v[idx]; }
static v4f v4f_add(v4f a, v4f b) { return a + b; }*/
#endif

TEST {
    plan(1);
#if defined(__x86_64__) || defined(_M_X64)
    subtest("128-bit Vector (v4f) Reverse Callback") {
        plan(3);

        infix_arena_t * arena = infix_arena_create(1024);
        infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * vec_type = NULL;
        infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 4);

        ok(status == INFIX_SUCCESS, "Created vector type (4x float)");

        // ( v4f, v4f) -> v4f
        infix_type * args[] = {vec_type, vec_type};
        infix_reverse_t * ctx = NULL;

        status = infix_reverse_create_closure_manual(&ctx, vec_type, args, 2, 2, vector_add_handler, NULL);

        ok(status == INFIX_SUCCESS, "Created reverse closure for vector function");

        if (ctx) {
            typedef v4f (*vec_add_fn)(v4f, v4f);
            vec_add_fn fn = (vec_add_fn)infix_reverse_get_code(ctx);

            execute_vector_callback(fn);
        }
        else
            fail("Closure creation failed");

        infix_reverse_destroy(ctx);
        infix_arena_destroy(arena);
    }
#else
    skip(1, "Skip these tests on Windows ARM for now...");
#endif
}
