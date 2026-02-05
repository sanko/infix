/**
 * @file 406_simd_forward.c
 * @brief Unit test for forward SIMD vector calls.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/platform.h"
#include <infix/infix.h>
#include <math.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include <stdalign.h>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

NOINLINE __m128 v4f_add_c(__m128 a, __m128 b) { return _mm_add_ps(a, b); }

NOINLINE float v4f_add_4_floats(float a, float b, float c, float d) { return a + b + c + d; }

NOINLINE int v4f_check_c(__m128 a) {
    union {
        __m128 m;
        float f[4];
    } u;
    u.m = a;
    if (fabs(u.f[0] - 1.0f) < 1e-6 && fabs(u.f[3] - 4.0f) < 1e-6)
        return 42;
    return 0;
}

NOINLINE __m256 v8f_add_c(__m256 a, __m256 b) { return _mm256_add_ps(a, b); }

#endif

TEST {
    plan(4);
#if defined(__x86_64__) || defined(_M_X64)
    subtest("128-bit Vector (v4f) Forward Call") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(2048);
        infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * vec_type = NULL;
        infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 4);
        ok(status == INFIX_SUCCESS, "Created vector type (4x float)");

        infix_forward_t * forward = NULL;
        infix_type * args[] = {vec_type, vec_type};
        status = infix_forward_create_manual(&forward, vec_type, args, 2, 2, (void *)v4f_add_c);
        ok(status == INFIX_SUCCESS, "Created forward trampoline for v4f_add_c");

        if (forward) {
            infix_cif_func cif = infix_forward_get_code(forward);
            alignas(16) __m128 a = _mm_setr_ps(1.0f, 2.0f, 3.0f, 4.0f);
            alignas(16) __m128 b = _mm_setr_ps(10.0f, 20.0f, 30.0f, 40.0f);
            alignas(16) __m128 res = _mm_setzero_ps();
            void * call_args[] = {&a, &b};
            cif(&res, call_args);

            union {
                __m128 m;
                float f[4];
            } u;
            u.m = res;
            ok(fabs(u.f[0] - 11.0f) < 1e-6 && fabs(u.f[3] - 44.0f) < 1e-6, "Forward call returned correct sum");
        }
        infix_forward_destroy(forward);
        infix_arena_destroy(arena);
    }

    subtest("4 floats Argument Passing") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(2048);
        infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * args[] = {float_type, float_type, float_type, float_type};

        infix_forward_t * forward = NULL;
        infix_status status = infix_forward_create_manual(&forward, float_type, args, 4, 4, (void *)v4f_add_4_floats);
        ok(status == INFIX_SUCCESS, "Created forward trampoline for v4f_add_4_floats");

        if (forward) {
            infix_cif_func cif = infix_forward_get_code(forward);
            float a = 1.0f, b = 2.0f, c = 3.0f, d = 4.0f;
            float res = 0.0f;
            void * call_args[] = {&a, &b, &c, &d};
            cif(&res, call_args);
            ok(fabs(res - 10.0f) < 1e-6, "4 floats passed correctly (got %.1f)", (double)res);
        }
        infix_forward_destroy(forward);
        infix_arena_destroy(arena);
    }

    subtest("128-bit Vector (v4f) Argument Passing") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(2048);
        infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * vec_type = NULL;
        infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 4);
        ok(status == INFIX_SUCCESS, "Created vector type (4x float)");
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);

        infix_forward_t * forward = NULL;
        infix_type * args[] = {vec_type};
        status = infix_forward_create_manual(&forward, ret_type, args, 1, 1, (void *)v4f_check_c);
        ok(status == INFIX_SUCCESS, "Created forward trampoline for v4f_check_c");

        if (forward) {
            infix_cif_func cif = infix_forward_get_code(forward);
            alignas(16) __m128 a = _mm_setr_ps(1.0f, 2.0f, 3.0f, 4.0f);
            int res = 0;
            void * call_args[] = {&a};
            cif(&res, call_args);
            ok(res == 42, "Argument passed correctly (got %d)", res);
        }
        infix_forward_destroy(forward);
        infix_arena_destroy(arena);
    }

    if (infix_cpu_has_avx2()) {
        subtest("256-bit Vector (v8f) Forward Call") {
            plan(3);
            infix_arena_t * arena = infix_arena_create(2048);
            infix_type * float_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
            infix_type * vec_type = NULL;
            infix_status status = infix_type_create_vector(arena, &vec_type, float_type, 8);
            ok(status == INFIX_SUCCESS, "Created vector type (8x float)");

            infix_forward_t * forward = NULL;
            infix_type * args[] = {vec_type, vec_type};
            status = infix_forward_create_manual(&forward, vec_type, args, 2, 2, (void *)v8f_add_c);
            ok(status == INFIX_SUCCESS, "Created forward trampoline for v8f_add_c");

            if (forward) {
                infix_cif_func cif = infix_forward_get_code(forward);
                alignas(32) __m256 a = _mm256_setr_ps(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f);
                alignas(32) __m256 b = _mm256_setr_ps(10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f);
                alignas(32) __m256 res = _mm256_setzero_ps();
                void * call_args[] = {&a, &b};
                cif(&res, call_args);

                union {
                    __m256 m;
                    float f[8];
                } u;
                u.m = res;
                ok(fabs(u.f[0] - 11.0f) < 1e-6 && fabs(u.f[7] - 88.0f) < 1e-6, "Forward call returned correct sum");
            }
            infix_forward_destroy(forward);
            infix_arena_destroy(arena);
        }
    }
    else {
        subtest("256-bit Vector (v8f) Forward Call") {
            plan(1);
            skip(1, "CPU does not support AVX2");
        }
    }
#else
    skip(4, "SIMD tests only for x86-64");
#endif
}