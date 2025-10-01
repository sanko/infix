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
 * @file 101_by_value.c
 * @brief Tests passing and returning small aggregate types (structs) by value.
 *
 * @details This suite verifies the library's ability to handle one of the most
 * complex aspects of any ABI: the rules for passing and returning structs in
 * CPU registers. The behavior is highly platform-dependent.
 *
 * This file consolidates several previous tests (`008_return_point.c`,
 * `015_struct_with_array.c`, `207_mixed_type_aggr.c`) into a single,
 * cohesive suite with the following goals:
 *
 * 1.  **General Case:** Tests a simple `struct { double; double; }` to verify
 *     basic aggregate handling on all platforms.
 * 2.  **System V x64 Specific:** Tests a `struct { int; double; }`, which the
 *     SysV ABI dictates should be split and passed in one GPR and one XMM register.
 * 3.  **AArch64 (ARM64) Specific:** Tests a `struct { float v[4]; }`, which is a
 *     Homogeneous Floating-point Aggregate (HFA) and should be passed in four
 *     consecutive floating-point registers.
 *
 * Platform-specific tests are conditionally compiled using preprocessor guards to
 * ensure they only run on relevant targets.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // Test-specific type definitions
#include <common/infix_config.h>
#include <infix/infix.h>
#include <math.h>  // For fabs

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>  // For GCC/Clang
#endif

// Native C Target Functions
/** @brief Processes a Point struct passed by value, returning a sum of its members. */
double process_point_by_value(Point p) {
    note("process_point_by_value received p = { .x=%.1f, .y=%.1f }", p.x, p.y);
    return p.x + p.y;
}

/** @brief Returns a Point struct by value. */
Point return_point_by_value(void) {
    return (Point){100.0, 200.0};
}

/** @brief Processes a mixed-type struct, checking its members. (SysV x64 only) */
int process_mixed_struct(MixedIntDouble s) {
    note("process_mixed_struct received: i=%d, d=%.2f", s.i, s.d);
    // This function returns a boolean-like int indicating success.
    return s.i == -500 && fabs(s.d - 3.14) < 0.001;
}

/** @brief Sums the elements of a Vector4 HFA. (AArch64 only) */
float sum_vector4(Vector4 vec) {
    return vec.v[0] + vec.v[1] + vec.v[2] + vec.v[3];
}

// A native C function that adds two 128-bit vectors of doubles.
__m128d native_vector_add(__m128d a, __m128d b) {
    return _mm_add_pd(a, b);
}

TEST {
    plan(4);  // One subtest for each major scenario.

    subtest("Simple struct (Point) passed and returned by value") {
        plan(5);
        infix_arena_t * arena = infix_arena_create(4096);

        // First, create the infix_type for the Point struct. This will be reused.
        infix_struct_member * point_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        point_members[0] =
            infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
        infix_type * point_type = NULL;
        infix_status status = infix_type_create_struct(arena, &point_type, point_members, 2);
        if (!ok(status == INFIX_SUCCESS, "infix_type for Point created successfully")) {
            skip(4, "Cannot proceed without Point type");
            infix_arena_destroy(arena);
            return;
        }

        // Test 1: Pass Point as an argument
        infix_type * arg_ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
        infix_forward_t * arg_trampoline = NULL;
        status = infix_forward_create_manual(&arg_trampoline, arg_ret_type, &point_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for process_point_by_value created");

        infix_cif_func arg_cif = (infix_cif_func)infix_forward_get_code(arg_trampoline);
        Point p_in = {10.5, 20.5};
        double sum_result = 0.0;
        void * arg_args[] = {&p_in};
        arg_cif((void *)process_point_by_value, &sum_result, arg_args);
        ok(fabs(sum_result - 31.0) < 0.001, "Struct passed as argument correctly");
        infix_forward_destroy(arg_trampoline);

        // Test 2: Return Point as a value
        infix_forward_t * ret_trampoline = NULL;
        status = infix_forward_create_manual(&ret_trampoline, point_type, NULL, 0, 0);
        ok(status == INFIX_SUCCESS, "Trampoline for return_point_by_value created");

        infix_cif_func ret_cif = (infix_cif_func)infix_forward_get_code(ret_trampoline);
        Point p_out = {0.0, 0.0};
        ret_cif((void *)return_point_by_value, &p_out, NULL);
        ok(fabs(p_out.x - 100.0) < 0.001 && fabs(p_out.y - 200.0) < 0.001, "Struct returned by value correctly");
        infix_forward_destroy(ret_trampoline);

        infix_arena_destroy(arena);
    }

    subtest("ABI Specific: System V x64 mixed-register struct") {
        plan(2);
        note("Testing struct { int; double; } passed in GPR and XMM registers.");
        infix_arena_t * arena = infix_arena_create(4096);

        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] = infix_type_create_member(
            "i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(MixedIntDouble, i));
        members[1] = infix_type_create_member(
            "d", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(MixedIntDouble, d));
        infix_type * mixed_type = NULL;
        (void)infix_type_create_struct(arena, &mixed_type, members, 2);

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &mixed_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for mixed-type struct created");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
        MixedIntDouble arg_val = {-500, 3.14};
        int result = 0;
        void * args[] = {&arg_val};
        cif_func((void *)process_mixed_struct, &result, args);
        ok(result == 1, "Mixed-type struct was passed correctly");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }

    subtest("ABI Specific: AArch64 Homogeneous Floating-point Aggregate (HFA)") {
        plan(2);
        note("Testing struct { float v[4]; } as an HFA in V0-V3 registers.");
        infix_arena_t * arena = infix_arena_create(4096);

        // Level 1: Create the inner array type float[4]
        infix_type * array_type = NULL;
        infix_status status =
            infix_type_create_array(arena, &array_type, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 4);
        if (status != INFIX_SUCCESS) {
            fail("Failed to create HFA inner array type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        // Level 2: Wrap the array in a struct
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member), _Alignof(infix_struct_member));
        members[0] = infix_type_create_member("v", array_type, offsetof(Vector4, v));
        infix_type * struct_type = NULL;
        status = infix_type_create_struct(arena, &struct_type, members, 1);
        if (status != INFIX_SUCCESS) {
            fail("Failed to create HFA container struct type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        infix_forward_t * trampoline = NULL;
        status = infix_forward_create_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), &struct_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for HFA struct created");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
        Vector4 vec = {{1.5f, 2.5f, 3.5f, 4.5f}};
        float result = 0.0f;
        void * args[] = {&vec};
        cif_func((void *)sum_vector4, &result, args);
        ok(fabs(result - 12.0f) < 0.001, "HFA struct passed correctly");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }

    subtest("ABI Specific: 128-bit SIMD Vector (__m128d)") {
        plan(2);
        // This test will only run on platforms that support SSE2.
#if defined(INFIX_ARCH_X86_SSE2)
        note("Testing __m128d passed and returned by value.");
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Create the infix_type for v[2:double]
        infix_type * vector_type = NULL;
        infix_status status =
            infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 2);

        if (!ok(status == INFIX_SUCCESS, "infix_type for __m128d created successfully")) {
            skip(1, "Cannot proceed without vector type");
            infix_arena_destroy(arena);
            return;
        }

        // 2. Create the trampoline for __m128d(__m128d, __m128d)
        infix_type * arg_types[] = {vector_type, vector_type};
        infix_forward_t * trampoline = NULL;
        status = infix_forward_create_manual(&trampoline, vector_type, arg_types, 2, 2);

        // 3. Prepare arguments and call
        __m128d vec_a = _mm_set_pd(20.0, 10.0);  // Vector [10.0, 20.0]
        __m128d vec_b = _mm_set_pd(22.0, 32.0);  // Vector [32.0, 22.0]
        void * args[] = {&vec_a, &vec_b};

        union {
            __m128d v;
            double d[2];
        } result;
        result.v = _mm_setzero_pd();

        ((infix_cif_func)infix_forward_get_code(trampoline))((void *)native_vector_add, &result.v, args);

        // 4. Verify the result: [10.0+32.0, 20.0+22.0] -> [42.0, 42.0]
        ok(fabs(result.d[0] - 42.0) < 1e-9 && fabs(result.d[1] - 42.0) < 1e-9,
           "SIMD vector passed and returned correctly");
        diag("Result: [%f, %f]", result.d[0], result.d[1]);

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
#else
        skip(2, "SSE2 support not available, skipping SIMD vector test.");
#endif
    }
}
