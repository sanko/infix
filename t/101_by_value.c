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
 * This file consolidates several previous tests into a single,
 * cohesive suite with the following goals:
 *
 * 1.  **General Case:** Tests a simple `struct { double; double; }` to verify
 *     basic aggregate handling on all platforms.
 * 2.  **System V x64 Specific:** Tests a `struct { int; double; }`, which the
 *     SysV ABI dictates should be split and passed in one GPR and one XMM register.
 * 3.  **AArch64 (ARM64) Specific:** Tests a `struct { float v[4]; }`, which is a
 *     Homogeneous Floating-point Aggregate (HFA) and should be passed in four
 *     consecutive floating-point registers.
 * 4.  **SIMD Vector Types:** Contains conditionally compiled tests for native SIMD
 *     vector types, including 128-bit SSE (`__m128d`), 256-bit AVX (`__m256d`),
 *     AArch64 NEON (`float64x2_t`), and AArch64 SVE (`svfloat64_t`).
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

/**
 * @defgroup simd_macros SIMD Feature Detection Macros
 * @brief Internal macros for compile-time detection of SIMD instruction set support.
 * @details These macros are used to conditionally compile SIMD-specific code, such as
 *          the inclusion of intrinsic headers (`<immintrin.h>`, `<arm_neon.h>`) and
 *          the activation of tests that require specific hardware features. They are
 *          for internal library use and are not part of the public API.
 * @{
 */
/** @brief Can be defined by the user to disable all intrinsic-related code. */
//~ #define INFIX_NO_INTRINSICS

#if !defined(INFIX_NO_INTRINSICS)
#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX__))
/** @brief Defined if the target supports the AVX2 instruction set. */
#define INFIX_ARCH_X86_AVX2
#endif
#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86) && defined(_M_IX86_FP) && (_M_IX86_FP >= 2))
/** @brief Defined if the target supports SSE2. This is the baseline for x86-64. */
#define INFIX_ARCH_X86_SSE2
#endif
#if defined(__ARM_NEON) || defined(_M_ARM64)
/** @brief Defined if the target supports the ARM NEON instruction set. */
#define INFIX_ARCH_ARM_NEON
#endif
#if defined(__ARM_FEATURE_SVE)
/** @brief Defined if the target supports the ARM Scalable Vector Extension (SVE). */
#define INFIX_ARCH_ARM_SVE
#endif
#if defined(__ARM_FEATURE_SVE2)
/** @brief Defined if the target supports the ARM Scalable Vector Extension 2 (SVE2). */
#define INFIX_ARCH_ARM_SVE2
#endif
#if defined(__riscv) && defined(__riscv_vector)
#if ((defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 14) || (defined(__clang__) && __clang_major__ >= 19))
/** @brief Defined if the target supports the RISC-V Vector Extension ('V'). */
#define INFIX_ARCH_RISCV_RVV
#endif
#if defined(__ARM_NEON) || defined(_M_ARM64)
/** @brief Defined if the target supports the ARM NEON instruction set. */
#define INFIX_ARCH_ARM_NEON
#endif
#if defined(__ARM_FEATURE_SVE)
/** @brief Defined if the target supports the ARM Scalable Vector Extension (SVE). */
#define INFIX_ARCH_ARM_SVE
#endif
#if defined(__ARM_FEATURE_SVE2)
/** @brief Defined if the target supports the ARM Scalable Vector Extension 2 (SVE2). */
#define INFIX_ARCH_ARM_SVE2
#endif
#endif
#
#if defined(INFIX_ARCH_X86_AVX2)
#include <immintrin.h>
#endif
#if defined(INFIX_ARCH_X86_SSE2)
#include <emmintrin.h>
#elif defined(INFIX_ARCH_ARM_NEON)
#include <arm_neon.h>
#endif
#if defined(INFIX_ARCH_ARM_SVE)
#include <arm_sve.h>
#endif
#if defined(INFIX_ARCH_RISCV_RVV)
#include <riscv_vector.h>
#endif
#endif
/** @} */  // end simd_macros

// Platform-specific headers and functions for SIMD tests
#if defined(INFIX_ARCH_X86_SSE2)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <immintrin.h>  // For GCC/Clang
#endif
#elif defined(INFIX_ARCH_ARM_NEON)
#include <arm_neon.h>
// https://developer.arm.com/documentation/102581/0200/About-intrinsics
//
#endif
#if defined(INFIX_ARCH_ARM_SVE)
#include <arm_sve.h>
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

#if defined(INFIX_ARCH_X86_SSE2)
// A native C function that adds two 128-bit vectors of doubles.
__m128d native_vector_add(__m128d a, __m128d b) {
    return _mm_add_pd(a, b);
}
#elif defined(INFIX_ARCH_ARM_NEON)
// A native C function that uses NEON intrinsics to add two vectors.
float64x2_t neon_vector_add(float64x2_t a, float64x2_t b) {
    return vaddq_f64(a, b);
}
#endif

#if defined(INFIX_ARCH_X86_AVX2)
// A native C function that adds two 256-bit vectors of doubles.
__m256d native_vector_add_256(__m256d a, __m256d b) {
    return _mm256_add_pd(a, b);
}
#endif

#if defined(INFIX_ARCH_ARM_SVE)
// A native C function that adds two scalable vectors of doubles using SVE intrinsics.
svfloat64_t native_sve_vector_add(svfloat64_t a, svfloat64_t b) {
    // Get an all-true predicate for 64-bit elements to operate on all lanes.
    svbool_t pg = svptrue_b64();
    // Perform the addition under the control of the predicate.
    return svadd_z(pg, a, b);
}
#endif

#if defined(INFIX_ARCH_ARM_SVE)
#if defined(INFIX_OS_LINUX)
#include <sys/auxv.h>
#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)  // Define if missing from old headers
#endif
#elif defined(INFIX_OS_MACOS)
#include <sys/sysctl.h>
#elif defined(INFIX_OS_WINDOWS)
#include <windows.h>
#endif
#endif

#if defined(INFIX_ARCH_ARM_SVE)
/**
 * @brief Performs a runtime check to see if the CPU supports the ARM SVE feature set.
 */
static bool is_sve_supported(void) {
#if defined(INFIX_OS_LINUX)
    unsigned long hwcaps = getauxval(AT_HWCAP);
    return (hwcaps & HWCAP_SVE) != 0;
#elif defined(INFIX_OS_MACOS)
    int sve_present = 0;
    size_t size = sizeof(sve_present);
    // This sysctl key returns 1 if SVE is available, 0 otherwise.
    if (sysctlbyname("hw.optional.arm.FEAT_SVE", &sve_present, &size, NULL, 0) == 0) {
        return sve_present == 1;
    }
    return false;  // sysctl failed, assume no support.
#elif defined(INFIX_OS_WINDOWS)
    return IsProcessorFeaturePresent(PF_ARM_SVE_INSTRUCTIONS_AVAILABLE);
#else
    // For other POSIX-like systems (e.g., BSDs), this would need their specific
    // mechanism. For now, we conservatively assume no support.
    return false;
#endif
}
#endif

TEST {
    plan(6);  // One subtest for each major scenario.

    subtest("Simple struct (Point) passed and returned by value") {
        plan(7);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * point_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        point_members[0] =
            infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
        infix_type * point_type = nullptr;
        if (!ok(infix_type_create_struct(arena, &point_type, point_members, 2) == INFIX_SUCCESS,
                "Point type created")) {
            skip(6, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        // Test Pass Arg
        infix_forward_t *unbound_pass = nullptr, *bound_pass = nullptr;
        ok(infix_forward_create_unbound_manual(
               &unbound_pass, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), &point_type, 1, 1) == INFIX_SUCCESS,
           "Pass arg (unbound) created");
        ok(infix_forward_create_manual(&bound_pass,
                                       infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                       &point_type,
                                       1,
                                       1,
                                       (void *)process_point_by_value) == INFIX_SUCCESS,
           "Pass arg (bound) created");
        Point p_in = {10.5, 20.5};
        void * pass_args[] = {&p_in};
        double unbound_pass_res = 0.0, bound_pass_res = 0.0;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_pass);
        unbound_cif((void *)process_point_by_value, &unbound_pass_res, pass_args);
        infix_cif_func bound_cif = infix_forward_get_code(bound_pass);
        bound_cif(&bound_pass_res, pass_args);
        ok(fabs(unbound_pass_res - 31.0) < 0.001 && fabs(bound_pass_res - 31.0) < 0.001, "Pass arg correct");

        // Test Return
        infix_forward_t *unbound_ret = nullptr, *bound_ret = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_ret, point_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Ret val (unbound) created");
        ok(infix_forward_create_manual(&bound_ret, point_type, nullptr, 0, 0, (void *)return_point_by_value) ==
               INFIX_SUCCESS,
           "Ret val (bound) created");
        Point unbound_ret_res = {0, 0}, bound_ret_res = {0, 0};
        infix_unbound_cif_func unbound_ret_cif = infix_forward_get_unbound_code(unbound_ret);
        unbound_ret_cif((void *)return_point_by_value, &unbound_ret_res, nullptr);
        infix_cif_func bound_ret_cif = infix_forward_get_code(bound_ret);
        bound_ret_cif(&bound_ret_res, nullptr);
        ok(unbound_ret_res.x == 100.0 && unbound_ret_res.y == 200.0 && bound_ret_res.x == 100.0 &&
               bound_ret_res.y == 200.0,
           "Return val correct");

        infix_forward_destroy(unbound_pass);
        infix_forward_destroy(bound_pass);
        infix_forward_destroy(unbound_ret);
        infix_forward_destroy(bound_ret);
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
        infix_type * mixed_type = nullptr;
        (void)infix_type_create_struct(arena, &mixed_type, members, 2);

        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &mixed_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for mixed-type struct created");

        infix_unbound_cif_func cif_func = infix_forward_get_unbound_code(trampoline);
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
        infix_type * array_type = nullptr;
        infix_status status =
            infix_type_create_array(arena, &array_type, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 4);
        if (status != INFIX_SUCCESS) {
            fail("Failed to create HFA inner array type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
        }
        else {
            // Level 2: Wrap the array in a struct
            infix_struct_member * members =
                infix_arena_alloc(arena, sizeof(infix_struct_member), _Alignof(infix_struct_member));
            members[0] = infix_type_create_member("v", array_type, offsetof(Vector4, v));
            infix_type * struct_type = nullptr;
            status = infix_type_create_struct(arena, &struct_type, members, 1);
            if (status != INFIX_SUCCESS) {
                fail("Failed to create HFA container struct type");
                skip(1, "Cannot proceed");
                infix_arena_destroy(arena);
                return;
            }

            infix_forward_t * trampoline = nullptr;
            status = infix_forward_create_unbound_manual(
                &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), &struct_type, 1, 1);
            ok(status == INFIX_SUCCESS, "Trampoline for HFA struct created");

            infix_unbound_cif_func cif_func = infix_forward_get_unbound_code(trampoline);
            Vector4 vec = {{1.5f, 2.5f, 3.5f, 4.5f}};
            float result = 0.0f;
            void * args[] = {&vec};
            cif_func((void *)sum_vector4, &result, args);
            ok(fabs(result - 12.0f) < 0.001, "HFA struct passed correctly");

            infix_forward_destroy(trampoline);
            infix_arena_destroy(arena);
        }
    }
    subtest("ABI Specific: 128-bit SIMD Vector") {
        plan(2);
#if defined(INFIX_ARCH_X86_SSE2)
        infix_arena_t * arena = infix_arena_create(4096);
        // 1. Create the infix_type for v[2:double]
        infix_type * vector_type = nullptr;
        infix_status status =
            infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 2);

        if (!ok(status == INFIX_SUCCESS, "infix_type for __m128d created successfully")) {
            skip(1, "Cannot proceed without vector type");
            infix_arena_destroy(arena);
        }
        else {
            // 2. Create the trampoline for __m128d(__m128d, __m128d)
            infix_type * arg_types[] = {vector_type, vector_type};
            infix_forward_t * trampoline = nullptr;
            status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);

            // 3. Prepare arguments and call
            __m128d vec_a = _mm_set_pd(20.0, 10.0);  // Vector [10.0, 20.0]
            __m128d vec_b = _mm_set_pd(22.0, 32.0);  // Vector [32.0, 22.0]
            void * args[] = {&vec_a, &vec_b};
            union {  // So we can check each value
                __m128d v;
                double d[2];
            } result;
            result.v = _mm_setzero_pd();
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)native_vector_add, &result.v, args);

            ok(fabs(result.d[0] - 42.0) < 1e-9 && fabs(result.d[1] - 42.0) < 1e-9,
               "SIMD vector passed/returned correctly");
            diag("Result: [%f, %f]", result.d[0], result.d[1]);
            infix_forward_destroy(trampoline);
            infix_arena_destroy(arena);
        }
#elif defined(INFIX_ARCH_ARM_NEON)
        infix_arena_t * arena = infix_arena_create(4096);
        // 1. Create the infix_type for v[2:double]
        infix_type * neon_vector_type = nullptr;

        // A native NEON vector should be described as a VECTOR type, not an ARRAY.
        // This allows the ABI logic to distinguish it from a struct-of-doubles (HFA).
        infix_status status =
            infix_type_create_vector(arena, &neon_vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 2);

        if (!ok(status == INFIX_SUCCESS, "infix_type for float64x2_t layout created successfully")) {
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
        }
        else {
            infix_type * arg_types[] = {neon_vector_type, neon_vector_type};
            infix_forward_t * trampoline = nullptr;
            status = infix_forward_create_unbound_manual(&trampoline, neon_vector_type, arg_types, 2, 2);
            float64_t a_data[] = {10.0, 20.0};
            float64_t b_data[] = {32.0, 22.0};
            float64x2_t vec_a = vld1q_f64(a_data);
            float64x2_t vec_b = vld1q_f64(b_data);
            void * args[] = {&vec_a, &vec_b};
            float64x2_t result_vec;
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)neon_vector_add, &result_vec, args);
            float64_t result_data[2];
            vst1q_f64(result_data, result_vec);
            ok(fabs(result_data[0] - 42.0) < 1e-9 && fabs(result_data[1] - 42.0) < 1e-9,
               "NEON vector passed/returned correctly");
            diag("Result: [%f, %f]", result_data[0], result_data[1]);
            infix_forward_destroy(trampoline);
            infix_arena_destroy(arena);
        }
#else
        skip(2, "No supported 128-bit SIMD vector type on this platform.");
#endif
    }

    subtest("ABI Specific: 256-bit AVX Vector") {
        plan(2);
#if defined(INFIX_ARCH_X86_AVX2)
        note("Testing __m256d passed and returned by value on x86-64 with AVX2.");
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Create the infix_type for v[4:double] to represent __m256d.
        infix_type * vector_type = nullptr;
        infix_status status =
            infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 4);

        if (!ok(status == INFIX_SUCCESS, "infix_type for __m256d created successfully")) {
            skip(1, "Cannot proceed without vector type");
            infix_arena_destroy(arena);
        }
        else {
            // 2. Create the trampoline for __m256d(__m256d, __m256d)
            infix_type * arg_types[] = {vector_type, vector_type};
            infix_forward_t * trampoline = nullptr;
            status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);

            // 3. Prepare arguments and call
            __m256d vec_a = _mm256_set_pd(40.0, 30.0, 20.0, 10.0);  // Vector [10, 20, 30, 40]
            __m256d vec_b = _mm256_set_pd(2.0, 12.0, 22.0, 32.0);   // Vector [32, 22, 12,  2]
            void * args[] = {&vec_a, &vec_b};
            union {
                __m256d v;
                double d[4];
            } result;
            result.v = _mm256_setzero_pd();
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)native_vector_add_256, &result.v, args);

            ok(fabs(result.d[0] - 42.0) < 1e-9 && fabs(result.d[1] - 42.0) < 1e-9 && fabs(result.d[2] - 42.0) < 1e-9 &&
                   fabs(result.d[3] - 42.0) < 1e-9,
               "256-bit SIMD vector passed/returned correctly");
            diag("Result: [%f, %f, %f, %f]", result.d[0], result.d[1], result.d[2], result.d[3]);
            infix_forward_destroy(trampoline);
            infix_arena_destroy(arena);
        }
#else
        skip(2, "No supported 256-bit SIMD vector type on this platform (requires AVX2).");
#endif
    }

    subtest("ABI Specific: ARM64 Scalable Vector (SVE)") {
        plan(2);
#if defined(INFIX_ARCH_ARM_SVE)
        if (is_sve_supported()) {
            note("Testing ARM64 Scalable Vector Extension (SVE).");
            infix_arena_t * arena = infix_arena_create(4096);

            // 1. Determine the vector size at RUNTIME. This is the key to SVE.
            // Use svcntb() (count bytes) which is the canonical intrinsic for vector length.
            // svlen_b() is often an alias but is less portable and can cause linker errors.
            size_t vector_len_bytes = svcntb();
            size_t num_elements = svcntd();  // Count of 64-bit (double) elements.
            note("Detected SVE vector width: %zu bits (%zu double elements).", vector_len_bytes * 8, num_elements);

            // 2. Create the infix_type for the dynamically sized vector.
            infix_type * sve_vector_type = nullptr;
            infix_status status = infix_type_create_vector(
                arena, &sve_vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), num_elements);

            if (!ok(status == INFIX_SUCCESS, "infix_type for svfloat64_t created successfully")) {
                skip(1, "Cannot proceed without SVE vector type");
                infix_arena_destroy(arena);
            }
            else {
                // 3. Create the trampoline for svfloat64_t(svfloat64_t, svfloat64_t)
                infix_type * arg_types[] = {sve_vector_type, sve_vector_type};
                infix_forward_t * trampoline = nullptr;
                status = infix_forward_create_unbound_manual(&trampoline, sve_vector_type, arg_types, 2, 2);

                // 4. Prepare data arrays, call the trampoline, and verify the result.
                // Allocate memory for the data arrays based on the runtime size.
                double * vec_a_data = malloc(sizeof(double) * num_elements);
                double * vec_b_data = malloc(sizeof(double) * num_elements);
                double * result_data = malloc(sizeof(double) * num_elements);

                for (size_t i = 0; i < num_elements; ++i) {
                    vec_a_data[i] = 10.0 + i;
                    vec_b_data[i] = 32.0 - i;
                }

                svbool_t pg = svptrue_b64();
                svfloat64_t vec_a = svld1_f64(pg, vec_a_data);
                svfloat64_t vec_b = svld1_f64(pg, vec_b_data);
                svfloat64_t result_vec;

                void * args[] = {&vec_a, &vec_b};

                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)native_sve_vector_add, &result_vec, args);

                svst1_f64(pg, result_data, result_vec);

                bool all_correct = true;
                for (size_t i = 0; i < num_elements; ++i) {
                    if (fabs(result_data[i] - 42.0) > 1e-9) {
                        all_correct = false;
                        diag("Mismatch at element %zu: expected 42.0, got %f", i, result_data[i]);
                    }
                }

                ok(all_correct, "SVE vector passed/returned correctly for all %zu elements", num_elements);

                free(vec_a_data);
                free(vec_b_data);
                free(result_data);
                infix_forward_destroy(trampoline);
                infix_arena_destroy(arena);
            }
        }
        else
            skip(2, "SVE is not supported by the CPU at runtime.");
#else
        skip(2, "SVE tests skipped: not compiled with SVE support (e.g., -march=armv8-a+sve).");
#endif
    }
}
