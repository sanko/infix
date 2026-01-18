/**
 * @file 101_by_value.c
 * @brief Unit test for passing and returning aggregates and vectors by value.
 * @ingroup test_suite
 *
 * @details This test file is crucial for validating the ABI implementation for
 * passing and returning aggregate types (structs, arrays, vectors) directly in
 * CPU registers, where the ABI allows it. Different ABIs have complex and divergent
 * rules for this, which this test aims to cover.
 *
 * It tests several key ABI-specific scenarios:
 *
 * - **Simple Structs:** Verifies that small structs composed of identical types
 *   (e.g., `{ double, double }`) are correctly passed and returned in floating-point
 *   or general-purpose registers as per the ABI (e.g., in XMM0/XMM1 on SysV,
 *   or X0/X1 on AArch64).
 *
 * - **System V x64 Mixed-Register Structs:** Tests the specific SysV rule where a
 *   struct like `{ int, double }` is split and passed in both a GPR (for the `int`)
 *   and an XMM register (for the `double`).
 *
 * - **AArch64 Homogeneous Floating-point Aggregates (HFAs):** Tests the AAPCS64
 *   rule where a struct of up to four identical floats or doubles is passed in
 *   consecutive floating-point registers (V0-V3).
 *
 * - **SIMD Vectors:** Verifies that native hardware vector types (like `__m128d` on
 *   x86 or `float64x2_t` on ARM) are correctly passed and returned in SIMD registers.
 *   This includes checks for SSE2, AVX2, and NEON types, conditionally compiled
 *   based on architecture.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <stdbool.h>

#if !defined(INFIX_NO_INTRINSICS)
#if defined(__AVX512F__)
#define INFIX_ARCH_X86_AVX512
#endif
#if defined(__AVX2__)
#define INFIX_ARCH_X86_AVX2
#endif
#if defined(__SSE2__) || defined(_M_X64)
#define INFIX_ARCH_X86_SSE2
#endif
#if defined(INFIX_ARCH_X86_AVX512) || defined(INFIX_ARCH_X86_AVX2)
#include <immintrin.h>
#elif defined(INFIX_ARCH_X86_SSE2)
#include <emmintrin.h>
#endif
#if defined(__ARM_NEON) || defined(_M_ARM64)
#define INFIX_ARCH_ARM_NEON
#include <arm_neon.h>
#endif
#if defined(__ARM_FEATURE_SVE)
#define INFIX_ARCH_ARM_SVE
#include <arm_sve.h>
#endif
#endif
double process_point_by_value(Point p) {
    note("process_point_by_value received p = { .x=%.1f, .y=%.1f }", p.x, p.y);
    return p.x + p.y;
}
Point return_point_by_value(void) { return (Point){100.0, 200.0}; }
int process_mixed_struct(MixedIntDouble s) {
    note("process_mixed_struct received: i=%d, d=%.2f", s.i, s.d);
    return s.i == -500 && fabs(s.d - 3.14) < 0.001;
}
float sum_vector4(Vector4 vec) { return vec.v[0] + vec.v[1] + vec.v[2] + vec.v[3]; }
#if defined(INFIX_ARCH_X86_SSE2)
__m128d native_vector_add_128(__m128d a, __m128d b) { return _mm_add_pd(a, b); }
#elif defined(INFIX_ARCH_ARM_NEON)
float64x2_t neon_vector_add(float64x2_t a, float64x2_t b) { return vaddq_f64(a, b); }
#endif
#if defined(INFIX_ARCH_X86_AVX2)
__m256d native_vector_add_256(__m256d a, __m256d b) { return _mm256_add_pd(a, b); }
#endif
#if defined(INFIX_ARCH_X86_AVX512)
__m512d native_vector_add_512d(__m512d a, __m512d b) { return _mm512_add_pd(a, b); }
__m512 native_vector_add_512(__m512 a, __m512 b) { return _mm512_add_ps(a, b); }
#endif
#if defined(INFIX_ARCH_ARM_SVE)
svfloat64_t native_sve_vector_add(svfloat64_t a, svfloat64_t b) {
    svbool_t pg = svptrue_b64();
    return svadd_z(pg, a, b);
}
#endif
// A struct with a 20-byte payload. According to the SysV ABI, this MUST
// be passed on the stack (in memory), not in registers.
typedef struct {
    char data[20];
} Char20Struct;
/**
 * @brief A C function that receives the 20-byte struct.
 * @details It checks if the received data matches the expected pattern.
 * A correct call will result in a return value of 1, while a call where
 * the argument was corrupted (e.g., by being partially passed in registers)
 * will fail the check and return 0.
 */
int process_char20_struct(Char20Struct s) {
    if (s.data[0] == 'A' && s.data[19] == 'Z')
        return 1;  // Success
    return 0;      // Failure
}
/**
 * @brief A C function that receives a char array parameter.
 * @details The ABI will treat `s` as `char*`. This function verifies
 * that the pointer is valid and the data it points to is correct.
 */
int process_char_array_param(char s[20]) {
    if (s[0] == 'A' && s[19] == 'Z')
        return 1;  // Success
    return 0;      // Failure
}
TEST {
    plan(10);
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
        infix_type * array_type = nullptr;
        infix_status status =
            infix_type_create_array(arena, &array_type, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 4);
        if (status != INFIX_SUCCESS) {
            fail("Failed to create HFA inner array type");
            skip(1, "Cannot proceed");
            infix_arena_destroy(arena);
        }
        else {
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
        infix_type * vector_type = nullptr;
        infix_status status =
            infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 2);
        if (!ok(status == INFIX_SUCCESS, "infix_type for __m128d created successfully")) {
            skip(1, "Cannot proceed without vector type");
            infix_arena_destroy(arena);
        }
        else {
            infix_type * arg_types[] = {vector_type, vector_type};
            infix_forward_t * trampoline = nullptr;
            status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);
            __m128d vec_a = _mm_set_pd(20.0, 10.0);
            __m128d vec_b = _mm_set_pd(22.0, 32.0);
            void * args[] = {&vec_a, &vec_b};
            union {
                __m128d v;
                double d[2];
            } result;
            result.v = _mm_setzero_pd();
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)native_vector_add_128, &result.v, args);
            ok(fabs(result.d[0] - 42.0) < 1e-9 && fabs(result.d[1] - 42.0) < 1e-9,
               "SIMD vector passed/returned correctly");
            diag("Result: [%f, %f]", result.d[0], result.d[1]);
            infix_forward_destroy(trampoline);
            infix_arena_destroy(arena);
        }
#elif defined(INFIX_ARCH_ARM_NEON)
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * neon_vector_type = nullptr;
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
#if defined(INFIX_ARCH_X86_AVX2)
        if (infix_cpu_has_avx2()) {
            plan(2);
            note("Testing __m256d passed and returned by value on x86-64 with AVX2.");
            infix_arena_t * arena = infix_arena_create(4096);
            infix_type * vector_type = nullptr;
            infix_status status =
                infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 4);
            if (!ok(status == INFIX_SUCCESS, "infix_type for __m256d created successfully"))
                skip(1, "Cannot proceed without vector type");
            else {
                infix_type * arg_types[] = {vector_type, vector_type};
                infix_forward_t * trampoline = nullptr;
                status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);
                __m256d vec_a = _mm256_set_pd(40.0, 30.0, 20.0, 10.0);
                __m256d vec_b = _mm256_set_pd(2.0, 12.0, 22.0, 32.0);
                void * args[] = {&vec_a, &vec_b};
                union {
                    __m256d v;
                    double d[4];
                } result;
                result.v = _mm256_setzero_pd();
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)native_vector_add_256, &result.v, args);
                ok(fabs(result.d[0] - 42.0) < 1e-9 && fabs(result.d[1] - 42.0) < 1e-9 &&
                       fabs(result.d[2] - 42.0) < 1e-9 && fabs(result.d[3] - 42.0) < 1e-9,
                   "256-bit SIMD vector passed/returned correctly");
                diag("Result: [%f, %f, %f, %f]", result.d[0], result.d[1], result.d[2], result.d[3]);
                infix_forward_destroy(trampoline);
            }
            infix_arena_destroy(arena);
        }
        else {
            plan(1);
            skip(1, "CPU does not support AVX2, skipping test.");
        }
#else
        plan(1);
        skip(1, "No AVX2 support: compile with e.g., -mavx2 to enable this test.");
#endif
    }
    subtest("ABI Specific: ARM64 Scalable Vector (SVE)") {
#if defined(INFIX_ARCH_ARM_SVE)
        if (infix_cpu_has_sve()) {
            plan(2);
            note("Testing ARM64 Scalable Vector Extension (SVE).");
            infix_arena_t * arena = infix_arena_create(4096);
            size_t num_elements = svcntd();
            note("Detected SVE vector width: %zu bits (%zu double elements).", svcntb() * 8, num_elements);
            infix_type * sve_vector_type = nullptr;
            infix_status status = infix_type_create_vector(
                arena, &sve_vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), num_elements);
            if (!ok(status == INFIX_SUCCESS, "infix_type for svfloat64_t created successfully"))
                skip(1, "Cannot proceed without SVE vector type");
            else {
                infix_type * arg_types[] = {sve_vector_type, sve_vector_type};
                infix_forward_t * trampoline = nullptr;
                status = infix_forward_create_unbound_manual(&trampoline, sve_vector_type, arg_types, 2, 2);
                double * vec_a_data = (double *)malloc(sizeof(double) * num_elements);
                double * vec_b_data = (double *)malloc(sizeof(double) * num_elements);
                double * result_data = (double *)malloc(sizeof(double) * num_elements);
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
            }
            infix_arena_destroy(arena);
        }
        else {
            plan(1);
            skip(1, "SVE is not supported by the CPU at runtime.");
        }
#else
        plan(1);
        skip(1, "SVE tests skipped: not compiled with SVE support (e.g., -march=armv8-a+sve).");
#endif
    }
    subtest("ABI Specific: 512-bit AVX-512 Vector (__m512d)") {
#if defined(INFIX_ARCH_X86_AVX512)
        if (infix_cpu_has_avx512f()) {
            plan(2);
            note("Testing __m512d (8x double) passed and returned by value on x86-64 with AVX-512F.");
            infix_arena_t * arena = infix_arena_create(4096);
            infix_type * vector_type = nullptr;
            infix_status status =
                infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 8);
            if (!ok(status == INFIX_SUCCESS, "infix_type for __m512d created successfully"))
                skip(1, "Cannot proceed without vector type");
            else {
                infix_type * arg_types[] = {vector_type, vector_type};
                infix_forward_t * trampoline = nullptr;
                status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);
                __m512d vec_a = _mm512_set_pd(8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0);
                __m512d vec_b = _mm512_set_pd(34.0, 35.0, 36.0, 37.0, 38.0, 39.0, 40.0, 41.0);
                void * args[] = {&vec_a, &vec_b};
                union {
                    __m512d v;
                    double d[8];
                } result;
                result.v = _mm512_setzero_pd();
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)native_vector_add_512d, &result.v, args);
                bool all_correct = true;
                for (int i = 0; i < 8; ++i)
                    if (fabs(result.d[i] - 42.0) > 1e-9)
                        all_correct = false;
                ok(all_correct, "512-bit double vector (__m512d) passed/returned correctly");
                diag("Result: [%.1f, %.1f, %.1f, %.1f, %.1f, %.1f, %.1f, %.1f]",
                     result.d[0],
                     result.d[1],
                     result.d[2],
                     result.d[3],
                     result.d[4],
                     result.d[5],
                     result.d[6],
                     result.d[7]);
                infix_forward_destroy(trampoline);
            }
            infix_arena_destroy(arena);
        }
        else {
            plan(1);
            skip(1, "CPU does not support AVX-512F, skipping test.");
        }
#else
        plan(1);
        skip(1, "No AVX-512 support: compile with e.g., -mavx512f to enable this test.");
#endif
    }
    subtest("ABI Specific: 512-bit AVX-512 Vector (__m512)") {
#if defined(INFIX_ARCH_X86_AVX512)
        if (infix_cpu_has_avx512f()) {
            plan(2);
            note("Testing __m512 (16x float) passed and returned by value on x86-64 with AVX-512F.");
            infix_arena_t * arena = infix_arena_create(4096);
            infix_type * vector_type = nullptr;
            infix_status status =
                infix_type_create_vector(arena, &vector_type, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), 16);
            if (!ok(status == INFIX_SUCCESS, "infix_type for __m512 created successfully"))
                skip(1, "Cannot proceed without vector type");
            else {
                infix_type * arg_types[] = {vector_type, vector_type};
                infix_forward_t * trampoline = nullptr;
                status = infix_forward_create_unbound_manual(&trampoline, vector_type, arg_types, 2, 2);
                __m512 vec_a = _mm512_set_ps(16.0f,
                                             15.0f,
                                             14.0f,
                                             13.0f,
                                             12.0f,
                                             11.0f,
                                             10.0f,
                                             9.0f,
                                             8.0f,
                                             7.0f,
                                             6.0f,
                                             5.0f,
                                             4.0f,
                                             3.0f,
                                             2.0f,
                                             1.0f);
                __m512 vec_b = _mm512_set_ps(26.0f,
                                             27.0f,
                                             28.0f,
                                             29.0f,
                                             30.0f,
                                             31.0f,
                                             32.0f,
                                             33.0f,
                                             34.0f,
                                             35.0f,
                                             36.0f,
                                             37.0f,
                                             38.0f,
                                             39.0f,
                                             40.0f,
                                             41.0f);
                void * args[] = {&vec_a, &vec_b};
                union {
                    __m512 v;
                    float f[16];
                } result;
                result.v = _mm512_setzero_ps();
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)native_vector_add_512, &result.v, args);
                bool all_correct = true;
                for (int i = 0; i < 16; ++i) {
                    // _mm512_set_ps sets the values in reverse memory order.
                    float expected = (1.0f + i) + (41.0f - i);
                    if (fabsf(result.f[i] - expected) > 1e-6) {
                        all_correct = false;
                        diag("Mismatch at element %d: expected %.1f, got %f", i, expected, result.f[i]);
                    }
                }
                ok(all_correct, "512-bit float vector (__m512) passed/returned correctly");
                infix_forward_destroy(trampoline);
            }
            infix_arena_destroy(arena);
        }
        else {
            plan(1);
            skip(1, "CPU does not support AVX-512F, skipping test.");
        }
#else
        plan(1);
        skip(1, "No AVX-512 support: compile with e.g., -mavx512f to enable this test.");
#endif
    }
    subtest("SysV ABI: Passing a 20-byte aggregate") {
        plan(3);
#if defined(INFIX_ABI_SYSV_X64)
        note("Verifying that a 20-byte struct is correctly passed on the stack on SysV x64.");
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * char_array_type = NULL;
        infix_status status =
            infix_type_create_array(arena, &char_array_type, infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 20);
        ok(status == INFIX_SUCCESS, "Created infix_type for char[20]");
        infix_struct_member members[] = {{"data", char_array_type, 0, 0, 0, false}};
        infix_type * struct_type = NULL;
        status = infix_type_create_struct(arena, &struct_type, members, 1);
        ok(status == INFIX_SUCCESS && struct_type->size >= 20,
           "Created infix_type for 20-byte struct (size: %zu)",
           struct_type ? struct_type->size : 0);
        infix_forward_t * trampoline = NULL;
        if (infix_forward_create_manual(&trampoline,
                                        infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                        &struct_type,
                                        1,
                                        1,
                                        (void *)process_char20_struct) != INFIX_SUCCESS)
            fail("Failed to create trampoline.");
        else {
            Char20Struct arg_struct;
            memset(arg_struct.data, 'X', 20);
            arg_struct.data[0] = 'A';
            arg_struct.data[19] = 'Z';
            void * args[] = {&arg_struct};
            int result = 0;
            infix_cif_func cif = infix_forward_get_code(trampoline);
            cif(&result, args);
            ok(result == 1, "20-byte struct passed correctly to C function.");
            infix_forward_destroy(trampoline);
        }
        infix_arena_destroy(arena);
#else
        skip(3, "This test is specific to the System V x64 ABI.");
#endif
    };
    subtest("SysV ABI: Passing an array parameter (decays to pointer)") {
        plan(2);
#if defined(INFIX_ABI_SYSV_X64)
        note("Verifying that a char[20] parameter is correctly passed as a pointer on SysV x64.");
        infix_arena_t * arena = infix_arena_create(4096);
        // Create the signature for a function taking `char[20]`.
        infix_type * array_type = NULL;
        infix_status status =
            infix_type_create_array(arena, &array_type, infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 20);
        infix_forward_t * trampoline = NULL;
        status = infix_forward_create_manual(&trampoline,
                                             infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                             &array_type,
                                             1,
                                             1,
                                             (void *)process_char_array_param);
        if (!ok(status == INFIX_SUCCESS, "Trampoline created for function with array parameter"))
            skip(1, "Cannot proceed with call test.");
        else {
            // Prepare the argument data.
            char arg_data[20];
            memset(arg_data, 'X', 20);
            arg_data[0] = 'A';
            arg_data[19] = 'Z';
            void * args[] = {&arg_data};
            int result = 0;
            // Execute the call.
            infix_cif_func cif = infix_forward_get_code(trampoline);
            cif(&result, args);
            ok(result == 1, "Array parameter was passed correctly as a pointer.");
        }
        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
#else
        skip(2, "This test is specific to the System V x64 ABI.");
#endif
    }
}
