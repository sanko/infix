/**
 * @file Ch02_Rec10_SIMD_AVX.c
 * @brief Cookbook Chapter 2, Recipe 10: Working with SIMD Vectors (x86-64)
 *
 * This example demonstrates FFI calls with x86-64 SIMD vector types. It
 * covers 256-bit AVX vectors (`__m256d`) and 512-bit AVX-512 vectors (`__m512d`).
 * `infix` handles the ABI-specific rules for passing these types in YMM/ZMM registers.
 *
 * NOTE: This program must be compiled with the appropriate CPU features enabled
 * (e.g., `-mavx2`, `-mavx512f` on GCC/Clang) and run on hardware that supports
 * these instruction sets to avoid illegal instruction errors.
 */
#include <infix/infix.h>
#include <stdbool.h>
#include <stdio.h>

#if defined(__AVX2__)
#include <immintrin.h>
#else
typedef struct {
    double d[4];
} __m256d;
typedef struct {
    double d[8];
} __m512d;
#endif

// Only define and use these helpers if intrinsics are available.
#if defined(__AVX2__) || defined(__AVX512F__)
#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
static bool cpu_has_avx2() {
    unsigned int eax, ebx, ecx, edx;
    return __get_cpuid(7, &eax, &ebx, &ecx, &edx) && (ebx & bit_AVX2);
}
static bool cpu_has_avx512f() {
    unsigned int eax, ebx, ecx, edx;
    return __get_cpuid(7, &eax, &ebx, &ecx, &edx) && (ebx & bit_AVX512F);
}
#elif defined(_MSC_VER)
#include <intrin.h>
static bool cpu_has_avx2() {
    int info[4];
    __cpuidex(info, 7, 0);
    return (info[1] & (1 << 5));
}
static bool cpu_has_avx512f() {
    int info[4];
    __cpuidex(info, 7, 0);
    return (info[1] & (1 << 16));
}
#else
static bool cpu_has_avx2() { return false; }
static bool cpu_has_avx512f() { return false; }
#endif
#endif

#if defined(__AVX2__)
__m256d vector_add_256(__m256d a, __m256d b) { return _mm256_add_pd(a, b); }
#endif

#if defined(__AVX512F__)
__m512d vector_add_512(__m512d a, __m512d b) { return _mm512_add_pd(a, b); }
#endif

int main() {
    printf("--- Cookbook Chapter 2, Recipe 10: Working with SIMD Vectors (x86-64) ---\n");

#if defined(__AVX2__)
    if (cpu_has_avx2()) {
        printf("\n-- AVX (__m256d) Example --\n");
        const char * sig256 = "(m256d, m256d) -> m256d";
        infix_forward_t * t256 = NULL;
        if (infix_forward_create(&t256, sig256, (void *)vector_add_256, NULL) == INFIX_SUCCESS) {
            __m256d a = _mm256_set_pd(40.0, 30.0, 20.0, 10.0);
            __m256d b = _mm256_set_pd(2.0, 12.0, 22.0, 32.0);
            void * args[] = {&a, &b};
            __m256d result;
            infix_forward_get_code(t256)(&result, args);
            double * d = (double *)&result;
            printf("AVX vector result: [%.1f, %.1f, %.1f, %.1f]\n", d[0], d[1], d[2], d[3]);
            printf("(Expected: [42.0, 42.0, 42.0, 42.0])\n");
            infix_forward_destroy(t256);
        }
    }
    else {
        printf("\n-- AVX (__m256d) Example --\nSKIPPED: CPU does not support AVX2 at runtime.\n");
    }
#else
    printf("\n-- AVX (__m256d) Example --\nSKIPPED: Not compiled with AVX2 support (e.g., -mavx2).\n");
#endif

#if defined(__AVX512F__)
    if (cpu_has_avx512f()) {
        printf("\n-- AVX-512 (__m512d) Example --\n");
        const char * sig512 = "(m512d, m512d) -> m512d";
        infix_forward_t * t512 = NULL;
        if (infix_forward_create(&t512, sig512, (void *)vector_add_512, NULL) == INFIX_SUCCESS) {
            __m512d a = _mm512_set_pd(8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0);
            __m512d b = _mm512_set_pd(34.0, 35.0, 36.0, 37.0, 38.0, 39.0, 40.0, 41.0);
            void * args[] = {&a, &b};
            __m512d result;
            infix_forward_get_code(t512)(&result, args);
            double * d = (double *)&result;
            printf("AVX-512 vector result: [%.1f, ..., %.1f]\n", d[0], d[7]);
            printf("(Expected: [42.0, ..., 42.0])\n");
            infix_forward_destroy(t512);
        }
    }
    else {
        printf("\n-- AVX-512 (__m512d) Example --\nSKIPPED: CPU does not support AVX-512F at runtime.\n");
    }
#else
    printf("\n-- AVX-512 (__m512d) Example --\nSKIPPED: Not compiled with AVX-512 support (e.g., -mavx512f).\n");
#endif

    return 0;
}
