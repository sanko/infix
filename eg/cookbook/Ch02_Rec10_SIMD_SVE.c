/**
 * @file Ch02_Rec10_SIMD_SVE.c
 * @brief Cookbook Chapter 2, Recipe 10: Working with SIMD Vectors (AArch64 SVE)
 *
 * This example demonstrates interfacing with ARM's Scalable Vector Extension (SVE).
 * SVE is unique because the vector register size is not fixed by the architecture;
 * it is implemented by the CPU and can vary (128 bits, 256 bits, 512 bits, etc.).
 *
 * This requires a dynamic approach:
 * 1. Check for SVE support at runtime.
 * 2. Query the CPU's implemented vector length.
 * 3. Build the `infix` signature string *dynamically* based on the result.
 * 4. Create and call the trampoline using the dynamically generated signature.
 *
 * NOTE: This program must be compiled for AArch64 with SVE enabled
 * (e.g., `-march=armv8-a+sve`) and run on supporting hardware.
 */
#include <infix/infix.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// Check if the compiler has SVE support enabled.
#if defined(__ARM_FEATURE_SVE)
#include <arm_sve.h>

// Platform-specific headers for runtime CPU feature detection.
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)  // From Linux kernel headers
#endif
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

// Helper function to check for SVE support at runtime.
static bool is_sve_supported(void) {
#if defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_SVE) != 0;
#elif defined(__APPLE__)
    int sve_present = 0;
    size_t size = sizeof(sve_present);
    // Check the sysctl key for the SVE feature flag.
    if (sysctlbyname("hw.optional.arm.FEAT_SVE", &sve_present, &size, NULL, 0) == 0)
        return sve_present == 1;
    return false;
#else
    // Other platforms (like Windows on ARM) would have their own detection methods.
    return false;
#endif
}

// Native C function using SVE for a horizontal add.
// It sums all the double-precision elements in a scalable vector.
static double sve_horizontal_add(svfloat64_t vec) { return svaddv_f64(svptrue_b64(), vec); }

int main() {
    printf("--- Cookbook Chapter 2, Recipe 10: SIMD Vectors (AArch64 SVE) ---\n");

    if (!is_sve_supported()) {
        printf("SKIPPED: SVE not supported on this CPU at runtime.\n");
        return 0;
    }

    // 1. Query the vector length at runtime.
    // `svcntd()` returns the number of `double` elements that fit in a Z-register.
    size_t num_doubles = svcntd();
    printf("Detected SVE vector length: %zu doubles (%zu bits)\n", num_doubles, num_doubles * 64);

    // 2. Build the signature string dynamically based on the runtime result.
    char signature[64];
    snprintf(signature, sizeof(signature), "(v[%zu:double]) -> double", num_doubles);
    printf("Generated dynamic signature: %s\n", signature);

    // 3. Create the trampoline with the dynamic signature.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)sve_horizontal_add, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create SVE trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 4. Prepare arguments and call.
    double * data = (double *)malloc(sizeof(double) * num_doubles);
    for (size_t i = 0; i < num_doubles; ++i)
        data[i] = (i == 0) ? 42.0 : 0.0;  // Place a value only in the first lane.

    svbool_t pg = svptrue_b64();  // A "predicate governor" to operate on all lanes.
    svfloat64_t input_vec = svld1_f64(pg, data);
    void * args[] = {&input_vec};
    double result;

    cif(&result, args);

    printf("Calling SVE horizontal sum...\n");
    printf("Result: %.1f (Expected: 42.0)\n", result);

    // 5. Clean up.
    free(data);
    infix_forward_destroy(t);

    return 0;
}

#else  // If not compiled with SVE support

int main() {
    printf("--- Cookbook Chapter 2, Recipe 10: SIMD Vectors (AArch64 SVE) ---\n");
    printf("SKIPPED: Not compiled with SVE support (e.g., -march=armv8-a+sve).\n");
    return 0;
}

#endif
