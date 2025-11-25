/**
 * @file Ch02_SIMD_NEON.c
 * @brief Cookbook Chapter 2: Working with SIMD Vectors (AArch64 NEON)
 *
 * This example demonstrates FFI calls with ARM NEON vector types, which are the
 * standard SIMD instruction set on 64-bit ARM processors. It uses the `float32x4_t`
 * type, a 128-bit vector containing four 32-bit floats.
 *
 * NOTE: This program must be compiled for the AArch64 architecture.
 */

#include <infix/infix.h>
#include <stdio.h>

#if defined(__ARM_NEON)
#include <arm_neon.h>

// Native C function that performs a horizontal add on a NEON vector,
// summing all four elements into a single scalar float.
static float neon_horizontal_sum(float32x4_t vec) { return vaddvq_f32(vec); }

int main() {
    printf("Cookbook Chapter 2: SIMD Vectors (AArch64 NEON)\n");

    // 1. The signature `v[4:float]` directly maps to the `float32x4_t` type.
    const char * signature = "(v[4:float]) -> float";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)neon_horizontal_sum, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare the NEON vector argument.
    float data[] = {10.0f, 20.0f, 5.5f, 6.5f};
    float32x4_t input_vec = vld1q_f32(data);  // Load data from memory into a vector register.
    void * args[] = {&input_vec};
    float result;

    // 4. Call the function.
    cif(&result, args);

    printf("Calling NEON horizontal sum with vector {10.0, 20.0, 5.5, 6.5}...\n");
    printf("Result: %.1f (Expected: 42.0)\n", result);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}

#else  // If not compiled for ARM NEON

int main() {
    printf("Cookbook Chapter 2: SIMD Vectors (AArch64 NEON)\n");
    printf("SKIPPED: Not compiled for AArch64 with NEON support.\n");
    return 0;
}

#endif
