/**
 * @file Ch02_ComplexNumbers.c
 * @brief Cookbook Chapter 2: Working with Complex Numbers
 *
 * This example demonstrates how to call C functions that use the standard
 * C99 `_Complex` types. The `infix` signature for a complex number is `c[<base>]`,
 * where `<base>` is the underlying floating-point type (`float` or `double`).
 *
 * NOTE: This feature is not supported by the MSVC compiler. This example will be
 * skipped on Windows when using MSVC.
 */

// MSVC does not support <complex.h>, so we skip this entire example.
#if !defined(_MSC_VER)

#include <complex.h>
#include <infix/infix.h>
#include <stdio.h>

// A native C function that operates on complex numbers.
static double complex c_square(double complex z) { return z * z; }

int main() {
    printf("Cookbook Chapter 2: Working with Complex Numbers\n");

    // 1. The signature for `double _Complex` is `c[double]`.
    const char * signature = "(c[double]) -> c[double]";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)c_square, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare arguments and call. The C `complex.h` header provides the `I` macro.
    double complex input = 3.0 + 4.0 * I;
    double complex result;
    void * args[] = {&input};

    cif(&result, args);

    printf("Calling a function that squares (3.0 + 4.0i)...\n");
    printf("Result: (%.1f + %.1fi) (Expected: -7.0 + 24.0i)\n", creal(result), cimag(result));

    // 4. Clean up.
    infix_forward_destroy(t);

    return 0;
}

#else  // On MSVC, provide a dummy main to satisfy the build system.

#include <stdio.h>

int main() {
    printf("Cookbook Chapter 2: Working with Complex Numbers\n");
    printf("SKIPPED: MSVC does not support C99 _Complex types.\n");
    return 0;
}

#endif
