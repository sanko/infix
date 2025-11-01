/**
 * @file Ch04_Rec04_LongDouble.c
 * @brief Cookbook Chapter 4, Recipe 4: Handling `long double`
 *
 * This example demonstrates how to call a function that uses the `long double` type.
 * The size and ABI handling of `long double` are highly platform-specific:
 * - On x86-64 Linux/BSD (System V ABI), it is often an 80-bit extended-precision
 *   float passed on the x87 FPU stack.
 * - On AArch64, it is a 128-bit quadruple-precision float.
 * - On Windows (MSVC) and macOS, it is typically just an alias for `double` (64 bits).
 *
 * The `infix` keyword `longdouble` correctly resolves to the appropriate ABI
 * handling on each platform, making the signature portable.
 */
#include <infix/infix.h>
#include <math.h>
#include <stdio.h>

// A simple native function that uses long double.
// `sqrtl` is the long double variant of `sqrt`.
static long double native_sqrtl(long double x) { return sqrtl(x); }

int main() {
    printf("--- Cookbook Chapter 4, Recipe 4: Handling `long double` ---\n");
    printf("Size of `long double` on this platform: %zu bytes\n", sizeof(long double));

    // 1. Use the `longdouble` keyword. infix will determine the correct ABI rules.
    const char * signature = "(longdouble) -> longdouble";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)native_sqrtl, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline for long double.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare arguments and call. Use the 'L' suffix for a long double literal.
    long double input = 144.0L;
    long double result = 0.0L;
    void * args[] = {&input};

    cif(&result, args);

    printf("Calling sqrtl(144.0L) via FFI...\n");
    // Use %Lf to print a long double.
    printf("Result: %Lf (Expected: 12.0)\n", result);

    // 4. Clean up.
    infix_forward_destroy(t);

    return 0;
}
