#include <complex.h>
#include <infix/infix.h>
#include <stdio.h>

// A C function to call, e.g., from a math library.
double complex c_square(double complex z) {
    return z * z;
}

int main() {
    // 1. Signature for: double complex(double complex)
    const char * signature = "(c[double]) -> c[double]";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    double complex input = 3.0 + 4.0 * I;
    double complex result;
    void * args[] = {&input};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)c_square, &result, args);

    printf("The square of (3.0 + 4.0i) is (%.1f + %.1fi)\n", creal(result), cimag(result));
    // Expected: -7.0 + 24.0i

    infix_forward_destroy(trampoline);
    return 0;
}
