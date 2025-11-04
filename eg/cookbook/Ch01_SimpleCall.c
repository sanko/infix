/**
 * @file Ch01_SimpleCall.c
 * @brief Cookbook Chapter 1: Calling a Simple C Function
 *
 * This example demonstrates the most fundamental use of infix: calling a standard
 * C library function (`atan2`) that takes two `double` arguments and returns a
 * `double`. It uses an "unbound" trampoline, which is flexible and can be used
 * to call any function matching the specified signature.
 */
#include <infix/infix.h>
#include <math.h>
#include <stdio.h>

int main() {
    printf("--- Cookbook Chapter 1: Calling a Simple C Function ---\n");

    // 1. Describe the signature of the function we want to call:
    //    double atan2(double y, double x);
    const char * signature = "(double, double) -> double";

    // 2. Create an unbound trampoline. The function to call is not specified yet.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create_unbound(&trampoline, signature, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create unbound trampoline.\n");
        return 1;
    }

    // 3. Get the callable function pointer from the trampoline.
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);

    // 4. Prepare arguments and a buffer for the return value.
    //    The `args` array must hold *pointers* to the argument values.
    double y = 1.0, x = 1.0;
    void * args[] = {&y, &x};
    double result;

    // 5. Invoke the call. For an unbound trampoline, the target function
    //    (`atan2` in this case) is passed as the first argument.
    cif((void *)atan2, &result, args);

    printf("Calling atan2(1.0, 1.0) via infix...\n");
    printf("Result: %f (Expected: ~0.785, which is PI/4)\n", result);

    // 6. Clean up the trampoline.
    infix_forward_destroy(trampoline);

    return 0;
}
