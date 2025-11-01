/**
 * @file Ch04_Rec01_VariadicPrintf.c
 * @brief Cookbook Chapter 4, Recipe 1: Calling Variadic Functions like `printf`
 *
 * This example demonstrates how to call a C function that takes a variable
 * number of arguments, such as `printf`.
 *
 * The key is the semicolon (`;`) in the signature string, which separates the
 * fixed arguments from the variadic arguments. The signature must exactly
 * match the types you are passing in a *specific call*. You would need a
 * different trampoline for `printf("%s", ...)` versus `printf("%d", ...)`.
 */
#include <infix/infix.h>
#include <stdio.h>

int main() {
    printf("--- Cookbook Chapter 4, Recipe 1: Calling Variadic Functions ---\n");

    // 1. The signature for this specific call to `printf`.
    //    Signature: int printf(const char* format, ...);
    //    Our call:  printf("%d, %.2f", (int)42, (double)123.45);
    //    The signature separates fixed and variadic args with a semicolon.
    const char * signature = "(*char; int, double) -> int";

    // 2. Create the trampoline bound to `printf`.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create(&trampoline, signature, (void *)printf, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create variadic trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 3. Prepare the arguments.
    const char * fmt = "Formatted output from variadic call -> Count: %d, Value: %.2f\n";
    int count = 42;
    double value = 123.45;
    void * args[] = {&fmt, &count, &value};
    int result;  // To hold the return value of printf.

    // 4. Make the call.
    cif(&result, args);

    printf("printf returned %d (number of characters written).\n", result);

    // 5. Clean up.
    infix_forward_destroy(trampoline);

    return 0;
}
