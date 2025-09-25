/**
 * @file 01_simple_call.c
 * @brief Recipe: Calling a Simple C Function.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-calling-a-simple-c-function
 */
#include <infix/infix.h>
#include <stdio.h>

// The C function we want to call dynamically.
int add_ints(int a, int b) {
    return a + b;
}

int main() {
    // 1. Describe the signature: int(int, int) using the signature mini-language.
    //    'i' stands for int32_t. The arguments are listed before '=>', and the
    //    return type is listed after.
    const char * signature = "i,i=>i";

    // 2. Generate the trampoline. This is the one-time setup cost.
    //    It JIT-compiles a small function tailored to this exact signature.
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 3. Prepare arguments for the call.
    //    The args array must contain *pointers* to the actual argument values.
    int a = 40, b = 2;
    void * args[] = {&a, &b};
    int result = 0;  // A buffer to hold the return value.

    // 4. Get the callable function pointer from the trampoline and invoke it.
    infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
    cif_func((void *)add_ints, &result, args);

    printf("Result of add_ints(40, 2) is: %d\n", result);  // Expected: 42

    // 5. Clean up the trampoline's executable memory.
    infix_forward_destroy(trampoline);
    return 0;
}
