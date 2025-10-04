/**
 * @file 14_variadic_printf.c
 * @brief Recipe: Calling Variadic Functions like `printf`.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-calling-variadic-functions-like-printf
 */
#include <infix/infix.h>
#include <stdio.h>

int main() {
    // 1. Describe the *specific instance* of the variadic signature we intend to call:
    //    int printf(const char* format, int, const char*);
    //
    //    The semicolon ';' marks the start of the variadic arguments.
    const char * signature = "c*;i,c*=>i";

    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments for this specific call.
    const char * fmt = "Number: %d, String: %s\n";
    int val = 123;
    const char * str = "test";
    void * args[] = {&fmt, &val, &str};
    int result = 0;

    // 3. Call printf through the trampoline.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)printf, &result, args);

    printf("printf returned %d\n", result);

    infix_forward_destroy(trampoline);
    return 0;
}
