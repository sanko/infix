/**
 * @file 10_unions.c
 * @brief Recipe: Working with Unions.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-working-with-unions
 */
#include "lib/types.h"  // For the definition of Number
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes a union and interprets it as an integer.
int process_number_as_int(Number n) {
    return n.i * 2;
}

int main() {
    // 1. Signature for int(Number). A Number is a union of int and float: <i,f>.
    const char * signature = "<i,f>=>i";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the union argument.
    Number num_val;
    num_val.i = 21;  // We will use the integer member.
    int result = 0;
    void * args[] = {&num_val};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_number_as_int, &result, args);
    printf("Result: %d\n", result);  // Expected: 42

    infix_forward_destroy(trampoline);
    return 0;
}
