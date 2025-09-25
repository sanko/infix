/**
 * @file 06_small_struct_by_value.c
 * @brief Recipe: Small Structs Passed by Value.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-small-structs-passed-by-value
 */
#include "lib/types.h"  // For the definition of Point
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes a small struct by value.
double process_point(Point p) {
    return p.x + p.y;
}

int main() {
    // 1. Describe the signature: double(Point).
    //    A Point is a struct of two doubles: {d,d}.
    const char * signature = "{d,d}=>d";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the struct argument.
    Point p = {1.5, 2.5};
    void * args[] = {&p};
    double result = 0;

    // 3. Call the function. infix automatically handles the platform-specific
    //    details of passing the struct in registers or on the stack.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_point, &result, args);

    printf("Result is: %f\n", result);  // Expected: 4.0

    infix_forward_destroy(trampoline);
    return 0;
}
