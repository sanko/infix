/**
 * @file 08_return_struct.c
 * @brief Recipe: Receiving a Struct from a Function.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-receiving-a-struct-from-a-function
 */
#include "lib/types.h"  // For the definition of Point
#include <infix/infix.h>
#include <stdio.h>

// A C function that returns a struct by value.
Point create_point() {
    return (Point){100.0, 200.0};
}

int main() {
    // 1. Signature: Point(void). The return type is the struct {d,d}.
    const char * signature = "=>{d,d}";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare a buffer to receive the returned struct.
    Point result_point;

    // 3. Call the function. `infix` handles the ABI details of returning the
    //    struct, whether in registers or via a hidden pointer.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)create_point, &result_point, NULL);

    printf("Returned point: (%f, %f)\n", result_point.x, result_point.y);

    infix_forward_destroy(trampoline);
    return 0;
}
