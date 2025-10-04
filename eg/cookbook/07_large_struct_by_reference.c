/**
 * @file 07_large_struct_by_reference.c
 * @brief Recipe: Large Structs Passed by Reference.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-large-structs-passed-by-reference
 */
#include "lib/types.h"  // For the definition of LargeStruct
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes a large struct. The ABI will pass it by reference.
int sum_large_struct(LargeStruct s) {
    return s.a + s.f;
}

int main() {
    // 1. Signature: int(LargeStruct). A LargeStruct is {int,int,int,int,int,int}.
    const char * signature = "({int,int,int,int,int,int}) -> int";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. The process is identical to the small struct example. `infix` handles
    //    the "pass by reference" detail automatically.
    LargeStruct data = {10, 20, 30, 40, 50, 60};
    void * args[] = {&data};
    int result = 0;

    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_large_struct, &result, args);

    printf("Result is: %d\n", result);  // Expected: 70

    infix_forward_destroy(trampoline);
    return 0;
}
