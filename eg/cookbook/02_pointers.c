/**
 * @file 02_pointers.c
 * @brief Recipe: Passing and Receiving Pointers.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-passing-and-receiving-pointers
 */
#include <infix/infix.h>
#include <stdio.h>

// A C function that takes pointers and modifies the values they point to.
void swap_ints(int * a, int * b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main() {
    // 1. Describe the signature: void(int*, int*)
    //    The '*' is a prefix modifier for the pointer type.
    const char * signature = "(*int, *int) -> void";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    int x = 10, y = 20;
    int * ptr_x = &x;  // These pointers are the actual arguments to the C function.
    int * ptr_y = &y;

    // The `args` array for infix must hold the addresses *of our pointer variables*.
    void * args[] = {&ptr_x, &ptr_y};

    printf("Before swap: x = %d, y = %d\n", x, y);

    // 3. Call the function via the trampoline. The return value buffer is NULL for a void function.
    infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);
    cif_func((void *)swap_ints, NULL, args);

    printf("After swap: x = %d, y = %d\n", x, y);  // Expected: x = 20, y = 10

    // 4. Clean up.
    infix_forward_destroy(trampoline);
    return 0;
}
