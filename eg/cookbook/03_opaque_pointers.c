/**
 * @file 03_opaque_pointers.c
 * @brief Recipe: Working with Opaque Pointers (Incomplete Types).
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-working-with-opaque-pointers-incomplete-types
 */
#include "lib/handle_lib.h"  // Include our mock C library
#include <infix/infix.h>
#include <stdio.h>

int main() {
    // 1. Create trampolines for the C API using signatures.
<<<<<<< HEAD
    //    `*void` is the canonical signature for any opaque pointer or handle.
    infix_forward_t *t_create, *t_destroy, *t_get;
    infix_forward_create(&t_create, "(int) -> *void");    // create_handle
    infix_forward_create(&t_destroy, "(*void) -> void");  // destroy_handle
    infix_forward_create(&t_get, "(*void) -> int");       // get_handle_value
=======
    //    'v*' is the canonical signature for any opaque pointer or handle.
    infix_forward_t *t_create, *t_destroy, *t_get;
    infix_forward_create(&t_create, "i=>v*");   // int -> void*
    infix_forward_create(&t_destroy, "v*=>v");  // void*(void)
    infix_forward_create(&t_get, "v*=>i");      // void* -> int
>>>>>>> main

    // 2. Use the API through the trampolines.
    my_handle_t * handle = NULL;
    int initial_val = 123;
    void * create_args[] = {&initial_val};
    ((infix_cif_func)infix_forward_get_code(t_create))((void *)create_handle, &handle, create_args);

    if (handle) {
        int value = 0;
        void * handle_arg[] = {&handle};
        ((infix_cif_func)infix_forward_get_code(t_get))((void *)get_handle_value, &value, handle_arg);
        printf("Value from handle: %d\n", value);  // Expected: 123

        ((infix_cif_func)infix_forward_get_code(t_destroy))((void *)destroy_handle, NULL, handle_arg);
    }
    else {
        fprintf(stderr, "Failed to create handle.\n");
    }

    // 3. Clean up.
    infix_forward_destroy(t_create);
    infix_forward_destroy(t_destroy);
    infix_forward_destroy(t_get);
    return 0;
}
