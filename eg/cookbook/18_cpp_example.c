/**
 * @file 18_cpp_example.c
 * @brief Recipe: Interoperating with a C++ Class via a C Wrapper.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#part-1-the-c-master-example
 */
#include "lib/counter.hpp"  // The C-compatible header
#include <infix/infix.h>
#include <stdio.h>

// This example assumes the C++ code has been compiled into a shared library
// and that this C code will be linked against it.
//
// Example compile commands:
// g++ -shared -fPIC -o libcounter.so lib/counter.cpp
// gcc 18_cpp_example.c -I./lib -L. -lcounter -linfix -o cpp_example

int main() {
    // 1. Create trampolines for the clean C wrapper functions.
<<<<<<< HEAD
    //    The Counter* handle is treated as an opaque pointer `*void`.
    infix_forward_t *t_create, *t_destroy, *t_add, *t_get;
    infix_forward_create(&t_create, "() -> *void");        // Counter* Counter_create();
    infix_forward_create(&t_destroy, "(*void) -> void");   // void Counter_destroy(Counter*);
    infix_forward_create(&t_add, "(*void, int) -> void");  // void Counter_add(Counter*, int);
    infix_forward_create(&t_get, "(*void) -> int");        // int Counter_get(Counter*);
=======
    //    The Counter* handle is treated as an opaque pointer `v*`.
    infix_forward_t *t_create, *t_destroy, *t_add, *t_get;
    infix_forward_create(&t_create, "=>v*");    // Counter* Counter_create();
    infix_forward_create(&t_destroy, "v*=>v");  // void Counter_destroy(Counter*);
    infix_forward_create(&t_add, "v*,i=>v");    // void Counter_add(Counter*, int);
    infix_forward_create(&t_get, "v*=>i");      // int Counter_get(Counter*);
>>>>>>> main

    // 2. Interact with the C++ object through the trampolines.
    Counter * counter_obj = NULL;
    ((infix_cif_func)infix_forward_get_code(t_create))((void *)Counter_create, &counter_obj, NULL);

    if (counter_obj) {
        printf("[C] Got Counter object handle: %p\n", (void *)counter_obj);

        int val_to_add = 50;
        void * add_args[] = {&counter_obj, &val_to_add};
        ((infix_cif_func)infix_forward_get_code(t_add))((void *)Counter_add, NULL, add_args);

        val_to_add = -8;
        ((infix_cif_func)infix_forward_get_code(t_add))((void *)Counter_add, NULL, add_args);

        int final_val = 0;
        void * get_args[] = {&counter_obj};
        ((infix_cif_func)infix_forward_get_code(t_get))((void *)Counter_get, &final_val, get_args);

        printf("[C] Final value from C++ object: %d\n", final_val);  // Expected: 42

        ((infix_cif_func)infix_forward_get_code(t_destroy))((void *)Counter_destroy, NULL, get_args);
    }

    // 3. Clean up the trampolines.
    infix_forward_destroy(t_create);
    infix_forward_destroy(t_destroy);
    infix_forward_destroy(t_add);
    infix_forward_destroy(t_get);

    return 0;
}
