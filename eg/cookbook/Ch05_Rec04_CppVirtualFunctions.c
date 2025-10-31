/**
 * @file Ch05_Rec04_CppVirtualFunctions.c
 * @brief Cookbook Chapter 5, Recipe 4: Calling C++ Virtual Functions
 *
 * This example demonstrates how to call a C++ `virtual` function from C
 * without any wrappers. This is achieved by emulating the compiler's v-table
 * dispatch mechanism:
 * 1. Read the hidden v-table pointer (vptr) from the object's memory.
 * 2. Read the function pointer from the v-table at its known index.
 * 3. Use `infix` to call that function pointer, passing the object as the
 *    first ('this') argument.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
const char * LIB_NAME = "shapes.dll";
#else
const char * LIB_NAME = "./libshapes.so";
#endif

int main() {
    printf("--- Cookbook Chapter 5, Recipe 4: Calling C++ Virtual Functions ---\n");

    infix_library_t * lib = infix_library_open(LIB_NAME);
    if (!lib) {
        fprintf(stderr, "Failed to open library '%s'.\n", LIB_NAME);
        return 1;
    }

    // 1. Get the extern "C" factory function (the correct way to construct).
    void * (*create_rectangle)(double, double) = infix_library_get_symbol(lib, "create_rectangle");

    // 2. Create a C++ object via the factory.
    void * rect_obj = create_rectangle(10.0, 5.0);
    printf("Created C++ Rectangle object at address %p.\n", rect_obj);

    // 3. Manually read the v-table pointer from the object.
    void ** vptr = (void **)rect_obj;
    void ** vtable = *vptr;
    printf("Read v-table pointer: %p\n", (void *)vtable);

    // 4. Read function pointers from their known indices in the v-table.
    //    This is ABI-dependent and can be fragile.
    void * area_fn_ptr = vtable[0];      // double area() const
    void * name_fn_ptr = vtable[1];      // const char* name() const
    void * dtor_fn_ptr = vtable[2];      // virtual ~Shape()
    printf("Found `area()` function pointer at vtable[0]: %p\n", area_fn_ptr);
    printf("Found `name()` function pointer at vtable[1]: %p\n", name_fn_ptr);
    printf("Found `~Shape()` function pointer at vtable[2]: %p\n", dtor_fn_ptr);

    // 5. Create trampolines for the discovered function pointers.
    infix_forward_t *t_area, *t_name, *t_dtor;
    infix_forward_create(&t_area, "(*void)->double", area_fn_ptr, NULL);
    infix_forward_create(&t_name, "(*void)->*char", name_fn_ptr, NULL);
    infix_forward_create(&t_dtor, "(*void)->void", dtor_fn_ptr, NULL);

    // 6. Prepare the arguments array for the member function calls.
    //    The only argument is the `this` pointer.
    void* args[] = { &rect_obj };

    // 7. Call the virtual functions.
    double rect_area;
    const char * rect_name;
    infix_forward_get_code(t_area)(&rect_area, args);
    infix_forward_get_code(t_name)((void*)&rect_name, args);

    printf("\n--- Results ---\n");
    printf("Object's virtual name() returned: '%s'\n", rect_name);
    printf("Object's virtual area() returned: %f\n", rect_area);

    // 8. Call the virtual destructor directly instead of an extern "C" wrapper.
    printf("\nCalling virtual destructor at %p...\n", dtor_fn_ptr);
    infix_forward_get_code(t_dtor)(NULL, args);
    printf("Object destroyed.\n");

    // 9. Clean up.
    infix_forward_destroy(t_area);
    infix_forward_destroy(t_name);
    infix_forward_destroy(t_dtor);
    infix_library_close(lib);

    return 0;
}
