/**
 * @file Ch05_Rec01_CppMangledNames.c
 * @brief Cookbook Chapter 5, Recipe 1: Calling C++ Mangled Names
 *
 * This example demonstrates the advanced and fragile technique of manually
 * replicating the C++ `new` and `delete` operators from C.
 *
 * This is a two-step process:
 * 1. `new`: First, allocate raw memory (`malloc`), then call the constructor
 *    on that memory with its mangled name.
 * 2. `delete`: First, call the destructor with its mangled name, then free
 *    the raw memory (`free`).
 *
 * @warning This technique is shown for educational purposes. It is not robust
 * because it depends on compiler-specific name mangling. The strongly
 * recommended best practice is to use `extern "C"` factory functions
 * (`create_object`/`destroy_object`) to hide this complexity.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// The name of the shared library to load.
#if defined(_WIN32)
const char * LIB_NAME = "myclass.dll";
#else
const char * LIB_NAME = "./libmyclass.so";
#endif

int main() {
    printf("--- Cookbook Chapter 5, Recipe 1: Calling C++ Mangled Names ---\n\n");

    // 1. Open the C++ shared library.
    infix_library_t * lib = infix_library_open(LIB_NAME);
    if (!lib) {
        fprintf(stderr, "Failed to open library '%s'.\n", LIB_NAME);
        return 1;
    }

    // 2. Get the extern "C" helper functions and the mangled names.
    size_t (*get_sizeof_myclass)() = infix_library_get_symbol(lib, "get_sizeof_myclass");
    const char * (*get_mangled_constructor)() = infix_library_get_symbol(lib, "get_mangled_constructor");
    const char * (*get_mangled_getvalue)() = infix_library_get_symbol(lib, "get_mangled_getvalue");
    const char * (*get_mangled_destructor)() = infix_library_get_symbol(lib, "get_mangled_destructor");

    const char * mangled_ctor = get_mangled_constructor();
    const char * mangled_getval = get_mangled_getvalue();
    const char * mangled_dtor = get_mangled_destructor();

    printf("Looked up mangled names:\n");
    printf("  Constructor: %s\n", mangled_ctor);
    printf("  getValue:    %s\n", mangled_getval);
    printf("  Destructor:  %s\n\n", mangled_dtor);

    // 3. Manually replicate `new MyClass(100);`
    printf("Simulating `MyClass* obj = new MyClass(100);`\n");

    //  3a. Allocate raw memory for the object.
    size_t obj_size = get_sizeof_myclass();
    void * obj_memory = malloc(obj_size);
    printf("Step 1: Allocated %zu bytes for object at address %p\n", obj_size, obj_memory);

    //  3b. Call the constructor on the allocated memory.
    //      Signature: void MyClass(MyClass* this, int val) -> "(*void, int) -> void"
    void * ctor_ptr = infix_library_get_symbol(lib, mangled_ctor);
    if (!ctor_ptr) {
        fprintf(stderr, "Failed to find mangled constructor symbol: %s\n", mangled_ctor);
        infix_library_close(lib);
        return 1;
    }
    infix_forward_t * t_ctor;
    (void)infix_forward_create(&t_ctor, "(*void, int)->void", ctor_ptr, NULL);

    int initial_val = 100;
    void * ctor_args[] = {&obj_memory, &initial_val};

    printf("Step 2: Calling constructor...\n");
    infix_forward_get_code(t_ctor)(NULL, ctor_args);  // No return value
    printf("Object constructed.\n\n");

    // 4. Call a member function on the constructed object.
    //    Signature: int getValue(const MyClass* this) -> "(*void)->int"
    void * getval_ptr = infix_library_get_symbol(lib, mangled_getval);
    if (!getval_ptr) {
        fprintf(stderr, "Failed to find mangled getValue symbol: %s\n", mangled_getval);
        // clean up and exit...
        free(obj_memory);
        infix_library_close(lib);
        return 1;
    }
    infix_forward_t * t_getval;
    (void)infix_forward_create(&t_getval, "(*void)->int", getval_ptr, NULL);

    int result;
    void * getval_args[] = {&obj_memory};

    printf("Calling member function `getValue()` via FFI...\n");
    infix_forward_get_code(t_getval)(&result, getval_args);
    printf("Result from getValue(): %d (Expected: 100)\n\n", result);

    // 5. Manually replicate `delete obj;`
    printf("Simulating `delete obj;`\n");

    //  5a. Call the destructor.
    //      Signature: void ~MyClass(MyClass* this) -> "(*void)->void"
    void * dtor_ptr = infix_library_get_symbol(lib, mangled_dtor);
    infix_forward_t * t_dtor;
    (void)infix_forward_create(&t_dtor, "(*void)->void", dtor_ptr, NULL);

    void * dtor_args[] = {&obj_memory};
    printf("Step 1: Calling destructor...\n");
    infix_forward_get_code(t_dtor)(NULL, dtor_args);

    //  5b. Free the raw memory.
    printf("Step 2: Freeing object memory at %p\n", obj_memory);
    free(obj_memory);
    printf("Object destroyed and memory freed.\n\n");

    // 6. Clean up all resources.
    infix_forward_destroy(t_ctor);
    infix_forward_destroy(t_getval);
    infix_forward_destroy(t_dtor);
    infix_library_close(lib);

    return 0;
}
