/**
 * @file Ch05_CppTemplates.c
 * @brief Cookbook Chapter 5: Interfacing with C++ Templates
 *
 * This example demonstrates calling a specific instantiation of a C++ template
 * class. While you can't call the template itself, you can find the mangled
 * name for a concrete instantiation (e.g., `Box<double>`) and call its methods.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Mangled name for `Box<double>::get_value()` on GCC/Clang (Itanium ABI)
const char * MANGLED_GET_DBL = "_ZNK3BoxIdE9get_valueEv";

#if defined(_WIN32)
const char * LIB_NAME = "box.dll";
#else
const char * LIB_NAME = "./libbox.so";
#endif

int main() {
    printf("Cookbook Chapter 5: Interfacing with C++ Templates\n");

    infix_library_t * lib = infix_library_open(LIB_NAME);
    if (!lib) {
        fprintf(stderr, "Failed to open library '%s'.\n", LIB_NAME);
        return 1;
    }

    // In a real scenario, you would call the mangled constructor.
    // For simplicity, we'll just allocate memory and place the value directly.
    double val = 3.14;
    void * my_box = malloc(sizeof(double));
    memcpy(my_box, &val, sizeof(double));
    printf("Manually created a C++ 'Box<double>' object containing %f.\n", val);

    void * p_get_value = infix_library_get_symbol(lib, MANGLED_GET_DBL);
    if (!p_get_value) {
        fprintf(stderr,
                "Failed to find mangled template function '%s'. (Note: mangled names differ between compilers).\n",
                MANGLED_GET_DBL);
        free(my_box);
        infix_library_close(lib);
        return 1;
    }

    // Signature: double get_value(const Box<double>* this) -> "(*void) -> double"
    infix_forward_t * t_get = NULL;
    (void)infix_forward_create(&t_get, "(*void) -> double", p_get_value, NULL);

    double result;
    infix_forward_get_code(t_get)(&result, (void *[]){&my_box});

    printf("Value from C++ template object's get_value() method: %f (Expected: 3.14)\n", result);

    free(my_box);
    infix_forward_destroy(t_get);
    infix_library_close(lib);

    return 0;
}
