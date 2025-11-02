/**
 * @file Ch06_Rec03_LibraryDependencies.c
 * @brief Cookbook Chapter 6, Recipe 3: Handling Library Dependencies
 *
 * This example demonstrates that `infix` does not require any special handling
 * when loading a shared library that itself depends on other shared libraries.
 * The operating system's dynamic linker automatically handles loading and
 * linking all necessary dependencies.
 *
 * This example loads `libA`, which internally calls a function from `libB`.
 */
#include <infix/infix.h>
#include <stdio.h>

#if defined(_WIN32)
const char * LIB_A_NAME = "libA.dll";
#else
const char * LIB_A_NAME = "./libA.so";
#endif

int main() {
    printf("--- Cookbook Chapter 6, Recipe 3: Handling Library Dependencies ---\n");

    // 1. We only need to open the top-level library, `libA`.
    //    The OS dynamic linker will automatically find and load `libB.so`/`.dll`
    //    because `libA` was linked against it.
    printf("Loading library '%s'...\n", LIB_A_NAME);
    infix_library_t * lib = infix_library_open(LIB_A_NAME);
    if (!lib) {
        fprintf(stderr,
                "Failed to open library '%s'. Make sure its dependency (libB) is in the same directory.\n",
                LIB_A_NAME);
        return 1;
    }
    printf("Library loaded successfully.\n");

    // 2. Get the symbol from `libA`.
    void * p_entry = infix_library_get_symbol(lib, "entry_point_a");
    if (!p_entry) {
        fprintf(stderr, "Failed to find 'entry_point_a'.\n");
        infix_library_close(lib);
        return 1;
    }

    // 3. Create a trampoline and call the function.
    infix_forward_t * t = NULL;
    (void)infix_forward_create(&t, "()->int", p_entry, NULL);

    int result;
    infix_forward_get_code(t)(&result, NULL);

    printf("Called 'entry_point_a()' from libA...\n");
    printf("Result from chained libraries: %d (Expected: 300)\n", result);

    // 4. Clean up.
    infix_forward_destroy(t);
    infix_library_close(lib);

    return 0;
}
