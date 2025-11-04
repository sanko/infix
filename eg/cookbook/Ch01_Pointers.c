/**
 * @file Ch01_Pointers.c
 * @brief Cookbook Chapter 1: Passing and Receiving Pointers
 *
 * This example demonstrates how to call a C function that takes a pointer as an
 * argument and also returns a pointer. It uses the standard library function
 * `strchr`. The signature `*char` represents a pointer to a character.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("--- Cookbook Chapter 1: Passing and Receiving Pointers ---\n");

    // 1. Describe the signature for: const char* strchr(const char* s, int c);
    //    Note that `const char*` becomes `*char` and `int` is used for the character.
    const char * signature = "(*char, int) -> *char";

    // 2. Create a "bound" trampoline, which is optimized for calling a single
    //    specific function. The address of `strchr` is compiled into it.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create(&trampoline, signature, (void *)strchr, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create bound trampoline.\n");
        return 1;
    }

    // 3. Get the callable function pointer.
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 4. Prepare arguments. The value for the `*char` argument is the
    //    address of our `const char*` variable.
    const char * haystack = "hello-world";
    int needle = '-';
    void * args[] = {&haystack, &needle};
    const char * result_ptr = NULL;  // Buffer for the returned pointer.

    // 5. Invoke the call.
    cif(&result_ptr, args);

    printf("Calling strchr(\"hello-world\", '-') via infix...\n");
    if (result_ptr)
        printf("strchr found substring: '%s'\n", result_ptr);  // Expected: "-world"
    else
        printf("strchr did not find the character.\n");

    // 6. Clean up.
    infix_forward_destroy(trampoline);

    return 0;
}
