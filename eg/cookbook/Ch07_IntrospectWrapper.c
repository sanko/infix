/**
 * @file Ch07_IntrospectWrapper.c
 * @brief Cookbook Chapter 7: Introspecting a Trampoline for a Wrapper
 *
 * This example demonstrates how a language binding or a generic wrapper function
 * can use the trampoline introspection API to validate arguments at runtime before
 * making an FFI call. This allows for more robust error checking.
 */
#include <infix/infix.h>
#include <stdbool.h>
#include <stdio.h>

// A simple C function to be our FFI target.
static int add_and_multiply(int a, double b) { return (int)((double)a * b); }

/**
 * @brief A conceptual generic "wrapper" function for an unbound trampoline.
 *
 * In a real language binding, this function would take language-native objects
 * as arguments, unbox them into a C `void**` array, and perform type checking.
 *
 * @param trampoline An unbound trampoline for the desired signature.
 * @param target_func The native C function to call.
 * @param args An array of pointers to the C argument values.
 * @param num_provided_args The number of arguments provided by the caller.
 * @param ret_buffer A buffer to receive the return value.
 * @return `true` on success, `false` on failure.
 */
static bool dynamic_wrapper(
    infix_forward_t * trampoline, void * target_func, void ** args, size_t num_provided_args, void * ret_buffer) {
    printf("Inside dynamic_wrapper\n");

    // 1. Introspect the trampoline to get expected argument count.
    size_t num_expected_args = infix_forward_get_num_args(trampoline);
    printf("Introspection: Trampoline expects %zu arguments.\n", num_expected_args);

    if (num_provided_args != num_expected_args) {
        fprintf(stderr,
                "ERROR: Incorrect number of arguments. Expected %zu, but got %zu.\n",
                num_expected_args,
                num_provided_args);
        return false;
    }

    // A real binding would also loop through and check the types of each argument
    // using `infix_forward_get_arg_type(trampoline, i)`.

    printf("Argument count matches. Making FFI call...\n");

    // 2. Make the call using the unbound function pointer.
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
    cif(target_func, ret_buffer, args);

    printf("Exiting dynamic_wrapper\n");
    return true;
}

int main() {
    printf("Cookbook Chapter 7: Introspecting a Trampoline\n");

    const char * signature = "(int, double) -> int";
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create_unbound(&trampoline, signature, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }

    // Test Case 1: Correct number of arguments
    printf("\nCalling wrapper with correct number of arguments\n");
    int a1 = 10;
    double b1 = 4.2;
    void * correct_args[] = {&a1, &b1};
    int result1 = 0;
    dynamic_wrapper(trampoline, (void *)add_and_multiply, correct_args, 2, &result1);
    printf("Wrapper call finished. Result: %d (Expected: 42)\n", result1);

    // Test Case 2: Incorrect number of arguments
    printf("\nCalling wrapper with incorrect number of arguments\n");
    int a2 = 10;
    void * incorrect_args[] = {&a2};
    int result2 = 0;
    dynamic_wrapper(trampoline, (void *)add_and_multiply, incorrect_args, 1, &result2);

    infix_forward_destroy(trampoline);

    return 0;
}
