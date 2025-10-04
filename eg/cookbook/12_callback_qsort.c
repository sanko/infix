/**
 * @file 12_callback_qsort.c
 * @brief Recipe: Creating a Stateless Callback for `qsort`.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-creating-a-stateless-callback-for-qsort
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// This is our C handler. Its signature must match the callback's public signature,
// but with `infix_context_t*` as the very first argument.
// `qsort` expects: int(const void*, const void*)
// Our handler is: int(infix_context_t*, const void*, const void*)
int compare_ints_handler(infix_context_t * context, const void * a, const void * b) {
    (void)context;  // The context is unused in this stateless example.

    int int_a = *(const int *)a;
    int int_b = *(const int *)b;

    if (int_a < int_b)
        return -1;
    if (int_a > int_b)
        return 1;
    return 0;
}

int main() {
    // 1. Describe the signature `qsort` expects for its comparison function:
    //    int(const void*, const void*)
<<<<<<< HEAD
    const char * qsort_compare_sig = "(*void, *void) -> int32";
=======
    const char * qsort_compare_sig = "v*,v*=>i";
>>>>>>> main
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, qsort_compare_sig, (void *)compare_ints_handler, NULL);

    // 2. Get the native, callable function pointer from the reverse trampoline.
    //    This pointer can be given to any C library that expects this signature.
    int (*comparison_func_ptr)(const void *, const void *) =
        (int (*)(const void *, const void *))infix_reverse_get_code(rt);

    // 3. Call `qsort` with our generated function pointer.
    int numbers[] = {5, 2, 8, 1, 9};
    qsort(numbers, 5, sizeof(int), comparison_func_ptr);

    printf("Sorted numbers: ");
    for (size_t i = 0; i < 5; ++i) {
        printf("%d ", numbers[i]);
    }
    printf("\n");

    // 4. Clean up the reverse trampoline.
    infix_reverse_destroy(rt);
    return 0;
}
