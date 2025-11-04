/**
 * @file Ch03_QsortCallback.c
 * @brief Cookbook Chapter 3: Creating a Type-Safe Callback for `qsort`
 *
 * This example demonstrates a "reverse call" or callback. We generate a native
 * C function pointer that can be passed to a C library function that expects one.
 * Here, we use `infix_reverse_create_callback` to create a comparison function
 * for the standard library's `qsort`.
 *
 * The key feature of this API is that the handler function (`compare_integers_handler`)
 * has a clean, type-safe C signature that exactly matches what `qsort` expects.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// 1. The handler function has a standard C signature. No context pointer or
//    generic argument arrays are needed for this high-level API.
static int compare_integers_handler(const void * a, const void * b) {
    // Standard comparison logic for qsort.
    return (*(const int *)a - *(const int *)b);
}

int main() {
    printf("--- Cookbook Chapter 3: Creating a Type-Safe Callback ---\n");

    // 2. Define the signature for the qsort comparison function:
    //    int (*)(const void*, const void*)
    const char * cmp_sig = "(*void, *void) -> int";

    // 3. Create the reverse trampoline (callback).
    infix_reverse_t * context = NULL;
    infix_status status = infix_reverse_create_callback(&context, cmp_sig, (void *)compare_integers_handler, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create reverse trampoline.\n");
        return 1;
    }

    // 4. Get the native, JIT-compiled function pointer from the context.
    typedef int (*compare_func_t)(const void *, const void *);
    compare_func_t my_comparator = (compare_func_t)infix_reverse_get_code(context);

    // 5. Use the generated callback with the C library function.
    int numbers[] = {5, 1, 4, 2, 3};
    size_t num_count = sizeof(numbers) / sizeof(numbers[0]);

    printf("Array before qsort: [ 5 1 4 2 3 ]\n");
    qsort(numbers, num_count, sizeof(int), my_comparator);
    printf("Array after qsort:  [ ");
    for (size_t i = 0; i < num_count; ++i)
        printf("%d ", numbers[i]);
    printf("]\n");

    // 6. Clean up.
    infix_reverse_destroy(context);

    return 0;
}
