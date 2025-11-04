/**
 * @file Ch02_ArrayDecay.c
 * @brief Cookbook Chapter 2: Working with Fixed-Size Arrays
 *
 * This example clarifies a common point of confusion when working with arrays in C.
 * When an array is passed as a function argument, it "decays" into a pointer to
 * its first element. Therefore, the `infix` signature must describe it as a pointer,
 * not an array type.
 *
 * The `[N:type]` array syntax is only used to describe an array when it is a
 * member of a struct or a return type (a rare case).
 */
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// A native C function that takes an array. In C, the `arr[4]` syntax in a
// function parameter is purely cosmetic; the compiler treats it as `arr*`.
// We add a `count` parameter to make the function safe.
static int64_t sum_array_elements(const int64_t * arr, size_t count) {
    int64_t sum = 0;
    for (size_t i = 0; i < count; ++i)
        sum += arr[i];
    return sum;
}

int main() {
    printf("--- Cookbook Chapter 2: Working with Fixed-Size Arrays ---\n");

    // 1. Describe the signature for: int64_t sum_array_elements(const int64_t* arr, size_t count);
    //    Even though the original C declaration might look like `arr[4]`, it decays
    //    to a pointer, so the signature must be `*sint64`. We use `size_t` for the count.
    const char * signature = "(*sint64, size_t) -> sint64";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)sum_array_elements, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare the array and other arguments.
    int64_t my_array[] = {10, 20, 30, 40};
    // The argument we pass is a pointer to the array (or its first element).
    const int64_t * ptr_to_array = my_array;
    size_t count = 4;
    void * args[] = {&ptr_to_array, &count};
    int64_t result = 0;

    // 4. Call the function.
    cif(&result, args);

    printf("Calling function that takes a pointer to an array...\n");
    printf("Sum of array is: %lld (Expected: 100)\n", (long long)result);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}
