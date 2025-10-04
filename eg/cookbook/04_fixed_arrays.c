/**
 * @file 04_fixed_arrays.c
 * @brief Recipe: Working with Fixed-Size Arrays.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-working-with-fixed-size-arrays
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

// In C, a function parameter declared as an array `arr[4]` is treated as a pointer `arr*`.
// The size information is lost. This function actually takes a pointer.
int64_t sum_array_elements(const int64_t * arr) {
    int64_t sum = 0;
    for (int i = 0; i < 4; ++i)
        sum += arr[i];
    return sum;
}

int main() {
    // 1. Signature describes the decayed pointer type: int64_t(const int64_t*)
    //    'x' is the specifier for int64_t. 'x*' is a pointer to it.
    const char * signature = "x*=>x";
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare the array and the pointer to it.
    int64_t my_array[] = {10, 20, 30, 40};
    const int64_t * ptr_to_array = my_array;  // This is the actual argument.
    void * args[] = {&ptr_to_array};          // The args array holds the address of the pointer.
    int64_t result = 0;

    // 3. Invoke the call.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_array_elements, &result, args);

    printf("Sum of array is: %lld\n", (long long)result);  // Expected: 100

    infix_forward_destroy(trampoline);
    return 0;
}
