/**
 * @file Ch02_Rec06_Unions.c
 * @brief Cookbook Chapter 2, Recipe 6: Working with Unions
 *
 * This example shows how to pass and return C `union` types. The `infix`
 * signature for a union uses angle brackets `<...>` to list its members.
 * The library calculates the correct size and alignment based on the largest
 * and most-aligned member, respectively, just as a C compiler would.
 */
#include <infix/infix.h>
#include <stdio.h>

// A simple union that can hold either an int or a float.
typedef union {
    int i;
    float f;
} Number;

// Native C function that interprets the union as an integer.
static int process_number_as_int(Number n) { return n.i * 2; }

int main() {
    printf("--- Cookbook Chapter 2, Recipe 6: Working with Unions ---\n");

    // 1. Describe the signature for: int process_number_as_int(Number n);
    //    The union's members are listed inside angle brackets.
    const char * signature = "(<int, float>) -> int";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)process_number_as_int, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare the union argument. We will set its integer member.
    Number num_val;
    num_val.i = 21;
    int result = 0;
    void * args[] = {&num_val};

    // 4. Call the function.
    cif(&result, args);

    printf("Calling function, passing a union containing an integer...\n");
    printf("Result: %d (Expected: 42)\n", result);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}
