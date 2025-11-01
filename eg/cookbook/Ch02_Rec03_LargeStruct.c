/**
 * @file Ch02_Rec03_LargeStruct.c
 * @brief Cookbook Chapter 2, Recipe 3: Large Structs Passed by Reference
 *
 * This example demonstrates how `infix` handles structs that are too large to
 * fit in registers. The C ABI specifies that such structs are passed by
 * reference (i.e., a pointer to the struct is passed) or on the stack. From the
 * `infix` user's perspective, the signature and call process are identical to
 * a small struct; the library's ABI logic automatically handles the correct
 * passing convention.
 */
#include <infix/infix.h>
#include <stdio.h>

// A struct that is larger than 16 bytes, ensuring it will not be passed
// entirely in registers on common 64-bit ABIs.
typedef struct {
    int data[8];
} LargeStruct;

// A native C function that takes the large struct by value.
// The compiler will implement this as a pass-by-reference call under the hood.
static int get_first_element(LargeStruct s) { return s.data[0]; }

int main() {
    printf("--- Cookbook Chapter 2, Recipe 3: Large Structs Passed by Reference ---\n");

    // 1. Describe the signature for: int get_first_element(LargeStruct s);
    //    The signature describes the struct by its contents.
    const char * signature = "({[8:int]}) -> int";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)get_first_element, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare the struct argument and call. Even though the ABI will pass a
    //    pointer, the FFI call site still passes a pointer *to the struct value*.
    LargeStruct my_struct = {{123, -1, -1, -1, -1, -1, -1, -1}};
    void * args[] = {&my_struct};
    int result;

    cif(&result, args);

    printf("Calling get_first_element() with a large struct...\n");
    printf("Result: %d (Expected: 123)\n", result);

    // 4. Clean up.
    infix_forward_destroy(t);

    return 0;
}
