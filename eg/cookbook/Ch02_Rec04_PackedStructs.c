/**
 * @file Ch02_Rec04_PackedStructs.c
 * @brief Cookbook Chapter 2, Recipe 4: Working with Packed Structs
 *
 * This example demonstrates how to interface with C structs that have non-default
 * alignment, typically specified with `#pragma pack(1)` or `__attribute__((packed))`.
 * The `infix` signature language supports this with the `!{...}` syntax for 1-byte
 * alignment, or `!N:{...}` for a specific N-byte alignment.
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

// 1. Define a packed struct. Without packing, this struct would typically be
//    16 bytes with 8-byte alignment due to the uint64_t member. With packing,
//    it is 9 bytes with 1-byte alignment.
#pragma pack(push, 1)
typedef struct {
    char a;
    uint64_t b;
} Packed;
#pragma pack(pop)

// The native C function to be called.
static int process_packed(Packed p) {
    // Check if the members were received correctly despite the unusual layout.
    return (p.a == 'X' && p.b == 0x1122334455667788ULL) ? 42 : -1;
}

int main() {
    printf("--- Cookbook Chapter 2, Recipe 4: Working with Packed Structs ---\n");

    // 2. The signature uses `!{...}` to indicate a packed layout. `infix` will
    //    calculate the correct unpadded size and 1-byte alignment.
    const char * signature = "(!{char, uint64}) -> int";

    // 3. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)process_packed, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 4. Prepare the packed struct instance and call.
    Packed p = {'X', 0x1122334455667788ULL};
    int result = 0;
    void * args[] = {&p};

    cif(&result, args);

    printf("Calling a function with a 9-byte packed struct...\n");
    printf("Result: %d (Expected: 42)\n", result);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}
