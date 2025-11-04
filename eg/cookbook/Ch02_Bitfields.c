/**
 * @file Ch02_Bitfields.c
 * @brief Cookbook Chapter 2: Working with Structs that Contain Bitfields
 *
 * This example demonstrates how to work with C structs that use bitfields. The
 * `infix` signature language has no direct syntax for bitfields because their
 * in-memory layout is implementation-defined and not portable.
 *
 * The solution is to model the struct based on its underlying integer storage
 * type and manually pack/unpack the bitfield values in the host application
 * before and after the FFI call.
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>

// The native C struct with bitfields. It occupies the space of a single uint32_t.
typedef struct {
    uint32_t a : 4;   // 4 bits
    uint32_t b : 12;  // 12 bits
    uint32_t c : 16;  // 16 bits
} BitfieldStruct;

// The native C function we want to call.
static uint32_t process_bitfields(BitfieldStruct s) { return s.a + s.b + s.c; }

int main() {
    printf("--- Cookbook Chapter 2: Working with Bitfields ---\n");

    // 1. Describe the struct by its underlying integer storage. For the FFI
    //    call, we treat it as a `struct { uint32_t; }`.
    const char * signature = "({uint32}) -> uint32";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)process_bitfields, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Manually pack the data into a uint32_t using bitwise operators. This
    //    mirrors what the C compiler does when assigning to bitfield members.
    uint32_t packed_data = 0;
    packed_data |= (15 & 0xF) << 0;         // Field a = 15
    packed_data |= (1000 & 0xFFF) << 4;     // Field b = 1000
    packed_data |= (30000 & 0xFFFF) << 16;  // Field c = 30000

    // 4. The FFI call sees a simple struct containing a single uint32_t.
    void * args[] = {&packed_data};
    uint32_t result;

    cif(&result, args);

    printf("Calling function with manually packed bitfield data...\n");
    printf("Bitfield sum: %u (Expected: 31015)\n", result);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}
