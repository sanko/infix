/**
 * @file 09_packed_struct.c
 * @brief Recipe: Working with Packed Structs via the Signature API.
 * @see
 * https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-working-with-packed-structs-via-the-signature-api
 */
#include "lib/types.h"  // For the definition of PackedStruct
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// A C function that takes our packed struct.
int process_packed(PackedStruct p) {
    return (p.a == 'X' && p.b == 0x1122334455667788ULL) ? 42 : -1;
}

int main() {
    // 1. Describe the packed struct using the `!{...}` syntax.
    //    The `!` indicates a packed struct with default 1-byte alignment.
    //    The infix parser will calculate the correct packed offsets automatically.
    const char * signature = "(!{char, uint64}) -> int";

    printf("Using signature: %s\n", signature);

    // 2. Create the trampoline.
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 3. Prepare arguments and call.
    PackedStruct data = {'X', 0x1122334455667788ULL};
    int result = 0;
    void * args[] = {&data};
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_packed, &result, args);

    printf("Packed struct result: %d\n", result);  // Expected: 42
    infix_forward_destroy(trampoline);
    return 0;
}
