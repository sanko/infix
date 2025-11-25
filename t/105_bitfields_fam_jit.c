/**
 * @file 105_bitfields_fam_jit.c
 * @brief End-to-end JIT execution tests for Bitfields and Flexible Array Members.
 * @ingroup test_suite
 *
 * @details This test validates that the JIT engine correctly handles the data marshaling
 * for types with advanced layout rules.
 *
 * 1. Bitfields: Verifies that a struct with sub-byte bitfields is passed by value
 *    correctly. This ensures the JIT treats the struct as a contiguous block of
 *    sized bytes and doesn't corrupt the internal bit packing.
 *
 * 2. Flexible Array Members (FAM): Verifies that passing a pointer to a struct with
 *    a FAM works, allowing the C function to access data beyond the struct's nominal size.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Native C Definitions

// A struct with bitfields that fits in 2 bytes
// Layout (Little Endian usually):
// Byte 0: [bbbaaaaa] (a:5, b:3)
// Byte 1: [00000ccc] (c:3, padding:5)
typedef struct {
    uint8_t a : 5;
    uint8_t b : 3;
    uint8_t c : 3;
} BitfieldStruct;

// A struct with a flexible array member
typedef struct {
    uint32_t count;
    double values[];  // FAM
} FlexStruct;

// Native C Functions

// Verifies the bitfields contain specific values
int check_bitfields(BitfieldStruct bfs) {
    note("C received bitfields: a=%d, b=%d, c=%d", bfs.a, bfs.b, bfs.c);
    if (bfs.a == 0x1F && bfs.b == 0x05 && bfs.c == 0x07)
        return 1;
    return 0;
}

// Sums the values in the flexible array
double sum_flexible_array(FlexStruct * fs) {
    double total = 0;
    for (uint32_t i = 0; i < fs->count; ++i)
        total += fs->values[i];
    return total;
}

TEST {
    plan(2);
    infix_arena_t * arena = infix_arena_create(4096);

    subtest("Bitfields passed by value") {
        plan(3);

        // Define the Infix Type
        infix_type * u8 = infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);
        infix_struct_member members[] = {infix_type_create_bitfield_member("a", u8, 0, 5),
                                         infix_type_create_bitfield_member("b", u8, 0, 3),
                                         infix_type_create_bitfield_member("c", u8, 0, 3)};

        infix_type * bf_type = NULL;
        infix_status status = infix_type_create_struct(arena, &bf_type, members, 3);
        ok(status == INFIX_SUCCESS, "Created bitfield type");

        // Create Trampoline
        infix_forward_t * t = NULL;
        status = infix_forward_create_manual(&t,
                                             infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),  // ret: int
                                             &bf_type,
                                             1,
                                             1,  // args: [BitfieldStruct]
                                             (void *)check_bitfields);
        ok(status == INFIX_SUCCESS, "Created trampoline for bitfield function");

        // Manually pack the bits to match the expected C values:
        // a=31 (0x1F), b=5 (0x5), c=7 (0x7)
        BitfieldStruct arg;
        arg.a = 0x1F;
        arg.b = 0x05;
        arg.c = 0x07;

        int result = 0;
        void * args[] = {&arg};

        infix_cif_func cif = infix_forward_get_code(t);
        cif(&result, args);

        ok(result == 1, "Bitfield struct was passed correctly by value");

        infix_forward_destroy(t);
    }

    subtest("Flexible Array Member passed by pointer") {
        plan(4);

        // Define the Infix Type
        infix_type * dbl = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
        infix_type * fam_array = NULL;
        infix_type_create_flexible_array(arena, &fam_array, dbl);

        infix_struct_member members[] = {
            infix_type_create_member("count", infix_type_create_primitive(INFIX_PRIMITIVE_UINT32), 0),
            infix_type_create_member("values", fam_array, 0)};

        infix_type * flex_type = NULL;
        infix_status status = infix_type_create_struct(arena, &flex_type, members, 2);
        ok(status == INFIX_SUCCESS, "Created struct with FAM type");

        // Create Trampoline
        // Signature: (*FlexStruct) -> double
        infix_type * ptr_to_flex = NULL;
        ok(infix_type_create_pointer_to(arena, &ptr_to_flex, flex_type) == INFIX_SUCCESS,
           "Created pointer to flexible struct");

        infix_forward_t * t = NULL;
        status = infix_forward_create_manual(&t,
                                             dbl,  // ret: double
                                             &ptr_to_flex,
                                             1,
                                             1,  // args: [*FlexStruct]
                                             (void *)sum_flexible_array);
        ok(status == INFIX_SUCCESS, "Created trampoline for FAM function");

        // Execute
        // Allocate enough memory for the struct + 3 doubles
        size_t alloc_size = sizeof(FlexStruct) + (sizeof(double) * 3);
        FlexStruct * arg = malloc(alloc_size);
        arg->count = 3;
        arg->values[0] = 1.1;
        arg->values[1] = 2.2;
        arg->values[2] = 3.3;

        double result = 0;
        void * args[] = {&arg};  // Pass address of the pointer

        infix_cif_func cif = infix_forward_get_code(t);
        cif(&result, args);

        // 1.1 + 2.2 + 3.3 = 6.6
        // Use a small epsilon for float comparison
        double diff = result - 6.6;
        if (diff < 0)
            diff = -diff;

        ok(diff < 0.0001, "FAM accessed correctly (got %.2f, expected 6.60)", result);

        free(arg);
        infix_forward_destroy(t);
    }

    infix_arena_destroy(arena);
}
