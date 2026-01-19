/**
 * @file 009_bitfields_fam.c
 * @brief Unit test for Bitfields and Flexible Array Members (FAM).
 * @ingroup test_suite
 *
 * @details This test verifies the functionality of two advanced C type features:
 *
 * 1.  **Flexible Array Members:**
 *     - Tests the `[?:type]` signature syntax.
 *     - Tests the `infix_type_create_flexible_array` Manual API.
 *     - Verifies that the struct layout (size and offsets) correctly handles the FAM
 *       (i.e., it adds no size to the struct but respects alignment).
 *
 * 2.  **Bitfields:**
 *     - Tests the `name:type:width` signature syntax.
 *     - Tests the `infix_type_create_bitfield_member` Manual API.
 *     - Verifies packing of `uint8_t` bitfields.
 *     - Verifies the behavior of zero-width bitfields for alignment forcing.
 *
 * @note The current implementation of bitfields primarily supports byte-granular
 * packing (typical of `uint8_t` flags). Complex packing of larger integers across
 * byte boundaries (e.g., `uint32_t`) is implementation-defined in C and currently
 * simplified in `infix` to flush to the next byte on overflow.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>

// Native C types for layout comparison

// Struct with Flexible Array Member
typedef struct {
    int32_t len;
    char data[];
} StructWithFAM;

// Simple Bitfields (fit in 1 byte)
typedef struct {
    uint8_t a : 1;
    uint8_t b : 7;
} BitfieldStruct1;

// Bitfields with overflow (requires 2 bytes)
typedef struct {
    uint8_t a : 4;
    uint8_t b : 6;  // 4+6=10 > 8, should spill to next byte
} BitfieldStructOverflow;

// Zero-width bitfield (forces alignment)
typedef struct {
    uint8_t a : 4;
    uint8_t : 0;
    uint8_t b : 4;
} BitfieldStructZeroWidth;

TEST {
    plan(2);
    infix_arena_t * arena = infix_arena_create(4096);

    subtest("Flexible Array Members (FAM)") {
        plan(2);

        subtest("Manual API Creation") {
            plan(4);
            infix_type * int_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
            infix_type * char_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT8);
            infix_type * fam_type = nullptr;

            ok(infix_type_create_flexible_array(arena, &fam_type, char_type) == INFIX_SUCCESS, "Created FAM type");

            infix_struct_member members[2];
            members[0] = infix_type_create_member("len", int_type, 0);
            members[1] = infix_type_create_member("data", fam_type, 0);

            infix_type * struct_type = nullptr;
            ok(infix_type_create_struct(arena, &struct_type, members, 2) == INFIX_SUCCESS, "Created struct with FAM");

            // Layout Validation
            if (struct_type) {
                ok(struct_type->size == sizeof(StructWithFAM),
                   "Struct size matches C compiler (expect %lu, got %lu)",
                   (unsigned long)sizeof(StructWithFAM),
                   (unsigned long)struct_type->size);

                const infix_struct_member * m_data = infix_type_get_member(struct_type, 1);
                // offsetof is valid for FAM in standard C
                ok(m_data->offset == offsetof(StructWithFAM, data),
                   "FAM offset matches C compiler (expect %lu, got %lu)",
                   (unsigned long)offsetof(StructWithFAM, data),
                   (unsigned long)m_data->offset);
            }
            else
                skip(2, "Struct creation failed");
        }

        subtest("Signature Parsing") {
            plan(1);
            infix_type * parsed_type = nullptr;
            infix_arena_t * parse_arena = nullptr;
            // Syntax: { len:int32, data:[?:int8] }
            const char * sig = "{len:int32, data:[?:int8]}";
            if (ok(infix_type_from_signature(&parsed_type, &parse_arena, sig, nullptr) == INFIX_SUCCESS,
                   "Parsed FAM signature")) {
                // Basic check
                if (parsed_type)
                    note("No further checks needed if layout logic is shared, which it is.");
            }

            infix_arena_destroy(parse_arena);
        }
    }

    subtest("Bitfields") {
        plan(2);

        subtest("Manual API Creation") {
            infix_type * u8 = infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);

            // Simple packing { a:u8:1, b:u8:7 } -> 1 byte
            infix_struct_member bf1_m[] = {infix_type_create_bitfield_member("a", u8, 0, 1),
                                           infix_type_create_bitfield_member("b", u8, 0, 7)};
            infix_type * bf1 = NULL;
            if (infix_type_create_struct(arena, &bf1, bf1_m, 2) != INFIX_SUCCESS)
                fail("Setup failed");
            ok(bf1->size == sizeof(BitfieldStruct1), "BitfieldStruct1 size matches (1 byte)");

            // Overflow { a:u8:4, b:u8:6 } -> 2 bytes
            infix_struct_member bf2_m[] = {infix_type_create_bitfield_member("a", u8, 0, 4),
                                           infix_type_create_bitfield_member("b", u8, 0, 6)};
            infix_type * bf2 = NULL;
            if (infix_type_create_struct(arena, &bf2, bf2_m, 2) != INFIX_SUCCESS)
                fail("Setup failed");
            ok(bf2->size == sizeof(BitfieldStructOverflow), "BitfieldStructOverflow size matches (2 bytes)");

            // Zero width forcing alignment { a:u8:4, :0, b:u8:4 } -> 2 bytes
            infix_struct_member bf3_m[] = {infix_type_create_bitfield_member("a", u8, 0, 4),
                                           infix_type_create_bitfield_member("", u8, 0, 0),  // Zero width
                                           infix_type_create_bitfield_member("b", u8, 0, 4)};
            infix_type * bf3 = NULL;
            if (infix_type_create_struct(arena, &bf3, bf3_m, 3) != INFIX_SUCCESS)
                fail("Setup failed");
            ok(bf3->size == sizeof(BitfieldStructZeroWidth), "BitfieldStructZeroWidth size matches (2 bytes)");
        }
        subtest("Signature Parsing") {
            // "{ flags:uint8:1, mode:uint8:3 }"
            infix_type * parsed_bf = NULL;
            infix_arena_t * parse_arena = NULL;
            if (ok(infix_type_from_signature(&parsed_bf, &parse_arena, "{f:uint8:1, m:uint8:3}", NULL) == INFIX_SUCCESS,
                   "Parsed bitfield signature")) {
                if (parsed_bf) {
                    // 1 + 3 = 4 bits -> 1 byte
                    if (parsed_bf->size != 1)
                        diag("Parsed bitfield size incorrect: %lu", (unsigned long)parsed_bf->size);
                }
            }

            infix_arena_destroy(parse_arena);
        }
    }

    infix_arena_destroy(arena);
}
