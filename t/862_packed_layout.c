/**
 * @file 862_packed_layout.c
 * @brief Regression test for packed struct layout through signature parsing.
 * @ingroup test_suite
 *
 * @details Verifies that packed structs parsed via `infix_type_from_signature`
 * (the `!{...}` syntax) produce correct member offsets and total sizes through the
 * `_layout_struct` code path.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    char a;
    int b;
} packed_char_int;
typedef struct {
    char a;
    uint64_t b;
} packed_char_u64;
typedef struct {
    int a;
    char b;
    int c;
} packed_int_char_int;
typedef struct {
    char a;
    short b;
    int c;
    long long d;
} packed_mixed;
#pragma pack()

TEST {
    plan(5);

    subtest("Parsed !{char,int} -- size and offsets") {
        plan(4);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        ok(infix_type_from_signature(&type, &arena, "!{a:char,b:sint32}", NULL) == INFIX_SUCCESS,
           "Parsed !{a:char,b:sint32}");
        if (type) {
            ok(type->size == sizeof(packed_char_int), "Size should be %lu", (unsigned long)sizeof(packed_char_int));
            const infix_struct_member * mem_a = infix_type_get_member(type, 0);
            const infix_struct_member * mem_b = infix_type_get_member(type, 1);
            ok(mem_a && mem_a->offset == 0, "Offset of 'a' should be 0");
            ok(mem_b && mem_b->offset == 1, "Offset of 'b' should be 1");
        }
        else
            skip(3, "Skipping layout checks due to parse failure");
        infix_arena_destroy(arena);
    }

    subtest("Parsed !{char,uint64_t} -- size and offsets") {
        plan(4);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        ok(infix_type_from_signature(&type, &arena, "!{a:char,b:uint64}", NULL) == INFIX_SUCCESS,
           "Parsed !{a:char,b:uint64}");
        if (type) {
            ok(type->size == sizeof(packed_char_u64), "Size should be %lu", (unsigned long)sizeof(packed_char_u64));
            const infix_struct_member * mem_b = infix_type_get_member(type, 1);
            ok(mem_b && mem_b->offset == 1, "Offset of 'b' should be 1");
            ok(type->alignment == 1, "Alignment should be 1 for packed struct");
        }
        else
            skip(3, "Skipping layout checks due to parse failure");
        infix_arena_destroy(arena);
    }

    subtest("Parsed !{int,char,int} -- three members") {
        plan(5);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        ok(infix_type_from_signature(&type, &arena, "!{a:sint32,b:char,c:sint32}", NULL) == INFIX_SUCCESS,
           "Parsed !{a:sint32,b:char,c:sint32}");
        if (type) {
            ok(type->size == sizeof(packed_int_char_int),
               "Size should be %lu",
               (unsigned long)sizeof(packed_int_char_int));
            const infix_struct_member * mem_a = infix_type_get_member(type, 0);
            const infix_struct_member * mem_b = infix_type_get_member(type, 1);
            const infix_struct_member * mem_c = infix_type_get_member(type, 2);
            ok(mem_a && mem_a->offset == 0, "Offset of 'a' should be 0");
            ok(mem_b && mem_b->offset == 4, "Offset of 'b' should be 4");
            ok(mem_c && mem_c->offset == 5, "Offset of 'c' should be 5");
        }
        else
            skip(4, "Skipping layout checks due to parse failure");
        infix_arena_destroy(arena);
    }

    subtest("Parsed !{char,short,int,longlong} -- mixed types") {
        plan(7);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        ok(infix_type_from_signature(&type, &arena, "!{a:char,b:sint16,c:sint32,d:sint64}", NULL) == INFIX_SUCCESS,
           "Parsed !{a:char,b:sint16,c:sint32,d:sint64}");
        if (type) {
            ok(type->size == sizeof(packed_mixed), "Size should be %lu", (unsigned long)sizeof(packed_mixed));
            const infix_struct_member * ma = infix_type_get_member(type, 0);
            const infix_struct_member * mb = infix_type_get_member(type, 1);
            const infix_struct_member * mc = infix_type_get_member(type, 2);
            const infix_struct_member * md = infix_type_get_member(type, 3);
            ok(ma && ma->offset == 0, "Offset of 'a' should be 0");
            ok(mb && mb->offset == 1, "Offset of 'b' should be 1");
            ok(mc && mc->offset == 3, "Offset of 'c' should be 3");
            ok(md && md->offset == 7, "Offset of 'd' should be 7");
            ok(type->alignment == 1, "Alignment should be 1");
        }
        else
            skip(6, "Skipping layout checks due to parse failure");
        infix_arena_destroy(arena);
    }

    subtest("Print roundtrip for packed struct") {
        plan(2);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        ok(infix_type_from_signature(&type, &arena, "!{a:char,b:sint32}", NULL) == INFIX_SUCCESS,
           "Parse !{a:char,b:sint32}");
        if (type) {
            char buf[256];
            infix_status status = infix_type_print(buf, sizeof(buf), type, INFIX_DIALECT_SIGNATURE);
            ok(status == INFIX_SUCCESS && strstr(buf, "!") != NULL,
               "Printed signature should contain '!' prefix: %s",
               buf);
        }
        else
            fail("Skipping print check due to parse failure");
        infix_arena_destroy(arena);
    }
}
