/**
 * @file 862_packed_layout.c
 * @brief Regression test for packed struct layout and by-value returns.
 * @ingroup test_suite
 *
 * @details Verifies that packed structs parsed via `infix_type_from_signature`
 * (the `!{...}` syntax) produce correct member offsets and total sizes through the
 * `_layout_struct` code path. Also verifies that packed structs with non-power-of-2
 * sizes are correctly returned by value through forward trampolines.
 *
 * On AAPCS64, structs <= 16 bytes are returned in X0 (bytes 0-7) and X1 (bytes 8-15).
 * The forward trampoline epilogue must decompose the return buffer write into
 * correct sub-register stores for each chunk. Prior to the fix, sizes other than
 * {1, 2, 4, 8, 16} hit `default: break;` and wrote zero bytes.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include "types.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
#pragma pack(pop)

PackedABC return_packed_abc(void) { return (PackedABC){42, -66, 99}; }
PackedTiny return_packed_tiny(void) { return (PackedTiny){-1, 300}; }
PackedSix return_packed_six(void) { return (PackedSix){10, 20, 3000}; }

static infix_type * create_packed_abc_type(infix_arena_t * arena) {
    infix_struct_member * members =
        infix_arena_alloc(arena, 3 * sizeof(infix_struct_member), _Alignof(infix_struct_member));
    members[0] = infix_type_create_member("a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0);
    members[1] = infix_type_create_member("b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 4);
    members[2] = infix_type_create_member("c", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 5);
    infix_type * type = nullptr;
    if (infix_type_create_packed_struct(arena, &type, sizeof(PackedABC), 1, members, 3) != INFIX_SUCCESS)
        return nullptr;
    return type;
}

static infix_type * create_packed_tiny_type(infix_arena_t * arena) {
    infix_struct_member * members =
        infix_arena_alloc(arena, 2 * sizeof(infix_struct_member), _Alignof(infix_struct_member));
    members[0] = infix_type_create_member("a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0);
    members[1] = infix_type_create_member("b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT16), 1);
    infix_type * type = nullptr;
    if (infix_type_create_packed_struct(arena, &type, sizeof(PackedTiny), 1, members, 2) != INFIX_SUCCESS)
        return nullptr;
    return type;
}

static infix_type * create_packed_six_type(infix_arena_t * arena) {
    infix_struct_member * members =
        infix_arena_alloc(arena, 3 * sizeof(infix_struct_member), _Alignof(infix_struct_member));
    members[0] = infix_type_create_member("a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0);
    members[1] = infix_type_create_member("b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 1);
    members[2] = infix_type_create_member("c", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 2);
    infix_type * type = nullptr;
    if (infix_type_create_packed_struct(arena, &type, sizeof(PackedSix), 1, members, 3) != INFIX_SUCCESS)
        return nullptr;
    return type;
}

TEST {
    plan(8);

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

    subtest("By-value return -- PackedABC (9 bytes)") {
        plan(7);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * packed_type = create_packed_abc_type(arena);
        if (!ok(packed_type != nullptr, "PackedABC type created")) {
            skip(6, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        ok(packed_type->size == 9, "Size is 9 bytes");
        ok(packed_type->alignment == 1, "Alignment is 1");

        infix_forward_t *unbound = nullptr, *bound = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound, packed_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Unbound forward trampoline created");
        ok(infix_forward_create_manual(&bound, packed_type, nullptr, 0, 0, (void *)return_packed_abc) == INFIX_SUCCESS,
           "Bound forward trampoline created");

        PackedABC unbound_res = {0, 0, 0}, bound_res = {0, 0, 0};
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound);
        unbound_cif((void *)return_packed_abc, &unbound_res, nullptr);
        infix_cif_func bound_cif = infix_forward_get_code(bound);
        bound_cif(&bound_res, nullptr);

        ok(unbound_res.a == 42 && unbound_res.b == -66 && unbound_res.c == 99,
           "Unbound: fields correct (a=%d, b=%d, c=%d)",
           unbound_res.a,
           unbound_res.b,
           unbound_res.c);
        ok(bound_res.a == 42 && bound_res.b == -66 && bound_res.c == 99,
           "Bound: fields correct (a=%d, b=%d, c=%d)",
           bound_res.a,
           bound_res.b,
           bound_res.c);

        infix_forward_destroy(unbound);
        infix_forward_destroy(bound);
        infix_arena_destroy(arena);
    }

    subtest("By-value return -- PackedTiny (3 bytes)") {
        plan(6);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * packed_type = create_packed_tiny_type(arena);
        if (!ok(packed_type != nullptr, "PackedTiny type created")) {
            skip(5, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        ok(packed_type->size == 3, "Size is 3 bytes");

        infix_forward_t *unbound = nullptr, *bound = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound, packed_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Unbound forward trampoline created");
        ok(infix_forward_create_manual(&bound, packed_type, nullptr, 0, 0, (void *)return_packed_tiny) == INFIX_SUCCESS,
           "Bound forward trampoline created");

        PackedTiny unbound_res = {0, 0}, bound_res = {0, 0};
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound);
        unbound_cif((void *)return_packed_tiny, &unbound_res, nullptr);
        infix_cif_func bound_cif = infix_forward_get_code(bound);
        bound_cif(&bound_res, nullptr);

        ok(unbound_res.a == -1 && unbound_res.b == 300,
           "Unbound: fields correct (a=%d, b=%d)",
           unbound_res.a,
           unbound_res.b);
        ok(bound_res.a == -1 && bound_res.b == 300, "Bound: fields correct (a=%d, b=%d)", bound_res.a, bound_res.b);

        infix_forward_destroy(unbound);
        infix_forward_destroy(bound);
        infix_arena_destroy(arena);
    }

    subtest("By-value return -- PackedSix (6 bytes)") {
        plan(6);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * packed_type = create_packed_six_type(arena);
        if (!ok(packed_type != nullptr, "PackedSix type created")) {
            skip(5, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }
        ok(packed_type->size == 6, "Size is 6 bytes");

        infix_forward_t *unbound = nullptr, *bound = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound, packed_type, nullptr, 0, 0) == INFIX_SUCCESS,
           "Unbound forward trampoline created");
        ok(infix_forward_create_manual(&bound, packed_type, nullptr, 0, 0, (void *)return_packed_six) == INFIX_SUCCESS,
           "Bound forward trampoline created");

        PackedSix unbound_res = {0, 0, 0}, bound_res = {0, 0, 0};
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound);
        unbound_cif((void *)return_packed_six, &unbound_res, nullptr);
        infix_cif_func bound_cif = infix_forward_get_code(bound);
        bound_cif(&bound_res, nullptr);

        ok(unbound_res.a == 10 && unbound_res.b == 20 && unbound_res.c == 3000,
           "Unbound: fields correct (a=%d, b=%d, c=%d)",
           unbound_res.a,
           unbound_res.b,
           unbound_res.c);
        ok(bound_res.a == 10 && bound_res.b == 20 && bound_res.c == 3000,
           "Bound: fields correct (a=%d, b=%d, c=%d)",
           bound_res.a,
           bound_res.b,
           bound_res.c);

        infix_forward_destroy(unbound);
        infix_forward_destroy(bound);
        infix_arena_destroy(arena);
    }
}
