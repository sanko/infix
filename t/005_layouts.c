/**
 * @file 005_layouts.c
 * @brief Unit test for the Manual API's struct and union layout calculations.
 * @ingroup test_suite
 *
 * @details This test file verifies that the layout algorithms in `types.c` (specifically
 * `infix_type_create_struct` and `infix_type_create_union`) produce memory layouts
 * that are identical to those produced by the host C compiler.
 *
 * It defines several native C `struct` and `union` types and then programmatically
 * creates their `infix_type` equivalents. It then asserts that the `size`, `alignment`,
 * and member `offset` fields of the generated types match the results of the `sizeof`,
 * `_Alignof`, and `offsetof` operators on the native types.
 *
 * The test covers:
 * - A struct with standard internal padding.
 * - A struct with no padding.
 * - A struct containing a nested struct.
 * - A packed struct (`#pragma pack(1)`).
 * - A union with members of different sizes and alignments.
 *
 * This test is crucial for ensuring that `infix` can correctly and portably reason
 * about the memory representation of C data structures.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
// Native C types to use as a baseline for layout comparison
/** @internal A test struct with standard internal padding. */
typedef struct {
    char a;
    int b;
} test_struct_padding;
/** @internal A test struct with no internal padding required. */
typedef struct {
    long long a;
    char b;
} test_struct_no_padding;
/** @internal A test struct containing another struct as a member. */
typedef struct {
    char a;
    test_struct_padding b;
} test_struct_nested;
/** @internal A packed test struct with 1-byte alignment. */
#pragma pack(1)
typedef struct {
    char a;
    int b;
} test_struct_packed;
#pragma pack()
/** @internal A test union with members of different sizes and alignments. */
typedef union {
    long long a;
    double b;
    char c[12];
} test_union;
TEST {
    plan(5);
    infix_arena_t * arena = infix_arena_create(4096);
    subtest("Struct with standard padding") {
        plan(5);
        infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                         {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0}};
        infix_type * type = nullptr;
        infix_status status = infix_type_create_struct(arena, &type, members, 2);
        ok(status == INFIX_SUCCESS, "Struct creation should succeed");
        if (type) {
            ok(infix_type_get_size(type) == sizeof(test_struct_padding), "Size should match sizeof");
            ok(infix_type_get_alignment(type) == _Alignof(test_struct_padding), "Alignment should match _Alignof");
            const infix_struct_member * mem_a = infix_type_get_member(type, 0);
            ok(mem_a && mem_a->offset == offsetof(test_struct_padding, a), "Offset of 'a' should match offsetof");
            const infix_struct_member * mem_b = infix_type_get_member(type, 1);
            ok(mem_b && mem_b->offset == offsetof(test_struct_padding, b), "Offset of 'b' should match offsetof");
        }
        else
            skip(4, "Skipping layout checks due to creation failure");
    }
    subtest("Struct with no padding") {
        plan(5);
        infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT64), 0},
                                         {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0}};
        infix_type * type = nullptr;
        infix_status status = infix_type_create_struct(arena, &type, members, 2);
        ok(status == INFIX_SUCCESS, "Struct creation should succeed");
        if (type) {
            ok(infix_type_get_size(type) == sizeof(test_struct_no_padding), "Size should match sizeof");
            ok(infix_type_get_alignment(type) == _Alignof(test_struct_no_padding), "Alignment should match _Alignof");
            ok(infix_type_get_member(type, 0)->offset == offsetof(test_struct_no_padding, a), "Offset of 'a' matches");
            ok(infix_type_get_member(type, 1)->offset == offsetof(test_struct_no_padding, b), "Offset of 'b' matches");
        }
        else
            skip(4, "Skipping layout checks");
    }
    subtest("Nested struct") {
        plan(4);
        // First, create the inner struct type.
        infix_struct_member inner_members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                               {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0}};
        infix_type * inner_type = nullptr;
        infix_status inner_status = infix_type_create_struct(arena, &inner_type, inner_members, 2);
        ok(inner_status == INFIX_SUCCESS, "Inner struct creation should succeed");
        // Then, create the outer struct type that contains the inner one.
        infix_type * outer_type = nullptr;
        if (inner_type) {
            infix_struct_member outer_members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                                   {"b", inner_type, 0}};
            infix_status outer_status = infix_type_create_struct(arena, &outer_type, outer_members, 2);
            ok(outer_status == INFIX_SUCCESS, "Nested struct creation should succeed");
        }
        else
            fail("Nested struct creation skipped");
        if (outer_type) {
            ok(infix_type_get_size(outer_type) == sizeof(test_struct_nested), "Size should match sizeof");
            ok(infix_type_get_alignment(outer_type) == _Alignof(test_struct_nested), "Alignment should match _Alignof");
        }
        else
            skip(2, "Skipping layout checks");
    }
    subtest("Packed struct (pack 1)") {
        plan(3);
        // For packed structs, we must provide the pre-calculated offsets.
        infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                         {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 1}};
        infix_type * type = nullptr;
        infix_status status = infix_type_create_packed_struct(
            arena, &type, sizeof(test_struct_packed), _Alignof(test_struct_packed), members, 2);
        ok(status == INFIX_SUCCESS, "Packed struct creation should succeed");
        if (type) {
            ok(infix_type_get_size(type) == sizeof(test_struct_packed), "Size should match sizeof");
            ok(infix_type_get_alignment(type) == _Alignof(test_struct_packed), "Alignment should match _Alignof");
        }
        else
            skip(2, "Skipping layout checks");
    }
    subtest("Union layout") {
        plan(4);
        infix_type * char_array = nullptr;
        infix_status array_status =
            infix_type_create_array(arena, &char_array, infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 12);
        ok(array_status == INFIX_SUCCESS, "Array creation for union member should succeed");
        infix_type * type = nullptr;
        if (char_array) {
            infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT64), 0},
                                             {"b", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 0},
                                             {"c", char_array, 0}};
            infix_status union_status = infix_type_create_union(arena, &type, members, 3);
            ok(union_status == INFIX_SUCCESS, "Union creation should succeed");
        }
        else
            fail("Union creation skipped due to array member failure");
        if (type) {
            ok(infix_type_get_size(type) == sizeof(test_union), "Size should match sizeof");
            ok(infix_type_get_alignment(type) == _Alignof(test_union), "Alignment should match _Alignof");
        }
        else
            skip(2, "Skipping layout checks");
    }
    infix_arena_destroy(arena);
}
