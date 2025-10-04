/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file 005_layouts.c
 * @brief Tests the correctness of the ABI-aware layout calculation for aggregates.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>  // For offsetof

// A series of native C structs to serve as the ground truth for our tests.

typedef struct {
    char a;  // size 1, align 1
    // 3 bytes padding
    int b;  // size 4, align 4
} test_struct_padding;

typedef struct {
    long long a;  // size 8, align 8
    char b;       // size 1, align 1
} test_struct_no_padding;

typedef struct {
    char a;
    test_struct_padding b;
} test_struct_nested;

#pragma pack(1)
typedef struct {
    char a;
    int b;
} test_struct_packed;
#pragma pack()

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

        infix_type * type = NULL;
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

        infix_type * type = NULL;
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

        infix_struct_member inner_members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                               {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0}};
        infix_type * inner_type = NULL;
        infix_status inner_status = infix_type_create_struct(arena, &inner_type, inner_members, 2);
        ok(inner_status == INFIX_SUCCESS, "Inner struct creation should succeed");

        infix_type * outer_type = NULL;
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

        infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 0},
                                         {"b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 1}};

        infix_type * type = NULL;
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

        infix_type * char_array = NULL;
        infix_status array_status =
            infix_type_create_array(arena, &char_array, infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), 12);
        ok(array_status == INFIX_SUCCESS, "Array creation for union member should succeed");

        infix_type * type = NULL;
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
