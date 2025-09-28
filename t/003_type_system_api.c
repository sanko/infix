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
 * @file 003_type_system_api.c
 * @brief Tests the infix_type_* API functions for correctness and error handling.
 *
 * @details This test suite focuses on the internal consistency of the type system's
 * public API, rather than its use in FFI calls. It ensures that the functions for
 * creating structs, unions, and arrays behave as expected under both normal and
 * exceptional conditions.
 *
 * The tests verify:
 * 1.  **Correctness:** That `infix_type_create_struct`, `_union`, and `_array`
 *     calculate the size and alignment of types in a way that matches the C
 *     compiler's own `sizeof` and `_Alignof` operators.
 * 2.  **Error Handling:** That the creation functions correctly reject invalid
 *     arguments (e.g., NULL pointers for required parameters) and return the
 *     appropriate error status.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>  // For offsetof
#include <stdint.h>  // For int64_t

// Reference C types for comparison
typedef struct {
    char c;    // size=1, align=1
    double d;  // size=8, align=8
} TestStruct;  // Expected align=8, size=16 (7 bytes padding after 'c')

typedef union {
    int i;     // size=4, align=4
    double d;  // size=8, align=8
} TestUnion;   // Expected align=8, size=8

typedef int64_t TestArray[10];

TEST {
    plan(4);  // One subtest per major API area.

    subtest("infix_type_create_struct API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Happy Path: Verify correct size and alignment calculation.
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] = infix_struct_member_create(
            "c", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), offsetof(TestStruct, c));
        members[1] = infix_struct_member_create(
            "d", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(TestStruct, d));
        infix_type * struct_type = NULL;
        infix_status status = infix_type_create_struct(arena, &struct_type, members, 2);

        if (ok(status == INFIX_SUCCESS && struct_type != NULL, "Successfully created a valid struct type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestStruct),
                 (unsigned long long)_Alignof(TestStruct));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)struct_type->size,
                 (unsigned long long)struct_type->alignment);
            ok(struct_type->size == sizeof(TestStruct) && struct_type->alignment == (size_t)_Alignof(TestStruct),
               "Struct size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");

        // 2. Error Handling: Pass a NULL member type.
        infix_struct_member * bad_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member), _Alignof(infix_struct_member));
        bad_members[0] = infix_struct_member_create("bad", NULL, 0);
        infix_type * bad_struct_type = NULL;
        status = infix_type_create_struct(arena, &bad_struct_type, bad_members, 1);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_struct rejects NULL member type");

        infix_arena_destroy(arena);
    }

    subtest("infix_type_create_union API validation") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Happy Path: Verify correct size and alignment.
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] = infix_struct_member_create(
            "i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(TestUnion, i));
        members[1] = infix_struct_member_create(
            "d", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(TestUnion, d));
        infix_type * union_type = NULL;
        infix_status status = infix_type_create_union(arena, &union_type, members, 2);

        if (ok(status == INFIX_SUCCESS && union_type != NULL, "Successfully created a valid union type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestUnion),
                 (unsigned long long)_Alignof(TestUnion));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)union_type->size,
                 (unsigned long long)union_type->alignment);
            ok(union_type->size == sizeof(TestUnion) && union_type->alignment == (size_t)_Alignof(TestUnion),
               "Union size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");

        infix_arena_destroy(arena);
    }

    subtest("infix_type_create_array API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Happy Path: Verify correct size and alignment.
        infix_type * element_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT64);
        infix_type * array_type = NULL;
        infix_status status = infix_type_create_array(arena, &array_type, element_type, 10);

        if (ok(status == INFIX_SUCCESS && array_type != NULL, "Successfully created a valid array type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestArray),
                 (unsigned long long)_Alignof(TestArray));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)array_type->size,
                 (unsigned long long)array_type->alignment);
            ok(array_type->size == sizeof(TestArray) && array_type->alignment == (size_t)_Alignof(TestArray),
               "Array size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");

        // 2. Error Handling: Pass a NULL element type.
        infix_type * bad_array_type = NULL;
        status = infix_type_create_array(arena, &bad_array_type, NULL, 10);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array rejects NULL element type");

        infix_arena_destroy(arena);
    }

    subtest("infix_type_create_enum API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);

        // 1. Happy Path: Verify correct size and alignment.
        infix_type * underlying_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * enum_type = NULL;
        infix_status status = infix_type_create_enum(arena, &enum_type, underlying_type);

        if (ok(status == INFIX_SUCCESS && enum_type != NULL, "Successfully created a valid enum type"))
            ok(enum_type->size == sizeof(int32_t) && enum_type->alignment == (size_t)_Alignof(int32_t),
               "Enum size and alignment match underlying integer type");
        else
            skip(1, "Cannot verify layout due to creation failure");

        // 2. Error Handling: Pass a non-integer underlying type.
        infix_type * bad_underlying_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
        infix_type * bad_enum_type = NULL;
        status = infix_type_create_enum(arena, &bad_enum_type, bad_underlying_type);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_enum rejects non-integer underlying type");

        infix_arena_destroy(arena);
    }
}
