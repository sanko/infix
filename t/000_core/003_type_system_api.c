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
 * @brief Tests the ffi_type_* API functions for correctness and error handling.
 *
 * @details This test suite focuses on the internal consistency of the type system's
 * public API, rather than its use in FFI calls. It ensures that the functions for
 * creating structs, unions, and arrays behave as expected under both normal and
 * exceptional conditions.
 *
 * The tests verify:
 * 1.  **Correctness:** That `ffi_type_create_struct`, `_union`, and `_array`
 *     calculate the size and alignment of types in a way that matches the C
 *     compiler's own `sizeof` and `_Alignof` operators.
 * 2.  **Error Handling:** That the creation functions correctly reject invalid
 *     arguments (e.g., NULL pointers for required parameters) and return the
 *     appropriate error status.
 * 3.  **Memory Safety:** That `ffi_type_destroy` can be safely called on static
 *     types (primitives, pointers) without causing a crash, which is a key
 *     part of its API contract.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
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

    subtest("ffi_type_create_struct API validation") {
        plan(3);

        // 1. Happy Path: Verify correct size and alignment calculation.
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
        members[0] =
            ffi_struct_member_create("c", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8), offsetof(TestStruct, c));
        members[1] = ffi_struct_member_create(
            "d", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(TestStruct, d));
        ffi_type * struct_type = NULL;
        ffi_status status = ffi_type_create_struct(&struct_type, members, 2);

        if (ok(status == FFI_SUCCESS && struct_type != NULL, "Successfully created a valid struct type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestStruct),
                 (unsigned long long)_Alignof(TestStruct));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)struct_type->size,
                 (unsigned long long)struct_type->alignment);
            ok(struct_type->size == sizeof(TestStruct) && struct_type->alignment == (size_t)_Alignof(TestStruct),
               "Struct size and alignment match compiler's layout");
        }
        else {
            skip(1, "Cannot verify layout due to creation failure");
            // On failure, we are responsible for the members array.
            infix_free(members);
        }
        ffi_type_destroy(struct_type);  // This frees the members array on success.

        // 2. Error Handling: Pass a NULL member type.
        ffi_struct_member * bad_members = infix_malloc(sizeof(ffi_struct_member));
        bad_members[0] = ffi_struct_member_create("bad", NULL, 0);
        ffi_type * bad_struct_type = NULL;
        status = ffi_type_create_struct(&bad_struct_type, bad_members, 1);
        ok(status == FFI_ERROR_INVALID_ARGUMENT, "ffi_type_create_struct rejects NULL member type");
        // We must free the members array ourselves on failure.
        infix_free(bad_members);
    }

    subtest("ffi_type_create_union API validation") {
        plan(2);

        // 1. Happy Path: Verify correct size and alignment.
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
        members[0] =
            ffi_struct_member_create("i", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), offsetof(TestUnion, i));
        members[1] =
            ffi_struct_member_create("d", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(TestUnion, d));
        ffi_type * union_type = NULL;
        ffi_status status = ffi_type_create_union(&union_type, members, 2);

        if (ok(status == FFI_SUCCESS && union_type != NULL, "Successfully created a valid union type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestUnion),
                 (unsigned long long)_Alignof(TestUnion));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)union_type->size,
                 (unsigned long long)union_type->alignment);
            ok(union_type->size == sizeof(TestUnion) && union_type->alignment == (size_t)_Alignof(TestUnion),
               "Union size and alignment match compiler's layout");
        }
        else {
            skip(1, "Cannot verify layout due to creation failure");
            infix_free(members);
        }
        ffi_type_destroy(union_type);
    }

    subtest("ffi_type_create_array API validation") {
        plan(3);
        // 1. Happy Path: Verify correct size and alignment.
        ffi_type * element_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT64);
        ffi_type * array_type = NULL;
        ffi_status status = ffi_type_create_array(&array_type, element_type, 10);

        if (ok(status == FFI_SUCCESS && array_type != NULL, "Successfully created a valid array type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestArray),
                 (unsigned long long)_Alignof(TestArray));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)array_type->size,
                 (unsigned long long)array_type->alignment);
            ok(array_type->size == sizeof(TestArray) && array_type->alignment == (size_t)_Alignof(TestArray),
               "Array size and alignment match compiler's layout");
        }
        else {
            skip(1, "Cannot verify layout due to creation failure");
        }
        ffi_type_destroy(array_type);

        // 2. Error Handling: Pass a NULL element type.
        ffi_type * bad_array_type = NULL;
        status = ffi_type_create_array(&bad_array_type, NULL, 10);
        ok(status == FFI_ERROR_INVALID_ARGUMENT, "ffi_type_create_array rejects NULL element type");
    }

    subtest("ffi_type_destroy safety on static types") {
        plan(3);
        note("Verifying that ffi_type_destroy() does not crash on non-dynamic types.");

        // These calls should be no-ops and must not cause a segmentation fault.
        ffi_type_destroy(ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32));
        pass("ffi_type_destroy() on a primitive type is safe.");

        ffi_type_destroy(ffi_type_create_pointer());
        pass("ffi_type_destroy() on a pointer type is safe.");
        ffi_type_destroy(ffi_type_create_void());
        pass("ffi_type_destroy() on the void type is safe.");
    }
}
