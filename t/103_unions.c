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
 * @file 103_unions.c
 * @brief Tests passing and returning C unions by value.
 *
 * @details This test suite verifies that the library correctly handles C `union`
 * types according to the target platform's ABI. It ensures that the size and
 * alignment are calculated correctly and that the data is placed in the
 * appropriate registers or stack locations.
 *
 * The suite covers two primary scenarios:
 * 1.  **Passing a Union:** A `Number` union is passed to native functions that
 *     interpret its contents as either an `int` or a `double`. This implicitly
 *     verifies the ABI classification rules (e.g., on System V x64, this union
 *     is passed in an XMM register, while on Windows x64 it's passed in a GPR).
 * 2.  **Returning a Union:** A native function returns a `Number` union by value,
 *     and the test verifies that the returned data is correct.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // For the definition of the Number union
#include <infix/infix.h>
#include <math.h>    // For fabs
#include <string.h>  // For memcpy

// Native C Target Functions
/** @brief Receives a Number union and processes it as an integer. */
int process_number_union_as_int(Number num) {
    note("process_number_union_as_int received num.i = %d", num.i);
    return num.i * 2;
}

/** @brief Receives a Number union and processes it as a float. */
float process_number_union_as_float(Number num) {
    note("process_number_union_as_float received num.f = %f", num.f);
    return num.f + 1.0f;
}

Number return_number_union(int selector) {
    Number n;
    if (selector == 1)
        n.i = 500;
    else
        n.f = 42.42f;
    return n;
}

TEST {
    plan(3);

    // Setup: Create an arena for this test's type definitions.
    infix_arena_t * arena = infix_arena_create(4096);

    // Create the infix_type for the Number union within the arena.
    infix_struct_member * members =
        infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
    members[0] =
        infix_struct_member_create("i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(Number, i));
    members[1] =
        infix_struct_member_create("f", infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), offsetof(Number, f));
    infix_type * union_type = NULL;
    infix_status status = infix_type_create_union(arena, &union_type, members, 2);

    if (!ok(status == INFIX_SUCCESS, "infix_type for Number union created successfully")) {
        diag("Cannot proceed with union tests without a valid infix_type.");
        skip(2, "Skipping subtests due to setup failure");
        infix_arena_destroy(arena);
        return;
    }

    subtest("Passing union as argument") {
        plan(4);

        // Test 1: Pass as integer
        infix_forward_t * int_trampoline = NULL;
        status = infix_forward_create_manual(
            &int_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &union_type, 1, 1);
        ok(status == INFIX_SUCCESS && int_trampoline != NULL, "Trampoline for process_number_union_as_int created");

        infix_cif_func int_cif = (infix_cif_func)infix_forward_get_code(int_trampoline);
        Number num_int;
        num_int.i = 123;
        int int_result = 0;
        void * int_args[] = {&num_int};
        int_cif((void *)process_number_union_as_int, &int_result, int_args);
        ok(int_result == 246, "Union passed as integer correctly");
        infix_forward_destroy(int_trampoline);

        // Test 2: Pass as float
        infix_forward_t * flt_trampoline = NULL;
        status = infix_forward_create_manual(
            &flt_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), &union_type, 1, 1);
        ok(status == INFIX_SUCCESS && flt_trampoline != NULL, "Trampoline for process_number_union_as_float created");

        infix_cif_func flt_cif = (infix_cif_func)infix_forward_get_code(flt_trampoline);
        Number num_flt;
        num_flt.f = 99.5f;
        float flt_result = 0.0f;
        void * flt_args[] = {&num_flt};
        flt_cif((void *)process_number_union_as_float, &flt_result, flt_args);
        ok(fabs(flt_result - 100.5f) < 0.001, "Union passed as float correctly");
        infix_forward_destroy(flt_trampoline);
    }

    subtest("Returning union by value") {
        plan(3);
        infix_forward_t * trampoline = NULL;
        infix_type * arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        status = infix_forward_create_manual(&trampoline, union_type, &arg_type, 1, 1);
        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline for return_number_union created");

        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);

        // Test 1: Return as integer
        Number int_result;
        int selector_int = 1;
        void * int_args[] = {&selector_int};
        cif((void *)return_number_union, &int_result, int_args);
        ok(int_result.i == 500, "Union returned as integer correctly");

        // Test 2: Return as float
        Number flt_result;
        int selector_flt = 2;
        void * flt_args[] = {&selector_flt};
        cif((void *)return_number_union, &flt_result, flt_args);
        ok(fabs(flt_result.f - 42.42f) < 0.001, "Union returned as float correctly");

        infix_forward_destroy(trampoline);
    }

    // A single call to destroy the arena frees all memory used for type creation.
    infix_arena_destroy(arena);
}
