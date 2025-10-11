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
 * @file 202_in_structs.c
 * @brief Tests passing structs that contain pointer members.
 *
 * @details This test suite verifies the library's ability to handle aggregates
 * that have pointers as members. This is a critical test as it combines the
 * rules for aggregate passing with the rules for pointer passing.
 *
 * The test defines a `PointerStruct` containing an `int*` and a `const char*`.
 * An instance of this struct is passed through the FFI to a native C function.
 * The native function's primary goal is to verify that it can successfully
 * dereference both pointers and access the original, correct data. The test
 * succeeds if the native function receives valid pointers and can return a
 * value based on the data they point to.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // For the definition of PointerStruct
#include <infix/infix.h>
#include <string.h>  // For strcmp

// Native C Target Function

/**
 * @brief Receives a PointerStruct and dereferences its members to verify them.
 * @return An integer based on the dereferenced value to confirm success.
 */
int process_pointer_struct(PointerStruct ps) {
    note("process_pointer_struct received struct with pointers:");
    note("  ps.val_ptr points to value: %d", (ps.val_ptr ? *ps.val_ptr : -1));
    note("  ps.str_ptr points to string: \"%s\"", (ps.str_ptr ? ps.str_ptr : "(null)"));

    // Check if the pointers are valid and point to the expected data.
    if (ps.val_ptr && *ps.val_ptr == 500 && ps.str_ptr && strcmp(ps.str_ptr, "Hello Pointers") == 0) {
        return *ps.val_ptr + 50;  // Return a derived value on success.
    }

    return -1;  // Return an error code on failure.
}


TEST {
    plan(5);

    infix_arena_t * arena = infix_arena_create(4096);
    infix_struct_member * members =
        infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
    members[0] = infix_type_create_member("val_ptr", infix_type_create_pointer(), offsetof(PointerStruct, val_ptr));
    members[1] = infix_type_create_member("str_ptr", infix_type_create_pointer(), offsetof(PointerStruct, str_ptr));
    infix_type * struct_type = nullptr;
    if (!ok(infix_type_create_struct(arena, &struct_type, members, 2) == INFIX_SUCCESS, "Type created")) {
        skip(4, "Cannot proceed");
        infix_arena_destroy(arena);
        return;
    }

    infix_type * return_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    int value_to_point_to = 500;
    const char * string_to_point_to = "Hello Pointers";
    PointerStruct struct_instance = {&value_to_point_to, string_to_point_to};
    void * args[] = {&struct_instance};

    // Unbound
    infix_forward_t * unbound_t = nullptr;
    ok(infix_forward_create_unbound_manual(&unbound_t, return_type, &struct_type, 1, 1) == INFIX_SUCCESS,
       "Unbound created");
    int unbound_result = 0;
    infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
    unbound_cif((void *)process_pointer_struct, &unbound_result, args);
    ok(unbound_result == 550, "Unbound call correct");

    // Bound
    infix_forward_t * bound_t = nullptr;
    ok(infix_forward_create_manual(&bound_t, return_type, &struct_type, 1, 1, (void *)process_pointer_struct) ==
           INFIX_SUCCESS,
       "Bound created");
    int bound_result = 0;
    infix_cif_func bound_cif = infix_forward_get_code(bound_t);
    bound_cif(&bound_result, args);
    ok(bound_result == 550, "Bound call correct");

    infix_forward_destroy(unbound_t);
    infix_forward_destroy(bound_t);
    infix_arena_destroy(arena);
}
