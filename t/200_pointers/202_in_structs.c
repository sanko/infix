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
#include "types.h"  // For the definition of PointerStruct
#include <double_tap.h>
#include <infix.h>
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
    plan(3);  // One for type creation, one for trampoline, one for the final result.

    // 1. Define the ffi_type for PointerStruct
    ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
    members[0] = ffi_struct_member_create("val_ptr", ffi_type_create_pointer(), offsetof(PointerStruct, val_ptr));
    members[1] = ffi_struct_member_create("str_ptr", ffi_type_create_pointer(), offsetof(PointerStruct, str_ptr));
    ffi_type * struct_type = NULL;
    ffi_status status = ffi_type_create_struct(&struct_type, members, 2);

    if (!ok(status == FFI_SUCCESS, "ffi_type for PointerStruct created successfully")) {
        fail("Cannot proceed with test without a valid ffi_type.");
        skip(2, "Skipping remaining tests");
        infix_free(members);  // On failure, we must free this.
        return;
    }

    // 2. Generate the trampoline for `int(PointerStruct)`
    ffi_type * return_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_trampoline_t * trampoline = NULL;
    status = generate_forward_trampoline(&trampoline, return_type, &struct_type, 1, 1);
    ok(status == FFI_SUCCESS, "Trampoline created successfully");

    // 3. Prepare data and execute the FFI call
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

    int value_to_point_to = 500;
    const char * string_to_point_to = "Hello Pointers";
    PointerStruct struct_instance = {&value_to_point_to, string_to_point_to};

    int result = 0;
    void * args[] = {&struct_instance};

    cif_func((void *)process_pointer_struct, &result, args);

    // 4. Verify the result
    ok(result == 550, "Struct with pointer members passed correctly");
    diag("Function returned: %d (expected 550)", result);

    // 5. Cleanup
    ffi_trampoline_free(trampoline);
    ffi_type_destroy(struct_type);  // Recursively frees the members array.
}
