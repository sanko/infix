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
 * @file 102_by_reference.c
 * @brief Tests passing and returning aggregates that are handled by reference.
 *
 * @details This test suite focuses on aggregates that are too large to be
 * passed entirely in registers. According to most ABIs, such structs are either
 * passed as a pointer to a copy on the stack (by reference) or directly on the
 * stack. When returned, a hidden pointer to a caller-allocated buffer is often
 * used. This suite verifies these mechanisms.
 *
 * It covers two main scenarios:
 *
 * 1.  **Large Structs (All Platforms):** A struct larger than 16 bytes is used
 *     to test the common case for stack-based passing and returning via a hidden
 *     pointer. This is expected behavior on SysV x64, Windows x64, and AArch64.
 *
 * 2.  **Windows x64 Specific Rule:** The Windows x64 ABI mandates that any
 *     aggregate whose size is not a power of two (1, 2, 4, or 8 bytes) must be
 *     passed by reference, regardless of its total size. This test verifies this
 *     specific edge case using a 12-byte struct.
 */

#define DBLTAP_IMPLEMENTATION
#include "types.h"
#include <double_tap.h>
#include <infix.h>

// Native C Target Functions

/** @brief Processes a large struct, returning a value derived from its members. */
int process_large_struct(LargeStruct s) {
    note("process_large_struct received s = { .a=%d, ..., .f=%d }", s.a, s.f);
    return s.a + s.f;
}

/** @brief Returns a large struct by value, which the ABI turns into a hidden pointer return. */
LargeStruct return_large_struct(int base_val) {
    return (LargeStruct){
        base_val,
        base_val + 1,
        base_val + 2,
        base_val + 3,
        base_val + 4,
        base_val + 5,
    };
}

// A struct whose size (12 bytes) is not a power of two.
typedef struct {
    int a, b, c;
} NonPowerOfTwoStruct;
int process_npot_struct(NonPowerOfTwoStruct s) {
    note("process_npot_struct received s = { .a=%d, .b=%d, .c=%d }", s.a, s.b, s.c);
    return s.a + s.b + s.c;
}

TEST {
    plan(2);

    subtest("Large struct (>16 bytes) passed and returned by reference/stack") {
        // 1. Create the ffi_type for LargeStruct. This is used for both tests.
        plan(5);
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 6);
        ffi_type * s32_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        for (int i = 0; i < 6; ++i) {
            members[i] = ffi_struct_member_create(NULL, s32_type, sizeof(int) * i);
        }
        ffi_type * large_struct_type = NULL;
        ffi_status status = ffi_type_create_struct(&large_struct_type, members, 6);
        if (!ok(status == FFI_SUCCESS, "ffi_type for LargeStruct created successfully")) {
            skip(3, "Cannot proceed without LargeStruct type");
            infix_free(members);  // On failure, we must free this ourselves.
            return;
        }

        // Test 1: Passing LargeStruct as an argument
        ffi_trampoline_t * arg_trampoline = NULL;
        status = generate_forward_trampoline(
            &arg_trampoline, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), &large_struct_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for process_large_struct created");

        ffi_cif_func arg_cif = (ffi_cif_func)ffi_trampoline_get_code(arg_trampoline);
        LargeStruct s_in = {10, 20, 30, 40, 50, 60};
        int result = 0;
        void * arg_args[] = {&s_in};
        arg_cif((void *)process_large_struct, &result, arg_args);
        ok(result == 70, "Large struct passed as argument correctly");
        ffi_trampoline_free(arg_trampoline);

        // Test 2: Returning LargeStruct by value
        ffi_trampoline_t * ret_trampoline = NULL;
        ffi_type * ret_arg_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        status = generate_forward_trampoline(&ret_trampoline, large_struct_type, &ret_arg_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for return_large_struct created");
        ffi_cif_func ret_cif = (ffi_cif_func)ffi_trampoline_get_code(ret_trampoline);
        LargeStruct s_out;
        int base_val = 100;
        void * ret_args[] = {&base_val};
        ret_cif((void *)return_large_struct, &s_out, ret_args);
        ok(s_out.a == 100 && s_out.f == 105, "Large struct returned via hidden pointer correctly");
        ffi_trampoline_free(ret_trampoline);
        ffi_type_destroy(large_struct_type);
    }

    subtest("Non-power-of-two sized struct") {
        plan(3);
        note("Testing 12-byte struct passed by reference.");
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 3);
        ffi_type * s32_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        members[0] = ffi_struct_member_create("a", s32_type, offsetof(NonPowerOfTwoStruct, a));
        members[1] = ffi_struct_member_create("b", s32_type, offsetof(NonPowerOfTwoStruct, b));
        members[2] = ffi_struct_member_create("c", s32_type, offsetof(NonPowerOfTwoStruct, c));

        ffi_type * npot_type = NULL;
        ffi_status status = ffi_type_create_struct(&npot_type, members, 3);
        if (!ok(status == FFI_SUCCESS, "ffi_type for NonPowerOfTwoStruct created")) {
            skip(2, "Cannot proceed");
            infix_free(members);
            return;
        }

        ffi_trampoline_t * trampoline = NULL;
        status = generate_forward_trampoline(
            &trampoline, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), &npot_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for non-power-of-two struct created");

        ffi_cif_func cif = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        NonPowerOfTwoStruct s_in = {10, 20, 30};
        int result = 0;
        void * args[] = {&s_in};
        cif((void *)process_npot_struct, &result, args);
        ok(result == 60, "Non-power-of-two struct passed by reference correctly");

        ffi_trampoline_free(trampoline);
        ffi_type_destroy(npot_type);
    }
}
