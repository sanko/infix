<<<<<<< HEAD:t/102_by_reference.c
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
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>

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
        plan(5);
        infix_arena_t * arena = infix_arena_create(4096);
        // 1. Create the infix_type for LargeStruct. This is used for both tests.
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 6, _Alignof(infix_struct_member));
        infix_type * s32_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        for (int i = 0; i < 6; ++i) {
            members[i] = infix_type_create_member(NULL, s32_type, sizeof(int) * i);
        }
        infix_type * large_struct_type = NULL;
        infix_status status = infix_type_create_struct(arena, &large_struct_type, members, 6);
        if (!ok(status == INFIX_SUCCESS, "infix_type for LargeStruct created successfully")) {
            skip(4, "Cannot proceed without LargeStruct type");
            infix_arena_destroy(arena);
            return;
        }

        // Test 1: Passing LargeStruct as an argument
        infix_forward_t * arg_trampoline = NULL;
        status = infix_forward_create_manual(
            &arg_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &large_struct_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for process_large_struct created");

        infix_cif_func arg_cif = (infix_cif_func)infix_forward_get_code(arg_trampoline);
        LargeStruct s_in = {10, 20, 30, 40, 50, 60};
        int result = 0;
        void * arg_args[] = {&s_in};
        arg_cif((void *)process_large_struct, &result, arg_args);
        ok(result == 70, "Large struct passed as argument correctly");
        infix_forward_destroy(arg_trampoline);

        // Test 2: Returning LargeStruct by value
        infix_forward_t * ret_trampoline = NULL;
        infix_type * ret_arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        status = infix_forward_create_manual(&ret_trampoline, large_struct_type, &ret_arg_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for return_large_struct created");
        infix_cif_func ret_cif = (infix_cif_func)infix_forward_get_code(ret_trampoline);
        LargeStruct s_out;
        int base_val = 100;
        void * ret_args[] = {&base_val};
        ret_cif((void *)return_large_struct, &s_out, ret_args);
        ok(s_out.a == 100 && s_out.f == 105, "Large struct returned via hidden pointer correctly");
        infix_forward_destroy(ret_trampoline);
        infix_arena_destroy(arena);
    }

    subtest("Non-power-of-two sized struct") {
        plan(3);
        note("Testing 12-byte struct passed by reference.");
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 3, _Alignof(infix_struct_member));
        infix_type * s32_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        members[0] = infix_type_create_member("a", s32_type, offsetof(NonPowerOfTwoStruct, a));
        members[1] = infix_type_create_member("b", s32_type, offsetof(NonPowerOfTwoStruct, b));
        members[2] = infix_type_create_member("c", s32_type, offsetof(NonPowerOfTwoStruct, c));

        infix_type * npot_type = NULL;
        infix_status status = infix_type_create_struct(arena, &npot_type, members, 3);
        if (!ok(status == INFIX_SUCCESS, "infix_type for NonPowerOfTwoStruct created")) {
            skip(2, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        infix_forward_t * trampoline = NULL;
        status = infix_forward_create_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &npot_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for non-power-of-two struct created");

        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        NonPowerOfTwoStruct s_in = {10, 20, 30};
        int result = 0;
        void * args[] = {&s_in};
        cif((void *)process_npot_struct, &result, args);
        ok(result == 60, "Non-power-of-two struct passed by reference correctly");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }
}
=======
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
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>

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
        plan(5);
        infix_arena_t * arena = infix_arena_create(4096);
        // 1. Create the infix_type for LargeStruct. This is used for both tests.
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 6, _Alignof(infix_struct_member));
        infix_type * s32_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        for (int i = 0; i < 6; ++i) {
            members[i] = infix_struct_member_create(NULL, s32_type, sizeof(int) * i);
        }
        infix_type * large_struct_type = NULL;
        infix_status status = infix_type_create_struct(arena, &large_struct_type, members, 6);
        if (!ok(status == INFIX_SUCCESS, "infix_type for LargeStruct created successfully")) {
            skip(4, "Cannot proceed without LargeStruct type");
            infix_arena_destroy(arena);
            return;
        }

        // Test 1: Passing LargeStruct as an argument
        infix_forward_t * arg_trampoline = NULL;
        status = infix_forward_create_manual(
            &arg_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &large_struct_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for process_large_struct created");

        infix_cif_func arg_cif = (infix_cif_func)infix_forward_get_code(arg_trampoline);
        LargeStruct s_in = {10, 20, 30, 40, 50, 60};
        int result = 0;
        void * arg_args[] = {&s_in};
        arg_cif((void *)process_large_struct, &result, arg_args);
        ok(result == 70, "Large struct passed as argument correctly");
        infix_forward_destroy(arg_trampoline);

        // Test 2: Returning LargeStruct by value
        infix_forward_t * ret_trampoline = NULL;
        infix_type * ret_arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        status = infix_forward_create_manual(&ret_trampoline, large_struct_type, &ret_arg_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for return_large_struct created");
        infix_cif_func ret_cif = (infix_cif_func)infix_forward_get_code(ret_trampoline);
        LargeStruct s_out;
        int base_val = 100;
        void * ret_args[] = {&base_val};
        ret_cif((void *)return_large_struct, &s_out, ret_args);
        ok(s_out.a == 100 && s_out.f == 105, "Large struct returned via hidden pointer correctly");
        infix_forward_destroy(ret_trampoline);
        infix_arena_destroy(arena);
    }

    subtest("Non-power-of-two sized struct") {
        plan(3);
        note("Testing 12-byte struct passed by reference.");
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 3, _Alignof(infix_struct_member));
        infix_type * s32_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        members[0] = infix_struct_member_create("a", s32_type, offsetof(NonPowerOfTwoStruct, a));
        members[1] = infix_struct_member_create("b", s32_type, offsetof(NonPowerOfTwoStruct, b));
        members[2] = infix_struct_member_create("c", s32_type, offsetof(NonPowerOfTwoStruct, c));

        infix_type * npot_type = NULL;
        infix_status status = infix_type_create_struct(arena, &npot_type, members, 3);
        if (!ok(status == INFIX_SUCCESS, "infix_type for NonPowerOfTwoStruct created")) {
            skip(2, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        infix_forward_t * trampoline = NULL;
        status = infix_forward_create_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &npot_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for non-power-of-two struct created");

        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        NonPowerOfTwoStruct s_in = {10, 20, 30};
        int result = 0;
        void * args[] = {&s_in};
        cif((void *)process_npot_struct, &result, args);
        ok(result == 60, "Non-power-of-two struct passed by reference correctly");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }
}
>>>>>>> main:t/100_aggregates/102_by_reference.c
