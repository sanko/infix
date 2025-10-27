/**
 * @file 102_by_reference.c
 * @brief Unit test for passing and returning large aggregates by reference.
 * @ingroup test_suite
 *
 * @details This test file validates the ABI implementation for handling aggregates
 * (structs) that are too large to be passed or returned directly in registers.
 * According to most ABIs (including System V and Windows x64), such aggregates are
 * handled "by reference."
 *
 * - **Passing by Reference:** The caller allocates memory for the struct, and a
 *   pointer to this memory is passed in a general-purpose register.
 *
 * - **Returning by Reference:** The caller allocates space for the return value
 *   and passes a hidden pointer to this space as the *first* (often invisible)
 *   argument to the function. The callee then writes its result to this location.
 *
 * This test verifies both scenarios for:
 * - A `LargeStruct` (24 bytes), which is guaranteed to be passed by reference.
 * - A `NonPowerOfTwoStruct` (12 bytes), which is also passed by reference on many
 *   ABIs (like Windows x64) that have strict size rules for register passing.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>

/** @brief A C function that takes a large struct, which the ABI will pass by reference. */
int process_large_struct(LargeStruct s) {
    note("process_large_struct received s = { .a=%d, ..., .f=%d }", s.a, s.f);
    return s.a + s.f;
}

/** @brief A C function that returns a large struct, which the ABI will return by reference. */
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

/** @brief A C function that takes a struct whose size is not a power of two. */
int process_npot_struct(NonPowerOfTwoStruct s) {
    note("process_npot_struct received s = { .a=%d, .b=%d, .c=%d }", s.a, s.b, s.c);
    return s.a + s.b + s.c;
}

TEST {
    plan(2);

    subtest("Large struct (>16 bytes) passed and returned by reference/stack") {
        plan(7);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 6, _Alignof(infix_struct_member));
        infix_type * s32_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        for (int i = 0; i < 6; ++i)
            members[i] = infix_type_create_member(nullptr, s32_type, sizeof(int) * i);
        infix_type * large_struct_type = nullptr;
        if (!ok(infix_type_create_struct(arena, &large_struct_type, members, 6) == INFIX_SUCCESS, "Type created")) {
            skip(6, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        // Test passing the struct as an argument.
        infix_forward_t *unbound_pass, *bound_pass;
        ok(infix_forward_create_unbound_manual(&unbound_pass, s32_type, &large_struct_type, 1, 1) == INFIX_SUCCESS,
           "Unbound pass created");
        ok(infix_forward_create_manual(&bound_pass, s32_type, &large_struct_type, 1, 1, (void *)process_large_struct) ==
               INFIX_SUCCESS,
           "Bound pass created");
        LargeStruct s_in = {10, 20, 30, 40, 50, 60};
        void * pass_args[] = {&s_in};
        int unbound_pass_res = 0, bound_pass_res = 0;
        infix_unbound_cif_func unbound_pass_cif = infix_forward_get_unbound_code(unbound_pass);
        unbound_pass_cif((void *)process_large_struct, &unbound_pass_res, pass_args);
        infix_cif_func bound_pass_cif = infix_forward_get_code(bound_pass);
        bound_pass_cif(&bound_pass_res, pass_args);
        ok(unbound_pass_res == 70 && bound_pass_res == 70, "Pass arg correct");

        // Test returning the struct by value (which the ABI implements by reference).
        infix_forward_t *unbound_ret, *bound_ret;
        ok(infix_forward_create_unbound_manual(&unbound_ret, large_struct_type, &s32_type, 1, 1) == INFIX_SUCCESS,
           "Unbound ret created");
        ok(infix_forward_create_manual(&bound_ret, large_struct_type, &s32_type, 1, 1, (void *)return_large_struct) ==
               INFIX_SUCCESS,
           "Bound ret created");
        int base_val = 100;
        void * ret_args[] = {&base_val};
        LargeStruct unbound_ret_res, bound_ret_res;
        infix_unbound_cif_func unbound_ret_cif = infix_forward_get_unbound_code(unbound_ret);
        unbound_ret_cif((void *)return_large_struct, &unbound_ret_res, ret_args);
        infix_cif_func bound_ret_cif = infix_forward_get_code(bound_ret);
        bound_ret_cif(&bound_ret_res, ret_args);
        ok(unbound_ret_res.a == 100 && unbound_ret_res.f == 105 && bound_ret_res.a == 100 && bound_ret_res.f == 105,
           "Return val correct");

        infix_forward_destroy(unbound_pass);
        infix_forward_destroy(bound_pass);
        infix_forward_destroy(unbound_ret);
        infix_forward_destroy(bound_ret);
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

        infix_type * npot_type = nullptr;
        infix_status status = infix_type_create_struct(arena, &npot_type, members, 3);
        if (!ok(status == INFIX_SUCCESS, "infix_type for NonPowerOfTwoStruct created")) {
            skip(2, "Cannot proceed");
            infix_arena_destroy(arena);
            return;
        }

        infix_forward_t * trampoline = nullptr;
        status = infix_forward_create_unbound_manual(
            &trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &npot_type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for non-power-of-two struct created");

        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        NonPowerOfTwoStruct s_in = {10, 20, 30};
        int result = 0;
        void * args[] = {&s_in};
        cif((void *)process_npot_struct, &result, args);
        ok(result == 60, "Non-power-of-two struct passed by reference correctly");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }
}
