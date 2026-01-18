/**
 * @file 202_in_structs.c
 * @brief Unit test for passing structs that contain pointer members.
 * @ingroup test_suite
 *
 * @details This test case is an important follow-up to `201_basic.c`. It verifies
 * that `infix` can correctly handle structs that are passed by value, but which
 * themselves contain pointer members.
 *
 * The ABI classifier must correctly identify the struct as an aggregate to be passed
 * according to the platform's rules (e.g., in registers or on the stack). The JIT
 * code must then correctly copy the entire struct, including the pointer values
 * within it.
 *
 * The test defines a `PointerStruct` containing an `int*` and a `const char*`.
 * It calls a C function that takes this struct by value, dereferences the pointers
 * inside it, and verifies their contents. This confirms that the pointer values
 * were correctly preserved through the FFI call.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <string.h>

/**
 * @brief A C function that takes a struct containing pointers by value.
 * @details The ABI will pass this struct according to its size and alignment.
 * The function then dereferences the pointers to verify they were passed correctly.
 */
int process_pointer_struct(PointerStruct ps) {
    note("process_pointer_struct received struct with pointers:");
    note("  ps.val_ptr points to value: %d", (ps.val_ptr ? *ps.val_ptr : -1));
    note("  ps.str_ptr points to string: \"%s\"", (ps.str_ptr ? ps.str_ptr : "(null)"));
    if (ps.val_ptr && *ps.val_ptr == 500 && ps.str_ptr && strcmp(ps.str_ptr, "Hello Pointers") == 0)
        return *ps.val_ptr + 50;
    return -1;
}
TEST {
    plan(5);
    // 1. Programmatically create the `infix_type` for `PointerStruct`.
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
    // 2. Set up the arguments.
    infix_type * return_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    int value_to_point_to = 500;
    const char * string_to_point_to = "Hello Pointers";
    PointerStruct struct_instance = {&value_to_point_to, string_to_point_to};
    void * args[] = {&struct_instance};
    // 3. Test unbound trampoline.
    infix_forward_t * unbound_t = nullptr;
    ok(infix_forward_create_unbound_manual(&unbound_t, return_type, &struct_type, 1, 1) == INFIX_SUCCESS,
       "Unbound created");
    int unbound_result = 0;
    infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
    unbound_cif((void *)process_pointer_struct, &unbound_result, args);
    ok(unbound_result == 550, "Unbound call correct");
    // 4. Test bound trampoline.
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
