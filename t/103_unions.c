/**
 * @file 103_unions.c
 * @brief Unit test for passing and returning unions by value.
 * @ingroup test_suite
 *
 * @details This test verifies that `infix` correctly handles C unions in FFI calls.
 * A union is a special type of aggregate, and its handling by the ABI often
 * follows the same rules as structs of the same size and alignment.
 *
 * This test uses a simple `Number` union containing an `int` and a `float`.
 * It verifies that:
 * 1.  The `infix_type` for the union is created with the correct size (the size
 *     of the largest member) and alignment (the alignment of the most-aligned member).
 * 2.  When the union is passed as an argument, its raw byte representation is
 *     correctly transmitted, allowing the callee to interpret it as either an
 *     `int` or a `float`.
 * 3.  When a union is returned by value, its raw bytes are correctly received
 *     by the caller.
 *
 * This test is important for validating the aggregate classification logic for
 * a type that is less common than structs but still a core part of the C language.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>
// Native C Functions for Testing
/** @brief A C function that interprets a passed-in `Number` union as an integer. */
int process_number_union_as_int(Number num) {
    note("process_number_union_as_int received num.i = %d", num.i);
    return num.i * 2;
}
/** @brief A C function that interprets a passed-in `Number` union as a float. */
float process_number_union_as_float(Number num) {
    note("process_number_union_as_float received num.f = %f", num.f);
    return num.f + 1.0f;
}
/** @brief A C function that returns a `Number` union by value. */
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
    infix_arena_t * arena = infix_arena_create(4096);
    // 1. Create the `infix_type` for the `Number` union programmatically.
    infix_struct_member * members =
        infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
    members[0] =
        infix_type_create_member("i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(Number, i));
    members[1] = infix_type_create_member("f", infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), offsetof(Number, f));
    infix_type * union_type = nullptr;
    infix_status status = infix_type_create_union(arena, &union_type, members, 2);
    if (!ok(status == INFIX_SUCCESS, "infix_type for Number union created successfully")) {
        diag("Cannot proceed with union tests without a valid infix_type.");
        skip(2, "Skipping subtests due to setup failure");
        infix_arena_destroy(arena);
        return;
    }
    subtest("Passing union as argument") {
        plan(4);
        // Test passing the union and interpreting it as an int.
        infix_forward_t * int_trampoline = nullptr;
        status = infix_forward_create_unbound_manual(
            &int_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), &union_type, 1, 1);
        ok(status == INFIX_SUCCESS && int_trampoline != nullptr, "Trampoline for process_number_union_as_int created");
        infix_unbound_cif_func int_cif = infix_forward_get_unbound_code(int_trampoline);
        Number num_int;
        num_int.i = 123;
        int int_result = 0;
        void * int_args[] = {&num_int};
        int_cif((void *)process_number_union_as_int, &int_result, int_args);
        ok(int_result == 246, "Union passed as integer correctly");
        infix_forward_destroy(int_trampoline);
        // Test passing the union and interpreting it as a float.
        infix_forward_t * flt_trampoline = nullptr;
        status = infix_forward_create_unbound_manual(
            &flt_trampoline, infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT), &union_type, 1, 1);
        ok(status == INFIX_SUCCESS && flt_trampoline != nullptr,
           "Trampoline for process_number_union_as_float created");
        infix_unbound_cif_func flt_cif = infix_forward_get_unbound_code(flt_trampoline);
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
        infix_forward_t * trampoline = nullptr;
        infix_type * arg_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        status = infix_forward_create_unbound_manual(&trampoline, union_type, &arg_type, 1, 1);
        ok(status == INFIX_SUCCESS && trampoline != nullptr, "Trampoline for return_number_union created");
        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        // Test receiving the union with an integer value.
        Number int_result;
        int selector_int = 1;
        void * int_args[] = {&selector_int};
        cif((void *)return_number_union, &int_result, int_args);
        ok(int_result.i == 500, "Union returned as integer correctly");
        // Test receiving the union with a float value.
        Number flt_result;
        int selector_flt = 2;
        void * flt_args[] = {&selector_flt};
        cif((void *)return_number_union, &flt_result, flt_args);
        ok(fabs(flt_result.f - 42.42f) < 0.001, "Union returned as float correctly");
        infix_forward_destroy(trampoline);
    }
    infix_arena_destroy(arena);
}
