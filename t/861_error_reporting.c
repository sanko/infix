/**
 * @file 861_error_reporting_regression.c
 * @brief Unit tests verifying specific error codes for invalid inputs.
 * @ingroup test_suite
 *
 * @details This test ensures that the library reports specific, useful error codes
 * (like INFIX_CODE_NULL_POINTER, INFIX_CODE_EMPTY_SIGNATURE, etc.) instead of
 * generic unknown errors when the API is misused. This prevents the "silent failure"
 * or "error code 1" scenarios encountered in production.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>

TEST {
    plan(4);

    subtest("Signature parser input validation") {
        plan(6);
        infix_arena_t * arena = NULL;
        infix_type * ret_type = NULL;
        infix_function_argument * args = NULL;
        size_t n_args, n_fixed;
        infix_status status;

        // NULL signature
        status = infix_signature_parse(NULL, &arena, &ret_type, &args, &n_args, &n_fixed, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT,
           "infix_signature_parse(NULL, ...) returns INFIX_ERROR_INVALID_ARGUMENT");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Error code is INFIX_CODE_NULL_POINTER");

        // Empty signature
        status = infix_signature_parse("", &arena, &ret_type, &args, &n_args, &n_fixed, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT,
           "infix_signature_parse(\"\", ...) returns INFIX_ERROR_INVALID_ARGUMENT");
        ok(infix_get_last_error().code == INFIX_CODE_EMPTY_SIGNATURE, "Error code is INFIX_CODE_EMPTY_SIGNATURE");

        // NULL output pointers
        // Note: valid signature, invalid outputs
        status = infix_signature_parse("()->void", NULL, NULL, NULL, NULL, NULL, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT,
           "infix_signature_parse(..., NULLs) returns INFIX_ERROR_INVALID_ARGUMENT");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Error code is INFIX_CODE_NULL_POINTER");
    }

    subtest("Trampoline creation validation") {
        plan(4);
        infix_forward_t * t = NULL;
        infix_status status;

        // NULL signature in forward create
        status = infix_forward_create(&t, NULL, NULL, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT,
           "infix_forward_create(..., NULL, ...) returns INFIX_ERROR_INVALID_ARGUMENT");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Error code is INFIX_CODE_NULL_POINTER");

        // Missing registry for named type
        status = infix_forward_create(&t, "@MyType", NULL, NULL);  // Registry is NULL
        ok(status == INFIX_ERROR_INVALID_ARGUMENT,
           "infix_forward_create(..., \"@MyType\", ..., NULL) returns INFIX_ERROR_INVALID_ARGUMENT");
        ok(infix_get_last_error().code == INFIX_CODE_MISSING_REGISTRY, "Error code is INFIX_CODE_MISSING_REGISTRY");
    }

    subtest("Manual API validation (NULL ptrs)") {
        plan(6);
        infix_arena_t * arena = infix_arena_create(1024);
        infix_type * out_type = NULL;
        infix_status status;

        // Pointer to NULL
        status = infix_type_create_pointer_to(arena, &out_type, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_pointer_to(..., NULL) -> ERROR");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Code: INFIX_CODE_NULL_POINTER");

        // Array of NULL type
        status = infix_type_create_array(arena, &out_type, NULL, 10);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array(..., NULL, ...) -> ERROR");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Code: INFIX_CODE_NULL_POINTER");

        // Enum of NULL base
        status = infix_type_create_enum(arena, &out_type, NULL);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_enum(..., NULL) -> ERROR");
        ok(infix_get_last_error().code == INFIX_CODE_NULL_POINTER, "Code: INFIX_CODE_NULL_POINTER");

        infix_arena_destroy(arena);
    }

    subtest("Manual API validation (alignment/packing)") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(1024);
        infix_type * out_type = NULL;
        infix_struct_member members[] = {{"a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), 0, 0, 0, false}};

        // 0 Alignment is invalid
        infix_status status = infix_type_create_packed_struct(arena, &out_type, 4, 0, members, 1);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_packed_struct(..., align=0, ...) -> ERROR");
        ok(infix_get_last_error().code == INFIX_CODE_INVALID_ALIGNMENT, "Code: INFIX_CODE_INVALID_ALIGNMENT");

        infix_arena_destroy(arena);
    }
}
