/**
 * @file 003_type_system_api.c
 * @brief Unit test for the Manual API (`infix_type_create_*` functions).
 * @ingroup test_suite
 *
 * @details This test file validates the correctness of the programmatic type creation
 * API. Its primary goal is to ensure that the `infix_type` objects created by
 * these functions have a memory layout (size and alignment) that perfectly
 * matches the layout produced by the C compiler for equivalent native types.
 *
 * It tests:
 * - `infix_type_create_struct`: Verifies standard padding and layout calculation.
 * - `infix_type_create_union`: Verifies size and alignment for unions.
 * - `infix_type_create_array`: Verifies layout for fixed-size arrays.
 * - `infix_type_create_enum`: Verifies that enums have the layout of their underlying type.
 * - **Introspection API**: Checks that functions like `infix_forward_get_num_args` and
 *   `infix_forward_get_arg_type` return correct information about a created trampoline.
 *
 * This test is crucial for guaranteeing that the library's internal understanding
 * of C's data layout rules is accurate.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>

// Native C types used as a baseline for comparison.
/** @internal A test struct with standard padding requirements. */
typedef struct {
    char c;
    int b;
} TestStruct;
/** @internal A test union to verify size and alignment calculation. */
typedef union {
    int i;
    double d;
} TestUnion;
/** @internal A test array to verify size and alignment calculation. */
typedef int64_t TestArray[10];
TEST {
    plan(5);
    subtest("infix_type_create_struct API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);
        // 1. Create a struct type programmatically that mirrors `TestStruct`.
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] =
            infix_type_create_member("c", infix_type_create_primitive(INFIX_PRIMITIVE_SINT8), offsetof(TestStruct, c));
        members[1] =
            infix_type_create_member("b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(TestStruct, b));
        infix_type * struct_type = nullptr;
        infix_status status = infix_type_create_struct(arena, &struct_type, members, 2);
        // 2. Verify that creation succeeded and the layout matches the compiler's layout.
        if (ok(status == INFIX_SUCCESS && struct_type != nullptr, "Successfully created a valid struct type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestStruct),
                 (unsigned long long)_Alignof(TestStruct));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)struct_type->size,
                 (unsigned long long)struct_type->alignment);
            ok(struct_type->size == sizeof(TestStruct) && struct_type->alignment == (size_t)_Alignof(TestStruct),
               "Struct size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");
        // 3. Test API hardening: ensure it rejects invalid input (e.g., a null member type).
        infix_struct_member * bad_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member), _Alignof(infix_struct_member));
        bad_members[0] = infix_type_create_member("bad", nullptr, 0);
        infix_type * bad_struct_type = nullptr;
        status = infix_type_create_struct(arena, &bad_struct_type, bad_members, 1);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_struct rejects nullptr member type");
        infix_arena_destroy(arena);
    }
    subtest("infix_type_create_union API validation") {
        plan(2);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] =
            infix_type_create_member("i", infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), offsetof(TestUnion, i));
        members[1] =
            infix_type_create_member("d", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(TestUnion, d));
        infix_type * union_type = nullptr;
        infix_status status = infix_type_create_union(arena, &union_type, members, 2);
        if (ok(status == INFIX_SUCCESS && union_type != nullptr, "Successfully created a valid union type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestUnion),
                 (unsigned long long)_Alignof(TestUnion));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)union_type->size,
                 (unsigned long long)union_type->alignment);
            ok(union_type->size == sizeof(TestUnion) && union_type->alignment == (size_t)_Alignof(TestUnion),
               "Union size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");
        infix_arena_destroy(arena);
    }
    subtest("infix_type_create_array API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * element_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT64);
        infix_type * array_type = nullptr;
        infix_status status = infix_type_create_array(arena, &array_type, element_type, 10);
        if (ok(status == INFIX_SUCCESS && array_type != nullptr, "Successfully created a valid array type")) {
            diag("Expected size: %llu, alignment: %llu",
                 (unsigned long long)sizeof(TestArray),
                 (unsigned long long)_Alignof(TestArray));
            diag("Actual size:   %llu, alignment: %llu",
                 (unsigned long long)array_type->size,
                 (unsigned long long)array_type->alignment);
            ok(array_type->size == sizeof(TestArray) && array_type->alignment == (size_t)_Alignof(TestArray),
               "Array size and alignment match compiler's layout");
        }
        else
            skip(1, "Cannot verify layout due to creation failure");
        infix_type * bad_array_type = nullptr;
        status = infix_type_create_array(arena, &bad_array_type, nullptr, 10);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array rejects nullptr element type");
        infix_arena_destroy(arena);
    }
    subtest("infix_type_create_enum API validation") {
        plan(3);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * underlying_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * enum_type = nullptr;
        infix_status status = infix_type_create_enum(arena, &enum_type, underlying_type);
        if (ok(status == INFIX_SUCCESS && enum_type != nullptr, "Successfully created a valid enum type"))
            ok(enum_type->size == sizeof(int32_t) && enum_type->alignment == (size_t)_Alignof(int32_t),
               "Enum size and alignment match underlying integer type");
        else
            skip(1, "Cannot verify layout due to creation failure");
        // Test API hardening: enums cannot have a floating-point base.
        infix_type * bad_underlying_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
        infix_type * bad_enum_type = nullptr;
        status = infix_type_create_enum(arena, &bad_enum_type, bad_underlying_type);
        ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_enum rejects non-integer underlying type");
        infix_arena_destroy(arena);
    }
    subtest("Forward trampoline introspection API") {
        plan(7);
        infix_arena_t * arena = infix_arena_create(4096);
        // Create a sample signature to test introspection on.
        infix_type * ret_type = infix_type_create_pointer();
        infix_type * arg1_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_struct_member members[] = {{"d", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), 0, 0, 0, false}};
        infix_type * arg2_type = nullptr;
        (void)infix_type_create_struct(arena, &arg2_type, members, 1);
        infix_type * arg_types[] = {arg1_type, arg2_type};
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound_manual(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == INFIX_SUCCESS && trampoline != nullptr, "Trampoline created for introspection test");
        if (trampoline) {
            ok(infix_forward_get_num_args(trampoline) == 2, "get_num_args returns correct count");
            ok(infix_forward_get_return_type(trampoline)->category == INFIX_TYPE_POINTER, "get_return_type is correct");
            ok(infix_forward_get_arg_type(trampoline, 0)->category == INFIX_TYPE_PRIMITIVE,
               "get_arg_type(0) is correct");
            ok(infix_forward_get_arg_type(trampoline, 1)->category == INFIX_TYPE_STRUCT, "get_arg_type(1) is correct");
            // Test edge cases and API hardening.
            ok(infix_forward_get_arg_type(trampoline, 99) == nullptr,
               "get_arg_type returns nullptr for out-of-bounds index");
            ok(infix_forward_get_num_args(nullptr) == 0, "get_num_args handles nullptr input gracefully");
        }
        else
            skip(6, "Skipping introspection checks due to creation failure");
        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
    }
}
