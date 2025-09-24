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
 * @file 302_aggregates.c
 * @brief Tests reverse trampolines (callbacks) with struct and union arguments/returns.
 *
 * @details This is a comprehensive test suite for verifying the reverse FFI
 * (callback) functionality with aggregate types. It covers a wide range of
 * scenarios that are highly dependent on the target platform's ABI rules.
 *
 * The suite consolidates several previous tests and verifies:
 * - **Small Structs:** Passing and returning a `Point` struct, which is small
 *   enough to be handled in registers on most platforms.
 * - **Large Structs (Pass by Reference):** Passing a `LargeStruct` to a
 *   callback, which ABIs will handle by passing a pointer to a copy on the stack.
 * - **Large Structs (Return via Hidden Pointer):** Returning a `LargeStruct`
 *   from a callback, which ABIs handle by having the caller provide a hidden
 *   pointer to a buffer where the result is written.
 * - **ABI-Specific Aggregates (HFA):** Passing a `Vector4` struct, which is
 *   treated as a Homogeneous Floating-point Aggregate on AArch64.
 * - **Unions:** Returning a `Number` union from a callback.
 */

#define DBLTAP_IMPLEMENTATION
#include "types.h"
#include <double_tap.h>
#include <infix.h>
#include <math.h>

/** @brief Handler for Point(Point) signature. Doubles the coordinates. */
Point point_callback_handler(ffi_reverse_trampoline_t * context, Point p) {
    (void)context;
    note("point_callback_handler received p={%.1f, %.1f}", p.x, p.y);
    return (Point){p.x * 2.0, p.y * 2.0};
}

/** @brief Handler for int(LargeStruct) signature. Processes a large struct. */
int large_struct_pass_handler(ffi_reverse_trampoline_t * context, LargeStruct s) {
    (void)context;
    note("large_struct_pass_handler received s.a=%d, s.f=%d", s.a, s.f);
    return s.a - s.f;
}

/** @brief Handler for LargeStruct(int) signature. Returns a large struct. */
LargeStruct large_struct_return_handler(ffi_reverse_trampoline_t * context, int a) {
    (void)context;
    note("large_struct_return_handler called with a=%d", a);
    return (LargeStruct){a, a + 1, a + 2, a + 3, a + 4, a + 5};
}

/** @brief Handler for int(Vector4) signature. Sums the vector elements. */
int vector4_callback_handler(ffi_reverse_trampoline_t * context, Vector4 v) {
    (void)context;
    return (int)(v.v[0] + v.v[1] + v.v[2] + v.v[3]);
}

/** @brief Handler for Number(float) signature. Returns a union. */
Number number_union_return_handler(ffi_reverse_trampoline_t * context, float f) {
    (void)context;
    Number n;
    n.f = f * 10.0f;
    return n;
}
void execute_point_callback(Point (*func_ptr)(Point), Point p) {
    Point result = func_ptr(p);
    ok(fabs(result.x - p.x * 2.0) < 0.001 && fabs(result.y - p.y * 2.0) < 0.001, "Callback returned correct Point");
}
void execute_large_struct_pass_callback(int (*func_ptr)(LargeStruct), LargeStruct s) {
    int result = func_ptr(s);
    ok(result == (s.a - s.f), "Callback returned correct int from LargeStruct");
}
void execute_large_struct_return_callback(LargeStruct (*func_ptr)(int), int a) {
    LargeStruct s = func_ptr(a);
    ok(s.a == a && s.b == a + 1 && s.f == a + 5, "Callback returned correct LargeStruct");
}
void execute_vector4_callback(int (*func_ptr)(Vector4), Vector4 v, int expected) {
    int result = func_ptr(v);
    ok(result == expected, "Callback returned correct sum from Vector4 (got %d, expected %d)", result, expected);
}
void execute_number_union_return_callback(Number (*func_ptr)(float), float f) {
    Number result = func_ptr(f);
    ok(fabs(result.f - (f * 10.0f)) < 0.001, "Callback returned correct Number union");
}

/** @brief A simple C function to act as our FFI target. It verifies the struct's contents. */
int process_packed_struct(PackedStruct p) {
    note("C target received PackedStruct with a='%c', b=%" PRIu64, p.a, p.b);
    if (p.a == 'X' && p.b == 0xDEADBEEFCAFEBABE)
        return 42;  // Success code
    return -1;      // Failure code
}

TEST {
    plan(6);

    subtest("Callback with small struct: Point(Point)") {
        plan(3);
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
        members[0] =
            ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
        members[1] =
            ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));
        ffi_type * point_type = NULL;

        ffi_status status = ffi_type_create_struct(&point_type, members, 2);
        if (!ok(status == FFI_SUCCESS, "Point ffi_type created")) {
            skip(2, "Test skipped");
            infix_free(members);
            return;
        }

        ffi_reverse_trampoline_t * rt = NULL;
        status = generate_reverse_trampoline(&rt, point_type, &point_type, 1, 1, (void *)point_callback_handler, NULL);
        ok(status == FFI_SUCCESS, "Reverse trampoline created");

        if (rt)
            execute_point_callback((Point(*)(Point))ffi_reverse_trampoline_get_code(rt), (Point){10.0, -5.0});
        else
            skip(1, "Test skipped");

        ffi_reverse_trampoline_free(rt);
        ffi_type_destroy(point_type);
    }

    subtest("Callback with large struct argument: int(LargeStruct)") {
        plan(3);
        ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 6);
        for (int i = 0; i < 6; ++i)
            members[i] =
                ffi_struct_member_create(NULL, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), sizeof(int) * i);
        ffi_type * large_struct_type = NULL;

        ffi_status status = ffi_type_create_struct(&large_struct_type, members, 6);
        if (!ok(status == FFI_SUCCESS, "LargeStruct ffi_type created")) {
            skip(2, "Test skipped");
            infix_free(members);
            return;
        }

        ffi_reverse_trampoline_t * rt = NULL;
        status = generate_reverse_trampoline(
            &rt, ret_type, &large_struct_type, 1, 1, (void *)large_struct_pass_handler, NULL);
        ok(status == FFI_SUCCESS, "Reverse trampoline created");

        if (rt)
            execute_large_struct_pass_callback((int (*)(LargeStruct))ffi_reverse_trampoline_get_code(rt),
                                               (LargeStruct){100, 0, 0, 0, 0, 25});
        else
            skip(1, "Test skipped");

        ffi_reverse_trampoline_free(rt);
        ffi_type_destroy(large_struct_type);
    }

    subtest("Callback returning large struct: LargeStruct(int)") {
        plan(3);
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 6);
        for (int i = 0; i < 6; ++i)
            members[i] =
                ffi_struct_member_create(NULL, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), sizeof(int) * i);
        ffi_type * large_struct_type = NULL;

        ffi_status status = ffi_type_create_struct(&large_struct_type, members, 6);
        if (!ok(status == FFI_SUCCESS, "LargeStruct ffi_type created")) {
            skip(2, "Test skipped");
            infix_free(members);
            return;
        }
        ffi_type * arg_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);

        ffi_reverse_trampoline_t * rt = NULL;
        status = generate_reverse_trampoline(
            &rt, large_struct_type, &arg_type, 1, 1, (void *)large_struct_return_handler, NULL);
        ok(status == FFI_SUCCESS, "Reverse trampoline created");

        if (rt)
            execute_large_struct_return_callback((LargeStruct(*)(int))ffi_reverse_trampoline_get_code(rt), 50);
        else
            skip(1, "Test skipped");

        ffi_reverse_trampoline_free(rt);
        ffi_type_destroy(large_struct_type);
    }

    subtest("Callback with struct containing array: int(Vector4)") {
        plan(4);
        ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        ffi_type * array_type = NULL;

        ffi_status status = ffi_type_create_array(&array_type, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT), 4);
        if (!ok(status == FFI_SUCCESS, "Array ffi_type created")) {
            skip(3, "Test skipped");
            return;
        }

        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member));
        members[0] = ffi_struct_member_create("v", array_type, offsetof(Vector4, v));
        ffi_type * struct_type = NULL;

        status = ffi_type_create_struct(&struct_type, members, 1);
        if (!ok(status == FFI_SUCCESS, "Vector4 ffi_type created")) {
            skip(2, "Test skipped");
            ffi_type_destroy(array_type);  // Clean up sub-type
            return;
        }

        ffi_reverse_trampoline_t * rt = NULL;
        status = generate_reverse_trampoline(&rt, ret_type, &struct_type, 1, 1, (void *)vector4_callback_handler, NULL);
        ok(status == FFI_SUCCESS, "Reverse trampoline created");

        if (rt)
            execute_vector4_callback(
                (int (*)(Vector4))ffi_reverse_trampoline_get_code(rt), (Vector4){{4.0f, 6.0f, 8.0f, 12.0f}}, 30);
        else
            skip(1, "Test skipped");

        ffi_reverse_trampoline_free(rt);
        ffi_type_destroy(struct_type);
    }

    subtest("Callback returning union: Number(float)") {
        plan(3);
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
        members[0] = ffi_struct_member_create("i", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), 0);
        members[1] = ffi_struct_member_create("f", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT), 0);
        ffi_type * union_type = NULL;

        ffi_status status = ffi_type_create_union(&union_type, members, 2);
        if (!ok(status == FFI_SUCCESS, "Number union ffi_type created")) {
            skip(2, "Test skipped");
            infix_free(members);
            return;
        }
        ffi_type * arg_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT);

        ffi_reverse_trampoline_t * rt = NULL;
        status =
            generate_reverse_trampoline(&rt, union_type, &arg_type, 1, 1, (void *)number_union_return_handler, NULL);
        ok(status == FFI_SUCCESS, "Reverse trampoline created");

        if (rt)
            execute_number_union_return_callback((Number(*)(float))ffi_reverse_trampoline_get_code(rt), 3.14f);
        else
            skip(1, "Test skipped");

        ffi_reverse_trampoline_free(rt);
        ffi_type_destroy(union_type);
    }

    subtest("Packed struct") {
        plan(5);

        ffi_struct_member * members = infix_malloc(2 * sizeof(ffi_struct_member));
        members[0] = ffi_struct_member_create(
            "a", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8), offsetof(PackedStruct, a));
        members[1] = ffi_struct_member_create(
            "b", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64), offsetof(PackedStruct, b));

        ffi_type * packed_type = NULL;
        ffi_status status =
            ffi_type_create_packed_struct(&packed_type, sizeof(PackedStruct), _Alignof(PackedStruct), members, 2);

        if (!ok(status == FFI_SUCCESS, "Packed struct ffi_type created")) {
            skip(4, "Test skipped");
            infix_free(members);
            return;
        }

        ok(packed_type->size == 9, "Packed struct size should be 9 bytes.");
        ok(packed_type->alignment == 1, "Packed struct alignment should be 1 byte.");

        // Action: Generate and call the trampoline
        ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
        ffi_trampoline_t * trampoline = NULL;
        status = generate_forward_trampoline(&trampoline, ret_type, &packed_type, 1, 1);
        ok(status == FFI_SUCCESS, "Successfully generated trampoline for packed struct.");
        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

        PackedStruct arg_struct = {'X', 0xDEADBEEFCAFEBABE};
        int result = 0;
        void * args[] = {&arg_struct};

        cif_func((void *)process_packed_struct, &result, args);

        // Verification
        ok(result == 42, "Packed struct was passed and processed correctly.");

        // Teardown
        ffi_trampoline_free(trampoline);
        ffi_type_destroy(packed_type);
    }
}
