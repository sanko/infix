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
 * @file 101_by_value.c
 * @brief Tests passing and returning small aggregate types (structs) by value.
 *
 * @details This suite verifies the library's ability to handle one of the most
 * complex aspects of any ABI: the rules for passing and returning structs in
 * CPU registers. The behavior is highly platform-dependent.
 *
 * This file consolidates several previous tests (`008_return_point.c`,
 * `015_struct_with_array.c`, `207_mixed_type_aggr.c`) into a single,
 * cohesive suite with the following goals:
 *
 * 1.  **General Case:** Tests a simple `struct { double; double; }` to verify
 *     basic aggregate handling on all platforms.
 * 2.  **System V x64 Specific:** Tests a `struct { int; double; }`, which the
 *     SysV ABI dictates should be split and passed in one GPR and one XMM register.
 * 3.  **AArch64 (ARM64) Specific:** Tests a `struct { float v[4]; }`, which is a
 *     Homogeneous Floating-point Aggregate (HFA) and should be passed in four
 *     consecutive floating-point registers.
 *
 * Platform-specific tests are conditionally compiled using preprocessor guards to
 * ensure they only run on relevant targets.
 */

#define DBLTAP_IMPLEMENTATION
#include "types.h"  // Test-specific type definitions
#include <double_tap.h>
#include <infix.h>
#include <math.h>  // For fabs

// Native C Target Functions
/** @brief Processes a Point struct passed by value, returning a sum of its members. */
double process_point_by_value(Point p) {
    note("process_point_by_value received p = { .x=%.1f, .y=%.1f }", p.x, p.y);
    return p.x + p.y;
}

/** @brief Returns a Point struct by value. */
Point return_point_by_value(void) {
    return (Point){100.0, 200.0};
}

/** @brief Processes a mixed-type struct, checking its members. (SysV x64 only) */
int process_mixed_struct(MixedIntDouble s) {
    note("process_mixed_struct received: i=%d, d=%.2f", s.i, s.d);
    // This function returns a boolean-like int indicating success.
    return s.i == -500 && fabs(s.d - 3.14) < 0.001;
}

/** @brief Sums the elements of a Vector4 HFA. (AArch64 only) */
float sum_vector4(Vector4 vec) {
    return vec.v[0] + vec.v[1] + vec.v[2] + vec.v[3];
}

TEST {
    plan(3);  // One subtest for each major scenario.

    subtest("Simple struct (Point) passed and returned by value") {
        plan(5);

        // First, create the ffi_type for the Point struct. This will be reused.
        ffi_struct_member * point_members = infix_malloc(sizeof(ffi_struct_member) * 2);
        point_members[0] =
            ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));
        ffi_type * point_type = NULL;
        ffi_status status = ffi_type_create_struct(&point_type, point_members, 2);
        if (!ok(status == FFI_SUCCESS, "ffi_type for Point created successfully")) {
            skip(3, "Cannot proceed without Point type");
            infix_free(point_members);  // On failure, we must free this ourselves.
            return;
        }

        // Test 1: Pass Point as an argument
        ffi_type * arg_ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE);
        ffi_trampoline_t * arg_trampoline = NULL;
        status = generate_forward_trampoline(&arg_trampoline, arg_ret_type, &point_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for process_point_by_value created");

        ffi_cif_func arg_cif = (ffi_cif_func)ffi_trampoline_get_code(arg_trampoline);
        Point p_in = {10.5, 20.5};
        double sum_result = 0.0;
        void * arg_args[] = {&p_in};
        arg_cif((void *)process_point_by_value, &sum_result, arg_args);
        ok(fabs(sum_result - 31.0) < 0.001, "Struct passed as argument correctly");
        ffi_trampoline_free(arg_trampoline);

        // Test 2: Return Point as a value
        ffi_trampoline_t * ret_trampoline = NULL;
        status = generate_forward_trampoline(&ret_trampoline, point_type, NULL, 0, 0);
        ok(status == FFI_SUCCESS, "Trampoline for return_point_by_value created");

        ffi_cif_func ret_cif = (ffi_cif_func)ffi_trampoline_get_code(ret_trampoline);
        Point p_out = {0.0, 0.0};
        ret_cif((void *)return_point_by_value, &p_out, NULL);
        ok(fabs(p_out.x - 100.0) < 0.001 && fabs(p_out.y - 200.0) < 0.001, "Struct returned by value correctly");
        ffi_trampoline_free(ret_trampoline);

        // Cleanup: this recursively frees the members array as well.
        ffi_type_destroy(point_type);
    }

    subtest("ABI Specific: System V x64 mixed-register struct") {
        //~ #if defined(FFI_ABI_SYSV_X64)
        plan(2);
        note("Testing struct { int; double; } passed in GPR and XMM registers.");

        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member) * 2);
        members[0] = ffi_struct_member_create(
            "i", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), offsetof(MixedIntDouble, i));
        members[1] = ffi_struct_member_create(
            "d", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(MixedIntDouble, d));
        ffi_type * mixed_type = NULL;
        (void)ffi_type_create_struct(&mixed_type, members, 2);

        ffi_trampoline_t * trampoline = NULL;
        ffi_status status = generate_forward_trampoline(
            &trampoline, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), &mixed_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for mixed-type struct created");

        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        MixedIntDouble arg_val = {-500, 3.14};
        int result = 0;
        void * args[] = {&arg_val};
        cif_func((void *)process_mixed_struct, &result, args);
        ok(result == 1, "Mixed-type struct was passed correctly");

        ffi_trampoline_free(trampoline);
        ffi_type_destroy(mixed_type);
    }

    subtest("ABI Specific: AArch64 Homogeneous Floating-point Aggregate (HFA)") {
        plan(2);
        note("Testing struct { float v[4]; } as an HFA in V0-V3 registers.");

        // Level 1: Create the inner array type float[4]
        ffi_type * array_type = NULL;
        ffi_status status = ffi_type_create_array(&array_type, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT), 4);
        if (status != FFI_SUCCESS) {
            fail("Failed to create HFA inner array type");
            skip(1, "Cannot proceed");
            return;
        }

        // Level 2: Wrap the array in a struct
        ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member));
        members[0] = ffi_struct_member_create("v", array_type, offsetof(Vector4, v));
        ffi_type * struct_type = NULL;
        status = ffi_type_create_struct(&struct_type, members, 1);
        if (status != FFI_SUCCESS) {
            fail("Failed to create HFA container struct type");
            skip(1, "Cannot proceed");
            ffi_type_destroy(array_type);
            return;
        }

        ffi_trampoline_t * trampoline = NULL;
        status = generate_forward_trampoline(
            &trampoline, ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT), &struct_type, 1, 1);
        ok(status == FFI_SUCCESS, "Trampoline for HFA struct created");

        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
        Vector4 vec = {{1.5f, 2.5f, 3.5f, 4.5f}};
        float result = 0.0f;
        void * args[] = {&vec};
        cif_func((void *)sum_vector4, &result, args);
        ok(fabs(result - 12.0f) < 0.001, "HFA struct passed correctly");

        ffi_trampoline_free(trampoline);
        ffi_type_destroy(struct_type);  // Recursively destroys the inner array type
    }
}
