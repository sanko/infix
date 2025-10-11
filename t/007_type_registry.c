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
 * @file 007_registry.c
 * @brief Comprehensive test suite for the Named Type Registry.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>

double get_point_x(Point p) {
    note("get_point_x received Point {x=%.1f, y=%.1f}", p.x, p.y);
    return p.x;
}
Point move_point_handler(infix_context_t * context, Point p) {
    (void)context;
    note("move_point_handler received Point {x=%.1f, y=%.1f}", p.x, p.y);
    p.x += 100.0;
    p.y -= 100.0;
    return p;
}
void execute_move_point_callback(Point (*func_ptr)(Point), Point p_in) {
    Point p_out = func_ptr(p_in);
    ok(fabs(p_out.x - (p_in.x + 100.0)) < 1e-9 && fabs(p_out.y - (p_in.y - 100.0)) < 1e-9,
       "Callback returned correctly modified Point");
}

TEST {
    plan(5);

    subtest("Basic Registry Lifecycle and Simple Definitions") {
        plan(4);
        infix_registry_t * registry = infix_registry_create();
        ok(registry != nullptr, "Registry created successfully");
        if (!registry) {
            skip(3, "Cannot proceed without a registry");
            return;
        }
        const char * definitions = "@MyInt = int32; @Point = { x: double, y: double };";
        infix_status status = infix_register_types(registry, definitions);
        ok(status == INFIX_SUCCESS, "Registered simple alias and struct");
        status = infix_register_types(registry, "@MyInt = int64;");
        ok(status != INFIX_SUCCESS, "Attempting to redefine a type correctly fails");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Redefinition error has correct category");
        }
        else {
            fail("Redefinition should have failed but didn't");
        }
        infix_registry_destroy(registry);
    }

    subtest("Using Named Types in Forward Calls") {
        plan(3);
        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS,
           "Setup: @Point registered");
        const char * signature = "(@Point) -> double";
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create(&trampoline, signature, (void *)get_point_x, registry);
        ok(status == INFIX_SUCCESS, "Forward trampoline created using named type '@Point'");
        if (trampoline) {
            Point p = {42.5, -10.0};
            void * args[] = {&p};
            double result = 0.0;
            infix_cif_func cif = infix_forward_get_code(trampoline);
            cif(&result, args);
            ok(fabs(result - 42.5) < 1e-9, "FFI call with named type as argument succeeded");
        }
        else {
            skip(1, "Call test skipped");
        }
        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    subtest("Using Named Types in Reverse Calls") {
        plan(3);
        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS,
           "Setup: @Point registered");
        const char * signature = "(@Point) -> @Point";
        infix_reverse_t * context = nullptr;
        infix_status status = infix_reverse_create(&context, signature, (void *)move_point_handler, nullptr, registry);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created using named type '@Point'");
        if (context) {
            typedef Point (*PointFunc)(Point);
            PointFunc func_ptr = (PointFunc)infix_reverse_get_code(context);
            execute_move_point_callback(func_ptr, (Point){10.0, 20.0});
        }
        else {
            skip(1, "Callback execution skipped");
        }
        infix_reverse_destroy(context);
        infix_registry_destroy(registry);
    }

    subtest("Advanced Definitions (Recursive & Forward Declared)") {
        plan(4);
        infix_registry_t * registry = infix_registry_create();

        const char * recursive_def = "@Node = { value: int, next: *@Node };";
        infix_status status = infix_register_types(registry, recursive_def);
        ok(status == INFIX_SUCCESS, "Successfully registered a recursive type");

        const char * mutual_defs = "@A; @B; @A = { b_ptr: *@B }; @B = { a_ptr: *@A };";
        status = infix_register_types(registry, mutual_defs);
        ok(status == INFIX_SUCCESS, "Successfully registered mutually recursive types via forward declarations");

        infix_type * node_ptr_type = nullptr;
        infix_arena_t * temp_arena = nullptr;
        status = infix_type_from_signature(&node_ptr_type, &temp_arena, "*@Node", registry);
        if (ok(status == INFIX_SUCCESS, "Parsed `*@Node` using registry")) {
            infix_type * node_type = node_ptr_type->meta.pointer_info.pointee_type;
            infix_type * next_ptr_type = node_type->meta.aggregate_info.members[1].type;
            infix_type * next_pointee_type = next_ptr_type->meta.pointer_info.pointee_type;
            ok(next_pointee_type == node_type, "Recursive pointer correctly points to the parent struct type");
        }
        else {
            skip(1, "Introspection check skipped");
        }
        infix_arena_destroy(temp_arena);
        infix_registry_destroy(registry);
    }

    subtest("Error Handling") {
        plan(7);
        infix_registry_t * registry = infix_registry_create();

        const char * bad_syntax = "@Bad = { int,, double};";
        infix_status status = infix_register_types(registry, bad_syntax);
        ok(status != INFIX_SUCCESS, "Registration fails on syntax error in definition");

        infix_forward_t * trampoline = nullptr;
        status = infix_forward_create(&trampoline, "(@DoesNotExist)->void", (void *)get_point_x, registry);
        ok(status != INFIX_SUCCESS, "Creation fails when using an unregistered named type");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.code == INFIX_CODE_UNRESOLVED_NAMED_TYPE, "Error code is UNRESOLVED_NAMED_TYPE for missing type");
        }
        else {
            skip(1, "Error detail check skipped");
        }
        infix_forward_destroy(trampoline);

        ok(infix_register_types(registry, "@FwdOnly;") == INFIX_SUCCESS, "Setup: forward declare @FwdOnly");
        status = infix_forward_create(&trampoline, "(@FwdOnly)->void", (void *)get_point_x, registry);
        ok(status != INFIX_SUCCESS, "Creation fails when using an unresolved forward-declared type");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.code == INFIX_CODE_UNRESOLVED_NAMED_TYPE, "Error code is UNRESOLVED_NAMED_TYPE for fwd-decl");
        }
        else {
            skip(1, "Error detail check skipped");
        }
        infix_forward_destroy(trampoline);

        status = infix_forward_create(&trampoline, "(@SomeType)->void", (void *)get_point_x, nullptr);
        ok(status != INFIX_SUCCESS, "Creation fails when using '@' sigil with a NULL registry");
        infix_forward_destroy(trampoline);

        infix_registry_destroy(registry);
    }
}
