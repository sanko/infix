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
 * @file 851_lifecycle_regression.c
 * @brief Regression tests for memory lifecycle bugs found in production.
 *
 * @details This suite contains tests for specific, critical bugs related to the
 * memory lifecycle of `infix_type` objects, particularly the handoff between
 * temporary parser arenas and permanent trampoline arenas.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <string.h>

void dummy_func() {}

TEST {
    plan(5);

    // Original Test 1: Still valuable as a baseline.
    subtest("Use-after-free of resolved named pointee type") {
        plan(5);
        note("Verifies that a pointer to a named type (*@Point) remains valid after trampoline creation.");

        infix_registry_t* registry = infix_registry_create();
        ok(registry != NULL, "Registry created");
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS, "Registered @Point type");

        infix_forward_t* trampoline = NULL;
        const char* signature = "(*@Point) -> void";
        infix_status status = infix_forward_create(&trampoline, signature, (void*)dummy_func, registry);

        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline created successfully");

        if (trampoline) {
            const infix_type* arg_type = infix_forward_get_arg_type(trampoline, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_POINTER, "Argument is a pointer");

            const infix_type* pointee_type = arg_type->meta.pointer_info.pointee_type;
            ok(pointee_type && pointee_type->category == INFIX_TYPE_STRUCT,
               "Pointee is a valid struct type, not garbage/NULL");
        } else {
            skip(2, "Skipping introspection due to creation failure.");
        }

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    // Original Test 2: Also still valuable.
    subtest("Garbage output from infix_type_print on copied named type") {
        plan(3);
        note("Verifies that infix_type_print works correctly on a copied type graph.");

        infix_registry_t* registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = {x:double, y:double};") == INFIX_SUCCESS, "Registered @Point type");

        infix_forward_t* trampoline = NULL;
        const char* signature = "(*@Point) -> void";
        infix_status create_status = infix_forward_create(&trampoline, signature, (void*)dummy_func, registry);

        if (ok(create_status == INFIX_SUCCESS && trampoline != NULL, "Trampoline created")) {
            const infix_type* arg_type = infix_forward_get_arg_type(trampoline, 0);
            char buffer[256];
            infix_status print_status = infix_type_print(buffer, sizeof(buffer), arg_type, INFIX_DIALECT_SIGNATURE);

            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "*@Point") == 0, "infix_type_print output is correct ('%s')", buffer);
        } else {
            skip(1, "Skipping print test due to creation failure.");
        }

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    // NEW TEST 1: Test direct and nested named types.
    subtest("Lifecycle with direct and nested named types") {
        plan(4);
        note("Verifies lifecycle for named types passed by value and nested in other structs.");

        infix_registry_t* registry = infix_registry_create();
        ok(infix_register_types(registry,
            "@Point = {x:double, y:double};"
            "@Rect = {tl:@Point, br:@Point};"
        ) == INFIX_SUCCESS, "Registered nested types @Point and @Rect");

        infix_forward_t* trampoline = NULL;
        const char* signature = "(@Rect) -> void";
        infix_status status = infix_forward_create(&trampoline, signature, (void*)dummy_func, registry);

        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline with nested named type created");

        if (trampoline) {
            const infix_type* rect_type = infix_forward_get_arg_type(trampoline, 0);
            ok(rect_type && rect_type->category == INFIX_TYPE_STRUCT, "Argument is a struct");

            const infix_struct_member* member = infix_type_get_member(rect_type, 0);
            // After the copy, the member type should be a valid struct, not garbage.
            ok(member && member->type && member->type->category == INFIX_TYPE_STRUCT, "Nested member type is valid");
        } else {
            skip(2, "Skipping introspection checks");
        }

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    // NEW TEST 2: The recursive type test.
    subtest("Lifecycle with recursive named types") {
        plan(6);
        note("Verifies the copy mechanism handles recursive types without infinite loops or UAF.");

        infix_registry_t* registry = infix_registry_create();
        ok(infix_register_types(registry, "@Node = { value: int, next: *@Node };") == INFIX_SUCCESS, "Registered recursive @Node type");

        infix_forward_t* trampoline = NULL;
        const char* signature = "(*@Node) -> void";
        // The creation itself is a test. If the memoization fix is wrong, this will infinite loop.
        infix_status status = infix_forward_create(&trampoline, signature, (void*)dummy_func, registry);
        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline with recursive type created (no infinite loop)");

        if (trampoline) {
            const infix_type* arg_type = infix_forward_get_arg_type(trampoline, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_POINTER, "Argument is a pointer");

            const infix_type* node_type = arg_type->meta.pointer_info.pointee_type;
            ok(node_type && node_type->category == INFIX_TYPE_STRUCT, "Pointee is a struct");

            const infix_struct_member* next_member = infix_type_get_member(node_type, 1);
            ok(next_member && next_member->type->category == INFIX_TYPE_POINTER, "Member 'next' is a pointer");

            // The ultimate test: The `next` pointer's pointee should be the *exact same* copied node_type.
            const infix_type* next_pointee_type = next_member->type->meta.pointer_info.pointee_type;
            ok(next_pointee_type == node_type, "Recursive pointer correctly points back to parent struct");
        } else {
            skip(4, "Skipping introspection due to creation failure.");
        }

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    // NEW TEST 3: Expanded print test (NOW FIXED).
    subtest("Expanded infix_type_print validation for named types") {
        plan(4);
        note("Verifies name propagation for printing in various contexts (return, nested).");

        infix_registry_t* registry = infix_registry_create();
        ok(infix_register_types(registry,
            "@Point = {x:double, y:double};"
            "@Rect = {tl:@Point, br:@Point};"
        ) == INFIX_SUCCESS, "Registered types for print test");

        // Test 1: Printing a named type as a return value.
        infix_forward_t* t_ret = NULL;
        if (ok(infix_forward_create(&t_ret, "()->@Rect", (void*)dummy_func, registry) == INFIX_SUCCESS, "Created return-type trampoline")) {
            char buffer[128];
            infix_status print_status = infix_type_print(buffer, sizeof(buffer), infix_forward_get_return_type(t_ret), INFIX_DIALECT_SIGNATURE);
            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "@Rect") == 0, "Printing named return type is correct ('%s')", buffer);
        } else {
            skip(1, "Skipping return type print test");
        }

        // Test 2: Printing a signature containing a nested named type.
        infix_forward_t* t_nested = NULL;
        if (ok(infix_forward_create(&t_nested, "({sint32, r:@Rect})->void", (void*)dummy_func, registry) == INFIX_SUCCESS, "Created nested-type trampoline")) {
            char buffer[128];
            const infix_type* arg_type = infix_forward_get_arg_type(t_nested, 0);
            infix_status print_status = infix_type_print(buffer, sizeof(buffer), arg_type, INFIX_DIALECT_SIGNATURE);
            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "{sint32,r:@Rect}") == 0, "Printing nested named type is correct ('%s')", buffer);
        } else {
            skip(1, "Skipping nested type print test");
        }


        infix_forward_destroy(t_ret);
        infix_forward_destroy(t_nested);
        infix_registry_destroy(registry);
    }
}
