/**
 * @file 007_type_registry.c
 * @brief Unit test for the named type registry system.
 * @ingroup test_suite
 *
 * @details This test file validates the complete functionality of the type registry,
 * ensuring that named types can be defined, resolved, and used correctly in both
 * forward and reverse FFI calls.
 *
 * The test covers:
 * - **Lifecycle and Basic Definitions:** Verifying that a registry can be created and
 *   destroyed, that simple types can be registered, and that attempting to redefine
 *   a type correctly produces an error.
 *
 * - **Usage in FFI Calls:** Demonstrates using a registered named type (e.g., `@Point`)
 *   in a signature string to create both forward and reverse trampolines, and
 *   verifies that the resulting FFI calls work correctly.
 *
 * - **Advanced Definitions:** Tests the registry's ability to handle complex scenarios
 *   like recursive type definitions (`struct Node { struct Node* next; }`) and
 *   mutually-recursive types using forward declarations. It uses introspection
 *   to verify that the resulting type graphs have the correct circular structure.
 *
 * - **Error Handling:** Ensures that the system fails gracefully with the correct error
 *   codes when using unregistered types, unresolved forward declarations, or when
 *   using the `@Name` syntax with a `NULL` registry.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>

// Native C Functions for Testing

double get_point_x(Point p) {
    note("get_point_x received Point {x=%.1f, y=%.1f}", p.x, p.y);
    return p.x;
}
Point move_point_handler(Point p) {
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

        // Test error case: redefining an existing type should fail.
        status = infix_register_types(registry, "@MyInt = int64;");
        ok(status != INFIX_SUCCESS, "Attempting to redefine a type correctly fails");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Redefinition error has correct category");
        }
        else
            fail("Redefinition should have failed but didn't");

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
        else
            skip(1, "Call test skipped");

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
        infix_status status = infix_reverse_create_callback(&context, signature, (void *)move_point_handler, registry);
        ok(status == INFIX_SUCCESS, "Reverse trampoline created using named type '@Point'");
        if (context) {
            typedef Point (*PointFunc)(Point);
            PointFunc func_ptr = (PointFunc)infix_reverse_get_code(context);
            execute_move_point_callback(func_ptr, (Point){10.0, 20.0});
        }
        else
            skip(1, "Callback execution skipped");

        infix_reverse_destroy(context);
        infix_registry_destroy(registry);
    }

    subtest("Advanced Definitions (Recursive & Forward Declared)") {
        plan(4);
        infix_registry_t * registry = infix_registry_create();

        // Test a simple recursive type (linked list node).
        const char * recursive_def = "@Node = { value: int, next: *@Node };";
        infix_status status = infix_register_types(registry, recursive_def);
        ok(status == INFIX_SUCCESS, "Successfully registered a recursive type");

        // Test mutually recursive types using forward declarations.
        const char * mutual_defs = "@A; @B; @A = { b_ptr: *@B }; @B = { a_ptr: *@A };";
        status = infix_register_types(registry, mutual_defs);
        ok(status == INFIX_SUCCESS, "Successfully registered mutually recursive types via forward declarations");

        // Introspect the recursive type to verify its structure.
        infix_type * node_ptr_type = nullptr;
        infix_arena_t * temp_arena = nullptr;
        status = infix_type_from_signature(&node_ptr_type, &temp_arena, "*@Node", registry);
        if (ok(status == INFIX_SUCCESS, "Parsed `*@Node` using registry")) {
            infix_type * node_type = node_ptr_type->meta.pointer_info.pointee_type;
            infix_type * next_ptr_type = node_type->meta.aggregate_info.members[1].type;
            infix_type * next_pointee_type = next_ptr_type->meta.pointer_info.pointee_type;
            // The crucial check: does the `next` pointer's pointee type point back to the parent struct itself?
            ok(next_pointee_type == node_type, "Recursive pointer correctly points to the parent struct type");
        }
        else
            skip(1, "Introspection check skipped");

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
        else
            skip(1, "Error detail check skipped");

        infix_forward_destroy(trampoline);

        ok(infix_register_types(registry, "@FwdOnly;") == INFIX_SUCCESS, "Setup: forward declare @FwdOnly");
        status = infix_forward_create(&trampoline, "(@FwdOnly)->void", (void *)get_point_x, registry);
        ok(status != INFIX_SUCCESS, "Creation fails when using an unresolved forward-declared type");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.code == INFIX_CODE_UNRESOLVED_NAMED_TYPE, "Error code is UNRESOLVED_NAMED_TYPE for fwd-decl");
        }
        else
            skip(1, "Error detail check skipped");

        infix_forward_destroy(trampoline);

        status = infix_forward_create(&trampoline, "(@SomeType)->void", (void *)get_point_x, nullptr);
        ok(status != INFIX_SUCCESS, "Creation fails when using '@' sigil with a NULL registry");
        infix_forward_destroy(trampoline);

        infix_registry_destroy(registry);
    }
}
