/**
 * @file 851_lifecycle_regression.c
 * @brief Regression tests for specific memory lifecycle and ownership bugs.
 * @ingroup test_suite
 *
 * @details This test file targets specific, subtle bugs related to the memory
 * lifecycle of `infix_type` objects, particularly when they are copied between
 * different memory arenas during the "Parse -> Copy -> Resolve -> Layout" pipeline.
 *
 * The tests verify:
 *
 * 1.  **Use-After-Free of Pointee Types:** Ensures that when a signature like `*@Point`
 *     is parsed, the `Point` type object (resolved from the registry) remains valid
 *     and is not prematurely freed after the temporary parser arena is destroyed.
 *
 * 2.  **Correct Printing of Copied Named Types:** Verifies that `infix_type_print` can
 *     correctly serialize a type graph that has been deep-copied into a trampoline's
 *     private arena, ensuring that pointers to type names remain valid after the copy.
 *
 * 3.  **Handling of Recursive Types:** Confirms that the deep-copy mechanism
 *     correctly handles recursive type definitions (like a linked list node) without
 *     causing a stack overflow from infinite recursion, and that the resulting
 *     copied graph maintains its correct recursive structure.
 *
 * 4.  **Semantic Name Preservation:** Validates that the new `name` field is correctly
 *     populated and preserved through the full parse/copy/resolve pipeline for all
 *     named types, including aliases.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <string.h>

void dummy_func() {}

TEST {
    plan(6);

    subtest("Use-after-free of resolved named pointee type") {
        plan(5);
        note("Verifies that a pointer to a named type (*@Point) remains valid after trampoline creation.");

        infix_registry_t * registry = infix_registry_create();
        ok(registry != NULL, "Registry created");
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS,
           "Registered @Point type");

        infix_forward_t * trampoline = NULL;
        const char * signature = "(*@Point) -> void";
        infix_status status = infix_forward_create(&trampoline, signature, (void *)dummy_func, registry);

        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline created successfully");

        if (trampoline) {
            const infix_type * arg_type = infix_forward_get_arg_type(trampoline, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_POINTER, "Argument is a pointer");

            const infix_type * pointee_type = arg_type->meta.pointer_info.pointee_type;
            ok(pointee_type && pointee_type->category == INFIX_TYPE_STRUCT,
               "Pointee is a valid struct type, not garbage/NULL");
        }
        else
            skip(2, "Skipping introspection due to creation failure.");

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    subtest("Garbage output from infix_type_print on copied named type") {
        plan(3);
        note("Verifies that infix_type_print works correctly on a copied type graph.");

        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = {x:double, y:double};") == INFIX_SUCCESS, "Registered @Point type");

        infix_forward_t * trampoline = NULL;
        const char * signature = "(*@Point) -> void";
        infix_status create_status = infix_forward_create(&trampoline, signature, (void *)dummy_func, registry);

        if (ok(create_status == INFIX_SUCCESS && trampoline != NULL, "Trampoline created")) {
            const infix_type * arg_type = infix_forward_get_arg_type(trampoline, 0);
            char buffer[256];
            infix_status print_status = infix_type_print(buffer, sizeof(buffer), arg_type, INFIX_DIALECT_SIGNATURE);

            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "*@Point") == 0,
               "infix_type_print output is correct ('%s')",
               buffer);
        }
        else
            skip(1, "Skipping print test due to creation failure.");

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    subtest("Lifecycle with direct and nested named types") {
        plan(4);
        note("Verifies lifecycle for named types passed by value and nested in other structs.");

        infix_registry_t * registry = infix_registry_create();

        ok(infix_register_types(registry, "@Point = {x:double, y:double}; @Rect = {tl:@Point, br:@Point};") ==
               INFIX_SUCCESS,
           "Registered nested types @Point and @Rect");

        infix_forward_t * trampoline = NULL;
        const char * signature = "(@Rect) -> void";
        infix_status status = infix_forward_create(&trampoline, signature, (void *)dummy_func, registry);

        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline with nested named type created");

        if (trampoline) {
            const infix_type * rect_type = infix_forward_get_arg_type(trampoline, 0);
            ok(rect_type && rect_type->category == INFIX_TYPE_STRUCT, "Argument is a struct");

            const infix_struct_member * member = infix_type_get_member(rect_type, 0);

            ok(member && member->type && member->type->category == INFIX_TYPE_STRUCT, "Nested member type is valid");
        }
        else
            skip(2, "Skipping introspection checks");

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    subtest("Lifecycle with recursive named types") {
        plan(6);
        note("Verifies the copy mechanism handles recursive types without infinite loops or UAF.");

        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Node = { value: int, next: *@Node };") == INFIX_SUCCESS,
           "Registered recursive @Node type");

        infix_forward_t * trampoline = NULL;
        const char * signature = "(*@Node) -> void";

        infix_status status = infix_forward_create(&trampoline, signature, (void *)dummy_func, registry);
        ok(status == INFIX_SUCCESS && trampoline != NULL, "Trampoline with recursive type created (no infinite loop)");

        if (trampoline) {
            const infix_type * arg_type = infix_forward_get_arg_type(trampoline, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_POINTER, "Argument is a pointer");

            const infix_type * node_type = arg_type->meta.pointer_info.pointee_type;
            ok(node_type && node_type->category == INFIX_TYPE_STRUCT, "Pointee is a struct");

            const infix_struct_member * next_member = infix_type_get_member(node_type, 1);
            ok(next_member && next_member->type && next_member->type->category == INFIX_TYPE_POINTER,
               "Member 'next' is a pointer");

            const infix_type * next_pointee_type = next_member->type->meta.pointer_info.pointee_type;
            ok(next_pointee_type == node_type, "Recursive pointer correctly points back to parent struct");
        }
        else
            skip(4, "Skipping introspection due to creation failure.");

        infix_forward_destroy(trampoline);
        infix_registry_destroy(registry);
    }

    subtest("Expanded infix_type_print validation for named types") {
        plan(5);
        note("Verifies name propagation for printing in various contexts (return, nested).");

        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = {x:double, y:double}; @Rect = {tl:@Point, br:@Point};") ==
               INFIX_SUCCESS,
           "Registered types for print test");

        infix_forward_t * t_ret = NULL;
        if (ok(infix_forward_create(&t_ret, "()->@Rect", (void *)dummy_func, registry) == INFIX_SUCCESS,
               "Created return-type trampoline")) {
            char buffer[128];
            infix_status print_status =
                infix_type_print(buffer, sizeof(buffer), infix_forward_get_return_type(t_ret), INFIX_DIALECT_SIGNATURE);
            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "@Rect") == 0,
               "Printing named return type is correct ('%s')",
               buffer);
        }
        else
            skip(1, "Skipping return type print test");

        infix_forward_t * t_nested = NULL;
        if (ok(infix_forward_create(&t_nested, "({sint32, r:@Rect})->void", (void *)dummy_func, registry) ==
                   INFIX_SUCCESS,
               "Created nested-type trampoline")) {
            char buffer[128];
            const infix_type * arg_type = infix_forward_get_arg_type(t_nested, 0);
            infix_status print_status = infix_type_print(buffer, sizeof(buffer), arg_type, INFIX_DIALECT_SIGNATURE);
            ok(print_status == INFIX_SUCCESS && strcmp(buffer, "{sint32,r:@Rect}") == 0,
               "Printing nested named type is correct ('%s')",
               buffer);
        }
        else
            skip(1, "Skipping nested type print test");

        infix_forward_destroy(t_ret);
        infix_forward_destroy(t_nested);
        infix_registry_destroy(registry);
    }

    subtest("Introspection of resolved named types") {
        plan(11);
        note("Verifies that the semantic name of a type is preserved after the full parse/copy/resolve pipeline.");

        infix_registry_t * registry = infix_registry_create();
        const char * defs =
            "@Point = { x: double, y: double };"
            "@Rect = { top_left: @Point, bottom_right: @Point };";
        ok(infix_register_types(registry, defs) == INFIX_SUCCESS, "Setup: Registered @Point and @Rect");

        // Test Case 1: A pointer to a named type
        const char * sig1 = "(*@Point) -> void";
        infix_forward_t * t1 = NULL;
        ok(infix_forward_create(&t1, sig1, (void *)dummy_func, registry) == INFIX_SUCCESS,
           "Trampoline for '(*@Point)->void' created");

        if (t1) {
            const infix_type * arg_type = infix_forward_get_arg_type(t1, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_POINTER, "Arg is a pointer");

            const infix_type * pointee_type = arg_type->meta.pointer_info.pointee_type;
            ok(pointee_type && pointee_type->category == INFIX_TYPE_STRUCT, "Pointee is a struct (not a named ref)");
            const char * pointee_name = infix_type_get_name(pointee_type);
            ok(pointee_name != NULL, "Pointee struct has a name field");
            ok(strcmp(pointee_name, "Point") == 0, "Pointee struct's name is 'Point'");
        }
        else
            skip(4, "Skipping introspection for *@Point");

        infix_forward_destroy(t1);

        // Test Case 2: A struct with nested named types
        const char * sig2 = "(@Rect) -> void";
        infix_forward_t * t2 = NULL;
        ok(infix_forward_create(&t2, sig2, (void *)dummy_func, registry) == INFIX_SUCCESS,
           "Trampoline for '(@Rect)->void' created");

        if (t2) {
            const infix_type * arg_type = infix_forward_get_arg_type(t2, 0);
            ok(arg_type && arg_type->category == INFIX_TYPE_STRUCT, "Arg is a struct");
            ok(strcmp(infix_type_get_name(arg_type), "Rect") == 0, "Arg struct's name is 'Rect'");

            const infix_struct_member * member = infix_type_get_member(arg_type, 0);
            ok(member && member->type && member->type->category == INFIX_TYPE_STRUCT, "Nested member is a struct");
            ok(strcmp(infix_type_get_name(member->type), "Point") == 0, "Nested member struct's name is 'Point'");
        }
        else
            skip(4, "Skipping introspection for @Rect");

        infix_forward_destroy(t2);

        infix_registry_destroy(registry);
    }
}
