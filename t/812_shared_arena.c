/**
 * @file 812_shared_arena.c
 * @brief Unit test for advanced arena-based memory management features.
 * @ingroup test_suite
 *
 * @details This test validates two important aspects of the `infix` memory model.
 * First, it ensures that the internal arena for a default type registry can
 * dynamically grow to handle a large number of definitions, preventing allocation
 * failures.
 *
 * Second, it verifies the "shared arena" optimization. When a registry and
 * trampolines are created in a user-provided arena, this test confirms that pointers
 * to named types are shared (rather than deep-copied) to save memory. A control
 * test ensures that the standard API without a shared arena maintains its safe,
 * deep-copying behavior.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdlib.h>  // For malloc/free
void dummy_func_for_test(void) {}
TEST {
    plan(3);
    subtest("Registry arena is now growable") {
        plan(1);
        note("Verifies the registry arena can grow beyond its initial size.");
        infix_registry_t * registry = infix_registry_create();  // Uses a default initial size.
        // Allocate the large definition string on the heap to avoid stack overflow.
        size_t num_defs = 400;
        size_t required_size = num_defs * 80;  // A generous estimate
        char * large_def = malloc(required_size);
        if (!large_def)
            bail_out("Failed to allocate memory for large definition string.");
        char * p = large_def;
        for (size_t i = 0; i < num_defs; ++i)
            p += sprintf(p, "@Type%llu = { a: int, b: int, c: int, d: int };", (unsigned long long)i);
        // This call should now succeed because the arena can grow.
        infix_status status = infix_register_types(registry, large_def);
        ok(status == INFIX_SUCCESS, "Successfully registered a large number of types without allocation failure");
        free(large_def);
        infix_registry_destroy(registry);
    }
    subtest("Shared Arena: Named types are shared via pointers") {
        plan(5);
        note("Verifies that when a shared arena is used, named types are not deep-copied.");
        infix_arena_t * shared_arena = infix_arena_create(65536);
        infix_registry_t * registry = infix_registry_create_in_arena(shared_arena);
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS, "Registered @Point");
        infix_forward_t *t1 = NULL, *t2 = NULL;
        ok(infix_forward_create_in_arena(&t1, shared_arena, "(*@Point)->void", (void *)dummy_func_for_test, registry) ==
               INFIX_SUCCESS,
           "Created t1 in shared arena");
        ok(infix_forward_create_in_arena(
               &t2, shared_arena, "(*@Point, *@Point)->void", (void *)dummy_func_for_test, registry) == INFIX_SUCCESS,
           "Created t2 in shared arena");
        if (t1 && t2) {
            const infix_type * point_from_t1 = infix_forward_get_arg_type(t1, 0)->meta.pointer_info.pointee_type;
            const infix_type * point_from_t2 = infix_forward_get_arg_type(t2, 0)->meta.pointer_info.pointee_type;
            ok(point_from_t1 && point_from_t2, "Resolved @Point types are not null");
            ok(point_from_t1 == point_from_t2, "Pointers to @Point type are identical, proving sharing");
        }
        else
            skip(2, "Introspection checks skipped.");
        infix_forward_destroy(t1);
        infix_forward_destroy(t2);
        infix_registry_destroy(registry);
        infix_arena_destroy(shared_arena);
    }
    subtest("Default Behavior: Named types are deep-copied") {
        plan(4);
        note("Verifies that the default API continues to use safe deep-copying.");
        infix_registry_t * registry = infix_registry_create();
        ok(infix_register_types(registry, "@Point = { x: double, y: double };") == INFIX_SUCCESS, "Registered @Point");
        infix_forward_t * t1 = NULL;
        ok(infix_forward_create(&t1, "(*@Point)->void", (void *)dummy_func_for_test, registry) == INFIX_SUCCESS,
           "Trampoline created with default API");
        if (t1) {
            const infix_type * canonical_point = infix_registry_lookup_type(registry, "Point");
            const infix_type * copied_point = infix_forward_get_arg_type(t1, 0)->meta.pointer_info.pointee_type;
            ok(canonical_point && copied_point, "Canonical and copied types are not null");
            ok(canonical_point != copied_point, "Pointers to @Point type are different, proving deep-copy");
        }
        else
            skip(2, "Introspection checks skipped.");
        infix_forward_destroy(t1);
        infix_registry_destroy(registry);
    }
}
