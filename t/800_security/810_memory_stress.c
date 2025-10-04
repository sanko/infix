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
 * @file 810_memory_stress.c
 * @brief A stress test for detecting memory leaks in the infix FFI library.
 *
 * @details This test is designed to be run under a memory analysis tool like
 * Valgrind or AddressSanitizer. Its purpose is not to verify functional
 * correctness, but to expose memory leaks by performing a large number of
 * allocations and deallocations of all major dynamic FFI objects.
 *
 * In a tight loop, the test performs the following cycle:
 * 1.  Creates a memory arena.
 * 2.  Builds a deeply nested, complex `infix_type` graph within the arena.
 * 3.  Generates a forward trampoline using this complex type.
 * 4.  Generates a reverse trampoline (callback) using the same type.
 * 5.  Frees all resources created in that cycle, including the arena itself.
 *
 * The test is considered successful if it completes without crashing and the
 * memory analysis tool reports ZERO memory leaks.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // Test-specific type definitions
#include <infix/infix.h>
#include <stddef.h>  // For offsetof

// The number of full create/destroy cycles to run.
#define STRESS_ITERATIONS 5000

// A complex struct to create a deeply nested infix_type.
typedef struct {
    uint64_t object_id;
    Point elements[10];
} StressObject;

// Dummy C functions to act as valid targets for the FFI calls
void dummy_stress_func_fwd(StressObject obj) {
    (void)obj;
}
void dummy_stress_handler_rev(infix_context_t * context, StressObject obj) {
    (void)context;
    (void)obj;
}


TEST {
    plan(1);

    subtest("Memory leak stress test (happy path)") {
        plan(STRESS_ITERATIONS);
        note("Running %d create/destroy cycles. Success requires a clean Valgrind/ASan report.", STRESS_ITERATIONS);

        for (int i = 0; i < STRESS_ITERATIONS; ++i) {
            // 1. Create an arena for this cycle's type definitions.
            infix_arena_t * arena = infix_arena_create(8192);
            if (!arena) {
                bail_out("Failed to create arena in iteration %d", i);
            }

            // 2. Dynamically Create the Complex FFI Type (Deeply Nested) using the arena.

            // Level 1: Point struct
            infix_struct_member * point_members =
                infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
            point_members[0] = infix_struct_member_create(
                "x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
            point_members[1] = infix_struct_member_create(
                "y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
            infix_type * point_type = NULL;
            if (infix_type_create_struct(arena, &point_type, point_members, 2) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create point_type");
            }

            // Level 2: Array of Point
            infix_type * array_type = NULL;
            if (infix_type_create_array(arena, &array_type, point_type, 10) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create array_type");
            }

            // Level 3 (Top): StressObject (contains array)
            infix_struct_member * object_members =
                infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
            object_members[0] = infix_struct_member_create(
                "object_id", infix_type_create_primitive(INFIX_PRIMITIVE_UINT64), offsetof(StressObject, object_id));
            object_members[1] = infix_struct_member_create("elements", array_type, offsetof(StressObject, elements));
            infix_type * object_type = NULL;
            if (infix_type_create_struct(arena, &object_type, object_members, 2) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create object_type");
            }

            // 3. Generate and Destroy a Forward Trampoline
            infix_forward_t * forward_trampoline = NULL;
            if (infix_forward_create_manual(&forward_trampoline, infix_type_create_void(), &object_type, 1, 1) !=
                INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to generate forward trampoline");
            }
            infix_forward_destroy(forward_trampoline);

            // 4. Generate and Destroy a Reverse Trampoline
            infix_reverse_t * reverse_trampoline = NULL;
            if (infix_reverse_create_manual(&reverse_trampoline,
                                            infix_type_create_void(),
                                            &object_type,
                                            1,
                                            1,
                                            (void *)dummy_stress_handler_rev,
                                            NULL) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to generate reverse trampoline");
            }
            infix_reverse_destroy(reverse_trampoline);

            // 5. Destroy the arena, cleaning up the entire type graph at once.
            infix_arena_destroy(arena);

            pass("Iteration %d completed", i + 1);
        }
    }
}
