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
 * 1.  Creates a deeply nested, complex `ffi_type` (a struct containing an
 *     array of structs, which in turn contain other structs). This exercises
 *     the `ffi_type_create_*` and `ffi_type_destroy` logic.
 * 2.  Generates a forward trampoline using this complex type.
 * 3.  Generates a reverse trampoline (callback) using the same type. This is
 *     the most allocation-heavy operation in the library.
 * 4.  Frees all resources created in that cycle.
 *
 * The test is considered successful if it completes without crashing and the
 * memory analysis tool reports ZERO memory leaks.
 */

#define DBLTAP_IMPLEMENTATION
#include "types.h"  // Test-specific type definitions
#include <double_tap.h>
#include <infix.h>
#include <stddef.h>  // For offsetof

// The number of full create/destroy cycles to run.
// This should be high enough to make small leaks detectable by a profiler.
#define STRESS_ITERATIONS 5000

// Dummy C functions to act as valid targets for the FFI calls

// A complex struct to create a deeply nested ffi_type.
typedef struct {
    uint64_t object_id;
    Point elements[10];
} StressObject;

void dummy_stress_func_fwd(StressObject obj) {
    (void)obj;
}
void dummy_stress_handler_rev(StressObject obj) {
    (void)obj;
}


TEST {
    plan(1);

    subtest("Memory leak stress test (happy path)") {
        plan(STRESS_ITERATIONS);
        note("Running %d create/destroy cycles. Success requires a clean Valgrind/ASan report.", STRESS_ITERATIONS);

        for (int i = 0; i < STRESS_ITERATIONS; ++i) {
            // 1. Dynamically Create the Complex FFI Type (Deeply Nested)

            // Level 1: Point struct
            ffi_struct_member * point_members = malloc(sizeof(ffi_struct_member) * 2);
            if (!point_members)
                bail_out("Failed to allocate memory for point_members");
            point_members[0] =
                ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
            point_members[1] =
                ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));
            ffi_type * point_type = NULL;
            if (ffi_type_create_struct(&point_type, point_members, 2) != FFI_SUCCESS) {
                free(point_members);  // Must manually free on failure
                bail_out("Failed to create point_type");
            }

            // Level 2: Array of Point
            ffi_type * array_type = NULL;
            if (ffi_type_create_array(&array_type, point_type, 10) != FFI_SUCCESS) {
                ffi_type_destroy(point_type);  // Must clean up successful sub-allocations
                bail_out("Failed to create array_type");
            }

            // Level 3 (Top): StressObject (contains array)
            ffi_struct_member * object_members = malloc(sizeof(ffi_struct_member) * 2);
            if (!object_members)
                bail_out("Failed to allocate memory for object_members");
            object_members[0] = ffi_struct_member_create(
                "object_id", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64), offsetof(StressObject, object_id));
            object_members[1] = ffi_struct_member_create("elements", array_type, offsetof(StressObject, elements));
            ffi_type * object_type = NULL;
            if (ffi_type_create_struct(&object_type, object_members, 2) != FFI_SUCCESS) {
                ffi_type_destroy(array_type);  // Clean up sub-allocations
                free(object_members);
                bail_out("Failed to create object_type");
            }

            // 2. Generate and Destroy a Forward Trampoline
            ffi_trampoline_t * forward_trampoline = NULL;
            if (generate_forward_trampoline(&forward_trampoline, ffi_type_create_void(), &object_type, 1, 1) !=
                FFI_SUCCESS) {
                ffi_type_destroy(object_type);  // Clean up type before bailing
                bail_out("Failed to generate forward trampoline");
            }
            ffi_trampoline_free(forward_trampoline);

            // 3. Generate and Destroy a Reverse Trampoline
            ffi_reverse_trampoline_t * reverse_trampoline = NULL;
            if (generate_reverse_trampoline(&reverse_trampoline,
                                            ffi_type_create_void(),
                                            &object_type,
                                            1,
                                            1,
                                            (void *)dummy_stress_handler_rev,
                                            NULL) != FFI_SUCCESS) {
                ffi_type_destroy(object_type);  // Clean up type before bailing
                bail_out("Failed to generate reverse trampoline");
            }
            ffi_reverse_trampoline_free(reverse_trampoline);

            // 4. Destroy the Top-Level Dynamic Type
            // This single call should recursively free all nested types (the array, the inner struct, and all member
            // arrays).
            ffi_type_destroy(object_type);

            // If an iteration completes, we mark it as a pass.
            // The real result is the absence of leak reports from the memory checker.
            pass("Iteration %d completed", i + 1);
        }
    }
}
