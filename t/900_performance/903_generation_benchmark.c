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
 * @file 903_generation_benchmark.c
 * @brief A microbenchmark for FFI trampoline *generation* time.
 *
 * @details This test measures the performance of the trampoline creation process,
 * which was the target of the arena allocator optimization. It should not be run
 * as part of the regular test suite.
 *
 * It repeatedly generates and destroys a reverse trampoline for a complex
 * function signature, as this is the most allocation-heavy operation in the
 * library. The test reports the total time and the average time per generation.
 * This can be compared against a version of the library without the arena
 * allocator to quantify the performance improvement.
 */

#define DBLTAP_IMPLEMENTATION
#include "types.h"  // For Point struct
#include <double_tap.h>
#include <infix.h>
#include <time.h>  // For clock()

#define BENCHMARK_ITERATIONS 10000

// A dummy handler function to be a valid target for trampoline generation.
void benchmark_handler(Point p) {
    (void)p;
}

TEST {
    plan(1);

    diag("Trampoline Generation Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Target: generate_reverse_trampoline for Point(Point)");

    // 1. Pre-build the ffi_type outside the timing loop.
    ffi_struct_member * point_members = infix_malloc(sizeof(ffi_struct_member) * 2);
    point_members[0] =
        ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
    point_members[1] =
        ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));
    ffi_type * point_type = NULL;
    if (ffi_type_create_struct(&point_type, point_members, 2) != FFI_SUCCESS) {
        bail_out("Failed to create ffi_type for benchmark.");
    }

    // 2. Run the benchmark loop.
    clock_t start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        ffi_reverse_trampoline_t * rt = NULL;
        ffi_status status =
            generate_reverse_trampoline(&rt, point_type, &point_type, 1, 1, (void *)benchmark_handler, NULL);
        if (status != FFI_SUCCESS) {
            // Free the type before bailing out to avoid a leak.
            ffi_type_destroy(point_type);
            bail_out("Trampoline generation failed mid-benchmark on iteration %d.", i);
        }
        // Immediately free the trampoline to test the full lifecycle.
        ffi_reverse_trampoline_free(rt);
    }
    clock_t end = clock();

    // 3. Report the results.
    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double time_per_generation_us = (total_time / BENCHMARK_ITERATIONS) * 1e6;  // microseconds

    diag("Total time: %.4f s", total_time);
    diag("Average generation time: %.2f us/op", time_per_generation_us);

    pass("Benchmark completed successfully.");

    // 4. Final cleanup.
    ffi_type_destroy(point_type);
}
