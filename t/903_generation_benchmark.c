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
 * function signature using the manual, arena-based API. This measures the full
 * setup cost and quantifies the performance of the type system and JIT generator.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // For Point struct
#include <infix/infix.h>
#include <time.h>  // For clock()

#define BENCHMARK_ITERATIONS 10000

// A dummy handler function to be a valid target for trampoline generation.
void benchmark_handler(infix_context_t * context, Point p) {
    (void)context;
    (void)p;
}

TEST {
    plan(1);

    diag("Trampoline Generation Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Target: infix_reverse_create_manual for Point(Point) using arena API");

    // Run the benchmark loop. Each iteration is a full create/destroy cycle.
    clock_t start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        infix_arena_t * arena = infix_arena_create(1024);
        if (!arena) {
            bail_out("Arena creation failed mid-benchmark.");
        }

        // 1. Build the infix_type within the timing loop, using the arena.
        infix_struct_member * point_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        point_members[0] =
            infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
        infix_type * point_type = nullptr;
        if (infix_type_create_struct(arena, &point_type, point_members, 2) != INFIX_SUCCESS) {
            infix_arena_destroy(arena);
            bail_out("Failed to create infix_type for benchmark.");
        }

        // 2. Generate the trampoline.
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_manual(&rt, point_type, &point_type, 1, 1, (void *)benchmark_handler, nullptr);
        if (status != INFIX_SUCCESS) {
            infix_arena_destroy(arena);
            bail_out("Trampoline generation failed mid-benchmark on iteration %d.", i);
        }

        // 3. Immediately free all resources for this cycle.
        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    clock_t end = clock();

    // 4. Report the results.
    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double time_per_generation_us = (total_time / BENCHMARK_ITERATIONS) * 1e6;  // microseconds

    diag("Total time: %.4f s", total_time);
    diag("Average generation time: %.2f us/op", time_per_generation_us);

    pass("Benchmark completed successfully.");
}
