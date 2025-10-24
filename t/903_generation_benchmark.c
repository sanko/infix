/**
 * @file 903_generation_benchmark.c
 * @brief A micro-benchmark to measure the performance of trampoline generation.
 * @ingroup test_suite
 *
 * @details This is not a correctness test, but a performance benchmark. Its purpose
 * is to measure the time it takes to perform a complete create/destroy cycle for a
 * reverse trampoline. This is a key metric for applications that need to create
 * callbacks dynamically and frequently.
 *
 * The benchmark runs a tight loop that, in each iteration:
 * 1. Creates a memory arena.
 * 2. Programmatically creates a moderately complex `infix_type` for a struct.
 * 3. Calls `infix_reverse_create_callback_manual` to generate a JIT-compiled callback.
 * 4. Destroys the created trampoline.
 * 5. Destroys the arena.
 *
 * The output is the average time for one complete cycle, reported in microseconds
 * per operation (`us/op`). This metric is useful for tracking the performance of
 * the entire JIT pipeline, including type creation, ABI classification, code
 * emission, and memory management.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <time.h>

#define BENCHMARK_ITERATIONS 10000

/** @brief A dummy handler function to provide a valid function pointer for creation. */
void benchmark_handler(Point p) {
    (void)p;
}

TEST {
    plan(1);

    diag("Trampoline Generation Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Target: Full create/destroy cycle for a reverse callback with signature 'void(Point)'");

    clock_t start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        // The work inside this loop is what is being benchmarked.
        infix_arena_t * arena = infix_arena_create(1024);
        if (!arena)
            bail_out("Arena creation failed mid-benchmark.");

        // Create a moderately complex type to make the test realistic.
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

        // Create and destroy the trampoline.
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt, point_type, &point_type, 1, 1, (void *)benchmark_handler);
        if (status != INFIX_SUCCESS) {
            infix_arena_destroy(arena);
            bail_out("Trampoline generation failed mid-benchmark on iteration %d.", i);
        }

        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
    clock_t end = clock();

    // Calculate and report the results.
    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double time_per_generation_us = (total_time / BENCHMARK_ITERATIONS) * 1e6;

    diag("Total time: %.4f s", total_time);
    diag("Average generation time: %.2f us/op", time_per_generation_us);

    pass("Benchmark completed successfully.");
}
