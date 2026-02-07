/**
 * @file 904_registry_benchmark.c
 * @brief Measures the performance of infix_register_types with many definitions.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BENCHMARK_ITERATIONS 100
#define TYPES_PER_ITERATION 1000

TEST {
    plan(1);
    diag("Type Registry Registration Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Types per iteration: %d", TYPES_PER_ITERATION);

    // Build a large registration string with many simple aliases
    size_t buf_size = TYPES_PER_ITERATION * 32;
    char * defs = malloc(buf_size);
    char * p = defs;
    for (int i = 0; i < TYPES_PER_ITERATION; ++i) {
        int len = sprintf(p, "@Type%d = sint32;", i);
        p += len;
    }

    clock_t start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        infix_registry_t * reg = infix_registry_create();
        if (!reg)
            bail_out("Registry creation failed.");

        if (infix_register_types(reg, defs) != INFIX_SUCCESS) {
            infix_registry_destroy(reg);
            bail_out("Registration failed mid-benchmark.");
        }

        infix_registry_destroy(reg);
    }
    clock_t end = clock();

    free(defs);

    double total_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double time_per_op_ms = (total_time / BENCHMARK_ITERATIONS) * 1e3;

    diag("Total time: %.4f s", total_time);
    diag("Average registration time (%d types): %.2f ms", TYPES_PER_ITERATION, time_per_op_ms);

    pass("Benchmark completed successfully.");
}
