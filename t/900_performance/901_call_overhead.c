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
 * @file 901_call_overhead.c
 * @brief A microbenchmark to measure the performance overhead of an FFI call.
 *
 * @details This is a non-functional test designed to measure the raw speed of
 * the generated FFI trampolines. It should not be run as part of the standard
 * test suite, but rather invoked explicitly when performance analysis is needed.
 *
 * The test operates in two phases:
 * 1.  **Baseline (Direct Call):** It measures the time taken to execute millions
 *     of direct, native C function calls to a simple `int add(int, int)` function.
 *     This establishes a baseline performance measurement.
 * 2.  **FFI Call:** It then generates a forward trampoline for the same function and
 *     measures the time taken to execute the same number of calls through the FFI.
 *
 * The difference between these two measurements, divided by the number of
 * iterations, gives the average per-call overhead of the trampoline mechanism in
 * nanoseconds. This is a critical metric for performance-sensitive applications.
 *
 * An optional comparison against the `dyncall` library can be enabled by defining
 * the `DYNCALL_BENCHMARK` macro at compile time.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <time.h>  // For clock()

#ifdef DYNCALL_BENCHMARK
#include <dyncall.h>
#endif

// A simple, fast function to minimize the overhead of the target itself.
int add_for_benchmark(int a, int b) {
    return a + b;
}

TEST {
    plan(1);
    // Use a large number of iterations to get a stable average and minimize
    // the impact of clock resolution.
    const int BENCHMARK_ITERATIONS = 10000000;
    // Use volatile to prevent the compiler from optimizing away the loop bodies.
    volatile int accumulator = 0;
    clock_t start, end;

    diag("FFI Call Overhead Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Target function: int(int, int)");

    // Phase 1: Direct Call Baseline
    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        accumulator += add_for_benchmark(i, i + 1);
    }
    end = clock();
    double direct_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double direct_ns_per_call = (direct_time / BENCHMARK_ITERATIONS) * 1e9;
    diag("Direct Call Time: %.4f s (%.2f ns/call)", direct_time, direct_ns_per_call);

    // Phase 2: infix Trampoline Call
    ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type * arg_types[] = {ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),
                              ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)};
    ffi_trampoline_t * trampoline = NULL;
    ffi_status status = generate_forward_trampoline(&trampoline, ret_type, arg_types, 2, 2);
    if (status != FFI_SUCCESS) {
        bail_out("Failed to create trampoline for benchmark");
    }
    ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);

    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        int a = i, b = i + 1, result;
        void * args[] = {&a, &b};
        cif_func((void *)add_for_benchmark, &result, args);
        accumulator += result;
    }
    end = clock();
    double trampoline_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double trampoline_ns_per_call = (trampoline_time / BENCHMARK_ITERATIONS) * 1e9;
    double infix_overhead_ns = trampoline_ns_per_call - direct_ns_per_call;
    diag("infix Time:       %.4f s (%.2f ns/call)", trampoline_time, trampoline_ns_per_call);
    diag("infix Overhead:  ~%.2f ns/call", infix_overhead_ns);
    ffi_trampoline_free(trampoline);

    // Phase 3: Optional Dyncall Comparison
#ifdef DYNCALL_BENCHMARK
    DCCallVM * vm = dcNewCallVM(4096);
    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        dcReset(vm);
        dcArgInt(vm, i);
        dcArgInt(vm, i + 1);
        accumulator += dcCallInt(vm, (DCpointer)&add_for_benchmark);
    }
    end = clock();
    double dyncall_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double dyncall_ns_per_call = (dyncall_time / BENCHMARK_ITERATIONS) * 1e9;
    double dyncall_overhead_ns = dyncall_ns_per_call - direct_ns_per_call;
    diag("dyncall Time:     %.4f s (%.2f ns/call)", dyncall_time, dyncall_ns_per_call);
    diag("dyncall Overhead:~%.2f ns/call", dyncall_overhead_ns);
    dcFree(vm);
#else
    note("dyncall benchmarking was not enabled.");
#endif

    // The single 'pass' here is just to satisfy the test harness.
    // The real result is the diagnostic output printed above.
    pass("Benchmark completed (final accumulator value: %d)", accumulator);
}
