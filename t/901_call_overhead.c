/**
 * @file 901_call_overhead.c
 * @brief A micro-benchmark to measure the performance overhead of an FFI call.
 * @ingroup test_suite
 *
 * @details This is not a correctness test, but a performance benchmark. Its purpose
 * is to quantify the "cost" of making a C function call through an `infix` trampoline
 * compared to a direct C call.
 *
 * The benchmark measures and reports the average time per call for:
 *
 * 1.  **Direct Call:** A tight loop of direct C-to-C function calls. This serves
 *     as the baseline performance.
 *
 * 2.  **`infix` (Unbound):** A loop calling the same C function via an unbound
 *     forward trampoline. This measures the overhead of the most flexible FFI path.
 *
 * 3.  **`infix` (Bound):** A loop calling the same C function via a bound forward
 *     trampoline. This measures the overhead of the highest-performance FFI path.
 *
 * 4.  **dyncall (Optional):** If compiled with `DYNCALL_BENCHMARK`, it also measures
 *     the performance of the popular `dyncall` library for the same function call,
 *     providing a useful point of comparison against another FFI library.
 *
 * The output is a "nanoseconds per call" metric, which helps quantify the FFI
 * overhead and track performance regressions or improvements over time.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <time.h>

// If this macro is defined (e.g., via a compiler flag), the benchmark will
// also include a comparison against the dyncall library.
#ifdef DYNCALL_BENCHMARK
#include <dyncall.h>
#endif

/** @brief The simple C function used as the target for all benchmarked calls. */
int add_for_benchmark(int a, int b) {
    return a + b;
}

TEST {
    plan(1);

    const int BENCHMARK_ITERATIONS = 10000000;

    // Use a volatile accumulator to prevent the compiler from optimizing away the function calls.
    volatile int accumulator = 0;
    clock_t start, end;

    diag("infix Call Overhead Benchmark");
    diag("Iterations: %d", BENCHMARK_ITERATIONS);
    diag("Target function: int(int, int)");

    // 1. Baseline: Direct C Call
    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        accumulator += add_for_benchmark(i, i + 1);
    }
    end = clock();
    double direct_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double direct_ns_per_call = (direct_time / BENCHMARK_ITERATIONS) * 1e9;
    diag("Direct Call Time: %.4f s (%.2f ns/call)", direct_time, direct_ns_per_call);

    // 2. `infix` Unbound Trampoline
    infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
    infix_forward_t * unbound_t = nullptr;
    if (infix_forward_create_unbound_manual(&unbound_t, ret_type, arg_types, 2, 2) != INFIX_SUCCESS)
        bail_out("Failed to create unbound trampoline");
    infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);

    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        int a = i, b = i + 1, result;
        void * args[] = {&a, &b};
        unbound_cif((void *)add_for_benchmark, &result, args);
        accumulator += result;
    }
    end = clock();
    double unbound_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double unbound_ns = (unbound_time / BENCHMARK_ITERATIONS) * 1e9;
    diag("infix (Unbound):    %.4f s (%.2f ns/call) -> Overhead: ~%.2f ns",
         unbound_time,
         unbound_ns,
         unbound_ns - direct_ns_per_call);

    // 3. `infix` Bound Trampoline
    infix_forward_t * bound_t = nullptr;
    if (infix_forward_create_manual(&bound_t, ret_type, arg_types, 2, 2, (void *)add_for_benchmark) != INFIX_SUCCESS)
        bail_out("Failed to create bound trampoline");
    infix_cif_func bound_cif = infix_forward_get_code(bound_t);

    start = clock();
    for (int i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        int a = i, b = i + 1, result;
        void * args[] = {&a, &b};
        bound_cif(&result, args);
        accumulator += result;
    }
    end = clock();
    double bound_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double bound_ns = (bound_time / BENCHMARK_ITERATIONS) * 1e9;
    diag("infix (Bound):      %.4f s (%.2f ns/call) -> Overhead: ~%.2f ns",
         bound_time,
         bound_ns,
         bound_ns - direct_ns_per_call);

    infix_forward_destroy(unbound_t);
    infix_forward_destroy(bound_t);

    // 4. (Optional) dyncall Comparison
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
    diag("dyncall:            %.4f s (%.2f ns/call) -> Overhead: ~%.2f ns",
         dyncall_time,
         dyncall_ns_per_call,
         dyncall_overhead_ns);
    dcFree(vm);
#else
    note("dyncall benchmarking was not enabled.");
#endif

    pass("Benchmark completed (final accumulator value: %d)", accumulator);
}
