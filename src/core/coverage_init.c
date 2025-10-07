#pragma once
/**
 * @file coverage_init.c
 * @brief Initializer to fix Clang coverage linking with static libraries.
 * @ingroup internal_core
 *
 * @internal
 * Clang's code coverage instrumentation throws `__llvm_prf_data` away because
 * it's convinced that it's unreferenced from the main executable. The result as
 * demonstrated at https://github.com/sanko/infix/actions/runs/18317837036/job/52162808854
 *
 *   clang -std=c17 -Wall -Wextra -g -O2 -pthread -I/home/runner/work/infix/infix/include
 *     -I/home/runner/work/infix/infix/src -I/home/runner/work/infix/infix/src/core
 *     -I/home/runner/work/infix/infix/src/arch/x64 -I/home/runner/work/infix/infix/src/arch/aarch64
 *     -I/home/runner/work/infix/infix/t/include -fprofile-instr-generate -fcoverage-mapping -DDBLTAP_ENABLE=1 -o
 *     t/007_introspection t/007_introspection.c build_lib/libinfix.a -fprofile-instr-generate -fcoverage-mapping -lm
 *     -pthread
 *     -Wl,-w
 *     ld: error: relocation refers to a discarded section: __llvm_prf_data
 *     >>> defined in build_lib/libinfix.a(infix.o)
 *     >>> referenced by infix.c
 *     >>>               infix.o:(__llvm_profile_init) in archive build_lib/libinfix.a
 *    clang: error: linker command failed with exit code 1 (use -v to see invocation)
 *
 * We can (I hope) work around this with the `__attribute__((constructor))`
 * attribute which will e executed by the C runtime even before `int main(...)`.
 * In the function function, we explicitly call `__llvm_profile_initialize_file()`,
 * which creates a strong reference to the profiling data and runtime, preventing the
 * linker from discarding the necessary sections.

 * See
 * https://developer.arm.com/documentation/dui0472/latest/Compiler-specific-Features/--attribute----constructor--priority-----function-attribute
 *
 * All of this is wrapped in a fence so it only compiles for clang where `INFIX_COVERAGE_BUILD` is defined.
 * @endinternal
 */

#if defined(INFIX_COMPILER_CLANG)

#if __has_feature(coverage_sanitizer)

// These are part of clang's profiling runtime, but are not in public headers.
// We must declare them to be able to reference them.
extern int __llvm_profile_runtime;
void __llvm_profile_initialize_file(void);

/**
 * @internal
 * @brief A constructor function that is run automatically before main().
 * @details This function's sole purpose is to create a reference to the Clang
 *          profiling runtime, forcing the linker to include the necessary
 *          coverage sections when linking against the static libinfix.a.
 */
__attribute__((constructor)) static void infix_coverage_init(void) {
    // The `if` condition is a standard trick. By referencing the address of
    // the __llvm_profile_runtime symbol, we ensure the linker includes the
    // profiling runtime object file. If it weren't linked for some reason,
    // this check would prevent a crash.
    if (&__llvm_profile_runtime)
        __llvm_profile_initialize_file();
}
#endif

#endif
