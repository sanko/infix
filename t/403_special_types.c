/**
 * @file 403_special_types.c
 * @brief Unit test for FFI calls with special, non-standard, or platform-dependent primitive types.
 * @ingroup test_suite
 *
 * @details This test file validates the ABI implementation for primitive types that
 * have unique or complex calling convention rules.
 *
 * The test covers:
 *
 * - **`long double`**: This type's size and representation vary by platform. On
 *   System V x64, it's an 80-bit extended-precision float passed on the x87 FPU
 *   stack, while on Windows and AArch64, it's often an alias for `double`. This
 *   test verifies the correct handling for platforms where it is a distinct type.
 *
 * - **`__int128_t` / `__uint128_t`**: These are 128-bit integer types provided as
 *   a compiler extension by GCC and Clang (but not MSVC). They are typically
 *   passed in a pair of general-purpose registers (e.g., RDI/RSI on SysV x64).
 *   This test verifies their handling in both forward and reverse calls.
 *
 * Each test is conditionally compiled to run only on architectures and compilers
 * that support the specific type, ensuring the test suite remains portable.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <infix/infix.h>

// Check if `long double` has a distinct representation on this platform.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
#define HAS_DISTINCT_LONG_DOUBLE 0
#else
#define HAS_DISTINCT_LONG_DOUBLE 1
#endif

long double passthrough_long_double(long double v) {
    return v;
}

#if !defined(INFIX_COMPILER_MSVC)

const __int128_t S128_CONSTANT = (((__int128_t)0x12345678ABCDDCBA) << 64) | 0x1122334455667788;
const __uint128_t U128_CONSTANT = (((__uint128_t)0xFFFFFFFFFFFFFFFF) << 64) | 0xAABBCCDDEEFF0011;
bool check_s128(__int128_t val) {
    return val == S128_CONSTANT;
}
bool check_u128(__uint128_t val) {
    return val == U128_CONSTANT;
}
__int128_t return_s128(void) {
    return S128_CONSTANT;
}
bool s128_callback_handler(__int128_t val) {
    note("s128_callback_handler received value.");
    return val == S128_CONSTANT;
}
#endif

TEST {
    plan(3);

    subtest("Special type: long double") {
        plan(2);

#if HAS_DISTINCT_LONG_DOUBLE
        note("Testing 80-bit or 128-bit long double on SysV/AArch64");

        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        long double input = 1.234567890123456789L;
        long double result = 0.0L;
        void * args[] = {&input};
        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        cif((void *)passthrough_long_double, &result, args);

        ok(result == input, "long double passed and returned correctly");
        if (result != input)
            diag("long double value mismatch (size: %llu bytes)", (unsigned long long)sizeof(long double));
        infix_forward_destroy(trampoline);
#else
        skip(2, "long double is an alias for double on this platform; tested in 001_primitives.c");
#endif
    }

    subtest("Special type: __int128_t") {
        plan(6);
#if !defined(INFIX_COMPILER_MSVC)
        infix_type * s128_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_status status;

        infix_forward_t * pass_trampoline = nullptr;
        status = infix_forward_create_unbound_manual(&pass_trampoline, bool_type, &s128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Pass trampoline created for __int128_t")) {
            bool pass_result = false;
            void * pass_args[] = {(void *)&S128_CONSTANT};
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(pass_trampoline);
            cif((void *)check_s128, &pass_result, pass_args);
            ok(pass_result, "Forward call: __int128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(pass_trampoline);

        infix_forward_t * ret_trampoline = nullptr;
        status = infix_forward_create_unbound_manual(&ret_trampoline, s128_type, nullptr, 0, 0);
        if (ok(status == INFIX_SUCCESS, "Return trampoline created for __int128_t")) {
            __int128_t ret_result = 0;
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(ret_trampoline);
            cif((void *)return_s128, &ret_result, nullptr);
            ok(ret_result == S128_CONSTANT, "Forward call: __int128_t returned correctly");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(ret_trampoline);

        infix_reverse_t * rt = nullptr;
        status = infix_reverse_create_callback_manual(&rt, bool_type, &s128_type, 1, 1, (void *)s128_callback_handler);
        if (ok(status == INFIX_SUCCESS, "Reverse trampoline created for __int128_t")) {
            typedef bool (*s128_harness_fn)(__int128_t);
            s128_harness_fn harness = (s128_harness_fn)infix_reverse_get_code(rt);
            bool cb_result = harness(S128_CONSTANT);
            ok(cb_result, "Reverse call: __int128_t passed to handler correctly");
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
#else
        skip(6, "128-bit integers are not supported on MSVC");
#endif
    }

    subtest("Special type: __uint128_t") {
        plan(2);
#if !defined(INFIX_COMPILER_MSVC)
        infix_type * u128_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);

        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound_manual(&trampoline, bool_type, &u128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Trampoline created for __uint128_t")) {
            bool result = false;
            void * args[] = {(void *)&U128_CONSTANT};
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)check_u128, &result, args);
            ok(result, "Forward call: __uint128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(trampoline);
#else
        skip(2, "128-bit integers are not supported on MSVC");
#endif
    }
}
