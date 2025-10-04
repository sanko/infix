<<<<<<< HEAD:t/403_special_types.c
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
 * @file 403_special_types.c
 * @brief Tests FFI calls with types that have unique ABI handling rules.
 *
 * @details This suite focuses on C types that are not handled as simple
 * primitives by the target ABI. These often involve legacy hardware (like the
 * x87 FPU) or require values to be split across multiple registers.
 *
 * It covers two main categories of special types:
 * 1.  **`long double`:** On the System V x64 ABI (Linux/BSD), this is an 80-bit
 *     extended-precision type passed on the x87 FPU stack, not in SSE/XMM
 *     registers. On AArch64, it's a 128-bit type passed in a full Q-register.
 *     This test verifies these special-case mechanisms for both passing and
 *     returning the type.
 * 2.  **`__int128_t` / `__uint128_t`:** These 128-bit integers are a
 *     non-standard compiler extension (not available on MSVC). They are too
 *     large for a single GPR and are passed/returned in a register pair
 *     (e.g., RAX:RDX on SysV, X0:X1 on AArch64). This test verifies that the
 *     library correctly splits and reassembles these large integer values for
 *     both forward and reverse FFI calls.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>

// A macro to check if the current platform has a distinct `long double` type.
// On Windows and macOS, it's just an alias for `double` and is tested elsewhere.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
#define HAS_DISTINCT_LONG_DOUBLE 0
#else
#define HAS_DISTINCT_LONG_DOUBLE 1
#endif

// Native C Functions and Handlers
long double passthrough_long_double(long double v) {
    return v;
}

#if !defined(INFIX_COMPILER_MSVC)
// Use constant values to check 128-bit integer passing.
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
bool s128_callback_handler(infix_context_t * context, __int128_t val) {
    (void)context;
    note("s128_callback_handler received value.");
    return val == S128_CONSTANT;
}
#endif

TEST {
    plan(3);

    subtest("Special type: long double") {
#if HAS_DISTINCT_LONG_DOUBLE
        plan(2);
        note("Testing 80-bit or 128-bit long double on SysV/AArch64");

        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        long double input = 1.234567890123456789L;
        long double result = 0.0L;
        void * args[] = {&input};
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        cif((void *)passthrough_long_double, &result, args);

        ok(result == input, "long double passed and returned correctly");
        if (result != input)
            diag("long double value mismatch (size: %llu bytes)", (unsigned long long)sizeof(long double));
        infix_forward_destroy(trampoline);
#else
        plan(1);
        skip(1, "long double is an alias for double on this platform; tested in 001_primitives.c");
#endif
    }

    subtest("Special type: __int128_t") {
#if !defined(INFIX_COMPILER_MSVC)
        plan(6);
        infix_type * s128_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_status status;

        // Test 1: Forward call passing __int128_t
        infix_forward_t * pass_trampoline = NULL;
        status = infix_forward_create_manual(&pass_trampoline, bool_type, &s128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Pass trampoline created for __int128_t")) {
            bool pass_result = false;
            void * pass_args[] = {(void *)&S128_CONSTANT};
            ((infix_cif_func)infix_forward_get_code(pass_trampoline))((void *)check_s128, &pass_result, pass_args);
            ok(pass_result, "Forward call: __int128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(pass_trampoline);

        // Test 2: Forward call returning __int128_t
        infix_forward_t * ret_trampoline = NULL;
        status = infix_forward_create_manual(&ret_trampoline, s128_type, NULL, 0, 0);
        if (ok(status == INFIX_SUCCESS, "Return trampoline created for __int128_t")) {
            __int128_t ret_result = 0;
            ((infix_cif_func)infix_forward_get_code(ret_trampoline))((void *)return_s128, &ret_result, NULL);
            ok(ret_result == S128_CONSTANT, "Forward call: __int128_t returned correctly");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(ret_trampoline);

        // Test 3: Reverse call with __int128_t
        infix_reverse_t * rt = NULL;
        status = infix_reverse_create_manual(&rt, bool_type, &s128_type, 1, 1, (void *)s128_callback_handler, NULL);
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
        plan(1);
        skip(1, "128-bit integers are not supported on MSVC");
#endif
    }

    subtest("Special type: __uint128_t") {
#if !defined(INFIX_COMPILER_MSVC)
        plan(2);
        infix_type * u128_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, bool_type, &u128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Trampoline created for __uint128_t")) {
            bool result = false;
            void * args[] = {(void *)&U128_CONSTANT};
            ((infix_cif_func)infix_forward_get_code(trampoline))((void *)check_u128, &result, args);
            ok(result, "Forward call: __uint128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(trampoline);
#else
        plan(1);
        skip(1, "128-bit integers are not supported on MSVC");
#endif
    }
}
=======
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
 * @file 403_special_types.c
 * @brief Tests FFI calls with types that have unique ABI handling rules.
 *
 * @details This suite focuses on C types that are not handled as simple
 * primitives by the target ABI. These often involve legacy hardware (like the
 * x87 FPU) or require values to be split across multiple registers.
 *
 * It covers two main categories of special types:
 * 1.  **`long double`:** On the System V x64 ABI (Linux/BSD), this is an 80-bit
 *     extended-precision type passed on the x87 FPU stack, not in SSE/XMM
 *     registers. On AArch64, it's a 128-bit type passed in a full Q-register.
 *     This test verifies these special-case mechanisms for both passing and
 *     returning the type.
 * 2.  **`__int128_t` / `__uint128_t`:** These 128-bit integers are a
 *     non-standard compiler extension (not available on MSVC). They are too
 *     large for a single GPR and are passed/returned in a register pair
 *     (e.g., RAX:RDX on SysV, X0:X1 on AArch64). This test verifies that the
 *     library correctly splits and reassembles these large integer values for
 *     both forward and reverse FFI calls.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>

// A macro to check if the current platform has a distinct `long double` type.
// On Windows and macOS, it's just an alias for `double` and is tested elsewhere.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
#define HAS_DISTINCT_LONG_DOUBLE 0
#else
#define HAS_DISTINCT_LONG_DOUBLE 1
#endif

// Native C Functions and Handlers
long double passthrough_long_double(long double v) {
    return v;
}

#if !defined(INFIX_COMPILER_MSVC)
// Use constant values to check 128-bit integer passing.
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
bool s128_callback_handler(infix_context_t * context, __int128_t val) {
    (void)context;
    note("s128_callback_handler received value.");
    return val == S128_CONSTANT;
}
#endif

TEST {
    plan(3);

    subtest("Special type: long double") {
#if HAS_DISTINCT_LONG_DOUBLE
        plan(2);
        note("Testing 80-bit or 128-bit long double on SysV/AArch64");

        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        long double input = 1.234567890123456789L;
        long double result = 0.0L;
        void * args[] = {&input};
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        cif((void *)passthrough_long_double, &result, args);

        ok(result == input, "long double passed and returned correctly");
        if (result != input)
            diag("long double value mismatch (size: %llu bytes)", (unsigned long long)sizeof(long double));
        infix_forward_destroy(trampoline);
#else
        plan(1);
        skip(1, "long double is an alias for double on this platform; tested in 001_primitives.c");
#endif
    }

    subtest("Special type: __int128_t") {
#if !defined(INFIX_COMPILER_MSVC)
        plan(6);
        infix_type * s128_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
        infix_status status;

        // Test 1: Forward call passing __int128_t
        infix_forward_t * pass_trampoline = NULL;
        status = infix_forward_create_manual(&pass_trampoline, bool_type, &s128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Pass trampoline created for __int128_t")) {
            bool pass_result = false;
            void * pass_args[] = {(void *)&S128_CONSTANT};
            ((infix_cif_func)infix_forward_get_code(pass_trampoline))((void *)check_s128, &pass_result, pass_args);
            ok(pass_result, "Forward call: __int128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(pass_trampoline);

        // Test 2: Forward call returning __int128_t
        infix_forward_t * ret_trampoline = NULL;
        status = infix_forward_create_manual(&ret_trampoline, s128_type, NULL, 0, 0);
        if (ok(status == INFIX_SUCCESS, "Return trampoline created for __int128_t")) {
            __int128_t ret_result = 0;
            ((infix_cif_func)infix_forward_get_code(ret_trampoline))((void *)return_s128, &ret_result, NULL);
            ok(ret_result == S128_CONSTANT, "Forward call: __int128_t returned correctly");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(ret_trampoline);

        // Test 3: Reverse call with __int128_t
        infix_reverse_t * rt = NULL;
        status = infix_reverse_create_manual(&rt, bool_type, &s128_type, 1, 1, (void *)s128_callback_handler, NULL);
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
        plan(1);
        skip(1, "128-bit integers are not supported on MSVC");
#endif
    }

    subtest("Special type: __uint128_t") {
#if !defined(INFIX_COMPILER_MSVC)
        plan(2);
        infix_type * u128_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        infix_type * bool_type = infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, bool_type, &u128_type, 1, 1);
        if (ok(status == INFIX_SUCCESS, "Trampoline created for __uint128_t")) {
            bool result = false;
            void * args[] = {(void *)&U128_CONSTANT};
            ((infix_cif_func)infix_forward_get_code(trampoline))((void *)check_u128, &result, args);
            ok(result, "Forward call: __uint128_t passed correctly as argument");
        }
        else
            skip(1, "Test skipped");

        infix_forward_destroy(trampoline);
#else
        plan(1);
        skip(1, "128-bit integers are not supported on MSVC");
#endif
    }
}
>>>>>>> main:t/400_advanced/403_special_types.c
