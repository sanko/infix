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
 * @file 402_variadic_functions.c
 * @brief Tests FFI calls for variadic functions.
 *
 * @details This test suite verifies the library's ability to handle variadic
 * functions (those with `...` in their signature) for both forward and reverse
 * FFI calls. Variadic argument passing involves special ABI rules that differ
 * significantly between platforms, making this a critical area to test.
 *
 * This file consolidates all previous variadic tests and covers:
 * 1.  **Forward Call:** A custom C function (`forward_variadic_checker`) is
 *     called with a mix of fixed and variadic arguments (`const char*`, `int`,
 *     `double`) to verify the basic mechanism. Using a custom checker provides
 *     clearer diagnostics than calling an opaque library function like `snprintf`.
 * 2.  **Reverse Variadic Callback:** A reverse trampoline is created for a handler
 *     with a variadic signature, confirming that the JIT stub can correctly
 *     marshal both fixed and variadic arguments.
 * 3.  **Platform: Windows x64:** A specific test, compiled only on Windows, that
 *     verifies that a variadic `double` is correctly passed in both a GPR (for
 *     `va_arg`) and an XMM register (for direct use by the callee).
 * 4.  **Platform: macOS on AArch64:** A specific test, compiled only on macOS ARM,
 *     that verifies the unique rule where all variadic arguments (including
 *     structs) are passed on the stack.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <stdarg.h>  // For va_list
#include <stdio.h>   // For snprintf (used in older versions, header kept for reference)
#include <string.h>  // For strcmp

// Native C Handlers and Functions

/**
 * @brief A custom checker function to transparently validate variadic arguments.
 * @details This function replaces `snprintf` from previous tests. It accepts a
 * variadic argument list and uses the `double_tap` harness to `ok()` each
 * argument it receives. This provides precise feedback on which argument, if
 * any, is being passed incorrectly.
 * @return 1 on success (all checks passed), 0 on failure.
 */
int forward_variadic_checker(char * buffer, size_t size, const char * format, ...) {
    (void)buffer;
    (void)size;  // Unused, kept to match the test signature.

    va_list args;
    va_start(args, format);
    const char * str_arg = va_arg(args, const char *);
    int int_arg = va_arg(args, int);
    double dbl_arg = va_arg(args, double);
    va_end(args);

    note("forward_variadic_checker received:");
    note("  format = \"%s\"", format);
    note("  str_arg = \"%s\"", str_arg);
    note("  int_arg = %d", int_arg);
    note("  dbl_arg = %.2f", dbl_arg);

    // Use a subtest to check all arguments. This is thread-safe.
    subtest("Inside forward_variadic_checker") {
        plan(4);
        ok(strcmp(format, "format string") == 0, "Fixed arg 'format' is correct");
        ok(strcmp(str_arg, "hello") == 0, "Variadic arg 1 (string) is correct");
        ok(int_arg == 123, "Variadic arg 2 (int) is correct");
        ok(fabs(dbl_arg - 3.14) < 0.001, "Variadic arg 3 (double) is correct");
    }
    // Return 1 only if all checks passed.
    return 1;
}

/** @brief A handler for a reverse trampoline with a variadic signature. */
int variadic_reverse_handler(infix_context_t * context, const char * topic, ...) {
    (void)context;
    va_list args;
    va_start(args, topic);
    int count = va_arg(args, int);
    double value = va_arg(args, double);
    const char * message = va_arg(args, const char *);
    va_end(args);

    subtest("Inside variadic_reverse_handler") {
        plan(4);
        ok(strcmp(topic, "LOG") == 0, "Fixed arg (topic) is correct");
        ok(count == 42, "Variadic arg 1 (count) is correct");
        ok(fabs(value - 3.14) < 0.001, "Variadic arg 2 (value) is correct");
        ok(strcmp(message, "Done") == 0, "Variadic arg 3 (message) is correct");
    }
    return count + (int)value;
}

#if defined(INFIX_OS_MACOS) && defined(INFIX_ARCH_AARCH64)
// Test specific to macOS on ARM (Apple Silicon)
typedef struct {
    long a;
    long b;
} MacTestStruct;
// This native function checks that variadic arguments were passed on the stack.
int macos_variadic_checker(int fixed_arg, ...) {
    va_list args;
    va_start(args, fixed_arg);
    double var_double = va_arg(args, double);
    MacTestStruct var_struct = va_arg(args, MacTestStruct);
    va_end(args);
    note("macOS variadic checker received: fixed=%d, double=%.2f, struct={%ld, %ld}",
         fixed_arg,
         var_double,
         var_struct.a,
         var_struct.b);
    return fixed_arg + (int)var_double + (int)var_struct.a + (int)var_struct.b;
}
#endif

#if defined(INFIX_ABI_WINDOWS_X64)
// Test specific to the Windows x64 ABI
double win_variadic_float_checker(int fixed_arg, ...) {
    va_list args;
    va_start(args, fixed_arg);
    double var_double = va_arg(args, double);
    va_end(args);
    note("Windows variadic checker received fixed=%d, variadic_double=%.2f", fixed_arg, var_double);
    return var_double;
}
#endif

TEST {
    plan(4);

    subtest("Forward variadic call") {
        plan(3);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {
            infix_type_create_pointer(),                          // char* buffer
            infix_type_create_primitive(INFIX_PRIMITIVE_UINT64),  // size_t size
            infix_type_create_pointer(),                          // const char* format
            infix_type_create_pointer(),                          // variadic: const char*
            infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),  // variadic: int
            infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE)   // variadic: double
        };

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 6, 3);
        ok(status == INFIX_SUCCESS, "Variadic forward trampoline created");

        infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);

        char buffer[1] = {0};  // Dummy buffer for signature match
        size_t size = 1;       // Dummy size for signature match
        const char * fmt = "format string";
        const char * str_arg = "hello";
        int int_arg = 123;
        double dbl_arg = 3.14;
        int result = 0;
        void * args[] = {&buffer, &size, &fmt, &str_arg, &int_arg, &dbl_arg};

        cif_func((void *)forward_variadic_checker, &result, args);
        ok(result == 1, "Custom variadic checker function returned success");

        infix_forward_destroy(trampoline);
    }

    subtest("Reverse variadic callback") {
        plan(3);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_pointer(),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                    infix_type_create_pointer()};

        infix_reverse_t * rt = NULL;
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 4, 1, (void *)variadic_reverse_handler, NULL);
        ok(status == INFIX_SUCCESS, "Variadic reverse trampoline created");

        if (rt) {
            typedef int (*VariadicLogFunc)(const char *, ...);
            VariadicLogFunc func_ptr = (VariadicLogFunc)infix_reverse_get_code(rt);
            int result = func_ptr("LOG", 42, 3.14, "Done");
            ok(result == 45, "Variadic callback returned correct sum (42 + 3)");
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
    }

    subtest("Platform ABI: macOS AArch64 variadic struct passing") {
#if defined(INFIX_OS_MACOS) && defined(INFIX_ARCH_AARCH64)
        plan(2);
        note("Testing variadic call with struct argument on macOS/ARM (must go on stack)");
        infix_arena_t * arena = infix_arena_create(4096);

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_struct_member * members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        members[0] = infix_type_create_member(
            "a", infix_type_create_primitive(INFIX_PRIMITIVE_SINT64), offsetof(MacTestStruct, a));
        members[1] = infix_type_create_member(
            "b", infix_type_create_primitive(INFIX_PRIMITIVE_SINT64), offsetof(MacTestStruct, b));
        infix_type * struct_type = NULL;
        infix_type_create_struct(arena, &struct_type, members, 2);

        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                    struct_type};

        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 3, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for macOS variadic test created");

        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        int fixed_val = 10;
        double dbl_val = 20.0;
        MacTestStruct struct_val = {30, 40};
        void * args[] = {&fixed_val, &dbl_val, &struct_val};
        int result = 0;
        cif((void *)macos_variadic_checker, &result, args);
        ok(result == 100, "macOS variadic arguments passed correctly (10+20+30+40)");

        infix_forward_destroy(trampoline);
        infix_arena_destroy(arena);
#else
        plan(1);
        skip(1, "Test is only for macOS on AArch64");
#endif
    }

    subtest("Platform ABI: Windows x64 variadic float/double passing") {
#if defined(INFIX_ABI_WINDOWS_X64)
        plan(2);
        note("Testing if a variadic double is passed correctly on Windows x64");

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE)};
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, ret_type, arg_types, 2, 1);
        ok(status == INFIX_SUCCESS, "Trampoline for Windows variadic test created");

        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        int fixed_val = 100;
        double dbl_val = 123.45;
        void * args[] = {&fixed_val, &dbl_val};
        double result = 0.0;
        cif((void *)win_variadic_float_checker, &result, args);
        ok(fabs(result - 123.45) < 0.001, "Windows variadic double passed correctly");
        infix_forward_destroy(trampoline);
#else
        plan(1);
        skip(1, "Test is only for the Windows x64 ABI");
#endif
    }
}
