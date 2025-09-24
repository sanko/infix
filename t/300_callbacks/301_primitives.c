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
 * @file 301_primitives.c
 * @brief Tests reverse trampolines (callbacks) with primitive type signatures.
 *
 * @details This test suite is the cornerstone for verifying the reverse FFI
 * (callback) functionality. It ensures that the library can correctly generate
 * native, callable function pointers for user-defined handlers that operate on
 * primitive C types.
 *
 * For each signature, the test performs these steps:
 * 1.  Defines a C "handler" function (e.g., `int_callback_handler`). This handler's
 *     first argument is now always `infix_context_t* context`.
 * 2.  Creates the `infix_type` definitions for the handler's public signature.
 * 3.  Calls `infix_reverse_create_manual` to create a native function pointer.
 * 4.  Defines a C "harness" function that takes a function pointer of the
 *     native type as an argument.
 * 5.  Calls the harness, passing it the generated function pointer.
 * 6.  Inside the harness, the generated function pointer is called. This triggers
 *     the JIT-compiled assembly stub, which marshals the arguments, prepends the
 *     context, and invokes the original C handler.
 * 7.  The test asserts that the value returned by the callback is correct.
 *
 * This validates the entire reverse call chain: native call -> JIT stub ->
 * internal dispatcher -> cached forward trampoline -> user C handler.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>

// Native C Handlers

/** @brief A simple callback handler that multiplies two integers. */
int int_callback_handler(infix_context_t * context, int a, int b) {
    (void)context;  // Context is unused in this stateless handler.
    note("int_callback_handler received: a=%d, b=%d", a, b);
    return a * b;
}

/** @brief A callback handler that adds two floats. */
float float_callback_handler(infix_context_t * context, float a, float b) {
    (void)context;
    note("float_callback_handler received: a=%.2f, b=%.2f", a, b);
    return a + b;
}

/** @brief A callback handler with a void return type that checks its argument. */
void void_callback_handler(infix_context_t * context, int check_val) {
    (void)context;
    note("void_callback_handler received check_val = %d", check_val);
    ok(check_val == 1337, "void(int) callback received the correct value");
}

// Native C Harness Functions
// These functions accept a native function pointer and call it, acting as the
// "native C code" that invokes the callback.

void execute_int_callback(int (*func_ptr)(int, int), int x, int y) {
    int result = func_ptr(x, y);
    ok(result == x * y, "int(int,int) callback returned the correct value");
}

void execute_float_callback(float (*func_ptr)(float, float), float a, float b) {
    float result = func_ptr(a, b);
    ok(fabs(result - (a + b)) < 0.01, "float(float, float) callback returned correct sum");
}

void execute_void_callback(void (*func_ptr)(int), int val) {
    func_ptr(val);  // The assertion is inside the handler itself.
}

TEST {
    plan(3);

    subtest("Callback with signature: int(int, int)") {
        plan(2);  // One for trampoline creation, one for the result check.

        // 1. Define the FFI signature.
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};

        // 2. Generate the reverse trampoline.
        infix_reverse_t * rt = NULL;
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 2, 2, (void *)int_callback_handler, NULL);
        ok(status == INFIX_SUCCESS && rt && infix_reverse_get_code(rt), "Reverse trampoline created");

        // 3. Cast the executable code to the correct native type and execute.
        if (rt && infix_reverse_get_code(rt))
            execute_int_callback((int (*)(int, int))infix_reverse_get_code(rt), 7, 6);
        else
            skip(1, "Test skipped due to creation failure");

        infix_reverse_destroy(rt);
    }

    subtest("Callback with signature: float(float, float)") {
        plan(2);

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};

        infix_reverse_t * rt = NULL;
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 2, 2, (void *)float_callback_handler, NULL);
        ok(status == INFIX_SUCCESS && rt && infix_reverse_get_code(rt), "Reverse trampoline created");

        if (rt && infix_reverse_get_code(rt))
            execute_float_callback((float (*)(float, float))infix_reverse_get_code(rt), 10.5f, 20.0f);
        else
            skip(1, "Test skipped due to creation failure");

        infix_reverse_destroy(rt);
    }

    subtest("Callback with signature: void(int)") {
        plan(2);  // One for creation, one for the check inside the handler.

        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};

        infix_reverse_t * rt = NULL;
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 1, 1, (void *)void_callback_handler, NULL);
        ok(status == INFIX_SUCCESS && rt && infix_reverse_get_code(rt), "Reverse trampoline created");

        if (rt && infix_reverse_get_code(rt))
            execute_void_callback((void (*)(int))infix_reverse_get_code(rt), 1337);
        else
            skip(1, "Test skipped due to creation failure");

        infix_reverse_destroy(rt);
    }
}
