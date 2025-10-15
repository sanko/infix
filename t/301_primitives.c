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
 * 1.  Defines a C "handler" function (e.g., `int_callback_handler`).
 * 2.  Creates the `infix_type` definitions for the handler's public signature.
 * 3.  Calls the appropriate `infix_reverse_create_*_manual` function to create a native function pointer.
 * 4.  Defines a C "harness" function that takes a function pointer of the
 *     native type as an argument.
 * 5.  Calls the harness, passing it the generated function pointer.
 * 6.  Inside the harness, the generated function pointer is called. This triggers
 *     the JIT-compiled assembly stub, which marshals the arguments and invokes
 *     the original C handler via the correct path (type-safe or generic).
 * 7.  The test asserts that the value returned by the callback is correct.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>

// Native C Handlers (Type-Safe "Callback" Style)

/** @brief A simple callback handler that multiplies two integers. */
int int_callback_handler(int a, int b) {
    note("int_callback_handler received: a=%d, b=%d", a, b);
    return a * b;
}

/** @brief A callback handler that adds two floats. */
float float_callback_handler(float a, float b) {
    note("float_callback_handler received: a=%.2f, b=%.2f", a, b);
    return a + b;
}

/** @brief A callback handler with a void return type that checks its argument. */
void void_callback_handler(int check_val) {
    note("void_callback_handler received check_val = %d", check_val);
    ok(check_val == 1337, "void(int) callback received the correct value");
}


// Generic Handlers ("Closure" Style)

void int_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    int a = *(int *)args[0];
    int b = *(int *)args[1];
    int result = a * b;
    memcpy(return_value, &result, sizeof(int));
}

void float_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    float a = *(float *)args[0];
    float b = *(float *)args[1];
    float result = a + b;
    memcpy(return_value, &result, sizeof(float));
}

void void_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    (void)return_value;
    int check_val = *(int *)args[0];
    ok(check_val == 1337, "void(int) closure received the correct value");
}


// Native C Harness Functions
// These functions accept a native function pointer and call it, acting as the
// "native C code" that invokes the callback.

void execute_int_callback(int (*func_ptr)(int, int), int x, int y) {
    int result = func_ptr(x, y);
    ok(result == x * y, "callback/closure returned the correct value");
}

void execute_float_callback(float (*func_ptr)(float, float), float a, float b) {
    float result = func_ptr(a, b);
    ok(fabs(result - (a + b)) < 0.01, "callback/closure returned correct sum");
}

void execute_void_callback(void (*func_ptr)(int), int val) {
    func_ptr(val);  // The assertion is inside the handler itself.
}

TEST {
    plan(3);

    subtest("Callback with signature: int(int, int)") {
        plan(4);

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        typedef int (*IntCallbackFunc)(int, int);

        // Test Type-Safe Callback
        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 2, 2, (void *)int_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_int_callback((IntCallbackFunc)infix_reverse_get_code(rt_cb), 7, 6);
        else
            skip(1, "Test skipped");

        // Test Generic Closure
        infix_reverse_t * rt_cl = nullptr;
        status = infix_reverse_create_closure_manual(&rt_cl, ret_type, arg_types, 2, 2, int_closure_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Generic closure created");
        if (rt_cl)
            execute_int_callback((IntCallbackFunc)infix_reverse_get_code(rt_cl), 8, 8);
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt_cb);
        infix_reverse_destroy(rt_cl);
    }

    subtest("Callback with signature: float(float, float)") {
        plan(4);

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};
        typedef float (*FloatCallbackFunc)(float, float);

        // Test Type-Safe Callback
        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 2, 2, (void *)float_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_float_callback((FloatCallbackFunc)infix_reverse_get_code(rt_cb), 10.5f, 20.0f);
        else
            skip(1, "Test skipped");

        // Test Generic Closure
        infix_reverse_t * rt_cl = nullptr;
        status = infix_reverse_create_closure_manual(&rt_cl, ret_type, arg_types, 2, 2, float_closure_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Generic closure created");
        if (rt_cl)
            execute_float_callback((FloatCallbackFunc)infix_reverse_get_code(rt_cl), -5.5f, 5.5f);
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt_cb);
        infix_reverse_destroy(rt_cl);
    }

    subtest("Callback with signature: void(int)") {
        plan(4);  // One for creation, one for the check inside the handler, for each type.

        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        typedef void (*VoidCallbackFunc)(int);

        // Test Type-Safe Callback
        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 1, 1, (void *)void_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_void_callback((VoidCallbackFunc)infix_reverse_get_code(rt_cb), 1337);
        else
            skip(1, "Test skipped");

        // Test Generic Closure
        infix_reverse_t * rt_cl = nullptr;
        status = infix_reverse_create_closure_manual(&rt_cl, ret_type, arg_types, 1, 1, void_closure_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Generic closure created");
        if (rt_cl)
            execute_void_callback((VoidCallbackFunc)infix_reverse_get_code(rt_cl), 1337);
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt_cb);
        infix_reverse_destroy(rt_cl);
    }
}
