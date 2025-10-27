/**
 * @file 301_primitives.c
 * @brief Unit test for reverse trampolines (callbacks) with primitive C types.
 * @ingroup test_suite
 *
 * @details This test file is the reverse-call counterpart to `001_primitives.c`.
 * It verifies that `infix` can correctly generate a callable C function pointer
 * from a user-provided handler function for all basic primitive types.
 *
 * For each primitive type, it tests two distinct reverse trampoline models:
 *
 * 1.  **Type-Safe Callback (`infix_reverse_create_callback_manual`):** The user provides
 *     a C handler with a native, type-safe signature (e.g., `int handler(int, int)`).
 *     This is the high-level, convenient API.
 *
 * 2.  **Generic Closure (`infix_reverse_create_closure_manual`):** The user provides
 *     a generic handler (`infix_closure_handler_fn`) that receives arguments as a
 *     `void**` array. This is the low-level, more flexible API, typically used
 *     for language bindings.
 *
 * The test creates a JIT-compiled function pointer for each model and passes it
 * to a C "harness" function. The harness calls the pointer, and the test verifies
 * that the user-provided handler was invoked correctly and that the return value
 * was transmitted back to the harness.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>

// Handler Functions for Testing

/** @brief A type-safe handler for an `int(int, int)` callback. */
int int_callback_handler(int a, int b) {
    note("int_callback_handler received: a=%d, b=%d", a, b);
    return a * b;
}

/** @brief A type-safe handler for a `float(float, float)` callback. */
float float_callback_handler(float a, float b) {
    note("float_callback_handler received: a=%.2f, b=%.2f", a, b);
    return a + b;
}

/** @brief A type-safe handler for a `void(int)` callback. */
void void_callback_handler(int check_val) {
    note("void_callback_handler received check_val = %d", check_val);
    ok(check_val == 1337, "void(int) callback received the correct value");
}

/** @brief A generic closure handler for an `int(int, int)` signature. */
void int_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    int a = *(int *)args[0];
    int b = *(int *)args[1];
    int result = a * b;
    memcpy(return_value, &result, sizeof(int));
}

/** @brief A generic closure handler for a `float(float, float)` signature. */
void float_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    float a = *(float *)args[0];
    float b = *(float *)args[1];
    float result = a + b;
    memcpy(return_value, &result, sizeof(float));
}

/** @brief A generic closure handler for a `void(int)` signature. */
void void_closure_handler(infix_context_t * context, void * return_value, void ** args) {
    (void)context;
    (void)return_value;
    int check_val = *(int *)args[0];
    ok(check_val == 1337, "void(int) closure received the correct value");
}

void execute_int_callback(int (*func_ptr)(int, int), int x, int y) {
    int result = func_ptr(x, y);
    ok(result == x * y, "callback/closure returned the correct value");
}

void execute_float_callback(float (*func_ptr)(float, float), float a, float b) {
    float result = func_ptr(a, b);
    ok(fabs(result - (a + b)) < 0.01, "callback/closure returned correct sum");
}

void execute_void_callback(void (*func_ptr)(int), int val) { func_ptr(val); }

TEST {
    plan(3);

    subtest("Callback with signature: int(int, int)") {
        plan(4);

        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        typedef int (*IntCallbackFunc)(int, int);

        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 2, 2, (void *)int_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_int_callback((IntCallbackFunc)infix_reverse_get_code(rt_cb), 7, 6);
        else
            skip(1, "Test skipped");

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

        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 2, 2, (void *)float_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_float_callback((FloatCallbackFunc)infix_reverse_get_code(rt_cb), 10.5f, 20.0f);
        else
            skip(1, "Test skipped");

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
        plan(4);

        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        typedef void (*VoidCallbackFunc)(int);

        infix_reverse_t * rt_cb = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt_cb, ret_type, arg_types, 1, 1, (void *)void_callback_handler);
        ok(status == INFIX_SUCCESS, "Type-safe callback created");
        if (rt_cb)
            execute_void_callback((VoidCallbackFunc)infix_reverse_get_code(rt_cb), 1337);
        else
            skip(1, "Test skipped");

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
