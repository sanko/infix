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
 * @file 303_advanced.c
 * @brief Tests advanced reverse trampoline (callback) patterns.
 *
 * @details This test suite verifies the library's ability to handle complex,
 * higher-order function patterns involving callbacks. It consolidates several
 * previous tests to create a focused suite for advanced use cases.
 *
 * The scenarios tested are:
 * 1.  **Pointer Modification:** A callback receives a pointer to a variable in
 *     the caller's scope and modifies its value, a common pattern for "out"
 *     parameters.
 * 2.  **Callback as an Argument:** A generated callback (reverse trampoline) is
 *     passed as a function pointer argument to a different function (called via
 *     a forward trampoline). This tests the interplay between the two FFI mechanisms.
 * 3.  **Callback Returning a Callback:** A callback is generated whose sole
 *     purpose is to return a different, dynamically-generated function pointer.
 *     This is achieved by storing the target function pointer in the `user_data`
 *     field of the reverse trampoline context, testing a powerful feature for
 *     creating stateful, dynamic callback providers.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>

// Scenario 1: Modify Data Via Pointer

/** @brief Handler that dereferences a pointer and writes a new value. */
void pointer_modify_handler(infix_context_t * context, int * p) {
    (void)context;
    note("pointer_modify_handler received pointer p=%p", (void *)p);
    if (p)
        *p = 999;
}

/** @brief Harness that calls the provided function pointer, passing it an address. */
void execute_pointer_modify_callback(void (*func_ptr)(int *), int * p) {
    func_ptr(p);
    ok(*p == 999, "Callback correctly modified the integer via its pointer");
}

// Scenario 2: Callback as an Argument

/** @brief The inner callback that will be passed as an argument. */
void inner_callback_handler(infix_context_t * context, int val) {
    (void)context;
    note("inner_callback_handler received val=%d", val);
    ok(val == 42, "Inner callback received the correct value from the harness");
}

/** @brief The harness function that accepts a function pointer as its argument. */
void execute_callback_as_arg_harness(void (*cb)(int)) {
    note("Harness is about to call the provided callback with value 42.");
    cb(42);
}

// Scenario 3: Callback Returning a Callback

/** @brief The innermost handler that will be returned and ultimately called. */
int final_multiply_handler(infix_context_t * context, int val) {
    (void)context;
    return val * 10;
}
/**
 * @brief A handler for the "provider" callback.
 * @details This handler leverages the `user_data` to return another function pointer.
 * It retrieves the function pointer from its own context and returns it.
 */
void * callback_provider_handler(infix_context_t * context) {
    note("Provider callback called, returning function pointer from user_data.");
    return infix_reverse_get_user_data(context);
}

/** @brief A harness that receives the provider, calls it to get the real callback, and then calls that. */
typedef int (*int_func_int)(int);
typedef int_func_int (*callback_provider)(void);

int call_returned_callback_harness(callback_provider provider, int val) {
    int_func_int worker_cb = provider();
    return worker_cb(val);
}

TEST {
    plan(3);

    subtest("Callback modifies data via pointer") {
        plan(2);
        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_pointer()};
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 1, 1, (void *)pointer_modify_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Reverse trampoline for pointer modification created");

        if (rt) {
            int my_value = 100;
            execute_pointer_modify_callback((void (*)(int *))infix_reverse_get_code(rt), &my_value);
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
    }

    subtest("Callback passed as an argument") {
        plan(3);
        infix_reverse_t * inner_rt = nullptr;
        infix_type * inner_arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_status status = infix_reverse_create_manual(
            &inner_rt, infix_type_create_void(), inner_arg_types, 1, 1, (void *)inner_callback_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Inner reverse trampoline (the argument) created");

        // The harness takes a `void (*)(int)` which is a pointer.
        infix_forward_t * fwd_trampoline = nullptr;
        infix_type * fwd_arg_types[] = {infix_type_create_pointer()};
        status = infix_forward_create_unbound_manual(&fwd_trampoline, infix_type_create_void(), fwd_arg_types, 1, 1);
        ok(status == INFIX_SUCCESS, "Forward trampoline (for the harness) created");

        if (inner_rt && fwd_trampoline) {
            void * callback_ptr_arg = infix_reverse_get_code(inner_rt);
            void * args[] = {&callback_ptr_arg};
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(fwd_trampoline);
            cif((void *)execute_callback_as_arg_harness, nullptr, args);
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(inner_rt);
        infix_forward_destroy(fwd_trampoline);
    }

    subtest("Callback returns a function pointer (via user_data)") {
        plan(3);

        infix_reverse_t * inner_t = nullptr;
        infix_type * inner_arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_status status = infix_reverse_create_manual(&inner_t,
                                                          infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                                          inner_arg_types,
                                                          1,
                                                          1,
                                                          (void *)final_multiply_handler,
                                                          nullptr);
        ok(status == INFIX_SUCCESS, "Inner callback created");

        infix_reverse_t * provider_t = nullptr;
        void * user_data_ptr = inner_t ? infix_reverse_get_code(inner_t) : nullptr;
        status = infix_reverse_create_manual(
            &provider_t, infix_type_create_pointer(), nullptr, 0, 0, (void *)callback_provider_handler, user_data_ptr);
        ok(status == INFIX_SUCCESS, "Provider callback created");

        if (inner_t && provider_t) {
            int result = call_returned_callback_harness((callback_provider)infix_reverse_get_code(provider_t), 7);
            ok(result == 70, "Callback returned from another callback works correctly (7 * 10 = 70)");
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(provider_t);
        infix_reverse_destroy(inner_t);
    }
}
