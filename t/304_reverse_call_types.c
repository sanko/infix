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
 * @file 304_reverse_call_types.c
 * @brief Unit test to verify both the type-safe "callback" and generic "closure" APIs.
 *
 * @details This test validates the two distinct reverse trampoline creation APIs.
 * It ensures that both `infix_reverse_create_callback` (for C/C++ developers)
 * and `infix_reverse_create_closure` (for language binding authors) can produce
 * a valid, C-callable function pointer that works correctly when passed to
 * native C code.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <string.h>  // For memcpy

// The native C function that will receive and execute our generated callbacks.
// It expects a standard C function pointer.
void harness(int (*func_ptr)(int, int), int a, int b, int expected) {
    int result = func_ptr(a, b);
    ok(result == expected, "Callback/closure returned the correct value (got %d, expected %d)", result, expected);
}

// Handler for the type-safe "Callback" system.
// Its signature is type-safe and matches the public-facing part of the FFI signature.
int handler_callback(int a, int b) {
    note("Type-safe handler called with a=%d, b=%d", a, b);
    return a * b;
}

// Handler for the generic "Closure" system.
// Its signature is always the same, requiring manual argument casting.
void handler_closure(infix_context_t * ctx, void * ret, void ** args) {
    (void)ctx;
    // Manually cast arguments from the void** array.
    int a = *(int *)args[0];
    int b = *(int *)args[1];
    note("Generic closure handler called with a=%d, b=%d", a, b);

    // Perform the operation.
    int result = a * b;

    // Manually write the result to the return value buffer.
    memcpy(ret, &result, sizeof(int));
}

TEST {
    plan(1);

    subtest("Reverse Trampoline API: Callback vs. Closure") {
        plan(4);  // 2 creation checks, 2 result checks from the harness.

        const char * signature = "(int, int) -> int";
        typedef int (*NativeFuncPtr)(int, int);

        // Test 1: The Type-Safe "Callback" for C/C++ developers
        infix_reverse_t * ctx_callback = NULL;
        infix_status status_cb =
            infix_reverse_create_callback(&ctx_callback, signature, (void *)handler_callback, NULL);

        if (ok(status_cb == INFIX_SUCCESS, "infix_reverse_create_callback created successfully")) {
            NativeFuncPtr func_ptr = (NativeFuncPtr)infix_reverse_get_code(ctx_callback);
            harness(func_ptr, 10, 5, 50);
        }
        else
            skip(1, "Harness call skipped for callback due to creation failure.");

        infix_reverse_destroy(ctx_callback);


        // Test 2: The Generic "Closure" for language binding authors
        infix_reverse_t * ctx_closure = NULL;
        infix_status status_cl = infix_reverse_create_closure(&ctx_closure, signature, handler_closure, NULL, NULL);

        if (ok(status_cl == INFIX_SUCCESS, "infix_reverse_create_closure created successfully")) {
            NativeFuncPtr func_ptr = (NativeFuncPtr)infix_reverse_get_code(ctx_closure);
            harness(func_ptr, 8, 8, 64);
        }
        else
            skip(1, "Harness call skipped for closure due to creation failure.");

        infix_reverse_destroy(ctx_closure);
    }
}
