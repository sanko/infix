/**
 * @file 304_reverse_call_types.c
 * @brief Unit test to explicitly compare the "Callback" vs. "Closure" reverse trampoline APIs.
 * @ingroup test_suite
 *
 * @details This test serves as a clear, side-by-side demonstration of the two main
 * models for creating reverse trampolines in `infix`. Both models are functionally
 * equivalent from the perspective of the C code that calls the generated function
 * pointer, but they offer different interfaces to the developer using the `infix` library.
 *
 * 1.  **`infix_reverse_create_callback`**:
 *     - **Handler:** A native, type-safe C function (e.g., `int handler(int, int)`).
 *     - **Pros:** Easy to use from C/C++, compile-time type checking, potentially higher performance.
 *     - **Cons:** Less flexible, stateless by default.
 *
 * 2.  **`infix_reverse_create_closure`**:
 *     - **Handler:** A generic function (`infix_closure_handler_fn`) that receives
 *       arguments as a `void**` array.
 *     - **Pros:** Highly flexible, ideal for language bindings, supports stateful
 *       callbacks via `user_data`.
 *     - **Cons:** Requires manual argument unpacking, lacks compile-time type safety.
 *
 * This test creates a JIT-compiled function pointer using both APIs for the same
 * signature (`(int, int) -> int`) and verifies that both can be called from a C
 * harness function and produce the correct result.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <string.h>

void harness(int (*func_ptr)(int, int), int a, int b, int expected) {
    int result = func_ptr(a, b);
    ok(result == expected, "Callback/closure returned the correct value (got %d, expected %d)", result, expected);
}

int handler_callback(int a, int b) {
    note("Type-safe handler called with a=%d, b=%d", a, b);
    return a * b;
}

void handler_closure(infix_context_t * ctx, void * ret, void ** args) {
    (void)ctx;

    int a = *(int *)args[0];
    int b = *(int *)args[1];
    note("Generic closure handler called with a=%d, b=%d", a, b);

    int result = a * b;

    memcpy(ret, &result, sizeof(int));
}

TEST {
    plan(1);

    subtest("Reverse Trampoline API: Callback vs. Closure") {
        plan(4);

        const char * signature = "(int, int) -> int";
        typedef int (*NativeFuncPtr)(int, int);

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
