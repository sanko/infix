/**
 * @file Ch04_Rec05_Reentrancy.c
 * @brief Cookbook Chapter 4, Recipe 5: Proving Reentrancy with Nested FFI Calls
 *
 * This test demonstrates that `infix` is fully reentrant, meaning it is safe to
 * make an `infix` FFI call from within a handler that was invoked by another
 * `infix` FFI call.
 *
 * The call chain is:
 * 1. C `main` function (Forward Call) -> `harness` function
 * 2. `harness` function (Native Call) -> `infix` Reverse Callback
 * 3. Reverse Callback Handler (Forward Call) -> `multiply` function
 *
 * This works because `infix` uses no global mutable state; all context is either
 * passed directly or stored in thread-local storage.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>  // For memcpy

// The innermost C function that will be the final target.
static int multiply(int a, int b) {
    printf("    -> Innermost function `multiply(%d, %d)` called.\n", a, b);
    return a * b;
}

// The generic handler for our reverse closure.
// It needs state (the forward trampoline for `multiply`), so we MUST use a closure.
static void nested_call_handler(infix_context_t * ctx, void * ret, void ** args) {
    printf("   -> Nested callback handler entered.\n");
    // 1. Retrieve the forward trampoline from user_data.
    infix_forward_t * fwd_trampoline = (infix_forward_t *)infix_reverse_get_user_data(ctx);

    // 2. Unbox the argument passed from the `harness` function.
    int val = *(int *)args[0];
    int multiplier = 5;
    void * mult_args[] = {&val, &multiplier};

    // 3. Make the nested forward call to `multiply`.
    int result;
    infix_forward_get_code(fwd_trampoline)(&result, mult_args);

    // 4. Write the result to the return buffer for the `harness` function.
    memcpy(ret, &result, sizeof(int));
    printf("   -> Nested callback handler exiting.\n");
}

// The outer C function that takes our generated callback.
static int harness(int (*func)(int), int input) {
    printf(" -> Harness function entered, about to call the provided callback...\n");
    int result = func(input);
    printf(" -> Harness function exiting.\n");
    return result;
}

int main() {
    printf("--- Cookbook Chapter 4, Recipe 5: Proving Reentrancy ---\n");

    // 1. Create the innermost forward trampoline (for `multiply`).
    infix_forward_t * fwd_multiply = NULL;
    if (infix_forward_create(&fwd_multiply, "(int, int)->int", (void *)multiply, NULL) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create multiply trampoline.\n");
        return 1;
    }
    // 2. Create the reverse closure, passing the `multiply` trampoline as its state.
    infix_reverse_t * rev_nested = NULL;
    if (infix_reverse_create_closure(&rev_nested, "(int)->int", nested_call_handler, fwd_multiply, NULL) !=
        INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create nested closure.\n");
        infix_forward_destroy(fwd_multiply);
        return 1;
    }
    // 3. Create the outermost forward trampoline (for `harness`).
    infix_forward_t * fwd_harness = NULL;
    const char * harness_sig = "(*((int)->int), int)->int";
    if (infix_forward_create(&fwd_harness, harness_sig, (void *)harness, NULL) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create harness trampoline.\n");
        infix_reverse_destroy(rev_nested);
        infix_forward_destroy(fwd_multiply);
        return 1;
    }
    // 4. Execute the entire call chain.
    void * callback_ptr = infix_reverse_get_code(rev_nested);
    int base_val = 8;
    void * harness_args[] = {&callback_ptr, &base_val};
    int final_result;

    printf("Executing top-level forward call to `harness`...\n");
    infix_forward_get_code(fwd_harness)(&final_result, harness_args);
    printf("...Top-level call finished.\n");
    printf("Final result from nested/reentrant call: %d (Expected: 40)\n", final_result);

    // 5. Clean up all three trampolines in reverse order of creation.
    infix_forward_destroy(fwd_harness);
    infix_reverse_destroy(rev_nested);
    infix_forward_destroy(fwd_multiply);

    return 0;
}
