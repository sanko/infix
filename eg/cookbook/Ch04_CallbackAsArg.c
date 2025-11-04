/**
 * @file Ch04_CallbackAsArg.c
 * @brief Cookbook Chapter 4: Receiving and Calling a Function Pointer
 *
 * This example demonstrates a powerful composition of forward and reverse calls.
 * We create a reverse trampoline (a callback) and then pass its function pointer
 * as an argument to another C function using a forward trampoline.
 *
 * This pattern is very common in C APIs that use callbacks for event handling,
 * sorting, or iteration.
 */
#include <infix/infix.h>
#include <stdio.h>

// The "inner" handler function for our callback.
static int multiply_handler(int x) {
    printf("  -> Inner callback (multiply_handler) received: %d\n", x);
    return x * 10;
}

// The "outer" C function that accepts a function pointer as an argument.
static int harness_func(int (*worker_func)(int), int base_val) {
    printf(" -> Harness function is about to call the worker_func...\n");
    return worker_func(base_val);
}

int main() {
    printf("--- Cookbook Chapter 4: Passing a Callback as an Argument ---\n");

    // 1. Create the "inner" reverse trampoline for our callback logic.
    infix_reverse_t * inner_cb_ctx = NULL;
    infix_status status = infix_reverse_create_callback(&inner_cb_ctx, "(int)->int", (void *)multiply_handler, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create inner callback.\n");
        return 1;
    }

    // 2. Create the "outer" forward trampoline for the harness function.
    //    The signature for a function pointer is `*(...)`.
    //    Signature for: int harness_func( int(*)(int), int );
    const char * harness_sig = "(*((int)->int), int) -> int";
    infix_forward_t * harness_trampoline = NULL;
    status = infix_forward_create(&harness_trampoline, harness_sig, (void *)harness_func, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create harness trampoline.\n");
        infix_reverse_destroy(inner_cb_ctx);
        return 1;
    }

    // 3. Get the native function pointer from our inner callback.
    void * inner_cb_ptr = infix_reverse_get_code(inner_cb_ctx);
    int value = 7;

    // 4. Prepare arguments for the harness call. The first argument is the
    //    function pointer we just generated.
    void * harness_args[] = {&inner_cb_ptr, &value};
    int result;

    // 5. Make the call.
    printf("Calling the harness function via FFI...\n");
    infix_forward_get_code(harness_trampoline)(&result, harness_args);

    printf("...Harness function returned.\n");
    printf("Final result from nested callback: %d (Expected: 70)\n", result);

    // 6. Clean up both trampolines.
    infix_forward_destroy(harness_trampoline);
    infix_reverse_destroy(inner_cb_ctx);

    return 0;
}
