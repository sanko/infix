/**
 * @file 17_return_callback.c
 * @brief Recipe: Receiving and Calling a Function Pointer.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-receiving-and-calling-a-function-pointer
 */
#include <infix/infix.h>
#include <stdio.h>

// 1. The innermost C handler that will be returned and ultimately called.
int final_multiply_handler(infix_context_t * context, int val) {
    (void)context;
    return val * 10;
}

// 2. The handler for the "provider" callback. Its only job is to return
//    the function pointer we stored in its user_data.
void * callback_provider_handler(infix_context_t * context) {
    printf("Provider callback called, returning worker function pointer from user_data...\n");
    return infix_reverse_get_user_data(context);
}

// 3. A C harness function that demonstrates the pattern.
typedef int (*worker_func_t)(int);
typedef worker_func_t (*provider_func_t)(void);

int call_harness(provider_func_t provider, int input_val) {
    // Call the provider to get the actual worker callback.
    worker_func_t worker = provider();
    // Call the worker and return its result.
    return worker(input_val);
}

int main() {
    // Step A: Create the inner "worker" trampoline for `int(int)`.
    infix_reverse_t * worker_rt = NULL;
    infix_reverse_create(&worker_rt, "(int) -> int", (void *)final_multiply_handler, NULL);

    // Step B: Create the "provider" trampoline for `void*(void)`.
    // Store the callable pointer of the worker trampoline in the provider's user_data.
    infix_reverse_t * provider_rt = NULL;
    void * worker_ptr = infix_reverse_get_code(worker_rt);
    infix_reverse_create(&provider_rt, "() -> *void", (void *)callback_provider_handler, worker_ptr);

    // Step C: Create a forward trampoline to call the C harness.
    // Signature: int( provider_func_t, int ) which is int( int(*(*)(void))(int), int )
    // This is a function that takes a pointer to a function returning a function pointer.
    // Simpler: the argument is a function pointer, `provider_ptr`.
    const char * harness_sig = "(*(() -> *void), int) -> int";
    infix_forward_t * harness_ft = NULL;
    infix_forward_create(&harness_ft, harness_sig);

    // Step D: Execute the call chain.
    provider_func_t provider_ptr = (provider_func_t)infix_reverse_get_code(provider_rt);
    int input = 7;
    int result = 0;
    void * harness_args[] = {&provider_ptr, &input};

    ((infix_cif_func)infix_forward_get_code(harness_ft))((void *)call_harness, &result, harness_args);

    printf("Final result: %d\n", result);  // Expected: 70

    // Step E: Clean up all trampolines in reverse order of dependency.
    infix_forward_destroy(harness_ft);
    infix_reverse_destroy(provider_rt);
    infix_reverse_destroy(worker_rt);

    return 0;
}
