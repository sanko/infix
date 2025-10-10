/**
 * @file 16_nested_calls.c
 * @brief Recipe: Proving Reentrancy with Nested FFI Calls.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-proving-reentrancy-with-nested-ffi-calls
 */
#include <infix/infix.h>
#include <stdio.h>

// Mock C Library
// This simulates a C library that takes a callback.
static void (*g_handler)(int) = NULL;
void log_event(const char * msg) {
    printf("C Log: %s\n", msg);
}
void register_handler(void (*h)(int)) {
    g_handler = h;
}
void run_loop() {
    printf("C library 'run_loop' starting...\n");
    if (g_handler) {
        g_handler(42);  // The library invokes our callback.
    }
    printf("C library 'run_loop' finished.\n");
}
// End Mock

// A global forward trampoline for the log_event function, which will be
// called from *inside* our callback handler.
static infix_forward_t * g_log_trampoline = NULL;

// Our callback handler.
void my_handler(infix_context_t * context, int event_code) {
    (void)context;
    printf("Handler: Received event %d.\n", event_code);
    const char * log_msg = "Event processed inside handler.";
    void * log_args[] = {&log_msg};

    // This is the nested call: a forward FFI call made from within a reverse FFI call.
    ((infix_cif_func)infix_forward_get_code(g_log_trampoline))((void *)log_event, NULL, log_args);
}

int main() {
    // 1. Create all necessary trampolines upfront. Caching is key.
    infix_forward_create(&g_log_trampoline, "(*char) -> void");  // For log_event

    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, "(int) -> void", (void *)my_handler, NULL);  // For my_handler
    void * handler_ptr = infix_reverse_get_code(rt);

    infix_forward_t *t_register, *t_run;
    // Signature for register_handler: void(void(*)(int))
    // A pointer `*` to a function type `(int) -> void`.
    infix_forward_create(&t_register, "(*((int) -> void)) -> void");
    infix_forward_create(&t_run, "() -> void");  // For run_loop

    // 2. Execute the nested call.
    printf("Registering handler...\n");
    ((infix_cif_func)infix_forward_get_code(t_register))((void *)register_handler, NULL, &handler_ptr);

    printf("Running main loop...\n");
    ((infix_cif_func)infix_forward_get_code(t_run))((void *)run_loop, NULL, NULL);

    // 3. Cleanup all trampolines.
    infix_forward_destroy(g_log_trampoline);
    infix_reverse_destroy(rt);
    infix_forward_destroy(t_register);
    infix_forward_destroy(t_run);
    return 0;
}
