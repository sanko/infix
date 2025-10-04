/**
 * @file 15_variadic_callback.c
 * @brief Recipe: Creating a Variadic Callback.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-creating-a-variadic-callback
 */
#include <infix/infix.h>
#include <stdarg.h>
#include <stdio.h>

// Our C handler is itself variadic.
void my_logger(infix_context_t * context, const char * level, const char * format, ...) {
    (void)context;
    printf("[%s] ", level);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

// A C function (the "harness") that will call our logger.
typedef void (*log_func_t)(const char *, const char *, ...);
void run_logger(log_func_t logger) {
    logger("INFO", "User logged in with ID %d\n", 42);
}

int main() {
    // 1. Describe the *concrete signature* of the call being made inside run_logger:
    //    void(const char*, const char*, int)
    //    The semicolon indicates that the `int` is a variadic argument.
    const char * signature = "c*,c*;i=>v";

    // 2. Create the reverse trampoline.
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, signature, (void *)my_logger, NULL);

    // 3. Pass the generated function pointer to the harness to be called.
    run_logger((log_func_t)infix_reverse_get_code(rt));

    infix_reverse_destroy(rt);
    return 0;
}
