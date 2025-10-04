/**
 * @file 13_stateful_callback.c
 * @brief Recipe: Creating a Stateful Callback (The Modern Way).
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-creating-a-stateful-callback-the-modern-way
 */
#include <infix/infix.h>
#include <stdio.h>

// A mock C library with a stateless callback API.
typedef void (*item_processor_t)(int item_value);
void process_list(int * items, int count, item_processor_t process_func) {
    for (int i = 0; i < count; ++i) {
        process_func(items[i]);
    }
}
// End mock library

// Our application's state that we want to access in the callback.
typedef struct {
    const char * name;
    int sum;
} AppContext;

// This is our C handler. It receives the `infix_context_t*` as its first argument.
// The subsequent arguments (int item_value) match the signature string "i=>v".
void my_stateful_handler(infix_context_t * context, int item_value) {
    // Retrieve our application's state from the user_data pointer!
    AppContext * ctx = (AppContext *)infix_reverse_get_user_data(context);

    // Now we can use the state.
    printf("Handler for '%s' processing %d\n", ctx->name, item_value);
    ctx->sum += item_value;
}

int main() {
    AppContext ctx = {"My List", 0};

    // 1. Create a reverse trampoline for the signature the C library expects: void(int).
    //    We pass a pointer to our AppContext struct as the user_data.
    infix_reverse_t * rt = NULL;
    infix_reverse_create(&rt, "i=>v", (void *)my_stateful_handler, &ctx);

    item_processor_t processor_ptr = (item_processor_t)infix_reverse_get_code(rt);

    // 2. Call the C library. It is completely unaware that our handler is stateful.
    int list[] = {10, 20, 30};
    process_list(list, 3, processor_ptr);

    printf("Context '%s' has final sum: %d\n", ctx.name, ctx.sum);  // Expected: 60

    infix_reverse_destroy(rt);
    return 0;
}
