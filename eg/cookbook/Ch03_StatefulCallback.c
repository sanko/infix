/**
 * @file Ch03_StatefulCallback.c
 * @brief Cookbook Chapter 3: Creating a Stateful Callback
 *
 * This example demonstrates how to create a "closure" or stateful callback.
 * This is essential when a C library's callback mechanism does not provide a
 * `void* user_data` parameter, but your handler still needs access to
 * application state.
 *
 * `infix_reverse_create_closure` is used for this. It takes a generic handler
 * function and a `void*` pointer to your state, which can be retrieved inside
 * the handler.
 */
#include <infix/infix.h>
#include <stdio.h>

// Our application's state that the callback needs to access.
typedef struct {
    const char * name;
    int sum;
} AppContext;

// 1. The handler for a closure has a generic signature. It receives arguments
//    as a `void**` array.
static void my_stateful_handler(infix_context_t * context, void * ret, void ** args) {
    (void)ret;  // This handler's signature is `(int)->void`, so no return value.

    // 2. Retrieve your application state from the context's user_data field.
    AppContext * ctx = (AppContext *)infix_reverse_get_user_data(context);

    // 3. Manually unbox the arguments from the void** array.
    int item_value = *(int *)args[0];

    printf("  -> Stateful handler received item: %d\n", item_value);
    ctx->sum += item_value;
}

// A hypothetical C library function that takes a callback but no user_data.
typedef void (*item_processor_t)(int);
static void process_list(const int * items, int count, item_processor_t process_func) {
    for (int i = 0; i < count; ++i)
        process_func(items[i]);
}

int main() {
    printf("Cookbook Chapter 3: Creating a Stateful Callback\n");

    // a. Prepare your state.
    AppContext ctx = {"My List", 0};

    // b. Create the closure, passing a pointer to your state as `user_data`.
    infix_reverse_t * rt = NULL;
    infix_status status = infix_reverse_create_closure(&rt, "(int) -> void", my_stateful_handler, &ctx, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create closure.\n");
        return 1;
    }

    // c. Get the native function pointer and use it with the C library function.
    item_processor_t processor_ptr = (item_processor_t)infix_reverse_get_code(rt);
    int list[] = {10, 20, 30};

    printf("Calling C library function with our stateful closure...\n");
    process_list(list, 3, processor_ptr);
    printf("...C library function finished.\n");
    printf("Final sum for '%s': %d (Expected: 60)\n", ctx.name, ctx.sum);

    // d. Clean up.
    infix_reverse_destroy(rt);

    return 0;
}
