/**
 * @file Ch08_ArenaCallFrame.c
 * @brief Cookbook Chapter 8: Building a Dynamic Call Frame with an Arena
 *
 * This example demonstrates an advanced, high-performance technique for language
 * bindings: using an `infix` arena to build the entire call frame for an FFI call.
 *
 * In a binding, you receive arguments from the host language (e.g., Python),
 * unbox them into temporary C values, and create the `void* args[]` array of
 * pointers to these temporaries. Using `malloc` for this in a tight loop is
 * inefficient.
 *
 * This recipe shows how to allocate both the unboxed C values AND the `void**`
 * array from a single, short-lived arena. This is extremely fast and simplifies
 * cleanup to a single `infix_arena_destroy` call, preventing memory leaks.
 */
#include <infix/infix.h>
#include <stdarg.h>  // For va_list
#include <stdio.h>
#include <string.h>  // For memcpy

// A sample C function we want to call dynamically.
static void process_user_data(int id, double score, const char * name) {
    printf("  -> C Function Received: ID=%d, Score=%.2f, Name='%s'\n", id, score, name);
}

/**
 * This function simulates the core logic of a language binding's generic "call" function.
 * It takes a va_list to represent dynamic arguments coming from a script.
 */
static void dynamic_ffi_call(infix_forward_t * trampoline, void * target_func, int arg_count, ...) {
    // 1. Create a temporary arena for this call's entire data frame.
    infix_arena_t * call_arena = infix_arena_create(1024);
    if (!call_arena) {
        fprintf(stderr, "Error: Could not create call arena.\n");
        return;
    }

    // 2. Allocate the void** array itself from the arena.
    void ** args = infix_arena_alloc(call_arena, sizeof(void *) * arg_count, _Alignof(void *));

    va_list va;
    va_start(va, arg_count);

    // 3. For each argument, allocate space for its C value in the arena,
    //    copy the value, and store the pointer in the `args` array.
    for (int i = 0; i < arg_count; ++i) {
        // In a real binding, you would inspect the trampoline's arg types here.
        // For this example, we'll assume the order (int, double, const char*).
        if (i == 0) {  // int
            int * val_ptr = infix_arena_alloc(call_arena, sizeof(int), _Alignof(int));
            *val_ptr = va_arg(va, int);
            args[i] = val_ptr;
        }
        else if (i == 1) {  // double
            double * val_ptr = infix_arena_alloc(call_arena, sizeof(double), _Alignof(double));
            *val_ptr = va_arg(va, double);
            args[i] = val_ptr;
        }
        else if (i == 2) {  // const char*
            const char ** val_ptr = infix_arena_alloc(call_arena, sizeof(const char *), _Alignof(const char *));
            *val_ptr = va_arg(va, const char *);
            args[i] = val_ptr;
        }
    }
    va_end(va);

    // 4. Make the FFI call using the arena-managed data.
    printf("Making dynamic FFI call with arena-allocated frame...\n");
    infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
    cif(target_func, NULL, args);

    // 5. A single free cleans up the void** array AND all the argument values.
    infix_arena_destroy(call_arena);
    printf("Call frame arena destroyed.\n");
}

int main() {
    printf("Cookbook Chapter 8: Building a Dynamic Call Frame with an Arena\n");

    // Setup the trampoline once and cache it (as a real binding would).
    const char * signature = "(int, double, *char) -> void";
    infix_forward_t * trampoline = NULL;
    (void)infix_forward_create_unbound(&trampoline, signature, NULL);

    dynamic_ffi_call(trampoline, (void *)process_user_data, 3, 123, 99.8, "test user");

    infix_forward_destroy(trampoline);

    return 0;
}
