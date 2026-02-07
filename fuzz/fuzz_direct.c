/**
 * @file fuzz_direct.c
 * @brief Fuzzer target for the Direct Marshalling API generation logic.
 * @ingroup internal_fuzz
 *
 * @internal
 * This fuzzer stresses the `infix_forward_create_direct` pipeline.
 *
 * Strategy:
 * 1. Generate a random function signature using the helper library.
 * 2. Generate a matching array of `infix_direct_arg_handler_t` structs.
 *    - Randomly assign scalar vs aggregate marshallers based on the type category.
 *    - Randomly assign writeback handlers to pointer types.
 * 3. Call `infix_forward_create_direct` to trigger ABI analysis and Code Gen.
 * 4. Destroy the trampoline.
 *
 * We do NOT execute the trampoline (`cif`) because we cannot safely generate a
 * C target function that matches a random signature at runtime without crashing
 * the stack. The goal here is to ensure the JIT compiler itself is robust
 * against all possible type combinations.
 */

#include "fuzz_helpers.h"
#include <stdio.h>
#include <string.h>

// Explicitly declare the internal error clearing function.
// This is necessary because the fuzzer runs in a loop on the same thread,
// and we must ensure no stale stack pointers remain in the TLS error context.
extern void _infix_clear_error(void);

// Dummy Handlers (Addresses needed for JIT generation)
infix_direct_value_t dummy_scalar_marshaller(void * src) { return (infix_direct_value_t){0}; }

void dummy_agg_marshaller(void * src, void * dest, const infix_type * type) {
    (void)src;
    (void)dest;
    (void)type;
    // In a real execution, we'd memcpy. Here we do nothing.
}

void dummy_writeback(void * src, void * c_data, const infix_type * type) {
    (void)src;
    (void)c_data;
    (void)type;
    // Do nothing.
}

void dummy_target_func(void) {
    // Does nothing.
}

// Main Fuzz Logic
static void FuzzTest(fuzzer_input in) {
    // Clear thread-local error state.
    // Previous iterations might have left g_infix_last_signature_context pointing to
    // a stack buffer that is now invalid (use-after-return).
    _infix_clear_error();

    infix_arena_t * arena = infix_arena_create(65536);
    if (!arena)
        return;

    // Generate Random Types
    size_t total_fields = 0;

    // Return Type
    infix_type * ret_type = generate_random_type(arena, &in, 0, &total_fields);
    if (!ret_type)
        goto cleanup;

    // Argument Types
    uint8_t arg_count_byte;
    if (!consume_uint8_t(&in, &arg_count_byte))
        goto cleanup;

    size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;
    infix_type ** arg_types = calloc(num_args, sizeof(infix_type *));
    infix_direct_arg_handler_t * handlers = calloc(num_args, sizeof(infix_direct_arg_handler_t));

    if (!arg_types || !handlers) {
        free(arg_types);
        free(handlers);
        goto cleanup;
    }

    for (size_t i = 0; i < num_args; ++i) {
        arg_types[i] = generate_random_type(arena, &in, 0, &total_fields);
        if (!arg_types[i]) {
            // If generation fails mid-stream, abort cleanly
            free(arg_types);
            free(handlers);
            goto cleanup;
        }

        // Assign Dummy Handlers based on type
        uint8_t handler_choice;
        if (!consume_uint8_t(&in, &handler_choice))
            handler_choice = 0;

        if (arg_types[i]->category == INFIX_TYPE_STRUCT || arg_types[i]->category == INFIX_TYPE_UNION ||
            arg_types[i]->category == INFIX_TYPE_ARRAY || arg_types[i]->category == INFIX_TYPE_COMPLEX) {

            handlers[i].aggregate_marshaller = &dummy_agg_marshaller;
        }
        else  // Primitive or Pointer
            handlers[i].scalar_marshaller = &dummy_scalar_marshaller;

        // Randomly add writeback to pointers (50% chance)
        if (arg_types[i]->category == INFIX_TYPE_POINTER && (handler_choice % 2 == 0))
            handlers[i].writeback_handler = &dummy_writeback;
    }

    // Call the API under test
    // Build signature string safely.
    char signature[4096];
    char * p = signature;
    // Reserve 1 byte for null terminator at all times.
    size_t remain = sizeof(signature) - 1;

// Helper macro to safely append a string literal
#define APPEND_LITERAL(lit)           \
    do {                              \
        size_t len = sizeof(lit) - 1; \
        if (remain < len)             \
            goto sig_done;            \
        memcpy(p, lit, len);          \
        p += len;                     \
        remain -= len;                \
    } while (0)

    APPEND_LITERAL("(");

    for (size_t i = 0; i < num_args; ++i) {
        if (i > 0)
            APPEND_LITERAL(",");
        // Use the buffer directly, relying on infix_type_print's bounds checking
        infix_status s = infix_type_print(p, remain + 1, arg_types[i], INFIX_DIALECT_SIGNATURE);
        if (s != INFIX_SUCCESS)
            goto sig_done;

        size_t len = strlen(p);
        p += len;
        remain -= len;
    }

    APPEND_LITERAL(")->");

    infix_type_print(p, remain + 1, ret_type, INFIX_DIALECT_SIGNATURE);
    // p and remain are not updated here, but that's fine as it's the last step.

sig_done:
    // Ensure null termination (infix_type_print might have failed or we jumped out)
    signature[sizeof(signature) - 1] = '\0';

    // Trigger Compilation
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create_direct(&trampoline,
                                                      signature,
                                                      (void *)&dummy_target_func,
                                                      handlers,
                                                      NULL  // No registry needed, types are anonymous in signature
    );

    // Cleanup
    if (status == INFIX_SUCCESS)
        infix_forward_destroy(trampoline);

    free(arg_types);
    free(handlers);

cleanup:
    infix_arena_destroy(arena);
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
