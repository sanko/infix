/**
 * @file 303_advanced.c
 * @brief Unit test for advanced reverse trampoline (callback) scenarios.
 * @ingroup test_suite
 *
 * @details This test file explores more complex and dynamic uses of reverse
 * trampolines, verifying that the library's features compose correctly.
 *
 * The test covers:
 *
 * 1.  **Modifying Data via Pointers:** A callback is created for a function that
 *     takes a pointer (`void(int*)`). The test verifies that when the C harness
 *     calls the JIT-compiled pointer, the handler is able to correctly dereference
 *     the pointer and modify the original data in the harness.
 *
 * 2.  **Callbacks as Arguments:** This is a "callback inception" test. It creates
 *     an "inner" callback and passes its JIT-compiled function pointer as an
 *     argument (via a forward trampoline) to a C "harness" function. The harness
 *     then calls the function pointer it received. This complex chain tests the
 *     interoperability of forward and reverse trampolines.
 *
 * 3.  **Closures Returning Function Pointers:** A "provider" closure is created.
 *     Its `user_data` is set to the function pointer of another, "worker" callback.
 *     When the provider is called, its handler retrieves the worker's function
 *     pointer from `user_data` and returns it. The C harness then calls this
 *     returned pointer, verifying that function pointers can be passed as data
 *     through closures.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <string.h>

void pointer_modify_handler(int * p) {
    note("pointer_modify_handler received pointer p=%p", (void *)p);
    if (p)
        *p = 999;
}

void execute_pointer_modify_callback(void (*func_ptr)(int *), int * p) {
    func_ptr(p);
    ok(*p == 999, "Callback correctly modified the integer via its pointer");
}

void inner_callback_handler(int val) {
    note("inner_callback_handler received val=%d", val);
    ok(val == 42, "Inner callback received the correct value from the harness");
}

void execute_callback_as_arg_harness(void (*cb)(int)) {
    note("Harness is about to call the provided callback with value 42.");
    cb(42);
}

int final_multiply_handler(int val) {
    return val * 10;
}

void closure_provider_handler(infix_context_t * context, void * ret, void ** args) {
    (void)args;
    note("Provider closure called, returning function pointer from user_data.");
    void * func_ptr = infix_reverse_get_user_data(context);
    memcpy(ret, &func_ptr, sizeof(void *));
}

typedef int (*int_func_int)(int);
typedef int_func_int (*callback_provider)(void);

int call_returned_callback_harness(callback_provider provider, int val) {
    int_func_int worker_cb = provider();
    return worker_cb(val);
}

TEST {
    plan(3);

    subtest("Callback modifies data via pointer") {
        plan(2);
        infix_type * ret_type = infix_type_create_void();
        infix_type * arg_types[] = {infix_type_create_pointer()};
        infix_reverse_t * rt = nullptr;
        infix_status status =
            infix_reverse_create_callback_manual(&rt, ret_type, arg_types, 1, 1, (void *)pointer_modify_handler);
        ok(status == INFIX_SUCCESS, "Reverse trampoline for pointer modification created");

        if (rt) {
            int my_value = 100;
            execute_pointer_modify_callback((void (*)(int *))infix_reverse_get_code(rt), &my_value);
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
    }

    subtest("Callback passed as an argument") {
        plan(3);
        infix_reverse_t * inner_rt = nullptr;
        infix_type * inner_arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_status status = infix_reverse_create_callback_manual(
            &inner_rt, infix_type_create_void(), inner_arg_types, 1, 1, (void *)inner_callback_handler);
        ok(status == INFIX_SUCCESS, "Inner reverse trampoline (the argument) created");

        infix_forward_t * fwd_trampoline = nullptr;
        infix_type * fwd_arg_types[] = {infix_type_create_pointer()};
        status = infix_forward_create_unbound_manual(&fwd_trampoline, infix_type_create_void(), fwd_arg_types, 1, 1);
        ok(status == INFIX_SUCCESS, "Forward trampoline (for the harness) created");

        if (inner_rt && fwd_trampoline) {
            void * callback_ptr_arg = infix_reverse_get_code(inner_rt);
            void * args[] = {&callback_ptr_arg};
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(fwd_trampoline);
            cif((void *)execute_callback_as_arg_harness, nullptr, args);
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(inner_rt);
        infix_forward_destroy(fwd_trampoline);
    }

    subtest("Closure returns a function pointer (via user_data)") {
        plan(3);

        infix_reverse_t * inner_t = nullptr;
        infix_type * inner_arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_status status = infix_reverse_create_callback_manual(&inner_t,
                                                                   infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                                                   inner_arg_types,
                                                                   1,
                                                                   1,
                                                                   (void *)final_multiply_handler);
        ok(status == INFIX_SUCCESS, "Inner callback (final target) created");

        infix_reverse_t * provider_cl = nullptr;
        void * user_data_ptr = inner_t ? infix_reverse_get_code(inner_t) : nullptr;
        status = infix_reverse_create_closure_manual(
            &provider_cl, infix_type_create_pointer(), nullptr, 0, 0, closure_provider_handler, user_data_ptr);
        ok(status == INFIX_SUCCESS, "Provider closure created");

        if (inner_t && provider_cl) {

            int result = call_returned_callback_harness((callback_provider)infix_reverse_get_code(provider_cl), 7);
            ok(result == 70, "Closure returned correct function pointer (7 * 10 = 70)");
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(provider_cl);
        infix_reverse_destroy(inner_t);
    }
}
