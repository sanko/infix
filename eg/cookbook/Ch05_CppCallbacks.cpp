/**
 * @file Ch05_Rec05_CppCallbacks.cpp
 * @brief Cookbook Chapter 5, Recipe 5: Bridging C++ Callbacks
 *
 * This example demonstrates a powerful two-way FFI interaction: providing a
 * C-side stateful callback to a C++ method.
 *
 * 1. A C++ `EventManager` class is exposed via its mangled method names.
 * 2. The C side creates a stateful `infix` closure.
 * 3. The C side calls the C++ `set_handler` method, passing the closure's raw
 *    function pointer and its state pointer (`user_data`).
 * 4. The C side then calls the C++ `trigger` method, which causes the C++ object
 *    to invoke the C callback, correctly passing back the state pointer.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <infix/infix.h>

#ifdef __cplusplus
}
#endif

#include <stdio.h>
#include <stdlib.h>

// On GCC/Clang, find these with: nm -C libeventmanager.so | grep EventManager
#if defined(__GNUC__) || defined(__clang__)
const char * MANGLED_CTOR = "_ZN12EventManagerC1Ev";
const char * MANGLED_SET_HANDLER = "_ZN12EventManager11set_handlerEPFviPvES0_";
const char * MANGLED_TRIGGER = "_ZN12EventManager7triggerEi";
#elif defined(_MSC_VER)
// NOTE: These names are illustrative and may need to be adjusted for your specific MSVC version.
const char * MANGLED_CTOR = "??0EventManager@@QEAA@XZ";
const char * MANGLED_SET_HANDLER = "?set_handler@EventManager@@QEAAXP6AXHPEAX@Z0@Z";
const char * MANGLED_TRIGGER = "?trigger@EventManager@@QEAAXH@Z";
#endif

#if defined(_WIN32)
const char * LIB_NAME = "eventmanager.dll";
#else
const char * LIB_NAME = "./libeventmanager.so";
#endif

typedef struct {
    int call_count;
} C_AppState;

void my_closure_handler(infix_context_t * context, void * ret, void ** args) {
    (void)ret;
    C_AppState * state = (C_AppState *)infix_reverse_get_user_data(context);
    state->call_count++;
    int value_from_cpp = *(int *)args[0];
    printf("  -> C handler called (invocation #%d)! Received value: %d\n", state->call_count, value_from_cpp);
}

int main() {
    printf("--- Cookbook Chapter 5, Recipe 5: Bridging C++ Callbacks ---\n");

    infix_library_t * lib = infix_library_open(LIB_NAME);
    if (!lib) {
        fprintf(stderr, "Failed to open library '%s'.\n", LIB_NAME);
        return 1;
    }

    size_t (*get_size)() = (size_t (*)())infix_library_get_symbol(lib, "EventManager_get_size");
    void * p_ctor = infix_library_get_symbol(lib, MANGLED_CTOR);
    void * p_set_handler = infix_library_get_symbol(lib, MANGLED_SET_HANDLER);
    void * p_trigger = infix_library_get_symbol(lib, MANGLED_TRIGGER);

    if (!get_size || !p_ctor || !p_set_handler || !p_trigger) {
        fprintf(stderr, "Failed to find one or more mangled C++ symbols.\n");
        infix_library_close(lib);
        return 1;
    }

    infix_registry_t * reg = infix_registry_create();
    const char * defs = "@CallbackFn = *((int, *void)->void);";
    if (infix_register_types(reg, defs) != INFIX_SUCCESS) /* ... */
        return 1;


    // 1. Create the C-side state and the infix closure to manage it.
    C_AppState app_state = {0};
    infix_reverse_t * closure = NULL;
    (void)infix_reverse_create_closure(&closure, "(int, *void)->void", my_closure_handler, &app_state, NULL);

    // 2. Create an instance of the C++ EventManager object by calling its constructor.
    printf("Allocating %zu bytes for C++ object.\n", get_size());
    void * manager_obj = malloc(get_size());

    infix_forward_t * t_ctor;
    (void)infix_forward_create(&t_ctor, "(*void)->void", p_ctor, NULL);

    // The constructor's only argument is the `this` pointer. Its value is the
    // address stored in `manager_obj`. The args array must contain a pointer
    // to the `manager_obj` variable itself.
    void * ctor_args[] = {&manager_obj};
    infix_forward_get_code(t_ctor)(NULL, ctor_args);

    // 3. Call the C++ `set_handler` method to register our closure's components.
    infix_forward_t * t_set_handler;
    const char * sig = "(*void, @CallbackFn, *void)->void";
    (void)infix_forward_create(&t_set_handler, sig, p_set_handler, reg);

    void * closure_c_func = infix_reverse_get_code(closure);
    void * set_handler_args[] = {&manager_obj, &closure_c_func, &closure};
    infix_forward_get_code(t_set_handler)(NULL, set_handler_args);

    // 4. Call the C++ `trigger` method to make it invoke our C callback.
    infix_forward_t * t_trigger;
    (void)infix_forward_create(&t_trigger, "(*void, int)->void", p_trigger, NULL);

    int value_to_send = 42;
    void * trigger_args[] = {&manager_obj, &value_to_send};
    infix_forward_get_code(t_trigger)(NULL, trigger_args);  // First call

    value_to_send = 99;
    infix_forward_get_code(t_trigger)(NULL, trigger_args);  // Second call

    printf("\nFinal C-side call count: %d (Expected: 2)\n", app_state.call_count);

    // In a real app, you would call the mangled destructor here.
    free(manager_obj);
    infix_forward_destroy(t_ctor);
    infix_forward_destroy(t_set_handler);
    infix_forward_destroy(t_trigger);
    infix_reverse_destroy(closure);
    infix_registry_destroy(reg);
    infix_library_close(lib);

    return 0;
}
