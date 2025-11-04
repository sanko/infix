/**
 * @file Ch02_Enums.c
 * @brief Cookbook Chapter 2: Working with Enums
 *
 * This example shows how to handle C `enum` types. For the purpose of an FFI
 * call, an enum behaves identically to its underlying integer type (which is
 * `int` by default, unless specified otherwise).
 *
 * The `infix` signature `e:<type>` is used to represent an enum. This makes the
 * signature more descriptive, but for ABI purposes, it is treated exactly like
 * its underlying `<type>`.
 */
#include <infix/infix.h>
#include <stdio.h>

// A native C enum and a function that uses it.
typedef enum { STATUS_OK = 0, STATUS_WARN = 1, STATUS_ERR = -1 } StatusCode;

static const char * status_to_string(StatusCode code) {
    switch (code) {
    case STATUS_OK:
        return "OK";
    case STATUS_WARN:
        return "Warning";
    case STATUS_ERR:
        return "Error";
    default:
        return "Unknown";
    }
}

int main() {
    printf("--- Cookbook Chapter 2: Working with Enums ---\n");

    // 1. Describe the signature for: const char* status_to_string(StatusCode code);
    //    The C `enum` is based on `int`, so we describe it as `e:int`.
    const char * signature = "(e:int) -> *char";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)status_to_string, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Pass the enum value as its underlying integer type.
    int code = STATUS_ERR;
    const char * result_str = NULL;
    void * args[] = {&code};

    // 4. Call the function.
    cif(&result_str, args);

    printf("Calling status_to_string() with enum value STATUS_ERR...\n");
    printf("Result: '%s' (Expected: 'Error')\n", result_str);

    // 5. Clean up.
    infix_forward_destroy(t);

    return 0;
}
