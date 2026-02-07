/**
 * eg/cookbook/Ch09_SafeExceptions.c
 *
 * This recipe demonstrates how to use the "Safe Exception Boundary" feature
 * to catch exceptions (C++ or Windows SEH) that occur inside native code,
 * preventing them from crashing your application.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
// A native function that triggers a hardware exception (Access Violation)
void native_crash_func() {
    volatile int * p = nullptr;
    *p = 42;
}
#else
// On POSIX, we'll just simulate a crash or assume a C++ throw if linked correctly.
void native_crash_func() { abort(); }
#endif

int main() {
    printf("Chapter 9: Safe Exception Boundaries");
    // 1. Describe the signature of the crashing function.
    const char * signature = "() -> void";

    // 2. Create a SAFE forward trampoline.
    // Standard infix_forward_create would allow the exception to propagate
    // (crashing if not caught by C++ try/catch). infix_forward_create_safe
    // establishes an internal boundary.
    infix_forward_t * trampoline = nullptr;
    infix_status status = infix_forward_create_safe(&trampoline, signature, (void *)native_crash_func, nullptr);

    if (status != INFIX_SUCCESS) {
        infix_error_details_t err = infix_get_last_error();
        fprintf(stderr, "Failed to create trampoline: %s", err.message);
        return 1;
    }

    // 3. Get the callable function pointer.
    infix_cif_func cif = infix_forward_get_code(trampoline);

    printf("Calling native function that will crash...");

    // 4. Execute the call.
    // The internal boundary will catch the exception and redirect to the epilogue.
    cif(nullptr, nullptr);

    // 5. Check if an exception was caught.
    infix_error_details_t err = infix_get_last_error();
    if (err.code == INFIX_CODE_NATIVE_EXCEPTION)
        printf("SUCCESS: Caught native exception: %s", err.message);
    else
        printf("FAILURE: Exception was not caught (or didn't occur).");

    // 6. Clean up.
    infix_forward_destroy(trampoline);

    printf("Application continues running safely.");
    return 0;
}
