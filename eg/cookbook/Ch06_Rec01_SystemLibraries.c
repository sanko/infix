/**
 * @file Ch06_Rec01_SystemLibraries.c
 * @brief Cookbook Chapter 6, Recipe 1: Calling Native System Libraries
 *
 * This example demonstrates how to dynamically load a system library (like
 * `user32.dll` on Windows) at runtime, look up a function by name, and call it
 * using an `infix` trampoline. This technique avoids the need to link against
 * the library's import library at compile time.
 */
#include <infix/infix.h>
#include <stdio.h>

// This entire example is platform-specific.
#if defined(_WIN32)
#include <windows.h>  // For UINT, etc.

int main() {
    printf("--- Cookbook Chapter 6, Recipe 1: Calling Native System Libraries ---\n");

    // 1. Open the system library by name. The OS will find it in the system path.
    infix_library_t * user32 = infix_library_open("user32.dll");
    if (!user32) {
        fprintf(stderr, "Failed to open user32.dll.\n");
        return 1;
    }
    printf("Successfully opened user32.dll.\n");

    // 2. Look up the address of the `MessageBoxA` function.
    void * pMessageBoxA = infix_library_get_symbol(user32, "MessageBoxA");
    if (!pMessageBoxA) {
        fprintf(stderr, "Failed to find symbol 'MessageBoxA'.\n");
        infix_library_close(user32);
        return 1;
    }
    printf("Found 'MessageBoxA' at address %p.\n", pMessageBoxA);

    // 3. Define the signature for:
    //    int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    //    Note: HWND is a pointer type, LPCSTR is *char, and UINT is uint32.
    const char * sig = "(*void, *char, *char, uint32) -> int";
    infix_forward_t * t = NULL;
    (void)infix_forward_create(&t, sig, pMessageBoxA, NULL);
    if (!t) {
        fprintf(stderr, "Failed to create trampoline.\n");
        infix_library_close(user32);
        return 1;
    }

    // 4. Prepare arguments and call the function.
    void * hwnd = NULL;  // No parent window
    const char * text = "Hello from a dynamically loaded function!";
    const char * caption = "infix FFI Example";
    uint32_t type = 0x00000040L;  // MB_OK | MB_ICONINFORMATION
    void * args[] = {&hwnd, &text, &caption, &type};
    int result;

    printf("Calling MessageBoxA via FFI... (a dialog box should appear)\n");
    infix_forward_get_code(t)(&result, args);
    printf("MessageBoxA returned: %d\n", result);

    // 5. Clean up.
    infix_forward_destroy(t);
    infix_library_close(user32);

    return 0;
}
#else
// Dummy implementation for non-Windows platforms to allow compilation.
int main() {
    printf("--- Cookbook Chapter 6, Recipe 1: Calling Native System Libraries ---\n");
    printf("SKIPPED: This example is for Windows only.\n");
    return 0;
}
#endif
