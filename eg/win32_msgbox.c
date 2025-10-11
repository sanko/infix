/*
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */

#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>  // For LoadLibraryA and GetProcAddress

int main() {
    // 1. Load the User32 library and get the function pointer.
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (!user32)
        return 1;

    void * MessageBoxW_ptr = (void *)GetProcAddress(user32, "MessageBoxW");
    if (!MessageBoxW_ptr)
        return 1;

    // 2. Describe the function signature using the high-level string API.
    // Signature for int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
    // HWND and LPCWSTR are pointer types (*void), and UINT is a 32-bit uint.
    const char * signature = "(*void, *void, *void, uint) -> int";

    // 3. Generate the trampoline from the signature.
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 4. Prepare arguments. Windows uses UTF-16 for wide strings, so we use the L"" prefix.
    HWND hwnd = NULL;  // No owner window
    const wchar_t * text = L"This is a message from infix!";
    const wchar_t * caption = L"infix FFI Test";
    UINT type = 0x00000040L;  // MB_ICONINFORMATION

    void * args[] = {&hwnd, &text, &caption, &type};
    int result = 0;

    // 5. Call the function.
    ((infix_unbound_cif_func)infix_forward_get_code(trampoline))((void *)MessageBoxW_ptr, &result, args);
    printf("MessageBoxW returned: %d\n", result);

    // 6. Clean up.
    infix_forward_destroy(trampoline);
    FreeLibrary(user32);

    return 0;
}
