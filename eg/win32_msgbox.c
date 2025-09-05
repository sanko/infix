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

#include <infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>  // For LoadLibraryA and GetProcAddress

int main() {
    // 1. Load the User32 library and get the function pointer.
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (!user32)
        return 1;

    int (*MessageBoxW_ptr)(HWND, LPCWSTR, LPCWSTR, UINT) = (void *)GetProcAddress(user32, "MessageBoxW");
    if (!MessageBoxW_ptr)
        return 1;

    // 2. Describe the function signature.
    ffi_type * ret_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    ffi_type * arg_types[] = {
        ffi_type_create_pointer(),                            // HWND hWnd (handle is a pointer)
        ffi_type_create_pointer(),                            // LPCWSTR lpText (wide string is a pointer)
        ffi_type_create_pointer(),                            // LPCWSTR lpCaption
        ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT32)  // UINT uType
    };

    // 3. Generate the trampoline.
    ffi_trampoline_t * trampoline = NULL;
    (void)generate_forward_trampoline(&trampoline, ret_type, arg_types, 4, 4);

    // 4. Prepare arguments. Windows uses UTF-16 for wide strings, so we use the L"" prefix.
    HWND hwnd = NULL;  // No owner window
    const wchar_t * text = L"This is a message from infix!";
    const wchar_t * caption = L"infix FFI Test";
    UINT type = 0x00000040L;  // MB_ICONINFORMATION

    void * args[] = {&hwnd, &text, &caption, &type};
    int result = 0;

    // 5. Call the function.
    ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void *)MessageBoxW_ptr, &result, args);
    printf("MessageBoxW returned: %d\n", result);

    // 6. Clean up.
    ffi_trampoline_free(trampoline);
    FreeLibrary(user32);

    return 0;
}
