/**
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

/**
 * @file loader.c
 * @brief Implements the cross-platform dynamic library loading and symbol resolution API.
 * @ingroup internal_core
 *
 * @internal
 * This file provides a crucial hardware abstraction layer (HAL) for interacting
 * with dynamic libraries (e.g., `.so`, `.dylib`, `.dll`). It abstracts the
 * platform-specific system calls for loading libraries, looking up symbol
 * addresses, and unloading libraries into a single, consistent internal API.
 *
 * This abstraction allows the rest of the infix library to operate on library
 * and symbol handles without needing to know the underlying operating system.
 * @endinternal
 */

#include "common/infix_internals.h"

// Platform-specific headers for dynamic library handling.
#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

/**
 * @internal
 * @struct infix_library_t
 * @brief An opaque internal handle to a loaded dynamic library.
 * @details This struct is a simple wrapper that holds the native OS handle for
 * a loaded library. On Windows, this is an `HMODULE`. On POSIX-compliant
 * systems (Linux, macOS, BSD), this is a `void*` pointer. By using this
 * wrapper, the rest of the library can treat library handles generically.
 */
struct infix_library_t {
    void * handle;
};

/**
 * @internal
 * @brief Opens a dynamic library and returns a handle to it.
 * @details This is a cross-platform wrapper around `LoadLibraryA` (Windows) and
 * `dlopen` (POSIX). It attempts to load the specified library into the current
 * process's address space.
 *
 * @param path The file path to the dynamic library.
 * @return A pointer to an `infix_library_t` handle on success, or `nullptr` if
 *         the library could not be found or loaded. The returned handle must
 *         be freed with `infix_library_close`.
 */
c23_nodiscard infix_library_t * infix_library_open(const char * path) {
    if (path == nullptr)
        return nullptr;

    // Allocate memory for our opaque wrapper struct.
    infix_library_t * lib = infix_malloc(sizeof(infix_library_t));
    if (lib == nullptr)
        return nullptr;

#if defined(INFIX_OS_WINDOWS)
    // On Windows, use LoadLibraryA to load the DLL.
    // 'A' specifies the ANSI version, which matches the `const char*` input.
    lib->handle = LoadLibraryA(path);
#else
    // On POSIX systems, use dlopen.
    // - RTLD_LAZY: Resolves symbols only when they are first used (lazy binding),
    //   which can improve startup performance.
    // - RTLD_GLOBAL: Makes symbols from this library available for resolution
    //   by subsequently loaded libraries. This is important for handling
    //   complex dependencies between shared objects.
    lib->handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
#endif

    // Both LoadLibraryA and dlopen return NULL on failure.
    if (lib->handle == nullptr) {
        // If the OS call failed, we must free the wrapper struct we allocated
        // to prevent a memory leak.
        infix_free(lib);
        return nullptr;
    }
    return lib;
}

/**
 * @internal
 * @brief Closes a dynamic library handle and unloads it from the process.
 * @details This is a cross-platform wrapper around `FreeLibrary` (Windows) and
 * `dlclose` (POSIX). It is safe to call with a `nullptr` argument.
 *
 * @param lib A handle to a previously opened library.
 */
void infix_library_close(infix_library_t * lib) {
    if (lib == nullptr)
        return;

    // Only attempt to unload if the native handle is valid.
    if (lib->handle) {
#if defined(INFIX_OS_WINDOWS)
        // On Windows, FreeLibrary decrements the library's reference count.
        // The DLL is unloaded when its reference count reaches zero.
        FreeLibrary((HMODULE)lib->handle);
#else
        // On POSIX, dlclose does the same.
        dlclose(lib->handle);
#endif
    }
    // Finally, free our wrapper struct.
    infix_free(lib);
}

/**
 * @internal
 * @brief Retrieves the memory address of a symbol (function or global variable)
 *        from a loaded dynamic library.
 * @details This is a cross-platform wrapper around `GetProcAddress` (Windows) and
 * `dlsym` (POSIX).
 *
 * @param lib A handle to a previously opened library.
 * @param symbol_name The null-terminated name of the symbol to look up.
 * @return A `void*` pointer to the symbol's address on success, or `nullptr` if
 *         the symbol was not found in the specified library.
 */
c23_nodiscard void * infix_library_get_symbol(infix_library_t * lib, const char * symbol_name) {
    if (lib == nullptr || lib->handle == nullptr || symbol_name == nullptr)
        return nullptr;

#if defined(INFIX_OS_WINDOWS)
    // On Windows, use GetProcAddress. The return type is technically FARPROC,
    // which must be cast to a generic `void*` for our cross-platform API.
    return (void *)GetProcAddress((HMODULE)lib->handle, symbol_name);
#else
    // On POSIX, use dlsym. It directly returns a `void*`.
    return dlsym(lib->handle, symbol_name);
#endif
}

/**
 * @internal
 * @brief Reads a global variable from a library using its type signature for size.
 * @details This is a high-level convenience function that combines symbol lookup
 * with the type system to safely read a global variable.
 *
 * @param lib A handle to a loaded library.
 * @param symbol_name The name of the global variable.
 * @param type_signature A signature string describing the variable's type (e.g., "int").
 * @param[out] buffer A pointer to a user-provided buffer to store the read value.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_read_global(infix_library_t * lib,
                                             const char * symbol_name,
                                             const char * type_signature,
                                             void * buffer) {
    if (buffer == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Find the address of the global variable in the library.
    void * symbol_addr = infix_library_get_symbol(lib, symbol_name);
    if (symbol_addr == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Parse the type signature to determine the size of the variable.
    // This creates a temporary arena to hold the type information.
    infix_type * type = nullptr;
    infix_arena_t * arena = nullptr;
    infix_status status = infix_type_from_signature(&type, &arena, type_signature);

    if (status != INFIX_SUCCESS)
        return status;

    // Perform a memory copy of the correct size.
    memcpy(buffer, symbol_addr, type->size);

    // Clean up the temporary arena used for parsing.
    infix_arena_destroy(arena);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Writes to a global variable in a library using its type signature for size.
 * @details This is a high-level convenience function that combines symbol lookup
 * with the type system to safely write a new value to a global variable.
 *
 * @param lib A handle to a loaded library.
 * @param symbol_name The name of the global variable.
 * @param type_signature A signature string describing the variable's type.
 * @param[in] buffer A pointer to a buffer containing the new value to write.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_write_global(infix_library_t * lib,
                                              const char * symbol_name,
                                              const char * type_signature,
                                              void * buffer) {
    if (buffer == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Find the address of the global variable in the library.
    void * symbol_addr = infix_library_get_symbol(lib, symbol_name);
    if (symbol_addr == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Parse the type signature to determine the size of the variable.
    infix_type * type = nullptr;
    infix_arena_t * arena = nullptr;
    infix_status status = infix_type_from_signature(&type, &arena, type_signature);

    if (status != INFIX_SUCCESS)
        return status;

    // Perform a memory copy of the correct size.
    memcpy(symbol_addr, buffer, type->size);

    // Clean up the temporary arena used for parsing.
    infix_arena_destroy(arena);
    return INFIX_SUCCESS;
}
