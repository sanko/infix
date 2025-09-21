#pragma once
/**
 * @file infix.h
 * @brief The main public header for the infix FFI library.
 * @copyright Copyright (c) 2025 Sanko Robinson
 *
 * @mainpage Infix FFI Library
 *
 * @section intro_sec Introduction
 *
 * Welcome to the documentation for **infix**, a powerful and flexible Foreign Function
 * Interface (FFI) library for C. Infix simplifies the process of calling C functions
 * from other environments and creating C-callable function pointers from foreign handlers.
 *
 * The core of the library is a Just-in-Time (JIT) compiler that generates small,
 * highly-optimized "trampoline" functions at runtime. These trampolines correctly
 * handle the low-level Application Binary Interface (ABI) for the target platform,
 * ensuring seamless interoperability.
 *
 * This file, `infix.h`, is the only header you need to include to use the library.
 * It contains the entire public API, type system, and platform-detection logic.
 *
 * @section features_sec Key Features
 *
 * - **Forward Calls:** Call any C function dynamically by providing a function pointer
 *   and its arguments at runtime. The library generates a trampoline that correctly
 *   places arguments in registers and on the stack according to the platform's ABI.
 *
 * - **Reverse Calls (Callbacks):** Create native C function pointers from your own
 *   handlers (e.g., functions from an embedded scripting language). These pointers
 *   can be passed to C libraries that require callbacks. When the C code invokes the
 *   pointer, the infix trampoline marshals the arguments and passes them to your handler.
 *
 * - **High-Level Signature API:** Define complex function signatures, including
 *   structs, unions, arrays, and variadic arguments, using a simple and readable
 *   string format. This is the recommended way to interact with the library.
 *
 * - **Manual Type System:** For advanced use cases, provides a complete set of
 *   functions to manually construct `ffi_type` descriptors for any C data type.
 *
 * - **Cross-Platform and Cross-Architecture:** Designed to be portable, with
 *   initial support for x86-64 (System V and Windows x64) and AArch64 (AAPCS64).
 *
 * - **Security-Conscious Design:** Enforces Write XOR Execute (W^X) memory policies
 *   for JIT-compiled code to mitigate security vulnerabilities.
 *
 * - **Customizable Memory Management:** Allows users to override `malloc`, `free`,
 *   etc., to integrate the library with custom memory allocators or pools.
 *
 * @section concepts_sec Core Concepts
 *
 * - **`ffi_type`:** The central data structure that describes any C type, from a
 *   simple `int` to a complex, nested `struct`. The library uses this metadata to
 *   understand how to handle data according to ABI rules.
 *
 * - **Trampoline:** A small piece of machine code JIT-compiled by infix. It acts as
 *   a bridge between a generic calling convention and a specific, native C function
 *   signature.
 *
 * - **Forward Trampoline (`ffi_trampoline_t`):** Enables calls *from* a generic
 *   environment *into* a specific C function. You invoke it with a standard
 *   interface (`target_function`, `return_value`, `args_array`), and it executes a
 *   native call.
 *
 * - **Reverse Trampoline (`ffi_reverse_trampoline_t`):** A C function pointer that
 *   wraps a foreign handler. When called by native C code, it translates the native
 *   arguments into a generic format and calls your handler.
 *
 * - **Arena Allocator (`arena_t`):** An efficient memory allocator used internally,
 *   especially by the high-level signature parser, to manage the memory for complex
 *   `ffi_type` object graphs with a single `free` operation. It is also exposed as
 *   part of the public API for performance-critical applications.
 *
 * @section usage_sec Basic Usage
 *
 * The easiest way to use infix is with the high-level signature API.
 *
 * **Example: Creating a forward trampoline to call `printf`**
 * ```c
 * #include <stdio.h>
 * #include "infix.h"
 *
 * int main() {
 *     ffi_trampoline_t* trampoline = NULL;
 *     const char* signature = "i*,i=>i"; // const char*, int => int
 *
 *     ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, signature);
 *     if (status != FFI_SUCCESS) {
 *         // Handle error
 *         return 1;
 *     }
 *
 *     ffi_cif_func cif = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
 *
 *     const char* my_string = "Hello, Infix! The number is %d\n";
 *     int my_int = 42;
 *     int printf_ret;
 *
 *     void* args[] = { &my_string, &my_int };
 *
 *     cif(&printf, &printf_ret, args);
 *
 *     printf("printf returned: %d\n", printf_ret); // Should match the number of chars printed
 *
 *     ffi_trampoline_free(trampoline);
 *     return 0;
 * }
 * ```
 *
 * @section license_sec Licensing
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
 * @defgroup version_macros Version Information
 * @brief Macros defining the semantic version of the infix library.
 * @details The versioning scheme follows Semantic Versioning 2.0.0 (SemVer).
 * - **MAJOR** version is incremented for incompatible API changes.
 * - **MINOR** version is incremented for adding functionality in a backward-compatible manner.
 * - **PATCH** version is incremented for making backward-compatible bug fixes.
 * @{
 */
/** @brief The major version of the infix library. Incremented for breaking API changes. */
#define INFIX_MAJOR 0
/** @brief The minor version of the infix library. Incremented for new, backward-compatible features. */
#define INFIX_MINOR 1
/** @brief The patch version of the infix library. Incremented for backward-compatible bug fixes. */
#define INFIX_PATCH 0
/** @} */

// Define the POSIX source macro to ensure function declarations for shm_open,
// ftruncate, etc., are visible on all POSIX-compliant systems.
// This must be defined before any system headers are included.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

// Define the POSIX source macro to ensure function declarations for posix_memalign
// are visible. This must be defined before any system headers are included.
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @brief The central structure for describing any data type in the FFI system. */
typedef struct ffi_type_t ffi_type;
/** @brief Describes a single member of an aggregate type (struct or union). */
typedef struct ffi_struct_member_t ffi_struct_member;
/** @brief An opaque handle to a JIT-compiled forward-call trampoline. */
typedef struct ffi_trampoline_handle_t ffi_trampoline_t;
/** @brief An opaque handle to the context of a reverse-call trampoline (callback). */
typedef struct ffi_reverse_trampoline_t ffi_reverse_trampoline_t;
/** @brief An opaque handle to a memory arena for fast, temporary allocations. */
typedef struct arena_t arena_t;

//~ /** @brief Describes a single member of an aggregate type (struct or union). */
//~ struct ffi_struct_member_t;

/**
 * @enum ffi_type_category
 * @brief Enumerates the fundamental categories of types supported by the FFI system.
 */
typedef enum {
    FFI_TYPE_PRIMITIVE,           ///< A built-in type like `int`, `float`, `double`.
    FFI_TYPE_POINTER,             ///< A generic `void*` pointer type.
    FFI_TYPE_STRUCT,              ///< A user-defined structure (`struct`).
    FFI_TYPE_UNION,               ///< A user-defined union (`union`).
    FFI_TYPE_ARRAY,               ///< A fixed-size array.
    FFI_TYPE_REVERSE_TRAMPOLINE,  ///< A callback wrapper.
    FFI_TYPE_VOID                 ///< The `void` type, used for function returns with no value.
} ffi_type_category;

/**
 * @enum ffi_primitive_type_id
 * @brief Enumerates the specific primitive C types supported by the FFI system.
 * @see https://en.wikipedia.org/wiki/C_data_types
 */
typedef enum {
    FFI_PRIMITIVE_TYPE_BOOL,        ///< `bool` or `_Bool`
    FFI_PRIMITIVE_TYPE_UINT8,       ///< `unsigned char`, `uint8_t`
    FFI_PRIMITIVE_TYPE_SINT8,       ///< `signed char`, `int8_t`
    FFI_PRIMITIVE_TYPE_UINT16,      ///< `unsigned short`, `uint16_t`
    FFI_PRIMITIVE_TYPE_SINT16,      ///< `signed short`, `int16_t`
    FFI_PRIMITIVE_TYPE_UINT32,      ///< `unsigned int`, `uint32_t`
    FFI_PRIMITIVE_TYPE_SINT32,      ///< `signed int`, `int32_t`
    FFI_PRIMITIVE_TYPE_UINT64,      ///< `unsigned long long`, `uint64_t`
    FFI_PRIMITIVE_TYPE_SINT64,      ///< `signed long long`, `int64_t`
    FFI_PRIMITIVE_TYPE_UINT128,     ///< `__uint128_t` (GCC/Clang specific)
    FFI_PRIMITIVE_TYPE_SINT128,     ///< `__int128_t` (GCC/Clang specific)
    FFI_PRIMITIVE_TYPE_FLOAT,       ///< `float`
    FFI_PRIMITIVE_TYPE_DOUBLE,      ///< `double`
    FFI_PRIMITIVE_TYPE_LONG_DOUBLE  ///< `long double`
} ffi_primitive_type_id;

/**
 * @struct ffi_type
 * @brief The central structure for describing any data type in the FFI system.
 *
 * This structure provides the FFI code generator with the necessary metadata
 * (size, alignment, category, and contents) to correctly handle arguments and
 * return values according to the target ABI.
 */
struct ffi_type_t {
    ffi_type_category category;  ///< The fundamental category of the type.
    size_t size;                 ///< The total size of the type in bytes, per `sizeof`.
    size_t alignment;            ///< The alignment requirement of the type in bytes, per `_Alignof`.
    bool is_arena_allocated;  ///< If true, this type was allocated from an arena and should not be individually freed.
                              /** @brief Type-specific metadata. */
    union {
        /** @brief For `FFI_TYPE_PRIMITIVE`. */
        ffi_primitive_type_id primitive_id;
        /** @brief For `FFI_TYPE_STRUCT` and `FFI_TYPE_UNION`. */
        struct {
            ffi_struct_member * members;  ///< Array of members for the aggregate.
            size_t num_members;           ///< Number of members in the aggregate.
        } aggregate_info;
        /** @brief For `FFI_TYPE_ARRAY`. */
        struct {
            struct ffi_type_t * element_type;  ///< The type of elements in the array.
            size_t num_elements;               ///< The number of elements in the array.
        } array_info;
        /** @brief For `FFI_TYPE_REVERSE_TRAMPOLINE`. */
        struct {
            struct ffi_type_t * return_type;  ///< Reverse trampoline return value.
            struct ffi_type_t ** arg_types;   ///< Arg list
            size_t num_args;                  ///< The total number of fixed and variadic arguments.
            size_t num_fixed_args;            ///< The number of non-variadic arguments.
        } func_ptr_info;
    } meta;
};

/**
 * @struct ffi_struct_member
 * @brief Describes a single member of an aggregate type (struct or union).
 * @details This structure provides the necessary metadata to define the layout of
 * a C struct or union, which is essential for correct ABI classification.
 */
struct ffi_struct_member_t {
    const char * name;  ///< The name of the member (for debugging/reflection).
    ffi_type * type;    ///< An `ffi_type` describing the member's type.
    size_t offset;      ///< The byte offset of the member from the start of the aggregate.
};

// Provides C23 compatibility shims for older language standards.
// This is included *after* the core types are defined.
#include <compat_c23.h>

// Configurable Memory Allocators
#ifndef infix_malloc
/**
 * @def infix_malloc
 * @brief A macro for the memory allocation function used by the library.
 * @details By default, this maps to the standard `malloc`. Users can define this
 * macro before including `infix.h` to redirect all memory allocations to a custom
 * allocator (e.g., for memory pooling or tracking).
 */
#define infix_malloc malloc
#endif
#ifndef infix_calloc
/**
 * @def infix_calloc
 * @brief A macro for the zero-initializing memory allocation function.
 * @details Defaults to `calloc`. Can be overridden for custom memory management.
 */
#define infix_calloc calloc
#endif
#ifndef infix_realloc
/**
 * @def infix_realloc
 * @brief A macro for the memory reallocation function.
 * @details Defaults to `realloc`. Can be overridden for custom memory management.
 */
#define infix_realloc realloc
#endif
#ifndef infix_free
/**
 * @def infix_free
 * @brief A macro for the memory deallocation function.
 * @details Defaults to `free`. Can be overridden for custom memory management.
 */
#define infix_free free
#endif
#ifndef infix_memcpy
/**
 * @def infix_free
 * @brief A macro for the copy memory to a new pointer.
 * @details Defaults to `memcpy`. Can be overridden for custom memory management.
 */
#define infix_memcpy memcpy
#endif
#ifndef infix_memset
/**
 * @def infix_free
 * @brief A macro for the set memory to a value.
 * @details Defaults to `memset`. Can be overridden for custom memory management.
 */
#define infix_memset memset
#endif


/**
 * @brief This section automatically detects the operating system, CPU architecture,
 * compiler, and the corresponding Application Binary Interface (ABI).
 *
 * The following preprocessor macros will be defined based on the build environment:
 *
 * Operating System:
 * - FFI_OS_WINDOWS:       Microsoft Windows
 * - FFI_OS_MACOS:         Apple macOS
 * - FFI_OS_IOS:           Apple iOS
 * - FFI_OS_LINUX:         Linux (excluding Android)
 * - FFI_OS_ANDROID:       Android
 * - FFI_OS_TERMUX:        Termux on Android
 * - FFI_OS_FREEBSD:       FreeBSD
 * - FFI_OS_OPENBSD:       OpenBSD
 * - FFI_OS_NETBSD:        NetBSD
 * - FFI_OS_DRAGONFLY:     DragonFly BSD
 * - FFI_OS_SOLARIS:       Oracle Solaris
 * - FFI_OS_HAIKU:         Haiku OS
 *
 * Processor Architecture:
 * - FFI_ARCH_X64:         x86-64 / AMD64
 * - FFI_ARCH_AARCH64:     ARM64
 * - FFI_ARCH_X86:         x86 (32-bit)
 * - FFI_ARCH_ARM:         ARM (32-bit)
 *
 * Application Binary Interface (ABI):
 * - FFI_ABI_WINDOWS_X64:  Microsoft x64 Calling Convention
 * - FFI_ABI_SYSV_X64:     System V AMD64 ABI
 * - FFI_ABI_AAPCS64:      ARM 64-bit Procedure Call Standard
 *
 * Compiler:
 * - FFI_COMPILER_MSVC:    Microsoft Visual C++
 * - FFI_COMPILER_CLANG:   Clang
 * - FFI_COMPILER_GCC:     GNU Compiler Collection
 * - FFI_COMPILER_INTEL:   Intel C/C++ Compiler
 * - FFI_COMPILER_IBM:     IBM XL C/C++
 * - FFI_COMPILER_NFI:     Unknown compiler
 *
 * Environment:
 * - FFI_ENV_POSIX:         Defined for POSIX-compliant systems (macOS, Linux, BSDs, etc.)
 * - FFI_ENV_MSYS:         MSYS/MSYS2 build environment
 * - FFI_ENV_CYGWIN:       Cygwin environment
 * - FFI_ENV_MINGW:        MinGW/MinGW-w64 compilers
 * - FFI_ENV_TERMUX:       Termux running on Android or Chrome OS
 *
 */

// Host Platform and Architecture Detection
// This block ALWAYS detects the native host. It is NOT overridden by the ABI flag.
#if defined(_WIN32)
// #warning "OS: Detected _WIN32. Defining FFI_OS_WINDOWS."
#define FFI_OS_WINDOWS
#include <windows.h>
#if defined(__MSYS__)
/** @def FFI_ENV_MSYS Defined for MSYS/MSYS2 build environments. */
#define FFI_ENV_MSYS 1
#elif defined(__CYGWIN__)
/** @def FFI_ENV_CYGWIN Defined for the Cygwin environment. */
#define FFI_ENV_CYGWIN 1
#define FFI_ENV_POSIX 1
#elif defined(__MINGW32__) || defined(__MINGW64__)
/** @def FFI_ENV_MINGW Defined for MinGW/MinGW-w64 compilers. */
#define FFI_ENV_MINGW 1
#endif
#elif defined(__TERMUX__)
// #warning "OS: Detected __TERMUX__. Defining FFI_OS_TERMUX, FFI_OS_ANDROID, FFI_OS_LINUX, FFI_ENV_POSIX."
#define FFI_OS_TERMUX
#define FFI_OS_ANDROID  // Container
#define FFI_OS_LINUX
#define FFI_ENV_POSIX
/** @def FFI_ENV_TERMUX Defined for Termux running under Android or Chrome OS. */
#define FFI_ENV_TERMUX 1
#elif defined(__ANDROID__)
#define FFI_OS_ANDROID
#define FFI_OS_LINUX  // Android is close enough...
#define FFI_ENV_POSIX
#elif defined(__APPLE__)
#define FFI_ENV_POSIX
#define _DARWIN_C_SOURCE
#include <TargetConditionals.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
// TODO: https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon
#if TARGET_IPHONE_SIMULATOR || TARGET_OS_IPHONE
#define FFI_OS_IOS
#elif TARGET_OS_MAC
#define FFI_OS_MACOS
#else
#error "Unsupported/unknown Apple platform"
#endif
#elif defined(__linux__)
#define FFI_OS_LINUX
#define FFI_ENV_POSIX
#elif defined(__FreeBSD__)
#define FFI_OS_FREEBSD
#define FFI_ENV_POSIX
#elif defined(__OpenBSD__)
#define FFI_OS_OPENBSD
#define FFI_ENV_POSIX
#elif defined(__NetBSD__)
#define FFI_OS_NETBSD
#define FFI_ENV_POSIX
#elif defined(__DragonFly__)
#define FFI_OS_DRAGONFLY
#define FFI_ENV_POSIX
#elif defined(__sun) && defined(__SVR4)
#define FFI_OS_SOLARIS
#define FFI_ENV_POSIX
#elif defined(__HAIKU__)
#define FFI_OS_HAIKU
#define FFI_ENV_POSIX
#else
#warning "Unsupported/unknown operating system"
#endif

#if defined(__clang__)
#define FFI_COMPILER_CLANG
#elif defined(_MSC_VER)
#define FFI_COMPILER_MSVC
#elif defined(__GNUC__)
#define FFI_COMPILER_GCC
#else
#warning "Compiler: Unknown compiler detected."
#define FFI_COMPILER_NFI
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#define FFI_ARCH_AARCH64
#elif defined(__x86_64__) || defined(_M_X64)
#define FFI_ARCH_X64
#else
#error "Unsupported architecture. Only x86-64 and AArch64 are currently supported."
#endif

// Target ABI Logic Selection
// This block determines which ABI implementation to use. It can be overridden
// by a compiler flag, which is useful for cross-ABI testing and fuzzing.

#if defined(FFI_FORCE_ABI_WINDOWS_X64)
#define FFI_ABI_WINDOWS_X64 1
#define FFI_ABI_FORCED 1
#elif defined(FFI_FORCE_ABI_SYSV_X64)
#define FFI_ABI_SYSV_X64 1
#define FFI_ABI_FORCED 1
#elif defined(FFI_FORCE_ABI_AAPCS64)
#define FFI_ABI_AAPCS64 1
#define FFI_ABI_FORCED 1
#endif

// If no ABI was forced, detect it based on the host architecture.
#ifndef FFI_ABI_FORCED
#if defined(FFI_ARCH_AARCH64)
#define FFI_ABI_AAPCS64
#elif defined(FFI_ARCH_X64)
#if defined(FFI_OS_WINDOWS)
#define FFI_ABI_WINDOWS_X64
#else
#define FFI_ABI_SYSV_X64
#endif
#endif
#endif

/**
 * @brief The signature for a generic forward-call trampoline, the "Call InterFace" function.
 * @details This is the function pointer type returned by `ffi_trampoline_get_code`.
 * It provides a standardized way to invoke any C function for which a trampoline was generated.
 * @param target_function A pointer to the native C function to be called.
 * @param return_value A pointer to a buffer where the return value will be stored.
 * @param args An array of pointers, where each element points to an argument's value.
 */
typedef void (*ffi_cif_func)(void * target_function, void * return_value, void ** args);

/**
 * @brief An enumeration of all possible success or failure codes from the public API.
 */
typedef enum {
    FFI_SUCCESS = 0,              ///< The operation completed successfully.
    FFI_ERROR_ALLOCATION_FAILED,  ///< A memory allocation request failed.
    FFI_ERROR_INVALID_ARGUMENT,   ///< An invalid argument was provided to a function.
    FFI_ERROR_UNSUPPORTED_ABI,    ///< The current platform/ABI is not supported.
    FFI_ERROR_LAYOUT_FAILED,      ///< Failed to calculate the call frame layout.
    FFI_ERROR_PROTECTION_FAILED,  ///< Failed to change memory permissions (e.g., `mprotect` or `VirtualProtect`).
    FFI_ERROR_                    ///< An unspecified error occurred.
} ffi_status;

/**
 * @brief Creates an `ffi_type` descriptor for a primitive C type.
 * @details This function returns a pointer to a static, singleton instance for the
 * requested primitive type. These do not need to be freed.
 * @param id The enumerator for the desired primitive type (e.g., `FFI_PRIMITIVE_TYPE_SINT32`).
 * @return A pointer to the static `ffi_type` descriptor. Returns `nullptr` for invalid IDs.
 * @warning The returned pointer must NOT be passed to `ffi_type_destroy`.
 */
c23_nodiscard ffi_type * ffi_type_create_primitive(ffi_primitive_type_id);

/**
 * @brief Creates an `ffi_type` descriptor for a generic pointer.
 * @details Returns a pointer to the static, singleton instance for `void*`.
 * @return A pointer to the static `ffi_type` descriptor for a pointer.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard ffi_type * ffi_type_create_pointer(void);

/**
 * @brief Creates an `ffi_type` descriptor for the `void` type.
 * @details Returns a pointer to the static, singleton instance for `void`, which is
 * used exclusively to describe the return type of functions that return nothing.
 * @return A pointer to the static `ffi_type` for `void`.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard ffi_type * ffi_type_create_void(void);

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a struct.
 * @details Calculates the size and alignment of the struct based on its members,
 * adhering to standard C layout rules.
 *
 * @param[out] out_type On success, this will point to the newly created `ffi_type`.
 * @param members An array of `ffi_struct_member` describing each member of the struct.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note On success, the library takes ownership of the `members` array. On failure, the
 *       caller is responsible for freeing it. The `ffi_type` written to `out_type` must
 *       be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_struct(ffi_type **, ffi_struct_member *, size_t);

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a packed struct.
 * @details This function is used for structs defined with attributes like `__attribute__((packed))`
 *          or `#pragma pack(1)`. Unlike `ffi_type_create_struct`, this function does not
 *          calculate the size and alignment itself. Instead, the caller must provide the
 *          exact size and alignment of the packed struct as determined by their compiler,
 *          typically by using `sizeof(my_packed_struct)` and `_Alignof(my_packed_struct)`.
 *
 * @param[out] out_type On success, this will point to the newly created `ffi_type`.
 * @param total_size The exact size of the packed struct in bytes.
 * @param alignment The alignment of the packed struct in bytes. For most packed structs, this will be 1.
 * @param members An array of `ffi_struct_member` describing each member of the struct. The offsets
 *                within this array must be the correct, packed offsets from `offsetof`.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned `ffi_type` must be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_packed_struct(ffi_type **, size_t, size_t, ffi_struct_member *, size_t);

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a union.
 * @details Calculates the size and alignment of the union based on its members.
 * @param[out] out_type On success, this will point to the newly created `ffi_type`.
 * @param members An array of `ffi_struct_member` describing each member of the union.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note On success, the library takes ownership of the `members` array. On failure, the
 *       caller is responsible for freeing it. The `ffi_type` written to `out_type` must
 *       be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_union(ffi_type **, ffi_struct_member *, size_t);

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a fixed-size array.
 * @param[out] out_type On success, this will point to the newly created `ffi_type`.
 * @param element_type An `ffi_type` describing the type of each element in the array.
 * @param num_elements The number of elements in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note On success, the library takes ownership of the `element_type`. On failure, the
 *       caller is responsible for freeing it. The `ffi_type` written to `out_type` must
 *       be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_array(ffi_type **, ffi_type *, size_t);

/**
 * @brief A factory function to create an `ffi_struct_member`.
 * @details This is a convenience helper for populating the `members` array passed to
 * `ffi_type_create_struct` or `ffi_type_create_union`.
 * @param name The member's name (for debugging; can be `nullptr`).
 * @param type A pointer to the member's `ffi_type`.
 * @param offset The byte offset of the member, obtained via the `offsetof` macro.
 * @return An initialized `ffi_struct_member`.
 */
ffi_struct_member ffi_struct_member_create(const char *, ffi_type *, size_t);

/**
 * @brief Frees a dynamically-allocated `ffi_type` and any nested dynamic types.
 * @details This function safely destroys `ffi_type` objects created with
 * `ffi_type_create_struct`, `_union`, or `_array`. It recursively frees any
 * dynamically-allocated member or element types. It is safe to call this on
 * static types (primitives, pointer, void), in which case it does nothing.
 * @param type The `ffi_type` to destroy. Can be `nullptr`.
 */
void ffi_type_destroy(ffi_type *);

/**
 * @defgroup high_level_api High-Level Signature API
 * @brief Convenience functions for creating trampolines from a signature string.
 * @details This API is the recommended way for most users to interact with infix.
 *          It provides a simple, readable, and powerful way to generate FFI
 *          trampolines without needing to manually construct `ffi_type` objects.
 *          The implementation for these functions is in `src/core/signature.c`.
 * @{
 */
/**
 * @brief Generates a forward-call trampoline for a given function signature.
 * @details This is the core function for enabling calls *into* C code. It JIT-compiles
 * a small function (the trampoline) that takes a standard set of arguments
 * (`target_function`, `return_value_ptr`, `args_array`) and translates them into a
 * native C call that respects the platform's ABI.
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param return_type The `ffi_type` of the function's return value.
 * @param arg_types An array of `ffi_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args For variadic functions, the number of non-variadic arguments. For non-variadic functions, this
 * must equal `num_args`.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned trampoline must be freed with `ffi_trampoline_free`.
 */
c23_nodiscard ffi_status generate_forward_trampoline(ffi_trampoline_t **, ffi_type *, ffi_type **, size_t, size_t);

/**
 * @brief Generates a reverse-call trampoline (a native callable function pointer for a callback).
 * @details Creates a native C function pointer that, when called, will invoke a user-provided
 *          C handler function, marshalling the arguments correctly. This single function
 *          handles both non-variadic and variadic callbacks.
 *
 * @param[out] out_context On success, will point to the new reverse trampoline context.
 * @param return_type The return type of the callback.
 * @param arg_types An array of `ffi_type` pointers for ALL callback arguments (fixed and variadic).
 * @param num_args The TOTAL number of arguments (fixed + variadic).
 * @param num_fixed_args The number of fixed arguments that appear before a potential '...'.
 *        - **For non-variadic functions**, set `num_fixed_args` equal to `num_args`.
 *        - **For variadic functions**, set this to the number of arguments before the ellipsis.
 * @param user_callback_fn A function pointer to the user's C callback handler. Its signature must
 *        match the concrete signature described by `arg_types`.
 * @param user_data A user-defined pointer for passing state to the handler.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned context must be freed with `ffi_reverse_trampoline_free`.
 */
c23_nodiscard ffi_status
generate_reverse_trampoline(ffi_reverse_trampoline_t **, ffi_type *, ffi_type **, size_t, size_t, void *, void *);

/**
 * @brief Frees a forward trampoline and its associated executable memory.
 * @param trampoline The trampoline to free. Can be `nullptr`.
 */
void ffi_trampoline_free(ffi_trampoline_t *);

/**
 * @brief Frees a reverse trampoline, its JIT-compiled stub, and its context.
 * @param reverse_trampoline The reverse trampoline to free. Can be `nullptr`.
 */
void ffi_reverse_trampoline_free(ffi_reverse_trampoline_t *);

/**
 * @brief Retrieves the executable code pointer from a forward trampoline.
 * @param trampoline A handle to a previously created forward trampoline.
 * @return A callable function pointer of type `ffi_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_trampoline_get_code(ffi_trampoline_t *);

/**
 * @brief Retrieves the executable code pointer from a reverse trampoline.
 * @param trampoline A handle to a previously created reverse trampoline.
 * @return A callable function pointer of type `ffi_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_reverse_trampoline_get_code(const ffi_reverse_trampoline_t *);

/**
 * @brief Retrieves the user_data stored with a reverse trampoline.
 * @param trampoline A handle to opaque user_data.
 * @return Opaque pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_reverse_trampoline_get_user_data(const ffi_reverse_trampoline_t *);

/**
 * @defgroup high_level_api High-Level Signature API
 * @brief Convenience functions for creating trampolines from a signature string.
 * @details This API is the recommended way for most users to interact with infix.
 *          It provides a simple, readable, and powerful way to generate FFI
 *          trampolines without needing to manually construct `ffi_type` objects.
 *          The implementation for these functions is in `src/core/signature.c`.
 * @{
 */
/**
 * @brief Generates a forward-call trampoline from a signature string.
 *
 * This is the primary function of the high-level API. It parses a signature
 * string, constructs the necessary `ffi_type` objects internally, generates the
 * trampoline, and cleans up all intermediate type descriptions. The resulting
 * trampoline is self-contained and ready for use.
 *
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param signature A null-terminated string describing the function signature.
 *                  Format: "arg1,arg2;variadic_arg=>ret_type". See cookbook for details.
 *                  Supports packed structs with the syntax: p(size,align){type@offset;...}
 * @return `FFI_SUCCESS` on success, or an error code on failure. `FFI_ERROR_INVALID_ARGUMENT`
 *         is returned for parsing errors.
 * @note The returned trampoline must be freed with `ffi_trampoline_free`.
 */
c23_nodiscard ffi_status ffi_create_forward_trampoline_from_signature(ffi_trampoline_t **, const char *);

/**
 * @brief Generates a reverse-call trampoline (callback) from a signature string.
 *
 * This function parses a signature string to create a native, C-callable function
 * pointer that invokes the provided user handler. It simplifies the creation
 * of callbacks by managing the underlying `ffi_type` objects automatically.
 *
 * @param[out] out_context On success, will point to the new reverse trampoline context.
 * @param signature A null-terminated string describing the callback's signature.
 *                  Format: "arg1,arg2;variadic_arg=>ret_type". Supports packed structs.
 * @param user_callback_fn A function pointer to the user's C callback handler.
 *                         Its signature must match the one described in the string.
 * @param user_data A user-defined pointer for passing state to the handler,
 *                  accessible inside the handler via the context.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned context must be freed with `ffi_reverse_trampoline_free`.
 */
c23_nodiscard ffi_status ffi_create_reverse_trampoline_from_signature(ffi_reverse_trampoline_t **,
                                                                      const char *,
                                                                      void *,
                                                                      void *);

/**
 * @brief Parses a full function signature string into its constituent ffi_type parts.
 * @details This function provides direct access to the signature parser. It creates a
 *          dedicated arena to hold the resulting `ffi_type` object graph for the
 *          entire function signature. This is an advanced function for callers who
 *          need to inspect the type information before or after generating a
 *          trampoline, or for those who wish to use the lower-level
 *          `generate_forward_trampoline` function directly.
 *
 * @param[in]  signature A null-terminated string describing the function signature.
 *                       See the project's documentation for the full signature language.
 * @param[out] out_arena On success, this will be populated with a pointer to the new
 *                       arena that owns the entire parsed type graph. The caller is
 *                       responsible for destroying this arena with `arena_destroy()`.
 * @param[out] out_ret_type On success, will point to the `ffi_type` for the return value.
 *                          This pointer is valid for the lifetime of the arena.
 * @param[out] out_arg_types On success, will point to an array of `ffi_type*` for the
 *                           arguments. This array is also allocated within the arena.
 * @param[out] out_num_args On success, will be set to the total number of arguments.
 * @param[out] out_num_fixed_args On success, will be set to the number of non-variadic arguments.
 *
 * @return Returns `FFI_SUCCESS` if parsing is successful.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if any parameters are null or the
 *         signature string is malformed.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if the internal arena could not be created.
 *
 * @note **Memory Management:** On success, this function transfers ownership of the newly
 *       created arena to the caller. A single call to `arena_destroy(*out_arena)` is
 *       sufficient to free all memory associated with the parsed types. If the
 *       function fails, `*out_arena` will be set to `NULL`.
 */
c23_nodiscard ffi_status ffi_signature_parse(const char *, arena_t **, ffi_type **, ffi_type ***, size_t *, size_t *);

/**
 * @brief Parses a signature string representing a single data type.
 * @details This is a specialized version of the parser for use cases like data
 *          marshalling, serialization, or dynamic type inspection, where you need
 *          to describe a single data type rather than a full function signature.
 *          It creates a dedicated arena to hold the resulting `ffi_type` object
 *          graph for the specified type.
 *
 * @param[out] out_type On success, will point to the newly created `ffi_type`. This
 *                      pointer is valid for the lifetime of the returned arena.
 * @param[out] out_arena On success, will point to the new arena that owns the type
 *                       object graph. The caller is responsible for destroying this
 *                       arena with `arena_destroy()`.
 * @param[in]  signature A string describing the data type (e.g., "i", "d*", "{s@0;i@4}").
 *
 * @return Returns `FFI_SUCCESS` if parsing is successful.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if any parameters are null or the
 *         signature string is malformed or contains trailing characters.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if the internal arena could not be created.
 *
 * @note **Memory Management:** On success, the caller takes ownership of the arena
 *       returned in `*out_arena` and is responsible for its destruction. This
 *       function is the ideal tool for creating the `ffi_type` descriptors needed
 *       for pinning variables or for manually constructing aggregate types.
 */
c23_nodiscard ffi_status ffi_type_from_signature(ffi_type **, arena_t **, const char *);

/**
 * @defgroup signature_specifiers Signature Format Specifiers
 * @brief Defines for characters used in the high-level signature string format.
 * @details These macros provide symbolic names for the characters used to define
 *          types in a signature string, making programmatic string construction
 *          safer and more readable than using magic character literals.
 * @{
 */

// Primitive Types
#define FFI_SIG_VOID 'v'
#define FFI_SIG_BOOL 'b'
#define FFI_SIG_CHAR 'c'
#define FFI_SIG_SINT8 'a'
#define FFI_SIG_UINT8 'h'
#define FFI_SIG_SINT16 's'
#define FFI_SIG_UINT16 't'
#define FFI_SIG_SINT32 'i'
#define FFI_SIG_UINT32 'j'
#define FFI_SIG_LONG 'l'
#define FFI_SIG_ULONG 'm'
#define FFI_SIG_SINT64 'x'
#define FFI_SIG_UINT64 'y'
#define FFI_SIG_SINT128 'n'
#define FFI_SIG_UINT128 'o'
#define FFI_SIG_FLOAT 'f'
#define FFI_SIG_DOUBLE 'd'
#define FFI_SIG_LONG_DOUBLE 'e'

// Type Modifiers and Constructs
#define FFI_SIG_POINTER '*'
#define FFI_SIG_STRUCT_START '{'
#define FFI_SIG_STRUCT_END '}'
#define FFI_SIG_UNION_START '<'
#define FFI_SIG_UNION_END '>'
#define FFI_SIG_ARRAY_START '['
#define FFI_SIG_ARRAY_END ']'
#define FFI_SIG_PACKED_STRUCT 'p'
#define FFI_SIG_FUNC_PTR_START '('
#define FFI_SIG_FUNC_PTR_END ')'

// Delimiters
#define FFI_SIG_MEMBER_SEPARATOR ','
#define FFI_SIG_VARIADIC_SEPARATOR ';'
#define FFI_SIG_OFFSET_SEPARATOR '@'
#define FFI_SIG_NAME_SEPARATOR ':'
#define FFI_SIG_RETURN_SEPARATOR "=>"

/** @} */  // End of signature_specifiers group

/** @} */  // End of high_level_api group

/**
 * @brief Creates and initializes a new memory arena.
 * @details Allocates a single large block of memory to be used for subsequent
 *          arena allocations.
 *
 * @param initial_size The total number of bytes to pre-allocate for the arena.
 * @return A pointer to the new `arena_t`, or `nullptr` if the initial allocation fails.
 */
c23_nodiscard arena_t * arena_create(size_t);

/**
 * @brief Frees an entire memory arena and all objects allocated within it.
 * @details This is the only way to free memory from an arena. Individual
 *          allocations cannot be freed.
 *
 * @param arena The arena to destroy. Can be `nullptr` (no-op).
 */
void arena_destroy(arena_t *);

/**
 * @brief Allocates a block of memory from the arena with a specific alignment.
 * @details This is the core allocation function. It returns a pointer to a block
 *          of memory within the arena, ensuring the pointer is aligned to the
 *          specified boundary.
 *
 * @param arena The arena to allocate from.
 * @param size The number of bytes to allocate.
 * @param alignment The required alignment of the returned pointer (must be a power of two).
 * @return A pointer to the allocated memory, or `nullptr` if the arena is full or
 *         an invalid argument is provided.
 */
c23_nodiscard void * arena_alloc(arena_t *, size_t, size_t);

/**
 * @brief Allocates a zero-initialized block of memory from the arena.
 * @details A convenience wrapper around `arena_alloc` that also sets the memory
 *          to zero, similar to `calloc`.
 *
 * @param arena The arena to allocate from.
 * @param num The number of elements to allocate.
 * @param size The size of each element.
 * @param alignment The required alignment of the returned pointer.
 * @return A pointer to the zero-initialized memory, or `nullptr` on failure.
 */
c23_nodiscard void * arena_calloc(arena_t *, size_t, size_t, size_t);
