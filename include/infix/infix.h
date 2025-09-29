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
 *   functions to manually construct `infix_type` descriptors for any C data type using
 *   a safe, arena-based memory model.
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
 * - **`infix_type`:** The central data structure that describes any C type, from a
 *   simple `int` to a complex, nested `struct`. The library uses this metadata to
 *   understand how to handle data according to ABI rules.
 *
 * - **Trampoline:** A small piece of machine code JIT-compiled by infix. It acts as
 *   a bridge between a generic calling convention and a specific, native C function
 *   signature.
 *
 * - **Forward Trampoline (`infix_forward_t`):** Enables calls *from* a generic
 *   environment *into* a specific C function. You invoke it with a standard
 *   interface (`target_function`, `return_value`, `args_array`), and it executes a
 *   native call.
 *
 * - **Reverse Trampoline (`infix_reverse_t`):** A C function pointer that
 *   wraps a foreign handler. When called by native C code, it translates the native
 *   arguments into a generic format and calls your handler.
 *
 * - **Arena Allocator (`infix_arena_t`):** An efficient memory allocator used internally,
 *   especially by the high-level signature parser, to manage the memory for complex
 *   `infix_type` object graphs with a single `free` operation. It is also exposed as
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
 *     infix_forward_t* trampoline = NULL;
 *     const char* signature = "i*,i=>i"; // const char*, int => int
 *
 *     infix_status status = infix_forward_create(&trampoline, signature);
 *     if (status != INFIX_SUCCESS) {
 *         // Handle error
 *         return 1;
 *     }
 *
 *     infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
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
 *     infix_forward_destroy(trampoline);
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
#define INFIX_MAJOR 1
/** @brief The minor version of the infix library. Incremented for new, backward-compatible features. */
#define INFIX_MINOR 0
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
typedef struct infix_type_t infix_type;
/** @brief Describes a single member of an aggregate type (struct or union). */
typedef struct infix_struct_member_t infix_struct_member;
/** @brief An opaque handle to a JIT-compiled forward-call trampoline. */
typedef struct infix_forward_t infix_forward_t;
/** @brief An opaque handle to the context of a reverse-call trampoline (callback). */
typedef struct infix_reverse_t infix_reverse_t;
/** @brief A clear alias for `infix_reverse_t`, intended for use in callback handler signatures. */
typedef infix_reverse_t infix_context_t;
/** @brief An opaque handle to a memory arena for fast, temporary allocations. */
typedef struct infix_arena_t infix_arena_t;

/**
 * @enum infix_type_category
 * @brief Enumerates the fundamental categories of types supported by the FFI system.
 */
typedef enum {
    INFIX_TYPE_PRIMITIVE,           ///< A built-in type like `int`, `float`, `double`.
    INFIX_TYPE_POINTER,             ///< A generic `void*` pointer type.
    INFIX_TYPE_STRUCT,              ///< A user-defined structure (`struct`).
    INFIX_TYPE_UNION,               ///< A user-defined union (`union`).
    INFIX_TYPE_ARRAY,               ///< A fixed-size array.
    INFIX_TYPE_REVERSE_TRAMPOLINE,  ///< A callback wrapper.
    INFIX_TYPE_ENUM,                ///< A C-style enumeration, with an underlying integer type.
    INFIX_TYPE_COMPLEX,             ///< A `_Complex` number type.
    INFIX_TYPE_VECTOR,              ///< A SIMD vector type.
    INFIX_TYPE_NAMED_REFERENCE,     ///< A reference to a named type (e.g., `struct<Node>`).
    INFIX_TYPE_VOID                 ///< The `void` type, used for function returns with no value.
} infix_type_category;

/**
 * @enum infix_primitive_type_id
 * @brief Enumerates the specific primitive C types supported by the FFI system.
 * @see https://en.wikipedia.org/wiki/C_data_types
 */
typedef enum {
    INFIX_PRIMITIVE_BOOL,        ///< `bool` or `_Bool`
    INFIX_PRIMITIVE_UINT8,       ///< `unsigned char`, `uint8_t`
    INFIX_PRIMITIVE_SINT8,       ///< `signed char`, `int8_t`
    INFIX_PRIMITIVE_UINT16,      ///< `unsigned short`, `uint16_t`
    INFIX_PRIMITIVE_SINT16,      ///< `signed short`, `int16_t`
    INFIX_PRIMITIVE_UINT32,      ///< `unsigned int`, `uint32_t`
    INFIX_PRIMITIVE_SINT32,      ///< `signed int`, `int32_t`
    INFIX_PRIMITIVE_UINT64,      ///< `unsigned long long`, `uint64_t`
    INFIX_PRIMITIVE_SINT64,      ///< `signed long long`, `int64_t`
    INFIX_PRIMITIVE_UINT128,     ///< `__uint128_t` (GCC/Clang specific)
    INFIX_PRIMITIVE_SINT128,     ///< `__int128_t` (GCC/Clang specific)
    INFIX_PRIMITIVE_FLOAT,       ///< `float`
    INFIX_PRIMITIVE_DOUBLE,      ///< `double`
    INFIX_PRIMITIVE_LONG_DOUBLE  ///< `long double`
} infix_primitive_type_id;

/**
 * @struct infix_type
 * @brief The central structure for describing any data type in the FFI system.
 *
 * This structure provides the FFI code generator with the necessary metadata
 * (size, alignment, category, and contents) to correctly handle arguments and
 * return values according to the target ABI.
 */
struct infix_type_t {
    infix_type_category category;  ///< The fundamental category of the type.
    size_t size;                   ///< The total size of the type in bytes, per `sizeof`.
    size_t alignment;              ///< The alignment requirement of the type in bytes, per `_Alignof`.
    bool is_arena_allocated;  ///< If true, this type was allocated from an arena and should not be individually freed.
    /** @brief Type-specific metadata. */
    union {
        /** @brief For `INFIX_TYPE_PRIMITIVE`. */
        infix_primitive_type_id primitive_id;
        /** @brief For `INFIX_TYPE_POINTER`. */
        struct {
            struct infix_type_t * pointee_type;  ///< The type this pointer points to.
        } pointer_info;
        /** @brief For `INFIX_TYPE_STRUCT` and `INFIX_TYPE_UNION`. */
        struct {
            infix_struct_member * members;  ///< Array of members for the aggregate.
            size_t num_members;             ///< Number of members in the aggregate.
        } aggregate_info;
        /** @brief For `INFIX_TYPE_ARRAY`. */
        struct {
            struct infix_type_t * element_type;  ///< The type of elements in the array.
            size_t num_elements;                 ///< The number of elements in the array.
        } array_info;
        /** @brief For `INFIX_TYPE_REVERSE_TRAMPOLINE`. */
        struct {
            struct infix_type_t * return_type;  ///< Reverse trampoline return value.
            struct infix_type_t ** arg_types;   ///< Arg list
            size_t num_args;                    ///< The total number of fixed and variadic arguments.
            size_t num_fixed_args;              ///< The number of non-variadic arguments.
        } func_ptr_info;
        /** @brief For `INFIX_TYPE_ENUM`. */
        struct {
            struct infix_type_t * underlying_type;  ///< The integer type this enum is based on.
        } enum_info;
        /** @brief For `INFIX_TYPE_COMPLEX`. */
        struct {
            struct infix_type_t * base_type;  ///< The floating point type of the real and imaginary parts.
        } complex_info;
        /** @brief For `INFIX_TYPE_VECTOR`. */
        struct {
            struct infix_type_t * element_type;  ///< The type of the elements in the vector.
            size_t num_elements;                 ///< The number of elements in the vector.
        } vector_info;
        /** @brief For `INFIX_TYPE_NAMED_REFERENCE`. */
        struct {
            const char * name;
        } named_reference;
    } meta;
};

/**
 * @struct infix_struct_member
 * @brief Describes a single member of an aggregate type (struct or union).
 * @details This structure provides the necessary metadata to define the layout of
 * a C struct or union, which is essential for correct ABI classification.
 */
struct infix_struct_member_t {
    const char * name;  ///< The name of the member (for debugging/reflection).
    infix_type * type;  ///< An `infix_type` describing the member's type.
    size_t offset;      ///< The byte offset of the member from the start of the aggregate.
};

// Provides C23 compatibility shims for older language standards.
// This is included *after* the core types are defined.
#include <common/compat_c23.h>

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
 * @def infix_memcpy
 * @brief A macro for the copy memory to a new pointer.
 * @details Defaults to `memcpy`. Can be overridden for custom memory management.
 */
#define infix_memcpy memcpy
#endif
#ifndef infix_memset
/**
 * @def infix_memset
 * @brief A macro for the set memory to a value.
 * @details Defaults to `memset`. Can be overridden for custom memory management.
 */
#define infix_memset memset
#endif

/**
 * @brief The signature for a generic forward-call trampoline, the "Call InterFace" function.
 * @details This is the function pointer type returned by `infix_forward_get_code`.
 * It provides a standardized way to invoke any C function for which a trampoline was generated.
 * @param target_function A pointer to the native C function to be called.
 * @param return_value A pointer to a buffer where the return value will be stored.
 * @param args An array of pointers, where each element points to an argument's value.
 */
typedef void (*infix_cif_func)(void * target_function, void * return_value, void ** args);

/**
 * @brief An enumeration of all possible success or failure codes from the public API.
 */
typedef enum {
    INFIX_SUCCESS = 0,              ///< The operation completed successfully.
    INFIX_ERROR_ALLOCATION_FAILED,  ///< A memory allocation request failed.
    INFIX_ERROR_INVALID_ARGUMENT,   ///< An invalid argument was provided to a function.
    INFIX_ERROR_UNSUPPORTED_ABI,    ///< The current platform/ABI is not supported.
    INFIX_ERROR_LAYOUT_FAILED,      ///< Failed to calculate the call frame layout.
    INFIX_ERROR_PROTECTION_FAILED,  ///< Failed to change memory permissions (e.g., `mprotect` or `VirtualProtect`).
    INFIX_ERROR_                    ///< An unspecified error occurred.
} infix_status;

/**
 * @brief Creates an `infix_type` descriptor for a primitive C type.
 * @details This function returns a pointer to a static, singleton instance for the
 * requested primitive type. These do not need to be freed.
 * @param id The enumerator for the desired primitive type (e.g., `INFIX_PRIMITIVE_SINT32`).
 * @return A pointer to the static `infix_type` descriptor. Returns `nullptr` for invalid IDs.
 * @warning The returned pointer must NOT be passed to any deallocation function.
 */
c23_nodiscard infix_type * infix_type_create_primitive(infix_primitive_type_id);

/**
 * @brief Creates an `infix_type` descriptor for a generic `void*` pointer.
 * @details Returns a pointer to the static, singleton instance for `void*`. This is
 *          useful for opaque handles or when type information is not needed.
 * @return A pointer to the static `infix_type` descriptor for a pointer.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard infix_type * infix_type_create_pointer(void);

/**
 * @brief Creates an `infix_type` for a pointer to a specific type from an arena.
 * @details This function creates a new pointer type descriptor that retains information
 *          about the type it points to, which is essential for introspection.
 *
 * @param arena The arena from which to allocate memory for the new pointer type.
 * @param[out] out_type On success, this will point to the newly created `infix_type`.
 * @param pointee_type An `infix_type` describing the type the pointer points to.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_type_create_pointer_to(infix_arena_t *, infix_type **, infix_type *);

/**
 * @brief Creates an `infix_type` descriptor for the `void` type.
 * @details Returns a pointer to the static, singleton instance for `void`, which is
 * used exclusively to describe the return type of functions that return nothing.
 * @return A pointer to the static `infix_type` for `void`.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard infix_type * infix_type_create_void(void);

/**
 * @brief Creates a new `infix_type` for a struct from an arena.
 * @details Calculates the size and alignment of the struct based on its members,
 * adhering to standard C layout rules. All memory for the new type is allocated
 * from the provided arena.
 *
 * @param arena The arena from which to allocate memory for the new type.
 * @param[out] out_type On success, this will point to the newly created `infix_type`.
 * @param members An array of `infix_struct_member` describing each member of the struct.
 * @param num_members The number of elements in the `members` array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note All allocated memory is owned by the arena.
 */
c23_nodiscard infix_status infix_type_create_struct(infix_arena_t *, infix_type **, infix_struct_member *, size_t);

/**
 * @brief Creates a new `infix_type` for a packed struct from an arena.
 * @details This function is used for structs with non-standard layouts (e.g., from `__attribute__((packed))`).
 * The caller must provide the exact size and alignment. All memory for the new type is
 * allocated from the provided arena.
 *
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, this will point to the newly created `infix_type`.
 * @param total_size The exact size of the packed struct in bytes.
 * @param alignment The alignment of the packed struct in bytes (often 1).
 * @param members An array of `infix_struct_member` describing each member.
 * @param num_members The number of elements in the `members` array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note All allocated memory is owned by the arena.
 */
c23_nodiscard infix_status
infix_type_create_packed_struct(infix_arena_t *, infix_type **, size_t, size_t, infix_struct_member *, size_t);

/**
 * @brief Creates a new `infix_type` for a union from an arena.
 * @details Calculates the size and alignment of the union based on its members.
 * All memory for the new type is allocated from the provided arena.
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, this will point to the newly created `infix_type`.
 * @param members An array of `infix_struct_member` describing each member of the union.
 * @param num_members The number of elements in the `members` array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note All allocated memory is owned by the arena.
 */
c23_nodiscard infix_status infix_type_create_union(infix_arena_t *, infix_type **, infix_struct_member *, size_t);

/**
 * @brief Creates a new `infix_type` for a fixed-size array from an arena.
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, this will point to the newly created `infix_type`.
 * @param element_type An `infix_type` describing the type of each element in the array.
 * @param num_elements The number of elements in the array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note All allocated memory is owned by the arena.
 */
c23_nodiscard infix_status infix_type_create_array(infix_arena_t *, infix_type **, infix_type *, size_t);

/**
 * @brief Creates a new `infix_type` for an enum from an arena.
 * @details An enum is treated as a semantic alias for its underlying integer type for
 * ABI purposes. This function creates a type that has the same size and alignment
 * as its underlying type.
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, will point to the newly created `infix_type`.
 * @param underlying_type The integer `infix_type` that this enum is based on (e.g., `SINT32`).
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_type_create_enum(infix_arena_t *, infix_type **, infix_type *);


c23_nodiscard infix_status infix_type_create_named_reference(infix_arena_t * arena,
                                                             infix_type ** out_type,
                                                             const char * name);


/**
 * @brief A factory function to create an `infix_struct_member`.
 * @details This is a convenience helper for populating the `members` array passed to
 * `infix_type_create_struct` or `infix_type_create_union`.
 * @param name The member's name (for debugging; can be `nullptr`).
 * @param type A pointer to the member's `infix_type`.
 * @param offset The byte offset of the member, obtained via the `offsetof` macro.
 * @return An initialized `infix_struct_member`.
 */
infix_struct_member infix_struct_member_create(const char *, infix_type *, size_t);

/**
 * @defgroup high_level_api High-Level Signature API
 * @brief Convenience functions for creating trampolines from a signature string.
 * @details This API is the recommended way for most users to interact with infix.
 *          It provides a simple, readable, and powerful way to generate FFI
 *          trampolines without needing to manually construct `infix_type` objects.
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
 * @param return_type The `infix_type` of the function's return value.
 * @param arg_types An array of `infix_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args For variadic functions, the number of non-variadic arguments. For non-variadic functions, this
 * must equal `num_args`.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note The returned trampoline must be freed with `infix_forward_destroy`.
 */
c23_nodiscard infix_status infix_forward_create_manual(infix_forward_t **, infix_type *, infix_type **, size_t, size_t);

/**
 * @brief Generates a reverse-call trampoline (a native callable function pointer for a callback).
 * @details Creates a native C function pointer that, when called, will invoke a user-provided
 *          C handler function, marshalling the arguments correctly.
 *
 *          **CRITICAL**: The C handler function you provide (`user_callback_fn`) will **always**
 *          receive a pointer to its `infix_context_t` context as its **first argument**.
 *          The subsequent arguments will match the types described in the signature string. This
 *          context-passing mechanism allows you to create stateful callbacks.
 *
 * ### Handler Signature Example
 * If your `infix` signature string is `"i,d*=>v"`, which corresponds to a C type of
 * `void (*)(int, double*)`, your C handler function **must** have the following signature:
 * ```c
 * void my_c_handler(infix_context_t* context, int arg1, double* arg2);
 * ```
 * You can then retrieve your state within the handler by calling:
 * ```c
 * my_state_t* state = (my_state_t*)infix_reverse_get_user_data(context);
 * ```
 *
 * @param[out] out_context On success, will point to the new reverse trampoline context.
 * @param return_type The return type of the callback as seen by the *native C caller*.
 * @param arg_types An array of `infix_type` pointers for the callback's arguments, *not including*
 *                  the implicit initial context pointer.
 * @param num_args The TOTAL number of arguments in `arg_types`.
 * @param num_fixed_args The number of fixed arguments that appear before a potential '...'.
 * @param user_callback_fn A function pointer to your C callback handler. Its signature must
 *                         start with `infix_context_t*` followed by the types
 *                         described in `arg_types`.
 * @param user_data A user-defined pointer for passing state to the handler.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note The returned context must be freed with `infix_reverse_destroy`.
 */
c23_nodiscard infix_status
infix_reverse_create_manual(infix_reverse_t **, infix_type *, infix_type **, size_t, size_t, void *, void *);

/**
 * @brief Frees a forward trampoline and its associated executable memory.
 * @param trampoline The trampoline to free. Can be `nullptr`.
 */
void infix_forward_destroy(infix_forward_t *);

/**
 * @brief Frees a reverse trampoline, its JIT-compiled stub, and its context.
 * @param reverse_trampoline The reverse trampoline to free. Can be `nullptr`.
 */
void infix_reverse_destroy(infix_reverse_t *);

/**
 * @brief Retrieves the executable code pointer from a forward trampoline.
 * @param trampoline A handle to a previously created forward trampoline.
 * @return A callable function pointer of type `infix_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_forward_get_code(infix_forward_t *);

/**
 * @brief Retrieves the executable code pointer from a reverse trampoline.
 * @param reverse_trampoline A handle to a previously created reverse trampoline.
 * @return A callable function pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_reverse_get_code(const infix_reverse_t *);

/**
 * @brief Retrieves the user_data stored with a reverse trampoline.
 * @param reverse_trampoline A handle to a reverse trampoline context.
 * @return The opaque user_data pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_reverse_get_user_data(const infix_reverse_t *);

/**
 * @defgroup high_level_api High-Level Signature API
 * @brief Convenience functions for creating trampolines from a signature string.
 * @details This API is the recommended way for most users to interact with infix.
 *          It provides a simple, readable, and powerful way to generate FFI
 *          trampolines without needing to manually construct `infix_type` objects.
 *          The implementation for these functions is in `src/core/signature.c`.
 * @{
 */
/**
 * @brief Generates a forward-call trampoline from a signature string.
 *
 * This is the primary function of the high-level API. It parses a signature
 * string, constructs the necessary `infix_type` objects internally, generates the
 * trampoline, and cleans up all intermediate type descriptions. The resulting
 * trampoline is self-contained and ready for use.
 *
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param signature A null-terminated string describing the function signature.
 *                  Format: "arg1,arg2;variadic_arg=>ret_type". See cookbook for details.
 *                  Supports packed structs with the syntax: p(size,align){type@offset;...}
 * @return `INFIX_SUCCESS` on success, or an error code on failure. `INFIX_ERROR_INVALID_ARGUMENT`
 *         is returned for parsing errors.
 * @note The returned trampoline must be freed with `infix_forward_destroy`.
 */
c23_nodiscard infix_status infix_forward_create(infix_forward_t **, const char *);

/**
 * @brief Generates a reverse-call trampoline (callback) from a signature string.
 *
 * This function parses a signature string to create a native, C-callable function
 * pointer that invokes the provided user handler. It simplifies the creation
 * of callbacks by managing the underlying `infix_type` objects automatically.
 *
 * @param[out] out_context On success, will point to the new reverse trampoline context.
 * @param signature A null-terminated string describing the callback's signature.
 *                  Format: "arg1,arg2;variadic_arg=>ret_type". Supports packed structs.
 * @param user_callback_fn A function pointer to the user's C callback handler.
 *                         Its signature must start with `infix_context_t*`, followed
 *                         by the types described in the signature string.
 * @param user_data A user-defined pointer for passing state to the handler,
 *                  accessible inside the handler via `infix_reverse_get_user_data`.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note The returned context must be freed with `infix_reverse_destroy`.
 */
c23_nodiscard infix_status infix_reverse_create(infix_reverse_t **, const char *, void *, void *);

/**
 * @brief Parses a full function signature string into its constituent infix_type parts.
 * @details This function provides direct access to the signature parser. It creates a
 *          dedicated arena to hold the resulting `infix_type` object graph for the
 *          entire function signature. This is an advanced function for callers who
 *          need to inspect the type information before or after generating a
 *          trampoline, or for those who wish to use the lower-level
 *          `infix_forward_create_manual` function directly.
 *
 * @param[in]  signature A null-terminated string describing the function signature.
 *                       See the project's documentation for the full signature language.
 * @param[out] out_arena On success, this will be populated with a pointer to the new
 *                       arena that owns the entire parsed type graph. The caller is
 *                       responsible for destroying this arena with `infix_arena_destroy()`.
 * @param[out] out_ret_type On success, will point to the `infix_type` for the return value.
 *                          This pointer is valid for the lifetime of the arena.
 * @param[out] out_arg_types On success, will point to an array of `infix_type*` for the
 *                           arguments. This array is also allocated within the arena.
 * @param[out] out_num_args On success, will be set to the total number of arguments.
 * @param[out] out_num_fixed_args On success, will be set to the number of non-variadic arguments.
 *
 * @return Returns `INFIX_SUCCESS` if parsing is successful.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any parameters are null or the
 *         signature string is malformed.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if the internal arena could not be created.
 *
 * @note **Memory Management:** On success, this function transfers ownership of the newly
 *       created arena to the caller. A single call to `infix_arena_destroy(*out_arena)` is
 *       sufficient to free all memory associated with the parsed types. If the
 *       function fails, `*out_arena` will be set to `NULL`.
 */
c23_nodiscard infix_status
infix_signature_parse(const char *, infix_arena_t **, infix_type **, infix_type ***, size_t *, size_t *);

/**
 * @brief Parses a signature string representing a single data type.
 * @details This is a specialized version of the parser for use cases like data
 *          marshalling, serialization, or dynamic type inspection, where you need
 *          to describe a single data type rather than a full function signature.
 *          It creates a dedicated arena to hold the resulting `infix_type` object
 *          graph for the specified type.
 *
 * @param[out] out_type On success, will point to the newly created `infix_type`. This
 *                      pointer is valid for the lifetime of the returned arena.
 * @param[out] out_arena On success, will point to the new arena that owns the type
 *                       object graph. The caller is responsible for destroying this
 *                       arena with `infix_arena_destroy()`.
 * @param[in]  signature A string describing the data type (e.g., "i", "d*", "{s@0;i@4}").
 *
 * @return Returns `INFIX_SUCCESS` if parsing is successful.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any parameters are null or the
 *         signature string is malformed or contains trailing characters.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if the internal arena could not be created.
 *
 * @note **Memory Management:** On success, the caller takes ownership of the arena
 *       returned in `*out_arena` and is responsible for its destruction.
 */
c23_nodiscard infix_status infix_type_from_signature(infix_type **, infix_arena_t **, const char *);

/**
 * @defgroup signature_specifiers Signature Format Specifiers
 * @brief Defines for characters used in the high-level signature string format.
 * @details These macros provide symbolic names for the characters used to define
 *          types in a signature string, making programmatic string construction
 *          safer and more readable than using magic character literals.
 * @{
 */

// Primitive Types
#define INFIX_SIG_VOID 'v'
#define INFIX_SIG_BOOL 'b'
#define INFIX_SIG_CHAR 'c'
#define INFIX_SIG_SINT8 'a'
#define INFIX_SIG_UINT8 'h'
#define INFIX_SIG_SINT16 's'
#define INFIX_SIG_UINT16 't'
#define INFIX_SIG_SINT32 'i'
#define INFIX_SIG_UINT32 'j'
#define INFIX_SIG_LONG 'l'
#define INFIX_SIG_ULONG 'm'
#define INFIX_SIG_SINT64 'x'
#define INFIX_SIG_UINT64 'y'
#define INFIX_SIG_SINT128 'n'
#define INFIX_SIG_UINT128 'o'
#define INFIX_SIG_FLOAT 'f'
#define INFIX_SIG_DOUBLE 'd'
#define INFIX_SIG_LONG_DOUBLE 'e'

// Type Modifiers and Constructs
#define INFIX_SIG_POINTER '*'
#define INFIX_SIG_STRUCT_START '{'
#define INFIX_SIG_STRUCT_END '}'
#define INFIX_SIG_UNION_START '<'
#define INFIX_SIG_UNION_END '>'
#define INFIX_SIG_ARRAY_START '['
#define INFIX_SIG_ARRAY_END ']'
#define INFIX_SIG_PACKED_STRUCT 'p'
#define INFIX_SIG_FUNC_PTR_START '('
#define INFIX_SIG_FUNC_PTR_END ')'

// Delimiters
#define INFIX_SIG_MEMBER_SEPARATOR ','
#define INFIX_SIG_VARIADIC_SEPARATOR ';'
#define INFIX_SIG_OFFSET_SEPARATOR '@'
#define INFIX_SIG_NAME_SEPARATOR ':'
#define INFIX_SIG_RETURN_SEPARATOR "=>"

/** @} */  // End of signature_specifiers group

/** @} */  // End of high_level_api group

/**
 * @brief Creates and initializes a new memory arena.
 * @details Allocates a single large block of memory to be used for subsequent
 *          arena allocations.
 *
 * @param initial_size The total number of bytes to pre-allocate for the arena.
 * @return A pointer to the new `infix_arena_t`, or `nullptr` if the initial allocation fails.
 */
c23_nodiscard infix_arena_t * infix_arena_create(size_t);

/**
 * @brief Frees an entire memory arena and all objects allocated within it.
 * @details This is the only way to free memory from an arena. Individual
 *          allocations cannot be freed.
 *
 * @param arena The arena to destroy. Can be `nullptr` (no-op).
 */
void infix_arena_destroy(infix_arena_t *);

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
c23_nodiscard void * infix_arena_alloc(infix_arena_t *, size_t, size_t);

/**
 * @brief Allocates a zero-initialized block of memory from the arena.
 * @details A convenience wrapper around `infix_arena_alloc` that also sets the memory
 *          to zero, similar to `calloc`.
 *
 * @param arena The arena to allocate from.
 * @param num The number of elements to allocate.
 * @param size The size of each element.
 * @param alignment The required alignment of the returned pointer.
 * @return A pointer to the zero-initialized memory, or `nullptr` on failure.
 */
c23_nodiscard void * infix_arena_calloc(infix_arena_t *, size_t, size_t, size_t);
