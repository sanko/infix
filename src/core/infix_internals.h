#pragma once
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
 * @internal
 * @file infix_internals.h
 * @brief Declarations for internal-only functions shared across compilation units.
 * @warning This header is NOT part of the public API. It is used to expose
 * functions that are normally static within their own .c file to other parts
 * of the library, primarily for white-box testing and fuzzing.
 */

#include <infix.h>

/**
 * @internal
 * @brief A handle to a region of memory that contains executable machine code.
 * @details This structure manages a memory region intended for JIT-compiled code.
 * It is designed to enforce W^X (Write XOR Execute) security policies. On some
 * platforms, `rx_ptr` and `rw_ptr` may point to the same address but have different
 * permissions applied over time. On others, they are two separate virtual memory
 * mappings to the same physical memory.
 */
typedef struct {
#if defined(FFI_OS_WINDOWS)
    HANDLE handle;  ///< The Windows-specific handle to the allocated memory region.
#else
    int shm_fd;  ///< A file descriptor for the shared memory object on POSIX systems.
#endif
    void * rx_ptr;  ///< A pointer to the memory with Read+Execute permissions. This is the callable address.
    void * rw_ptr;  ///< A pointer to the memory with Read+Write permissions. Code is written here before being made
                    ///< executable.
    size_t size;    ///< The total size of the allocated memory region in bytes.
} ffi_executable_t;

/**
 * @internal
 * @brief A handle to a region of memory with modifiable permissions, used for data. */
typedef struct {
    void * rw_ptr;  ///< A pointer to the read-write data memory.
    size_t size;    ///< The size of the allocated memory region in bytes.
} ffi_protected_t;

/**
 * @internal
 * @brief The signature for the C dispatcher function called by a reverse trampoline stub.
 * @details This is an function pointer type. The JIT-compiled assembly stub for a
 * reverse trampoline calls a C function of this type, passing it the necessary context
 * and normalized arguments.
 * @param context A pointer to the `ffi_reverse_trampoline_t` that was invoked.
 * @param return_value_ptr A pointer to a buffer on the stub's stack for the return value.
 * @param args_array An array of pointers to the arguments passed by the native caller.
 */
typedef void (*ffi_internal_dispatch_callback_fn)(ffi_reverse_trampoline_t *, void *, void **);

/**
 * @internal
 * @struct ffi_trampoline_handle_t
 * @brief (Internal) The concrete implementation of a forward trampoline handle.
 * @details This structure holds the handle to the executable memory containing the
 * JIT-compiled trampoline code. It is defined here in the implementation file
 * to keep it opaque in the public API (`infix.h`).
 */
struct ffi_trampoline_handle_t {
    ffi_executable_t exec;
};

/**
 * @internal
 * @struct ffi_reverse_trampoline_t
 * @brief The complete context for a reverse trampoline (callback).
 * It is intentionally opaque in the public API.
 */
struct ffi_reverse_trampoline_t {
    ffi_executable_t exec;    ///< Handle to the executable JIT-compiled stub.
    ffi_type * return_type;   ///< The ffi_type of the callback's return value.
    ffi_type ** arg_types;    ///< An array of ffi_type pointers for each argument.
    size_t num_args;          ///< The total number of arguments.
    size_t num_fixed_args;    ///< The number of non-variadic arguments.
    bool is_variadic;         ///< True if the function signature is variadic.
    void * user_callback_fn;  ///< A pointer to the user's actual callback handler function.
    void * user_data;         ///< An arbitrary user-data pointer to be associated with this callback.
    ffi_internal_dispatch_callback_fn
        internal_dispatcher;  ///< Pointer to the C function that bridges the gap from assembly.
    ffi_trampoline_t *
        cached_forward_trampoline;  ///< A pre-compiled forward trampoline for calling the user's C callback.
    ffi_protected_t protected_ctx;  ///< Handle to the memory where this context struct itself resides.
};

/**
 * @internal
 * @struct arena_t
 * @brief Represents a memory arena from which temporary objects can be allocated.
 */
struct arena_t {
    char * buffer;          ///< The pointer to the large, pre-allocated memory block.
    size_t capacity;        ///< The total size of the buffer in bytes.
    size_t current_offset;  ///< The high-water mark; the offset of the next free byte.
    bool error;             ///< A sticky flag that is set if any allocation fails.
};

/**
 * @struct code_buffer
 * @brief An utility structure for dynamically building machine code in memory.
 * @This is not part of the public API. It's a simple dynamic array for
 * assembling byte sequences.
 * @internal
 */
typedef struct {
    uint8_t * code;   ///< The buffer holding the machine code.
    size_t capacity;  ///< The allocated capacity of the buffer.
    size_t size;      ///< The current number of bytes written to the buffer.
    bool error;       ///< A flag that is set if a memory allocation fails.
    arena_t * arena;  ///< The arena to use for allocations.
} code_buffer;

/** @def FFI_MAX_STACK_ALLOC
 *  @brief A safe upper limit on the amount of stack space a trampoline can allocate.
 *  @details This is a security and stability measure to prevent a malformed function
 *  signature from causing a stack overflow.
 *  @internal
 */
#define FFI_MAX_STACK_ALLOC (1024 * 1024 * 4)

/** @def FFI_MAX_ARG_SIZE
 *  @brief A safe upper limit on the size of a single argument to prevent OOM.
 */
#define FFI_MAX_ARG_SIZE (1024 * 64)

/**
 * @internal
 * @brief enum to classify where an argument is passed according to an ABI.
 * @This is used by the ABI-specific logic to describe how to handle each argument.
 */
typedef enum {
    ARG_LOCATION_GPR,  ///< Argument is passed in a General-Purpose Register.
#if defined(FFI_ABI_AAPCS64)
    ARG_LOCATION_VPR,            ///< Argument is passed in a Vector/Floating-Point Register.
    ARG_LOCATION_GPR_PAIR,       ///< Argument is passed in a pair of GPRs.
    ARG_LOCATION_GPR_REFERENCE,  ///< A pointer to the argument is passed in a GPR.
    ARG_LOCATION_VPR_HFA,        ///< Argument is a Homogeneous Floating-point Aggregate passed in VPRs.
#else                            // x86-64 ABIs
    ARG_LOCATION_XMM,               ///< Argument is passed in an XMM (SSE) register.
    ARG_LOCATION_GPR_PAIR,          ///< A struct passed in two GPRs (SysV only).
    ARG_LOCATION_SSE_SSE_PAIR,      ///< A struct passed in two XMM registers (SysV only).
    ARG_LOCATION_INTEGER_SSE_PAIR,  ///< A struct passed with one half in a GPR and the second in an XMM register (SysV
                                    ///< only).
    ARG_LOCATION_SSE_INTEGER_PAIR,  ///< A struct passed with one half in an XMM and the second in a GPR (SysV only).
#endif
    ARG_LOCATION_STACK  ///< Argument is passed on the stack.
} ffi_arg_location_type;

/**
 * @internal
 * @brief struct describing the location(s) of a single function argument.
 * @This blueprint details exactly where to find or place an argument's data.
 */
typedef struct {
    ffi_arg_location_type type;  ///< The classification of the argument's location.
    uint8_t reg_index;           ///< The index of the first register used (e.g., 0 for RCX/RDI).
    uint8_t reg_index2;          ///< The index of the second register if the argument is split.
    uint8_t num_regs;            ///< The number of registers this argument occupies.
    uint32_t stack_offset;       ///< The byte offset from the stack pointer if passed on the stack.
} ffi_arg_location;

/**
 * @internal
 * @brief A blueprint describing the complete layout of a FORWARD function call for a given ABI.
 * @This is generated by the ABI-specific `prepare_forward_call_frame` function.
 */
typedef struct {
    size_t total_stack_alloc;  ///< Total bytes to allocate on the stack.
    uint8_t num_gpr_args;      ///< Count of GPRs used for arguments.
#if defined(FFI_ABI_AAPCS64)
    uint8_t num_vpr_args;  ///< Count of VPRs used for arguments.
#else                      // x86-64 ABIs
    uint8_t num_xmm_args;  ///< Count of XMM registers used for arguments.
#endif
    ffi_arg_location * arg_locations;  ///< An array detailing the location of each argument.
    bool return_value_in_memory;       ///< True if the return value is passed via a hidden pointer.
    bool is_variadic;                  ///< True if the call is variadic.
    size_t num_stack_args;             ///< The number of arguments passed on the stack.
    size_t num_args;                   ///< The total number of arguments.
} ffi_call_frame_layout;

/**
 * @internal
 * @brief A blueprint describing the stack layout for a REVERSE trampoline stub.
 * @This is generated by the ABI-specific `prepare_reverse_call_frame` function.
 */
typedef struct {
    size_t total_stack_alloc;      ///< Total bytes to allocate on the stub's stack frame.
    int32_t return_buffer_offset;  ///< Offset to the space reserved for the return value.
    int32_t args_array_offset;     ///< Offset to the `void**` array passed to the C dispatcher.
    int32_t saved_args_offset;     ///< Offset to the start of the area where argument data is saved.
    int32_t gpr_save_area_offset;  ///< Offset to where incoming GPR arguments are saved.
    int32_t xmm_save_area_offset;  ///< Offset to where incoming XMM/VPR arguments are saved.
} ffi_reverse_call_frame_layout;

/**
 * @internal
 * @brief An interface (vtable) for an ABI-specific forward trampoline implementation.
 */
typedef struct {
    ffi_status (*prepare_forward_call_frame)(
        arena_t *, ffi_call_frame_layout **, ffi_type *, ffi_type **, size_t, size_t);
    ffi_status (*generate_forward_prologue)(code_buffer *, ffi_call_frame_layout *);
    ffi_status (*generate_forward_argument_moves)(code_buffer *, ffi_call_frame_layout *, ffi_type **, size_t, size_t);
    ffi_status (*generate_forward_epilogue)(code_buffer *, ffi_call_frame_layout *, ffi_type *);
} ffi_forward_abi_spec;

/**
 * @internal
 * @brief An interface (vtable) for an ABI-specific REVERSE trampoline implementation.
 */
typedef struct {
    ffi_status (*prepare_reverse_call_frame)(arena_t *, ffi_reverse_call_frame_layout **, ffi_reverse_trampoline_t *);
    ffi_status (*generate_reverse_prologue)(code_buffer *, ffi_reverse_call_frame_layout *);
    ffi_status (*generate_reverse_argument_marshalling)(code_buffer *,
                                                        ffi_reverse_call_frame_layout *,
                                                        ffi_reverse_trampoline_t *);
    ffi_status (*generate_reverse_dispatcher_call)(code_buffer *,
                                                   ffi_reverse_call_frame_layout *,
                                                   ffi_reverse_trampoline_t *);
    ffi_status (*generate_reverse_epilogue)(code_buffer *, ffi_reverse_call_frame_layout *, ffi_reverse_trampoline_t *);
} ffi_reverse_abi_spec;

// trampoline.c
/** @brief Selects the correct forward-call ABI spec at compile time. */
const ffi_forward_abi_spec * get_current_forward_abi_spec();
/** @brief Selects the correct reverse-call ABI spec at compile time. */
const ffi_reverse_abi_spec * get_current_reverse_abi_spec();

/**
 * @internal
 * @brief Initializes a code_buffer.
 */
void code_buffer_init(code_buffer *, arena_t *);
/**
 * @internal
 * @brief Appends data to a code_buffer, resizing if necessary.
 */
void code_buffer_append(code_buffer *, const void *, size_t);

/**
 * @internal
 * @brief Appends a single byte to the code buffer. */
void emit_byte(code_buffer *, uint8_t);
/**
 * @internal
 * @brief Appends a 32-bit integer to the code buffer (little-endian). */
void emit_int32(code_buffer *, int32_t);
/**
 * @internal
 * @brief Appends a 64-bit integer to the code buffer (little-endian). */
void emit_int64(code_buffer *, int64_t);

/**
 * @def EMIT_BYTES(buf, ...)
 * @brief A macro to append a variable number of bytes to the code buffer.
 * @param buf The code buffer to append to.
 * @param ... A comma-separated list of byte values (e.g., `0x48, 0x89, 0xE5`).
 * @internal
 */
#define EMIT_BYTES(buf, ...)                             \
    do {                                                 \
        const uint8_t bytes[] = {__VA_ARGS__};           \
        code_buffer_append((buf), bytes, sizeof(bytes)); \
    } while (0)

// executor.c
/**
 * @brief Allocates a block of page-aligned memory suitable for JIT code.
 * @details This is a low-level memory management function that allocates memory
 * with initial Read/Write permissions. It uses platform-specific APIs to ensure
 * the memory can later be made executable.
 * @param size The number of bytes to allocate.
 * @return An `ffi_executable_t` handle. On failure, `rw_ptr` will be `nullptr`.
 */
c23_nodiscard ffi_executable_t ffi_executable_alloc(size_t);

/**
 * @brief Frees a block of executable memory.
 * @param exec The memory handle returned by `ffi_executable_alloc`.
 */
void ffi_executable_free(ffi_executable_t);

/**
 * @brief Makes a memory block executable and read-only.
 * @details This function changes the memory protection from Read/Write to Read/Execute,
 * enforcing W^X security policy. It also flushes the instruction cache on relevant
 * architectures like AArch64. This should be called after code has been written to the buffer.
 * @param exec The memory handle.
 * @return `true` on success, `false` on failure.
 */
c23_nodiscard bool ffi_executable_make_executable(ffi_executable_t);

/**
 * @brief Allocates a block of page-aligned read-write data memory.
 * @param size The number of bytes to allocate.
 * @return An `ffi_protected_t` handle. `rw_ptr` will be `nullptr` on failure.
 */
c23_nodiscard ffi_protected_t ffi_protected_alloc(size_t);

/**
 * @brief Frees a block of protected data memory.
 * @param prot The memory handle to free.
 */
void ffi_protected_free(ffi_protected_t);

/**
 * @brief Changes a protected data block to be read-only.
 * @details This can be used to harden data structures (like the reverse trampoline context)
 * against accidental or malicious modification after initialization.
 * @param prot The handle to the memory to protect.
 * @return `true` on success, `false` on failure.
 */
c23_nodiscard bool ffi_protected_make_readonly(ffi_protected_t);

/**
 * @internal
 * @brief The internal C dispatcher function for all reverse trampolines (cached).
 */
void ffi_internal_dispatch_callback_fn_impl(ffi_reverse_trampoline_t *, void *, void **);

// More ABI sugar
/** @brief A convenience helper to check if an `ffi_type` is a `float`. */
static inline bool is_float(const ffi_type * type) {
    return type->category == FFI_TYPE_PRIMITIVE && type->meta.primitive_id == FFI_PRIMITIVE_TYPE_FLOAT;
}

/** @brief A convenience helper to check if an `ffi_type` is a `double`. */
static inline bool is_double(const ffi_type * type) {
    return type->category == FFI_TYPE_PRIMITIVE && type->meta.primitive_id == FFI_PRIMITIVE_TYPE_DOUBLE;
}

/** @brief A convenience helper to check if an `ffi_type` is a `long double`. */
static inline bool is_long_double(const ffi_type * type) {
    return type->category == FFI_TYPE_PRIMITIVE && type->meta.primitive_id == FFI_PRIMITIVE_TYPE_LONG_DOUBLE;
}

/** @brief Determines if an argument must be passed by reference according to Win x64 ABI rules. */
static inline bool is_passed_by_reference(ffi_type * type) {
    // On Windows x64, aggregates whose size is not a power of two (1, 2, 4, 8 bytes)
    // are passed by reference. This also applies to sizes larger than 8 bytes on MSVC.
    // However, GCC/Clang on Windows passes 16-byte types by value on the stack.
    // To ensure compatibility, we treat 16-byte types as pass-by-value.
    //~ if (type->size == 16)
    //~ return false;
    return type->size != 1 && type->size != 2 && type->size != 4 && type->size != 8;
}

/**
 * @brief The master dispatcher for determining if a return value uses a hidden pointer.
 * @details This function centralizes the logic for one of the most significant differences
 * between ABIs: how large structures are returned. Some ABIs require the caller to
 * allocate space for the return value and pass a hidden pointer to it as the first argument.
 * @param type The ffi_type of the return value.
 * @return `true` if the ABI mandates returning this type via a hidden pointer.
 */
static inline bool return_uses_hidden_pointer_abi(c23_maybe_unused ffi_type * type) {
#if defined(FFI_ABI_WINDOWS_X64)
#if defined(FFI_COMPILER_GCC)
    // On GCC for Windows, its 16-byte long double is a special case returned by reference.
    if (is_long_double(type))
        return true;
#endif
    // For all other compilers (MSVC, Clang) and for aggregate types on GCC, the rule is size-based.
    if (type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION || type->category == FFI_TYPE_ARRAY)
        return is_passed_by_reference(type);
    return false;  // Other primitives (including __int128_t) are returned by value.
#elif defined(FFI_ABI_SYSV_X64)
    // long double is not returned via hidden pointer on SysV, but on the x87 stack.
    // The check here is just for large aggregates.
    return (type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION ||
            type->category == FFI_TYPE_ARRAY) &&
        type->size > 16;
#elif defined(FFI_ABI_AAPCS64)
    return (type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION ||
            type->category == FFI_TYPE_ARRAY) &&
        type->size > 16;
#else
    return false;
#endif
}

// Include architecture-specific instruction emitters for use by ABI implementations.
#if defined(FFI_ABI_SYSV_X64) || defined(FFI_ABI_WINDOWS_X64)
#include <abi_x64_emitters.h>
#elif defined(FFI_ABI_AAPCS64)
#include <abi_arm64_emitters.h>
#endif

//=================================================================================================
// ABI Abstraction Layer
//=================================================================================================

/** @brief Determines if a return value is passed by reference on Windows x64. */
static inline bool return_value_is_by_reference_win_x64(ffi_type * type) {
#if defined(FFI_COMPILER_GCC)
    if (is_long_double(type))
        return true;
#endif
    if (type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION || type->category == FFI_TYPE_ARRAY)
        return is_passed_by_reference(type);
    return false;
}

/**
 * @brief Checks if all stack-passed arguments are of the same simple type.
 * @details This is a condition for an optimization. If a function takes many arguments
 *          of the same type (e.g., 500 doubles) that are all passed on the stack,
 *          we can generate a compact loop to move them instead of unrolled `mov` instructions.
 * @param layout The call frame layout.
 * @param arg_types The array of argument types.
 * @param num_args The total number of arguments.
 * @return `true` if the optimization can be applied, `false` otherwise.
 */
static inline bool are_all_stack_args_homogeneous(ffi_call_frame_layout * layout,
                                                  ffi_type ** arg_types,
                                                  size_t num_args) {
#if defined(BULK_MOVE_THRESHOLD)
    if (layout->num_stack_args < BULK_MOVE_THRESHOLD)
        return false;
#endif

    ffi_type * first_stack_type = nullptr;
    size_t first_stack_idx = 0;

    // Find the first argument passed on the stack
    for (size_t i = 0; i < num_args; ++i) {
        if (layout->arg_locations[i].type == ARG_LOCATION_STACK) {
            first_stack_type = arg_types[i];
            first_stack_idx = i;
            break;
        }
    }

    if (!first_stack_type)
        return false;  // No stack arguments

#if defined(FFI_ABI_WINDOWS_X64)
    if (is_passed_by_reference(first_stack_type) || first_stack_type->size != 8)
        return false;
#else
    // This optimization is only safe for simple 8-byte types (double, uint64_t, pointers, etc.).
    // It correctly excludes aggregates passed on the stack.
    if (first_stack_type->size != 8)
        return false;
#endif

    // Check that all subsequent stack arguments are of the exact same type.
    for (size_t i = first_stack_idx + 1; i < num_args; ++i) {
        if (layout->arg_locations[i].type == ARG_LOCATION_STACK) {
            if (arg_types[i] != first_stack_type)
                return false;
        }
    }

    return true;
}

/**
 * @internal
 * @brief Creates an `ffi_type` for a struct, allocating from an arena.
 * @details This is an advanced, arena-aware version of `ffi_type_create_struct`.
 *          It is used by the signature parser and is exposed for power-users who need
 *          to create many `ffi_type` objects with maximum performance. All memory for
 *          the `ffi_type` object itself is taken from the provided arena.
 *
 *          This function calculates the final size and alignment of the struct based on
 *          its members, adhering to standard C layout and padding rules. It uses the
 *          `offsetof` values provided in the `members` array to perform this calculation.
 *
 * @param arena [in] The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param members [in] An array of `ffi_struct_member` describing each member of the struct.
 *                    The `offset` field for each member **must** be correctly populated
 *                    using the `offsetof` macro.
 * @param num_members [in] The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note **Memory Ownership**: All allocated memory is owned by the arena. The
 *       returned `ffi_type` **must NOT** be passed to `ffi_type_destroy`. The entire
 *       object graph will be freed when `arena_destroy` is called.
 */
c23_nodiscard ffi_status ffi_type_create_struct_arena(arena_t *, ffi_type **, ffi_struct_member *, size_t);

/**
 * @internal
 * @brief Creates an `ffi_type` for a packed struct, allocating from an arena.
 * @details This is an advanced, arena-aware version of `ffi_type_create_packed_struct`.
 *          It is primarily used by the signature parser but is exposed for power-users
 *          who need to create many `ffi_type` objects with maximum performance and
 *          minimal memory overhead. Instead of allocating from the heap, all memory for
 *          the `ffi_type` object itself is taken from the provided arena.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param total_size The exact size of the packed struct, from `sizeof()`.
 * @param alignment The alignment requirement of the packed struct, from `_Alignof()`.
 * @param members An array of `ffi_struct_member` describing each member. The offsets
 *                within this array must be the correct, packed offsets from `offsetof()`.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note **Memory Ownership**: All allocated memory, including the returned `ffi_type`
 *       and its internal `members` array (if it's copied from the arena), is owned
 *       by the arena. The returned `ffi_type` **must NOT** be passed to `ffi_type_destroy`.
 *       The entire object graph will be freed when `arena_destroy` is called.
 */
c23_nodiscard ffi_status
ffi_type_create_packed_struct_arena(arena_t *, ffi_type **, size_t, size_t, ffi_struct_member *, size_t);

/**
 * @internal
 * @brief Creates an `ffi_type` for a union, allocating from an arena.
 * @details This is an advanced, arena-aware version of `ffi_type_create_union`.
 *          It is used by the signature parser and is exposed for power-users who need
 *          to create many `ffi_type` objects with maximum performance. All memory for
 *          the `ffi_type` object itself is taken from the provided arena.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param members An array of `ffi_struct_member` describing each member of the union.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note **Memory Ownership**: All allocated memory is owned by the arena. The
 *       returned `ffi_type` **must NOT** be passed to `ffi_type_destroy`. The entire
 *       object graph will be freed when `arena_destroy` is called.
 */
c23_nodiscard ffi_status ffi_type_create_union_arena(arena_t *, ffi_type **, ffi_struct_member *, size_t);

/**
 * @internal
 * @brief Creates an `ffi_type` for a fixed-size array, allocating from an arena.
 * @details This is an advanced, arena-aware version of `ffi_type_create_array`.
 *          It is used by the signature parser and is exposed for power-users who need
 *          to create many `ffi_type` objects with maximum performance. All memory for
 *          the `ffi_type` object itself is taken from the provided arena.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param element_type An `ffi_type` describing the type of elements in the array. This
 *                     type itself may be heap- or arena-allocated.
 * @param num_elements The number of elements in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note **Memory Ownership**: All allocated memory is owned by the arena. The
 *       returned `ffi_type` **must NOT** be passed to `ffi_type_destroy`. The entire
 *       object graph will be freed when `arena_destroy` is called.
 */
c23_nodiscard ffi_status ffi_type_create_array_arena(arena_t *, ffi_type **, ffi_type *, size_t);
