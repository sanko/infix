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
 * @file infix_internals.h
 * @brief Declarations for internal-only functions, types, and constants.
 * @ingroup internal_core
 *
 * @internal
 * This header is the central nervous system of the infix library. It includes all
 * other necessary internal headers and provides the concrete, "un-opaqued" definitions
 * for the library's core data structures (like `infix_forward_t` and `infix_reverse_t`).
 *
 * It is NOT part of the public API and must not be exposed to end-users. Its purpose
 * is to share type definitions and function prototypes across the library's own
 * compilation units.
 * @endinternal
 */

#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>

/**
 * @internal
 * @brief A handle to a region of memory that contains executable machine code.
 * @details This structure manages a memory region for JIT-compiled code, designed
 * to enforce W^X (Write XOR Execute) security policies. On some platforms,
 * `rx_ptr` and `rw_ptr` may be two separate virtual memory mappings to the same
 * physical memory, ensuring a page is never writable and executable at the same time.
 */
typedef struct {
#if defined(INFIX_OS_WINDOWS)
    HANDLE handle;  ///< Windows-specific handle to the allocated memory region.
#else
    int shm_fd;  ///< File descriptor for the shared memory object on POSIX systems.
#endif
    void * rx_ptr;  ///< Pointer with Read+Execute permissions (the callable address).
    void * rw_ptr;  ///< Pointer with Read+Write permissions (where code is written).
    size_t size;    ///< The total size of the allocated memory region in bytes.
} infix_executable_t;

/**
 * @internal
 * @brief A handle to a region of read-write data memory with modifiable permissions.
 * @details This is used for data that may need to be hardened to read-only after
 * initialization, such as the `infix_reverse_t` context struct.
 */
typedef struct {
    void * rw_ptr;  ///< A pointer to the read-write data memory.
    size_t size;    ///< The size of the allocated memory region in bytes.
} infix_protected_t;

/**
 * @internal
 * @brief The concrete, internal definition of a forward trampoline handle.
 * @details This structure is intentionally opaque in the public API (`infix.h`).
 */
struct infix_forward_t {
    infix_arena_t * arena;     ///< The arena that owns all the type metadata for this trampoline.
    infix_executable_t exec;   ///< Handle to the executable JIT-compiled stub.
    infix_type * return_type;  ///< The infix_type of the trampoline's return value.
    infix_type ** arg_types;   ///< An array of infix_type pointers for each argument.
    size_t num_args;           ///< The total number of arguments.
    size_t num_fixed_args;     ///< The number of non-variadic arguments.
    void * target_fn;          ///< If non-NULL, the hardcoded target function for a bound trampoline.
};

/**
 * @internal
 * @brief The signature for the C dispatcher function called by a reverse trampoline stub.
 * @param context A pointer to the `infix_reverse_t` that was invoked.
 * @param return_value_ptr A pointer to a buffer on the stub's stack for the return value.
 * @param args_array An array of pointers to the arguments passed by the native caller.
 */
typedef void (*infix_internal_dispatch_callback_fn)(infix_reverse_t *, void *, void **);

/**
 * @internal
 * @brief The concrete, internal definition of a reverse trampoline (callback) context.
 * @details This structure is intentionally opaque in the public API.
 */
struct infix_reverse_t {
    infix_arena_t * arena;            ///< The arena that owns all type metadata for this callback.
    infix_executable_t exec;          ///< Handle to the executable JIT-compiled stub.
    infix_protected_t protected_ctx;  ///< Handle to the memory where this context struct itself resides.
    infix_type * return_type;         ///< The `infix_type` of the callback's return value.
    infix_type ** arg_types;          ///< An array of `infix_type` pointers for each argument.
    size_t num_args;                  ///< The total number of arguments.
    size_t num_fixed_args;            ///< The number of non-variadic arguments.
    bool is_variadic;                 ///< True if the function signature is variadic.
    void * user_callback_fn;          ///< Pointer to the user's actual C callback handler function.
    void * user_data;                 ///< Arbitrary user-data pointer associated with this callback.
    infix_internal_dispatch_callback_fn internal_dispatcher;  ///< Pointer to the C function that bridges from assembly.
    infix_forward_t * cached_forward_trampoline;  ///< A pre-compiled trampoline for calling the user's C callback with
                                                  ///< the correct ABI.
};

/**
 * @internal
 * @brief The concrete, internal definition of a memory arena handle.
 */
struct infix_arena_t {
    char * buffer;          ///< The pointer to the large, pre-allocated memory block.
    size_t capacity;        ///< The total size of the buffer in bytes.
    size_t current_offset;  ///< The high-water mark; the offset of the next free byte.
    bool error;             ///< A sticky flag that is set if any allocation fails.
};

/**
 * @internal
 * @brief A utility structure for dynamically building machine code in memory.
 */
typedef struct {
    uint8_t * code;         ///< The buffer holding the machine code.
    size_t capacity;        ///< The allocated capacity of the buffer.
    size_t size;            ///< The current number of bytes written to the buffer.
    bool error;             ///< A flag that is set if a memory allocation fails.
    infix_arena_t * arena;  ///< The arena to use for allocations.
} code_buffer;

/**
 * @internal
 * @def INFIX_MAX_STACK_ALLOC
 * @brief A safe upper limit on the stack space a trampoline can allocate.
 * @details This is a security and stability measure to prevent a malformed function
 * signature from causing a stack overflow.
 */
#define INFIX_MAX_STACK_ALLOC (1024 * 1024 * 4)  // 4MB

/**
 * @internal
 * @def INFIX_MAX_ARG_SIZE
 * @brief A safe upper limit on the size of a single argument to prevent OOM errors.
 */
#define INFIX_MAX_ARG_SIZE (1024 * 64)  // 64KB

//=================================================================================================
// ABI-Specific Type Definitions
//=================================================================================================

/**
 * @internal
 * @brief Classifies where an argument is passed according to an ABI.
 */
typedef enum {
    ARG_LOCATION_GPR,  ///< Argument is passed in a General-Purpose Register.
#if defined(INFIX_ABI_AAPCS64)
    ARG_LOCATION_VPR,            ///< Argument is passed in a Vector/Floating-Point Register.
    ARG_LOCATION_GPR_PAIR,       ///< Argument is passed in a pair of GPRs.
    ARG_LOCATION_GPR_REFERENCE,  ///< A pointer to the argument is passed in a GPR.
    ARG_LOCATION_VPR_HFA,        ///< Argument is a Homogeneous Floating-point Aggregate passed in VPRs.
#else                            // x86-64 ABIs
    ARG_LOCATION_XMM,               ///< Argument is passed in an XMM (SSE) register.
    ARG_LOCATION_GPR_PAIR,          ///< A struct passed in two GPRs (SysV only).
    ARG_LOCATION_SSE_SSE_PAIR,      ///< A struct passed in two XMM registers (SysV only).
    ARG_LOCATION_INTEGER_SSE_PAIR,  ///< A struct passed in one GPR and one XMM (SysV only).
    ARG_LOCATION_SSE_INTEGER_PAIR,  ///< A struct passed in one XMM and one GPR (SysV only).
#endif
    ARG_LOCATION_STACK  ///< Argument is passed on the stack.
} infix_arg_location_type;

/**
 * @internal
 * @brief A blueprint describing the location(s) of a single function argument.
 */
typedef struct {
    infix_arg_location_type type;  ///< The classification of the argument's location.
    uint8_t reg_index;             ///< The index of the first register used (e.g., 0 for RCX/RDI/X0).
    uint8_t reg_index2;            ///< The index of the second register if the argument is split.
    uint8_t num_regs;              ///< The number of registers this argument occupies (for HFAs).
    uint32_t stack_offset;         ///< The byte offset from the stack pointer if passed on the stack.
} infix_arg_location;

/**
 * @internal
 * @brief A blueprint describing the complete layout for a FORWARD function call.
 * @details This is generated by the ABI-specific `prepare_forward_call_frame` function.
 */
typedef struct {
    size_t total_stack_alloc;  ///< Total bytes to allocate on the stack for arguments.
    uint8_t num_gpr_args;      ///< Count of GPRs used for arguments.
#if defined(INFIX_ABI_AAPCS64)
    uint8_t num_vpr_args;  ///< Count of VPRs used for arguments.
#else                      // x86-64 ABIs
    uint8_t num_xmm_args;  ///< Count of XMM registers used for arguments.
#endif
    infix_arg_location * arg_locations;  ///< An array detailing the location of each argument.
    bool return_value_in_memory;         ///< True if the return value is passed via a hidden pointer.
    bool is_variadic;                    ///< True if the call is variadic.
    size_t num_stack_args;               ///< The number of arguments passed on the stack.
    size_t num_args;                     ///< The total number of arguments.
    void * target_fn;                    ///< If non-NULL, the target function for a bound trampoline.
} infix_call_frame_layout;

/**
 * @internal
 * @brief A blueprint describing the stack layout for a REVERSE trampoline stub.
 * @details This is generated by the ABI-specific `prepare_reverse_call_frame` function.
 */
typedef struct {
    size_t total_stack_alloc;      ///< Total bytes to allocate on the stub's stack frame.
    int32_t return_buffer_offset;  ///< Offset from frame pointer to the return value buffer.
    int32_t args_array_offset;     ///< Offset to the `void**` array passed to the C dispatcher.
    int32_t saved_args_offset;     ///< Offset to the area where by-value argument data is saved.
    int32_t gpr_save_area_offset;  ///< Offset to where incoming GPR arguments are saved.
    int32_t xmm_save_area_offset;  ///< Offset to where incoming XMM/VPR arguments are saved.
} infix_reverse_call_frame_layout;

//=================================================================================================
// ABI Specification Interfaces (V-Tables)
//=================================================================================================

/**
 * @internal
 * @brief An interface (v-table) for an ABI-specific forward trampoline implementation.
 */
typedef struct {
    infix_status (*prepare_forward_call_frame)(
        infix_arena_t *, infix_call_frame_layout **, infix_type *, infix_type **, size_t, size_t, void *);
    infix_status (*generate_forward_prologue)(code_buffer *, infix_call_frame_layout *);
    infix_status (*generate_forward_argument_moves)(
        code_buffer *, infix_call_frame_layout *, infix_type **, size_t, size_t);
    infix_status (*generate_forward_call_instruction)(code_buffer *, infix_call_frame_layout *);
    infix_status (*generate_forward_epilogue)(code_buffer *, infix_call_frame_layout *, infix_type *);
} infix_forward_abi_spec;

/**
 * @internal
 * @brief An interface (v-table) for an ABI-specific REVERSE trampoline implementation.
 */
typedef struct {
    infix_status (*prepare_reverse_call_frame)(infix_arena_t *, infix_reverse_call_frame_layout **, infix_reverse_t *);
    infix_status (*generate_reverse_prologue)(code_buffer *, infix_reverse_call_frame_layout *);
    infix_status (*generate_reverse_argument_marshalling)(code_buffer *,
                                                          infix_reverse_call_frame_layout *,
                                                          infix_reverse_t *);
    infix_status (*generate_reverse_dispatcher_call)(code_buffer *,
                                                     infix_reverse_call_frame_layout *,
                                                     infix_reverse_t *);
    infix_status (*generate_reverse_epilogue)(code_buffer *, infix_reverse_call_frame_layout *, infix_reverse_t *);
} infix_reverse_abi_spec;

// --- From trampoline.c ---
const infix_forward_abi_spec * get_current_forward_abi_spec(void);
const infix_reverse_abi_spec * get_current_reverse_abi_spec(void);
void code_buffer_init(code_buffer *, infix_arena_t *);
void code_buffer_append(code_buffer *, const void *, size_t);
void emit_byte(code_buffer *, uint8_t);
void emit_int32(code_buffer *, int32_t);
void emit_int64(code_buffer *, int64_t);
c23_nodiscard infix_status _infix_forward_create_internal(
    infix_forward_t **, infix_type *, infix_type **, size_t, size_t, infix_arena_t *, void *);

// --- From executor.c ---
c23_nodiscard infix_executable_t infix_executable_alloc(size_t);
void infix_executable_free(infix_executable_t);
c23_nodiscard bool infix_executable_make_executable(infix_executable_t);
c23_nodiscard infix_protected_t infix_protected_alloc(size_t);
void infix_protected_free(infix_protected_t);
c23_nodiscard bool infix_protected_make_readonly(infix_protected_t);
void infix_internal_dispatch_callback_fn_impl(infix_reverse_t *, void *, void **);

// --- Macro for emitting multiple bytes ---
#define EMIT_BYTES(buf, ...)                             \
    do {                                                 \
        const uint8_t bytes[] = {__VA_ARGS__};           \
        code_buffer_append((buf), bytes, sizeof(bytes)); \
    } while (0)

/**
 * @internal
 * @brief Aligns a value up to the next multiple of a given alignment boundary.
 * @param value The value to align.
 * @param alignment The alignment boundary (must be a power of two).
 * @return The aligned value.
 */
static inline size_t _infix_align_up(size_t value, size_t alignment) {
    // Standard bit-twiddling hack for alignment.
    return (value + alignment - 1) & ~(alignment - 1);
}

/** @brief Convenience helper to check if an `infix_type` is a `float`. */
static inline bool is_float(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_FLOAT;
}

/** @brief Convenience helper to check if an `infix_type` is a `double`. */
static inline bool is_double(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_DOUBLE;
}

/** @brief Convenience helper to check if an `infix_type` is a `long double`. */
static inline bool is_long_double(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_LONG_DOUBLE;
}

//=================================================================================================
// Architecture-Specific Emitter Includes
//=================================================================================================

#if defined(INFIX_ABI_SYSV_X64) || defined(INFIX_ABI_WINDOWS_X64)
#include "arch/x64/abi_x64_emitters.h"
#elif defined(INFIX_ABI_AAPCS64)
#include "arch/aarch64/abi_arm64_emitters.h"
#endif
