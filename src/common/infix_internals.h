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
 */

#include "common/infix_config.h"
#include <infix/infix.h>

/**
 * @internal
 * @brief A handle to a region of memory that contains executable machine code.
 */
typedef struct {
#if defined(INFIX_OS_WINDOWS)
    HANDLE handle;
#else
    int shm_fd;
#endif
    void * rx_ptr;
    void * rw_ptr;
    size_t size;
} infix_executable_t;

/**
 * @internal
 * @brief A handle to a region of read-write data memory with modifiable permissions.
 */
typedef struct {
    void * rw_ptr;
    size_t size;
} infix_protected_t;

/**
 * @internal
 * @brief The concrete, internal definition of a forward trampoline handle.
 */
struct infix_forward_t {
    infix_arena_t * arena;
    infix_executable_t exec;
    infix_type * return_type;
    infix_type ** arg_types;
    size_t num_args;
    size_t num_fixed_args;
    void * target_fn;
};

typedef void (*infix_internal_dispatch_callback_fn)(infix_reverse_t *, void *, void **);

/**
 * @internal
 * @brief The concrete, internal definition of a reverse trampoline (callback) context.
 */
struct infix_reverse_t {
    infix_arena_t * arena;
    infix_executable_t exec;
    infix_protected_t protected_ctx;
    infix_type * return_type;
    infix_type ** arg_types;
    size_t num_args;
    size_t num_fixed_args;
    bool is_variadic;
    void * user_callback_fn;
    void * user_data;
    infix_internal_dispatch_callback_fn internal_dispatcher;
    infix_forward_t * cached_forward_trampoline;
};

/**
 * @internal
 * @brief The concrete, internal definition of a memory arena handle.
 */
struct infix_arena_t {
    char * buffer;
    size_t capacity;
    size_t current_offset;
    bool error;
};

/**
 * @internal
 * @struct _infix_registry_entry_t
 */
typedef struct _infix_registry_entry_t {
    const char * name;
    infix_type * type;
    bool is_forward_declaration;
    struct _infix_registry_entry_t * next;
} _infix_registry_entry_t;

/**
 * @internal
 * @brief The concrete, internal definition of the type registry handle.
 */
struct infix_registry_t {
    infix_arena_t * arena;
    size_t num_buckets;
    size_t num_items;
    _infix_registry_entry_t ** buckets;
};

/**
 * @internal
 * @brief A utility structure for dynamically building machine code in memory.
 */
typedef struct {
    uint8_t * code;
    size_t capacity;
    size_t size;
    bool error;
    infix_arena_t * arena;
} code_buffer;

/**
 * @internal
 * @struct infix_library_t
 */
struct infix_library_t {
    void * handle;
};

#define INFIX_MAX_STACK_ALLOC (1024 * 1024 * 4)
#define INFIX_MAX_ARG_SIZE (1024 * 64)

typedef enum {
    ARG_LOCATION_GPR,
#if defined(INFIX_ABI_AAPCS64)
    ARG_LOCATION_VPR,
    ARG_LOCATION_GPR_PAIR,
    ARG_LOCATION_GPR_REFERENCE,
    ARG_LOCATION_VPR_HFA,
#else
    ARG_LOCATION_XMM,
    ARG_LOCATION_GPR_PAIR,
    ARG_LOCATION_SSE_SSE_PAIR,
    ARG_LOCATION_INTEGER_SSE_PAIR,
    ARG_LOCATION_SSE_INTEGER_PAIR,
#endif
    ARG_LOCATION_STACK
} infix_arg_location_type;

typedef struct {
    infix_arg_location_type type;
    uint8_t reg_index;
    uint8_t reg_index2;
    uint8_t num_regs;
    uint32_t stack_offset;
} infix_arg_location;

typedef struct {
    size_t total_stack_alloc;
    uint8_t num_gpr_args;
#if defined(INFIX_ABI_AAPCS64)
    uint8_t num_vpr_args;
#else
    uint8_t num_xmm_args;
#endif
    infix_arg_location * arg_locations;
    bool return_value_in_memory;
    bool is_variadic;
    size_t num_stack_args;
    size_t num_args;
    void * target_fn;
} infix_call_frame_layout;

typedef struct {
    size_t total_stack_alloc;
    int32_t return_buffer_offset;
    int32_t args_array_offset;
    int32_t saved_args_offset;
    int32_t gpr_save_area_offset;
    int32_t xmm_save_area_offset;
} infix_reverse_call_frame_layout;

typedef struct {
    infix_status (*prepare_forward_call_frame)(
        infix_arena_t *, infix_call_frame_layout **, infix_type *, infix_type **, size_t, size_t, void *);
    infix_status (*generate_forward_prologue)(code_buffer *, infix_call_frame_layout *);
    infix_status (*generate_forward_argument_moves)(
        code_buffer *, infix_call_frame_layout *, infix_type **, size_t, size_t);
    infix_status (*generate_forward_call_instruction)(code_buffer *, infix_call_frame_layout *);
    infix_status (*generate_forward_epilogue)(code_buffer *, infix_call_frame_layout *, infix_type *);
} infix_forward_abi_spec;

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

// Function Prototypes for Internal Modules

void _infix_set_error(infix_error_category_t, infix_error_code_t, size_t);
void _infix_set_system_error(infix_error_category_t, infix_error_code_t, long, const char *);
void _infix_clear_error(void);

void _infix_type_recalculate_layout(infix_type * type);

c23_nodiscard infix_status _infix_resolve_and_copy_type_graph(infix_type **,
                                                              const infix_type *,
                                                              infix_arena_t *,
                                                              infix_registry_t *);

c23_nodiscard infix_status _infix_parse_type_internal(infix_type **, infix_arena_t **, const char *);

infix_type * _copy_type_graph_to_arena(infix_arena_t *, const infix_type *);

const infix_forward_abi_spec * get_current_forward_abi_spec(void);
const infix_reverse_abi_spec * get_current_reverse_abi_spec(void);
void code_buffer_init(code_buffer *, infix_arena_t *);
void code_buffer_append(code_buffer *, const void *, size_t);
void emit_byte(code_buffer *, uint8_t);
void emit_int32(code_buffer *, int32_t);
void emit_int64(code_buffer *, int64_t);
c23_nodiscard infix_status _infix_forward_create_internal(
    infix_forward_t **, infix_type *, infix_type **, size_t, size_t, infix_arena_t *, void *);

c23_nodiscard infix_executable_t infix_executable_alloc(size_t);
void infix_executable_free(infix_executable_t);
c23_nodiscard bool infix_executable_make_executable(infix_executable_t);
c23_nodiscard infix_protected_t infix_protected_alloc(size_t);
void infix_protected_free(infix_protected_t);
c23_nodiscard bool infix_protected_make_readonly(infix_protected_t);
void infix_internal_dispatch_callback_fn_impl(infix_reverse_t *, void *, void **);

#define EMIT_BYTES(buf, ...)                             \
    do {                                                 \
        const uint8_t bytes[] = {__VA_ARGS__};           \
        code_buffer_append((buf), bytes, sizeof(bytes)); \
    } while (0)
static inline size_t _infix_align_up(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}
static inline bool is_float(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_FLOAT;
}
static inline bool is_double(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_DOUBLE;
}
static inline bool is_long_double(const infix_type * type) {
    return type->category == INFIX_TYPE_PRIMITIVE && type->meta.primitive_id == INFIX_PRIMITIVE_LONG_DOUBLE;
}

#if defined(INFIX_ABI_SYSV_X64) || defined(INFIX_ABI_WINDOWS_X64)
#include "arch/x64/abi_x64_emitters.h"
#elif defined(INFIX_ABI_AAPCS64)
#include "arch/aarch64/abi_arm64_emitters.h"
#endif
