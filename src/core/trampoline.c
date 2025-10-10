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
 * @file trampoline.c
 * @brief The core engine for JIT compiling FFI trampolines.
 * @ingroup trampoline_engine
 *
 * @internal
 * This file implements the generic, platform-agnostic logic for generating
 * both forward and reverse trampolines. It acts as a central coordinator,
 * using ABI-specific "specs" (v-tables of function pointers) to call the
 * correct implementation for the target platform's calling convention.
 *
 * Its main responsibilities are:
 * 1.  **Dispatching:** Selecting the correct ABI implementation at compile time.
 * 2.  **Code Buffering:** Providing utilities for building machine code.
 * 3.  **Public API Implementation:** Containing the logic for the high-level
 *     `_create_manual` functions.
 * 4.  **Memory Safety:** Ensuring trampoline handles are self-contained by deep-copying
 *     all type metadata into private, internal memory arenas.
 * @endinternal
 */

#include "common/infix_internals.h"
#include "common/utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(INFIX_OS_MACOS)
#include <pthread.h>
#endif

#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

//=================================================================================================
// ABI Specification Declarations & Dispatch
//=================================================================================================

/*
 * These extern declarations link to the ABI-specific v-tables defined in files
 * like `abi_win_x64.c` and `abi_sysv_x64.c`. The preprocessor ensures that only
 * the v-table for the target platform is linked into the final binary.
 */
#if defined(INFIX_ABI_WINDOWS_X64)
extern const infix_forward_abi_spec g_win_x64_forward_spec;
extern const infix_reverse_abi_spec g_win_x64_reverse_spec;
#elif defined(INFIX_ABI_SYSV_X64)
extern const infix_forward_abi_spec g_sysv_x64_forward_spec;
extern const infix_reverse_abi_spec g_sysv_x64_reverse_spec;
#elif defined(INFIX_ABI_AAPCS64)
extern const infix_forward_abi_spec g_arm64_forward_spec;
extern const infix_reverse_abi_spec g_arm64_reverse_spec;
#endif

/**
 * @internal
 * @brief Selects the correct forward-call ABI spec at compile time.
 * @details This function is the primary mechanism for dispatching to the correct
 *          platform-specific code generation logic for forward trampolines.
 * @return A pointer to the active `infix_forward_abi_spec`, or `nullptr` if unsupported.
 */
const infix_forward_abi_spec * get_current_forward_abi_spec() {
#if defined(INFIX_ABI_WINDOWS_X64)
    return &g_win_x64_forward_spec;
#elif defined(INFIX_ABI_SYSV_X64)
    return &g_sysv_x64_forward_spec;
#elif defined(INFIX_ABI_AAPCS64)
    return &g_arm64_forward_spec;
#else
    return nullptr;
#endif
}

/**
 * @internal
 * @brief Selects the correct reverse-call ABI spec at compile time.
 * @return A pointer to the active `infix_reverse_abi_spec`, or `nullptr` if unsupported.
 */
const infix_reverse_abi_spec * get_current_reverse_abi_spec() {
#if defined(INFIX_ABI_WINDOWS_X64)
    return &g_win_x64_reverse_spec;
#elif defined(INFIX_ABI_SYSV_X64)
    return &g_sysv_x64_reverse_spec;
#elif defined(INFIX_ABI_AAPCS64)
    return &g_arm64_reverse_spec;
#else
    return nullptr;
#endif
}

//=================================================================================================
// Code Buffer & Emitter Utilities
//=================================================================================================

/**
 * @internal
 * @brief Initializes a `code_buffer` for use with an arena.
 */
void code_buffer_init(code_buffer * buf, infix_arena_t * arena) {
    buf->capacity = 64;  // Start with a small initial capacity.
    buf->arena = arena;
    buf->code = infix_arena_alloc(arena, buf->capacity, 16);
    buf->size = 0;
    buf->error = (buf->code == nullptr);
}

/**
 * @internal
 * @brief Appends data to a code buffer, reallocating from the arena if necessary.
 * @details Since arenas do not support `realloc`, this function allocates a new,
 *          larger block and copies the existing code when the buffer is full.
 */
void code_buffer_append(code_buffer * buf, const void * data, size_t len) {
    if (buf->error)
        return;  // If already in an error state, do nothing.

    if (len > SIZE_MAX - buf->size) {
        buf->error = true;
        return;
    }

    if (buf->size + len > buf->capacity) {
        size_t new_capacity = buf->capacity;
        while (new_capacity < buf->size + len) {
            if (new_capacity > SIZE_MAX / 2) {
                buf->error = true;
                return;
            }
            new_capacity *= 2;
        }

        void * new_code = infix_arena_alloc(buf->arena, new_capacity, 16);
        if (new_code == nullptr) {
            buf->error = true;
            return;
        }
        infix_memcpy(new_code, buf->code, buf->size);
        buf->code = new_code;
        buf->capacity = new_capacity;
    }
    infix_memcpy(buf->code + buf->size, data, len);
    buf->size += len;
}

/** @internal @brief Appends a single byte to the code buffer. */
void emit_byte(code_buffer * buf, uint8_t byte) {
    code_buffer_append(buf, &byte, 1);
}

/** @internal @brief Appends a 32-bit integer (little-endian) to the code buffer. */
void emit_int32(code_buffer * buf, int32_t value) {
    code_buffer_append(buf, &value, 4);
}

/** @internal @brief Appends a 64-bit integer (little-endian) to the code buffer. */
void emit_int64(code_buffer * buf, int64_t value) {
    code_buffer_append(buf, &value, 8);
}

//=================================================================================================
// Internal Type System Helpers
//=================================================================================================


/**
 * @internal
 * @brief Recursively checks if an entire type graph is fully resolved.
 * @details A type graph is "unresolved" if it contains any nodes of type
 *          `INFIX_TYPE_NAMED_REFERENCE`. Generating a trampoline from an
 *          unresolved graph is an error.
 * @return `true` if resolved, `false` otherwise.
 */
static bool _is_type_graph_resolved(infix_type * type) {
    if (!type)
        return true;
    switch (type->category) {
    case INFIX_TYPE_NAMED_REFERENCE:
        return false;
    case INFIX_TYPE_POINTER:
        return _is_type_graph_resolved(type->meta.pointer_info.pointee_type);
    case INFIX_TYPE_ARRAY:
        return _is_type_graph_resolved(type->meta.array_info.element_type);
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i)
            if (!_is_type_graph_resolved(type->meta.aggregate_info.members[i].type))
                return false;
        return true;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        if (!_is_type_graph_resolved(type->meta.func_ptr_info.return_type))
            return false;
        for (size_t i = 0; i < type->meta.func_ptr_info.num_args; ++i)
            if (!_is_type_graph_resolved(type->meta.func_ptr_info.args[i].type))
                return false;
        return true;
    default:
        return true;
    }
}

//=================================================================================================
// Forward Trampoline Implementation
//=================================================================================================

/*
 * Implementation for infix_forward_get_unbound_code.
 * This is a type-safe accessor for the public API.
 */
c23_nodiscard infix_cif_func infix_forward_get_unbound_code(infix_forward_t * trampoline) {
    if (trampoline == nullptr || trampoline->target_fn != nullptr)
        return nullptr;
    return (infix_cif_func)trampoline->exec.rx_ptr;
}

/*
 * Implementation for infix_forward_get_code.
 * This is a type-safe accessor for the public API.
 */
c23_nodiscard infix_bound_cif_func infix_forward_get_code(infix_forward_t * trampoline) {
    if (trampoline == nullptr || trampoline->target_fn == nullptr)
        return nullptr;
    return (infix_bound_cif_func)trampoline->exec.rx_ptr;
}

/**
 * @internal
 * @brief The internal core logic for creating a forward trampoline.
 * @details This function orchestrates the entire JIT compilation process for a
 *          forward trampoline. It uses the ABI spec v-table to delegate platform-specific
 *          layout calculation and code generation.
 *
 *          It also performs the "Just-Right" Arena Sizing optimization: if a `source_arena`
 *          is provided (from the signature parser), it measures the memory used by the
 *          source types and creates a new, tightly-sized arena for the final trampoline handle,
 *          drastically reducing memory overhead.
 *
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param source_arena An optional pointer to the arena from which the `infix_type` objects
 *                     were created. Used for the memory optimization.
 * @param target_fn If not NULL, creates a "bound" trampoline with a hardcoded target.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status _infix_forward_create_internal(infix_forward_t ** out_trampoline,
                                                          infix_type * return_type,
                                                          infix_type ** arg_types,
                                                          size_t num_args,
                                                          size_t num_fixed_args,
                                                          infix_arena_t * source_arena,
                                                          void * target_fn) {
    if (out_trampoline == nullptr || (arg_types == nullptr && num_args > 0))
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Validate the type graphs to ensure they don't contain unresolved placeholders.
    if (!_is_type_graph_resolved(return_type)) {
        _infix_set_error(INFIX_CATEGORY_ABI, INFIX_CODE_UNRESOLVED_NAMED_TYPE, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i < num_args; ++i) {
        if (arg_types[i] == nullptr || !_is_type_graph_resolved(arg_types[i]))
            return INFIX_ERROR_INVALID_ARGUMENT;
    }

    const infix_forward_abi_spec * spec = get_current_forward_abi_spec();
    if (spec == nullptr)
        return INFIX_ERROR_UNSUPPORTED_ABI;

    infix_status status = INFIX_SUCCESS;
    infix_call_frame_layout * layout = nullptr;
    infix_forward_t * handle = nullptr;
    // Use a temporary arena for layout calculations and code generation.
    infix_arena_t * temp_arena = infix_arena_create(65536);
    if (!temp_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    code_buffer buf;
    code_buffer_init(&buf, temp_arena);

    // JIT Compilation Pipeline
    status = spec->prepare_forward_call_frame(
        temp_arena, &layout, return_type, arg_types, num_args, num_fixed_args, target_fn);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_forward_prologue(&buf, layout);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_forward_argument_moves(&buf, layout, arg_types, num_args, num_fixed_args);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    status = spec->generate_forward_call_instruction(&buf, layout);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    status = spec->generate_forward_epilogue(&buf, layout, return_type);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    if (buf.error || temp_arena->error) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // Final Trampoline Handle Assembly
    handle = infix_calloc(1, sizeof(infix_forward_t));
    if (handle == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // "Just-Right" Arena Sizing Optimization
    size_t required_size = source_arena ? source_arena->current_offset : 8192;  // Fallback size
    handle->arena = infix_arena_create(required_size + INFIX_TRAMPOLINE_HEADROOM);
    if (handle->arena == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // Deep copy all type info into the handle's own arena to make it self-contained.
    handle->return_type = _copy_type_graph_to_arena(handle->arena, return_type);
    handle->arg_types = infix_arena_alloc(handle->arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *));
    if ((handle->return_type == nullptr && return_type != nullptr) || (num_args > 0 && handle->arg_types == nullptr)) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    for (size_t i = 0; i < num_args; ++i) {
        handle->arg_types[i] = _copy_type_graph_to_arena(handle->arena, arg_types[i]);
        if (handle->arg_types[i] == nullptr && arg_types[i] != nullptr) {
            status = INFIX_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }
    handle->num_args = num_args;
    handle->num_fixed_args = num_fixed_args;
    handle->target_fn = target_fn;

    // Allocate executable memory and copy the generated code into it.
    handle->exec = infix_executable_alloc(buf.size);
    if (handle->exec.rw_ptr == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    infix_memcpy(handle->exec.rw_ptr, buf.code, buf.size);

    if (!infix_executable_make_executable(handle->exec)) {
        status = INFIX_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    infix_dump_hex(handle->exec.rx_ptr, handle->exec.size, "Forward Trampoline Machine Code");
    *out_trampoline = handle;

cleanup:
    if (status != INFIX_SUCCESS && handle != nullptr)
        infix_forward_destroy(handle);
    infix_arena_destroy(temp_arena);
    return status;
}

/*
 * Implementation for infix_forward_create_manual (bound).
 */
c23_nodiscard infix_status infix_forward_create_manual(infix_forward_t ** out_trampoline,
                                                       infix_type * return_type,
                                                       infix_type ** arg_types,
                                                       size_t num_args,
                                                       size_t num_fixed_args,
                                                       void * target_function) {
    return _infix_forward_create_internal(
        out_trampoline, return_type, arg_types, num_args, num_fixed_args, nullptr, target_function);
}

/**
 * @brief Creates an "unbound" forward-call trampoline for a given function signature.
 * @details Creates a trampoline where the target function pointer is not hardcoded.
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param return_type The `infix_type` of the function's return value.
 * @param arg_types An array of `infix_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args For variadic functions, the number of non-variadic arguments.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 * @note The returned trampoline must be freed with `infix_forward_destroy`.
 */
c23_nodiscard infix_status infix_forward_create_unbound_manual(infix_forward_t ** out_trampoline,
                                                               infix_type * return_type,
                                                               infix_type ** arg_types,
                                                               size_t num_args,
                                                               size_t num_fixed_args) {
    return _infix_forward_create_internal(
        out_trampoline, return_type, arg_types, num_args, num_fixed_args, nullptr, nullptr);
}

/*
 * Implementation for infix_forward_destroy.
 * Frees all resources associated with a forward trampoline.
 */
void infix_forward_destroy(infix_forward_t * trampoline) {
    if (trampoline == nullptr)
        return;
    if (trampoline->arena)
        infix_arena_destroy(trampoline->arena);
    infix_executable_free(trampoline->exec);
    infix_free(trampoline);
}

//=================================================================================================
// Reverse Trampoline Implementation
//=================================================================================================

/*
 * @internal
 * A helper to get the system's memory page size.
 */
static size_t get_page_size() {
#if defined(INFIX_OS_WINDOWS)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwPageSize;
#else
    return sysconf(_SC_PAGESIZE);
#endif
}

/*
 * Implementation for infix_reverse_create_manual.
 * This is a large, complex function that orchestrates the entire process of
 * creating a reverse trampoline (callback).
 */
c23_nodiscard infix_status infix_reverse_create_manual(infix_reverse_t ** out_context,
                                                       infix_type * return_type,
                                                       infix_type ** arg_types,
                                                       size_t num_args,
                                                       size_t num_fixed_args,
                                                       void * user_callback_fn,
                                                       void * user_data) {
    if (out_context == nullptr || num_fixed_args > num_args)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Validate the user-provided type graphs.
    if (!_is_type_graph_resolved(return_type))
        return INFIX_ERROR_INVALID_ARGUMENT;
    if (arg_types == nullptr && num_args > 0)
        return INFIX_ERROR_INVALID_ARGUMENT;
    for (size_t i = 0; i < num_args; ++i) {
        if (arg_types[i] == nullptr || !_is_type_graph_resolved(arg_types[i]))
            return INFIX_ERROR_INVALID_ARGUMENT;
    }

    const infix_reverse_abi_spec * spec = get_current_reverse_abi_spec();
    if (spec == nullptr)
        return INFIX_ERROR_UNSUPPORTED_ABI;

    infix_status status = INFIX_SUCCESS;
    infix_reverse_call_frame_layout * layout = nullptr;
    infix_reverse_t * context = nullptr;
    infix_arena_t * temp_arena = nullptr;  // For layout calculations and code generation.
    infix_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    code_buffer buf;

    temp_arena = infix_arena_create(65536);
    if (!temp_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    code_buffer_init(&buf, temp_arena);

    // Allocate page-aligned memory for the context struct itself, so it can be hardened.
    size_t page_size = get_page_size();
    size_t context_alloc_size = (sizeof(infix_reverse_t) + page_size - 1) & ~(page_size - 1);
    prot = infix_protected_alloc(context_alloc_size);
    if (prot.rw_ptr == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    context = (infix_reverse_t *)prot.rw_ptr;
    infix_memset(context, 0, context_alloc_size);

    // Create the persistent arena that will be owned by the context.
    context->arena = infix_arena_create(8192);
    if (context->arena == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // Initialize the context fields.
    context->protected_ctx = prot;
    context->num_args = num_args;
    context->num_fixed_args = num_fixed_args;
    context->is_variadic = (num_fixed_args < num_args);
    context->user_callback_fn = user_callback_fn;
    context->user_data = user_data;
    context->internal_dispatcher = infix_internal_dispatch_callback_fn_impl;

    // Deep copy all type information into the context's own arena.
    context->return_type = _copy_type_graph_to_arena(context->arena, return_type);
    context->arg_types = infix_arena_alloc(context->arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *));
    if ((context->return_type == nullptr && return_type != nullptr) ||
        (num_args > 0 && context->arg_types == nullptr)) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    for (size_t i = 0; i < num_args; ++i) {
        context->arg_types[i] = _copy_type_graph_to_arena(context->arena, arg_types[i]);
        if (context->arg_types[i] == nullptr && arg_types[i] != nullptr) {
            status = INFIX_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }

    // The user's handler expects `context*` as its first argument. We must create a new
    // argument type list that reflects this for the cached forward trampoline.
    infix_type ** callback_arg_types =
        infix_arena_alloc(temp_arena, (1 + num_args) * sizeof(infix_type *), _Alignof(infix_type *));
    if (callback_arg_types == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    callback_arg_types[0] = infix_type_create_pointer();  // The context pointer
    if (context->num_args > 0)
        infix_memcpy(&callback_arg_types[1], context->arg_types, context->num_args * sizeof(infix_type *));

    // Generate the cached forward trampoline with the augmented argument list.
    status = infix_forward_create_manual(&context->cached_forward_trampoline,
                                         context->return_type,
                                         callback_arg_types,
                                         context->num_args + 1,
                                         context->num_fixed_args + 1,
                                         user_callback_fn);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    // JIT Compilation Pipeline for Reverse Trampoline
    status = spec->prepare_reverse_call_frame(temp_arena, &layout, context);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_reverse_prologue(&buf, layout);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_reverse_argument_marshalling(&buf, layout, context);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_reverse_dispatcher_call(&buf, layout, context);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_reverse_epilogue(&buf, layout, context);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    if (buf.error || temp_arena->error) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // Allocate executable memory and finalize the JIT code.
    context->exec = infix_executable_alloc(buf.size);
    if (context->exec.rw_ptr == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    infix_memcpy(context->exec.rw_ptr, buf.code, buf.size);

    if (!infix_executable_make_executable(context->exec)) {
        status = INFIX_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    // Harden the context struct itself to be read-only as a security measure.
    if (!infix_protected_make_readonly(context->protected_ctx)) {
        status = INFIX_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    infix_dump_hex(context->exec.rx_ptr, buf.size, "Reverse Trampoline Machine Code");
    *out_context = context;

cleanup:
    if (status != INFIX_SUCCESS && context != nullptr)
        infix_reverse_destroy(context);
    infix_arena_destroy(temp_arena);
    return status;
}

/*
 * Implementation for infix_reverse_get_code.
 * A simple accessor for the public API.
 */
c23_nodiscard void * infix_reverse_get_code(const infix_reverse_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->exec.rx_ptr;
}

/*
 * Implementation for infix_reverse_get_user_data.
 * A simple accessor for the public API.
 */
c23_nodiscard void * infix_reverse_get_user_data(const infix_reverse_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->user_data;
}

/*
 * Implementation for infix_reverse_destroy.
 * Frees all resources associated with a reverse trampoline, including its
 * cached forward trampoline, internal arena, executable stub, and protected context memory.
 */
void infix_reverse_destroy(infix_reverse_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return;
    if (reverse_trampoline->cached_forward_trampoline)
        infix_forward_destroy(reverse_trampoline->cached_forward_trampoline);
    if (reverse_trampoline->arena)
        infix_arena_destroy(reverse_trampoline->arena);
    infix_executable_free(reverse_trampoline->exec);
    infix_protected_free(reverse_trampoline->protected_ctx);
}

//=================================================================================================
// Unity Build Section
//=================================================================================================

/*
 * This section implements a unity build for the ABI-specific components.
 * Instead of relying on the build system to compile and link the correct `abi_*.c`
 * files, we include them directly into this compilation unit based on the ABI
 * selected in `infix_config.h`. This simplifies the build process.
 */
#if defined(INFIX_ABI_WINDOWS_X64)
#include "../arch/x64/abi_win_x64.c"
#include "../arch/x64/abi_x64_emitters.c"
#elif defined(INFIX_ABI_SYSV_X64)
#include "../arch/x64/abi_sysv_x64.c"
#include "../arch/x64/abi_x64_emitters.c"
#elif defined(INFIX_ABI_AAPCS64)
#include "../arch/aarch64/abi_arm64.c"
#include "../arch/aarch64/abi_arm64_emitters.c"
#else
#error "No supported ABI was selected for the unity build in trampoline.c."
#endif
