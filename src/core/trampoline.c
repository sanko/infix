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
 *
 * @details This file implements the generic, platform-agnostic logic for
 * generating both forward and reverse trampolines. It acts as a central coordinator,
 * using ABI-specific "specs" (virtual tables of function pointers) to call the
 * correct implementation for the target platform's calling convention.
 *
 * The main responsibilities of this file are:
 * 1.  **Dispatching:** It selects the correct ABI implementation at compile time via the
 *     `infix_forward_abi_spec` and `infix_reverse_abi_spec` interfaces.
 * 2.  **Code Buffering:** It provides utility functions for building machine code in a
 *     dynamic, automatically-resizing memory buffer (`code_buffer`).
 * 3.  **Public API Implementation:** It contains the logic for the high-level public API
 *     functions like `infix_forward_create_manual` and `infix_reverse_create_manual`,
 *     which orchestrate the entire code generation process from layout calculation
 *     to memory finalization.
 * 4.  **Low-Level Emitters:** It provides cross-architecture helper functions for
 *     emitting common data types (bytes, integers) into the code buffer.
 * 5.  **Memory Safety:** It ensures that the generated `infix_forward_t` and `infix_reverse_t`
 *     handles are self-contained objects. It achieves this by performing a deep copy
 *     of all necessary `infix_type` metadata into a private, internal memory arena
 *     owned by the handle. This eliminates a class of use-after-free bugs.
 */

#include "../common/infix_internals.h"
#include "../common/utility.h"  // Restored for infix_dump_hex and INFIX_DEBUG_PRINTF
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

// ABI Specification Declarations
// These extern declarations link to the ABI-specific v-tables defined in files
// like `abi_win_x64.c`, `abi_sysv_x64.c`, and `abi_arm64.c`. The preprocessor
// ensures that only the v-table for the target platform is linked into the final binary.
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
 * @brief Selects the correct forward-call ABI spec at compile time.
 * @details This function uses preprocessor directives to return a pointer to the
 *          globally defined ABI specification structure for the current target.
 *          This is the primary mechanism for dispatching to the correct platform-specific
 *          code generation logic for forward trampolines.
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
 * @brief Selects the correct reverse-call ABI spec at compile time.
 * @details Similar to `get_current_forward_abi_spec`, but for reverse trampolines (callbacks).
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

/**
 * @brief Initializes a code_buffer for use with an arena.
 * @param buf A pointer to the `code_buffer` to initialize.
 * @param arena The arena to use for memory allocations.
 */
void code_buffer_init(code_buffer * buf, infix_arena_t * arena) {
    buf->capacity = 64;  // Start with a small initial capacity.
    buf->arena = arena;
    buf->code = infix_arena_alloc(arena, buf->capacity, 16);  // Align to 16 bytes for safety
    buf->size = 0;
    buf->error = (buf->code == nullptr);
    //~ if (buf->error)
    //~ fprintf(stderr, "Error: infix_arena_alloc failed in code_buffer_init.\n");
}

/**
 * @brief Appends data to a code buffer, reallocating from the arena if necessary.
 * @param buf A pointer to the `code_buffer`.
 * @param data A pointer to the raw bytes to append.
 * @param len The number of bytes to append.
 */
void code_buffer_append(code_buffer * buf, const void * data, size_t len) {
    if (buf->error)  // If we're already in an error state, do nothing.
        return;

    if (len > SIZE_MAX - buf->size) {
        //~ fprintf(stderr,
        //~ "Error: Appending %llu bytes to buffer of size %llu would cause overflow.\n",
        //~ (unsigned long long)len,
        //~ (unsigned long long)buf->size);
        buf->error = true;
        return;
    }

    if (buf->size + len > buf->capacity) {
        size_t new_capacity = buf->capacity;
        while (new_capacity < buf->size + len) {
            if (new_capacity > SIZE_MAX / 2) {
                //~ fprintf(stderr, "Error: code_buffer cannot grow further without overflow.\n");
                buf->error = true;
                return;
            }
            new_capacity *= 2;
        }

        // Arena allocators don't support realloc. We must allocate a new block and copy.
        void * new_code = infix_arena_alloc(buf->arena, new_capacity, 16);
        if (new_code == nullptr) {
            //~ fprintf(stderr, "Error: infix_arena_alloc failed in code_buffer_append.\n");
            buf->error = true;
            return;
        }
        // Copy the old code to the new, larger buffer.
        infix_memcpy(new_code, buf->code, buf->size);
        buf->code = new_code;
        buf->capacity = new_capacity;
    }
    infix_memcpy(buf->code + buf->size, data, len);
    buf->size += len;
}

/**
 * @brief Appends a single byte to the code buffer.
 * @param buf The code buffer to which the byte will be appended.
 * @param byte The 8-bit value to emit.
 */
void emit_byte(code_buffer * buf, uint8_t byte) {
    code_buffer_append(buf, &byte, 1);
}

/**
 * @brief Appends a 32-bit integer (little-endian) to the code buffer.
 * @param buf The code buffer.
 * @param value The 32-bit integer to emit.
 */
void emit_int32(code_buffer * buf, int32_t value) {
    code_buffer_append(buf, &value, 4);
}

/**
 * @brief Appends a 64-bit integer (little-endian) to the code buffer.
 * @param buf The code buffer.
 * @param value The 64-bit integer to emit.
 */
void emit_int64(code_buffer * buf, int64_t value) {
    code_buffer_append(buf, &value, 8);
}

/**
 * @internal
 * @brief Recursively performs a deep copy of an `infix_type` object graph into a destination arena.
 * @details This function is the core of making trampolines self-contained. It walks a type
 *          graph and duplicates it in the destination arena. It correctly handles static
 *          primitive types by not copying them, which is a crucial optimization.
 * @param dest_arena The arena to copy the type graph into.
 * @param src_type The source type to copy. Can be NULL.
 * @return A pointer to the newly-copied type in the destination arena, or the original
 *         pointer if it was a non-arena-allocated static primitive. Returns NULL if the
 *         source was NULL or if an allocation fails.
 */
static infix_type * _copy_type_graph_to_arena(infix_arena_t * dest_arena, const infix_type * src_type) {
    if (src_type == nullptr)
        return nullptr;

    // If the source type is a static primitive (not from an arena), we don't need to copy it.
    // We can just return the original pointer.
    if (!src_type->is_arena_allocated)
        return (infix_type *)src_type;

    // Allocate space for the new type in the destination arena and copy the base struct.
    infix_type * dest_type = infix_arena_alloc(dest_arena, sizeof(infix_type), _Alignof(infix_type));
    if (dest_type == nullptr)
        return nullptr;

    memcpy(dest_type, src_type, sizeof(infix_type));

    // Recursively copy any nested types based on the category.
    switch (src_type->category) {
    case INFIX_TYPE_POINTER:
        dest_type->meta.pointer_info.pointee_type =
            _copy_type_graph_to_arena(dest_arena, src_type->meta.pointer_info.pointee_type);
        break;
    case INFIX_TYPE_ARRAY:
        dest_type->meta.array_info.element_type =
            _copy_type_graph_to_arena(dest_arena, src_type->meta.array_info.element_type);
        break;
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        if (src_type->meta.aggregate_info.num_members > 0) {
            size_t members_size = sizeof(infix_struct_member) * src_type->meta.aggregate_info.num_members;
            dest_type->meta.aggregate_info.members =
                infix_arena_alloc(dest_arena, members_size, _Alignof(infix_struct_member));
            if (dest_type->meta.aggregate_info.members == nullptr)
                return nullptr;  // Allocation failed.

            memcpy(dest_type->meta.aggregate_info.members, src_type->meta.aggregate_info.members, members_size);

            for (size_t i = 0; i < src_type->meta.aggregate_info.num_members; ++i)
                dest_type->meta.aggregate_info.members[i].type =
                    _copy_type_graph_to_arena(dest_arena, src_type->meta.aggregate_info.members[i].type);
        }
        break;
    // Other cases like ENUM, COMPLEX, VECTOR, etc. would follow the same pattern.
    case INFIX_TYPE_ENUM:
        dest_type->meta.enum_info.underlying_type =
            _copy_type_graph_to_arena(dest_arena, src_type->meta.enum_info.underlying_type);
        break;
    case INFIX_TYPE_COMPLEX:
        dest_type->meta.complex_info.base_type =
            _copy_type_graph_to_arena(dest_arena, src_type->meta.complex_info.base_type);
        break;
    case INFIX_TYPE_VECTOR:
        dest_type->meta.vector_info.element_type =
            _copy_type_graph_to_arena(dest_arena, src_type->meta.vector_info.element_type);
        break;
    default:
        // For PRIMITIVE, VOID, NAMED_REFERENCE, etc., the initial shallow copy is sufficient.
        // For REVERSE_TRAMPOLINE (function pointers), a deep copy of its signature is also needed.
        // This case would need to be handled if we support introspection of function pointer members.
        break;
    }
    return dest_type;
}

/**
 * @brief Retrieves the executable code pointer from a forward trampoline.
 * @param trampoline A handle to a previously created forward trampoline.
 * @return A callable function pointer of type `infix_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_forward_get_code(infix_forward_t * trampoline) {
    if (trampoline == nullptr)
        return nullptr;
    return trampoline->exec.rx_ptr;
}

/**
 * @brief (Internal) Recursively checks if an entire type graph is fully resolved.
 * @details A type graph is considered unresolved if it contains any nodes of
 *          type INFIX_TYPE_NAMED_REFERENCE.
 * @param type Pointer to infix_type_t struct which will be checked to confirm it's complete.
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

/**
 * @internal
 * @brief The internal core logic for creating a forward trampoline.
 * @details This function contains the full logic for JIT-compiling a forward trampoline.
 *          It accepts an optional `source_arena` parameter. If provided, it measures the
 *          memory used by the source types and creates a new, tightly-sized arena for the
 *          trampoline handle. This drastically reduces memory overhead. If `source_arena` is
 *          NULL, it falls back to a default size.
 * @param source_arena An optional pointer to the arena from which the `infix_type` objects
 *                     were created. Used for memory optimization.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status _infix_forward_create_internal(infix_forward_t ** out_trampoline,
                                                          infix_type * return_type,
                                                          infix_type ** arg_types,
                                                          size_t num_args,
                                                          size_t num_fixed_args,
                                                          infix_arena_t * source_arena) {
    if (out_trampoline == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Validate the type graphs to ensure they don't contain unresolved placeholders.
    if (!_is_type_graph_resolved(return_type))
        return INFIX_ERROR_INVALID_ARGUMENT;

    if (arg_types == nullptr && num_args > 0)
        return INFIX_ERROR_INVALID_ARGUMENT;
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
    infix_arena_t * arena = nullptr;
    code_buffer buf;

    // Use a larger arena (64KB) to handle extreme cases (I hope)
    arena = infix_arena_create(65536);
    if (!arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    code_buffer_init(&buf, arena);

    INFIX_DEBUG_PRINTF("Generating Generic Forward Trampoline");

    status = spec->prepare_forward_call_frame(arena, &layout, return_type, arg_types, num_args, num_fixed_args);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_forward_prologue(&buf, layout);
    if (status != INFIX_SUCCESS)
        goto cleanup;
    status = spec->generate_forward_argument_moves(&buf, layout, arg_types, num_args, num_fixed_args);
    if (status != INFIX_SUCCESS)
        goto cleanup;

#if defined(INFIX_ARCH_X64)
    EMIT_BYTES(&buf, 0x4D, 0x85, 0xE4);  // test r12, r12 (r12 holds the target function ptr)
    EMIT_BYTES(&buf, 0x75, 0x02);        // jnz +2 (skip next instruction if not null)
    EMIT_BYTES(&buf, 0x0F, 0x0B);        // ud2 (undefined instruction to cause a safe crash)
    EMIT_BYTES(&buf, 0x41, 0xFF, 0xD4);  // call r12
#elif defined(INFIX_ARCH_AARCH64)
    EMIT_BYTES(&buf, 0x53, 0x00, 0x00, 0xb5);  // cbnz x19, +8 (x19 holds the target)
    EMIT_BYTES(&buf, 0x00, 0x00, 0x20, 0xd4);  // brk #0 (break instruction for safe crash)
    EMIT_BYTES(&buf, 0x60, 0x02, 0x3f, 0xd6);  // blr x19 (branch with link to register)
#endif

    status = spec->generate_forward_epilogue(&buf, layout, return_type);
    if (status != INFIX_SUCCESS)
        goto cleanup;

    // Check for memory allocation errors within the arena or code buffer.
    if (buf.error || arena->error) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    handle = infix_calloc(1, sizeof(infix_forward_t));
    if (handle == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // --- "Just-Right" Arena Sizing Optimization ---
    size_t required_size = 0;
    if (source_arena)
        required_size = source_arena->current_offset;
    else
        required_size = 8192;  // Fallback size for manual API calls
    handle->arena = infix_arena_create(required_size + INFIX_TRAMPOLINE_HEADROOM);
    if (handle->arena == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // Deep copy all type info into the handle's own arena to make it self-contained.
    handle->return_type = _copy_type_graph_to_arena(handle->arena, return_type);
    if (handle->return_type == nullptr && return_type != nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    handle->arg_types = infix_arena_alloc(handle->arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *));
    if (num_args > 0 && handle->arg_types == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    for (size_t i = 0; i < num_args; ++i) {
        handle->arg_types[i] = _copy_type_graph_to_arena(handle->arena, arg_types[i]);
        // If the source was not NULL but the destination is, it means the copy failed.
        if (handle->arg_types[i] == nullptr && arg_types[i] != nullptr) {
            status = INFIX_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }
    handle->num_args = num_args;
    handle->num_fixed_args = num_fixed_args;

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
    // If we failed at any point, ensure the partially created handle is fully destroyed.
    if (status != INFIX_SUCCESS && handle != nullptr)
        infix_forward_destroy(handle);
    infix_arena_destroy(arena);
    return status;
}

/**
 * @brief Generates a forward-call trampoline for a given function signature.
 * @details This public API function is now a simple wrapper around the internal
 *          implementation. It calls the core logic without providing a source arena,
 *          triggering the fallback to a default internal arena size.
 */
c23_nodiscard infix_status infix_forward_create_manual(infix_forward_t ** out_trampoline,
                                                       infix_type * return_type,
                                                       infix_type ** arg_types,
                                                       size_t num_args,
                                                       size_t num_fixed_args) {
    return _infix_forward_create_internal(out_trampoline, return_type, arg_types, num_args, num_fixed_args, nullptr);
}

/**
 * @brief Frees a forward trampoline, its executable memory, and its internal arena.
 */
void infix_forward_destroy(infix_forward_t * trampoline) {
    if (trampoline == nullptr)
        return;
    if (trampoline->arena)
        infix_arena_destroy(trampoline->arena);
    infix_executable_free(trampoline->exec);
    infix_free(trampoline);
}

/**
 * @brief Gets the system's memory page size.
 * @return The page size in bytes.
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

/**
 * @brief Generates a reverse-call trampoline (callback) for a given function signature.
 * @details This function creates a native, C-callable function pointer that, when invoked,
 *          calls back into a user-provided handler. The returned `infix_reverse_t` context
 *          is now a fully self-contained object, owning deep copies of all necessary
 *          type information in its own private memory arena. This design eliminates
 *          use-after-free vulnerabilities caused by the user freeing their temporary
 *          type-creation arena.
 *
 * @param[out] out_context On success, will point to the context for the new reverse trampoline.
 * @param return_type The `infix_type` of the callback's return value.
 * @param arg_types An array of `infix_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of non-variadic arguments.
 * @param user_callback_fn A pointer to the user's C function that will be called.
 * @param user_data An arbitrary pointer that will be stored in the context.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
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

    INFIX_DEBUG_PRINTF("Generating Generic Reverse Trampoline");

    infix_status status = INFIX_SUCCESS;
    infix_reverse_call_frame_layout * layout = nullptr;
    infix_reverse_t * context = nullptr;
    infix_arena_t * arena = nullptr;  // Temporary arena for ABI-specific calculations
    infix_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    code_buffer buf;

    // Use a temporary arena for layout calculations and code generation.
    // The final context will have its own persistent arena.
    arena = infix_arena_create(65536);
    if (!arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    code_buffer_init(&buf, arena);

    size_t page_size = get_page_size();
    size_t context_alloc_size = (sizeof(infix_reverse_t) + page_size - 1) & ~(page_size - 1);
    prot = infix_protected_alloc(context_alloc_size);
    if (prot.rw_ptr == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    context = (infix_reverse_t *)prot.rw_ptr;
    infix_memset(context, 0, context_alloc_size);

    // Create a new persistent arena that will be owned by the context.
    context->arena = infix_arena_create(8192);  // 8KB should be enough for most type graphs.
    if (context->arena == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    context->protected_ctx = prot;
    context->num_args = num_args;
    context->num_fixed_args = num_fixed_args;
    context->is_variadic = (num_fixed_args < num_args);
    context->user_callback_fn = user_callback_fn;
    context->user_data = user_data;
    context->internal_dispatcher = infix_internal_dispatch_callback_fn_impl;

    // Deep copy all type information from the user's arena into the context's own arena.
    context->return_type = _copy_type_graph_to_arena(context->arena, return_type);
    if (context->return_type == nullptr && return_type != nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    context->arg_types = infix_arena_alloc(context->arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *));
    if (num_args > 0 && context->arg_types == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    for (size_t i = 0; i < num_args; ++i) {
        context->arg_types[i] = _copy_type_graph_to_arena(context->arena, arg_types[i]);
        // If the source was not NULL but the destination is, it means the copy failed.
        if (context->arg_types[i] == nullptr && arg_types[i] != nullptr) {
            status = INFIX_ERROR_ALLOCATION_FAILED;
            goto cleanup;
        }
    }

    // The user's callback handler expects the `infix_reverse_t*` context
    // as its FIRST argument. We must create a new argument type list that reflects this.
    // The new list will have `1 (for context) + num_args` elements.
    infix_type ** callback_arg_types =
        infix_arena_alloc(arena, (1 + num_args) * sizeof(infix_type *), _Alignof(infix_type *));
    if (callback_arg_types == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // The first argument is the context pointer.
    callback_arg_types[0] = infix_type_create_pointer();

    // Now, copy and promote the original user-defined arguments into the rest of the array.
    if (context->is_variadic) {
        for (size_t i = 0; i < context->num_args; ++i) {
            infix_type * current_type = context->arg_types[i];
            if (i >= num_fixed_args) {  // Apply default argument promotions for variadic part.
                if (is_float(current_type))
                    callback_arg_types[i + 1] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                else if (current_type->category == INFIX_TYPE_PRIMITIVE && current_type->size < sizeof(int))
                    callback_arg_types[i + 1] = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
                else
                    callback_arg_types[i + 1] = current_type;
            }
            else
                callback_arg_types[i + 1] = current_type;
        }
    }
    else {
        // For non-variadic functions, just copy the original types.
        if (context->num_args > 0)
            infix_memcpy(&callback_arg_types[1], context->arg_types, context->num_args * sizeof(infix_type *));
    }

    // Generate the cached forward trampoline with the *correct, prepended* argument list.
    status = infix_forward_create_manual(&context->cached_forward_trampoline,
                                         context->return_type,
                                         callback_arg_types,
                                         context->num_args + 1,
                                         context->num_fixed_args + 1);

    if (status != INFIX_SUCCESS)
        goto cleanup;

    status = spec->prepare_reverse_call_frame(arena, &layout, context);
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

    if (buf.error || arena->error) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    context->exec = infix_executable_alloc(buf.size);
    if (context->exec.rw_ptr == nullptr) {
        status = INFIX_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    infix_memcpy(context->exec.rw_ptr, buf.code, buf.size);
    size_t code_size = buf.size;

    if (!infix_executable_make_executable(context->exec)) {
        status = INFIX_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    if (!infix_protected_make_readonly(context->protected_ctx)) {
        status = INFIX_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    INFIX_DEBUG_PRINTF("Hardened reverse trampoline context at %p to be read-only.", (void *)context);
    infix_dump_hex(context->exec.rx_ptr, code_size, "Reverse Trampoline Machine Code");

    *out_context = context;

cleanup:
    if (status != INFIX_SUCCESS && context != nullptr)
        // If we failed, we must free the context and its nested resources.
        // infix_reverse_destroy handles this correctly.
        infix_reverse_destroy(context);

    infix_arena_destroy(arena);
    return status;
}

/**
 * @brief Retrieves the executable code pointer from a reverse trampoline.
 * @param reverse_trampoline A handle to a previously created reverse trampoline.
 * @return A callable function pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_reverse_get_code(const infix_reverse_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->exec.rx_ptr;
}

/**
 * @brief Retrieves the user_data stored with a reverse trampoline.
 * @param reverse_trampoline A handle to a reverse trampoline context.
 * @return The opaque user_data pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * infix_reverse_get_user_data(const infix_reverse_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->user_data;
}

/**
 * @brief Frees a reverse trampoline, its JIT-compiled stub, its context, and its internal arena.
 * @details This function safely cleans up all resources associated with a reverse
 *          trampoline, including the cached forward trampoline, the executable stub,
 *          the protected memory holding the context struct itself, and the internal
 *          arena that owns the type metadata.
 * @param reverse_trampoline The reverse trampoline to free. Can be `nullptr`.
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

/**
 * @brief This section implements a unity build for the ABI-specific components.
 * @details Instead of relying on the build system to compile and link the correct
 * `abi_*.c` files, we include them directly into this compilation unit based on the
 * ABI selected in `infix.h`. This simplifies the build process and makes cross-ABI
 * fuzzing possible.
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
