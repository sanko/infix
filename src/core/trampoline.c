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
 *     `ffi_forward_abi_spec` and `ffi_reverse_abi_spec` interfaces.
 * 2.  **Code Buffering:** It provides utility functions for building machine code in a
 *     dynamic, automatically-resizing memory buffer (`code_buffer`).
 * 3.  **Public API Implementation:** It contains the logic for the high-level public API
 *     functions like `generate_forward_trampoline` and `generate_reverse_trampoline`,
 *     which orchestrate the entire code generation process from layout calculation
 *     to memory finalization.
 * 4.  **Low-Level Emitters:** It provides cross-architecture helper functions for
 *     emitting common data types (bytes, integers) into the code buffer.
 */

// Define the POSIX source macro to ensure function declarations for posix_memalign
// are visible. This must be defined before any system headers are included.
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <assert.h>
#include <infix_internals.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utility.h>  // Restored for DumpHex and FFI_DEBUG_PRINTF

#if defined(FFI_OS_MACOS)
#include <pthread.h>
#endif

#if defined(FFI_OS_WINDOWS)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

/**
 * @struct ffi_trampoline_handle_t
 * @brief (Internal) The concrete implementation of a forward trampoline handle.
 * @details This structure holds the handle to the executable memory containing the
 * JIT-compiled trampoline code. It is defined here in the implementation file
 * to keep it opaque in the public API (`infix.h`).
 */
// This was removed because it is already defined in infix_internals.h
// struct ffi_trampoline_handle_t {
//    ffi_executable_t exec;
// };

// ABI Specification Declarations
// These extern declarations link to the ABI-specific v-tables defined in files
// like `abi_win_x64.c`, `abi_sysv_x64.c`, and `abi_arm64.c`. The preprocessor
// ensures that only the v-table for the target platform is linked into the final binary.
#if defined(FFI_ABI_WINDOWS_X64)
extern const ffi_forward_abi_spec g_win_x64_forward_spec;
extern const ffi_reverse_abi_spec g_win_x64_reverse_spec;
#elif defined(FFI_ABI_SYSV_X64)
extern const ffi_forward_abi_spec g_sysv_x64_forward_spec;
extern const ffi_reverse_abi_spec g_sysv_x64_reverse_spec;
#elif defined(FFI_ABI_AAPCS64)
extern const ffi_forward_abi_spec g_arm64_forward_spec;
extern const ffi_reverse_abi_spec g_arm64_reverse_spec;
#endif

/**
 * @brief Selects the correct forward-call ABI spec at compile time.
 * @details This function uses preprocessor directives to return a pointer to the
 *          globally defined ABI specification structure for the current target.
 *          This is the primary mechanism for dispatching to the correct platform-specific
 *          code generation logic for forward trampolines.
 * @return A pointer to the active `ffi_forward_abi_spec`, or `nullptr` if unsupported.
 */
const ffi_forward_abi_spec * get_current_forward_abi_spec() {
#if defined(FFI_ABI_WINDOWS_X64)
    return &g_win_x64_forward_spec;
#elif defined(FFI_ABI_SYSV_X64)
    return &g_sysv_x64_forward_spec;
#elif defined(FFI_ABI_AAPCS64)
    return &g_arm64_forward_spec;
#else
    return nullptr;
#endif
}

/**
 * @brief Selects the correct reverse-call ABI spec at compile time.
 * @details Similar to `get_current_forward_abi_spec`, but for reverse trampolines (callbacks).
 * @return A pointer to the active `ffi_reverse_abi_spec`, or `nullptr` if unsupported.
 */
const ffi_reverse_abi_spec * get_current_reverse_abi_spec() {
#if defined(FFI_ABI_WINDOWS_X64)
    return &g_win_x64_reverse_spec;
#elif defined(FFI_ABI_SYSV_X64)
    return &g_sysv_x64_reverse_spec;
#elif defined(FFI_ABI_AAPCS64)
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
void code_buffer_init(code_buffer * buf, arena_t * arena) {
    buf->capacity = 64;  // Start with a small initial capacity.
    buf->arena = arena;
    buf->code = arena_alloc(arena, buf->capacity, 16);  // Align to 16 bytes for safety
    buf->size = 0;
    buf->error = (buf->code == nullptr);
    //~ if (buf->error)
    //~ fprintf(stderr, "Error: arena_alloc failed in code_buffer_init.\n");
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
        void * new_code = arena_alloc(buf->arena, new_capacity, 16);
        if (new_code == NULL) {
            //~ fprintf(stderr, "Error: arena_alloc failed in code_buffer_append.\n");
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
 * @brief Retrieves the executable code pointer from a forward trampoline.
 * @param trampoline A handle to a previously created forward trampoline.
 * @return A callable function pointer of type `ffi_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_trampoline_get_code(ffi_trampoline_t * trampoline) {
    if (trampoline == nullptr)
        return nullptr;
    return trampoline->exec.rx_ptr;
}

/**
 * @brief Generates a forward-call trampoline for a given function signature.
 * @details This function orchestrates the entire process of JIT-compiling a forward
 *          trampoline. The process involves:
 *          1. Selecting the correct ABI-specific implementation.
 *          2. Calculating the function's call frame layout (register usage, stack space).
 *          3. Generating the machine code for the prologue, argument marshalling, the actual call, and the epilogue.
 *          4. Allocating executable memory.
 *          5. Copying the generated code into the memory and making it executable.
 *          Error handling is managed through a single cleanup path to ensure all
 *          intermediate resources are freed correctly.
 *
 * @param[out] out_trampoline On success, this will point to the handle for the new trampoline.
 * @param return_type The `ffi_type` of the function's return value.
 * @param arg_types An array of `ffi_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args For variadic functions, the number of non-variadic arguments. For non-variadic functions, this
 * must equal `num_args`.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard ffi_status generate_forward_trampoline(ffi_trampoline_t ** out_trampoline,
                                                     ffi_type * return_type,
                                                     ffi_type ** arg_types,
                                                     size_t num_args,
                                                     size_t num_fixed_args) {
    if (out_trampoline == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    const ffi_forward_abi_spec * spec = get_current_forward_abi_spec();
    if (spec == nullptr)
        return FFI_ERROR_UNSUPPORTED_ABI;

    ffi_status status = FFI_SUCCESS;
    ffi_call_frame_layout * layout = nullptr;
    ffi_trampoline_t * handle = nullptr;
    arena_t * arena = nullptr;
    code_buffer buf;

    // Use a larger arena (64KB) to handle extreme cases (I hope)
    arena = arena_create(65536);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    code_buffer_init(&buf, arena);

    FFI_DEBUG_PRINTF("Generating Generic Forward Trampoline");

    status = spec->prepare_forward_call_frame(arena, &layout, return_type, arg_types, num_args, num_fixed_args);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_forward_prologue(&buf, layout);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_forward_argument_moves(&buf, layout, arg_types, num_args, num_fixed_args);
    if (status != FFI_SUCCESS)
        goto cleanup;

#if defined(FFI_ARCH_X64)
    EMIT_BYTES(&buf, 0x4D, 0x85, 0xE4);  // test r12, r12 (r12 holds the target function ptr)
    EMIT_BYTES(&buf, 0x75, 0x02);        // jnz +2 (skip next instruction if not null)
    EMIT_BYTES(&buf, 0x0F, 0x0B);        // ud2 (undefined instruction to cause a safe crash)
    EMIT_BYTES(&buf, 0x41, 0xFF, 0xD4);  // call r12
#elif defined(FFI_ARCH_AARCH64)
    EMIT_BYTES(&buf, 0x53, 0x00, 0x00, 0xb5);  // cbnz x19, +8 (x19 holds the target)
    EMIT_BYTES(&buf, 0x00, 0x00, 0x20, 0xd4);  // brk #0 (break instruction for safe crash)
    EMIT_BYTES(&buf, 0x60, 0x02, 0x3f, 0xd6);  // blr x19 (branch with link to register)
#endif

    status = spec->generate_forward_epilogue(&buf, layout, return_type);
    if (status != FFI_SUCCESS)
        goto cleanup;

    // Check for memory allocation errors within the arena or code buffer.
    if (buf.error || arena->error) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    handle = infix_calloc(1, sizeof(ffi_trampoline_t));
    if (handle == nullptr) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    handle->exec = ffi_executable_alloc(buf.size);
    if (handle->exec.rw_ptr == nullptr) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        infix_free(handle);  // Manually free handle as ffi_trampoline_free won't be called
        handle = nullptr;
        goto cleanup;
    }

    infix_memcpy(handle->exec.rw_ptr, buf.code, buf.size);

    if (!ffi_executable_make_executable(handle->exec)) {
        ffi_executable_free(handle->exec);
        infix_free(handle);
        handle = nullptr;
        status = FFI_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    DumpHex(handle->exec.rx_ptr, handle->exec.size, "Forward Trampoline Machine Code");
    *out_trampoline = handle;

cleanup:
    // All temporary allocations (layout, code buffer) are cleaned up at once.
    arena_destroy(arena);
    return status;
}

/**
 * @brief Frees a forward trampoline and its associated executable memory.
 * @param trampoline The trampoline to free. Can be `nullptr`, in which case it does nothing.
 */
void ffi_trampoline_free(ffi_trampoline_t * trampoline) {
    if (trampoline == nullptr)
        return;
    ffi_executable_free(trampoline->exec);
    infix_free(trampoline);
}

/**
 * @brief Gets the system's memory page size.
 * @return The page size in bytes.
 */
static size_t get_page_size() {
#if defined(FFI_OS_WINDOWS)
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
 *          calls back into a user-provided handler. The process is highly optimized and
 *          follows a multi-stage generation process. A key part of this process is
 *          creating a **cached forward trampoline** that is used internally to call the
 *          user's C handler with the correct ABI.
 *
 * @param[out] out_context On success, will point to the context for the new reverse trampoline.
 * @param return_type The `ffi_type` of the callback's return value.
 * @param arg_types An array of `ffi_type*` for each argument.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of non-variadic arguments.
 * @param user_callback_fn A pointer to the user's C function that will be called.
 * @param user_data An arbitrary pointer that will be stored in the context.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard ffi_status generate_reverse_trampoline(ffi_reverse_trampoline_t ** out_context,
                                                     ffi_type * return_type,
                                                     ffi_type ** arg_types,
                                                     size_t num_args,
                                                     size_t num_fixed_args,
                                                     void * user_callback_fn,
                                                     void * user_data) {
    if (out_context == nullptr || num_fixed_args > num_args)
        return FFI_ERROR_INVALID_ARGUMENT;

    const ffi_reverse_abi_spec * spec = get_current_reverse_abi_spec();
    if (spec == nullptr)
        return FFI_ERROR_UNSUPPORTED_ABI;

    FFI_DEBUG_PRINTF("Generating Generic Reverse Trampoline");

    ffi_status status = FFI_SUCCESS;
    ffi_reverse_call_frame_layout * layout = nullptr;
    ffi_reverse_trampoline_t * context = nullptr;
    ffi_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    arena_t * arena = nullptr;
    code_buffer buf;

    // Use a larger arena (64KB) to handle extreme cases (I hope)
    arena = arena_create(65536);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    code_buffer_init(&buf, arena);

    size_t page_size = get_page_size();
    size_t context_alloc_size = (sizeof(ffi_reverse_trampoline_t) + page_size - 1) & ~(page_size - 1);
    prot = ffi_protected_alloc(context_alloc_size);
    if (prot.rw_ptr == nullptr) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    context = (ffi_reverse_trampoline_t *)prot.rw_ptr;
    infix_memset(context, 0, context_alloc_size);
    context->protected_ctx = prot;
    context->return_type = return_type;
    context->arg_types = arg_types;
    context->num_args = num_args;
    context->num_fixed_args = num_fixed_args;
    context->is_variadic = (num_fixed_args < num_args);
    context->user_callback_fn = user_callback_fn;
    context->user_data = user_data;
    context->internal_dispatcher = ffi_internal_dispatch_callback_fn_impl;

    // The user's callback handler expects the `ffi_reverse_trampoline_t*` context
    // as its FIRST argument. We must create a new argument type list that reflects this.
    // The new list will have `1 (for context) + num_args` elements.
    ffi_type ** callback_arg_types = arena_alloc(arena, (1 + num_args) * sizeof(ffi_type *), _Alignof(ffi_type *));
    if (callback_arg_types == NULL) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    // The first argument is the context pointer.
    callback_arg_types[0] = ffi_type_create_pointer();

    // Now, copy and promote the original user-defined arguments into the rest of the array.
    if (context->is_variadic) {
        for (size_t i = 0; i < num_args; ++i) {
            ffi_type * current_type = arg_types[i];
            if (i >= num_fixed_args) {  // Apply default argument promotions for variadic part.
                if (is_float(current_type))
                    callback_arg_types[i + 1] = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE);
                else if (current_type->category == FFI_TYPE_PRIMITIVE && current_type->size < sizeof(int))
                    callback_arg_types[i + 1] = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
                else
                    callback_arg_types[i + 1] = current_type;
            }
            else
                callback_arg_types[i + 1] = current_type;
        }
    }
    else {
        // For non-variadic functions, just copy the original types.
        if (num_args > 0)
            infix_memcpy(&callback_arg_types[1], arg_types, num_args * sizeof(ffi_type *));
    }

    // Generate the cached forward trampoline with the *correct, prepended* argument list.
    // The total number of arguments and fixed arguments are each increased by one.
    status = generate_forward_trampoline(
        &context->cached_forward_trampoline, return_type, callback_arg_types, num_args + 1, num_fixed_args + 1);

    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->prepare_reverse_call_frame(arena, &layout, context);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_reverse_prologue(&buf, layout);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_reverse_argument_marshalling(&buf, layout, context);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_reverse_dispatcher_call(&buf, layout, context);
    if (status != FFI_SUCCESS)
        goto cleanup;

    status = spec->generate_reverse_epilogue(&buf, layout, context);
    if (status != FFI_SUCCESS)
        goto cleanup;

    if (buf.error || arena->error) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    context->exec = ffi_executable_alloc(buf.size);
    if (context->exec.rw_ptr == nullptr) {
        status = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }

    infix_memcpy(context->exec.rw_ptr, buf.code, buf.size);
    size_t code_size = buf.size;

    if (!ffi_executable_make_executable(context->exec)) {
        status = FFI_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    if (!ffi_protected_make_readonly(context->protected_ctx)) {
        status = FFI_ERROR_PROTECTION_FAILED;
        goto cleanup;
    }

    FFI_DEBUG_PRINTF("Hardened reverse trampoline context at %p to be read-only.", (void *)context);
    DumpHex(context->exec.rx_ptr, code_size, "Reverse Trampoline Machine Code");

    *out_context = context;

cleanup:
    if (status != FFI_SUCCESS && context != nullptr)
        // If we failed, we must free the context and its nested resources.
        // ffi_reverse_trampoline_free handles this correctly.
        ffi_reverse_trampoline_free(context);

    arena_destroy(arena);
    return status;
}

/**
 * @brief Retrieves the executable code pointer from a reverse trampoline.
 * @param trampoline A handle to a previously created reverse trampoline.
 * @return A callable function pointer of type `ffi_cif_func`. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_reverse_trampoline_get_code(const ffi_reverse_trampoline_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->exec.rx_ptr;
}

/**
 * @brief Retrieves the user_data stored with a reverse trampoline.
 * @param trampoline A handle to opaque user_data.
 * @return Opaque pointer. Returns `nullptr` if the handle is invalid.
 */
c23_nodiscard void * ffi_reverse_trampoline_get_user_data(const ffi_reverse_trampoline_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return nullptr;
    return reverse_trampoline->user_data;
}

/**
 * @brief Frees a reverse trampoline, its JIT-compiled stub, and its context.
 * @details This function safely cleans up all resources associated with a reverse
 *          trampoline, including the cached forward trampoline, the executable stub,
 *          and the protected memory holding the context struct itself.
 * @param reverse_trampoline The reverse trampoline to free. Can be `nullptr`.
 */
void ffi_reverse_trampoline_free(ffi_reverse_trampoline_t * reverse_trampoline) {
    if (reverse_trampoline == nullptr)
        return;
    if (reverse_trampoline->cached_forward_trampoline)
        ffi_trampoline_free(reverse_trampoline->cached_forward_trampoline);
    ffi_executable_free(reverse_trampoline->exec);
    ffi_protected_free(reverse_trampoline->protected_ctx);
}

/**
 * @brief This section implements a unity build for the ABI-specific components.
 * @details Instead of relying on the build system to compile and link the correct
 * `abi_*.c` files, we include them directly into this compilation unit based on the
 * ABI selected in `infix.h`. This simplifies the build process and makes cross-ABI
 * fuzzing possible.
 */

#if defined(FFI_ABI_WINDOWS_X64)
#include "abi_win_x64.c"
#include "abi_x64_emitters.c"
#elif defined(FFI_ABI_SYSV_X64)
#include "abi_sysv_x64.c"
#include "abi_x64_emitters.c"
#elif defined(FFI_ABI_AAPCS64)
#include "abi_arm64.c"
#include "abi_arm64_emitters.c"
#else
#error "No supported ABI was selected for the unity build in trampoline.c."
#endif
