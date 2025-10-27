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
 * @file arena.c
 * @brief Implements a simple, fast arena (or region-based) allocator.
 * @ingroup internal_core
 *
 * @details Arenas provide a mechanism for fast, grouped memory allocations that can all
 * be freed at once with a single call. This allocation strategy is also known as
 * region-based memory management.
 *
 * An arena works by pre-allocating a large, contiguous block of memory (the "region").
 * Subsequent allocation requests are satisfied by simply "bumping" a pointer
 * within this block. This "bump allocation" is extremely fast as it involves only
 * pointer arithmetic and avoids the overhead of system calls (`malloc`/`free`) for
 * each small allocation.
 *
 * This model is used extensively by the `infix` type system to manage the
 * lifetime of `infix_type` object graphs. When a type is created from a signature
 * or via the Manual API, all its constituent nodes are allocated from a single
 * arena. When the type is no longer needed, destroying the arena frees all
 * associated memory at once, preventing memory leaks and eliminating the need
 * for complex reference counting or garbage collection.
 */

#include "common/infix_internals.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @internal
 * @brief Creates a new memory arena with a specified initial size.
 *
 * Allocates an `infix_arena_t` struct and its backing buffer in a single block
 * of memory. If allocation fails at any point, it cleans up successfully allocated
 * parts, sets a detailed error, and returns `nullptr`.
 *
 * @param initial_size The number of bytes for the initial backing buffer. A larger
 *        size can reduce the chance of reallocation for complex types.
 * @return A pointer to the new `infix_arena_t`, or `nullptr` on failure.
 */
c23_nodiscard infix_arena_t * infix_arena_create(size_t initial_size) {
    // Use calloc to ensure the initial struct state is zeroed.
    infix_arena_t * arena = infix_calloc(1, sizeof(infix_arena_t));
    if (arena == nullptr) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }

    arena->buffer = infix_calloc(1, initial_size);
    if (arena->buffer == nullptr && initial_size > 0) {
        infix_free(arena);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }

    arena->capacity = initial_size;
    arena->current_offset = 0;
    arena->error = false;

    return arena;
}

/**
 * @internal
 * @brief Destroys an arena and frees all memory associated with it.
 *
 * This function frees the arena's single backing buffer and the `infix_arena_t`
 * struct itself. Any pointers returned by `infix_arena_alloc` from this arena
 * become invalid after this call. It is safe to call this function with a
 * `nullptr` argument.
 *
 * @param arena A pointer to the arena to destroy.
 */
void infix_arena_destroy(infix_arena_t * arena) {
    if (arena == nullptr)
        return;

    if (arena->buffer)
        infix_free(arena->buffer);

    infix_free(arena);
}

/**
 * @internal
 * @brief Allocates a block of memory from an arena with a specified alignment.
 *
 * This is a "bump" allocator. It calculates the next memory address that satisfies
 * the requested alignment, checks if there is sufficient capacity in the arena's
 * buffer, and if so, "bumps" the `current_offset` pointer and returns the address.
 *
 * This operation is extremely fast as it involves no system calls, only simple
 * integer and pointer arithmetic.
 *
 * If an allocation fails (due to insufficient space or invalid arguments), the
 * arena's `error` flag is set, a detailed error is reported, and all subsequent
 * allocations from this arena will also fail.
 *
 * @param arena The arena to allocate from.
 * @param size The number of bytes to allocate.
 * @param alignment The required alignment for the allocation. Must be a power of two.
 * @return A pointer to the allocated memory, or `nullptr` if the arena is out of
 *         memory, has its error flag set, or an invalid alignment is requested.
 */
c23_nodiscard void * infix_arena_alloc(infix_arena_t * arena, size_t size, size_t alignment) {
    if (arena == nullptr || arena->error)
        return nullptr;

    // Alignment must be a power of two for the bitwise alignment trick to work.
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        arena->error = true;
        // This is a programmatic error. `INFIX_CODE_UNKNOWN` is the best fit from existing codes.
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return nullptr;
    }

    // A zero-size allocation simply returns the current aligned pointer without advancing it.
    if (size == 0)
        return (void *)(arena->buffer + arena->current_offset);

    // Calculate the next offset that meets the alignment requirement.
    size_t aligned_offset = _infix_align_up(arena->current_offset, alignment);

    // Security: Check for integer overflow on the alignment calculation.
    if (aligned_offset < arena->current_offset) {
        arena->error = true;
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_INTEGER_OVERFLOW, 0);
        return nullptr;
    }

    // Security: Check for integer overflow on the final size calculation and for capacity.
    if (SIZE_MAX - size < aligned_offset || aligned_offset + size > arena->capacity) {
        arena->error = true;
        // This is an out-of-memory condition for this specific arena.
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }

    void * ptr = arena->buffer + aligned_offset;
    arena->current_offset = aligned_offset + size;
    return ptr;
}

/**
 * @internal
 * @brief Allocates and zero-initializes a block of memory from an arena.
 *
 * This function is a convenience wrapper around `infix_arena_alloc` that also
 * ensures the allocated memory is set to zero, mimicking the behavior of `calloc`.
 * It includes a check for integer overflow on the `num * size` calculation and
 * will set a detailed error on failure.
 *
 * @param arena The arena to allocate from.
 * @param num The number of elements to allocate.
 * @param size The size of each element.
 * @param alignment The required alignment for the allocation. Must be a power of two.
 * @return A pointer to the zero-initialized memory, or `nullptr` on failure.
 */
c23_nodiscard void * infix_arena_calloc(infix_arena_t * arena, size_t num, size_t size, size_t alignment) {
    // Security: Check for multiplication overflow.
    if (size > 0 && num > SIZE_MAX / size) {
        if (arena)
            arena->error = true;
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_INTEGER_OVERFLOW, 0);
        return nullptr;
    }

    size_t total_size = num * size;
    void * ptr = infix_arena_alloc(arena, total_size, alignment);

    if (ptr != nullptr)
        memset(ptr, 0, total_size);

    return ptr;
}
