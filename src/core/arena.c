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
 * @brief Implementation of the internal arena allocator.
 *
 * @details This file provides the concrete implementations for the arena
 * allocator's functions. It contains the logic for creating the arena,
 * performing fast, aligned "bump" allocations, and destroying the arena
 * to free all its memory at once.
 *
 * The implementation includes security-critical checks to prevent integer
 * overflows when calculating allocation sizes and offsets, making it safe
 * for use with potentially untrusted inputs from the fuzzing harnesses.
 */

#include <infix.h>
#include <stdint.h>  // For uintptr_t
#include <stdlib.h>
#include <string.h>  // For memset

/**
 * @brief Creates and initializes a new memory arena.
 * @details Allocates two blocks of memory: one for the `arena_t` controller
 *          struct itself and a second, larger block for the arena's buffer.
 *          If either allocation fails, it ensures any partially allocated
 *          memory is cleaned up to prevent leaks.
 *
 * @param initial_size The number of bytes to pre-allocate for the arena's main buffer.
 * @return A pointer to the newly created `arena_t`, or `nullptr` if any memory
 *         allocation fails.
 */
arena_t * arena_create(size_t initial_size) {
    // Allocate the arena controller struct itself.
    arena_t * arena = infix_malloc(sizeof(arena_t));
    if (arena == nullptr)
        return nullptr;

    // Allocate the main memory block for the arena.
    arena->buffer = infix_malloc(initial_size);
    if (arena->buffer == nullptr && initial_size > 0) {
        infix_free(arena);  // Clean up on partial failure.
        return nullptr;
    }

    arena->capacity = initial_size;
    arena->current_offset = 0;
    arena->error = false;

    return arena;
}

/**
 * @brief Frees an entire memory arena and all objects allocated within it.
 * @details This is the primary cleanup function for an arena. It frees the main
 *          memory buffer and then frees the `arena_t` struct itself. It is
 *          safe to call this function with a `nullptr` argument.
 *
 * @param arena The arena to destroy. Can be `nullptr`, in which case it is a no-op.
 */
void arena_destroy(arena_t * arena) {
    if (arena == nullptr)
        return;

    // Free the main buffer, then the controller struct.
    if (arena->buffer)
        infix_free(arena->buffer);

    infix_free(arena);
}

/**
 * @brief Allocates a block of memory from the arena with a specific alignment.
 * @details This is the core "bump" allocation logic. It calculates the necessary
 *          padding to align the current offset to the requested boundary. It
 *          performs multiple security checks to prevent integer overflows during
 *          this calculation. If the requested size (plus padding) fits within
 *          the arena's capacity, it advances the `current_offset` and returns the
 *          aligned pointer. Otherwise, it sets the arena's internal error flag
 *          and returns `nullptr`.
 *
 * @param arena The arena to allocate from.
 * @param size The number of bytes requested.
 * @param alignment The required alignment for the returned pointer. Must be a power of two.
 * @return A pointer to the allocated memory, or `nullptr` on failure (out of memory,
 *         overflow, or invalid alignment).
 */
void * arena_alloc(arena_t * arena, size_t size, size_t alignment) {
    // Fail immediately if the arena is null or already in an error state.
    if (arena == nullptr || arena->error)
        return nullptr;

    // Alignment must be a power of two. This is a common check.
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        arena->error = true;
        return nullptr;
    }

    // An allocation of zero bytes should return a valid, unique pointer per the C standard.
    // We return a pointer to the current position without advancing it.
    if (size == 0)
        return (void *)(arena->buffer + arena->current_offset);

    // Calculate the padding required to meet the alignment.
    uintptr_t current_ptr = (uintptr_t)arena->buffer + arena->current_offset;
    uintptr_t aligned_ptr = (current_ptr + alignment - 1) & ~(alignment - 1);
    size_t padding = aligned_ptr - current_ptr;

    // Check if adding padding would overflow size_t.
    if (arena->current_offset > SIZE_MAX - padding) {
        arena->error = true;
        return nullptr;
    }
    size_t aligned_offset = arena->current_offset + padding;
    // Check if adding the requested size would overflow size_t.
    if (aligned_offset > SIZE_MAX - size) {
        arena->error = true;
        return nullptr;
    }

    // Check if there is enough space left in the arena.
    if (aligned_offset + size > arena->capacity) {
        arena->error = true;
        return nullptr;
    }

    // Bump the pointer and return the aligned address.
    arena->current_offset = aligned_offset + size;
    return (void *)aligned_ptr;
}

/**
 * @brief Allocates a zero-initialized block of memory from the arena.
 * @details This is a convenience wrapper around `arena_alloc`. It first calculates
 *          the total size required (`num * size`), checking for integer overflow.
 *          It then calls `arena_alloc` to get the memory block and, if successful,
 *          uses `memset` to zero it out.
 *
 * @param arena The arena to allocate from.
 * @param num The number of elements to allocate.
 * @param size The size of each element in bytes.
 * @param alignment The required alignment of the returned pointer.
 * @return A pointer to the zero-initialized memory block, or `nullptr` on failure.
 */
void * arena_calloc(arena_t * arena, size_t num, size_t size, size_t alignment) {
    // Security: Check for integer overflow in the size calculation.
    if (size > 0 && num > SIZE_MAX / size) {
        if (arena)
            arena->error = true;
        return nullptr;
    }

    size_t total_size = num * size;
    void * ptr = arena_alloc(arena, total_size, alignment);

    // If allocation was successful, zero out the memory.
    if (ptr != nullptr)
        memset(ptr, 0, total_size);

    return ptr;
}
