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
 * @ingroup memory_management
 *
 * @internal
 * This file provides the concrete implementations for the arena allocator's public API.
 * It contains the logic for creating the arena, performing fast, aligned "bump"
 * allocations, and destroying the arena to free all its memory at once.
 *
 * The implementation includes security-critical checks to prevent integer overflows
 * when calculating allocation sizes and offsets, making it safe for use with
 * potentially untrusted inputs from parsers or fuzzing harnesses.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <stdint.h>  // For uintptr_t, SIZE_MAX
#include <stdlib.h>
#include <string.h>  // For memset

/*
 * Implementation for infix_arena_create.
 * This function allocates two separate blocks of memory: one for the `infix_arena_t`
 * controller struct itself, and a second, larger block for the arena's main buffer.
 * It includes logic to prevent memory leaks if the second allocation fails.
 */
infix_arena_t * infix_arena_create(size_t initial_size) {
    // Allocate the arena controller struct itself.
    infix_arena_t * arena = infix_malloc(sizeof(infix_arena_t));
    if (arena == nullptr)
        return nullptr;

    // Allocate the main memory block for the arena.
    arena->buffer = infix_malloc(initial_size);
    if (arena->buffer == nullptr && initial_size > 0) {
        // Critical cleanup: if the main buffer allocation fails, we must free
        // the `arena` struct itself to prevent a memory leak.
        infix_free(arena);
        return nullptr;
    }

    arena->capacity = initial_size;
    arena->current_offset = 0;
    arena->error = false;

    return arena;
}

/*
 * Implementation for infix_arena_destroy.
 * This function frees the main memory buffer and then the `infix_arena_t` struct.
 * It is safe to call with a `nullptr` argument.
 */
void infix_arena_destroy(infix_arena_t * arena) {
    if (arena == nullptr)
        return;

    // Free the main buffer first, then the controller struct.
    if (arena->buffer)
        infix_free(arena->buffer);

    infix_free(arena);
}

/*
 * Implementation for infix_arena_alloc.
 * This is the core "bump" allocation logic. It calculates the necessary padding
 * to align the current offset and performs multiple security checks to prevent
 * integer overflows. If the request fits, it advances the `current_offset` and
 * returns the aligned pointer; otherwise, it sets the arena's error flag.
 */
void * infix_arena_alloc(infix_arena_t * arena, size_t size, size_t alignment) {
    // Fail immediately if the arena is null or already in an error state.
    if (arena == nullptr || arena->error)
        return nullptr;

    // Security: Alignment must be a power of two. This is a common and critical check.
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        arena->error = true;
        return nullptr;
    }

    // Per the C standard, an allocation of zero bytes should return a valid, unique pointer.
    // We return a pointer to the current position without advancing the offset.
    if (size == 0)
        return (void *)(arena->buffer + arena->current_offset);

    // Calculate the next aligned offset using the shared helper.
    size_t aligned_offset = _infix_align_up(arena->current_offset, alignment);

    // Security: Check for integer overflow during the alignment calculation.
    if (aligned_offset < arena->current_offset) {
        arena->error = true;
        return nullptr;
    }

    // Security: Check if adding the requested size would overflow size_t or exceed capacity.
    if (SIZE_MAX - size < aligned_offset || aligned_offset + size > arena->capacity) {
        arena->error = true;
        return nullptr;
    }

    // All checks passed. Get the pointer and "bump" the offset.
    void * ptr = arena->buffer + aligned_offset;
    arena->current_offset = aligned_offset + size;
    return ptr;
}

/*
 * Implementation for infix_arena_calloc.
 * This is a convenience wrapper around `infix_arena_alloc` that also zeroes the memory.
 * It includes a critical security check to prevent integer overflow when calculating
 * the total allocation size.
 */
void * infix_arena_calloc(infix_arena_t * arena, size_t num, size_t size, size_t alignment) {
    // Security: Check for integer overflow in the `num * size` calculation.
    if (size > 0 && num > SIZE_MAX / size) {
        if (arena)
            arena->error = true;
        return nullptr;
    }

    size_t total_size = num * size;
    void * ptr = infix_arena_alloc(arena, total_size, alignment);

    // If allocation was successful, zero out the memory.
    if (ptr != nullptr)
        memset(ptr, 0, total_size);

    return ptr;
}
