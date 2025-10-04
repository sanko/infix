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
 * @file 840_arena_allocator.c
 * @brief Unit tests for the internal arena allocator.
 *
 * @details This test validates the core functionality of the arena (bump)
 * allocator in isolation. It verifies:
 * 1.  Correct creation and destruction of the arena.
 * 2.  That `infix_arena_alloc` returns non-NULL pointers for valid requests.
 * 3.  That pointers returned by `infix_arena_alloc` are correctly aligned.
 * 4.  That `infix_arena_calloc` returns zero-initialized memory.
 * 5.  That the allocator correctly detects out-of-memory conditions and returns
 *     NULL without crashing when the arena's capacity is exceeded.
 */

// We must define our own allocators for this test to be self-contained
// and not interfere with other tests that might use fault injection.
#define infix_malloc malloc
#define infix_calloc calloc
#define infix_free free
#define infix_realloc realloc
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "core/arena.c"  // Include the .c file directly for white-box testing
#include <infix/infix.h>
#include <stdint.h>
#include <string.h>

TEST {
    plan(1);

    subtest("Arena Allocator Core Functionality") {
        plan(7);

        // 1. Test Creation and Destruction
        infix_arena_t * arena = infix_arena_create(1024);
        ok(arena != NULL && arena->buffer != NULL, "infix_arena_create succeeds");
        if (!arena) {
            skip(6, "Cannot proceed without a valid arena");
            return;
        }

        // 2. Test Basic Allocation
        void * p1 = infix_arena_alloc(arena, 10, 1);
        ok(p1 != NULL, "infix_arena_alloc returns a valid pointer");

        // 3. Test Alignment
        // Allocate a single byte to misalign the offset, then allocate an aligned type.
        (void)infix_arena_alloc(arena, 1, 1);
        uint64_t * aligned_ptr = infix_arena_alloc(arena, sizeof(uint64_t), _Alignof(uint64_t));
        ok(aligned_ptr != NULL, "infix_arena_alloc for aligned type succeeds");
        ok(((uintptr_t)aligned_ptr % _Alignof(uint64_t)) == 0, "Pointer is correctly aligned");

        // 4. Test infix_arena_calloc
        char * zeroed_ptr = infix_arena_calloc(arena, 1, 32, 1);
        bool is_zeroed = true;
        for (int i = 0; i < 32; ++i) {
            if (zeroed_ptr[i] != 0) {
                is_zeroed = false;
                break;
            }
        }
        ok(is_zeroed, "infix_arena_calloc returns zero-initialized memory");

        // 5. Test Out-of-Memory Condition
        void * p_fail = infix_arena_alloc(arena, 2048, 1);  // Request more than is available
        ok(p_fail == NULL, "infix_arena_alloc returns NULL when out of memory");
        ok(arena->error == true, "Arena error flag is set on allocation failure");

        infix_arena_destroy(arena);
    }
}
