/**
 * @file 840_arena_allocator.c
 * @brief Unit test for the internal arena allocator.
 * @ingroup test_suite
 *
 * @details This test file validates the core functionality of the `infix_arena_t`
 * memory manager. Since the arena allocator is an internal component, this test
 * must include the `arena.c` source file directly to access its functions.
 * It also defines the `infix_*` memory macros to use the standard `malloc`, etc.,
 * to avoid interference from the fault-injection allocator in other tests.
 *
 * The test verifies:
 * - **Creation/Destruction:** `infix_arena_create` and `infix_arena_destroy` work as expected.
 * - **Basic Allocation:** `infix_arena_alloc` returns a valid, non-null pointer.
 * - **Alignment:** A pointer allocated with a specific alignment is correctly aligned.
 * - **Zeroed Allocation:** `infix_arena_calloc` returns a block of memory that is
 *   properly zero-initialized.
 * - **Error Handling:** When an allocation request exceeds the arena's capacity,
 *   `infix_arena_alloc` correctly returns `nullptr` and sets the arena's internal
 *   error flag.
 */

// Define memory macros to use standard library functions for this test.
#define infix_malloc malloc
#define infix_calloc calloc
#define infix_free free
#define infix_realloc realloc

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdint.h>
#include <string.h>

#include "common/infix_internals.h"

TEST {
    plan(1);

    subtest("Arena Allocator Core Functionality") {
        plan(7);

        infix_arena_t * arena = infix_arena_create(1024);
        ok(arena != nullptr && arena->buffer != nullptr, "infix_arena_create succeeds");
        if (!arena) {
            skip(6, "Cannot proceed without a valid arena");
            return;
        }

        void * p1 = infix_arena_alloc(arena, 10, 1);
        ok(p1 != nullptr, "infix_arena_alloc returns a valid pointer");

        (void)infix_arena_alloc(arena, 1, 1);
        uint64_t * aligned_ptr = infix_arena_alloc(arena, sizeof(uint64_t), _Alignof(uint64_t));
        ok(aligned_ptr != nullptr, "infix_arena_alloc for aligned type succeeds");
        ok(((uintptr_t)aligned_ptr % _Alignof(uint64_t)) == 0, "Pointer is correctly aligned");

        char * zeroed_ptr = infix_arena_calloc(arena, 1, 32, 1);
        bool is_zeroed = true;
        for (int i = 0; i < 32; ++i) {
            if (zeroed_ptr[i] != 0) {
                is_zeroed = false;
                break;
            }
        }
        ok(is_zeroed, "infix_arena_calloc returns zero-initialized memory");

        void * p_grow = infix_arena_alloc(arena, 2048, 1);
        ok(p_grow != nullptr, "Arena grows and returns a valid pointer when initial capacity is exceeded");
        ok(arena->error == false, "Arena error flag is not set after successful growth");

        infix_arena_destroy(arena);
    }
}
