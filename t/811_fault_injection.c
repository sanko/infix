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
 * @file 811_fault_injection.c
 * @brief An advanced stress test that uses fault injection to find memory leaks
 *        in the library's error-handling code paths, adapted for the new arena model.
 *
 * @details This test replaces the standard malloc/calloc/free/realloc functions
 * with a custom, thread-safe allocator that can be programmed to fail after a
 * specific number of successful allocations.
 *
 * By repeatedly attempting to create complex FFI objects and forcing a
 * heap allocation failure at every possible point (e.g., arena creation,
 * handle creation, executable memory allocation), this test rigorously exercises
 * all error-handling and cleanup code in the library. It is designed to be
 * run under Valgrind's memcheck tool.
 *
 * The test is considered successful if two conditions are met:
 * 1.  The test program itself passes, confirming that the library correctly
 *     propagates `INFIX_ERROR_ALLOCATION_FAILED` status codes up the call stack.
 * 2.  Valgrind reports ZERO memory leaks, proving that all internal cleanup
 *     paths correctly free any partially allocated resources.
 *
 * This test targets the two most allocation-heavy high-level operations:
 * - `infix_reverse_create`
 * - `infix_type_from_signature`
 */

// Override infix's allocators with our custom ones *before* including headers.
#define infix_malloc test_malloc
#define infix_calloc test_calloc
#define infix_free test_free
#define infix_realloc test_realloc
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
// Platform-specific headers for thread-safe locking
#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <pthread.h>
#endif

// Fault-Injecting Allocator (Thread-Safe and Portable)

static int allocation_countdown = -1;  // -1 means "never fail"
static int allocation_counter = 0;
static bool fault_triggered = false;
#if defined(_WIN32) || defined(__CYGWIN__)
static CRITICAL_SECTION allocator_mutex;
static bool allocator_mutex_initialized = false;
#define ALLOCATOR_LOCK() EnterCriticalSection(&allocator_mutex)
#define ALLOCATOR_UNLOCK() LeaveCriticalSection(&allocator_mutex)
#define ALLOCATOR_INIT()                                 \
    do {                                                 \
        if (!allocator_mutex_initialized) {              \
            InitializeCriticalSection(&allocator_mutex); \
            allocator_mutex_initialized = true;          \
        }                                                \
    } while (0)
#else  // POSIX
static pthread_mutex_t allocator_mutex = PTHREAD_MUTEX_INITIALIZER;
#define ALLOCATOR_LOCK() pthread_mutex_lock(&allocator_mutex)
#define ALLOCATOR_UNLOCK() pthread_mutex_unlock(&allocator_mutex)
#define ALLOCATOR_INIT() ((void)0)  // pthreads mutex is statically initialized
#endif

/** @brief Configures the allocator to fail after a specific number of successful allocations. */
void setup_fault_injector(int fail_after_n_allocs) {
    ALLOCATOR_LOCK();
    allocation_countdown = fail_after_n_allocs;
    allocation_counter = 0;
    fault_triggered = false;
    ALLOCATOR_UNLOCK();
}

/** @brief Resets the allocator to its default (non-failing) behavior. */
void reset_fault_injector() {
    ALLOCATOR_LOCK();
    allocation_countdown = -1;
    ALLOCATOR_UNLOCK();
}

void * test_malloc(size_t size) {
    void * r = NULL;
    ALLOCATOR_LOCK();
    if (allocation_countdown != -1) {
        if (allocation_counter >= allocation_countdown)
            fault_triggered = true;  // Fail this allocation
        else {
            allocation_counter++;
            r = malloc(size);
        }
    }
    else
        r = malloc(size);

    ALLOCATOR_UNLOCK();
    return r;
}

void * test_calloc(size_t num, size_t size) {
    void * r = NULL;
    ALLOCATOR_LOCK();
    if (allocation_countdown != -1) {
        if (allocation_counter >= allocation_countdown)
            fault_triggered = true;
        else {
            allocation_counter++;
            r = calloc(num, size);
        }
    }
    else
        r = calloc(num, size);
    ALLOCATOR_UNLOCK();
    return r;
}

void test_free(void * ptr) {
    free(ptr);
}

void * test_realloc(void * ptr, size_t new_size) {
    void * r = NULL;
    ALLOCATOR_LOCK();
    if (allocation_countdown != -1) {
        if (allocation_counter >= allocation_countdown)
            fault_triggered = true;
        else {
            allocation_counter++;
            r = realloc(ptr, new_size);
        }
    }
    else
        r = realloc(ptr, new_size);

    ALLOCATOR_UNLOCK();
    return r;
}

// Dummy handler for trampoline generation.
void fault_injection_handler(void) {}

TEST {
    plan(3);

    ALLOCATOR_INIT();  // Initialize mutexes if needed (for Windows)

    subtest("Leak test for infix_forward_create_bound failures") {
        const int MAX_FAILS_TO_TEST = 20;
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when infix_forward_create_bound fails at every possible allocation.");
        const char * signature = "({*char, int}) -> void";
        bool success_was_reached = false;

        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            infix_forward_t * trampoline = NULL;
            infix_status status = infix_forward_create_bound(&trampoline, signature, (void *)fault_injection_handler);
            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
            }
            else {
                success_was_reached = true;
                pass("Successfully created bound trampoline with %d allocations.", i);
                infix_forward_destroy(trampoline);
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j) {
                    skip(1, "Success point found.");
                }
                break;
            }
        }
        if (!success_was_reached)
            fail("Test loop finished without succeeding. Increase MAX_FAILS_TO_TEST.");
        reset_fault_injector();
    }

    subtest("Leak test for infix_reverse_create failures") {
        const int MAX_FAILS_TO_TEST = 20;  // A reasonable upper bound on heap allocations
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when infix_reverse_create fails at every possible allocation.");

        // A complex signature to exercise the parser and JIT engine.
        const char * signature = "i*,d,p(1,1){c@0}=>v";
        bool success_was_reached = false;

        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);  // Fail on the i-th allocation
            infix_reverse_t * context = NULL;
            infix_status status = infix_reverse_create(&context, signature, (void *)fault_injection_handler, NULL);

            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
                // On failure, context should be null and no memory should be leaked.
                ok(context == NULL, "Context handle is NULL on failure");
            }
            else {
                // If we get here, it means we succeeded without triggering a fault.
                // We have now found the exact number of allocations required.
                success_was_reached = true;
                pass("Successfully created reverse trampoline with %d allocations.", i);
                // Since we plan for every test, we must explicitly skip the rest.
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                    skip(1, "Success point found, skipping further fault injections.");

                infix_reverse_destroy(context);
                break;
            }
        }
        if (!success_was_reached)
            fail(
                "Test loop finished without ever succeeding, which may indicate an issue or need for a higher "
                "MAX_FAILS_TO_TEST.");

        reset_fault_injector();
    }

    subtest("Leak test for infix_type_from_signature failures") {
        const int MAX_FAILS_TO_TEST = 10;  // This function should have very few heap allocations
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when creating a complex type from signature fails.");

        const char * signature = "{i, d, [10]{c*, s}}";  // Nested struct/array
        bool success_was_reached = false;

        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            infix_type * final_type = NULL;
            infix_arena_t * arena = NULL;

            infix_status status = infix_type_from_signature(&final_type, &arena, signature);

            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
                ok(arena == NULL && final_type == NULL, "Arena and type are NULL on failure");
            }
            else {
                success_was_reached = true;
                pass("Successfully created complex type with %d allocations.", i);
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                    skip(1, "Success point found.");

                // Cleanup on success
                infix_arena_destroy(arena);
                break;
            }
        }
        if (!success_was_reached)
            fail("Type creation test loop finished without ever succeeding.");
        reset_fault_injector();
    }
}
