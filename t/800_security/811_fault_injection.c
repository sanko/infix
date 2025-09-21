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
 *        in the library's error-handling code paths.
 *
 * @details This test replaces the standard malloc/calloc/free/realloc functions
 * with a custom, thread-safe allocator that can be programmed to fail after a
 * specific number of successful allocations.
 *
 * By repeatedly attempting to create complex FFI objects and forcing an
 * allocation failure at every possible point, this test rigorously exercises
 * all error-handling and cleanup code in the library. It is designed to be
 * run under Valgrind's memcheck tool.
 *
 * The test is considered successful if two conditions are met:
 * 1.  The test program itself passes, confirming that the library correctly
 *     propagates `FFI_ERROR_ALLOCATION_FAILED` status codes up the call stack.
 * 2.  Valgrind reports ZERO memory leaks, proving that all internal cleanup
 *     paths correctly free any partially allocated resources.
 *
 * This test targets the two most allocation-heavy operations:
 * - `generate_reverse_trampoline`
 * - `ffi_type_create_struct` with nested dynamic types.
 */

// Override infix's allocators with our custom ones *before* including headers.
#define infix_malloc test_malloc
#define infix_calloc test_calloc
#define infix_free test_free
#define infix_realloc test_realloc
#define DBLTAP_IMPLEMENTATION
#include "types.h"
#include <double_tap.h>
#include <infix.h>
#include <stddef.h>
#include <stdlib.h>
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
void fault_injection_handler(int a) {
    (void)a;
}

TEST {
    plan(2);

    ALLOCATOR_INIT();  // Initialize mutexes if needed (for Windows)

    subtest("Leak test for reverse trampoline creation failures") {
        const int MAX_FAILS_TO_TEST = 100;  // A reasonable upper bound on allocations
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when generate_reverse_trampoline fails at every possible allocation.");

        ffi_type * ret_type = ffi_type_create_void();
        ffi_type * arg_types[] = {ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)};
        bool success_was_reached = false;

        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);  // Fail on the i-th allocation
            ffi_reverse_trampoline_t * rt = NULL;
            ffi_status status =
                generate_reverse_trampoline(&rt, ret_type, arg_types, 1, 1, (void *)fault_injection_handler, NULL);

            if (fault_triggered)
                ok(status == FFI_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
            else {
                // If we get here, it means we succeeded without triggering a fault.
                // We have now found the exact number of allocations required.
                // We can now skip the remaining tests in this loop.
                success_was_reached = true;
                pass("Successfully created trampoline with %d allocations.", i);
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                    skip(1, "Success point found, skipping further fault injections.");

                ffi_reverse_trampoline_free(rt);
                break;
            }
        }
        if (!success_was_reached)
            fail("Test loop finished without ever succeeding, which may indicate an issue.");
        reset_fault_injector();
    }

    // This second subtest is essentially a duplicate of 901_error_handling_leaks.c, now consolidated.
    subtest("Leak test for ffi_type creation failures") {
        const int MAX_FAILS_TO_TEST = 20;
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when creating a complex, nested struct fails.");

        bool success_was_reached = false;
        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            ffi_type * final_type = NULL;
            ffi_status status = FFI_SUCCESS;

            ffi_struct_member * point_members = test_malloc(sizeof(ffi_struct_member) * 2);
            if (!point_members) {
                ok(fault_triggered, "Fail #%d: at point_members allocation", i);
                continue;
            }
            point_members[0] =
                ffi_struct_member_create("x", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, x));
            point_members[1] =
                ffi_struct_member_create("y", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE), offsetof(Point, y));

            ffi_type * point_type = NULL;
            status = ffi_type_create_struct(&point_type, point_members, 2);
            if (status != FFI_SUCCESS) {
                ok(fault_triggered, "Fail #%d: during point_type creation", i);
                test_free(point_members);
                continue;
            }

            ffi_struct_member * element_members = test_malloc(sizeof(ffi_struct_member) * 2);
            if (!element_members) {
                ok(fault_triggered, "Fail #%d: at element_members allocation", i);
                ffi_type_destroy(point_type);
                continue;
            }
            element_members[0] = ffi_struct_member_create(
                "id", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32), offsetof(Point, x));
            element_members[1] = ffi_struct_member_create("p", point_type, sizeof(int));

            status = ffi_type_create_struct(&final_type, element_members, 2);
            if (status != FFI_SUCCESS) {
                ok(fault_triggered, "Fail #%d: during final_type creation", i);
                test_free(element_members);
                ffi_type_destroy(point_type);
                continue;
            }

            success_was_reached = true;
            pass("Successfully created complex type with %d allocations.", i);
            ffi_type_destroy(final_type);
            for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                skip(1, "Success point found.");
            break;
        }
        if (!success_was_reached)
            fail("Type creation test loop finished without ever succeeding.");

        reset_fault_injector();
    }
}
