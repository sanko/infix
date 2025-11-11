/**
 * @file 811_fault_injection.c
 * @brief Unit test to verify resource cleanup under memory allocation failures.
 * @ingroup test_suite
 *
 * @details This test uses a fault injection technique to test the library's
 * resilience to memory allocation failures. It overrides the standard `malloc`
 * and `calloc` functions with custom versions (`test_malloc`, `test_calloc`) that
 * can be configured to fail after a specific number of successful allocations.
 *
 * The test strategy is as follows:
 * 1.  It iterates from `N = 0` to a maximum limit.
 * 2.  In each iteration `N`, it configures the custom allocator to fail on the N-th allocation.
 * 3.  It then calls a complex `infix` API function (e.g., `infix_forward_create`).
 * 4.  If the allocation failure was triggered, it asserts that the API function
 *     correctly returned an `INFIX_ERROR_ALLOCATION_FAILED` status.
 *
 * The most important part of this test is not the assertion itself, but running
 * it under a memory analysis tool like Valgrind or AddressSanitizer (ASan). A
 * "pass" for this test is a clean report from the memory tool, which proves that
 * even when an allocation fails midway through an operation, the `infix` library
 * correctly cleans up all memory it had allocated up to that point, preventing
 * memory leaks in error paths.
 */
// Override standard memory functions with our fault-injecting versions.#define infix_malloc test_malloc
#define infix_malloc test_malloc
#define infix_calloc test_calloc
#define infix_free test_free
#define infix_realloc test_realloc
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#else
#include <pthread.h>
#endif
static int allocation_countdown = -1;
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
#else
static pthread_mutex_t allocator_mutex = PTHREAD_MUTEX_INITIALIZER;
#define ALLOCATOR_LOCK() pthread_mutex_lock(&allocator_mutex)
#define ALLOCATOR_UNLOCK() pthread_mutex_unlock(&allocator_mutex)
#define ALLOCATOR_INIT() ((void)0)
#endif
void setup_fault_injector(int fail_after_n_allocs) {
    ALLOCATOR_LOCK();
    allocation_countdown = fail_after_n_allocs;
    allocation_counter = 0;
    fault_triggered = false;
    ALLOCATOR_UNLOCK();
}
void reset_fault_injector() {
    ALLOCATOR_LOCK();
    allocation_countdown = -1;
    ALLOCATOR_UNLOCK();
}
void * test_malloc(size_t size) {
    void * r = nullptr;
    ALLOCATOR_LOCK();
    if (allocation_countdown != -1) {
        if (allocation_counter >= allocation_countdown)
            fault_triggered = true;
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
    void * r = nullptr;
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
void test_free(void * ptr) { free(ptr); }
void * test_realloc(void * ptr, size_t new_size) {
    void * r = nullptr;
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
void fault_injection_handler(void) {}
TEST {
    plan(3);
    ALLOCATOR_INIT();
    subtest("Leak test for infix_forward_create failures") {
        const int MAX_FAILS_TO_TEST = 20;
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when infix_forward_create fails at every possible allocation.");
        const char * signature = "({*char, int}) -> void";
        bool success_was_reached = false;
        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            infix_forward_t * trampoline = nullptr;
            infix_status status =
                infix_forward_create(&trampoline, signature, (void *)fault_injection_handler, nullptr);
            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
            }
            else {
                success_was_reached = true;
                pass("Successfully created bound trampoline with %d allocations.", i);
                infix_forward_destroy(trampoline);
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                    skip(1, "Success point found.");
                break;
            }
        }
        if (!success_was_reached)
            fail("Test loop finished without succeeding. Increase MAX_FAILS_TO_TEST.");
        reset_fault_injector();
    }
    subtest("Leak test for infix_reverse_create_callback failures") {
        const int MAX_FAILS_TO_TEST = 20;
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when infix_reverse_create_callback fails at every possible allocation.");
        const char * signature = "({*char,int})->void";
        bool success_was_reached = false;
        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            infix_reverse_t * context = nullptr;
            infix_status status =
                infix_reverse_create_callback(&context, signature, (void *)fault_injection_handler, nullptr);
            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
                ok(context == nullptr, "Context handle is nullptr on failure");
            }
            else {
                success_was_reached = true;
                pass("Successfully created reverse trampoline with %d allocations.", i);
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
        const int MAX_FAILS_TO_TEST = 10;
        plan(MAX_FAILS_TO_TEST);
        note("Testing for leaks when creating a complex type from signature fails.");
        const char * signature = "{int, double, [10:{*char, short}]}";
        bool success_was_reached = false;
        for (int i = 0; i < MAX_FAILS_TO_TEST; ++i) {
            setup_fault_injector(i);
            infix_type * final_type = nullptr;
            infix_arena_t * arena = nullptr;
            infix_status status = infix_type_from_signature(&final_type, &arena, signature, nullptr);
            if (fault_triggered) {
                ok(status == INFIX_ERROR_ALLOCATION_FAILED, "Correctly failed on allocation #%d", i);
                ok(arena == nullptr && final_type == nullptr, "Arena and type are nullptr on failure");
            }
            else {
                success_was_reached = true;
                pass("Successfully created complex type with %d allocations.", i);
                for (int j = i + 1; j < MAX_FAILS_TO_TEST; ++j)
                    skip(1, "Success point found.");
                infix_arena_destroy(arena);
                break;
            }
        }
        if (!success_was_reached)
            fail("Type creation test loop finished without ever succeeding.");
        reset_fault_injector();
    }
}
