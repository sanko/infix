/**
 * @file 820_threading_helgrind.c
 * @brief A stress test to detect data races and other threading issues.
 * @ingroup test_suite
 *
 * @details This test is designed to be run with a thread sanitizer tool, such as
 * Valgrind's Helgrind or GCC/Clang's `-fsanitize=thread` (TSan). Its purpose is to
 * verify that the `infix` library's use of thread-local storage (TLS) for error
 * handling and other contexts is correct and free of data races.
 *
 * The test spawns multiple threads, and each thread independently runs a tight loop
 * of creating, using, and destroying `infix` trampolines.
 *
 * A "pass" for this test is not just that the program completes successfully, but
 * that the thread sanitizer tool reports zero data races or other synchronization
 * errors. This is critical for ensuring that `infix` is safe to use in multi-threaded
 * applications.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <infix/infix.h>
#include <stdbool.h>

#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else
#include <pthread.h>
#include <stdint.h>
#endif

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 500

void helgrind_test_handler(int a, int b) {
    (void)a;
    (void)b;
}

#if defined(INFIX_OS_WINDOWS)
DWORD WINAPI helgrind_thread_worker(LPVOID arg) {
#else
void * helgrind_thread_worker(void * arg) {
#endif
    (void)arg;

    infix_type * ret_type = infix_type_create_void();
    infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
    typedef void (*my_func_ptr)(int, int);

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        infix_reverse_t * rt = nullptr;

        infix_status status =
            infix_reverse_create_callback_manual(&rt, ret_type, arg_types, 2, 2, (void *)helgrind_test_handler);
        if (status != INFIX_SUCCESS)

#if defined(_WIN32)
            return 1;
#else
            return (void *)(intptr_t)1;
#endif

        my_func_ptr callable_func = (my_func_ptr)infix_reverse_get_code(rt);
        if (callable_func)
            callable_func(i, i + 1);

        infix_reverse_destroy(rt);
    }

#if defined(INFIX_OS_WINDOWS)
    return 0;
#else
    return (void *)(intptr_t)0;
#endif
}

TEST {
    plan(1);

    subtest("Thread-safety stress test") {
        plan(1);
        note("Starting %d threads, each running %d create/destroy cycles.", NUM_THREADS, ITERATIONS_PER_THREAD);
        note("Success is a clean report from the thread sanitizer (e.g., Helgrind).");

        bool any_thread_failed = false;

#if defined(INFIX_OS_WINDOWS)
        HANDLE threads[NUM_THREADS] = {0};
        for (int i = 0; i < NUM_THREADS; ++i) {
            threads[i] = CreateThread(nullptr, 0, helgrind_thread_worker, nullptr, 0, nullptr);
            if (threads[i] == nullptr) {
                diag("FATAL: CreateThread failed for thread %d.", i);
                any_thread_failed = true;
                break;
            }
        }

        if (!any_thread_failed)
            WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

        for (int i = 0; i < NUM_THREADS; ++i) {
            if (threads[i] == nullptr)
                continue;
            DWORD exit_code;
            if (GetExitCodeThread(threads[i], &exit_code)) {
                if (exit_code != 0) {
                    note("Thread %d returned a failure status (exit code %lu).", i, exit_code);
                    any_thread_failed = true;
                }
            }
            else {
                diag("FATAL: GetExitCodeThread failed for thread %d.", i);
                any_thread_failed = true;
            }
            CloseHandle(threads[i]);
        }
#else
        pthread_t threads[NUM_THREADS] = {0};
        for (int i = 0; i < NUM_THREADS; ++i) {
            if (pthread_create(&threads[i], nullptr, helgrind_thread_worker, nullptr) != 0) {
                perror("FATAL: pthread_create failed");
                any_thread_failed = true;
                break;
            }
        }

        for (int i = 0; i < NUM_THREADS; ++i) {
            if (threads[i] == 0)
                continue;
            void * retval;
            if (pthread_join(threads[i], &retval) != 0) {
                perror("FATAL: pthread_join failed");
                any_thread_failed = true;
            }
            if ((intptr_t)retval != 0) {
                note("Thread %d returned a failure status.", i);
                any_thread_failed = true;
            }
        }
#endif

        ok(!any_thread_failed, "All threads completed successfully. Check sanitizer output for data races.");
    }
}
