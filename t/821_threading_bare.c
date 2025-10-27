/**
 * @file 821_threading_bare.c
 * @brief A minimal, dependency-free version of the thread-safety stress test.
 * @ingroup test_suite
 *
 * @internal
 * This file is a stripped-down version of `820_threading_helgrind.c`. It performs
 * the same multi-threaded stress test of creating and destroying trampolines, but
 * it does not link against the `double_tap.h` test harness.
 *
 * The purpose of this "bare" test is to provide a minimal-footprint executable
 * that is easier and faster for thread sanitizers like Helgrind to analyze. The
 * `double_tap` harness, while useful, adds extra complexity with its own mutexes
 * and thread-local state for printing, which can sometimes clutter the output of
 * a sanitizer.
 *
 * This test prints basic TAP output manually and exits with a status code, but
 * its primary success condition is a clean report from the thread sanitizer.
 */

#include "common/infix_config.h"
#include <infix/infix.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if defined(INFIX_OS_WINDOWS) || defined(INFIX_ENV_CYGWIN)
#include <windows.h>
#else
#include <pthread.h>
#endif

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 500

void bare_helgrind_handler(int a, int b) {
    (void)a;
    (void)b;
}

#if defined(INFIX_OS_WINDOWS) || defined(__CYGWIN__)
DWORD WINAPI bare_thread_worker(LPVOID arg) {
#else
void * bare_thread_worker(void * arg) {
#endif
    (void)arg;

    infix_type * ret_type = infix_type_create_void();
    infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
    typedef void (*my_func_ptr)(int, int);

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        infix_reverse_t * rt = nullptr;

        infix_status status =
            infix_reverse_create_callback_manual(&rt, ret_type, arg_types, 2, 2, (void *)bare_helgrind_handler);
        if (status != INFIX_SUCCESS) {
            fprintf(stderr, "# Thread failed to generate reverse trampoline.\n");
#if defined(INFIX_OS_WINDOWS) || defined(__CYGWIN__)
            return (DWORD)(intptr_t)1;
#else
            return (void *)(intptr_t)1;
#endif
        }

        my_func_ptr callable_func = (my_func_ptr)infix_reverse_get_code(rt);
        if (callable_func)
            callable_func(i, i + 1);

        infix_reverse_destroy(rt);
    }

#if defined(INFIX_OS_WINDOWS) || defined(__CYGWIN__)
    return (DWORD)(intptr_t)0;
#else
    return (void *)(intptr_t)0;
#endif
}

int main(void) {
    printf("TAP version 13\n");
    printf("1..1\n");
    printf("# Starting barebones Helgrind thread-safety stress test...\n");
    printf("#   - Threads: %d\n", NUM_THREADS);
    printf("#   - Iterations per thread: %d\n", ITERATIONS_PER_THREAD);
    printf("#   - Success requires exit code 0 AND a clean Helgrind report.\n");
    fflush(stdout);

    bool any_thread_failed = false;

#if defined(INFIX_OS_WINDOWS) || defined(__CYGWIN__)
    HANDLE threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads[i] = CreateThread(nullptr, 0, bare_thread_worker, nullptr, 0, nullptr);
        if (threads[i] == nullptr) {
            fprintf(stderr, "# FATAL: CreateThread failed.\n");
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
        GetExitCodeThread(threads[i], &exit_code);
        if (exit_code != 0) {
            fprintf(stderr, "# ERROR: Thread %d returned a failure status.\n", i);
            any_thread_failed = true;
        }
        CloseHandle(threads[i]);
    }
#else
    pthread_t threads[NUM_THREADS] = {0};
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_create(&threads[i], nullptr, bare_thread_worker, nullptr) != 0) {
            perror("# FATAL: pthread_create failed");
            any_thread_failed = true;
            break;
        }
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        if (threads[i] == 0)
            continue;
        void * retval;
        if (pthread_join(threads[i], &retval) != 0) {
            perror("# FATAL: pthread_join failed");
            any_thread_failed = true;
        }
        if ((intptr_t)retval != 0) {
            fprintf(stderr, "# ERROR: Thread %d returned a failure status.\n", i);
            any_thread_failed = true;
        }
    }
#endif

    if (any_thread_failed) {
        printf("not ok 1 - One or more threads reported an error.\n");
        return 1;
    }

    printf("ok 1 - All threads completed successfully.\n");
    return 0;
}
