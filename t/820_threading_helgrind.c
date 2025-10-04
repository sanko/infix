<<<<<<< HEAD:t/820_threading_helgrind.c
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
 * @file 820_threading_helgrind.c
 * @brief A cross-platform test for thread-safety issues using Valgrind's Helgrind tool
 *        or other thread sanitizers.
 *
 * @details This test is designed to be run specifically under thread analysis tools.
 * It creates multiple threads that concurrently generate, use, and destroy FFI
 * reverse trampolines (callbacks). The tool will analyze the execution for
 * potential data races and other synchronization errors in the underlying library code.
 *
 * This version of the test is structured to be free of data races in the test
 * code itself. All reporting is done by the main thread after all worker threads
 * have completed. Therefore, a successful run should produce ZERO errors from the
 * analysis tool. Any reported error indicates a genuine thread-safety bug within the
 * infix library.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>
#include <stdbool.h>  // For bool type

// Platform-specific headers and definitions for threading
#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else
#include <pthread.h>
#include <stdint.h>  // For intptr_t
#endif

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 500

// A simple C callback function. It does nothing, as its purpose is just to be a valid call target.
void helgrind_test_handler(infix_context_t * context, int a, int b) {
    (void)context;
    (void)a;
    (void)b;
}

// The main function that will be executed by each worker thread.
// It returns a status code (0 for success, 1 for failure) in a platform-agnostic way.
#if defined(INFIX_OS_WINDOWS)
DWORD WINAPI helgrind_thread_worker(LPVOID arg) {
#else
void * helgrind_thread_worker(void * arg) {
#endif
    (void)arg;

    // Define the FFI types for the callback signature: void(int, int)
    infix_type * ret_type = infix_type_create_void();
    infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
    typedef void (*my_func_ptr)(int, int);

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        infix_reverse_t * rt = NULL;

        // Generate the reverse trampoline. This is a critical area for thread-safety.
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 2, 2, (void *)helgrind_test_handler, NULL);
        if (status != INFIX_SUCCESS)
// Return a failure status that the main thread can check.
#if defined(_WIN32)
            return 1;
#else
            return (void *)(intptr_t)1;
#endif

        // Get and invoke the callable function pointer.
        my_func_ptr callable_func = (my_func_ptr)infix_reverse_get_code(rt);
        if (callable_func)
            callable_func(i, i + 1);

        // Destroy the reverse trampoline. This is also a critical area for thread-safety.
        infix_reverse_destroy(rt);
    }

    // Return a success status.
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
            threads[i] = CreateThread(NULL, 0, helgrind_thread_worker, NULL, 0, NULL);
            if (threads[i] == NULL) {
                diag("FATAL: CreateThread failed for thread %d.", i);
                any_thread_failed = true;
                break;
            }
        }

        if (!any_thread_failed)
            WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

        for (int i = 0; i < NUM_THREADS; ++i) {
            if (threads[i] == NULL)
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
#else  // POSIX
        pthread_t threads[NUM_THREADS] = {0};
        for (int i = 0; i < NUM_THREADS; ++i) {
            if (pthread_create(&threads[i], NULL, helgrind_thread_worker, NULL) != 0) {
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
=======
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
 * @file 820_threading_helgrind.c
 * @brief A cross-platform test for thread-safety issues using Valgrind's Helgrind tool
 *        or other thread sanitizers.
 *
 * @details This test is designed to be run specifically under thread analysis tools.
 * It creates multiple threads that concurrently generate, use, and destroy FFI
 * reverse trampolines (callbacks). The tool will analyze the execution for
 * potential data races and other synchronization errors in the underlying library code.
 *
 * This version of the test is structured to be free of data races in the test
 * code itself. All reporting is done by the main thread after all worker threads
 * have completed. Therefore, a successful run should produce ZERO errors from the
 * analysis tool. Any reported error indicates a genuine thread-safety bug within the
 * infix library.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>
#include <stdbool.h>  // For bool type

// Platform-specific headers and definitions for threading
#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else
#include <pthread.h>
#include <stdint.h>  // For intptr_t
#endif

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 500

// A simple C callback function. It does nothing, as its purpose is just to be a valid call target.
void helgrind_test_handler(infix_context_t * context, int a, int b) {
    (void)context;
    (void)a;
    (void)b;
}

// The main function that will be executed by each worker thread.
// It returns a status code (0 for success, 1 for failure) in a platform-agnostic way.
#if defined(INFIX_OS_WINDOWS)
DWORD WINAPI helgrind_thread_worker(LPVOID arg) {
#else
void * helgrind_thread_worker(void * arg) {
#endif
    (void)arg;

    // Define the FFI types for the callback signature: void(int, int)
    infix_type * ret_type = infix_type_create_void();
    infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
    typedef void (*my_func_ptr)(int, int);

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        infix_reverse_t * rt = NULL;

        // Generate the reverse trampoline. This is a critical area for thread-safety.
        infix_status status =
            infix_reverse_create_manual(&rt, ret_type, arg_types, 2, 2, (void *)helgrind_test_handler, NULL);
        if (status != INFIX_SUCCESS)
// Return a failure status that the main thread can check.
#if defined(_WIN32)
            return 1;
#else
            return (void *)(intptr_t)1;
#endif

        // Get and invoke the callable function pointer.
        my_func_ptr callable_func = (my_func_ptr)infix_reverse_get_code(rt);
        if (callable_func)
            callable_func(i, i + 1);

        // Destroy the reverse trampoline. This is also a critical area for thread-safety.
        infix_reverse_destroy(rt);
    }

    // Return a success status.
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
            threads[i] = CreateThread(NULL, 0, helgrind_thread_worker, NULL, 0, NULL);
            if (threads[i] == NULL) {
                diag("FATAL: CreateThread failed for thread %d.", i);
                any_thread_failed = true;
                break;
            }
        }

        if (!any_thread_failed)
            WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

        for (int i = 0; i < NUM_THREADS; ++i) {
            if (threads[i] == NULL)
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
#else  // POSIX
        pthread_t threads[NUM_THREADS] = {0};
        for (int i = 0; i < NUM_THREADS; ++i) {
            if (pthread_create(&threads[i], NULL, helgrind_thread_worker, NULL) != 0) {
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
>>>>>>> main:t/800_security/820_threading_helgrind.c
