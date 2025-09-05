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
 * @file 821_threading_bare.c
 * @brief A "barebones" thread-safety test with no testing framework dependency.
 *
 * @details This test is designed to be the ultimate proof of thread safety for the
 *          infix library. It is intended to be compiled as a standalone executable
 *          and run under Valgrind's Helgrind tool.
 *
 *          By removing the dependency on the `double_tap.h` testing framework (which
 *          is not designed for this kind of stress test and can create noisy,
 *          misleading reports), we ensure that the only shared code being stressed
 *          is the infix library itself. This provides a clean, unambiguous result.
 *
 *          The test's success is determined by two conditions:
 *          1.  The program must exit with code 0.
 *          2.  Valgrind/Helgrind must report ZERO errors.
 */

#include <infix.h>    // The library under test
#include <stdbool.h>  // For bool type
#include <stdint.h>   // For intptr_t
#include <stdio.h>    // For printf

// Platform-specific headers for threading
#if defined(FFI_OS_WINDOWS) || defined(FFI_ENV_CYGWIN)
#include <windows.h>
#else
#include <pthread.h>
#endif

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 500

/** @brief A simple C callback function; its only purpose is to be a valid call target. */
void bare_helgrind_handler(int a, int b) {
    (void)a;
    (void)b;
}

/**
 * @brief The main function executed by each worker thread.
 * @details Creates, uses, and destroys a reverse trampoline in a tight loop.
 * @return Returns a status code (0 for success, 1 for failure) cast to a void pointer.
 */
#if defined(FFI_OS_WINDOWS) || defined(__CYGWIN__)
DWORD WINAPI bare_thread_worker(LPVOID arg) {
#else
void * bare_thread_worker(void * arg) {
#endif
    (void)arg;

    // Define the FFI types for the callback signature: void(int, int)
    ffi_type * ret_type = ffi_type_create_void();
    ffi_type * arg_types[] = {ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32),
                              ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32)};
    typedef void (*my_func_ptr)(int, int);

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        ffi_reverse_trampoline_t * rt = NULL;
        // Generate the reverse trampoline. This is a critical area for thread-safety.
        ffi_status status =
            generate_reverse_trampoline(&rt, ret_type, arg_types, 2, 2, (void *)bare_helgrind_handler, NULL);
        if (status != FFI_SUCCESS) {
            fprintf(stderr, "# Thread failed to generate reverse trampoline.\n");
#if defined(FFI_OS_WINDOWS) || defined(__CYGWIN__)
            return (DWORD)(intptr_t)1;
#else
            return (void *)(intptr_t)1;
#endif
        }

        // Get and invoke the callable function pointer.
        my_func_ptr callable_func = (my_func_ptr)rt->exec_code.rx_ptr;
        if (callable_func)
            callable_func(i, i + 1);

        // Destroy the reverse trampoline. This is also a critical area for thread-safety.
        ffi_reverse_trampoline_free(rt);
    }

#if defined(FFI_OS_WINDOWS) || defined(__CYGWIN__)
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

#if defined(FFI_OS_WINDOWS) || defined(__CYGWIN__)
    HANDLE threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; ++i) {
        threads[i] = CreateThread(NULL, 0, bare_thread_worker, NULL, 0, NULL);
        if (threads[i] == NULL) {
            fprintf(stderr, "# FATAL: CreateThread failed.\n");
            any_thread_failed = true;
            break;
        }
    }

    if (!any_thread_failed) {
        WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        if (threads[i] == NULL)
            continue;
        DWORD exit_code;
        GetExitCodeThread(threads[i], &exit_code);
        if (exit_code != 0) {
            fprintf(stderr, "# ERROR: Thread %d returned a failure status.\n", i);
            any_thread_failed = true;
        }
        CloseHandle(threads[i]);
    }
#else  // POSIX
    pthread_t threads[NUM_THREADS] = {0};
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, bare_thread_worker, NULL) != 0) {
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
