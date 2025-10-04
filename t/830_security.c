<<<<<<< HEAD:t/830_security.c
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
 * @file 830_security.c
 * @brief A test suite for security hardening and vulnerability prevention.
 *
 * @details This suite consolidates several tests to verify the security-related
 * features and hardening of the infix library. It is designed to be run on all
 * platforms, with specific tests activating based on the target OS and compiler.
 *
 * The key areas verified are:
 * 1.  **Use-After-Free Prevention:** Confirms that attempting to call a freed
 *     trampoline results in a safe, immediate crash (e.g., SIGSEGV or Access
 *     Violation) due to the guard page mechanism in `infix_executable_free`. This
 *     is tested for both forward and reverse trampolines.
 * 2.  **Read-Only Context Protection:** Verifies that the context for a reverse
 *     trampoline is made read-only after creation. Attempting to write to this
 *     hardened memory should cause a crash, preventing exploits that might
 *     modify callback behavior at runtime.
 * 3.  **API Hardening (Integer Overflows):** Ensures that the `infix_type_create_*`
 *     functions are resilient to integer overflow attacks. It passes maliciously
 *     crafted size, offset, or element counts that would cause `size_t` to wrap
 *     around, and confirms that the API rejects these inputs gracefully.
 * 4.  **POSIX Hardened Allocator:** A simple check to confirm that the dual-mapping
 *     `shm_open` memory allocator, used on hardened Linux/BSD systems, functions correctly.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include <infix/infix.h>  // Use the public API
#include <limits.h>       // For SIZE_MAX
#include <stdlib.h>       // For malloc/free in test scaffolding

// Platform-specific headers for process/exception management
#if defined(_WIN32)
#include <windows.h>
#else  // POSIX
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// NOTE: The defines and declarations for the internal heap functions have been removed.
// We will test the public, arena-based API instead.

// Dummy functions for testing
int dummy_target_func(int a) {
    return a * 10;
}
void dummy_handler_func(void) { /* Should never be called. */ }

#if defined(_WIN32)
static bool run_crash_test_as_child(const char * test_name) {
    char exe_path[MAX_PATH];
    if (GetModuleFileName(NULL, exe_path, MAX_PATH) == 0) {
        fail("GetModuleFileName() failed.");
        return false;
    }
    SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", test_name);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    // Redirect child's stdout/stderr to NUL to keep test output clean.
    si.hStdOutput = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    si.hStdError = si.hStdOutput;

    if (!CreateProcessA(exe_path, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fail("CreateProcess() failed.");
        SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", NULL);
        if (si.hStdOutput != INVALID_HANDLE_VALUE)
            CloseHandle(si.hStdOutput);
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (si.hStdOutput != INVALID_HANDLE_VALUE)
        CloseHandle(si.hStdOutput);
    SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", NULL);
    return exit_code == EXCEPTION_ACCESS_VIOLATION;
}
#endif

TEST {
#if defined(_WIN32)
    const char * child_test_name = getenv("INFIX_CRASH_TEST_CHILD");
    if (child_test_name != NULL) {
        if (strcmp(child_test_name, "forward_uaf") == 0) {
            infix_forward_t * t = NULL;
            infix_status status = infix_forward_create(&t, "(int32)->int32");
            if (status != INFIX_SUCCESS)
                exit(2);
            infix_cif_func f = (infix_cif_func)infix_forward_get_code(t);
            infix_forward_destroy(t);
            int a = 5, r = 0;
            void * aa[] = {&a};
            f((void *)dummy_target_func, &r, aa);  // This line should crash
        }
        else if (strcmp(child_test_name, "reverse_uaf") == 0) {
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "()->void", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            void (*f)() = (void (*)())infix_reverse_get_code(rt);
            infix_reverse_destroy(rt);
            f();  // This line should crash
        }
        else if (strcmp(child_test_name, "write_harden") == 0) {
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "()->void", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            rt->user_data = NULL;  // This line should crash
        }
        exit(1);  // Exit with a non-crash code if the crash didn't happen
    }
#endif

    plan(4);

    subtest("Guard pages prevent use-after-free") {
        plan(2);
        subtest("Calling a freed FORWARD trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("forward_uaf"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {  // Child process
                infix_forward_t * trampoline = NULL;
                infix_status status = infix_forward_create(&trampoline, "(int32)->int32");
                if (status != INFIX_SUCCESS)
                    exit(2);  // Exit with error if creation fails
                infix_cif_func dangling_ptr = (infix_cif_func)infix_forward_get_code(trampoline);
                infix_forward_destroy(trampoline);
                int arg = 5, result = 0;
                void * args[] = {&arg};
                dangling_ptr((void *)dummy_target_func, &result, args);  // Should crash here
                exit(0);                                                 // Should not be reached
            }
            else {  // Parent process
                int wstatus;
                waitpid(pid, &wstatus, 0);
                ok(WIFSIGNALED(wstatus) && (WTERMSIG(wstatus) == SIGSEGV || WTERMSIG(wstatus) == SIGBUS),
                   "Child crashed with SIGSEGV/SIGBUS as expected.");
                if (!WIFSIGNALED(wstatus))
                    fail("Child exited normally, but a crash was expected.");
            }
#else
            skip(1, "Crash test not supported on this platform.");
#endif
        }
        subtest("Calling a freed REVERSE trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("reverse_uaf"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {  // Child process
                infix_reverse_t * rt = NULL;
                infix_status status = infix_reverse_create(&rt, "()->void", (void *)dummy_handler_func, NULL);
                if (status != INFIX_SUCCESS)
                    exit(2);
                void (*dangling_ptr)() = (void (*)())infix_reverse_get_code(rt);
                infix_reverse_destroy(rt);
                dangling_ptr();  // Should crash here
                exit(0);         // Should not be reached
            }
            else {  // Parent process
                int wstatus;
                waitpid(pid, &wstatus, 0);
                ok(WIFSIGNALED(wstatus) && (WTERMSIG(wstatus) == SIGSEGV || WTERMSIG(wstatus) == SIGBUS),
                   "Child crashed with SIGSEGV/SIGBUS as expected.");
                if (!WIFSIGNALED(wstatus))
                    fail("Child exited normally, but a crash was expected.");
            }
#else
            skip(1, "Crash test not supported on this platform.");
#endif
        }
    }

    subtest("Writing to a hardened reverse trampoline context causes a crash") {
        plan(1);
#if defined(INFIX_OS_MACOS)
        skip(1, "Read-only context hardening disabled on macOS for stability.");
#elif defined(_WIN32)
        ok(run_crash_test_as_child("write_harden"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
        pid_t pid = fork();
        if (pid == -1) {
            bail_out("fork() failed");
        }
        else if (pid == 0) {  // Child process
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "()->void", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            rt->user_data = NULL;  // This write should trigger a SIGSEGV
            exit(0);               // Should not be reached
        }
        else {  // Parent process
            int status_write;
            waitpid(pid, &status_write, 0);
            ok(WIFSIGNALED(status_write) && WTERMSIG(status_write) == SIGSEGV,
               "Child crashed with SIGSEGV as expected.");
            if (!WIFSIGNALED(status_write))
                fail("Child exited normally, but a crash was expected.");
        }
#else
        skip(1, "Write protection test not supported on this platform.");
#endif
    }

    subtest("API hardening against integer overflows") {
        plan(3);
        // Each test now uses a temporary arena.
        subtest("infix_type_create_struct overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);

            // Test a real overflow scenario. Create a struct with two
            // members whose combined size and padding would wrap around SIZE_MAX.
            // This tests the library's internal calculation, not faulty user input.
            infix_type malicious_type = {.size = SIZE_MAX / 2 + 10, .alignment = 8};
            infix_struct_member members[2];
            members[0] = infix_type_create_member("a", &malicious_type, 0);
            members[1] = infix_type_create_member("b", &malicious_type, 0);

            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_struct(arena, &bad_type, members, 2);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT,
               "infix_type_create_struct returned error on calculated overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_array overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            infix_type * element_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
            size_t malicious_num_elements = (SIZE_MAX / element_type->size) + 1;
            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_array(arena, &bad_type, element_type, malicious_num_elements);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_union overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            // This test is already correct. It tests the padding calculation overflow.
            infix_type malicious_member_type = {.size = SIZE_MAX - 2, .alignment = 8};
            infix_struct_member members[1];
            members[0] = infix_type_create_member("bad", &malicious_member_type, 0);
            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_union(arena, &bad_type, members, 1);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_union returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
    }

    subtest("POSIX hardened allocator (shm_open)") {
        plan(1);
#if !defined(INFIX_OS_WINDOWS) && !defined(INFIX_OS_MACOS) && !defined(INFIX_OS_TERMUX) && \
    !defined(INFIX_OS_OPENBSD) && !defined(INFIX_OS_DRAGONFLY)
        note("Verifying that dual-mapping allocator works on this platform (e.g., Linux/FreeBSD).");
        infix_executable_t exec = infix_executable_alloc(16);
        ok(exec.rw_ptr != NULL && exec.rx_ptr != NULL, "infix_executable_alloc succeeded on hardened POSIX path");
        if (exec.size > 0)
            infix_executable_free(exec);
#else
        skip(1, "Test is only for specific POSIX platforms that use the dual-mapping strategy.");
#endif
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
 * @file 830_security.c
 * @brief A test suite for security hardening and vulnerability prevention.
 *
 * @details This suite consolidates several tests to verify the security-related
 * features and hardening of the infix library. It is designed to be run on all
 * platforms, with specific tests activating based on the target OS and compiler.
 *
 * The key areas verified are:
 * 1.  **Use-After-Free Prevention:** Confirms that attempting to call a freed
 *     trampoline results in a safe, immediate crash (e.g., SIGSEGV or Access
 *     Violation) due to the guard page mechanism in `infix_executable_free`. This
 *     is tested for both forward and reverse trampolines.
 * 2.  **Read-Only Context Protection:** Verifies that the context for a reverse
 *     trampoline is made read-only after creation. Attempting to write to this
 *     hardened memory should cause a crash, preventing exploits that might
 *     modify callback behavior at runtime.
 * 3.  **API Hardening (Integer Overflows):** Ensures that the `infix_type_create_*`
 *     functions are resilient to integer overflow attacks. It passes maliciously
 *     crafted size, offset, or element counts that would cause `size_t` to wrap
 *     around, and confirms that the API rejects these inputs gracefully.
 * 4.  **POSIX Hardened Allocator:** A simple check to confirm that the dual-mapping
 *     `shm_open` memory allocator, used on hardened Linux/BSD systems, functions correctly.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include <infix/infix.h>  // Use the public API
#include <limits.h>       // For SIZE_MAX
#include <stdlib.h>       // For malloc/free in test scaffolding

// Platform-specific headers for process/exception management
#if defined(_WIN32)
#include <windows.h>
#else  // POSIX
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// NOTE: The defines and declarations for the internal heap functions have been removed.
// We will test the public, arena-based API instead.

// Dummy functions for testing
int dummy_target_func(int a) {
    return a * 10;
}
void dummy_handler_func(void) { /* Should never be called. */ }

#if defined(_WIN32)
static bool run_crash_test_as_child(const char * test_name) {
    char exe_path[MAX_PATH];
    if (GetModuleFileName(NULL, exe_path, MAX_PATH) == 0) {
        fail("GetModuleFileName() failed.");
        return false;
    }
    SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", test_name);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    // Redirect child's stdout/stderr to NUL to keep test output clean.
    si.hStdOutput = CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    si.hStdError = si.hStdOutput;

    if (!CreateProcessA(exe_path, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        fail("CreateProcess() failed.");
        SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", NULL);
        if (si.hStdOutput != INVALID_HANDLE_VALUE)
            CloseHandle(si.hStdOutput);
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (si.hStdOutput != INVALID_HANDLE_VALUE)
        CloseHandle(si.hStdOutput);
    SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", NULL);
    return exit_code == EXCEPTION_ACCESS_VIOLATION;
}
#endif

TEST {
#if defined(_WIN32)
    const char * child_test_name = getenv("INFIX_CRASH_TEST_CHILD");
    if (child_test_name != NULL) {
        if (strcmp(child_test_name, "forward_uaf") == 0) {
            infix_forward_t * t = NULL;
            infix_status status = infix_forward_create(&t, "i=>i");
            if (status != INFIX_SUCCESS)
                exit(2);
            infix_cif_func f = (infix_cif_func)infix_forward_get_code(t);
            infix_forward_destroy(t);
            int a = 5, r = 0;
            void * aa[] = {&a};
            f((void *)dummy_target_func, &r, aa);  // This line should crash
        }
        else if (strcmp(child_test_name, "reverse_uaf") == 0) {
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "=>v", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            void (*f)() = (void (*)())infix_reverse_get_code(rt);
            infix_reverse_destroy(rt);
            f();  // This line should crash
        }
        else if (strcmp(child_test_name, "write_harden") == 0) {
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "=>v", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            rt->user_data = NULL;  // This line should crash
        }
        exit(1);  // Exit with a non-crash code if the crash didn't happen
    }
#endif

    plan(4);

    subtest("Guard pages prevent use-after-free") {
        plan(2);
        subtest("Calling a freed FORWARD trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("forward_uaf"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {  // Child process
                infix_forward_t * trampoline = NULL;
                infix_status status = infix_forward_create(&trampoline, "i=>i");
                if (status != INFIX_SUCCESS)
                    exit(2);  // Exit with error if creation fails
                infix_cif_func dangling_ptr = (infix_cif_func)infix_forward_get_code(trampoline);
                infix_forward_destroy(trampoline);
                int arg = 5, result = 0;
                void * args[] = {&arg};
                dangling_ptr((void *)dummy_target_func, &result, args);  // Should crash here
                exit(0);                                                 // Should not be reached
            }
            else {  // Parent process
                int wstatus;
                waitpid(pid, &wstatus, 0);
                ok(WIFSIGNALED(wstatus) && (WTERMSIG(wstatus) == SIGSEGV || WTERMSIG(wstatus) == SIGBUS),
                   "Child crashed with SIGSEGV/SIGBUS as expected.");
                if (!WIFSIGNALED(wstatus))
                    fail("Child exited normally, but a crash was expected.");
            }
#else
            skip(1, "Crash test not supported on this platform.");
#endif
        }
        subtest("Calling a freed REVERSE trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("reverse_uaf"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {  // Child process
                infix_reverse_t * rt = NULL;
                infix_status status = infix_reverse_create(&rt, "=>v", (void *)dummy_handler_func, NULL);
                if (status != INFIX_SUCCESS)
                    exit(2);
                void (*dangling_ptr)() = (void (*)())infix_reverse_get_code(rt);
                infix_reverse_destroy(rt);
                dangling_ptr();  // Should crash here
                exit(0);         // Should not be reached
            }
            else {  // Parent process
                int wstatus;
                waitpid(pid, &wstatus, 0);
                ok(WIFSIGNALED(wstatus) && (WTERMSIG(wstatus) == SIGSEGV || WTERMSIG(wstatus) == SIGBUS),
                   "Child crashed with SIGSEGV/SIGBUS as expected.");
                if (!WIFSIGNALED(wstatus))
                    fail("Child exited normally, but a crash was expected.");
            }
#else
            skip(1, "Crash test not supported on this platform.");
#endif
        }
    }

    subtest("Writing to a hardened reverse trampoline context causes a crash") {
        plan(1);
#if defined(INFIX_OS_MACOS)
        skip(1, "Read-only context hardening disabled on macOS for stability.");
#elif defined(_WIN32)
        ok(run_crash_test_as_child("write_harden"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
        pid_t pid = fork();
        if (pid == -1) {
            bail_out("fork() failed");
        }
        else if (pid == 0) {  // Child process
            infix_reverse_t * rt = NULL;
            infix_status status = infix_reverse_create(&rt, "=>v", (void *)dummy_handler_func, NULL);
            if (status != INFIX_SUCCESS)
                exit(2);
            rt->user_data = NULL;  // This write should trigger a SIGSEGV
            exit(0);               // Should not be reached
        }
        else {  // Parent process
            int status_write;
            waitpid(pid, &status_write, 0);
            ok(WIFSIGNALED(status_write) && WTERMSIG(status_write) == SIGSEGV,
               "Child crashed with SIGSEGV as expected.");
            if (!WIFSIGNALED(status_write))
                fail("Child exited normally, but a crash was expected.");
        }
#else
        skip(1, "Write protection test not supported on this platform.");
#endif
    }

    subtest("API hardening against integer overflows") {
        plan(3);
        // Each test now uses a temporary arena.
        subtest("infix_type_create_struct overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            infix_struct_member members[1];
            members[0] =
                infix_struct_member_create("bad", infix_type_create_primitive(INFIX_PRIMITIVE_UINT64), SIZE_MAX - 4);
            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_struct(arena, &bad_type, members, 1);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_struct returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_array overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            infix_type * element_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
            size_t malicious_num_elements = (SIZE_MAX / element_type->size) + 1;
            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_array(arena, &bad_type, element_type, malicious_num_elements);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_union overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            // Create a fake type on the stack just for this test
            infix_type malicious_member_type = {.size = SIZE_MAX - 2, .alignment = 8};
            infix_struct_member members[1];
            members[0] = infix_struct_member_create("bad", &malicious_member_type, 0);
            infix_type * bad_type = NULL;
            infix_status status = infix_type_create_union(arena, &bad_type, members, 1);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_union returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_arena_destroy(arena);
        }
    }

    subtest("POSIX hardened allocator (shm_open)") {
        plan(1);
#if !defined(INFIX_OS_WINDOWS) && !defined(INFIX_OS_MACOS) && !defined(INFIX_OS_TERMUX) && \
    !defined(INFIX_OS_OPENBSD) && !defined(INFIX_OS_DRAGONFLY)
        note("Verifying that dual-mapping allocator works on this platform (e.g., Linux/FreeBSD).");
        infix_executable_t exec = infix_executable_alloc(16);
        ok(exec.rw_ptr != NULL && exec.rx_ptr != NULL, "infix_executable_alloc succeeded on hardened POSIX path");
        if (exec.size > 0)
            infix_executable_free(exec);
#else
        skip(1, "Test is only for specific POSIX platforms that use the dual-mapping strategy.");
#endif
    }
}
>>>>>>> main:t/800_security/830_security.c
