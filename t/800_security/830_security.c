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
 *     Violation) due to the guard page mechanism in `ffi_executable_free`. This
 *     is tested for both forward and reverse trampolines.
 * 2.  **Read-Only Context Protection:** Verifies that the context for a reverse
 *     trampoline is made read-only after creation. Attempting to write to this
 *     hardened memory should cause a crash, preventing exploits that might
 *     modify callback behavior at runtime.
 * 3.  **API Hardening (Integer Overflows):** Ensures that the `ffi_type_create_*`
 *     functions are resilient to integer overflow attacks. It passes maliciously
 *     crafted size, offset, or element counts that would cause `size_t` to wrap
 *     around, and confirms that the API rejects these inputs gracefully.
 * 4.  **POSIX Hardened Allocator:** A simple check to confirm that the dual-mapping
 *     `shm_open` memory allocator, used on hardened Linux/BSD systems, functions correctly.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <limits.h>  // For SIZE_MAX

// Platform-specific headers for process/exception management
#if defined(_WIN32)
#include <windows.h>
#else  // POSIX
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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
            ffi_trampoline_t * t = NULL;
            ffi_type * s32 = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
            ffi_status status = generate_forward_trampoline(&t, s32, &s32, 1, 1);
            if (status != FFI_SUCCESS)
                exit(2);
            ffi_cif_func f = (ffi_cif_func)ffi_trampoline_get_code(t);
            ffi_trampoline_free(t);
            int a = 5, r = 0;
            void * aa[] = {&a};
            f((void *)dummy_target_func, &r, aa);
        }
        else if (strcmp(child_test_name, "reverse_uaf") == 0) {
            ffi_reverse_trampoline_t * rt = NULL;
            ffi_status status =
                generate_reverse_trampoline(&rt, ffi_type_create_void(), NULL, 0, 0, (void *)dummy_handler_func, NULL);
            if (status != FFI_SUCCESS)
                exit(2);
            void (*f)() = (void (*)())rt->exec_code.rx_ptr;
            ffi_reverse_trampoline_free(rt);
            f();
        }
        else if (strcmp(child_test_name, "write_harden") == 0) {
            ffi_reverse_trampoline_t * rt = NULL;
            ffi_status status =
                generate_reverse_trampoline(&rt, ffi_type_create_void(), NULL, 0, 0, (void *)dummy_handler_func, NULL);
            if (status != FFI_SUCCESS)
                exit(2);
            rt->user_data = NULL;
        }
        exit(1);
    }
#endif

    plan(4);

    subtest("Guard pages prevent use-after-free") {
        plan(2);
        subtest("Calling a freed FORWARD trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("forward_uaf"), "Child process crashed as expected.");
#elif defined(FFI_ENV_POSIX)
            ffi_trampoline_t * trampoline = NULL;
            ffi_type * s32_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
            ffi_status status = generate_forward_trampoline(&trampoline, s32_type, &s32_type, 1, 1);
            if (status != FFI_SUCCESS)
                bail_out("Failed to create trampoline for UAF test");
            ffi_cif_func dangling_ptr = (ffi_cif_func)ffi_trampoline_get_code(trampoline);
            pid_t pid = fork();
            if (pid == 0) {
                ffi_trampoline_free(trampoline);
                int arg = 5, result = 0;
                void * args[] = {&arg};
                dangling_ptr((void *)dummy_target_func, &result, args);
                exit(0);
            }
            else {
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
#elif defined(FFI_ENV_POSIX)
            ffi_reverse_trampoline_t * rt = NULL;
            ffi_status status =
                generate_reverse_trampoline(&rt, ffi_type_create_void(), NULL, 0, 0, (void *)dummy_handler_func, NULL);
            if (status != FFI_SUCCESS)
                bail_out("Failed to create reverse trampoline for UAF test");
            void (*dangling_ptr)() = (void (*)())rt->exec_code.rx_ptr;
            pid_t pid = fork();
            if (pid == 0) {
                ffi_reverse_trampoline_free(rt);
                dangling_ptr();
                exit(0);
            }
            else {
                int wstatus;
                waitpid(pid, &wstatus, 0);
                ok(WIFSIGNALED(wstatus) && (WTERMSIG(wstatus) == SIGSEGV || WTERMSIG(wstatus) == SIGBUS),
                   "Child crashed with SIGSEGV/SIGBUS as expected.");
                if (!WIFSIGNALED(wstatus))
                    fail("Child exited normally, but a crash was expected.");
                ffi_reverse_trampoline_free(rt);
            }
#else
            skip(1, "Crash test not supported on this platform.");
#endif
        }
    }

    subtest("Writing to a hardened reverse trampoline context causes a crash") {
        plan(1);
#if defined(FFI_OS_MACOS)
        skip(1, "Read-only context hardening disabled on macOS.");
#elif defined(_WIN32)
        ok(run_crash_test_as_child("write_harden"), "Child process crashed as expected.");
#elif defined(FFI_ENV_POSIX)
        ffi_reverse_trampoline_t * rt = NULL;
        ffi_status status =
            generate_reverse_trampoline(&rt, ffi_type_create_void(), NULL, 0, 0, (void *)dummy_handler_func, NULL);
        if (status != FFI_SUCCESS)
            bail_out("Failed to create reverse trampoline for write-protection test");
        pid_t pid = fork();
        if (pid == 0) {
            rt->user_data = NULL;
            exit(0);
        }
        else {
            int status_write;
            waitpid(pid, &status_write, 0);
            ok(WIFSIGNALED(status_write) && WTERMSIG(status_write) == SIGSEGV,
               "Child crashed with SIGSEGV as expected.");
            if (!WIFSIGNALED(status_write))
                fail("Child exited normally, but a crash was expected.");
            ffi_reverse_trampoline_free(rt);
        }
#else
        skip(1, "Write protection test not supported on this platform.");
#endif
    }

    subtest("API hardening against integer overflows") {
        plan(3);
        subtest("ffi_type_create_struct overflow") {
            plan(2);
            ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member));
            members[0] =
                ffi_struct_member_create("bad", ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64), SIZE_MAX - 4);
            ffi_type * bad_type = NULL;
            ffi_status status = ffi_type_create_struct(&bad_type, members, 1);
            ok(status == FFI_ERROR_INVALID_ARGUMENT, "ffi_type_create_struct returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_free(members);
        }
        subtest("ffi_type_create_array overflow") {
            plan(2);
            ffi_type * element_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64);
            size_t malicious_num_elements = (SIZE_MAX / element_type->size) + 1;
            ffi_type * bad_type = NULL;
            ffi_status status = ffi_type_create_array(&bad_type, element_type, malicious_num_elements);
            ok(status == FFI_ERROR_INVALID_ARGUMENT, "ffi_type_create_array returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
        }
        subtest("ffi_type_create_union overflow") {
            plan(2);
            ffi_type malicious_member_type = {.size = SIZE_MAX - 2, .alignment = 8};
            ffi_struct_member * members = infix_malloc(sizeof(ffi_struct_member));
            members[0] = ffi_struct_member_create("bad", &malicious_member_type, 0);
            ffi_type * bad_type = NULL;
            ffi_status status = ffi_type_create_union(&bad_type, members, 1);
            ok(status == FFI_ERROR_INVALID_ARGUMENT, "ffi_type_create_union returned error on overflow");
            ok(bad_type == NULL, "Output type is NULL on failure");
            infix_free(members);
        }
    }

    subtest("POSIX hardened allocator (shm_open)") {
        plan(1);
#if !defined(FFI_OS_WINDOWS) && !defined(FFI_OS_MACOS) && !defined(FFI_OS_TERMUX) && !defined(FFI_OS_OPENBSD) && \
    !defined(FFI_OS_DRAGONFLY)
        note("Verifying that dual-mapping allocator works on this platform (e.g., Linux/FreeBSD).");
        ffi_executable_t exec = ffi_executable_alloc(16);
        ok(exec.rw_ptr != NULL && exec.rx_ptr != NULL, "ffi_executable_alloc succeeded on hardened POSIX path");
        if (exec.size > 0)
            ffi_executable_free(exec);
#else
        skip(1, "Test is only for specific POSIX platforms that use the dual-mapping strategy.");
#endif
    }
}
