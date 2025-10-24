/**
 * @file 830_security.c
 * @brief Unit test for security-hardening features of the `infix` library.
 * @ingroup test_suite
 *
 * @details This test file verifies several critical security mechanisms designed to
 * make the library resilient against common memory corruption vulnerabilities.
 * Since these tests involve intentionally triggering crashes, they are executed
 * in child processes to avoid terminating the main test runner.
 *
 * The test covers:
 *
 * 1.  **Use-After-Free (UAF) Prevention:**
 *     - It creates a trampoline (forward bound, forward unbound, and reverse),
 *       destroys it, and then attempts to call the dangling function pointer.
 *     - It verifies that this action results in an immediate and controlled crash
 *       (e.g., a `SIGSEGV`), proving that the "guard page" mechanism in
 *       `infix_executable_free` is working correctly.
 *
 * 2.  **Context Memory Hardening:**
 *     - It creates a reverse trampoline, whose context struct is allocated in a
 *       special memory region.
 *     - After creation, the JIT engine makes this memory region read-only.
 *     - The test then attempts to write to a field within this context (`rt->user_data`).
 *     - It verifies that this write attempt causes a crash, proving that the
 *       context is successfully protected from runtime memory corruption.
 *
 * 3.  **API Hardening against Integer Overflows:**
 *     - It calls `infix_type_create_*` functions with maliciously crafted inputs
 *       designed to cause integer overflows during size and layout calculations
 *       (e.g., creating an array with `SIZE_MAX` elements).
 *     - It verifies that the API functions detect these overflows, return an
 *       error status (`INFIX_ERROR_INVALID_ARGUMENT`), and do not proceed with
 *       a potentially dangerous allocation.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include <infix/infix.h>
#include <limits.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// Dummy functions to provide valid pointers for trampoline creation.
int dummy_target_func(int a) {
    return a * 10;
}
void dummy_handler_func(void) {}

/**
 * @internal
 * @brief (Windows) Helper function to run a test that is expected to crash in a child process.
 * @details This function re-launches the current executable with a special environment
 *          variable set. The child process detects this variable and runs the specific
 *          crash-inducing code. The parent process waits for the child to exit and
 *          checks its exit code to confirm that it crashed as expected (specifically
 *          with an access violation).
 * @param test_name The name of the test to run in the child process.
 * @return `true` if the child process crashed with an access violation, `false` otherwise.
 */
#if defined(_WIN32)
static bool run_crash_test_as_child(const char * test_name) {
    char exe_path[MAX_PATH];
    if (GetModuleFileName(nullptr, exe_path, MAX_PATH) == 0) {
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

    si.hStdOutput = CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    si.hStdError = si.hStdOutput;

    if (!CreateProcessA(exe_path, nullptr, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        fail("CreateProcess() failed.");
        SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", nullptr);
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
    SetEnvironmentVariable("INFIX_CRASH_TEST_CHILD", nullptr);
    return exit_code == EXCEPTION_ACCESS_VIOLATION;
}
#endif

TEST {
#if defined(_WIN32)
    const char * child_test_name = getenv("INFIX_CRASH_TEST_CHILD");
    if (child_test_name != nullptr) {
        if (strcmp(child_test_name, "forward_uaf_unbound") == 0) {
            infix_forward_t * t = nullptr;
            infix_status status = infix_forward_create_unbound(&t, "(int32)->int32", nullptr);
            if (status != INFIX_SUCCESS)
                exit(2);
            infix_unbound_cif_func f = infix_forward_get_unbound_code(t);
            infix_forward_destroy(t);
            int a = 5, r = 0;
            void * aa[] = {&a};
            f((void *)dummy_target_func, &r, aa);
        }
        else if (strcmp(child_test_name, "forward_uaf_bound") == 0) {
            infix_forward_t * t = nullptr;
            infix_status status = infix_forward_create(&t, "(int32)->int32", (void *)dummy_target_func, nullptr);
            if (status != INFIX_SUCCESS)
                exit(2);
            infix_cif_func f = infix_forward_get_code(t);
            infix_forward_destroy(t);
            int a = 5, r = 0;
            void * aa[] = {&a};
            f(&r, aa);
        }
        else if (strcmp(child_test_name, "reverse_uaf") == 0) {
            infix_reverse_t * rt = nullptr;
            infix_status status = infix_reverse_create_callback(&rt, "()->void", (void *)dummy_handler_func, nullptr);
            if (status != INFIX_SUCCESS)
                exit(2);
            void (*f)() = (void (*)())infix_reverse_get_code(rt);
            infix_reverse_destroy(rt);
            f();
        }
        else if (strcmp(child_test_name, "write_harden") == 0) {
            infix_reverse_t * rt = nullptr;
            infix_status status = infix_reverse_create_callback(&rt, "()->void", (void *)dummy_handler_func, nullptr);
            if (status != INFIX_SUCCESS)
                exit(2);
            rt->user_data = nullptr;
        }
        exit(1);
    }
#endif

    plan(4);

    subtest("Guard pages prevent use-after-free") {
        plan(3);
        subtest("Calling a freed UNBOUND FORWARD trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("forward_uaf_unbound"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {
                infix_forward_t * trampoline = nullptr;
                infix_status status = infix_forward_create_unbound(&trampoline, "(int32)->int32", nullptr);
                if (status != INFIX_SUCCESS)
                    exit(2);
                infix_unbound_cif_func dangling_ptr = infix_forward_get_unbound_code(trampoline);
                infix_forward_destroy(trampoline);
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
        subtest("Calling a freed BOUND FORWARD trampoline causes a crash") {
            plan(1);
#if defined(_WIN32)
            ok(run_crash_test_as_child("forward_uaf_bound"), "Child process crashed as expected.");
#elif defined(INFIX_ENV_POSIX)
            pid_t pid = fork();
            if (pid == -1) {
                bail_out("fork() failed");
            }
            else if (pid == 0) {
                infix_forward_t * t = nullptr;
                if (infix_forward_create(&t, "(int32)->int32", (void *)dummy_target_func, nullptr) != INFIX_SUCCESS)
                    exit(2);
                infix_cif_func f = infix_forward_get_code(t);
                infix_forward_destroy(t);
                int a = 5, r = 0;
                void * aa[] = {&a};
                f(&r, aa);
                exit(0);
            }
            int wstatus;
            waitpid(pid, &wstatus, 0);
            ok(WIFSIGNALED(wstatus), "Child process crashed as expected.");
#else
            skip(1, "Crash test not supported.");
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
            else if (pid == 0) {
                infix_reverse_t * rt = nullptr;
                if (infix_reverse_create_callback(&rt, "()->void", (void *)dummy_handler_func, nullptr) !=
                    INFIX_SUCCESS)
                    exit(2);
                void (*dangling_ptr)() = (void (*)())infix_reverse_get_code(rt);
                infix_reverse_destroy(rt);
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
        else if (pid == 0) {
            infix_reverse_t * rt = nullptr;
            if (infix_reverse_create_callback(&rt, "()->void", (void *)dummy_handler_func, nullptr) != INFIX_SUCCESS)
                exit(2);
            rt->user_data = nullptr;
            exit(0);
        }
        else {
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

        subtest("infix_type_create_struct overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);

            infix_type malicious_type = {.size = SIZE_MAX / 2 + 10, .alignment = 8};
            infix_struct_member members[2];
            members[0] = infix_type_create_member("a", &malicious_type, 0);
            members[1] = infix_type_create_member("b", &malicious_type, 0);

            infix_type * bad_type = nullptr;
            infix_status status = infix_type_create_struct(arena, &bad_type, members, 2);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT,
               "infix_type_create_struct returned error on calculated overflow");
            ok(bad_type == nullptr, "Output type is nullptr on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_array overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);
            infix_type * element_type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
            size_t malicious_num_elements = (SIZE_MAX / element_type->size) + 1;
            infix_type * bad_type = nullptr;
            infix_status status = infix_type_create_array(arena, &bad_type, element_type, malicious_num_elements);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_array returned error on overflow");
            ok(bad_type == nullptr, "Output type is nullptr on failure");
            infix_arena_destroy(arena);
        }
        subtest("infix_type_create_union overflow") {
            plan(2);
            infix_arena_t * arena = infix_arena_create(256);

            infix_type malicious_member_type = {.size = SIZE_MAX - 2, .alignment = 8};
            infix_struct_member members[1];
            members[0] = infix_type_create_member("bad", &malicious_member_type, 0);
            infix_type * bad_type = nullptr;
            infix_status status = infix_type_create_union(arena, &bad_type, members, 1);
            ok(status == INFIX_ERROR_INVALID_ARGUMENT, "infix_type_create_union returned error on overflow");
            ok(bad_type == nullptr, "Output type is nullptr on failure");
            infix_arena_destroy(arena);
        }
    }

    subtest("POSIX hardened allocator (shm_open)") {
        plan(1);
#if !defined(INFIX_OS_WINDOWS) && !defined(INFIX_OS_MACOS) && !defined(INFIX_OS_TERMUX) && \
    !defined(INFIX_OS_OPENBSD) && !defined(INFIX_OS_DRAGONFLY)
        note("Verifying that dual-mapping allocator works on this platform (e.g., Linux/FreeBSD).");
        infix_executable_t exec = infix_executable_alloc(16);
        ok(exec.rw_ptr != nullptr && exec.rx_ptr != nullptr, "infix_executable_alloc succeeded on hardened POSIX path");
        if (exec.size > 0)
            infix_executable_free(exec);
#else
        skip(1, "Test is only for specific POSIX platforms that use the dual-mapping strategy.");
#endif
    }
}
