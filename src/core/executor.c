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
 * @file executor.c
 * @brief Implements OS-level memory management and the internal callback dispatcher.
 * @ingroup internal_core
 *
 * @internal
 * This file forms the OS abstraction layer for the library. It is responsible for
 * two primary, security-critical tasks:
 *
 * 1.  **Executable Memory Management:** It provides a cross-platform interface
 *     for allocating, freeing, and managing executable memory. The implementation
 *     adheres to a strict W^X (Write XOR Execute) security policy, meaning memory
 *     is never writable and executable at the same time.
 *
 * 2.  **Callback Dispatching:** It contains the high-level C function
 *     (`infix_internal_dispatch_callback_fn_impl`) that is called by the
 *     low-level assembly of a reverse trampoline. This function acts as the final
 *     bridge to invoke the user's C callback with the correctly marshalled arguments.
 *
 * ### macOS JIT Implementation with Graceful Fallback
 *
 * On Apple Silicon, the OS enforces strict W^X policies. The official, secure way
 * to create JIT code requires:
 *   a) The host process be signed with the `com.apple.security.cs.allow-jit` entitlement.
 *   b) Allocating memory with the `MAP_JIT` flag.
 *   c) Using `pthread_jit_write_protect_np()` to toggle permissions.
 *
 * This would normally require users to add `-framework` linker flags. To avoid this
 * friction, this implementation uses a **runtime dynamic linking** approach. On the first
 * JIT allocation on macOS, it attempts to `dlopen` the `Security` and `CoreFoundation`
 * frameworks and checks for the JIT entitlement.
 *
 * - **If Successful:** It uses the modern, secure API (`MAP_JIT`, etc.). This works out-of-the-box
 *   for hardened applications like official Python/Perl interpreters.
 * - **If It Fails (e.g., missing entitlement):** It gracefully falls back to the legacy
 *   (and insecure) method of calling `mprotect` on a standard `RW-` page. This ensures
 *   that unhardened development builds (like our CI runners) continue to work without
 *   any build configuration changes.
 * @endinternal
 */

#include "common/infix_internals.h"
#include "common/utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(INFIX_OS_WINDOWS)
#include <windows.h>
#else  // Linux, macOS, BSDs
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(INFIX_OS_MACOS)
#include <dlfcn.h>
#include <pthread.h>
#endif

// Portability shim for mmap anonymous flag.
#if defined(INFIX_ENV_POSIX) && !defined(INFIX_OS_WINDOWS)
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif
#endif

// Internal Helpers for macOS Runtime Linking
#if defined(INFIX_OS_MACOS)
// Define opaque types to avoid including the full framework headers, which is key
// to avoiding the forced linker dependency.
typedef const struct __CFString * CFStringRef;
typedef const void * CFTypeRef;
typedef struct __SecTask * SecTaskRef;
typedef struct __CFError * CFErrorRef;
#define kCFStringEncodingUTF8 0x08000100

// A struct to hold dynamically loaded function pointers. It is populated once at runtime.
static struct {
    void (*CFRelease)(CFTypeRef);
    bool (*CFBooleanGetValue)(CFTypeRef boolean);
    CFStringRef (*CFStringCreateWithCString)(CFTypeRef allocator, const char * cStr, uint32_t encoding);
    CFTypeRef kCFAllocatorDefault;
    SecTaskRef (*SecTaskCreateFromSelf)(CFTypeRef allocator);
    CFTypeRef (*SecTaskCopyValueForEntitlement)(SecTaskRef task, CFStringRef entitlement, CFErrorRef * error);
} g_macos_apis;

/**
 * @internal
 * @brief A one-time initializer that uses dlopen/dlsym to load macOS framework functions.
 * @details This is the core of the no-linker-flags solution. It runs only once per
 *          process. If any function fails to load, the corresponding pointer in the
 *          global struct remains NULL, which is used as a signal that the secure
 *          JIT path is unavailable.
 */
static void initialize_macos_apis(void) {
    // Attempt to load the required system frameworks dynamically.
    void * cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    void * sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);

    // If either fails, we cannot proceed with the secure path. Clean up and exit.
    if (!cf || !sec) {
        INFIX_DEBUG_PRINTF("Warning: Could not dlopen macOS frameworks. JIT security features will be degraded.");
        if (cf)
            dlclose(cf);
        if (sec)
            dlclose(sec);
        // Ensure all pointers are null to signal failure.
        memset(&g_macos_apis, 0, sizeof(g_macos_apis));
        return;
    }

    // Use dlsym to find the address of each function and global constant we need.
    g_macos_apis.CFRelease = dlsym(cf, "CFRelease");
    g_macos_apis.CFBooleanGetValue = dlsym(cf, "CFBooleanGetValue");
    g_macos_apis.CFStringCreateWithCString = dlsym(cf, "CFStringCreateWithCString");
    void ** pAlloc = (void **)dlsym(cf, "kCFAllocatorDefault");
    if (pAlloc)
        g_macos_apis.kCFAllocatorDefault = *pAlloc;

    g_macos_apis.SecTaskCreateFromSelf = dlsym(sec, "SecTaskCreateFromSelf");
    g_macos_apis.SecTaskCopyValueForEntitlement = dlsym(sec, "SecTaskCopyValueForEntitlement");

    // The handles can be closed; the OS keeps the libraries in memory and the pointers remain valid.
    dlclose(cf);
    dlclose(sec);
}

/**
 * @internal
 * @brief Checks at runtime if the current process has the `com.apple.security.cs.allow-jit` entitlement.
 * @ingroup internal_core
 *
 * @details This function is the key to enabling the secure JIT path on macOS without
 *          requiring build-time changes from the user. It performs the following steps:
 *          1.  Ensures `initialize_macos_apis` has been called exactly once in a
 *              thread-safe manner using `pthread_once`.
 *          2.  If the required framework functions could not be loaded, it returns `false`.
 *          3.  It uses the `SecTask` API to get a reference to the current running process.
 *          4.  It queries the task for the value of the "com.apple.security.cs.allow-jit"
 *              entitlement.
 *          5.  It checks that the returned value is a CoreFoundation boolean object
 *              representing `true`.
 *          6.  It carefully releases all CoreFoundation objects it created to prevent
 *              memory leaks.
 *
 * @return `true` if the entitlement is present and enabled, `false` in all other cases.
 */
static bool has_jit_entitlement(void) {
    // Use pthread_once to ensure the framework APIs are loaded exactly once in a thread-safe manner.
    static pthread_once_t init_once = PTHREAD_ONCE_INIT;
    pthread_once(&init_once, initialize_macos_apis);

    // If we failed to load the necessary APIs, we cannot check, so we must return false.
    if (!g_macos_apis.SecTaskCopyValueForEntitlement || !g_macos_apis.CFStringCreateWithCString)
        return false;

    bool result = false;
    // Get a reference to the current process's security properties.
    SecTaskRef task = g_macos_apis.SecTaskCreateFromSelf(g_macos_apis.kCFAllocatorDefault);
    if (!task)
        return false;

    // Create a CoreFoundation string for the entitlement key we're looking for.
    CFStringRef key = g_macos_apis.CFStringCreateWithCString(
        g_macos_apis.kCFAllocatorDefault, "com.apple.security.cs.allow-jit", kCFStringEncodingUTF8);
    CFTypeRef value = NULL;
    if (key) {  // Query the OS for the entitlement value.
        value = g_macos_apis.SecTaskCopyValueForEntitlement(task, key, NULL);
        g_macos_apis.CFRelease(key);  // Must release objects we create.
    }
    g_macos_apis.CFRelease(task);  // Must release the task reference.

    if (value) {
        // A JIT entitlement is boolean. We must check that its value is explicitly `true`.
        if (g_macos_apis.CFBooleanGetValue && g_macos_apis.CFBooleanGetValue(value))
            result = true;
        g_macos_apis.CFRelease(value);  // Must release the retrieved value object.
    }
    return result;
}
#endif

#if !defined(INFIX_OS_WINDOWS) && !defined(INFIX_OS_MACOS) && !defined(INFIX_OS_ANDROID) && !defined(INFIX_OS_OPENBSD)
#include <fcntl.h>
#include <stdint.h>

/**
 * @internal
 * @brief Creates a temporary, anonymous shared memory object for dual-mapping.
 * @ingroup internal_core
 *
 * @details This function is used on hardened POSIX systems like Linux that support
 *          the "dual-mapping" strategy for W^X memory. It creates a shared memory
 *          object that has a name in the filesystem, gets a file descriptor to it,
 *          and then immediately unlinks the name.
 *
 *          This **"create-then-unlink"** pattern is a secure way to create
 *          anonymous memory regions. The open file descriptor remains valid for the
 *          lifetime of the process, but the object has no name in the filesystem,
 *          preventing other processes from interfering with it. The kernel guarantees
 *          that it will automatically clean up the memory when the last file
 *          descriptor referring to it is closed (e.g., on process termination),
 *          preventing resource leaks.
 *
 * @return A valid file descriptor on success, or -1 on failure.
 */
static int shm_open_anonymous() {
    char shm_name[64];
    uint64_t random_val = 0;

    // Use /dev/urandom to generate a highly unpredictable name to avoid collisions
    // and prevent predictable name attacks.
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return -1;

    ssize_t bytes_read = read(rand_fd, &random_val, sizeof(random_val));
    close(rand_fd);
    if (bytes_read != sizeof(random_val))
        return -1;

    snprintf(shm_name, sizeof(shm_name), "/infix-jit-%d-%llx", getpid(), (unsigned long long)random_val);

    // Create the shared memory object.
    // - O_CREAT | O_EXCL: Atomically create the object, failing if it already exists.
    //   This prevents race conditions and symlink attacks.
    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        shm_unlink(shm_name);
        return fd;
    }

    return -1;
}
#endif

// Executable Memory Management
/**
 * @internal
 * @brief Allocates a region of page-aligned memory suitable for JIT code.
 * @ingroup internal_core
 *
 * @details This is the primary cross-platform wrapper for allocating memory that will
 *          eventually become executable. It implements several strategies depending
 *          on the target OS to achieve W^X compliance and portability.
 *
 *          - **Windows:** Uses `VirtualAlloc` to reserve a single region of memory
 *            with `PAGE_READWRITE` permissions.
 *
 *          - **macOS (with fallback):** Performs a one-time runtime check for the
 *            `com.apple.security.cs.allow-jit` entitlement.
 *              - If present, it uses `mmap` with `MAP_JIT`, the modern, secure method.
 *              - If absent, it falls back to a standard `mmap`, relying on the OS's
 *                permissive mode for unhardened binaries.
 *
 *          - **Linux/Hardened BSDs:** Uses a **"dual-mapping"** technique. It creates an
 *            anonymous shared memory object (via `shm_open_anonymous`) and then creates
 *            two separate virtual memory mappings to it: one `PROT_READ | PROT_WRITE`
 *            and another `PROT_READ | PROT_EXEC`. This is the strictest W^X enforcement.
 *
 *          - **Other POSIX (Termux, OpenBSD, etc.):** Uses a simple, single `mmap` with
 *            `MAP_PRIVATE | MAP_ANON`, falling back to mapping `/dev/zero` if `MAP_ANON`
 *            is not defined.
 *
 * @param size The number of bytes to allocate. This will be rounded up to the nearest page size.
 * @return An `infix_executable_t` handle containing pointers to the memory. If allocation
 *         fails, the handle's `size` will be 0.
 */
c23_nodiscard infix_executable_t infix_executable_alloc(size_t size) {
#if defined(INFIX_OS_WINDOWS)
    infix_executable_t exec = {.rx_ptr = nullptr, .rw_ptr = nullptr, .size = 0, .handle = NULL};
#else
    infix_executable_t exec = {.rx_ptr = nullptr, .rw_ptr = nullptr, .size = 0, .shm_fd = -1};
#endif

    if (size == 0)
        return exec;

#if defined(INFIX_OS_WINDOWS)
    void * code = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (code == nullptr)
        return exec;
    exec.rw_ptr = code;
    exec.rx_ptr = code;

#elif defined(INFIX_OS_MACOS) || defined(INFIX_OS_ANDROID) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    void * code = MAP_FAILED;
#if defined(MAP_ANON)
    int flags = MAP_PRIVATE | MAP_ANON;
#if defined(INFIX_OS_MACOS)
    static bool g_use_secure_jit_path = false;
    static bool g_checked_jit_support = false;
    if (!g_checked_jit_support) {
        g_use_secure_jit_path = has_jit_entitlement();
        INFIX_DEBUG_PRINTF("macOS JIT check: Entitlement found = %s. Using %s API.",
                           g_use_secure_jit_path ? "yes" : "no",
                           g_use_secure_jit_path ? "secure (MAP_JIT)" : "legacy/insecure (mprotect)");
        g_checked_jit_support = true;
    }
    // If the check determined the secure path is viable, add the MAP_JIT flag.
    // Otherwise, we proceed without it, using the legacy path.
    if (g_use_secure_jit_path)
        flags |= MAP_JIT;
#endif
    code = mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#endif
    if (code == MAP_FAILED) {  // Fallback for systems without MAP_ANON (like DragonflyBSD)
        int fd = open("/dev/zero", O_RDWR);
        if (fd != -1) {
            code = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
            close(fd);
        }
    }
    if (code == MAP_FAILED)
        return exec;
    exec.rw_ptr = code;
    exec.rx_ptr = code;

#else
    exec.shm_fd = shm_open_anonymous();
    if (exec.shm_fd < 0)
        return exec;
    if (ftruncate(exec.shm_fd, size) != 0) {
        close(exec.shm_fd);
        return exec;
    }
    exec.rw_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, exec.shm_fd, 0);
    exec.rx_ptr = mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, exec.shm_fd, 0);
    if (exec.rw_ptr == MAP_FAILED || exec.rx_ptr == MAP_FAILED) {
        if (exec.rw_ptr != MAP_FAILED)
            munmap(exec.rw_ptr, size);
        if (exec.rx_ptr != MAP_FAILED)
            munmap(exec.rx_ptr, size);
        close(exec.shm_fd);
        return (infix_executable_t){.rx_ptr = nullptr, .rw_ptr = nullptr, .size = 0, .shm_fd = -1};
    }
#endif

    exec.size = size;
    INFIX_DEBUG_PRINTF("Allocated JIT memory. RW at %p, RX at %p", exec.rw_ptr, exec.rx_ptr);
    return exec;
}

/**
 * @internal
 * @brief Frees a region of executable memory and arms a guard page.
 * @ingroup internal_core
 *
 * @details This function is the counterpart to `infix_executable_alloc`. It releases
 *          the JIT-compiled code memory back to the operating system.
 *
 *          **Security Feature:** Before freeing, this function first changes the memory's
 *          protection to be completely inaccessible (`PAGE_NOACCESS` on Windows,
 *          `PROT_NONE` on POSIX). This turns the freed region into a "guard page."
 *          Any subsequent attempt to execute a dangling function pointer that points
 *          to this freed memory will cause an immediate and safe access violation,
 *          rather than executing stale or unrelated data. This is a critical
 *          hardening feature against use-after-free vulnerabilities.
 *
 *          The implementation is platform-specific:
 *          - **Windows:** Calls `VirtualProtect` then `VirtualFree`.
 *          - **macOS (Secure Path):** Calls `pthread_jit_write_protect_np(true)` to make the
 *            memory writable before calling `mprotect` and `munmap`.
 *          - **Linux/BSD (Dual-Map):** Unmaps both the read-write and read-execute
 *            views and closes the shared memory file descriptor.
 *          - **Other POSIX:** Calls `mprotect` then `munmap`.
 *
 * @param exec A handle to the executable memory block to be freed. It is safe to
 *             call this function with a zero-sized (unallocated) handle.
 */
void infix_executable_free(infix_executable_t exec) {
    if (exec.size == 0)
        return;

#if defined(INFIX_OS_WINDOWS)
    if (exec.rw_ptr) {
        // Arm the guard page by revoking all access.
        if (!VirtualProtect(exec.rw_ptr, exec.size, PAGE_NOACCESS, &(DWORD){0}))
            INFIX_DEBUG_PRINTF("WARNING: VirtualProtect failed to set PAGE_NOACCESS.");
        // Now, release the memory.
        VirtualFree(exec.rw_ptr, 0, MEM_RELEASE);
    }
#elif defined(INFIX_OS_MACOS)
    if (exec.rw_ptr) {
#if INFIX_MACOS_SECURE_JIT_AVAILABLE
        // We must check the same static bool to know which path was taken during allocation.
        static bool g_use_secure_jit_path = false;
        if (g_use_secure_jit_path)
            // If the secure path was used, the memory must be made writable again
            // before it can be unmapped.
            pthread_jit_write_protect_np(true);
#endif
        mprotect(exec.rw_ptr, exec.size, PROT_NONE);
        munmap(exec.rw_ptr, exec.size);
    }
#elif defined(INFIX_OS_ANDROID) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    if (exec.rw_ptr) {
        mprotect(exec.rw_ptr, exec.size, PROT_NONE);
        munmap(exec.rw_ptr, exec.size);
    }
#else
    if (exec.rx_ptr)
        mprotect(exec.rx_ptr, exec.size, PROT_NONE);
    if (exec.rw_ptr)
        munmap(exec.rw_ptr, exec.size);
    if (exec.rx_ptr && exec.rx_ptr != exec.rw_ptr)
        munmap(exec.rx_ptr, exec.size);
    if (exec.shm_fd >= 0)
        close(exec.shm_fd);
#endif
}

/**
 * @internal
 * @brief Makes a region of JIT memory executable, enforcing W^X.
 * @ingroup internal_core
 *
 * @details This is the final step in the JIT process. After machine code has been written
 *          to the `rw_ptr`, this function is called to make the `rx_ptr` executable.
 *
 *          It performs two critical, platform-specific actions:
 *          1.  **Instruction Cache Flushing (AArch64):** On all ARM64 platforms, it is
 *              essential to flush the instruction cache before execution. The CPU's
 *              instruction pipeline may have cached stale data from the memory region
 *              before our JIT code was written to it. This call ensures the CPU sees
 *              the new machine code bytes.
 *          2.  **Permission Change (Single-Map Platforms):** On platforms that use a single
 *              memory mapping (Windows, macOS, etc.), this function changes the memory
 *              protection from `Read/Write` to `Read/Execute`, thereby enforcing the W^X
 *              policy. It uses the platform's preferred API for this (`VirtualProtect`,
 *              `pthread_jit_write_protect_np`, or `mprotect`).
 *
 * @param exec A handle to the executable memory block.
 * @return `true` on success, `false` if changing memory protection fails.
 */
c23_nodiscard bool infix_executable_make_executable(infix_executable_t exec) {
    if (exec.rw_ptr == nullptr || exec.size == 0)
        return false;

#if defined(INFIX_ARCH_AARCH64)
#if defined(_MSC_VER)
    FlushInstructionCache(GetCurrentProcess(), exec.rw_ptr, exec.size);
#else
    __builtin___clear_cache((char *)exec.rw_ptr, (char *)exec.rw_ptr + exec.size);
#endif
#endif

    bool result = false;
#if defined(INFIX_OS_WINDOWS)
    result = VirtualProtect(exec.rw_ptr, exec.size, PAGE_EXECUTE_READ, &(DWORD){0});
#elif defined(INFIX_OS_MACOS)
#if INFIX_MACOS_SECURE_JIT_AVAILABLE
    static bool g_use_secure_jit_path = false;
    if (g_use_secure_jit_path) {
        pthread_jit_write_protect_np(false);
        result = true;
    }
    else  // Fallback to the legacy, insecure method.
#endif
        result = (mprotect(exec.rw_ptr, exec.size, PROT_READ | PROT_EXEC) == 0);
#elif defined(INFIX_OS_ANDROID) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    result = (mprotect(exec.rw_ptr, exec.size, PROT_READ | PROT_EXEC) == 0);
#else
    result = true;  // No-op for dual-map platforms
#endif

    if (result)
        INFIX_DEBUG_PRINTF("Memory at %p is ready for execution.", exec.rx_ptr);
    return result;
}

// Protected Data Memory Management
/**
 * @internal
 * @brief Allocates a page-aligned block of read-write data memory.
 * @ingroup internal_core
 *
 * @details This function is a cross-platform wrapper around `VirtualAlloc` (Windows)
 *          and `mmap` (POSIX) to allocate a region of standard read-write memory.
 *
 *          Its primary purpose is to allocate the memory for the `infix_reverse_t`
 *          context struct itself. The memory is allocated with page alignment
 *          so that its permissions can be changed later by `infix_protected_make_readonly`
 *          to harden it against runtime modifications. This is a key security feature.
 *
 * @param size The number of bytes to allocate.
 * @return An `infix_protected_t` handle containing a pointer to the memory and
 *         its size. If allocation fails, the returned handle will have a size of 0.
 */
c23_nodiscard infix_protected_t infix_protected_alloc(size_t size) {
    infix_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    if (size == 0)
        return prot;
#if defined(INFIX_OS_WINDOWS)
    prot.rw_ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(MAP_ANON)
    prot.rw_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#else
    int fd = open("/dev/zero", O_RDWR);
    if (fd == -1)
        prot.rw_ptr = MAP_FAILED;
    else {
        prot.rw_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);
    }
#endif
    if (prot.rw_ptr == MAP_FAILED)
        prot.rw_ptr = nullptr;
#endif
    if (prot.rw_ptr)
        prot.size = size;
    return prot;
}

/**
 * @internal
 * @brief Frees a block of protected data memory.
 * @ingroup internal_core
 *
 * @details This function is the counterpart to `infix_protected_alloc`. It releases the
 *          memory region allocated for a reverse trampoline's context back to the
 *          operating system. It provides a cross-platform abstraction over the
 *          native memory deallocation functions.
 *
 * @param prot A handle to the protected memory block to be freed. It is safe to
 *             call this function with a zero-sized (unallocated) handle.
 */
void infix_protected_free(infix_protected_t prot) {
    if (prot.size == 0)
        return;
#if defined(INFIX_OS_WINDOWS)
    VirtualFree(prot.rw_ptr, 0, MEM_RELEASE);
#else
    munmap(prot.rw_ptr, prot.size);
#endif
}

/**
 * @internal
 * @brief Hardens a block of protected data memory by making it read-only.
 * @ingroup internal_core
 *
 * @details This is a critical security hardening feature. After a reverse trampoline's
 *          `infix_reverse_t` context is fully initialized, this function is called
 *          to change its memory permissions from read-write to read-only.
 *
 *          This mitigates a class of memory corruption vulnerabilities where an
 *          attacker could otherwise overwrite fields in the context at runtime,
 *          such as the `user_callback_fn` pointer, to achieve arbitrary code
 *          execution. By making the context read-only, any such attempt will
 *          result in an immediate and safe memory access violation.
 *
 *          This function is reliable on all supported platforms for standard data
 *          pages (unlike the special handling required for JIT-executable pages on macOS).
 *
 * @param prot A handle to the protected memory block to be hardened.
 * @return `true` if the memory was successfully made read-only, `false` otherwise.
 */
c23_nodiscard bool infix_protected_make_readonly(infix_protected_t prot) {
    if (prot.size == 0)
        return false;
    bool result = false;
#if defined(INFIX_OS_WINDOWS)
    result = VirtualProtect(prot.rw_ptr, prot.size, PAGE_READONLY, &(DWORD){0});
#else
    // On all POSIX platforms (Linux, macOS, BSDs), this works as expected for data pages.
    result = (mprotect(prot.rw_ptr, prot.size, PROT_READ) == 0);
#endif
    return result;
}

/**
 * @internal
 * @brief The high-level C bridge called by the assembly of a reverse trampoline.
 * @ingroup internal_core
 *
 * @details This function is the crucial link between the low-level, ABI-specific
 *          assembly stub and the high-level, user-provided C callback handler. The
 *          assembly stub handles the complexities of the native calling convention,
 *          finds all arguments (whether in registers or on the stack), and packages
 *          them into a simple `void**` array. This function receives that normalized
 *          data and performs the final step of invoking the user's code.
 *
 *          Its primary responsibility is to adapt the argument list for the user's
 *          handler. All `infix` callback handlers have a signature that begins with
 *          `infix_context_t*`, which provides access to state. This function
 *          constructs a new argument array on the stack, prepends a pointer to the
 *          `context` as the first argument, and then calls the user's handler
 *          through a pre-compiled **cached forward trampoline**. This final hop
 *          through another trampoline ensures that the call to the user's C code
 *          is itself ABI-correct.
 *
 * @param context A pointer to the `infix_reverse_t` context object for the
 *                callback that was invoked. This contains the pointer to the
 *                user's C handler and the cached forward trampoline.
 * @param return_value_ptr A pointer to a buffer on the JIT stub's stack. The
 *                         final return value from the user's handler will be
 *                         written here.
 * @param args_array An array of `void*` pointers, where each element points to
 *                   one of the original arguments passed by the native caller.
 *                   This array is prepared by the assembly stub.
 */
void infix_internal_dispatch_callback_fn_impl(infix_reverse_t * context, void * return_value_ptr, void ** args_array) {
    INFIX_DEBUG_PRINTF("Dispatching callback. Context: %p, User Fn: %p", (void *)context, context->user_callback_fn);

    infix_forward_t * trampoline = context->cached_forward_trampoline;
    if (trampoline == nullptr) {
        // This is a fatal internal error, likely from a failed allocation during setup.
        // We cannot propagate an error, but we can prevent a crash by zeroing the
        // return buffer if it exists.
        if (return_value_ptr && context->return_type->size > 0)
            infix_memset(return_value_ptr, 0, context->return_type->size);
        return;
    }

    // The cached trampoline is always a "bound" one, as its target (the user's C
    // handler) is known at creation time. Get its executable code pointer.
    infix_cif_func cif_func = infix_forward_get_code(trampoline);

    // The cached forward trampoline was generated to expect `num_args + 1` arguments,
    // with the first one being the `infix_reverse_t*` context. We must construct a
    // new argument array on the stack that reflects this.
#if defined(INFIX_COMPILER_MSVC)
    // MSVC does not support C99 VLAs, so we use its intrinsic `_alloca`.
    void ** callback_args = (void **)_alloca(sizeof(void *) * (context->num_args + 1));
#else
    // Use a standard Variable Length Array on GCC/Clang.
    void * callback_args[context->num_args + 1];
#endif

    // The first argument to the user's handler is the context pointer itself.
    callback_args[0] = &context;

    // Copy the original argument pointers into the rest of the new array.
    if (context->num_args > 0)
        infix_memcpy(&callback_args[1], args_array, context->num_args * sizeof(void *));

    // Call the user's handler through the trampoline with the complete, prepended argument list.
    cif_func(return_value_ptr, callback_args);

    INFIX_DEBUG_PRINTF("Exiting callback dispatcher.");
}
