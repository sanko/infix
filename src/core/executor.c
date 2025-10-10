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
 * ### macOS JIT Implementation
 *
 * On Apple Silicon, the OS enforces strict W^X policies at the hardware level. To
 * create JIT-compiled code, an application must:
 *   a) Be signed with the `com.apple.security.cs.allow-jit` entitlement.
 *   b) Use the `MAP_JIT` flag when allocating memory.
 *   c) Use the special `pthread_jit_write_protect_np()` function to toggle memory
 *      permissions between write and execute.
 *
 * To avoid forcing users of `infix` to add extra linker flags (`-framework Security`, etc.),
 * this implementation uses a **runtime dynamic linking** approach. On the first call to
 * `infix_executable_alloc` on macOS, it manually `dlopen`s the required system
 * frameworks, finds the necessary functions with `dlsym`, and then checks for the JIT
 * entitlement.
 *
 * If this modern, secure path is available, it is used. If not (e.g., on older OS
 * versions or in unhardened command-line builds), it gracefully falls back to the
 * legacy `mprotect` method. This provides the best of both worlds: maximum security
 * when possible, and maximum compatibility without user friction.
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

// On Apple platforms, include necessary headers for JIT and security framework APIs.
#if defined(INFIX_OS_MACOS)
// https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon
#include <dlfcn.h>  // For dlopen/dlsym
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
// Forward-declare the opaque types from Apple's frameworks to avoid including the full headers.
typedef const struct __CFString * CFStringRef;
typedef const void * CFTypeRef;
typedef struct __SecTask * SecTaskRef;
typedef struct __CFError * CFErrorRef;
#define kCFStringEncodingUTF8 0x08000100

// A struct to hold dynamically loaded function pointers from macOS frameworks.
static struct {
    // CoreFoundation functions
    void (*CFRelease)(CFTypeRef);
    bool (*CFBooleanGetValue)(CFTypeRef boolean);
    CFStringRef (*CFStringCreateWithCString)(CFTypeRef allocator, const char * cStr, uint32_t encoding);
    CFTypeRef kCFAllocatorDefault;

    // Security framework functions
    SecTaskRef (*SecTaskCreateFromSelf)(CFTypeRef allocator);
    CFTypeRef (*SecTaskCopyValueForEntitlement)(SecTaskRef task, CFStringRef entitlement, CFErrorRef * error);
} g_macos_framework_apis;

static void initialize_macos_apis(void) {
    void * cf_handle = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    void * sec_handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);

    if (!cf_handle || !sec_handle) {
        INFIX_DEBUG_PRINTF("Warning: Could not dlopen macOS frameworks. JIT security features will be degraded.");
        if (cf_handle)
            dlclose(cf_handle);
        if (sec_handle)
            dlclose(sec_handle);
        memset(&g_macos_framework_apis, 0, sizeof(g_macos_framework_apis));
        return;
    }
    g_macos_framework_apis.CFRelease = dlsym(cf_handle, "CFRelease");
    g_macos_framework_apis.CFBooleanGetValue = dlsym(cf_handle, "CFBooleanGetValue");
    g_macos_framework_apis.CFStringCreateWithCString = dlsym(cf_handle, "CFStringCreateWithCString");
    void ** pAllocator = (void **)dlsym(cf_handle, "kCFAllocatorDefault");
    if (pAllocator)
        g_macos_framework_apis.kCFAllocatorDefault = *pAllocator;
    g_macos_framework_apis.SecTaskCreateFromSelf = dlsym(sec_handle, "SecTaskCreateFromSelf");
    g_macos_framework_apis.SecTaskCopyValueForEntitlement = dlsym(sec_handle, "SecTaskCopyValueForEntitlement");
    dlclose(cf_handle);
    dlclose(sec_handle);
}
static bool has_jit_entitlement(void) {
    static bool api_initialized = false;
    if (!api_initialized) {
        initialize_macos_apis();
        api_initialized = true;
    }

    if (!g_macos_framework_apis.SecTaskCopyValueForEntitlement || !g_macos_framework_apis.CFStringCreateWithCString)
        return false;

    bool result = false;
    SecTaskRef task = g_macos_framework_apis.SecTaskCreateFromSelf(g_macos_framework_apis.kCFAllocatorDefault);
    if (task == NULL)
        return false;

    CFStringRef entitlement_key = g_macos_framework_apis.CFStringCreateWithCString(
        g_macos_framework_apis.kCFAllocatorDefault, "com.apple.security.cs.allow-jit", kCFStringEncodingUTF8);

    CFTypeRef value = NULL;
    if (entitlement_key)
        value = g_macos_framework_apis.SecTaskCopyValueForEntitlement(task, entitlement_key, NULL);

    g_macos_framework_apis.CFRelease(task);
    if (entitlement_key)
        g_macos_framework_apis.CFRelease(entitlement_key);

    if (value != NULL) {
        if (g_macos_framework_apis.CFBooleanGetValue && g_macos_framework_apis.CFBooleanGetValue(value))
            result = true;

        g_macos_framework_apis.CFRelease(value);
    }

    return result;
}
#endif

#if defined(INFIX_OS_LINUX) || defined(INFIX_OS_FREEBSD)
#include <fcntl.h>
#include <stdint.h>
/*
 * @internal
 * Creates a temporary, anonymous shared memory file descriptor on POSIX systems
 * that support the dual-mapping strategy (e.g., Linux).
 *
 * This function uses a "create-then-unlink" pattern for security and automatic cleanup:
 * 1. It generates a unique, unpredictable name for the shared memory object.
 * 2. It creates the object with `shm_open` using `O_CREAT | O_EXCL` to prevent
 *    race conditions and symlink attacks.
 * 3. It immediately calls `shm_unlink` to remove the name from the filesystem.
 *
 * The open file descriptor remains valid, but the object is now truly anonymous
 * and will be automatically cleaned up by the kernel when the process terminates
 * or the descriptor is closed.
 *
 * @return A valid file descriptor on success, or -1 on failure.
 */
static int shm_open_anonymous() {
    char shm_name[64];
    uint64_t random_val = 0;
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return -1;
    ssize_t bytes_read = read(rand_fd, &random_val, sizeof(random_val));
    close(rand_fd);
    if (bytes_read != sizeof(random_val))
        return -1;
    snprintf(shm_name, sizeof(shm_name), "/infix-jit-%d-%llx", getpid(), (unsigned long long)random_val);

    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        // Unlink the name immediately. The fd remains valid, and the object
        // becomes anonymous, guaranteeing kernel cleanup.
        shm_unlink(shm_name);
        return fd;
    }

    return -1;
}
#endif

// Executable Memory Management
/*
 * Implementation for infix_executable_alloc.
 * This is a cross-platform wrapper that allocates page-aligned memory suitable for JIT code.
 *
 * It employs different strategies based on the OS to achieve W^X:
 * - Windows: Uses `VirtualAlloc` for a single region, initially RW.
 * - macOS, OpenBSD, Termux: Uses a simple, single `mmap` with `MAP_PRIVATE | MAP_ANON`. On
 *   macOS, the `MAP_JIT` flag is now required by the OS for memory that will
 *   be made executable.
 * - Linux & other POSIX: Uses a "dual-mapping" technique with an anonymous shared memory
 *   object to create separate writable (`rw_ptr`) and executable (`rx_ptr`) virtual
 *   mappings to the same physical memory, satisfying strict security policies.
 */
c23_nodiscard infix_executable_t infix_executable_alloc(size_t size) {
// The initialization must be platform-specific to match the struct definition.
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
#elif defined(INFIX_OS_MACOS) || defined(INFIX_OS_TERMUX) || defined(INFIX_OS_NETBSD)  || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    void * code = MAP_FAILED;
#if defined(MAP_ANON)
    int flags = MAP_PRIVATE | MAP_ANON;
#if defined(INFIX_OS_MACOS)
    static bool use_modern_jit = false;
    static bool checked_jit_support = false;
    if (!checked_jit_support) {
        use_modern_jit = has_jit_entitlement();
        INFIX_DEBUG_PRINTF("macOS JIT check: Entitlement present = %s. Using %s API.",
                           use_modern_jit ? "yes" : "no",
                           use_modern_jit ? "secure (MAP_JIT)" : "legacy (mprotect)");
        checked_jit_support = true;
    }
    if (use_modern_jit)
        flags |= MAP_JIT;
#endif
    code = mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#endif  // MAP_ANON

    // If the MAP_ANON path was not taken or failed, fall back to /dev/zero.
    // This is the correct path for DragonflyBSD.
    if (code == MAP_FAILED) {
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

#else  // All other POSIX systems (Linux, FreeBSD) use dual-mapping
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

/*
 * Implementation for infix_executable_free.
 * This function first changes the memory's protection to be inaccessible
 * (`PAGE_NOACCESS` or `PROT_NONE`), turning it into a "guard page". Any
 * attempt to execute a dangling function pointer that points to this freed memory
 * will cause an immediate and safe access violation, rather than executing
 * stale or unrelated data. This is a critical security hardening feature.
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
        static bool use_modern_jit = false;
        if (use_modern_jit)
            pthread_jit_write_protect_np(true);
        mprotect(exec.rw_ptr, exec.size, PROT_NONE);
        munmap(exec.rw_ptr, exec.size);
    }
#else
    if (exec.rx_ptr)
        mprotect(exec.rx_ptr, exec.size, PROT_NONE);
    if (exec.rw_ptr && exec.rx_ptr != exec.rw_ptr)
        munmap(exec.rw_ptr, exec.size);
    if (exec.rx_ptr)
        munmap(exec.rx_ptr, exec.size);
    if (exec.shm_fd >= 0)
        close(exec.shm_fd);
#endif
}

/*
 * Implementation for infix_executable_make_executable.
 * This is the final step in the JIT process. After machine code has been written
 * to `rw_ptr`, this function makes `rx_ptr` executable.
 *
 * It performs two critical, platform-specific actions:
 * 1.  On AArch64, it flushes the instruction cache to ensure the CPU sees the newly
 *     written code bytes. This is done *before* changing permissions.
 * 2.  On single-map platforms, it enforces W^X by changing memory protection from
 *     Read/Write to Read/Execute.
 *     - macOS: Uses the Apple-specific `pthread_jit_write_protect_np` for reliability.
 *     - Windows: Uses `VirtualProtect`.
 *     - Other POSIX: Uses standard `mprotect`.
 */
c23_nodiscard bool infix_executable_make_executable(infix_executable_t exec) {
    if (exec.rw_ptr == nullptr || exec.size == 0)
        return false;

#if defined(INFIX_ARCH_AARCH64)
    // On all ARM64 platforms, the instruction cache must be flushed *before* execution
    // to ensure the CPU's instruction pipeline sees the newly written data.
#if defined(_MSC_VER)
    FlushInstructionCache(GetCurrentProcess(), exec.rw_ptr, exec.size);
#else
    __builtin___clear_cache((char *)exec.rw_ptr, (char *)exec.rw_ptr + exec.size);
#endif
#endif

    bool result = false;
#if defined(INFIX_OS_WINDOWS)
    // On single-map Windows, change protection from RW to RX.
    result = VirtualProtect(exec.rw_ptr, exec.size, PAGE_EXECUTE_READ, &(DWORD){0});
#elif defined(INFIX_OS_MACOS)
    static bool use_modern_jit = false;
    if (use_modern_jit) {
        pthread_jit_write_protect_np(false);
        result = true;
    }
    else
        result = (mprotect(exec.rw_ptr, exec.size, PROT_READ | PROT_EXEC) == 0);
#else
    if (exec.rx_ptr == exec.rw_ptr)
        result = (mprotect(exec.rw_ptr, exec.size, PROT_READ | PROT_EXEC) == 0);
    else
        result = true;
#endif

    if (result)
        INFIX_DEBUG_PRINTF("Memory at %p is ready for execution.", exec.rx_ptr);
    return result;
}

// Protected Data Memory Management
/*
 * Implementation for infix_protected_alloc.
 * This allocates a page-aligned block of read-write data memory, used for the
 * reverse trampoline context structure.
 */
c23_nodiscard infix_protected_t infix_protected_alloc(size_t size) {
    infix_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    if (size == 0)
        return prot;

#if defined(INFIX_OS_WINDOWS)
    prot.rw_ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else  // POSIX platforms
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

/*
 * Implementation for infix_protected_free.
 * This frees a block of protected data memory.
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

/*
 * Implementation for infix_protected_make_readonly.
 * This is a security hardening step. After the reverse trampoline context is fully
 * initialized, it is made read-only to prevent it from being modified at runtime,
 * which could otherwise lead to security vulnerabilities.
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

// Callback Dispatching
/*
 * Implementation for infix_internal_dispatch_callback_fn_impl.
 * This is the high-level C bridge called by the low-level assembly of a reverse trampoline.
 * It receives arguments in a normalized format (`void** args_array`).
 *
 * Its primary job is to prepare and call the user's C handler via a pre-compiled
 * forward trampoline (`cached_forward_trampoline`). This involves:
 * 1.  Constructing a new, augmented argument array on the stack.
 * 2.  Setting the *first* element of this new array to be a pointer to the `context`.
 * 3.  Copying the original arguments into the rest of the new array.
 * 4.  Calling the cached trampoline, which was generated to expect this exact
 *     `(context, ...)` argument signature.
 */
void infix_internal_dispatch_callback_fn_impl(infix_reverse_t * context, void * return_value_ptr, void ** args_array) {
    INFIX_DEBUG_PRINTF("Dispatching callback. Context: %p, User Fn: %p", (void *)context, context->user_callback_fn);

    infix_forward_t * trampoline = context->cached_forward_trampoline;
    if (trampoline == nullptr) {
        // This is a fatal internal error. We cannot propagate it, but we can prevent
        // a crash by zeroing the return buffer if it exists.
        if (return_value_ptr && context->return_type->size > 0)
            infix_memset(return_value_ptr, 0, context->return_type->size);
        return;
    }

    // The cached trampoline is always a "bound" one, as its target (the user's C
    // handler) is known at creation time.
    infix_bound_cif_func cif_func = infix_forward_get_code(trampoline);

    // The cached forward trampoline was generated to expect `num_args + 1` arguments,
    // with the first one being the `infix_reverse_t*` context. We must construct a
    // new argument array that reflects this.
#if defined(INFIX_COMPILER_MSVC)
    // MSVC does not support VLAs, so we use its intrinsic `_alloca` for stack allocation.
    void ** callback_args = (void **)_alloca(sizeof(void *) * (context->num_args + 1));
#else
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
