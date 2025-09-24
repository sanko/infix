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
 * @brief Implements the OS-level memory management and the internal callback dispatcher.
 *
 * @details This file forms the OS abstraction layer for the FFI library. It is
 * responsible for two primary, security-critical tasks:
 *
 * 1.  **Executable Memory Management:** It provides a cross-platform interface
 *     for allocating, freeing, and managing executable memory. This implementation
 *     adheres to a strict W^X (Write XOR Execute) security policy, meaning memory
 *     is never writable and executable at the same time. This is a crucial defense
 *     against JIT-spraying and other code injection attacks. Different OSes require
 *     different strategies to achieve this:
 *     - **On Windows:** It uses the native `VirtualAlloc` API for single-region allocation.
 *     - **On macOS & others:** It uses a simple and reliable single-region `mmap`, which is known
 *       to work correctly and avoid platform-specific JIT issues.
 *     - **On other POSIX systems (Linux, BSD):** It uses a dual-mapping technique with an
 *       anonymous shared memory object (`shm_open`) to create separate writable and
 *       executable views of the same physical memory, which is necessary for some hardened systems.
 *
 * 2.  **Callback Dispatching:** It contains the high-level C function
 *     (`infix_internal_dispatch_callback_fn_impl`) that is called by the
 *     low-level assembly of a reverse trampoline. This function acts as the final
 *     bridge to invoke the user's C callback with the correctly marshalled arguments.
 */

// Define the POSIX source macro to ensure function declarations for shm_open,
// ftruncate, etc., are visible on all POSIX-compliant systems.
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

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

// Portability shim for mmap anonymous flag. Most modern systems (especially BSDs)
// use MAP_ANON. Some older or Linux-specific code uses MAP_ANONYMOUS.
#if defined(INFIX_ENV_POSIX) && !defined(INFIX_OS_WINDOWS)
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif
#endif

#if !defined(INFIX_OS_WINDOWS) && !defined(INFIX_OS_MACOS) && !defined(INFIX_OS_TERMUX) && !defined(INFIX_OS_OPENBSD)
#include <fcntl.h>   // For O_RDONLY
#include <stdint.h>  // For uint64_t
/**
 * @brief (Internal) Creates a temporary, anonymous shared memory file descriptor on POSIX.
 * @details This helper function is used exclusively on POSIX systems other than macOS/OpenBSD
 *          (e.g., Linux, other BSDs) to support the dual-mapping memory strategy.
 *
 *          In an attempt to enhance security, it generates a unique, unpredictable name for the
 *          shared memory object by combining the process ID with random bytes from `/dev/urandom`.
 *          It then creates the object with `O_CREAT | O_EXCL` to prevent race conditions
 *          and immediately unlinks the name with `shm_unlink`. The open file descriptor remains
 *          valid, but the name is removed from the filesystem, ensuring that the object is
 *          automatically cleaned up by the kernel when the process terminates or the descriptor is closed.
 *
 * @return A valid file descriptor on success, or -1 on failure.
 */
static int shm_open_anonymous() {
    char shm_name[64];
    uint64_t random_val = 0;

    // Open /dev/urandom to get cryptographically secure random bytes.
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return -1;

    // Read 8 bytes (64 bits) of random data.
    ssize_t bytes_read = read(rand_fd, &random_val, sizeof(random_val));
    close(rand_fd);
    if (bytes_read != sizeof(random_val))
        return -1;
    // Create a highly unpredictable name to minimize collision risk.
    snprintf(shm_name, sizeof(shm_name), "/infix-jit-%d-%llx", getpid(), (unsigned long long)random_val);
    // O_EXCL is a critical security flag. It ensures that shm_open will fail if
    // a file with this name already exists, preventing symlink attacks or races.
    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        // We've successfully created the object. Now, unlink the name immediately.
        // The file descriptor remains valid, but the name is gone from the filesystem,
        // making it truly anonymous and ensuring automatic cleanup.
        shm_unlink(shm_name);
        return fd;
    }

    // If shm_open failed, it's likely a more serious system issue, as a
    // name collision is now astronomically unlikely.
    return -1;
}
#endif

/**
 * @brief Allocates a block of memory suitable for JIT compilation.
 * @details This function is a cross-platform wrapper that allocates memory with
 *          initial Read/Write permissions. The final memory block is guaranteed to
 *          be page-aligned, as required by memory protection APIs.
 *
 *          It employs different strategies based on the operating system to achieve W^X:
 *          - **Windows:** Uses `VirtualAlloc` to reserve and commit a single region of memory.
 *            The pointer is initially RW and later changed to RX.
 *          - **macOS, OpenBSD & Termux:** Uses a simple `mmap` with `MAP_PRIVATE | MAP_ANON`. This
 *            single-mapping approach is reliable and avoids `SIGBUS` errors and other
 *            complications common with more complex JIT setups on these platforms.
 *          - **Linux & other POSIX:** Uses a **dual-mapping** technique. It creates an
 *            anonymous shared memory object (`shm_open`) and then creates two separate
 *            virtual memory mappings to it: one that is `PROT_READ | PROT_WRITE` (`rw_ptr`)
 *            and another that is `PROT_READ | PROT_EXEC` (`rx_ptr`). This ensures memory
 *            is never writable and executable at the same time from different virtual addresses,
 *            satisfying strict security policies found on some hardened systems.
 *
 * @param size The number of bytes to allocate. Will be rounded up to the nearest page size.
 * @return An `infix_executable_t` handle. On failure, the `size` member of the returned struct will be 0.
 */
c23_nodiscard infix_executable_t infix_executable_alloc(size_t size) {
    infix_executable_t exec = {.rx_ptr = nullptr, .rw_ptr = nullptr, .size = 0};
    if (size == 0) {
        return exec;
    }

#if defined(INFIX_OS_WINDOWS)
    // Windows: Single Mapping (VirtualAlloc).
    void * code = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (code == nullptr)
        return exec;
    // In a single-mapping model, both pointers initially point to the same RW address.
    exec.rw_ptr = code;
    exec.rx_ptr = code;

#elif defined(INFIX_OS_MACOS) || defined(INFIX_OS_TERMUX) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    // Single Mapping (mmap). This simpler approach is more reliable on these platforms.
    // - macOS/OpenBSD: Avoids issues with shm + fork.
    // - termux: https://github.com/termux/libandroid-shmem/issues/10
    void * code = MAP_FAILED;
#if defined(MAP_ANON)
    int flags = MAP_PRIVATE | MAP_ANON;
#if defined(INFIX_OS_MACOS)
    flags |= MAP_JIT;
#endif
    code = mmap(nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
#else
    // Fallback for systems like DragonFly BSD that may not define MAP_ANON.
    int fd = open("/dev/zero", O_RDWR);
    if (fd != -1) {
        code = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        close(fd);
    }
#endif
    if (code == MAP_FAILED)
        return exec;

    // Both pointers point to the same memory region.
    exec.rw_ptr = code;
    exec.rx_ptr = code;

#else
    // Other POSIX (Linux, BSD): Dual Mapping (shm_open) for strict W^X.
    exec.shm_fd = shm_open_anonymous();
    if (exec.shm_fd < 0)
        return exec;

    if (ftruncate(exec.shm_fd, size) != 0) {
        close(exec.shm_fd);
        return exec;
    }
    // Create two separate virtual memory mappings to the same underlying shared memory object.
    exec.rw_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, exec.shm_fd, 0);
    exec.rx_ptr = mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_SHARED, exec.shm_fd, 0);
    if (exec.rw_ptr == MAP_FAILED || exec.rx_ptr == MAP_FAILED) {
        if (exec.rw_ptr != MAP_FAILED)
            munmap(exec.rw_ptr, size);
        if (exec.rx_ptr != MAP_FAILED)
            munmap(exec.rx_ptr, size);
        close(exec.shm_fd);
        // Reset all fields to indicate failure.
        return (infix_executable_t){.rx_ptr = nullptr, .rw_ptr = nullptr, .size = 0, .shm_fd = -1};
    }
#endif

    exec.size = size;
    INFIX_DEBUG_PRINTF("Allocated JIT memory. RW at %p, RX at %p", exec.rw_ptr, exec.rx_ptr);
    return exec;
}

/**
 * @brief Frees a block of executable memory, turning it into a guard page first.
 * @details This function first changes the memory's protection to be inaccessible
 *          (`PAGE_NOACCESS` or `PROT_NONE`), turning it into a "guard page". Any
 *          attempt to execute a dangling function pointer that points to this memory
 *          will cause an immediate and safe access violation, rather than executing
 *          stale or unrelated data. After arming the guard, it then releases the
 *          underlying memory resources.
 *
 * @param exec The `infix_executable_t` handle to the memory to be freed.
 */
void infix_executable_free(infix_executable_t exec) {
    if (exec.size == 0)
        return;

#if defined(INFIX_OS_WINDOWS)
    if (exec.rw_ptr) {
        // Turn the page into a guard page by revoking all access.
        VirtualProtect(exec.rw_ptr, exec.size, PAGE_NOACCESS, &(DWORD){0});
        // Now, release the memory reservation.
        VirtualFree(exec.rw_ptr, 0, MEM_RELEASE);
    }
#elif defined(INFIX_OS_MACOS) || defined(INFIX_OS_TERMUX) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    if (exec.rw_ptr) {
        // On single-map platforms, rw_ptr == rx_ptr
        // Turn the page into a guard page.
        mprotect(exec.rw_ptr, exec.size, PROT_NONE);
        // Now, unmap the memory.
        munmap(exec.rw_ptr, exec.size);
    }
#else
    // Other POSIX (Linux, BSD) with dual-mapping
    // For dual-mapped systems, we only need to make the *executable* view inaccessible.
    if (exec.rx_ptr)
        mprotect(exec.rx_ptr, exec.size, PROT_NONE);
    // Now unmap both views and close the shared memory file descriptor.
    if (exec.rw_ptr)
        munmap(exec.rw_ptr, exec.size);
    if (exec.rx_ptr && exec.rx_ptr != exec.rw_ptr)
        munmap(exec.rx_ptr, exec.size);
    if (exec.shm_fd >= 0)
        close(exec.shm_fd);
#endif
}

/**
 * @brief Makes a memory block executable and finalizes it for use.
 * @details This is the final step in the JIT process. After machine code has been
 *          written to the `rw_ptr` of an `infix_executable_t` handle, this function
 *          makes the `rx_ptr` executable.
 *
 *          Platform-specific actions:
 *          - **ARM64 (All OSes):** It first performs an instruction cache flush
 *            (`__builtin___clear_cache` or `FlushInstructionCache`). This is critical
 *            on architectures with separate data and instruction caches to ensure the
 *            CPU sees the newly written code bytes.
 *          - **Windows/macOS/OpenBSD (Single-Map):** It then changes the memory protection of the
 *            single memory region from `Read/Write` to `Read/Execute` using `VirtualProtect`
 *            or `mprotect`, thereby enforcing W^X.
 *          - **Linux/BSD (Dual-Map):** No `mprotect` call is needed because the `rx_ptr`
 *            is a separate mapping that was already created with `PROT_EXEC`. The function's
 *            only job on these platforms is to perform the necessary cache flush on ARM.
 *
 * @param exec The `infix_executable_t` handle to the memory block.
 * @return `true` on success, `false` on failure (e.g., if `mprotect` fails).
 */
c23_nodiscard bool infix_executable_make_executable(infix_executable_t exec) {
    if (exec.rw_ptr == nullptr || exec.size == 0)
        return false;

#if defined(INFIX_ARCH_AARCH64)
    // On all ARM64 platforms, the instruction cache must be flushed before execution.
// This is done *before* changing memory permissions to ensure the writes are visible.
#if defined(_MSC_VER)
    FlushInstructionCache(GetCurrentProcess(), exec.rw_ptr, exec.size);
#else
    // A GCC/Clang built-in that emits the necessary cache maintenance instructions.
    __builtin___clear_cache((char *)exec.rw_ptr, (char *)exec.rw_ptr + exec.size);
#endif
#endif

    bool result = false;
#if defined(INFIX_OS_WINDOWS)
    // For single-map on Windows, we change the protection from RW to RX.
    result = VirtualProtect(exec.rw_ptr, exec.size, PAGE_EXECUTE_READ, &(DWORD){0});
#elif defined(INFIX_OS_MACOS) || defined(INFIX_OS_TERMUX) || defined(INFIX_OS_OPENBSD) || defined(INFIX_OS_DRAGONFLY)
    // For single-map on these POSIX systems, we also change protection from RW to RX.
    result = (mprotect(exec.rw_ptr, exec.size, PROT_READ | PROT_EXEC) == 0);
#else
    result = true;  // Dual-map is already executable
#endif

    if (result)
        INFIX_DEBUG_PRINTF("Memory at %p is ready for execution.", exec.rx_ptr);
    return result;
}

/**
 * @brief Allocates a page-aligned block of read-write data memory.
 * @internal This is used to allocate the context structure for reverse trampolines.
 *           The memory can later be made read-only for security hardening.
 * @param size The number of bytes to allocate.
 * @return An `infix_protected_t` handle. `rw_ptr` will be `nullptr` on failure.
 */
c23_nodiscard infix_protected_t infix_protected_alloc(size_t size) {
    infix_protected_t prot = {.rw_ptr = nullptr, .size = 0};
    if (size == 0)
        return prot;

#if defined(INFIX_OS_WINDOWS)
    prot.rw_ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else  // POSIX platforms
#if defined(MAP_ANON)
    prot.rw_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#else
    int fd = open("/dev/zero", O_RDWR);
    if (fd == -1)
        prot.rw_ptr = MAP_FAILED;
    else {
        prot.rw_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
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
 * @brief Frees a block of protected data memory.
 * @internal Used to clean up the memory allocated for a reverse trampoline context.
 * @param prot The handle to the memory to be freed.
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
 * @brief Changes the permissions of a protected data block from Read/Write to Read-Only.
 * @internal This is a security hardening step for the reverse trampoline context. After
 *           the context is fully initialized, it is made read-only to prevent it from
 *           being modified at runtime, which could otherwise lead to security vulnerabilities.
 * @note This feature is currently disabled on macOS because `mprotect` on general-purpose
 *       `mmap`'d memory has been observed to be unreliable on that platform.
 * @param prot The handle to the memory block.
 * @return `true` on success, `false` otherwise.
 */
c23_nodiscard bool infix_protected_make_readonly(infix_protected_t prot) {
    if (prot.size == 0)
        return false;

    bool result = false;
#if defined(INFIX_OS_WINDOWS)
    // On Linux and BSDs, this works as expected.
    result = VirtualProtect(prot.rw_ptr, prot.size, PAGE_READONLY, &(DWORD){0});
#elif !defined(INFIX_OS_MACOS)
    // On Linux and BSDs, this works as expected.
    result = (mprotect(prot.rw_ptr, prot.size, PROT_READ) == 0);
#else
    // On macOS, mprotect on mmap'd data pages can be unreliable.
    // We skip this hardening step for now to ensure stability.
    (void)prot;
    result = true;
#endif
    return result;
}

/**
 * @brief The internal C dispatcher function for all reverse trampolines (cached).
 * @details This function is the high-level C bridge called by the low-level assembly of
 *          a reverse trampoline. It receives arguments in a normalized format (an array
 *          of `void*`) and is responsible for invoking the user's actual C callback handler.
 *
 *          The process is as follows:
 *          1.  It receives the `infix_reverse_t` context and the `args_array`
 *              from the JIT-compiled assembly stub.
 *          2.  It constructs a **new, augmented argument array** on the stack.
 *          3.  The **first element** of this new array is set to a pointer to the `context`.
 *          4.  The pointers from the original `args_array` are copied into the rest of the
 *              new array.
 *          5.  It retrieves the `cached_forward_trampoline` from the context (which was generated
 *              to expect this augmented argument list).
 *          6.  It calls the user's C handler through this trampoline, transparently passing
 *              the context as the first argument.
 *
 * @param context A pointer to the callback's context structure.
 * @param return_value_ptr A pointer to a buffer on the trampoline's stack where the
 *                         return value should be stored.
 * @param args_array An array of pointers from the JIT stub, where each element points
 *                   to an argument's data from the native caller.
 */
void infix_internal_dispatch_callback_fn_impl(infix_reverse_t * context, void * return_value_ptr, void ** args_array) {
    INFIX_DEBUG_PRINTF("In infix_internal_dispatch_callback_fn_impl");
    INFIX_DEBUG_PRINTF("  Context: %p, User Callback: %p, NumArgs: %llu",
                       (void *)context,
                       context->user_callback_fn,
                       (unsigned long long)context->num_args);
    infix_forward_t * trampoline = context->cached_forward_trampoline;
    if (trampoline == nullptr) {
        // This is a fatal internal error. We can't propagate an error from here,
        // but we can prevent a crash by zeroing the return buffer if it exists.
        if (return_value_ptr && context->return_type->size > 0)
            infix_memset(return_value_ptr, 0, context->return_type->size);
        return;
    }

    infix_cif_func cif_func = (infix_cif_func)infix_forward_get_code(trampoline);

    /// For all other function signatures, use the cached forward trampoline
    // to call the user's C callback handler with the correct native ABI.

    // The cached_forward_trampoline was generated to expect `num_args + 1` arguments,
    // with the first one being the `infix_reverse_t*` context.
    // We must construct a new argument array that reflects this.
#if defined(INFIX_COMPILER_MSVC)
    // MSVC does not support VLAs, so we use its intrinsic `_alloca` for stack allocation.
    void ** callback_args = (void **)_alloca(sizeof(void *) * (context->num_args + 1));
#else
    void * callback_args[context->num_args + 1];
#endif

    // The first argument to the user's handler is the context pointer itself.
    // The args array needs a pointer to this value.
    callback_args[0] = &context;

    // Copy the original argument pointers into the rest of the new array.
    if (context->num_args > 0)
        infix_memcpy(&callback_args[1], args_array, context->num_args * sizeof(void *));

    // Call the user's handler through the trampoline with the complete, prepended argument list.
    cif_func(context->user_callback_fn, return_value_ptr, callback_args);

    INFIX_DEBUG_PRINTF("Exiting infix_internal_dispatch_callback_fn_impl");
}
