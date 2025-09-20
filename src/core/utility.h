#pragma once
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
 * @file utility.h
 * @brief A header for debugging utilities that are conditionally compiled.
 *
 * @details This header is the central point for the library's debugging
 * infrastructure. Its primary feature is that it behaves differently based on
 * the `FFI_DEBUG_ENABLED` preprocessor macro. This allows debugging code to be
 * seamlessly integrated during development without affecting the performance or
 * size of the final production binary.
 *
 * - **When `FFI_DEBUG_ENABLED` is defined and non-zero (Debug Mode):**
 *   - If `DBLTAP_ENABLE` is *also* defined, this header includes `double_tap.h`
 *     and defines `FFI_DEBUG_PRINTF` to use its `note()` macro for integrated
 *     test logging.
 *   - If `DBLTAP_ENABLE` is *not* defined (e.g., for a bare test executable),
 *     it defines `FFI_DEBUG_PRINTF` to fall back to a standard `printf`.
 *   - In both cases, it declares the `DumpHex` function for memory inspection.
 *
 * - **When `FFI_DEBUG_ENABLED` is not defined or is zero (Release Mode):**
 *   All debugging macros are defined as no-ops (`((void)0)`), and `DumpHex` is
 *   defined as an empty `static inline` function. This ensures that all debugging
 *   code is completely compiled out by the optimizer.
 */

#include <compat_c23.h>
#include <stddef.h>

// Check if FFI_DEBUG_ENABLED is defined and set to a non-zero value.
#if defined(FFI_DEBUG_ENABLED) && FFI_DEBUG_ENABLED

// The double_tap framework is only included if both debug mode AND the main
// test harness toggle are enabled. This allows for debug builds of non-test executables.
#if defined(DBLTAP_ENABLE)
#include <double_tap.h>

/**
 * @def FFI_DEBUG_PRINTF(...)
 * @brief A macro for printing formatted debug messages during a debug build with the test harness.
 * @details In debug builds where the `double_tap.h` test harness is active, this macro
 *          wraps the `note()` macro, which prints a formatted string prefixed with `# `.
 *          This allows FFI-specific debug output to be cleanly integrated into the test logs.
 *
 * **Example Usage:**
 * ```c
 * FFI_DEBUG_PRINTF("Processing type %d with size %zu", type->id, type->size);
 * ```
 */
#define FFI_DEBUG_PRINTF(...) note("FFI_DEBUG: " __VA_ARGS__)

#else
#include <stdio.h>  // Include for the printf fallback.

/**
 * @def FFI_DEBUG_PRINTF(...)
 * @brief A macro for printing formatted debug messages (printf fallback).
 * @details In debug builds where the `double_tap.h` harness is *not* active, this macro
 *          falls back to a standard `printf`, ensuring that debug messages are still visible.
 */
#define FFI_DEBUG_PRINTF(...)                \
    do {                                     \
        printf("# FFI_DEBUG: " __VA_ARGS__); \
        printf("\n");                        \
    } while (0)
#endif  // DBLTAP_ENABLE

/**
 * @brief Declares the function prototype for `DumpHex` (available in debug builds only).
 * @details This function is invaluable for inspecting the raw machine code generated
 *          by the JIT compiler. It prints a detailed hexadecimal and ASCII dump of a
 *          memory region to the standard output, formatted for readability. See the
 *          implementation in `utility.c` for more details.
 *
 * @param data A pointer to the start of the memory block to dump.
 * @param size The number of bytes to dump.
 * @param title A descriptive title to print before and after the hex dump.
 */
void DumpHex(const void * data, size_t size, const char * title);

#else  // FFI_DEBUG_ENABLED is NOT defined or is zero (Release Mode)

/**
 * @def FFI_DEBUG_PRINTF(...)
 * @brief A macro for printing formatted debug messages (a no-op in release builds).
 * @details In release builds, this macro is defined as `((void)0)`, a standard C idiom
 *          for creating a statement that does nothing and has no side effects. The
 *          compiler will completely remove any calls to it, ensuring zero performance impact.
 */
#define FFI_DEBUG_PRINTF(...) ((void)0)

/**
 * @brief A no-op version of `DumpHex` for release builds.
 * @details This function is defined as an empty `static inline` function.
 *          - `static`: Prevents linker errors if this header is included in multiple files.
 *          - `inline`: Suggests to the compiler that the function body is empty,
 *            allowing it to completely remove any calls to this function at the call site.
 *          - `c23_maybe_unused`: Explicitly tells the compiler that the parameters are
 *            intentionally unused in this version of the function, suppressing warnings.
 *
 * @param data Unused in release builds.
 * @param size Unused in release builds.
 * @param title Unused in release builds.
 */
static inline void DumpHex(c23_maybe_unused const void * data,
                           c23_maybe_unused size_t size,
                           c23_maybe_unused const char * title) {
    // This function does nothing in release builds and will be optimized away.
}

#endif  // FFI_DEBUG_ENABLED
