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
 * @file compat_c23.h
 * @brief Provides compatibility shims for C23 features in a C17/C11 project.
 * @ingroup internal_compat
 *
 * @internal
 * This header uses preprocessor macros and common compiler extensions
 * to provide a subset of C23's ergonomic improvements, such as the `nullptr`
 * keyword and the `[[attribute]]` syntax, to older C standards like C11 and C17.
 *
 * This allows the main codebase to be written using more modern, expressive, and
 * safer syntax while maintaining compatibility with a wide range of C compilers
 * that may not yet fully support the C23 standard. Each macro gracefully degrades
 * or maps to a compiler-specific equivalent if the C23 feature is not available.
 * @endinternal
 */

#include <stdbool.h>  // For bool, true, false
#include <stddef.h>   // For offsetof, size_t

/**
 * @internal
 * @def nullptr
 * @brief A C17/C11-compatible emulation of the C23 `nullptr` keyword.
 * @details This is defined as `((void*)0)`. It provides a type-safe null pointer
 *          constant that is safer and more expressive than the traditional `NULL`
 *          macro, which can be ambiguously defined as either `0` or `(void*)0`.
 */
#ifndef nullptr
#define nullptr ((void *)0)
#endif

/**
 * @internal
 * @def static_assert(cond, msg)
 * @brief A C17/C11-compatible alias for the `_Static_assert` keyword.
 * @details This macro provides the more modern `static_assert` keyword, making
 *          compile-time assertions more readable and consistent with C++. It has
 *          no functional difference from `_Static_assert`.
 */
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) || (defined(_MSC_VER) && _MSC_VER >= 1900)
// On modern compilers, <assert.h> may also define `static_assert` as a macro.
// We include it here to ensure the system's definition is seen first, which
// allows our `#ifndef` guard to correctly prevent a redefinition warning.
#include <assert.h>
#ifndef static_assert
#define static_assert(cond, msg) _Static_assert(cond, msg)
#endif
#endif

// (Internal) Helper to check for native C23-style attributes [[...]]
#if defined(__has_c_attribute)
#define COMPAT_HAS_C_ATTRIBUTE(x) __has_c_attribute(x)
#else
#define COMPAT_HAS_C_ATTRIBUTE(x) 0
#endif

/**
 * @internal
 * @def c23_nodiscard
 * @brief A cross-compiler macro for the `[[nodiscard]]` attribute.
 * @details Instructs the compiler to issue a warning if the return value of a
 *          function decorated with this attribute is ignored by the caller. This
 *          is a powerful tool for preventing bugs where an important return value
 *          (like an error code or a newly allocated resource) is not checked or used.
 *
 *          It first checks for the standard C23 `[[nodiscard]]` syntax and falls
 *          back to `__attribute__((warn_unused_result))` on GCC/Clang and
 *          `_Check_return_` on MSVC if it's not available. On other compilers,
 *          it becomes a no-op.
 */
#if COMPAT_HAS_C_ATTRIBUTE(nodiscard)
#define c23_nodiscard [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define c23_nodiscard __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define c23_nodiscard _Check_return_
#else
#define c23_nodiscard
#endif

/**
 * @internal
 * @def c23_deprecated
 * @brief A cross-compiler macro for the `[[deprecated]]` attribute.
 * @details Instructs the compiler to issue a warning if a function, type, or
 *          variable decorated with this attribute is used. This is useful for
 *          gracefully phasing out old APIs.
 *
 *          It falls back to `__attribute__((deprecated))` on GCC/Clang and
 *          `__declspec(deprecated)` on MSVC.
 */
#if COMPAT_HAS_C_ATTRIBUTE(deprecated)
#define c23_deprecated [[deprecated]]
#elif defined(__GNUC__) || defined(__clang__)
#define c23_deprecated __attribute__((deprecated))
#elif defined(_MSC_VER)
#define c23_deprecated __declspec(deprecated)
#else
#define c23_deprecated
#endif

/**
 * @internal
 * @def c23_fallthrough
 * @brief A cross-compiler macro for the `[[fallthrough]]` attribute.
 * @details Suppresses compiler warnings about a `case` in a `switch` statement
 *          that intentionally falls through to the next `case` without a `break`.
 *          This makes the code's intent explicit.
 *
 *          It falls back to `__attribute__((fallthrough))` on GCC/Clang.
 */
#if COMPAT_HAS_C_ATTRIBUTE(fallthrough)
#define c23_fallthrough [[fallthrough]]
#elif defined(__GNUC__) || defined(__clang__)
#define c23_fallthrough __attribute__((fallthrough))
#else
#define c23_fallthrough /* fallthrough */
#endif

/**
 * @internal
 * @def c23_maybe_unused
 * @brief A cross-compiler macro for the `[[maybe_unused]]` attribute.
 * @details Suppresses compiler warnings about an unused variable, function parameter,
 *          or static function. This is useful for parameters that are only used in
 *          certain build configurations (like debug vs. release).
 *
 *          It falls back to `__attribute__((unused))` on GCC/Clang.
 */
#if COMPAT_HAS_C_ATTRIBUTE(maybe_unused)
#define c23_maybe_unused [[maybe_unused]]
#elif defined(__GNUC__) || defined(__clang__)
#define c23_maybe_unused __attribute__((unused))
#else
#define c23_maybe_unused
#endif
