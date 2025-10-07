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
 * @file error.c
 * @brief Implements the thread-local error reporting system.
 * @ingroup internal_core
 */

#include "common/infix_internals.h"
#include <infix/infix.h>
#include <stdarg.h>

// Use the same thread-local storage mechanism as the test harness for consistency.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#define INFIX_TLS _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define INFIX_TLS __thread
#elif defined(_MSC_VER)
#define INFIX_TLS __declspec(thread)
#else
#define INFIX_TLS
#endif

// The thread-local variable that stores the last error.
static INFIX_TLS infix_error_details_t g_infix_last_error = {INFIX_CATEGORY_NONE, INFIX_CODE_SUCCESS, 0};

/**
 * @internal
 * @brief Sets the last error details for the current thread.
 */
void _infix_set_error(infix_error_category_t category, infix_error_code_t code, size_t position) {
    g_infix_last_error.category = category;
    g_infix_last_error.code = code;
    g_infix_last_error.position = position;
}

/**
 * @internal
 * @brief Resets the error state for the current thread. Called at the start of a public API function.
 */
void _infix_clear_error(void) {
    g_infix_last_error.category = INFIX_CATEGORY_NONE;
    g_infix_last_error.code = INFIX_CODE_SUCCESS;
    g_infix_last_error.position = 0;
}

/**
 * @brief Public API function to retrieve the last error.
 */
infix_error_details_t infix_get_last_error(void) {
    return g_infix_last_error;
}
