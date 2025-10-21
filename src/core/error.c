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
#include <stdio.h>  // For snprintf
#include <string.h>

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

// A portable macro for safe string copying.
#if defined(_MSC_VER)
// Use the bounds-checked version provided by MSVC.
#define _INFIX_SAFE_STRNCPY(dest, src, count) strncpy_s(dest, sizeof(dest), src, count)
#else
// On other compilers, use standard strncpy and ensure null-termination.
#define _INFIX_SAFE_STRNCPY(dest, src, count) \
    do {                                      \
        strncpy(dest, src, (count));          \
        (dest)[(sizeof(dest)) - 1] = '\0';    \
    } while (0)
#endif

// The thread-local variable that stores the last error.
static INFIX_TLS infix_error_details_t g_infix_last_error = {INFIX_CATEGORY_NONE, INFIX_CODE_SUCCESS, 0, 0, {0}};
// A thread-local buffer to hold the original signature string for parser errors.
static INFIX_TLS const char * g_infix_last_signature_context = nullptr;

/**
 * @internal
 * @brief Maps an error code to its human-readable string representation.
 */
static const char * _get_error_message_for_code(infix_error_code_t code) {
    switch (code) {
    case INFIX_CODE_SUCCESS:
        return "Success";
    case INFIX_CODE_UNKNOWN:
        return "An unknown error occurred";
    case INFIX_CODE_OUT_OF_MEMORY:
        return "Out of memory";
    case INFIX_CODE_EXECUTABLE_MEMORY_FAILURE:
        return "Failed to allocate executable memory";
    case INFIX_CODE_PROTECTION_FAILURE:
        return "Failed to change memory protection flags";
    case INFIX_CODE_UNEXPECTED_TOKEN:
        return "Unexpected token or character";
    case INFIX_CODE_UNTERMINATED_AGGREGATE:
        return "Unterminated aggregate (missing '}', '>', ']', or ')')'";
    case INFIX_CODE_INVALID_KEYWORD:
        return "Invalid type keyword";
    case INFIX_CODE_MISSING_RETURN_TYPE:
        return "Function signature missing '->' or return type";
    case INFIX_CODE_INTEGER_OVERFLOW:
        return "Integer overflow detected during layout calculation";
    case INFIX_CODE_RECURSION_DEPTH_EXCEEDED:
        return "Type definition is too deeply nested";
    case INFIX_CODE_EMPTY_MEMBER_NAME:
        return "Named type was declared with empty angle brackets";
    case INFIX_CODE_UNSUPPORTED_ABI:
        return "The current platform ABI is not supported";
    case INFIX_CODE_TYPE_TOO_LARGE:
        return "A data type was too large to be handled by the ABI";
    case INFIX_CODE_UNRESOLVED_NAMED_TYPE:
        return "Named type not found in registry or is an undefined forward declaration";
    case INFIX_CODE_INVALID_MEMBER_TYPE:
        return "Aggregate contains an illegal member type (e.g., a struct with a void member)";
    case INFIX_CODE_LIBRARY_NOT_FOUND:
        return "The requested dynamic library could not be found";
    case INFIX_CODE_SYMBOL_NOT_FOUND:
        return "The requested symbol was not found in the library";
    case INFIX_CODE_LIBRARY_LOAD_FAILED:
        return "Loading the dynamic library failed";
    default:
        return "An unknown or unspecified error occurred";
    }
}

/**
 * @internal
 * @brief Sets the last error details for the current thread. If the error is from the
 * parser, it generates a rich, multi-line diagnostic message.
 */
void _infix_set_error(infix_error_category_t category, infix_error_code_t code, size_t position) {
    g_infix_last_error.category = category;
    g_infix_last_error.code = code;
    g_infix_last_error.position = position;
    g_infix_last_error.system_error_code = 0;

    if (category == INFIX_CATEGORY_PARSER && g_infix_last_signature_context != nullptr) {
        // Generate a rich, GCC-style error message for parser failures.
        const char * signature = g_infix_last_signature_context;
        size_t sig_len = strlen(signature);
        size_t radius = 20;

        size_t start = (position > radius) ? (position - radius) : 0;
        size_t end = (position + radius < sig_len) ? (position + radius) : sig_len;

        const char * start_indicator = (start > 0) ? "... " : "";
        const char * end_indicator = (end < sig_len) ? " ..." : "";
        size_t start_indicator_len = (start > 0) ? 4 : 0;

        char snippet[128];
        snprintf(snippet,
                 sizeof(snippet),
                 "%s%.*s%s",
                 start_indicator,
                 (int)(end - start),
                 signature + start,
                 end_indicator);

        char pointer[128];
        size_t caret_pos = position - start + start_indicator_len;
        snprintf(pointer, sizeof(pointer), "%*s^", (int)caret_pos, "");

        // Build the message piece by piece to avoid buffer overflows.
        char * p = g_infix_last_error.message;
        size_t remaining = sizeof(g_infix_last_error.message);
        int written;

        written = snprintf(p, remaining, "\n\n  %s\n  %s", snippet, pointer);
        if (written < 0 || (size_t)written >= remaining) {
            const char * msg = _get_error_message_for_code(code);
            _INFIX_SAFE_STRNCPY(g_infix_last_error.message, msg, sizeof(g_infix_last_error.message) - 1);
            return;
        }
        p += written;
        remaining -= written;

        written = snprintf(p, remaining, "\n\nError: %s", _get_error_message_for_code(code));
        // If this last part gets truncated, that's acceptable. snprintf will null-terminate.
    }
    else {
        // For non-parser errors, just copy the standard message.
        const char * msg = _get_error_message_for_code(code);
        _INFIX_SAFE_STRNCPY(g_infix_last_error.message, msg, sizeof(g_infix_last_error.message) - 1);
    }
}

/**
 * @internal
 * @brief Sets a detailed system error with a message.
 */
void _infix_set_system_error(infix_error_category_t category,
                             infix_error_code_t code,
                             long system_code,
                             const char * msg) {
    g_infix_last_error.category = category;
    g_infix_last_error.code = code;
    g_infix_last_error.position = 0;
    g_infix_last_error.system_error_code = system_code;
    if (msg) {
        _INFIX_SAFE_STRNCPY(g_infix_last_error.message, msg, sizeof(g_infix_last_error.message) - 1);
    }
    else {
        const char * default_msg = _get_error_message_for_code(code);
        _INFIX_SAFE_STRNCPY(g_infix_last_error.message, default_msg, sizeof(g_infix_last_error.message) - 1);
    }
}

/**
 * @internal
 * @brief Resets the error state for the current thread. Called at the start of a public API function.
 */
void _infix_clear_error(void) {
    g_infix_last_error.category = INFIX_CATEGORY_NONE;
    g_infix_last_error.code = INFIX_CODE_SUCCESS;
    g_infix_last_error.position = 0;
    g_infix_last_error.system_error_code = 0;
    g_infix_last_error.message[0] = '\0';
    g_infix_last_signature_context = nullptr;
}

/**
 * @brief Public API function to retrieve the last error.
 */
infix_error_details_t infix_get_last_error(void) {
    return g_infix_last_error;
}
