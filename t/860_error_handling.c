/**
 * @file 860_error_handling.c
 * @brief Unit test for the error reporting system.
 * @ingroup test_suite
 *
 * @details This test file validates that the `infix` library correctly detects,
 * categorizes, and reports errors to the user. A robust error reporting system
 * is critical for a good developer experience.
 *
 * The test covers two main areas:
 *
 * 1.  **Signature Parser Error Reporting:**
 *     - It feeds the parser a series of deliberately malformed signature strings.
 *     - For each invalid signature, it calls `infix_get_last_error()` to retrieve
 *       the detailed error information.
 *     - It then asserts that the returned `infix_error_details_t` struct contains
 *       the correct `category`, `code`, `position` (the byte offset of the error
 *       in the string), and a human-readable `message`.
 *     - This ensures that users receive precise feedback when they make a syntax
 *       error in a signature.
 *
 * 2.  **API Hardening Error Reporting:**
 *     - It tests how the API handles inputs that are syntactically valid but would
 *       lead to dangerous behavior, specifically integer overflows.
 *     - It constructs a signature for an enormous array (e.g., `[SIZE_MAX:short]`)
 *       that would cause an overflow when calculating its total size.
 *     - It verifies that the library detects this condition, returns an
 *       `INFIX_ERROR_INVALID_ARGUMENT` status, and sets the last error code to
 *       `INFIX_CODE_INTEGER_OVERFLOW`. This confirms that security and stability
 *       checks are in place and are reported correctly.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
TEST {
    plan(2);
    subtest("Signature Parser Error Reporting") {
        plan(15);
        infix_arena_t * arena = nullptr;
        infix_type * type = nullptr;
        infix_status status;
        // Test Case 1: An unexpected token in a function signature.
        const char * sig1 = "(int, ^) -> void";
        infix_type * ret_type = nullptr;
        infix_function_argument * args = nullptr;
        size_t num_args, num_fixed;
        status = infix_signature_parse(sig1, &arena, &ret_type, &args, &num_args, &num_fixed, nullptr);
        infix_arena_destroy(arena);
        arena = nullptr;
        ok(status != INFIX_SUCCESS, "Parser fails on unexpected token '^'");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_UNEXPECTED_TOKEN, "Error code is UNEXPECTED_TOKEN");
            ok(err.position == 6, "Error position is correct for '^'");
            // The rich error message should contain the standard description.
            ok(strstr(err.message, "Unexpected token or character") != NULL, "Error message is correct");
        }
        else
            skip(4, "Error detail tests skipped on unexpected success");
        // Test Case 2: An unclosed aggregate (struct).
        const char * sig2 = "{int, double";
        status = infix_type_from_signature(&type, &arena, sig2, nullptr);
        infix_arena_destroy(arena);
        arena = nullptr;
        ok(status != INFIX_SUCCESS, "Parser fails on unclosed aggregate");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_UNTERMINATED_AGGREGATE, "Error code is UNTERMINATED_AGGREGATE");
            ok(err.position > 0, "Error position is non-zero");
            ok(strstr(err.message, "Unterminated aggregate") != NULL, "Error message is correct");
        }
        else
            skip(4, "Error detail tests skipped on unexpected success");
        // Test Case 3: An invalid type keyword.
        const char * sig3 = "integer";
        status = infix_type_from_signature(&type, &arena, sig3, nullptr);
        infix_arena_destroy(arena);
        arena = nullptr;
        ok(status != INFIX_SUCCESS, "Parser fails on invalid keyword");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_INVALID_KEYWORD, "Error code is INVALID_KEYWORD");
            ok(err.position == 0, "Error position is at start of string");
            ok(strstr(err.message, "Invalid type keyword") != NULL, "Error message is correct");
        }
        else
            skip(4, "Error detail tests skipped on unexpected success");
    }
    subtest("API Hardening Error Reporting") {
        plan(4);
        infix_arena_t * arena = nullptr;
        infix_type * type = nullptr;
        infix_status status;
        // Construct a signature for an array so large it will cause an integer overflow
        // when its total size is calculated (num_elements * sizeof(element)).
        char overflow_sig[128];
        snprintf(overflow_sig, sizeof(overflow_sig), "[%llu:short]", (unsigned long long)((SIZE_MAX / 2) + 1));
        status = infix_type_from_signature(&type, &arena, overflow_sig, nullptr);
        ok(status != INFIX_SUCCESS, "infix_type_from_signature fails on integer overflow");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_INTEGER_OVERFLOW, "Error code is INTEGER_OVERFLOW");
            ok(strlen(err.message) > 0 && strstr(err.message, "Integer overflow") != NULL, "Error message is correct");
        }
        else
            skip(3, "Error detail tests skipped on unexpected success");
        infix_arena_destroy(arena);
    }
}
