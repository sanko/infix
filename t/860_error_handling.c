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
 * @file 860_error_handling.c
 * @brief Unit tests for the detailed error reporting system.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <limits.h>
#include <stdio.h>   // For snprintf
#include <string.h>  // For strlen, strstr

TEST {
    plan(2);

    subtest("Signature Parser Error Reporting") {
        plan(15);

        infix_arena_t * arena = nullptr;
        infix_type * type = nullptr;
        infix_status status;

        // Test 1: Unexpected token in a function signature
        const char * sig1 = "(int, ^) -> void";
        infix_type * ret_type = nullptr;
        infix_function_argument * args = nullptr;
        size_t num_args, num_fixed;
        status = infix_signature_parse(sig1, &arena, &ret_type, &args, &num_args, &num_fixed, nullptr);
        infix_arena_destroy(arena);  // Must destroy even on failure
        arena = nullptr;

        ok(status != INFIX_SUCCESS, "Parser fails on unexpected token '^'");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_UNEXPECTED_TOKEN, "Error code is UNEXPECTED_TOKEN");
            ok(err.position == 6, "Error position is correct for '^'");
            ok(strstr(err.message, "Unexpected token or character") != NULL, "Error message is correct");
        }
        else
            skip(4, "Error detail tests skipped on unexpected success");

        // Test 2: Unterminated aggregate
        const char * sig2 = "{int, double";
        status = infix_type_from_signature(&type, &arena, sig2, nullptr);
        infix_arena_destroy(arena);
        arena = nullptr;
        ok(status != INFIX_SUCCESS, "Parser fails on unclosed aggregate");
        if (status != INFIX_SUCCESS) {
            infix_error_details_t err = infix_get_last_error();
            ok(err.category == INFIX_CATEGORY_PARSER, "Error category is PARSER");
            ok(err.code == INFIX_CODE_UNTERMINATED_AGGREGATE, "Error code is UNTERMINATED_AGGREGATE");
            ok(err.position > 0, "Error position is non-zero");  // Position can vary, just check it's set
            ok(strstr(err.message, "Unterminated aggregate") != NULL, "Error message is correct");
        }
        else
            skip(4, "Error detail tests skipped on unexpected success");

        // Test 3: Invalid keyword
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

        // Test an integer overflow when creating an array via the signature API
        char overflow_sig[128];
        // Create a signature like "[<SIZE_MAX/2 + 1>:short]" which should overflow
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
