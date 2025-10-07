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
 * @file 007_introspection.c
 * @brief Tests for the type introspection and serialization APIs.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <ctype.h>
#include <infix/infix.h>
#include <string.h>

// Helper to remove all whitespace from a string for canonical comparison.
static void normalize_string(char * s) {
    if (!s)
        return;
    char * d = s;
    do {
        while (isspace((unsigned char)*s)) {
            s++;
        }
    } while ((*d++ = *s++));
}

static void test_print_roundtrip(const char * signature) {
    subtest(signature) {
        plan(1);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        infix_status status = infix_type_from_signature(&type, &arena, signature);

        if (status != INFIX_SUCCESS) {
            fail("Parsing failed, cannot test printing.");
            infix_arena_destroy(arena);
            return;
        }

        char buffer[1024];
        status = infix_type_print(buffer, sizeof(buffer), type, INFIX_DIALECT_SIGNATURE);
        if (status != INFIX_SUCCESS)
            fail("Printing failed.");
        else {
            char original_normalized[1024];
            char printed_normalized[1024];
            snprintf(original_normalized, sizeof(original_normalized), "%s", signature);
            snprintf(printed_normalized, sizeof(printed_normalized), "%s", buffer);

            normalize_string(original_normalized);
            normalize_string(printed_normalized);

            ok(strcmp(original_normalized, printed_normalized) == 0, "Printed string should match original signature");
            if (strcmp(original_normalized, printed_normalized) != 0) {
                diag("Original (normalized): %s", original_normalized);
                diag("Printed  (normalized): %s", printed_normalized);
            }
        }

        infix_arena_destroy(arena);
    }
}

TEST {
    plan(10);

    test_print_roundtrip("int");
    test_print_roundtrip("*[10:{int,float}]");
    test_print_roundtrip("<*void, double>");
    test_print_roundtrip("(*char;int,double)->void");
    test_print_roundtrip("{<int,char>, *char}");
    test_print_roundtrip("struct<Node>{int,*struct<Node>}");
    test_print_roundtrip("e:longlong");
    test_print_roundtrip("v[4:float]");
    test_print_roundtrip("struct<MyStruct>");
    test_print_roundtrip("union<MyUnion>");
}
