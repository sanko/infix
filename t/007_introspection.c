/**
 * @file 007_introspection.c
 * @brief Tests for the type introspection and serialization APIs.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <ctype.h>
#include <infix/infix.h>

// Helper to remove all whitespace from a string for canonical comparison.
static void normalize_string(char * s) {
    char * d = s;
    do {
        while (isspace(*s))
            s++;
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
            return;
        }

        char buffer[256];
        status = infix_type_print(buffer, sizeof(buffer), type, INFIX_DIALECT_SIGNATURE);
        if (status != INFIX_SUCCESS) {
            fail("Printing failed.");
        }
        else {
            char original_normalized[256];
            char printed_normalized[256];
            snprintf(original_normalized, sizeof(original_normalized), "%s", signature);
            snprintf(printed_normalized, sizeof(printed_normalized), "%s", buffer);

            normalize_string(original_normalized);
            normalize_string(printed_normalized);

            ok(strcmp(original_normalized, printed_normalized) == 0, "Printed string should match original signature");
            diag("Original: %s", original_normalized);
            diag("Printed:  %s", printed_normalized);
        }

        infix_arena_destroy(arena);
    }
}

TEST {
    plan(5);

    test_print_roundtrip("int");
    test_print_roundtrip("*[10:{int,float}]");
    test_print_roundtrip("<*void, double>");
    test_print_roundtrip("(*char;int,double)->void");
    test_print_roundtrip("{<int,char>, *char}");
}
