/**
 * @file Ch09_ErrorReporting.c
 * @brief Cookbook Chapter 9: Advanced Error Reporting for the Parser
 *
 * This example demonstrates how to get detailed, thread-safe error information
 * when an `infix` API call fails. This is especially useful for providing rich
 * feedback to users when they provide an invalid signature string.
 *
 * After a parsing function fails, a call to `infix_get_last_error()` returns an
 * `infix_error_details_t` struct containing the error code, a human-readable
 * message, and the exact character position of the error in the source string.
 */
#include <infix/infix.h>
#include <stdio.h>

/**
 * @brief A helper function that attempts to parse a signature and reports
 *        detailed error information on failure.
 * @param signature The signature string to parse.
 */
static void report_parse_error(const char * signature) {
    infix_type * type = NULL;
    infix_arena_t * arena = NULL;

    printf("\nAttempting to parse signature:\n\"%s\"\n", signature);

    infix_status status = infix_type_from_signature(&type, &arena, signature, NULL);

    if (status != INFIX_SUCCESS) {
        // 1. Get the detailed error information for the current thread.
        infix_error_details_t err = infix_get_last_error();

        fprintf(stderr, "FAILURE: Parsing failed.\n");

        // 2. Print a helpful diagnostic, including a caret pointing to the error.
        fprintf(stderr, "  %s\n", signature);
        fprintf(stderr, "  %*s^\n", (int)err.position, "");  // Print spaces to align the caret
        fprintf(stderr, "Error Details:\n");
        fprintf(stderr, "  - Category: %d\n", err.category);
        fprintf(stderr, "  - Code: %d\n", err.code);
        fprintf(stderr, "  - Position: %zu\n", err.position);
        fprintf(stderr, "  - Message: %s\n", err.message);
    }
    else {
        printf("SUCCESS: Signature parsed correctly.\n");
    }

    // Clean up resources if parsing was successful.
    infix_arena_destroy(arena);
}

int main() {
    printf("Cookbook Chapter 9: Advanced Error Reporting\n");

    // Test Case 1: An invalid character '^' instead of a comma.
    report_parse_error("{int, double, ^*char}");

    // Test Case 2: An unterminated struct.
    report_parse_error("{int, double");

    // Test Case 3: A valid signature to show the success path.
    report_parse_error("{int, double, *char}");

    return 0;
}
