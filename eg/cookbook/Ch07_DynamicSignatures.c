/**
 * @file Ch07_DynamicSignatures.c
 * @brief Cookbook Chapter 7: Building a Signature String at Runtime
 *
 * This example shows that since `infix` signatures are just strings, they can be
 * constructed dynamically at runtime. This is a powerful feature for dynamic
 * languages or systems where the structure of data is not known until runtime
 * (e.g., it's defined in a configuration file or a user script).
 *
 * The dynamically generated signature can then be parsed to get layout
 * information, which is perfect for data marshalling or dynamic RPC systems.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Cookbook Chapter 7: Building a Signature String at Runtime\n");

    // Imagine this data comes from a config file or a user script.
    const char * user_defined_fields[] = {"int", "int", "double"};
    int num_fields = 3;

    char signature_buffer[256] = "{";
    size_t current_len = 1;

    // 1. Build the signature string dynamically using standard string functions.
    printf("Dynamically building signature from field list...\n");
    for (int i = 0; i < num_fields; ++i) {
        // Append the type name.
        strncat(signature_buffer, user_defined_fields[i], sizeof(signature_buffer) - current_len - 1);
        current_len += strlen(user_defined_fields[i]);

        // Append a comma if it's not the last member.
        if (i < num_fields - 1) {
            strncat(signature_buffer, ",", sizeof(signature_buffer) - current_len - 1);
            current_len++;
        }
    }
    strncat(signature_buffer, "}", sizeof(signature_buffer) - current_len - 1);

    printf("Dynamically generated signature: %s\n", signature_buffer);

    // 2. Use the dynamic signature to get layout information.
    infix_type * dynamic_type = NULL;
    infix_arena_t * arena = NULL;
    infix_status status = infix_type_from_signature(&dynamic_type, &arena, signature_buffer, NULL);

    if (status == INFIX_SUCCESS && dynamic_type) {
        printf("Successfully parsed dynamic signature.\n");
        printf("  - Calculated size: %zu bytes\n", infix_type_get_size(dynamic_type));
        printf("  - Calculated alignment: %zu bytes\n", infix_type_get_alignment(dynamic_type));
    }
    else {
        fprintf(stderr, "Failed to parse the dynamically generated signature.\n");
    }

    infix_arena_destroy(arena);

    return 0;
}
