/**
 * @file Ch05_SemanticStrings.c
 * @brief Cookbook Chapter 5: Handling Strings and Semantic Types
 *
 * This example demonstrates the recommended pattern for handling types like strings
 * (`char*`, `wchar_t*`) in a way that is robust for introspection.
 *
 * The core idea is to use the `infix` Type Registry to create "semantic aliases"
 * that describe the *intent* of a type, not just its structure. A language binding
 * can then inspect the name of the type to determine how to correctly marshal data.
 */
#include <infix/infix.h>
#include <stdio.h>
#include <string.h>

// A conceptual function demonstrating how a language binding would introspect.
void introspect_and_print(const char * signature, infix_registry_t * registry) {
    infix_arena_t * arena = NULL;
    infix_type * ret_type = NULL;
    infix_function_argument * args = NULL;
    size_t num_args = 0, num_fixed = 0;

    // 1. Parse the function signature to get its components.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed, registry);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Introspection failed: Could not parse signature.\n");
        return;
    }

    printf("\nIntrospecting signature: '%s'\n", signature);
    for (size_t i = 0; i < num_args; ++i) {
        const infix_type * arg_type = args[i].type;
        printf("  - Arg %zu: ", i);

        // 2. Get the semantic name of the type using the new API.
        const char * type_name = infix_type_get_name(arg_type);

        if (type_name != NULL) {
            printf("is a semantic type named '@%s'. ", type_name);

            // 3. Check for our semantic string names.
            if (strcmp(type_name, "UTF16String") == 0)
                printf("Action: Marshal as UTF-16 string.\n");
            else if (strcmp(type_name, "UTF8String") == 0)
                printf("Action: Marshal as UTF-8 string.\n");
            else
                printf("Action: Handle as a regular named type.\n");
        }
        else {
            // It's a regular, anonymous type.
            char buffer[64];
            if (infix_type_print(buffer, sizeof(buffer), arg_type, INFIX_DIALECT_SIGNATURE) == INFIX_SUCCESS)
                printf("is a standard anonymous type '%s'.\n", buffer);
            else
                printf("is a standard anonymous type (print failed).\n");
        }
    }

    infix_arena_destroy(arena);
}

int main() {
    printf("--- Cookbook Chapter 5: Handling Semantic String Types ---\n");

    // 1. Define semantic aliases in a registry.
    infix_registry_t * registry = infix_registry_create();
    const char * type_defs =
        "@HWND = *void;"
        // Note: The old struct wrapper pattern is no longer needed.
        // Direct aliases now preserve their names.
        "@UTF16String = *uint16;"  // Represents wchar_t* on Windows
        "@UTF8String = *char;";    // Represents const char*
    if (infix_register_types(registry, type_defs) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to register types.\n");
        infix_registry_destroy(registry);
        return 1;
    }

    // 2. Define function signatures using these aliases.
    const char * sig1 = "(@HWND, @UTF8String) -> void";
    const char * sig2 = "(@UTF16String, @UTF16String) -> int";

    // 3. Run the conceptual introspection.
    introspect_and_print(sig1, registry);
    introspect_and_print(sig2, registry);

    // 4. Clean up.
    infix_registry_destroy(registry);

    return 0;
}
