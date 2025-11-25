/**
 * @file Ch07_Rec01_SemanticAliases.c
 * @brief Cookbook Chapter 7: Creating and Introspecting Semantic Aliases
 *
 * This example demonstrates the powerful pattern of using the type registry to create
 * "semantic aliases". These are names for types that may be structurally identical
 * (e.g., multiple kinds of `void*` handles) but need to be treated differently by
 * a language binding or wrapper.
 *
 * The `infix_type_get_name()` API is the key to this pattern. It allows you to
 * retrieve the alias name from a type object, giving your code the semantic context
 * it needs to perform correct marshalling or type-checking.
 */

#include <infix/infix.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief A helper function to introspect a type defined by a signature string.
 *
 * This function simulates what a language binding would do: it parses a type,
 * then checks both its underlying structural properties (category, size) and its
 * semantic name.
 */
bool introspect_alias(const char * signature,
                      infix_registry_t * registry,
                      const char * expected_name,
                      infix_type_category expected_category,
                      size_t expected_size) {
    printf("\nIntrospecting '%s'\n", signature);

    infix_type * type = NULL;
    infix_arena_t * arena = NULL;
    bool success = true;

    // 1. Parse the signature. This resolves the alias using the registry.
    infix_status status = infix_type_from_signature(&type, &arena, signature, registry);

    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "  [FAIL] Signature failed to parse.\n");
        return false;
    }
    printf("  [PASS] Signature parsed successfully.\n");

    // 2. Introspect the structural properties.
    if (infix_type_get_category(type) == expected_category)
        printf("  [PASS] Category is correct.\n");
    else {
        fprintf(stderr, "  [FAIL] Category is incorrect.\n");
        success = false;
    }

    if (infix_type_get_size(type) == expected_size)
        printf("  [PASS] Size is correct.\n");
    else {
        fprintf(stderr, "  [FAIL] Size is incorrect.\n");
        success = false;
    }

    // 3. Introspect the semantic name using the new API.
    const char * name = infix_type_get_name(type);
    if (name && strcmp(name, expected_name) == 0)
        printf("  [PASS] Semantic name '%s' is preserved.\n", name);
    else {
        fprintf(stderr, "  [FAIL] Semantic name is incorrect or missing. Got: %s\n", name ? name : "NULL");
        success = false;
    }

    infix_arena_destroy(arena);
    return success;
}

int main() {
    printf("Cookbook Chapter 7: Creating and Introspecting Semantic Aliases\n");

    // 1. Define several kinds of aliases in a registry.
    infix_registry_t * registry = infix_registry_create();
    const char * type_defs =
        "@UserID = uint64;"           // Alias for a primitive
        "@DatabaseHandle = *void;"    // Alias for a pointer (opaque handle)
        "@Point = {double, double};"  // A standard named struct
        "@Vector = @Point;";          // An alias for another named type

    if (infix_register_types(registry, type_defs) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to register semantic aliases.\n");
        infix_registry_destroy(registry);
        return 1;
    }
    printf("Successfully registered semantic aliases.\n");

    // 2. Run introspection tests on each alias.
    bool all_ok = true;
    all_ok &= introspect_alias("@UserID", registry, "UserID", INFIX_TYPE_PRIMITIVE, sizeof(uint64_t));
    all_ok &= introspect_alias("@DatabaseHandle", registry, "DatabaseHandle", INFIX_TYPE_POINTER, sizeof(void *));
    all_ok &= introspect_alias("@Vector", registry, "Vector", INFIX_TYPE_STRUCT, sizeof(double) * 2);

    infix_registry_destroy(registry);

    if (all_ok) {
        printf("\nAll introspection checks passed!\n");
        return 0;
    }
    else {
        printf("\nOne or more introspection checks failed.\n");
        return 1;
    }
}
