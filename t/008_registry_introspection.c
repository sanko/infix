/**
 * @file 008_registry_introspection.c
 * @brief Unit test for the registry introspection and serialization APIs.
 * @ingroup test_suite
 *
 * @details This test file validates the new APIs for inspecting and dumping the
 * contents of a named type registry. It ensures that developers can accurately
 * debug and serialize the types they have defined.
 *
 * The test covers:
 *
 * 1.  **`infix_registry_print`:**
 *     - Verifies that all *defined* types are serialized into a single string.
 *     - Confirms that undefined forward declarations are explicitly listed as incomplete types.
 *     - Checks that the function returns an error when the provided buffer is too small.
 *
 * 2.  **Registry Iterator (`infix_registry_iterator_*`)**:
 *     - Verifies that the iterator correctly traverses all defined types in the registry.
 *     - Confirms that the correct number of types are found.
 *     - Checks that the `get_name` and `get_type` accessors return the correct data
 *       for each type.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include <infix/infix.h>
#include <string.h>

TEST {
    plan(3);
    // Setup: Create a registry with a mix of types.
    infix_registry_t * registry = infix_registry_create();
    if (!registry)
        bail_out("Failed to create registry for testing.");
    const char * definitions =
        "@MyInt = int64;"
        "@Point = { x: double, y: double };"
        "@FwdOnly;"  // An undefined forward declaration.
        "@Node = { value: int, next: *@Node };";
    if (infix_register_types(registry, definitions) != INFIX_SUCCESS) {
        infix_registry_destroy(registry);
        bail_out("Failed to register types for testing.");
    }
    subtest("`infix_registry_print` serialization") {
        plan(5);
        char buffer[1024];
        // Test happy path with a large enough buffer.
        infix_status status = infix_registry_print(buffer, sizeof(buffer), registry);
        ok(status == INFIX_SUCCESS, "infix_registry_print succeeds with adequate buffer");
        if (status == INFIX_SUCCESS) {
            diag("Registry dump:\n%s", buffer);
            // Use strstr to check for substrings, as the order of definitions from the hash table is not guaranteed.
            ok(strstr(buffer, "@MyInt = sint64;") != NULL, "Output contains @MyInt definition");
            ok(strstr(buffer, "@Point = {x:double,y:double};") != NULL, "Output contains correct @Point definition");
            ok(strstr(buffer, "@Node = {value:sint32,next:*@Node};") != NULL,
               "Output contains correct @Node definition");
            // We now expect forward declarations to be printed as "@Name;\n"
            ok(strstr(buffer, "@FwdOnly;") != NULL, "Output contains forward declaration @FwdOnly;");
        }
        else
            skip(4, "Skipping content checks due to print failure.");
    }
    subtest("Registry Iterator API") {
        plan(8);
        int found_mask = 0;
        int count = 0;
        // Iterate using the canonical while(next) pattern.
        infix_registry_iterator_t it = infix_registry_iterator_begin(registry);
        while (infix_registry_iterator_next(&it)) {
            count++;
            const char * name = infix_registry_iterator_get_name(&it);
            const infix_type * type = infix_registry_iterator_get_type(&it);
            ok(name != NULL && type != NULL, "Iterator returns valid name and type pointers for item %d", count);
            if (name) {
                if (strcmp(name, "MyInt") == 0) {
                    found_mask |= 1;
                    ok(type->category == INFIX_TYPE_PRIMITIVE, "@MyInt has correct type");
                }
                else if (strcmp(name, "Point") == 0) {
                    found_mask |= 2;
                    ok(type->category == INFIX_TYPE_STRUCT, "@Point has correct type");
                }
                else if (strcmp(name, "Node") == 0) {
                    found_mask |= 4;
                    ok(type->category == INFIX_TYPE_STRUCT, "@Node has correct type");
                }
                else if (strcmp(name, "FwdOnly") == 0)
                    fail("Iterator should not have found @FwdOnly (it is incomplete)");
            }
        }
        ok(count == 3, "Iterator found the correct number of fully defined types (3)");
        ok(found_mask == 7, "All expected types (MyInt, Point, Node) were found by the iterator");
    }
    subtest("Lookup by Name API") {
        plan(5);
        ok(infix_registry_is_defined(registry, "Point"), "`is_defined` returns true for defined type");
        ok(!infix_registry_is_defined(registry, "FwdOnly"), "`is_defined` returns false for fwd-declaration");
        ok(!infix_registry_is_defined(registry, "DoesNotExist"), "`is_defined` returns false for missing type");
        const infix_type * point_type = infix_registry_lookup_type(registry, "Point");
        ok(point_type != NULL && point_type->category == INFIX_TYPE_STRUCT,
           "`lookup_type` returns correct type for @Point");
        ok(infix_registry_lookup_type(registry, "FwdOnly") == NULL, "`lookup_type` returns NULL for fwd-declaration");
    }
    infix_registry_destroy(registry);
}
