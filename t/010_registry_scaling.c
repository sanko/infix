/**
 * @file 010_registry_scaling.c
 * @brief Unit test for the registry's hash table auto-scaling (rehashing).
 * @ingroup test_suite
 *
 * @details This test verifies that the `infix_registry_t` correctly resizes its
 * internal hash table when the load factor threshold is exceeded.
 *
 * It tests:
 * 1.  **Data Integrity:** Ensuring no types are lost during the rehash process.
 * 2.  **Lookup Correctness:** Verifying `infix_registry_lookup_type` finds items
 *     in the new bucket locations.
 * 3.  **Iterator Stability:** Ensuring iteration visits all items after a resize.
 * 4.  **Cloning:** Verifying that cloning a large, resized registry works.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

TEST {
    plan(3);

    subtest("Incremental Growth & Rehash Consistency") {
        plan(3);
        infix_registry_t * reg = infix_registry_create();
        if (!reg)
            bail_out("Failed to create registry");

        // Initial size is 61 buckets.
        // Rehash trigger is > 0.75 load factor (~46 items).
        // We insert 200 items to force multiple generations of resizing (61 -> 123 -> 247).
        int count = 200;
        char buffer[64];

        // Insert items individually
        for (int i = 0; i < count; ++i) {
            snprintf(buffer, sizeof(buffer), "@Type%d = int;", i);
            if (infix_register_types(reg, buffer) != INFIX_SUCCESS)
                fail("Failed to register @Type%d", i);
        }

        pass("Registered %d types (forced multiple rehashes)", count);

        // Verify all items exist via lookup
        bool all_found = true;
        for (int i = 0; i < count; ++i) {
            snprintf(buffer, sizeof(buffer), "Type%d", i);
            // Check existence
            if (!infix_registry_is_defined(reg, buffer)) {
                diag("Failed to lookup %s after rehash", buffer);
                all_found = false;
                break;
            }
            // Verify data integrity (it should be a primitive int)
            const infix_type * t = infix_registry_lookup_type(reg, buffer);
            if (!t || t->category != INFIX_TYPE_PRIMITIVE) {
                diag("Type data corrupted for %s", buffer);
                all_found = false;
                break;
            }
        }
        ok(all_found, "All %d types found via lookup after rehashes", count);

        // Verify iterator counts match
        int iter_count = 0;
        infix_registry_iterator_t it = infix_registry_iterator_begin(reg);
        while (infix_registry_iterator_next(&it))
            iter_count++;
        ok(iter_count == count, "Iterator found exactly %d items (got %d)", count, iter_count);

        infix_registry_destroy(reg);
    }

    subtest("Bulk Stress Test") {
        plan(2);
        infix_registry_t * reg = infix_registry_create();

        // Create a massive definition string
        int count = 5000;
        size_t buf_size = count * 32;
        char * bulk_def = malloc(buf_size);
        if (!bulk_def)
            bail_out("OOM in test setup");

        char * p = bulk_def;
        for (int i = 0; i < count; ++i)
            p += sprintf(p, "@StressT%d=int;", i);

        // This single call will trigger the parser loop, which calls _registry_insert,
        // which triggers _registry_rehash multiple times.
        infix_status status = infix_register_types(reg, bulk_def);
        ok(status == INFIX_SUCCESS, "Batch registered %d types via single string", count);
        free(bulk_def);

        // Verify count
        int found_count = 0;
        infix_registry_iterator_t it = infix_registry_iterator_begin(reg);
        while (infix_registry_iterator_next(&it))
            found_count++;
        ok(found_count == count, "Iterator matches batch insertion count (%d)", count);

        infix_registry_destroy(reg);
    }

    subtest("Cloning Scaled Registry") {
        plan(4);
        infix_registry_t * src = infix_registry_create();

        // Fill src to force scaling
        int count = 500;
        char buffer[64];
        for (int i = 0; i < count; ++i) {
            snprintf(buffer, sizeof(buffer), "@CloneT%d=int;", i);
            if (infix_register_types(src, buffer) != INFIX_SUCCESS)
                fail("Failed to register @CloneT%d", i);
        }

        // Clone it. The clone operation creates a NEW registry (small size)
        // and inserts items one by one, forcing the NEW registry to scale up too.
        infix_registry_t * dest = infix_registry_clone(src);
        ok(dest != NULL, "Cloned large registry");

        // Verify dest content
        ok(infix_registry_is_defined(dest, "CloneT0"), "Dest has start element");
        ok(infix_registry_is_defined(dest, "CloneT499"), "Dest has end element");

        int dest_count = 0;
        infix_registry_iterator_t it = infix_registry_iterator_begin(dest);
        while (infix_registry_iterator_next(&it))
            dest_count++;

        ok(dest_count == count, "Dest registry has correct count (%d)", dest_count);

        infix_registry_destroy(src);
        infix_registry_destroy(dest);
    }
}
