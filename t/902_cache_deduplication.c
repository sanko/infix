/**
 * @file 902_cache_deduplication.c
 * @brief Unit test for the trampoline deduplication (caching) system.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>

void target_fn_1() {}
void target_fn_2() {}

TEST {
    plan(1);

    subtest("Forward Trampoline Deduplication") {
        plan(6);

        infix_forward_t * t1 = nullptr;
        infix_forward_t * t2 = nullptr;
        infix_forward_t * t3 = nullptr;
        infix_forward_t * t4 = nullptr;

        // Create a trampoline
        infix_status s1 = infix_forward_create(&t1, "() -> void", (void *)target_fn_1, nullptr);
        ok(s1 == INFIX_SUCCESS, "First trampoline created");

        // Create the same trampoline again
        infix_status s2 = infix_forward_create(&t2, " () -> void ", (void *)target_fn_1, nullptr);
        ok(s2 == INFIX_SUCCESS, "Second trampoline created");
        ok(t1 == t2, "Deduplication: t1 and t2 point to the same object");

        // Create a trampoline with a different target
        infix_status s3 = infix_forward_create(&t3, "() -> void", (void *)target_fn_2, nullptr);
        ok(s3 == INFIX_SUCCESS, "Third trampoline (diff target) created");
        ok(t1 != t3, "t1 and t3 are different");

        // Create a trampoline with a different signature
        infix_status s4 = infix_forward_create(&t4, "(int) -> void", (void *)target_fn_1, nullptr);
        ok(s4 == INFIX_SUCCESS, "Fourth trampoline (diff sig) created");

        infix_forward_destroy(t1);
        infix_forward_destroy(t2);
        infix_forward_destroy(t3);
        infix_forward_destroy(t4);
    }
}
