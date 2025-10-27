/**
 * @file 810_memory_stress.c
 * @brief A stress test to detect memory leaks under heavy allocation/deallocation cycles.
 * @ingroup test_suite
 *
 * @details This test is not designed to check functional correctness, but rather to
 * ensure the library's memory management is sound. It runs a tight loop that
 * performs a large number of create/destroy cycles for complex forward and reverse
 * trampolines.
 *
 * In each iteration, it:
 * 1. Creates a new arena.
 * 2. Programmatically builds a complex `infix_type` representing a nested struct
 *    with arrays.
 * 3. Creates a forward trampoline using this type.
 * 4. Destroys the forward trampoline.
 * 5. Creates a reverse trampoline using the same type.
 * 6. Destroys the reverse trampoline.
 * 7. Destroys the arena.
 *
 * The test itself only asserts that it completes. Its true purpose is to be run
 * under a memory analysis tool like Valgrind or AddressSanitizer (ASan). A "pass"
 * for this test is a clean report from the memory tool, indicating that no memory
 * was leaked across the thousands of iterations. This is crucial for ensuring the
 * long-term stability of applications that frequently create and destroy trampolines.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <stddef.h>

#define STRESS_ITERATIONS 5000

typedef struct {
    uint64_t object_id;
    Point elements[10];
} StressObject;

void dummy_stress_func_fwd(StressObject obj) { (void)obj; }
void dummy_stress_handler_rev(StressObject obj) { (void)obj; }

TEST {
    plan(1);

    subtest("Memory leak stress test (happy path)") {
        plan(STRESS_ITERATIONS);
        note("Running %d create/destroy cycles. Success requires a clean Valgrind/ASan report.", STRESS_ITERATIONS);

        for (int i = 0; i < STRESS_ITERATIONS; ++i) {

            infix_arena_t * arena = infix_arena_create(8192);
            if (!arena)
                bail_out("Failed to create arena in iteration %d", i);

            infix_struct_member * point_members =
                infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
            point_members[0] =
                infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
            point_members[1] =
                infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
            infix_type * point_type = nullptr;
            if (infix_type_create_struct(arena, &point_type, point_members, 2) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create point_type");
            }

            infix_type * array_type = nullptr;
            if (infix_type_create_array(arena, &array_type, point_type, 10) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create array_type");
            }

            infix_struct_member * object_members =
                infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
            object_members[0] = infix_type_create_member(
                "object_id", infix_type_create_primitive(INFIX_PRIMITIVE_UINT64), offsetof(StressObject, object_id));
            object_members[1] = infix_type_create_member("elements", array_type, offsetof(StressObject, elements));
            infix_type * object_type = nullptr;
            if (infix_type_create_struct(arena, &object_type, object_members, 2) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to create object_type");
            }

            infix_forward_t * forward_trampoline = nullptr;
            if (infix_forward_create_unbound_manual(
                    &forward_trampoline, infix_type_create_void(), &object_type, 1, 1) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to generate forward trampoline");
            }
            infix_forward_destroy(forward_trampoline);

            infix_reverse_t * reverse_trampoline = nullptr;
            if (infix_reverse_create_callback_manual(&reverse_trampoline,
                                                     infix_type_create_void(),
                                                     &object_type,
                                                     1,
                                                     1,
                                                     (void *)dummy_stress_handler_rev) != INFIX_SUCCESS) {
                infix_arena_destroy(arena);
                bail_out("Failed to generate reverse trampoline");
            }
            infix_reverse_destroy(reverse_trampoline);

            infix_arena_destroy(arena);

            pass("Iteration %d completed", i + 1);
        }
    }
}
