/**
 * @file Ch08_Rec04_SharedArena.c
 * @brief An example demonstrating the "shared arena" memory optimization.
 *
 * @details This file illustrates an advanced memory management technique in `infix`.
 * It shows how to create a type registry (`infix_registry_create_in_arena`) and
 * multiple trampolines (`infix_forward_create_in_arena`) within a single,
 * user-provided memory arena.
 *
 * This approach enables trampolines to share pointers to named type definitions
 * rather than creating deep copies, which reduces memory consumption and can
 * improve performance when creating many trampolines with the same signatures.
 * The example also includes a control case to contrast this with the default
 * deep-copying behavior.
 */

#include <infix/infix.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

// Dummy C types and functions to interact with

typedef struct {
    double x;
    double y;
} Point;

typedef struct {
    uint64_t id;
    const char * name;
} User;

void handle_point(const Point * p) {
    if (p)
        printf("C handler 'handle_point' called with Point { x=%.1f, y=%.1f }\n", p->x, p->y);
    else
        printf("C handler 'handle_point' called with NULL pointer.\n");
}

void handle_user(const User * u) {
    if (u)
        printf("C handler 'handle_user' called with User { id=%" PRIu64 ", name=\"%s\" }\n", u->id, u->name);
    else
        printf("C handler 'handle_user' called with NULL pointer.\n");
}

int main(void) {
    printf("--- Shared Arena Optimization Example ---\n\n");

    // 1. Create a single, long-lived arena to hold all FFI metadata.
    infix_arena_t * shared_arena = infix_arena_create(65536);
    if (!shared_arena) {
        fprintf(stderr, "Error: Failed to create shared arena.\n");
        return 1;
    }
    printf("Step 1: Created a single shared arena at %p.\n", (void *)shared_arena);

    // 2. Create the type registry *within* the shared arena.
    infix_registry_t * registry = infix_registry_create_in_arena(shared_arena);
    if (!registry) {
        fprintf(stderr, "Error: Failed to create registry in shared arena.\n");
        infix_arena_destroy(shared_arena);
        return 1;
    }
    printf("Step 2: Created a type registry that uses the shared arena.\n");

    const char * my_types =
        "@Point = { x: double, y: double };"
        "@User  = { id: uint64, name: *char };";

    if (infix_register_types(registry, my_types) != INFIX_SUCCESS) {
        fprintf(stderr, "Error: Failed to register types.\n");
        infix_registry_destroy(registry);
        infix_arena_destroy(shared_arena);
        return 1;
    }
    printf("Step 3: Registered @Point and @User types into the registry.\n");

    // 4. Create multiple trampolines, also telling them to use the shared arena.
    infix_forward_t *t_point = NULL, *t_user = NULL;

    if (infix_forward_create_in_arena(&t_point, shared_arena, "(*@Point)->void", (void *)handle_point, registry) !=
        INFIX_SUCCESS) {
        fprintf(stderr, "Error: Failed to create point trampoline.\n");
        infix_registry_destroy(registry);
        infix_arena_destroy(shared_arena);
        return 1;
    }

    if (infix_forward_create_in_arena(&t_user, shared_arena, "(*@User)->void", (void *)handle_user, registry) !=
        INFIX_SUCCESS) {
        fprintf(stderr, "Error: Failed to create user trampoline.\n");
        infix_forward_destroy(t_point);
        infix_registry_destroy(registry);
        infix_arena_destroy(shared_arena);
        return 1;
    }
    printf("Step 4: Created two trampolines that share the arena's memory.\n");

    // 5. Use the trampolines as usual.
    printf("\nStep 5: Calling the trampolines...\n");
    Point p = {10.5, -20.0};
    User u = {12345, "Sanko"};

    // For a pointer argument (like Point*), you need a pointer to that pointer.
    Point * p_ptr = &p;
    void * point_args[] = {&p_ptr};

    User * u_ptr = &u;
    void * user_args[] = {&u_ptr};

    infix_cif_func cif_point = infix_forward_get_code(t_point);
    cif_point(NULL, point_args);

    infix_cif_func cif_user = infix_forward_get_code(t_user);
    cif_user(NULL, user_args);

    // 6. The user is responsible for the lifetime of all objects.
    printf("\nStep 6: Cleaning up...\n");
    infix_forward_destroy(t_point);
    infix_forward_destroy(t_user);
    infix_registry_destroy(registry);
    infix_arena_destroy(shared_arena);
    printf("Cleanup complete.\n\n");

    return 0;
}
