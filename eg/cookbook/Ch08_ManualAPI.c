/**
 * @file Ch08_ManualAPI.c
 * @brief Cookbook Chapter 8: The Full Manual API Lifecycle
 *
 * This example demonstrates how to create a trampoline without using the signature
 * parser. This is the "Manual API" and is ideal for performance-critical
 * applications or language bindings that construct type information programmatically.
 *
 * The process involves:
 * 1. Creating a memory arena.
 * 2. Building `infix_type` objects for all required types (structs, primitives)
 *    by allocating them from the arena.
 * 3. Calling `infix_forward_create_manual` with the constructed types.
 * 4. Destroying the arena and trampoline when done.
 */
#include <infix/infix.h>
#include <stddef.h>  // For offsetof
#include <stdio.h>

// The C types and function we want to call
typedef struct {
    double x, y;
} Point;
Point move_point(Point p, double dx) {
    p.x += dx;
    return p;
}

int main() {
    printf("Cookbook Chapter 8: The Full Manual API Lifecycle\n");

    // 1. Create an arena to hold all our type definitions.
    infix_arena_t * arena = infix_arena_create(4096);
    if (!arena) {
        fprintf(stderr, "Failed to create arena.\n");
        return 1;
    }

    // 2. Manually define the 'Point' struct type.
    //    We use the C `offsetof` macro to get the correct member offsets.
    infix_struct_member point_members[] = {
        infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x)),
        infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y))};
    infix_type * point_type = NULL;
    (void)infix_type_create_struct(arena, &point_type, point_members, 2);
    printf("Manually created 'Point' type description.\n");

    // 3. Define the argument types for the function `Point move_point(Point, double)`.
    infix_type * arg_types[] = {point_type, infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE)};
    printf("Prepared argument type array.\n");

    // 4. Create the trampoline using the manually constructed types.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create_manual(&trampoline, point_type, arg_types, 2, 2, (void *)move_point);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline via manual API.\n");
        infix_arena_destroy(arena);
        return 1;
    }
    printf("Trampoline created successfully via manual API.\n");

    // 5. Call the function as usual.
    Point start = {10.0, 20.0};
    double delta_x = 5.5;
    void * args[] = {&start, &delta_x};
    Point end;

    infix_forward_get_code(trampoline)(&end, args);
    printf("Manual API call result: Moved point has x = %.1f (Expected: 15.5)\n", end.x);

    // 6. Clean up.
    infix_forward_destroy(trampoline);
    infix_arena_destroy(arena);  // Frees the 'point_type' as well.

    return 0;
}
