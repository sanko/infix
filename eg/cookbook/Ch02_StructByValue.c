/**
 * @file Ch02_StructByValue.c
 * @brief Cookbook Chapter 2: Small Structs Passed by Value
 *
 * This example demonstrates calling a function that takes a small `struct`
 * argument. For most ABIs, a small struct like this will be passed directly
 * in CPU registers rather than on the stack. `infix` automatically handles
 * this ABI-specific detail.
 */
#include <infix/infix.h>
#include <stdio.h>

// A common C struct used in this chapter's examples
typedef struct {
    double x, y;
} Point;

// The native C function to be called.
// It takes a Point struct by value and returns a modified copy.
static Point move_point(Point p, double dx) {
    p.x += dx;
    return p;
}

int main() {
    printf("Cookbook Chapter 2: Small Structs Passed by Value\n");

    // 1. Describe the signature: Point move_point(Point p, double dx);
    //    The struct is described inline with its member types.
    const char * signature = "({double, double}, double) -> {double, double}";

    // 2. Create the trampoline.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create(&trampoline, signature, (void *)move_point, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 3. Prepare arguments and call.
    Point start = {10.0, 20.0};
    double delta_x = 5.5;
    void * args[] = {&start, &delta_x};
    Point end;

    cif(&end, args);

    printf("Calling move_point({10.0, 20.0}, 5.5)...\n");
    printf("Result: { x=%.1f, y=%.1f } (Expected: {15.5, 20.0})\n", end.x, end.y);

    // 4. Clean up.
    infix_forward_destroy(trampoline);

    return 0;
}
