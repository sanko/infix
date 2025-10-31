/**
 * @file Ch02_Rec02_ReturnStruct.c
 * @brief Cookbook Chapter 2, Recipe 2: Receiving a Struct from a Function
 *
 * This example demonstrates calling a function that returns a struct by value.
 * `infix` handles the ABI-specific details of how the struct is returned,
 * whether it's in one or more registers or via a hidden pointer passed by the
 * caller.
 */
#include <infix/infix.h>
#include <stdio.h>

// A common C struct used in this chapter's examples
typedef struct {
    double x, y;
} Point;

// The native C function to be called. It constructs and returns a Point.
static Point make_point(double x, double y) { return (Point){x, y}; }

int main() {
    printf("--- Cookbook Chapter 2, Recipe 2: Receiving a Struct from a Function ---\n");

    // 1. Describe the signature: Point make_point(double x, double y);
    const char * signature = "(double, double) -> {double, double}";

    // 2. Create the trampoline.
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create(&trampoline, signature, (void *)make_point, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(trampoline);

    // 3. Prepare arguments and a buffer for the returned struct.
    double x = 100.0, y = 200.0;
    void * args[] = {&x, &y};
    Point result;

    // 4. Call the function.
    cif(&result, args);

    printf("Calling make_point(100.0, 200.0)...\n");
    printf("Received point: { x=%.1f, y=%.1f } (Expected: {100.0, 200.0})\n", result.x, result.y);

    // 5. Clean up.
    infix_forward_destroy(trampoline);

    return 0;
}
