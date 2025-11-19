/**
 * @file Ch12_DirectMarshalling.c
 * @brief Cookbook Chapter 12: High-Performance Language Bindings
 *
 * This example demonstrates the "Direct Marshalling" (or "Bundle") API.
 * This is an advanced feature for writing language bindings (like for Python,
 * Lua, or Perl) where performance is critical.
 *
 * Instead of unboxing your language's objects into temporary C variables and
 * creating a `void* args[]` array for every call, you provide "Marshaller"
 * functions. The `infix` JIT compiler calls these functions *directly* to
 * fetch data from your objects just-in-time.
 *
 * Scenario:
 * We simulate a simple scripting language ("MockLang") and bind a C function
 * `move_point` that takes a struct pointer and modifies it. This demonstrates:
 * 1. Marshalling a complex object (Struct) from "Script" to C.
 * 2. Marshalling primitive values (Int) from "Script" to C.
 * 3. "Write-back": Updating the "Script" object after the C function modifies the struct.
 */

#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    double x, y;
} Point;

// A C function that modifies a point in place.
// Signature: (*{double,double}, int, int) -> void
void move_point_ref(Point * p, int dx, int dy) {
    printf("    [C] move_point_ref called.\n");
    printf("        Input:  {%.1f, %.1f}, dx=%d, dy=%d\n", p->x, p->y, dx, dy);
    p->x += dx;
    p->y += dy;
    printf("        Output: {%.1f, %.1f}\n", p->x, p->y);
}

// The "MockLang" Runtime Environment
typedef enum { MOCK_INT, MOCK_POINT } MockType;

// A generic object in our scripting language.
typedef struct {
    MockType type;
    union {
        int i;    // Integer storage
        struct {  // Point storage
            double x, y;
        } point;
    } data;
} MockObject;

MockObject * NewMockInt(int v) {
    MockObject * obj = malloc(sizeof(MockObject));
    obj->type = MOCK_INT;
    obj->data.i = v;
    return obj;
}

MockObject * NewMockPoint(double x, double y) {
    MockObject * obj = malloc(sizeof(MockObject));
    obj->type = MOCK_POINT;
    obj->data.point.x = x;
    obj->data.point.y = y;
    return obj;
}

// The Marshalling Logic (The Bridge)

/**
 * @brief Scalar Marshaller for Integer arguments.
 * Extracts the integer value from a MockObject.
 */
infix_direct_value_t marshal_mock_int(void * source_obj) {
    MockObject * obj = (MockObject *)source_obj;
    // In a real binding, you would check obj->type here and throw an error if mismatch.
    return (infix_direct_value_t){.i64 = obj->data.i};
}

/**
 * @brief Aggregate Marshaller for Point struct arguments.
 * Copies data from the MockObject into the temporary C buffer provided by the JIT.
 */
void marshal_mock_point(void * source_obj, void * dest_buffer, const infix_type * type) {
    MockObject * obj = (MockObject *)source_obj;
    Point * p = (Point *)dest_buffer;

    p->x = obj->data.point.x;
    p->y = obj->data.point.y;

    printf("    [JIT-Marshaller] Unboxed MockPoint {%.1f, %.1f} to C stack buffer.\n", p->x, p->y);
}

/**
 * @brief Write-back Handler for Point struct arguments.
 * Called after the C function returns. Copies data from the C buffer back to the MockObject.
 */
void writeback_mock_point(void * source_obj, void * c_data_ptr, const infix_type * type) {
    MockObject * obj = (MockObject *)source_obj;
    Point * p = (Point *)c_data_ptr;

    printf("    [JIT-Writeback]  Updating MockPoint with new values {%.1f, %.1f}.\n", p->x, p->y);

    // Propagate changes back to the script object.
    obj->data.point.x = p->x;
    obj->data.point.y = p->y;
}

// ============================================================
// 4. Main Application
// ============================================================

int main() {
    printf("Cookbook Chapter 12: Direct Marshalling\n\n");

    // 1. Create the "Script" objects.
    MockObject * p_obj = NewMockPoint(10.0, 20.0);
    MockObject * dx_obj = NewMockInt(5);
    MockObject * dy_obj = NewMockInt(-3);

    printf("Script State Before: Point is {%.1f, %.1f}\n\n", p_obj->data.point.x, p_obj->data.point.y);

    // 2. Define the handlers for the arguments.
    // Signature: move_point_ref(Point* p, int dx, int dy)
    infix_direct_arg_handler_t handlers[3] = {0};

    // Arg 0: Point* (Input/Output)
    // Since the C type is a pointer to a struct (`*{...}`), providing an `aggregate_marshaller`
    // tells `infix` to allocate temp stack space for the struct, call the marshaller to fill it,
    // and pass the *address* of that stack space to the function.
    handlers[0].aggregate_marshaller = marshal_mock_point;
    handlers[0].writeback_handler = writeback_mock_point;

    // Arg 1: int
    handlers[1].scalar_marshaller = marshal_mock_int;

    // Arg 2: int
    handlers[2].scalar_marshaller = marshal_mock_int;

    // 3. Generate the optimized trampoline.
    // Note: Registry is NULL here because we aren't using named types in the signature string,
    // though you certainly can combine them!
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create_direct(
        &trampoline, "(*{double,double}, int, int) -> void", (void *)move_point_ref, handlers, NULL);

    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create direct trampoline: %s\n", infix_get_last_error().message);
        return 1;
    }

    // 4. Prepare the array of raw object pointers (the "stack" of the script VM).
    void * script_stack[] = {p_obj, dx_obj, dy_obj};

    // 5. CALL!
    // Notice we don't pass `int` or `double` values. We pass the MockObject pointers directly.
    printf("Invoking JIT-compiled trampoline...\n");

    infix_direct_cif_func cif = infix_forward_get_direct_code(trampoline);
    cif(NULL, script_stack);  // Return buffer is NULL because return type is void.

    printf("\nScript State After:  Point is {%.1f, %.1f}\n", p_obj->data.point.x, p_obj->data.point.y);

    // Cleanup
    infix_forward_destroy(trampoline);
    free(p_obj);
    free(dx_obj);
    free(dy_obj);

    return 0;
}
