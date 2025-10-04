/**
 * @file 006_end_to_end_calls.c
 * @brief End-to-end integration tests for the entire FFI call process.
 * @details This is the first test suite to verify the entire pipeline:
 *          Signature Parser -> Type System -> ABI Classifier -> JIT Generator -> Call Execution.
 *          It focuses on aggregate types (structs, unions) which have the most
 *          complex ABI rules.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"  // For Point struct
#include <infix/infix.h>
#include <math.h>  // For fabs

// These are the native C functions we will call via the FFI.

/** @brief A simple function that takes and returns a small struct by value. */
Point move_point(Point p, double dx, double dy) {
    Point result = {p.x + dx, p.y + dy};
    note("Native C move_point called: (%f, %f) + (%f, %f) -> (%f, %f)", p.x, p.y, dx, dy, result.x, result.y);
    return result;
}

TEST {
    plan(2);  // Plan for forward and reverse call tests.

    subtest("Forward calls with aggregate types (structs)") {
        plan(1);

        subtest("Passing and returning a small struct by value") {
            plan(3);

            // 1. Define the signature for: Point move_point(Point, double, double)
            const char * signature = "({double, double}, double, double) -> {double, double}";

            // 2. Create the trampoline.
            infix_forward_t * trampoline = NULL;
            infix_status status = infix_forward_create(&trampoline, signature);
            ok(status == INFIX_SUCCESS, "Successfully created trampoline for struct by value");

            if (status == INFIX_SUCCESS) {
                // 3. Prepare arguments and return buffer.
                Point start_point = {10.0, 20.0};
                double offset_x = 5.5;
                double offset_y = -2.5;
                Point end_point = {0.0, 0.0};  // Buffer for the return value.

                void * args[] = {&start_point, &offset_x, &offset_y};

                // 4. Get the CIF function and execute the call.
                infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
                cif((void *)move_point, &end_point, args);

                // 5. Verify the results. Use a tolerance for floating point comparison.
                ok(fabs(end_point.x - 15.5) < 1e-9, "Resulting point.x is correct (got %f)", end_point.x);
                ok(fabs(end_point.y - 17.5) < 1e-9, "Resulting point.y is correct (got %f)", end_point.y);
            }
            else
                skip(2, "Skipping call checks due to trampoline creation failure.");

            infix_forward_destroy(trampoline);
        }
    }

    subtest("Reverse calls (callbacks) with aggregate types") {
        plan(1);
        skip(1, "TODO: Implement reverse call tests with structs.");
    }
}
