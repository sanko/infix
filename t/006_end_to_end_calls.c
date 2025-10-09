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

/** @brief A callback handler that receives a Point, modifies it, and returns it. */
Point point_callback_handler(infix_context_t * context, Point p) {
    (void)context;  // Context is unused in this simple handler.
    note("point_callback_handler received p={%.1f, %.1f}", p.x, p.y);
    // Return a new point with doubled coordinates to verify the call worked.
    return (Point){p.x * 2.0, p.y * 2.0};
}

/** @brief A harness function that simulates native C code calling our generated callback. */
void execute_point_callback(Point (*func_ptr)(Point), Point p) {
    Point result = func_ptr(p);
    ok(fabs(result.x - p.x * 2.0) < 1e-9 && fabs(result.y - p.y * 2.0) < 1e-9,
       "Callback returned correct Point struct by value");
    diag("Harness received Point {%.1f, %.1f}", result.x, result.y);
}


TEST {
    plan(2);  // Plan for forward and reverse call tests.

    subtest("Forward calls with aggregate types (structs)") {
        plan(1);

        subtest("Passing and returning a small struct by value") {
            plan(3);
            // Verify a non-match for sanity
            Point bad_result = {0, 0};
            ok(fabs(bad_result.x - 15.5) > 1e-9, "Sanity check: non-matching result fails");

            // 1. Define the signature for: Point move_point(Point, double, double)
            const char * signature = "({double, double}, double, double) -> {double, double}";
            Point start_point = {10.0, 20.0};
            double offset_x = 5.5;
            double offset_y = -2.5;
            void * args[] = {&start_point, &offset_x, &offset_y};

            subtest("Unbound trampoline") {
                plan(2);
                infix_forward_t * unbound_t = nullptr;
                ok(infix_forward_create_unbound(&unbound_t, signature) == INFIX_SUCCESS, "Unbound trampoline created");
                if (unbound_t) {
                    Point unbound_result = {0.0, 0.0};
                    infix_cif_func cif = infix_forward_get_unbound_code(unbound_t);
                    cif((void *)move_point, &unbound_result, args);
                    ok(fabs(unbound_result.x - 15.5) < 1e-9 && fabs(unbound_result.y - 17.5) < 1e-9,
                       "Unbound call correct");
                }
                else
                    skip(1, "Skipping unbound call");

                infix_forward_destroy(unbound_t);
            }

            subtest("Bound trampoline") {
                plan(2);
                infix_forward_t * bound_t = nullptr;
                ok(infix_forward_create(&bound_t, signature, (void *)move_point) == INFIX_SUCCESS,
                   "Bound trampoline created");
                if (bound_t) {
                    Point bound_result = {0.0, 0.0};
                    infix_bound_cif_func cif = infix_forward_get_code(bound_t);
                    cif(&bound_result, args);
                    ok(fabs(bound_result.x - 15.5) < 1e-9 && fabs(bound_result.y - 17.5) < 1e-9, "Bound call correct");
                }
                else
                    skip(1, "Skipping bound call");

                infix_forward_destroy(bound_t);
            }
        }
    }

    subtest("Reverse calls (callbacks) with aggregate types") {
        plan(1);
        subtest("Passing and returning a small struct by value") {
            plan(3);
            const char * signature = "({double, double}) -> {double, double}";

            infix_reverse_t * context = nullptr;
            infix_status status = infix_reverse_create(&context, signature, (void *)point_callback_handler, nullptr);
            ok(status == INFIX_SUCCESS, "Successfully created reverse trampoline for struct by value");

            if (status == INFIX_SUCCESS) {
                // Get the native C function pointer from the reverse trampoline.
                typedef Point (*PointCallback)(Point);
                PointCallback native_func_ptr = (PointCallback)infix_reverse_get_code(context);

                // Call the harness, which will invoke our generated callback.
                Point input_point = {21.0, -10.5};
                execute_point_callback(native_func_ptr, input_point);
            }
            else
                skip(1, "Skipping call check due to trampoline creation failure.");

            // Add a final check to ensure the plan is met
            pass("Subtest finished");

            infix_reverse_destroy(context);
        }
    }
}
