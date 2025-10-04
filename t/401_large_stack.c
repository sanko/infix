<<<<<<< HEAD:t/401_large_stack.c
/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file 401_large_stack.c
 * @brief Tests FFI calls with a large number of arguments, forcing stack usage.
 *
 * @details This test suite is designed to stress-test the ABI implementation
 * when the number of arguments exceeds the number of available parameter
 * registers. It verifies correct stack layout, alignment, and argument marshalling
 * for both forward and reverse FFI calls.
 *
 * It covers several key scenarios:
 * 1.  **Forward Call (Register Limit):** A function is called with the exact
 *     number of arguments to fill all available parameter registers, testing this
 *     important boundary condition.
 * 2.  **Forward Call (One on Stack):** A function is called with one more
 *     argument than fits in registers, testing the transition to stack-based
 *     passing.
 * 3.  **Forward Call (Massive Stack):** A function with over 500 arguments is
 *     called, verifying the library's ability to handle stack frames larger than
 *     a single memory page and exercising the bulk-copy optimization for
 *     homogeneous stack arguments.
 * 4.  **Reverse Call (Callback):** A callback is created for a handler with a
 *     mixed set of arguments that will spill onto the stack, ensuring the JIT
 *     stub can correctly retrieve arguments from both registers and the
 *     caller's stack frame.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>

// Platform-Specific Definitions for Register Limits
#if defined(INFIX_ABI_WINDOWS_X64)
#define MAX_REG_DOUBLES 4
#else  // System V x64 and AArch64
#define MAX_REG_DOUBLES 8
#endif
#define ONE_STACK_DOUBLE (MAX_REG_DOUBLES + 1)

// Native C Functions for Forward Call Tests

/** @brief Sums the maximum number of doubles that can fit in registers for the target ABI. */
double sum_max_reg_doubles(double a1,
                           double a2,
                           double a3,
                           double a4
#if MAX_REG_DOUBLES > 4
                           ,
                           double a5,
                           double a6,
                           double a7,
                           double a8
#endif
) {
    note("sum_max_reg_doubles called.");
    return a1 + a2 + a3 + a4
#if MAX_REG_DOUBLES > 4
        + a5 + a6 + a7 + a8
#endif
        ;
}

/** @brief Sums one more double than can fit in registers, forcing one onto the stack. */
double sum_one_stack_double(double a1,
                            double a2,
                            double a3,
                            double a4,
                            double a5
#if MAX_REG_DOUBLES > 4
                            ,
                            double a6,
                            double a7,
                            double a8,
                            double a9
#endif
) {
    note("sum_one_stack_double called.");
    return a1 + a2 + a3 + a4 + a5
#if MAX_REG_DOUBLES > 4
        + a6 + a7 + a8 + a9
#endif
        ;
}

// Helper macros to define the massive 520-argument function signature.
#define ARG(N) c23_maybe_unused double arg##N
#define LIST10(M, p) M(p##0), M(p##1), M(p##2), M(p##3), M(p##4), M(p##5), M(p##6), M(p##7), M(p##8), M(p##9)
#define LIST100(M, p)                                                                                     \
    LIST10(M, p##0), LIST10(M, p##1), LIST10(M, p##2), LIST10(M, p##3), LIST10(M, p##4), LIST10(M, p##5), \
        LIST10(M, p##6), LIST10(M, p##7), LIST10(M, p##8), LIST10(M, p##9)

// This construction is unambiguous and generates exactly 520 arguments (0-519).
#define ARGS_0_TO_99                                                                                               \
    LIST10(ARG, ), LIST10(ARG, 1), LIST10(ARG, 2), LIST10(ARG, 3), LIST10(ARG, 4), LIST10(ARG, 5), LIST10(ARG, 6), \
        LIST10(ARG, 7), LIST10(ARG, 8), LIST10(ARG, 9)
#define ARGS_100_TO_499 LIST100(ARG, 1), LIST100(ARG, 2), LIST100(ARG, 3), LIST100(ARG, 4)
#define ARGS_500_TO_519 LIST10(ARG, 50), LIST10(ARG, 51)

/** @brief A function with 520 arguments to test massive stack frames. */
double large_stack_callee(ARGS_0_TO_99, ARGS_100_TO_499, ARGS_500_TO_519) {
    diag("Inside large_stack_callee");
    diag("Received arg0: %.1f (expected 0.0)", arg0);
    diag("Received arg519: %.1f (expected 519.0)", arg519);
    return arg0 + arg519;
}

// Native C Handler and Harness for Reverse Call Test

/** @brief A callback handler that takes a mix of register and stack arguments. */
int many_args_callback_handler(infix_context_t * context, int a, double b, int c, const char * d, Point e, float f) {
    (void)context;
    subtest("Inside many_args_callback_handler") {
        plan(6);
        ok(a == 10, "Arg 1 (int) is correct");
        ok(fabs(b - 20.2) < 0.001, "Arg 2 (double) is correct");
        ok(c == -30, "Arg 3 (int) is correct");
        ok(strcmp(d, "arg4") == 0, "Arg 4 (char*) is correct");
        ok(fabs(e.x - 5.5) < 0.001 && fabs(e.y - 6.6) < 0.001, "Arg 5 (Point) is correct (Stack Arg)");
        ok(fabs(f - 7.7f) < 0.001, "Arg 6 (float) is correct (Stack Arg)");
    };
    return a + c;  // Return something to verify completion
}

/** @brief A harness to call the generated callback with many arguments. */
void execute_many_args_callback(int (*func_ptr)(int, double, int, const char *, Point, float)) {
    Point p = {5.5, 6.6};
    int result = func_ptr(10, 20.2, -30, "arg4", p, 7.7f);
    ok(result == -20, "Callback with stack args returned correct value");
}


TEST {
    plan(2);

    subtest("Forward calls with register and stack arguments") {
        plan(3);

        subtest("Call with max register arguments") {
            plan(2);
            infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
            infix_type * arg_types[MAX_REG_DOUBLES];
            double arg_values[MAX_REG_DOUBLES];
            void * args[MAX_REG_DOUBLES];
            double expected_sum = 0.0;

            for (int i = 0; i < MAX_REG_DOUBLES; ++i) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)(i + 1);
                args[i] = &arg_values[i];
                expected_sum += arg_values[i];
            }

            infix_forward_t * trampoline = NULL;
            infix_status status =
                infix_forward_create_manual(&trampoline, ret_type, arg_types, MAX_REG_DOUBLES, MAX_REG_DOUBLES);
            ok(status == INFIX_SUCCESS, "Trampoline created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_max_reg_doubles, &result, args);
                ok(fabs(result - expected_sum) < 0.001, "Correct sum for max register args");
            }
            else
                skip(1, "Test skipped");

            infix_forward_destroy(trampoline);
        }

        subtest("Call with one stack argument") {
            plan(2);
            infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
            infix_type * arg_types[ONE_STACK_DOUBLE];
            double arg_values[ONE_STACK_DOUBLE];
            void * args[ONE_STACK_DOUBLE];
            double expected_sum = 0.0;

            for (int i = 0; i < ONE_STACK_DOUBLE; ++i) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)(i + 1.1);
                args[i] = &arg_values[i];
                expected_sum += arg_values[i];
            }

            infix_forward_t * trampoline = NULL;
            infix_status status =
                infix_forward_create_manual(&trampoline, ret_type, arg_types, ONE_STACK_DOUBLE, ONE_STACK_DOUBLE);
            ok(status == INFIX_SUCCESS, "Trampoline created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_one_stack_double, &result, args);
                ok(fabs(result - expected_sum) < 0.001, "Correct sum for one stack arg");
            }
            else
                skip(1, "Test skipped");

            infix_forward_destroy(trampoline);
        }

        subtest("Call with >4KB homogeneous stack arguments") {
            plan(2);
#define NUM_LARGE_ARGS 520
            static infix_type * arg_types[NUM_LARGE_ARGS];
            static double arg_values[NUM_LARGE_ARGS];
            static void * args[NUM_LARGE_ARGS];

            diag("Preparing %d arguments for large stack test...", NUM_LARGE_ARGS);
            for (int i = 0; i < NUM_LARGE_ARGS; i++) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)i;
                args[i] = &arg_values[i];
            }
            diag("Finished preparing arguments.");

            double expected_result = arg_values[0] + arg_values[519];
            diag("Expected result (arg0 + arg519): %.1f", expected_result);

            infix_forward_t * trampoline = NULL;
            infix_status status = infix_forward_create_manual(&trampoline,
                                                              infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                                              arg_types,
                                                              NUM_LARGE_ARGS,
                                                              NUM_LARGE_ARGS);
            ok(status == INFIX_SUCCESS, "Trampoline for large stack created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)large_stack_callee, &result, args);
                ok(fabs(result - expected_result) < 0.001,
                   "Large stack call returned correct sum (got %.1f, expected %.1f)",
                   result,
                   expected_result);
            }
            else
                skip(1, "Test skipped");
            infix_forward_destroy(trampoline);
        }
    }

    subtest("Reverse call (callback) with stack arguments") {
        plan(4);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_struct_member * point_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        point_members[0] =
            infix_type_create_member("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            infix_type_create_member("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
        infix_type * point_type = NULL;
        infix_status status = infix_type_create_struct(arena, &point_type, point_members, 2);
        if (!ok(status == INFIX_SUCCESS, "Point infix_type created")) {
            skip(3, "Test skipped");
            infix_arena_destroy(arena);
            return;
        }

        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_pointer(),
                                    point_type,
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};

        infix_reverse_t * rt = NULL;
        status = infix_reverse_create_manual(&rt, ret_type, arg_types, 6, 6, (void *)many_args_callback_handler, NULL);
        ok(status == INFIX_SUCCESS, "Reverse trampoline with stack args created");

        if (rt) {
            typedef int (*ManyArgsCallback)(int, double, int, const char *, Point, float);
            execute_many_args_callback((ManyArgsCallback)infix_reverse_get_code(rt));
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
}
=======
/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file 401_large_stack.c
 * @brief Tests FFI calls with a large number of arguments, forcing stack usage.
 *
 * @details This test suite is designed to stress-test the ABI implementation
 * when the number of arguments exceeds the number of available parameter
 * registers. It verifies correct stack layout, alignment, and argument marshalling
 * for both forward and reverse FFI calls.
 *
 * It covers several key scenarios:
 * 1.  **Forward Call (Register Limit):** A function is called with the exact
 *     number of arguments to fill all available parameter registers, testing this
 *     important boundary condition.
 * 2.  **Forward Call (One on Stack):** A function is called with one more
 *     argument than fits in registers, testing the transition to stack-based
 *     passing.
 * 3.  **Forward Call (Massive Stack):** A function with over 500 arguments is
 *     called, verifying the library's ability to handle stack frames larger than
 *     a single memory page and exercising the bulk-copy optimization for
 *     homogeneous stack arguments.
 * 4.  **Reverse Call (Callback):** A callback is created for a handler with a
 *     mixed set of arguments that will spill onto the stack, ensuring the JIT
 *     stub can correctly retrieve arguments from both registers and the
 *     caller's stack frame.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>

// Platform-Specific Definitions for Register Limits
#if defined(INFIX_ABI_WINDOWS_X64)
#define MAX_REG_DOUBLES 4
#else  // System V x64 and AArch64
#define MAX_REG_DOUBLES 8
#endif
#define ONE_STACK_DOUBLE (MAX_REG_DOUBLES + 1)

// Native C Functions for Forward Call Tests

/** @brief Sums the maximum number of doubles that can fit in registers for the target ABI. */
double sum_max_reg_doubles(double a1,
                           double a2,
                           double a3,
                           double a4
#if MAX_REG_DOUBLES > 4
                           ,
                           double a5,
                           double a6,
                           double a7,
                           double a8
#endif
) {
    note("sum_max_reg_doubles called.");
    return a1 + a2 + a3 + a4
#if MAX_REG_DOUBLES > 4
        + a5 + a6 + a7 + a8
#endif
        ;
}

/** @brief Sums one more double than can fit in registers, forcing one onto the stack. */
double sum_one_stack_double(double a1,
                            double a2,
                            double a3,
                            double a4,
                            double a5
#if MAX_REG_DOUBLES > 4
                            ,
                            double a6,
                            double a7,
                            double a8,
                            double a9
#endif
) {
    note("sum_one_stack_double called.");
    return a1 + a2 + a3 + a4 + a5
#if MAX_REG_DOUBLES > 4
        + a6 + a7 + a8 + a9
#endif
        ;
}

// Helper macros to define the massive 520-argument function signature.
#define ARG(N) c23_maybe_unused double arg##N
#define LIST10(M, p) M(p##0), M(p##1), M(p##2), M(p##3), M(p##4), M(p##5), M(p##6), M(p##7), M(p##8), M(p##9)
#define LIST100(M, p)                                                                                     \
    LIST10(M, p##0), LIST10(M, p##1), LIST10(M, p##2), LIST10(M, p##3), LIST10(M, p##4), LIST10(M, p##5), \
        LIST10(M, p##6), LIST10(M, p##7), LIST10(M, p##8), LIST10(M, p##9)

// This construction is unambiguous and generates exactly 520 arguments (0-519).
#define ARGS_0_TO_99                                                                                               \
    LIST10(ARG, ), LIST10(ARG, 1), LIST10(ARG, 2), LIST10(ARG, 3), LIST10(ARG, 4), LIST10(ARG, 5), LIST10(ARG, 6), \
        LIST10(ARG, 7), LIST10(ARG, 8), LIST10(ARG, 9)
#define ARGS_100_TO_499 LIST100(ARG, 1), LIST100(ARG, 2), LIST100(ARG, 3), LIST100(ARG, 4)
#define ARGS_500_TO_519 LIST10(ARG, 50), LIST10(ARG, 51)

/** @brief A function with 520 arguments to test massive stack frames. */
double large_stack_callee(ARGS_0_TO_99, ARGS_100_TO_499, ARGS_500_TO_519) {
    diag("Inside large_stack_callee");
    diag("Received arg0: %.1f (expected 0.0)", arg0);
    diag("Received arg519: %.1f (expected 519.0)", arg519);
    return arg0 + arg519;
}

// Native C Handler and Harness for Reverse Call Test

/** @brief A callback handler that takes a mix of register and stack arguments. */
int many_args_callback_handler(infix_context_t * context, int a, double b, int c, const char * d, Point e, float f) {
    (void)context;
    subtest("Inside many_args_callback_handler") {
        plan(6);
        ok(a == 10, "Arg 1 (int) is correct");
        ok(fabs(b - 20.2) < 0.001, "Arg 2 (double) is correct");
        ok(c == -30, "Arg 3 (int) is correct");
        ok(strcmp(d, "arg4") == 0, "Arg 4 (char*) is correct");
        ok(fabs(e.x - 5.5) < 0.001 && fabs(e.y - 6.6) < 0.001, "Arg 5 (Point) is correct (Stack Arg)");
        ok(fabs(f - 7.7f) < 0.001, "Arg 6 (float) is correct (Stack Arg)");
    };
    return a + c;  // Return something to verify completion
}

/** @brief A harness to call the generated callback with many arguments. */
void execute_many_args_callback(int (*func_ptr)(int, double, int, const char *, Point, float)) {
    Point p = {5.5, 6.6};
    int result = func_ptr(10, 20.2, -30, "arg4", p, 7.7f);
    ok(result == -20, "Callback with stack args returned correct value");
}


TEST {
    plan(2);

    subtest("Forward calls with register and stack arguments") {
        plan(3);

        subtest("Call with max register arguments") {
            plan(2);
            infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
            infix_type * arg_types[MAX_REG_DOUBLES];
            double arg_values[MAX_REG_DOUBLES];
            void * args[MAX_REG_DOUBLES];
            double expected_sum = 0.0;

            for (int i = 0; i < MAX_REG_DOUBLES; ++i) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)(i + 1);
                args[i] = &arg_values[i];
                expected_sum += arg_values[i];
            }

            infix_forward_t * trampoline = NULL;
            infix_status status =
                infix_forward_create_manual(&trampoline, ret_type, arg_types, MAX_REG_DOUBLES, MAX_REG_DOUBLES);
            ok(status == INFIX_SUCCESS, "Trampoline created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_max_reg_doubles, &result, args);
                ok(fabs(result - expected_sum) < 0.001, "Correct sum for max register args");
            }
            else
                skip(1, "Test skipped");

            infix_forward_destroy(trampoline);
        }

        subtest("Call with one stack argument") {
            plan(2);
            infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
            infix_type * arg_types[ONE_STACK_DOUBLE];
            double arg_values[ONE_STACK_DOUBLE];
            void * args[ONE_STACK_DOUBLE];
            double expected_sum = 0.0;

            for (int i = 0; i < ONE_STACK_DOUBLE; ++i) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)(i + 1.1);
                args[i] = &arg_values[i];
                expected_sum += arg_values[i];
            }

            infix_forward_t * trampoline = NULL;
            infix_status status =
                infix_forward_create_manual(&trampoline, ret_type, arg_types, ONE_STACK_DOUBLE, ONE_STACK_DOUBLE);
            ok(status == INFIX_SUCCESS, "Trampoline created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)sum_one_stack_double, &result, args);
                ok(fabs(result - expected_sum) < 0.001, "Correct sum for one stack arg");
            }
            else
                skip(1, "Test skipped");

            infix_forward_destroy(trampoline);
        }

        subtest("Call with >4KB homogeneous stack arguments") {
            plan(2);
#define NUM_LARGE_ARGS 520
            static infix_type * arg_types[NUM_LARGE_ARGS];
            static double arg_values[NUM_LARGE_ARGS];
            static void * args[NUM_LARGE_ARGS];

            diag("Preparing %d arguments for large stack test...", NUM_LARGE_ARGS);
            for (int i = 0; i < NUM_LARGE_ARGS; i++) {
                arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
                arg_values[i] = (double)i;
                args[i] = &arg_values[i];
            }
            diag("Finished preparing arguments.");

            double expected_result = arg_values[0] + arg_values[519];
            diag("Expected result (arg0 + arg519): %.1f", expected_result);

            infix_forward_t * trampoline = NULL;
            infix_status status = infix_forward_create_manual(&trampoline,
                                                              infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                                              arg_types,
                                                              NUM_LARGE_ARGS,
                                                              NUM_LARGE_ARGS);
            ok(status == INFIX_SUCCESS, "Trampoline for large stack created");

            double result = 0.0;
            if (trampoline) {
                ((infix_cif_func)infix_forward_get_code(trampoline))((void *)large_stack_callee, &result, args);
                ok(fabs(result - expected_result) < 0.001,
                   "Large stack call returned correct sum (got %.1f, expected %.1f)",
                   result,
                   expected_result);
            }
            else
                skip(1, "Test skipped");
            infix_forward_destroy(trampoline);
        }
    }

    subtest("Reverse call (callback) with stack arguments") {
        plan(4);
        infix_arena_t * arena = infix_arena_create(4096);
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_struct_member * point_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * 2, _Alignof(infix_struct_member));
        point_members[0] =
            infix_struct_member_create("x", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, x));
        point_members[1] =
            infix_struct_member_create("y", infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE), offsetof(Point, y));
        infix_type * point_type = NULL;
        infix_status status = infix_type_create_struct(arena, &point_type, point_members, 2);
        if (!ok(status == INFIX_SUCCESS, "Point infix_type created")) {
            skip(3, "Test skipped");
            infix_arena_destroy(arena);
            return;
        }

        infix_type * arg_types[] = {infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                    infix_type_create_primitive(INFIX_PRIMITIVE_SINT32),
                                    infix_type_create_pointer(),
                                    point_type,
                                    infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT)};

        infix_reverse_t * rt = NULL;
        status = infix_reverse_create_manual(&rt, ret_type, arg_types, 6, 6, (void *)many_args_callback_handler, NULL);
        ok(status == INFIX_SUCCESS, "Reverse trampoline with stack args created");

        if (rt) {
            typedef int (*ManyArgsCallback)(int, double, int, const char *, Point, float);
            execute_many_args_callback((ManyArgsCallback)infix_reverse_get_code(rt));
        }
        else
            skip(1, "Test skipped");

        infix_reverse_destroy(rt);
        infix_arena_destroy(arena);
    }
}
>>>>>>> main:t/400_advanced/401_large_stack.c
