/**
 * @file 401_large_stack.c
 * @brief Unit test for FFI calls with a large number of arguments passed on the stack.
 * @ingroup test_suite
 *
 * @details This test file is a stress test for the ABI implementation's handling
 * of the stack. Modern calling conventions pass the first several arguments in
 * registers, but all subsequent arguments are passed on the stack. This test
 * verifies that `infix` can correctly handle both scenarios.
 *
 * It covers:
 *
 * 1.  **Register-Only Calls:** A call is made with the maximum number of arguments
 *     that can fit in registers, ensuring the register-passing logic is correct.
 *
 * 2.  **One Stack Argument:** A call is made with just enough arguments to force
 *     one argument to be placed on the stack, verifying the transition from
 *     registers to the stack.
 *
 * 3.  **Large Stack Allocation (>4KB):** A call is made with a very large number
 *     of arguments (520 doubles), forcing the JIT-compiled trampoline to allocate
 *     a significant amount of stack space (>4KB). This is a regression test for
 *     bugs where stack offsets were calculated incorrectly for large frames, and
 *     it stress-tests the stack allocation and argument marshalling logic.
 *
 * 4.  **Reverse Calls with Stack Arguments:** A reverse trampoline is created for
 *     a function with enough arguments to require some to be passed on the stack.
 *     This verifies that the reverse call stub can correctly retrieve arguments
 *     from the caller's stack frame in addition to registers.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <string.h>

// Determine the number of floating-point registers used for arguments on the current ABI.
#if defined(INFIX_ABI_WINDOWS_X64)
#define MAX_REG_DOUBLES 4
#else  // System V and AArch64
#define MAX_REG_DOUBLES 8
#endif
#define ONE_STACK_DOUBLE (MAX_REG_DOUBLES + 1)
/** @brief A function that takes the maximum number of doubles that can fit in registers. */
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
/** @brief A function that takes just enough doubles to force one onto the stack. */
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
#define ARG(N) c23_maybe_unused double arg##N
#define LIST10(M, p) M(p##0), M(p##1), M(p##2), M(p##3), M(p##4), M(p##5), M(p##6), M(p##7), M(p##8), M(p##9)
#define LIST100(M, p)                                                                                     \
    LIST10(M, p##0), LIST10(M, p##1), LIST10(M, p##2), LIST10(M, p##3), LIST10(M, p##4), LIST10(M, p##5), \
        LIST10(M, p##6), LIST10(M, p##7), LIST10(M, p##8), LIST10(M, p##9)
#define ARGS_0_TO_99                                                                                               \
    LIST10(ARG, ), LIST10(ARG, 1), LIST10(ARG, 2), LIST10(ARG, 3), LIST10(ARG, 4), LIST10(ARG, 5), LIST10(ARG, 6), \
        LIST10(ARG, 7), LIST10(ARG, 8), LIST10(ARG, 9)
#define ARGS_100_TO_499 LIST100(ARG, 1), LIST100(ARG, 2), LIST100(ARG, 3), LIST100(ARG, 4)
#define ARGS_500_TO_519 LIST10(ARG, 50), LIST10(ARG, 51)
double large_stack_callee(ARGS_0_TO_99, ARGS_100_TO_499, ARGS_500_TO_519) {
    diag("Inside large_stack_callee");
    diag("Received arg0: %.1f (expected 0.0)", arg0);
    diag("Received arg519: %.1f (expected 519.0)", arg519);
    return arg0 + arg519;
}
/** @brief A type-safe handler for a reverse call with mixed register and stack arguments. */
int many_args_callback_handler(int a, double b, int c, const char * d, Point e, float f) {
    // On most ABIs, 'a', 'b', 'c', 'd' will be in registers.
    // 'e' and 'f' will be on the stack.
    subtest("Inside many_args_callback_handler") {
        plan(6);
        ok(a == 10, "Arg 1 (int) is correct");
        ok(fabs(b - 20.2) < 0.001, "Arg 2 (double) is correct");
        ok(c == -30, "Arg 3 (int) is correct");
        ok(strcmp(d, "arg4") == 0, "Arg 4 (char*) is correct");
        ok(fabs(e.x - 5.5) < 0.001 && fabs(e.y - 6.6) < 0.001, "Arg 5 (Point) is correct (Stack Arg)");
        ok(fabs(f - 7.7f) < 0.001, "Arg 6 (float) is correct (Stack Arg)");
    };
    return a + c;
}
/** @brief A C harness to call the JIT-compiled reverse trampoline. */
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
            infix_forward_t * trampoline = nullptr;
            infix_status status =
                infix_forward_create_unbound_manual(&trampoline, ret_type, arg_types, MAX_REG_DOUBLES, MAX_REG_DOUBLES);
            ok(status == INFIX_SUCCESS, "Trampoline created");
            double result = 0.0;
            if (trampoline) {
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)sum_max_reg_doubles, &result, args);
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
            infix_forward_t * trampoline = nullptr;
            infix_status status = infix_forward_create_unbound_manual(
                &trampoline, ret_type, arg_types, ONE_STACK_DOUBLE, ONE_STACK_DOUBLE);
            ok(status == INFIX_SUCCESS, "Trampoline created");
            double result = 0.0;
            if (trampoline) {
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)sum_one_stack_double, &result, args);
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
            infix_forward_t * trampoline = nullptr;
            infix_status status =
                infix_forward_create_unbound_manual(&trampoline,
                                                    infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE),
                                                    arg_types,
                                                    NUM_LARGE_ARGS,
                                                    NUM_LARGE_ARGS);
            ok(status == INFIX_SUCCESS, "Trampoline for large stack created");
            diag("status: %d", status);
            double result = 0.0;
            if (trampoline) {
                infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
                cif((void *)large_stack_callee, &result, args);
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
        infix_type * point_type = nullptr;
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
        infix_reverse_t * rt = nullptr;
        status =
            infix_reverse_create_callback_manual(&rt, ret_type, arg_types, 6, 6, (void *)many_args_callback_handler);
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
