/**
 * @file 402_variadic_functions.c
 * @brief Unit test for FFI calls to and from variadic C functions.
 * @ingroup test_suite
 *
 * @details This test file is extremely important for verifying ABI-compliance, as
 * the rules for passing variadic arguments differ significantly between platforms,
 * even on the same architecture.
 *
 * The test covers:
 *
 * - **Forward Variadic Call (Primitives):** A call is made to a `printf`-like
 *   function with a mix of fixed and variadic arguments (`*char`, `int`, `double`).
 *   This tests the core variadic calling mechanism.
 *
 * - **Forward Variadic Call (Aggregates):** A call is made passing a struct as a
 *   variadic argument. This is highly platform-dependent:
 *   - On **System V**, the struct is passed on the stack.
 *   - On **Windows x64**, a pointer to the struct is passed in a GPR.
 *   - On **AArch64**, the struct is passed on the stack.
 *
 * - **Reverse Variadic Callback:** A reverse trampoline is created for a variadic
 *   function. The test verifies that when the JIT-compiled function pointer is
 *   called with variadic arguments, the C handler receives them correctly via
 *   `va_list`/`va_arg`.
 *
 * - **Platform-Specific ABI Deviations:** Includes dedicated subtests for known
 *   tricky variadic cases, such as passing floats/doubles on Windows x64 (which
 *   requires them to be passed in both GPRs and XMM registers) and passing structs
 *   on macOS on ARM (which has its own unique stack-passing rules).
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "types.h"
#include <infix/infix.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int forward_variadic_checker(char * buffer, size_t size, const char * format, ...) {
    (void)buffer;
    (void)size;
    va_list args;
    va_start(args, format);
    const char * str_arg = va_arg(args, const char *);
    int int_arg = va_arg(args, int);
    double dbl_arg = va_arg(args, double);
    va_end(args);
    note("forward_variadic_checker received:");
    note("  format = \"%s\"", format);
    note("  str_arg = \"%s\"", str_arg);
    note("  int_arg = %d", int_arg);
    note("  dbl_arg = %.2f", dbl_arg);
    subtest("Inside forward_variadic_checker") {
        plan(4);
        ok(strcmp(format, "format string") == 0, "Fixed arg 'format' is correct");
        ok(strcmp(str_arg, "hello") == 0, "Variadic arg 1 (string) is correct");
        ok(int_arg == 123, "Variadic arg 2 (int) is correct");
        ok(fabs(dbl_arg - 3.14) < 0.001, "Variadic arg 3 (double) is correct");
    }
    return 1;
}
int forward_variadic_aggregate_checker(int fixed_arg, ...) {
    va_list args;
    va_start(args, fixed_arg);
#if defined(INFIX_ABI_WINDOWS_X64)
    NonPowerOfTwoStruct * s_ptr = va_arg(args, NonPowerOfTwoStruct *);
    note("Windows variadic checker received struct pointer: %p", (void *)s_ptr);
    if (s_ptr)
        ok(s_ptr->a == 1 && s_ptr->b == 2 && s_ptr->c == 3, "Variadic NonPowerOfTwoStruct correct on Windows x64");
    else
        fail("Received a null pointer for variadic struct on Windows x64");
#else
    Point p = va_arg(args, Point);
    note("System V/AAPCS64 variadic checker received Point: {%.1f, %.1f}", p.x, p.y);
    ok(fabs(p.x - 10.5) < 1e-9 && fabs(p.y - 20.5) < 1e-9, "Variadic Point struct correct on SysV/AAPCS64");
#endif
    va_end(args);
    return 1;
}
int variadic_reverse_handler(const char * topic, ...) {
    va_list args;
    va_start(args, topic);
    int count = va_arg(args, int);
    double value = va_arg(args, double);
    const char * message = va_arg(args, const char *);
    va_end(args);
    subtest("Inside variadic_reverse_handler") {
        plan(4);
        ok(strcmp(topic, "LOG") == 0, "Fixed arg (topic) is correct");
        ok(count == 42, "Variadic arg 1 (count) is correct");
        ok(fabs(value - 3.14) < 0.001, "Variadic arg 2 (value) is correct");
        ok(strcmp(message, "Done") == 0, "Variadic arg 3 (message) is correct");
    }
    return count + (int)value;
}
#if defined(INFIX_OS_MACOS) && defined(INFIX_ARCH_AARCH64)
typedef struct {
    long a;
    long b;
} MacTestStruct;
int macos_variadic_checker(int fixed_arg, ...) {
    va_list args;
    va_start(args, fixed_arg);
    double var_double = va_arg(args, double);
    MacTestStruct var_struct = va_arg(args, MacTestStruct);
    va_end(args);
    note("macOS variadic checker received: fixed=%d, double=%.2f, struct={%ld, %ld}",
         fixed_arg,
         var_double,
         var_struct.a,
         var_struct.b);
    return fixed_arg + (int)var_double + (int)var_struct.a + (int)var_struct.b;
}
#endif
#if defined(INFIX_ABI_WINDOWS_X64)
double win_variadic_float_checker(int fixed_arg, ...) {
    va_list args;
    va_start(args, fixed_arg);
    double var_double = va_arg(args, double);
    va_end(args);
    note("Windows variadic checker received fixed=%d, variadic_double=%.2f", fixed_arg, var_double);
    return var_double;
}
#endif
TEST {
    plan(5);
    subtest("Forward variadic call") {
        plan(3);
        const char * signature = "(*char, uint64, *char; *char, int32, double) -> int32";
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound(&trampoline, signature, nullptr);
        ok(status == INFIX_SUCCESS, "Variadic forward trampoline created");
        char buffer[1] = {0};
        size_t size = 1;
        const char * fmt = "format string";
        const char * str_arg = "hello";
        int int_arg = 123;
        double dbl_arg = 3.14;
        int result = 0;
        void * args[] = {&buffer, &size, &fmt, &str_arg, &int_arg, &dbl_arg};
        infix_unbound_cif_func cif_func = infix_forward_get_unbound_code(trampoline);
        cif_func((void *)forward_variadic_checker, &result, args);
        pass("Custom variadic checker function was called.");
        infix_forward_destroy(trampoline);
    }
    subtest("Forward variadic call (aggregates)") {
        plan(3);
#if defined(INFIX_ABI_WINDOWS_X64)
        note("Testing variadic NonPowerOfTwoStruct on Windows x64 (pass-by-reference)");
        const char * signature = "(int;{int,int,int}) -> int";
        NonPowerOfTwoStruct s = {1, 2, 3};
#else
        note("Testing variadic Point struct on System V / AAPCS64 (pass-on-stack)");
        const char * signature = "(int;{double,double}) -> int";
        Point s = {10.5, 20.5};
#endif
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound(&trampoline, signature, nullptr);
        ok(status == INFIX_SUCCESS, "Variadic aggregate trampoline created");
        int fixed_arg = 1;
        void * args[] = {&fixed_arg, &s};
        int result = 0;
        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        cif((void *)forward_variadic_aggregate_checker, &result, args);
        pass("Aggregate checker function was called.");
        infix_forward_destroy(trampoline);
    }
    subtest("Reverse variadic callback") {
        plan(3);
        const char * signature = "(*char; int, double, *char) -> int";
        infix_reverse_t * rt = nullptr;
        infix_status status = infix_reverse_create_callback(&rt, signature, (void *)variadic_reverse_handler, nullptr);
        ok(status == INFIX_SUCCESS, "Variadic reverse trampoline created");
        if (rt) {
            typedef int (*VariadicLogFunc)(const char *, ...);
            VariadicLogFunc func_ptr = (VariadicLogFunc)infix_reverse_get_code(rt);
            int result = func_ptr("LOG", 42, 3.14, "Done");
            ok(result == 45, "Variadic callback returned correct sum (42 + 3)");
        }
        else
            skip(1, "Test skipped");
        infix_reverse_destroy(rt);
    }
    subtest("Platform ABI: macOS AArch64 variadic struct passing") {
        plan(2);
#if defined(INFIX_OS_MACOS) && defined(INFIX_ARCH_AARCH64)
        note("Testing variadic call with struct argument on macOS/ARM (must go on stack)");
        const char * signature = "(int32; double, {int64, int64}) -> int32";
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound(&trampoline, signature, nullptr);
        ok(status == INFIX_SUCCESS, "Trampoline for macOS variadic test created");
        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        int fixed_val = 10;
        double dbl_val = 20.0;
        MacTestStruct struct_val = {30, 40};
        void * args[] = {&fixed_val, &dbl_val, &struct_val};
        int result = 0;
        cif((void *)macos_variadic_checker, &result, args);
        ok(result == 100, "macOS variadic arguments passed correctly (10+20+30+40)");
        infix_forward_destroy(trampoline);
#else
        skip(2, "Test is only for macOS on AArch64");
#endif
    }
    subtest("Platform ABI: Windows x64 variadic float/double passing") {
        plan(2);
#if defined(INFIX_ABI_WINDOWS_X64)
        note("Testing if a variadic double is passed correctly on Windows x64");
        const char * signature = "(int32; double) -> double";
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound(&trampoline, signature, nullptr);
        ok(status == INFIX_SUCCESS, "Trampoline for Windows variadic test created");
        infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
        int fixed_val = 100;
        double dbl_val = 123.45;
        void * args[] = {&fixed_val, &dbl_val};
        double result = 0.0;
        cif((void *)win_variadic_float_checker, &result, args);
        ok(fabs(result - 123.45) < 0.001, "Windows variadic double passed correctly");
        infix_forward_destroy(trampoline);
#else
        skip(2, "Test is only for the Windows x64 ABI");
#endif
    }
}
