/**
 * @file 870_cpp_compat.cpp
 * @brief Unit test to ensure `infix` is compatible with C++ codebases.
 * @ingroup test_suite
 *
 * @details This test file is compiled as C++ (hence the `.cpp` extension) but includes
 * the C-compatible `infix.h` header. Its primary purpose is to verify that:
 *
 * 1.  **Header Compatibility:** The `infix.h` header is correctly wrapped in
 *     `extern "C"` blocks, preventing C++ name mangling issues during linking.
 *     If this were broken, this file would fail to link.
 *
 * 2.  **Type Compatibility:** C++ constructs like `std::vector` and classes can
 *     interoperate with `infix` types, provided the data layout matches.
 *
 * 3.  **Exception Safety:** The test verifies that C++ exceptions thrown *across*
 *     a JIT-compiled trampoline frame are propagated correctly. If a C++ function
 *     called via a trampoline throws an exception, the exception should bubble up
 *     through the trampoline (which has no unwind info on some platforms) and be
 *     caught by the caller.
 *     *Note:* On Windows x64, unwinding through JIT code without registered PDATA
 *     is not guaranteed to work and may terminate the process. This test checks
 *     if it works on the current platform, or fails gracefully if not supported.
 */
#ifndef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <cwctype>
#include <infix/infix.h>
#include <iostream>
#include <string>
#include <vector>

#define DBLTAP_IMPLEMENTATION
// Force C linkage for the test harness macros to work in C++.
#include "common/compat_c23.h"
#include "common/double_tap.h"

// A simple C++ class to test method calls (simulated as C functions with 'this').
class Calculator {
public:
    int multiplier;
    Calculator(int m) : multiplier(m) {}
    int multiply(int val) { return val * multiplier; }
};
// C-compatible wrapper for the C++ method.
extern "C" int calculator_multiply_c_wrapper(Calculator * calc, int val) { return calc->multiply(val); }
// Function that throws a C++ exception.
extern "C" void throw_exception_func() { throw std::runtime_error("Exception thrown across FFI boundary!"); }
TEST {
    plan(2);
    subtest("C++ Class Method Call via Trampoline") {
        plan(2);
        Calculator calc(10);
        // Signature: (void*, int) -> int. The void* is the 'this' pointer.
        infix_type * ret_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
        infix_type * arg_types[] = {infix_type_create_pointer(), infix_type_create_primitive(INFIX_PRIMITIVE_SINT32)};
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create_unbound_manual(&trampoline, ret_type, arg_types, 2, 2);
        ok(status == INFIX_SUCCESS, "Trampoline for C++ method wrapper created");
        if (trampoline) {
            int val = 5;
            Calculator * calc_ptr = &calc;
            void * args[] = {&calc_ptr, &val};
            int result = 0;
            infix_unbound_cif_func cif = infix_forward_get_unbound_code(trampoline);
            cif((void *)calculator_multiply_c_wrapper, &result, args);
            ok(result == 50, "C++ method called correctly (5 * 10 = 50)");
        }
        else
            skip(1, "Test skipped");
        infix_forward_destroy(trampoline);
    }
    subtest("C++ Exception Propagation") {
        plan(2);
#if defined(_WIN32) && defined(_M_X64)
        // Exception unwinding through JIT code is now supported on Windows x64.
#else
        // Exception unwinding through JIT code requires platform-specific metadata
        // (.eh_frame/DWARF on Linux/macOS) which is not yet implemented.
        skip(2, "Exception unwinding through JIT code is not yet supported on this platform.");
#endif
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create(&trampoline, "()->void", (void *)throw_exception_func, nullptr);
        ok(status == INFIX_SUCCESS, "Trampoline created for exception thrower");
        if (trampoline) {
            bool caught = false;
            infix_cif_func cif = infix_forward_get_code(trampoline);
            try {
                cif(nullptr, nullptr);
            } catch (const std::runtime_error & e) {
                caught = true;
                // Verify the exception message to ensure it's the right one.
                if (std::string(e.what()) == "Exception thrown across FFI boundary!")
                    pass("Caught expected C++ exception: %s", e.what());
                else
                    fail("Caught unexpected exception message: %s", e.what());
            } catch (...) {
                fail("Caught unknown exception type");
            }
            if (!caught)
                fail("Exception was NOT caught (or crashed the process)");
        }
        else
            skip(1, "Test skipped");
        infix_forward_destroy(trampoline);
    }
}
