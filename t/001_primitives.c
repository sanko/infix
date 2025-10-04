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
 * @file 001_primitives.c
 * @brief Tests FFI functionality with all supported primitive C types.
 *
 * @details This test suite verifies the core capability of the infix library to
 * handle all fundamental C data types. It does this by creating a simple
 * "passthrough" C function for each primitive (e.g., `bool`, `int8_t`, `double`,
 * `__int128_t`).
 *
 * For each type, the test performs the following steps:
 * 1. Defines the `infix_type` using `infix_type_create_primitive`.
 * 2. Generates a forward trampoline for the passthrough function's signature.
 * 3. Calls the native C function through the generated trampoline.
 * 4. Asserts that the value returned from the FFI call is identical to the
 *    value that was passed in.
 *
 * This process validates that the library correctly handles the size, alignment,
 * and ABI-specific calling conventions for every primitive type on the target
 * platform, forming the foundational layer of the entire test suite.
 *
 * These tests use the manual API to test primitive types to verify functionality
 * without bringing the signature system in.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "common/infix_config.h"  // Include the internal platform detection logic.
#include <infix/infix.h>
#include <inttypes.h>  // Include for portable format specifiers like PRIu64

// Native C Passthrough Functions
// A simple "passthrough" function is defined for each C primitive type.
// Each function takes one argument and returns it unmodified.

bool passthrough_bool(bool v) {
    return v;
}
uint8_t passthrough_uint8(uint8_t v) {
    return v;
}
int8_t passthrough_sint8(int8_t v) {
    return v;
}
uint16_t passthrough_uint16(uint16_t v) {
    return v;
}
int16_t passthrough_sint16(int16_t v) {
    return v;
}
uint32_t passthrough_uint32(uint32_t v) {
    return v;
}
int32_t passthrough_sint32(int32_t v) {
    return v;
}
uint64_t passthrough_uint64(uint64_t v) {
    return v;
}
int64_t passthrough_sint64(int64_t v) {
    return v;
}
float passthrough_float(float v) {
    return v;
}
double passthrough_double(double v) {
    return v;
}
long double passthrough_long_double(long double v) {
    return v;
}

// 128-bit integers are a non-standard extension, not supported by MSVC.
#if !defined(INFIX_COMPILER_MSVC)
__uint128_t passthrough_uint128(__uint128_t v) {
    return v;
}
__int128_t passthrough_sint128(__int128_t v) {
    return v;
}
#endif

/**
 * @def TEST_PRIMITIVE
 * @brief A helper macro to generate a subtest for a specific primitive type.
 *
 * @details This macro encapsulates the repetitive logic for testing a single
 * primitive type. It creates a subtest, generates a trampoline, performs the
 * FFI call, checks the result, and cleans up resources. This reduces code
 * duplication and makes the test suite easier to read and maintain.
 *
 * @param test_name The string name for the subtest.
 * @param c_type The C data type (e.g., `uint8_t`).
 * @param infix_id The `infix_primitive_type_id` enum value.
 * @param passthrough_func The name of the native C passthrough function.
 * @param input_val A literal value to use for testing.
 * @param format_specifier A printf format specifier for diagnostic messages.
 */
#define TEST_PRIMITIVE(test_name, c_type, infix_id, passthrough_func, input_val, format_specifier)                 \
    subtest(test_name) {                                                                                           \
        plan(2);                                                                                                   \
        infix_type * type = infix_type_create_primitive(infix_id);                                                 \
        infix_forward_t * trampoline = NULL;                                                                       \
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);                         \
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");                                          \
                                                                                                                   \
        c_type input = (input_val);                                                                                \
        c_type result = 0;                                                                                         \
        void * args[] = {&input};                                                                                  \
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);                                   \
        if (cif) {                                                                                                 \
            cif((void *)passthrough_func, &result, args);                                                          \
            ok(result == input, "Value is correct (" format_specifier " == " format_specifier ")", input, result); \
        }                                                                                                          \
        else                                                                                                       \
            fail("Trampoline code pointer was NULL");                                                              \
                                                                                                                   \
        infix_forward_destroy(trampoline);                                                                         \
    }

TEST {
    plan(14);  // One subtest for each primitive type.

    TEST_PRIMITIVE("bool", bool, INFIX_PRIMITIVE_BOOL, passthrough_bool, true, "%d");
    TEST_PRIMITIVE("uint8_t", uint8_t, INFIX_PRIMITIVE_UINT8, passthrough_uint8, 255, "%u");
    TEST_PRIMITIVE("int8_t", int8_t, INFIX_PRIMITIVE_SINT8, passthrough_sint8, -128, "%d");
    TEST_PRIMITIVE("uint16_t", uint16_t, INFIX_PRIMITIVE_UINT16, passthrough_uint16, 65535, "%u");
    TEST_PRIMITIVE("int16_t", int16_t, INFIX_PRIMITIVE_SINT16, passthrough_sint16, -32768, "%d");
    TEST_PRIMITIVE("uint32_t", uint32_t, INFIX_PRIMITIVE_UINT32, passthrough_uint32, 0xFFFFFFFF, "%u");
    TEST_PRIMITIVE("int32_t", int32_t, INFIX_PRIMITIVE_SINT32, passthrough_sint32, -2147483647 - 1, "%d");
    TEST_PRIMITIVE("uint64_t", uint64_t, INFIX_PRIMITIVE_UINT64, passthrough_uint64, 0xFFFFFFFFFFFFFFFF, "%" PRIu64);
    TEST_PRIMITIVE(
        "int64_t", int64_t, INFIX_PRIMITIVE_SINT64, passthrough_sint64, -9223372036854775807LL - 1, "%" PRId64);
    TEST_PRIMITIVE("float", float, INFIX_PRIMITIVE_FLOAT, passthrough_float, 3.14159f, "%f");
    TEST_PRIMITIVE("double", double, INFIX_PRIMITIVE_DOUBLE, passthrough_double, 2.718281828459045, "%f");

    subtest("long double") {
        plan(2);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        long double input = 1.234567890123456789L;
        long double result = 0.0L;
        void * args[] = {&input};
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        cif((void *)passthrough_long_double, &result, args);

        if (result == input)
            pass("Value is correct for long double");
        else {
            fail("Value is incorrect for long double");
            // On failure, print detailed byte-level diagnostics.
            union {
                long double ld;
                unsigned char bytes[sizeof(long double)];
            } u_in, u_out;
            u_in.ld = input;
            u_out.ld = result;
            char buf[512];
            int offset = snprintf(buf, sizeof(buf), "Expected: ");
            for (size_t i = 0; i < sizeof(long double); ++i)
                offset += snprintf(buf + offset, sizeof(buf) - offset, "%02x ", u_in.bytes[i]);
            diag("%s", buf);
            offset = snprintf(buf, sizeof(buf), "Got     : ");
            for (size_t i = 0; i < sizeof(long double); ++i) {
                int n = snprintf(buf + offset, sizeof(buf) - offset, "%02x ", u_out.bytes[i]);
                if (n < 0 || n >= 1024 - offset)
                    break;
                offset += n;
            }
            diag("%s", buf);
        }
        infix_forward_destroy(trampoline);
    }

#if !defined(INFIX_COMPILER_MSVC)
    subtest("__uint128_t") {
        plan(2);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        __uint128_t input = (((__uint128_t)0xFFFFFFFFFFFFFFFF) << 64) | 0xFFFFFFFFFFFFFFFF;
        __uint128_t result = 0;
        void * args[] = {&input};
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        cif((void *)passthrough_uint128, &result, args);
        ok(result == input, "Value is correct");
        infix_forward_destroy(trampoline);
    }

    subtest("__int128_t") {
        plan(2);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        infix_forward_t * trampoline = NULL;
        infix_status status = infix_forward_create_manual(&trampoline, type, &type, 1, 1);
        ok(status == INFIX_SUCCESS, "Trampoline generated successfully");

        __int128_t input = -(((__int128_t)0x7FFFFFFFFFFFFFFF) << 64) - 1;
        __int128_t result = 0;
        void * args[] = {&input};
        infix_cif_func cif = (infix_cif_func)infix_forward_get_code(trampoline);
        cif((void *)passthrough_sint128, &result, args);
        ok(result == input, "Value is correct");
        infix_forward_destroy(trampoline);
    }
#else
    // If MSVC is used, skip the 128-bit integer tests to satisfy the plan.
    skip(2, "__int128_t and __uint128_t are not supported on MSVC");
#endif
}
