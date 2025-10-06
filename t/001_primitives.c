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
#define TEST_PRIMITIVE(test_name, c_type, infix_id, passthrough_func, input_val, format_specifier)    \
    subtest(test_name) {                                                                              \
        plan(4);                                                                                      \
        infix_type * type = infix_type_create_primitive(infix_id);                                    \
        c_type input = (input_val);                                                                   \
        void * args[] = {&input};                                                                     \
                                                                                                      \
        /* Test Unbound Trampoline */                                                                 \
        infix_forward_t * unbound_t = NULL;                                                           \
        infix_status unbound_s = infix_forward_create_manual(&unbound_t, type, &type, 1, 1);          \
        ok(unbound_s == INFIX_SUCCESS, "Unbound trampoline generated successfully");                  \
                                                                                                      \
        c_type unbound_result = 0;                                                                    \
        infix_cif_func unbound_cif = (infix_cif_func)infix_forward_get_code(unbound_t);               \
        if (unbound_cif) {                                                                            \
            unbound_cif((void *)passthrough_func, &unbound_result, args);                             \
            ok(unbound_result == input,                                                               \
               "Unbound call correct (" format_specifier " == " format_specifier ")",                 \
               input,                                                                                 \
               unbound_result);                                                                       \
        }                                                                                             \
        else                                                                                          \
            fail("Unbound trampoline code pointer was NULL");                                         \
                                                                                                      \
        /* Test Bound Trampoline */                                                                   \
        infix_forward_t * bound_t = NULL;                                                             \
        infix_status bound_s =                                                                        \
            infix_forward_create_bound_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_func); \
        ok(bound_s == INFIX_SUCCESS, "Bound trampoline generated successfully");                      \
                                                                                                      \
        c_type bound_result = 0;                                                                      \
        infix_bound_cif_func bound_cif = (infix_bound_cif_func)infix_forward_get_code(bound_t);       \
        if (bound_cif) {                                                                              \
            bound_cif(&bound_result, args);                                                           \
            ok(bound_result == input,                                                                 \
               "Bound call correct (" format_specifier " == " format_specifier ")",                   \
               input,                                                                                 \
               bound_result);                                                                         \
        }                                                                                             \
        else                                                                                          \
            fail("Bound trampoline code pointer was NULL");                                           \
                                                                                                      \
        infix_forward_destroy(unbound_t);                                                             \
        infix_forward_destroy(bound_t);                                                               \
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
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        long double input = 1.234567890123456789L;
        void * args[] = {&input};

        // Unbound
        infix_forward_t * unbound_t = NULL;
        infix_status unbound_s = infix_forward_create_manual(&unbound_t, type, &type, 1, 1);
        ok(unbound_s == INFIX_SUCCESS, "Unbound trampoline generated successfully");
        long double unbound_result = 0.0L;
        ((infix_cif_func)infix_forward_get_code(unbound_t))((void *)passthrough_long_double, &unbound_result, args);
        ok(unbound_result == input, "Unbound long double correct");

        // Bound
        infix_forward_t * bound_t = NULL;
        infix_status bound_s =
            infix_forward_create_bound_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_long_double);
        ok(bound_s == INFIX_SUCCESS, "Bound trampoline generated successfully");
        long double bound_result = 0.0L;
        ((infix_bound_cif_func)infix_forward_get_code(bound_t))(&bound_result, args);
        ok(bound_result == input, "Bound long double correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }

#if !defined(INFIX_COMPILER_MSVC)
    subtest("__uint128_t") {
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        __uint128_t input = (((__uint128_t)0xFFFFFFFFFFFFFFFF) << 64) | 0xFFFFFFFFFFFFFFFF;
        void * args[] = {&input};

        infix_forward_t * unbound_t = NULL;
        ok(infix_forward_create_manual(&unbound_t, type, &type, 1, 1) == INFIX_SUCCESS, "Unbound created");
        __uint128_t unbound_result = 0;
        ((infix_cif_func)infix_forward_get_code(unbound_t))((void *)passthrough_uint128, &unbound_result, args);
        ok(unbound_result == input, "Unbound correct");

        infix_forward_t * bound_t = NULL;
        ok(infix_forward_create_bound_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_uint128) == INFIX_SUCCESS,
           "Bound created");
        __uint128_t bound_result = 0;
        ((infix_bound_cif_func)infix_forward_get_code(bound_t))(&bound_result, args);
        ok(bound_result == input, "Bound correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }

    subtest("__int128_t") {
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        __int128_t input = -(((__int128_t)0x7FFFFFFFFFFFFFFF) << 64) - 1;
        void * args[] = {&input};

        infix_forward_t * unbound_t = NULL;
        ok(infix_forward_create_manual(&unbound_t, type, &type, 1, 1) == INFIX_SUCCESS, "Unbound created");
        __int128_t unbound_result = 0;
        ((infix_cif_func)infix_forward_get_code(unbound_t))((void *)passthrough_sint128, &unbound_result, args);
        ok(unbound_result == input, "Unbound correct");

        infix_forward_t * bound_t = NULL;
        ok(infix_forward_create_bound_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_sint128) == INFIX_SUCCESS,
           "Bound created");
        __int128_t bound_result = 0;
        ((infix_bound_cif_func)infix_forward_get_code(bound_t))(&bound_result, args);
        ok(bound_result == input, "Bound correct");

        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
#else
    // If MSVC is used, skip the 128-bit integer tests to satisfy the plan.
    skip(2, "__int128_t and __uint128_t are not supported on MSVC");
#endif
}
