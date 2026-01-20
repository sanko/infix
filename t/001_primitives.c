/**
 * @file 001_primitives.c
 * @brief Unit test for creating trampolines for functions with primitive C types.
 * @ingroup test_suite
 *
 * @details This test file verifies the core functionality of the `infix` library for
 * the most fundamental C types (integers, floats, bool). It is a critical
 * "smoke test" that ensures the basic JIT compilation pipeline is working correctly
 * for each supported platform ABI.
 *
 * The test covers the following for each primitive type:
 * - **`infix_forward_create_unbound_manual`**: Creation of an unbound trampoline.
 * - **`infix_forward_create_manual`**: Creation of a bound trampoline.
 * - **Calling:** Correctly calling both unbound and bound trampolines.
 * - **Argument Passing:** Verifying that the primitive argument is passed correctly to the target C function.
 * - **Return Value:** Verifying that the primitive return value is correctly received from the target C function.
 *
 * It uses a "passthrough" C function for each type (e.g., `passthrough_int32`)
 * that simply returns its argument, allowing for a straightforward check of
 * whether the value was transmitted correctly through the FFI boundary.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <infix/infix.h>
#include <inttypes.h>

// A set of simple "passthrough" functions, one for each primitive type.
// These functions simply return their input argument, making it easy to verify
// that the FFI call correctly transmitted the value.
bool passthrough_bool(bool v) { return v; }
uint8_t passthrough_uint8(uint8_t v) { return v; }
int8_t passthrough_sint8(int8_t v) { return v; }
uint16_t passthrough_uint16(uint16_t v) { return v; }
int16_t passthrough_sint16(int16_t v) { return v; }
uint32_t passthrough_uint32(uint32_t v) { return v; }
int32_t passthrough_sint32(int32_t v) { return v; }
uint64_t passthrough_uint64(uint64_t v) { return v; }
int64_t passthrough_sint64(int64_t v) { return v; }
float passthrough_float(float v) { return v; }
double passthrough_double(double v) { return v; }
long double passthrough_long_double(long double v) { return v; }
#if !defined(INFIX_COMPILER_MSVC)
__uint128_t passthrough_uint128(__uint128_t v) { return v; }
__int128_t passthrough_sint128(__int128_t v) { return v; }
#endif
/**
 * @def TEST_PRIMITIVE
 * @brief A macro to generate a complete subtest for a single primitive type.
 *
 * @details This macro automates the repetitive process of testing each primitive
 * type. For a given C type and its corresponding `infix` ID, it generates a
 * subtest that:
 * 1. Creates the `infix_type` for the primitive.
 * 2. Creates and calls an unbound trampoline.
 * 3. Verifies the result of the unbound call.
 * 4. Creates and calls a bound trampoline.
 * 5. Verifies the result of the bound call.
 * This reduces code duplication and makes the test easy to read and extend.
 */
#define TEST_PRIMITIVE(test_name, c_type, infix_id, passthrough_func, input_val, format_specifier)                 \
    subtest(test_name) {                                                                                           \
        plan(4);                                                                                                   \
        infix_type * type = infix_type_create_primitive(infix_id);                                                 \
        c_type input = (input_val);                                                                                \
        void * args[] = {&input};                                                                                  \
        /* Test the unbound trampoline */                                                                          \
        infix_forward_t * unbound_t = nullptr;                                                                     \
        infix_status unbound_s = infix_forward_create_unbound_manual(&unbound_t, type, &type, 1, 1);               \
        ok(unbound_s == INFIX_SUCCESS, "Unbound trampoline generated successfully");                               \
        c_type unbound_result = 0;                                                                                 \
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);                            \
        if (unbound_cif) {                                                                                         \
            unbound_cif((void *)passthrough_func, &unbound_result, args);                                          \
            ok(unbound_result == input,                                                                            \
               "Unbound call correct (" format_specifier " == " format_specifier ")",                              \
               input,                                                                                              \
               unbound_result);                                                                                    \
        }                                                                                                          \
        else                                                                                                       \
            fail("Unbound trampoline code pointer was nullptr");                                                   \
        /* Test the bound trampoline */                                                                            \
        infix_forward_t * bound_t = nullptr;                                                                       \
        infix_status bound_s = infix_forward_create_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_func); \
        ok(bound_s == INFIX_SUCCESS, "Bound trampoline generated successfully");                                   \
        c_type bound_result = 0;                                                                                   \
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);                                                \
        if (bound_cif) {                                                                                           \
            bound_cif(&bound_result, args);                                                                        \
            ok(bound_result == input,                                                                              \
               "Bound call correct (" format_specifier " == " format_specifier ")",                                \
               input,                                                                                              \
               bound_result);                                                                                      \
        }                                                                                                          \
        else                                                                                                       \
            fail("Bound trampoline code pointer was nullptr");                                                     \
        infix_forward_destroy(unbound_t);                                                                          \
        infix_forward_destroy(bound_t);                                                                            \
    }
TEST {
    plan(14);  // One test for each primitive type subtest.
    // Test fundamental integer and boolean types.
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
    // Test floating-point types.
    TEST_PRIMITIVE("float", float, INFIX_PRIMITIVE_FLOAT, passthrough_float, 3.14159f, "%f");
    TEST_PRIMITIVE("double", double, INFIX_PRIMITIVE_DOUBLE, passthrough_double, 2.718281828459045, "%f");
    // `long double` has a unique representation on some platforms (e.g., 80-bit on SysV x64),
    // so it gets a dedicated subtest instead of using the macro.
    subtest("long double") {
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
        long double input = 1.234567890123456789L;
        void * args[] = {&input};
        infix_forward_t * unbound_t = nullptr;
        infix_status unbound_s = infix_forward_create_unbound_manual(&unbound_t, type, &type, 1, 1);
        ok(unbound_s == INFIX_SUCCESS, "Unbound trampoline generated successfully");
        long double unbound_result = 0.0L;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)passthrough_long_double, &unbound_result, args);
        ok(unbound_result == input, "Unbound long double correct");
        infix_forward_t * bound_t = nullptr;
        infix_status bound_s =
            infix_forward_create_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_long_double);
        ok(bound_s == INFIX_SUCCESS, "Bound trampoline generated successfully");
        long double bound_result = 0.0L;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result == input, "Bound long double correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
#if !defined(INFIX_COMPILER_MSVC)
    // 128-bit integers are a GCC/Clang extension and not supported on MSVC.
    subtest("__uint128_t") {
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
        __uint128_t input = (((__uint128_t)0xFFFFFFFFFFFFFFFF) << 64) | 0xFFFFFFFFFFFFFFFF;
        void * args[] = {&input};
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, type, &type, 1, 1) == INFIX_SUCCESS, "Unbound created");
        __uint128_t unbound_result = 0;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)passthrough_uint128, &unbound_result, args);
        ok(unbound_result == input, "Unbound correct");
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_uint128) == INFIX_SUCCESS,
           "Bound created");
        __uint128_t bound_result = 0;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result == input, "Bound correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
    subtest("__int128_t") {
        plan(4);
        infix_type * type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
        __int128_t input = -(((__int128_t)0x7FFFFFFFFFFFFFFF) << 64) - 1;
        void * args[] = {&input};
        infix_forward_t * unbound_t = nullptr;
        ok(infix_forward_create_unbound_manual(&unbound_t, type, &type, 1, 1) == INFIX_SUCCESS, "Unbound created");
        __int128_t unbound_result = 0;
        infix_unbound_cif_func unbound_cif = infix_forward_get_unbound_code(unbound_t);
        unbound_cif((void *)passthrough_sint128, &unbound_result, args);
        ok(unbound_result == input, "Unbound correct");
        infix_forward_t * bound_t = nullptr;
        ok(infix_forward_create_manual(&bound_t, type, &type, 1, 1, (void *)passthrough_sint128) == INFIX_SUCCESS,
           "Bound created");
        __int128_t bound_result = 0;
        infix_cif_func bound_cif = infix_forward_get_code(bound_t);
        bound_cif(&bound_result, args);
        ok(bound_result == input, "Bound correct");
        infix_forward_destroy(unbound_t);
        infix_forward_destroy(bound_t);
    }
#else
    // If on MSVC, explicitly skip these tests.
    skip(2, "__int128_t and __uint128_t are not supported on MSVC");
#endif
}
