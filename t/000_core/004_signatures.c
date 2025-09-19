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
 * @file 004_signatures.c
 * @brief Tests the high-level string-based signature API.
 *
 * @details This test suite verifies the functionality and robustness of the
 * `ffi_create_forward_trampoline_from_signature` API. It covers:
 * 1.  Happy Paths: Correctly parsing and generating trampolines for simple
 *     primitive, pointer, and variadic function signatures.
 * 2.  Advanced Packed Structs: Verifying the parsing of the complex
 *     `p(size,align){type:offset;...}` syntax.
 * 3.  Error Handling: Ensuring the parser correctly rejects a wide variety of
 *     malformed and invalid signature strings.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>

/**
 * @brief Helper subtest to verify that a single type signature string parses correctly.
 */
static void test_type_ok(const char * signature, ffi_type_category expected_cat, const char * name) {
    subtest(name) {
        plan(2);
        ffi_type * type = NULL;
        arena_t * arena = NULL;
        ffi_status status = ffi_type_from_signature(&type, &arena, signature);

        ok(status == FFI_SUCCESS, "Parsing should succeed for '%s'", signature);
        if (status == FFI_SUCCESS && type) {
            ok(type->category == expected_cat, "Type category should be %d (got %d)", expected_cat, type->category);
        }
        else {
            fail("Type category check skipped due to parsing failure");
        }
        arena_destroy(arena);
    }
}

/**
 * @brief Helper subtest to verify that an invalid signature string fails to parse.
 */
static void test_type_fail(const char * signature, const char * name) {
    subtest(name) {
        plan(1);
        ffi_type * type = NULL;
        arena_t * arena = NULL;
        ffi_status status = ffi_type_from_signature(&type, &arena, signature);
        ok(status == FFI_ERROR_INVALID_ARGUMENT, "Parsing should fail for invalid signature '%s'", signature);
        arena_destroy(arena);
    }
}

TEST {
    plan(5);

    subtest("Valid Single Type Signatures") {
        plan(15);
        test_type_ok("i", FFI_TYPE_PRIMITIVE, "Simple primitive");
        test_type_ok("e", FFI_TYPE_PRIMITIVE, "Long double primitive");
        test_type_ok("d*", FFI_TYPE_POINTER, "Simple pointer");
        test_type_ok("h***", FFI_TYPE_POINTER, "Deeply nested pointer");
        test_type_ok("{i,d}*", FFI_TYPE_POINTER, "Pointer to struct");
        test_type_ok("[10]s", FFI_TYPE_ARRAY, "Simple array");
        test_type_ok("[5][10]f", FFI_TYPE_ARRAY, "Nested array");
        test_type_ok("[2]i*", FFI_TYPE_ARRAY, "Array of pointers");
        test_type_ok("{i, d, c}", FFI_TYPE_STRUCT, "Simple struct");
        test_type_ok("<i, d, c>", FFI_TYPE_UNION, "Simple union");
        test_type_ok("{i, <f, [10]c>}", FFI_TYPE_STRUCT, "Struct with nested union and array");
        test_type_ok("p(16,8){x@0,x@8}", FFI_TYPE_STRUCT, "Simple packed struct");
        test_type_ok("(i=>v)*", FFI_TYPE_POINTER, "Simple function pointer");
        test_type_ok("(i,d;c*=>v)*", FFI_TYPE_POINTER, "Variadic function pointer");
        test_type_ok("  { i , [ 10 ] d * } * ", FFI_TYPE_POINTER, "Type with extra whitespace");
    }

    subtest("Valid Named Field Signatures") {
        plan(3);

        subtest("Named struct: {id:i, name:c*}") {
            plan(3);
            arena_t * arena = NULL;
            ffi_type * type = NULL;
            ffi_status status = ffi_type_from_signature(&type, &arena, "{id:i, name:c*}");
            ok(status == FFI_SUCCESS, "Parsing succeeds");
            if (status == FFI_SUCCESS && type) {
                ok(strcmp(type->meta.aggregate_info.members[0].name, "id") == 0, "First member name is correct");
                ok(strcmp(type->meta.aggregate_info.members[1].name, "name") == 0, "Second member name is correct");
            }
            else {
                fail("Skipping name checks for struct");
                fail("Skipping name checks for struct");
            }
            arena_destroy(arena);
        }

        subtest("Named packed struct: p(16,8){ptr:c*@0, len:y@8}") {
            plan(3);
            arena_t * arena = NULL;
            ffi_type * type = NULL;
            ffi_status status = ffi_type_from_signature(&type, &arena, "p(16,8){ptr:c*@0, len:y@8}");
            ok(status == FFI_SUCCESS, "Parsing succeeds");
            if (status == FFI_SUCCESS && type) {
                ok(strcmp(type->meta.aggregate_info.members[0].name, "ptr") == 0 &&
                       type->meta.aggregate_info.members[0].offset == 0,
                   "Packed member 1 OK");
                ok(strcmp(type->meta.aggregate_info.members[1].name, "len") == 0 &&
                       type->meta.aggregate_info.members[1].offset == 8,
                   "Packed member 2 OK");
            }
            else {
                fail("Skipping name checks for packed struct");
                fail("Skipping name checks for packed struct");
            }
            arena_destroy(arena);
        }

        test_type_fail("{name:}", "Named field with no type should fail");
    }

    subtest("Invalid Single Type Signatures") {
        plan(12);
        test_type_fail("{i,d", "Unmatched brace");
        test_type_fail("[10f]", "Invalid array syntax (no closing bracket for size)");
        test_type_fail("p(1,1){i@}", "Packed struct member missing offset");
        test_type_fail("i@", "Stray at-symbol");
        test_type_fail("z", "Invalid primitive character");
        test_type_fail("[10]i[5]", "Invalid postfix array specifier");
        test_type_fail("{i,}", "Trailing comma in struct");
        test_type_fail("p(a,b){i@0}", "Non-numeric size/align in packed struct");
        test_type_fail("i*d", "Junk after valid type");
        test_type_fail("=>v", "Function sig element in type context");
        test_type_fail("", "Empty string");
        test_type_fail("{,i}", "Leading comma in struct");
    }

    subtest("Valid Full Function Signatures") {
        plan(6);
// Helper lambda for repetitive tests
#define TEST_SIG(name, sig_str, n_args, n_fixed, ret_cat)                                                             \
    subtest(name) {                                                                                                   \
        plan(4);                                                                                                      \
        arena_t * a = NULL;                                                                                           \
        ffi_type * rt = NULL;                                                                                         \
        ffi_type ** at = NULL;                                                                                        \
        size_t na, nf;                                                                                                \
        ffi_status s = ffi_signature_parse(sig_str, &a, &rt, &at, &na, &nf);                                          \
        ok(s == FFI_SUCCESS, "Parsing succeeds");                                                                     \
        ok(na == n_args, "num_args should be %llu, was %llu", (unsigned long long)n_args, (unsigned long long)na);    \
        ok(nf == n_fixed, "num_fixed should be %llu, was %llu", (unsigned long long)n_fixed, (unsigned long long)nf); \
        if (rt) {                                                                                                     \
            ok(rt->category == ret_cat, "Return type category should be %d", ret_cat);                                \
        }                                                                                                             \
        else {                                                                                                        \
            fail("Return type was null");                                                                             \
        }                                                                                                             \
        arena_destroy(a);                                                                                             \
    }

        TEST_SIG("Simple function", "i, d => v", 2, 2, FFI_TYPE_VOID);
        TEST_SIG("Variadic function", "a*;i,d=>j", 3, 1, FFI_TYPE_PRIMITIVE);
        TEST_SIG("No-arg function", "=>v", 0, 0, FFI_TYPE_VOID);
        TEST_SIG("Variadic only function", ";i,d=>v", 2, 0, FFI_TYPE_VOID);
        TEST_SIG("Kitchen sink function", "{i,d}*, [10]c; p(1,1){c@0} => (i=>v)*", 3, 2, FFI_TYPE_POINTER);
        TEST_SIG("Function with whitespace", "  i , d  =>  v  ", 2, 2, FFI_TYPE_VOID);
    }

    subtest("Invalid Full Function Signatures") {
        plan(5);
        arena_t * arena = NULL;
        ffi_type * ret_type = NULL;
        ffi_type ** arg_types = NULL;
        size_t num_args, num_fixed;

        ok(ffi_signature_parse("i,d v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Signature without '=>' should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("i,d=>", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Signature with no return type should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("i;d;v=>i", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Multiple variadic separators should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("i,=>v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Trailing comma before '=>' should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("i,d=>v junk", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Trailing junk after signature should fail");
        arena_destroy(arena);
    }
}
