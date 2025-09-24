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
 *     `p(size,align){type@offset...}` syntax.
 * 3.  Detailed Function Pointers: Verifying that function pointer types are
 *     parsed recursively into detailed `FFI_TYPE_REVERSE_TRAMPOLINE` types.
 * 4.  Error Handling: Ensuring the parser correctly rejects a wide variety of
 *     malformed and invalid signature strings.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <string.h>

// This must match the internal definition in signature.c to test the boundary correctly.
#define MAX_RECURSION_DEPTH 32

// Use preprocessor macros for compile-time constants to ensure MSVC compatibility.
#define SAFE_NESTING_DEPTH ((MAX_RECURSION_DEPTH / 2) - 1)
#define OVERFLOW_NESTING_DEPTH (SAFE_NESTING_DEPTH + 1)

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
        else
            fail("Type category check skipped due to parsing failure");
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
    plan(9);

    subtest("Valid Single Type Signatures") {
        plan(18);
        test_type_ok("v", FFI_TYPE_VOID, "Simple void");
        test_type_ok("i", FFI_TYPE_PRIMITIVE, "Simple primitive");
        test_type_ok("e", FFI_TYPE_PRIMITIVE, "Long double primitive");
        test_type_ok("d*", FFI_TYPE_POINTER, "Simple pointer");
        test_type_ok("h***", FFI_TYPE_POINTER, "Deeply nested pointer");
        test_type_ok("{i,d}*", FFI_TYPE_POINTER, "Pointer to struct");
        test_type_ok("[10]s", FFI_TYPE_ARRAY, "Simple array");
        test_type_ok("[5][10]f", FFI_TYPE_ARRAY, "Nested array");
        test_type_ok("[2]i*", FFI_TYPE_ARRAY, "Array of pointers");
        test_type_ok("([10]i)*", FFI_TYPE_POINTER, "Pointer to array");
        test_type_ok("{i, d, c}", FFI_TYPE_STRUCT, "Simple struct");
        test_type_ok("<i, d, c>", FFI_TYPE_UNION, "Simple union");
        test_type_ok("{i, <f, [10]c>}", FFI_TYPE_STRUCT, "Struct with nested union and array");
        test_type_ok("p(16,8){x@0,x@8}", FFI_TYPE_STRUCT, "Simple packed struct");
        // A raw function pointer is now its own category.
        test_type_ok("(i=>v)", FFI_TYPE_REVERSE_TRAMPOLINE, "Simple function pointer");
        // A pointer TO a function pointer is still a regular pointer.
        test_type_ok("(i,d;c*=>v)*", FFI_TYPE_POINTER, "Pointer to variadic function pointer");
        test_type_ok("  { i , [ 10 ] d * } * ", FFI_TYPE_POINTER, "Type with extra whitespace");
        test_type_ok("([2](i*))*", FFI_TYPE_POINTER, "Pointer to array of pointers");
    }

    subtest("Detailed Function Pointer Parsing") {
        plan(6);
        const char * signature = "(i,d*=>{c,s})";
        ffi_type * type = NULL;
        arena_t * arena = NULL;
        ffi_status status = ffi_type_from_signature(&type, &arena, signature);

        ok(status == FFI_SUCCESS, "Parsing function pointer type succeeds");
        if (status != FFI_SUCCESS || !type) {
            fail("Skipping detail checks due to parse failure");
            fail("Skipping detail checks");
            fail("Skipping detail checks");
            fail("Skipping detail checks");
            fail("Skipping detail checks");
        }
        else {
            ok(type->category == FFI_TYPE_REVERSE_TRAMPOLINE, "Category is REVERSE_TRAMPOLINE");

            ffi_type * ret_type = type->meta.func_ptr_info.return_type;
            ffi_type ** arg_types = type->meta.func_ptr_info.arg_types;

            ok(type->meta.func_ptr_info.num_args == 2, "Has correct number of arguments (2)");
            ok(ret_type && ret_type->category == FFI_TYPE_STRUCT, "Return type is correct (struct)");
            ok(arg_types && arg_types[0] && arg_types[0]->category == FFI_TYPE_PRIMITIVE,
               "Arg 1 is correct (primitive)");
            ok(arg_types && arg_types[1] && arg_types[1]->category == FFI_TYPE_POINTER, "Arg 2 is correct (pointer)");
        }
        arena_destroy(arena);
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
        plan(14);
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
        test_type_fail("([10]i", "Unmatched grouping parenthesis");
        test_type_fail("[10]i)", "Stray closing parenthesis");
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
        ok(s == FFI_SUCCESS, "Parsing succeeds for '%s'", sig_str);                                                   \
        ok(na == n_args, "num_args should be %llu, was %llu", (unsigned long long)n_args, (unsigned long long)na);    \
        ok(nf == n_fixed, "num_fixed should be %llu, was %llu", (unsigned long long)n_fixed, (unsigned long long)nf); \
        if (rt)                                                                                                       \
            ok(rt->category == ret_cat, "Return type category should be %d", ret_cat);                                \
        else                                                                                                          \
            fail("Return type was null");                                                                             \
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

    subtest("Parser Security Hardening") {
        plan(2);

        // Build a deeply nested signature string that is JUST UNDER the limit.
        // For each level of nesting (e.g., `{...}`), the parser calls `parse_type`,
        // which then calls `parse_aggregate`, so the effective depth is ~2N.
        // The guard is `depth > 32`, so the max allowed depth is 32.
        // Therefore, the max nesting level is (32 / 2) - 1 = 15.
        char deep_sig[SAFE_NESTING_DEPTH * 2 + 2];
        char * p = deep_sig;
        for (int i = 0; i < SAFE_NESTING_DEPTH; ++i)
            *p++ = '{';
        *p++ = 'i';
        for (int i = 0; i < SAFE_NESTING_DEPTH; ++i)
            *p++ = '}';
        *p = '\0';

        test_type_ok(deep_sig, FFI_TYPE_STRUCT, "Type nested to a safe depth should pass");

        // Build a signature that is one level too deep.
        char overflow_sig[OVERFLOW_NESTING_DEPTH * 2 + 2];
        p = overflow_sig;
        for (int i = 0; i < OVERFLOW_NESTING_DEPTH; ++i)
            *p++ = '{';
        *p++ = 'i';
        for (int i = 0; i < OVERFLOW_NESTING_DEPTH; ++i)
            *p++ = '}';
        *p = '\0';
        test_type_fail(overflow_sig, "Type nested beyond the safe depth should fail");
    }

    subtest("Complex and Edge Case Signatures") {
        plan(7);
        test_type_ok("(([10]([5]i*))*)**", FFI_TYPE_POINTER, "Deeply nested mixed pointer/array types");
        test_type_ok("{i,(i=>v)*}", FFI_TYPE_STRUCT, "Struct with function pointer member");
        test_type_ok("[3]p(9,1){c@0,x@1}", FFI_TYPE_ARRAY, "Array of packed structs");
        test_type_ok("([3]p(9,1){c@0,x@1})*", FFI_TYPE_POINTER, "Pointer to array of packed structs");

        TEST_SIG("Whitespace torture test",
                 "  ( [2] { i, d* } )*  * , [5]< a , b > ;  p(1,1){c@0}  => v  ",
                 3,
                 2,
                 FFI_TYPE_VOID);
        TEST_SIG("Empty argument list but valid", "=>v", 0, 0, FFI_TYPE_VOID);

        subtest("Function with function pointer argument: (i=>i),i=>i") {
            plan(6);
            arena_t * a = NULL;
            ffi_type * rt = NULL;
            ffi_type ** at = NULL;
            size_t na, nf;
            ffi_status s = ffi_signature_parse("(i=>i),i=>i", &a, &rt, &at, &na, &nf);
            ok(s == FFI_SUCCESS, "Parsing succeeds");
            if (s == FFI_SUCCESS) {
                ok(na == 2, "Has 2 arguments");
                ok(nf == 2, "Has 2 fixed arguments");
                ok(rt && rt->category == FFI_TYPE_PRIMITIVE, "Return type is primitive");
                ok(at[0] && at[0]->category == FFI_TYPE_REVERSE_TRAMPOLINE, "Arg 1 is a function pointer");
                ok(at[1] && at[1]->category == FFI_TYPE_PRIMITIVE, "Arg 2 is a primitive");
            }
            else {
                fail("Skipping detail checks due to parse failure");
                fail("Skipping detail checks due to parse failure");
                fail("Skipping detail checks due to parse failure");
                fail("Skipping detail checks due to parse failure");
                fail("Skipping detail checks due to parse failure");
            }
            arena_destroy(a);
        }
    }

    subtest("Invalid Edge Case Signatures") {
        plan(9);
        test_type_fail("()", "Empty grouping");
        test_type_fail("p(1,1){}", "Empty packed struct members");
        test_type_fail("(i=>v", "Unmatched parens in function pointer");
        test_type_fail("[10 junk]i", "Junk inside array specifier");
        test_type_fail("{i@4}", "Offset on non-packed member");

        arena_t * arena = NULL;
        ffi_type * ret_type = NULL;
        ffi_type ** arg_types = NULL;
        size_t num_args, num_fixed;
        ok(ffi_signature_parse("i;;d=>v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Double variadic separator should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("i,;d=>v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Variadic separator in wrong place should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("p(1,1)=>v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Incomplete packed struct should fail");
        arena_destroy(arena);
        ok(ffi_signature_parse("name:i=>v", &arena, &ret_type, &arg_types, &num_args, &num_fixed) ==
               FFI_ERROR_INVALID_ARGUMENT,
           "Named primitive argument should fail");
        arena_destroy(arena);
    }
}
