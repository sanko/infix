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
 * @brief Hardened test suite for the high-level v1.0 signature API.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <infix/infix.h>
#include <string.h>

/**
 * @brief Helper subtest to verify that a single type signature string parses correctly.
 */
static void test_type_ok(const char * signature, infix_type_category expected_cat, const char * name) {
    subtest(name) {
        plan(2);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        infix_status status = infix_type_from_signature(&type, &arena, signature);

        ok(status == INFIX_SUCCESS, "Parsing should succeed for '%s'", signature);
        if (status == INFIX_SUCCESS && type)
            ok(type->category == expected_cat, "Type category should be %d (got %d)", expected_cat, type->category);
        else
            fail("Type category check skipped due to parsing failure");
        infix_arena_destroy(arena);
    }
}

/**
 * @brief Helper subtest to verify that an invalid signature string fails to parse.
 */
static void test_type_fail(const char * signature, const char * name) {
    subtest(name) {
        plan(1);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        infix_status status = infix_type_from_signature(&type, &arena, signature);
        ok(status != INFIX_SUCCESS, "Parsing should fail for invalid signature '%s'", signature);
        infix_arena_destroy(arena);
    }
}

void dummy_handler() {}

TEST {
    plan(5);

    subtest("Valid Single Types (v1.0 Syntax)") {
        plan(15);
        test_type_ok("void", INFIX_TYPE_VOID, "void");
        test_type_ok("int32", INFIX_TYPE_PRIMITIVE, "int32");
        test_type_ok("*int32", INFIX_TYPE_POINTER, "pointer to int32");
        test_type_ok("[10:int32]", INFIX_TYPE_ARRAY, "array of int32");
        test_type_ok("*[10:int32]", INFIX_TYPE_POINTER, "pointer to array");
        test_type_ok("[10:*int32]", INFIX_TYPE_ARRAY, "array of pointers");
        test_type_ok("{int32, double}", INFIX_TYPE_STRUCT, "simple struct");
        test_type_ok("<int32, double>", INFIX_TYPE_UNION, "simple union");
        test_type_ok("{int32, <double, *void>}", INFIX_TYPE_STRUCT, "nested aggregate");
        test_type_ok("(int) -> void", INFIX_TYPE_REVERSE_TRAMPOLINE, "simple function pointer");
        test_type_ok("(*void, int32) -> *int32", INFIX_TYPE_REVERSE_TRAMPOLINE, "complex function pointer");
        test_type_ok("*( (int32) -> void )", INFIX_TYPE_POINTER, "pointer to a function type");
        test_type_ok("e:int32", INFIX_TYPE_ENUM, "simple enum");
        test_type_ok("!{char, int64}", INFIX_TYPE_STRUCT, "simple packed struct (pack 1)");
        test_type_ok("struct<MyPoint>{int32, int32}", INFIX_TYPE_STRUCT, "named struct definition");
    }

    subtest("Valid Edge Cases (Whitespace, Nesting, Empty, References)") {
        plan(12);
        test_type_ok("  { #comment \n } ", INFIX_TYPE_STRUCT, "Struct with heavy whitespace and comments");
        test_type_ok("<>", INFIX_TYPE_UNION, "Empty union");
        test_type_ok("{}", INFIX_TYPE_STRUCT, "Empty struct");
        test_type_ok("!{}", INFIX_TYPE_STRUCT, "Empty packed struct");
        test_type_ok("!2:{}", INFIX_TYPE_STRUCT, "Empty packed struct with alignment");
        test_type_ok("*(*((int)->void))", INFIX_TYPE_POINTER, "Pointer to pointer to function");
        test_type_ok("[4:e<Color>:int]", INFIX_TYPE_ARRAY, "Array of named enums");
        test_type_ok("() -> !{char,int}", INFIX_TYPE_REVERSE_TRAMPOLINE, "Function returning a packed struct");
        test_type_ok("({*char, e:int}) -> void", INFIX_TYPE_REVERSE_TRAMPOLINE, "Function taking an anonymous struct");
        test_type_ok("struct<Node>", INFIX_TYPE_NAMED_REFERENCE, "Reference to a named struct");
        test_type_ok("union<Packet>", INFIX_TYPE_NAMED_REFERENCE, "Reference to a named union");
        test_type_ok("{a:int, b:union<U>}", INFIX_TYPE_STRUCT, "Struct with a named union reference member");
    }

    subtest("Valid Full Function Signatures (v1.0 Syntax)") {
        plan(8);  // Increased plan for new variadic tests
        subtest("Simple function: (int32, double) -> int64") {
            plan(4);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * at = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("(int32, double) -> int64", &a, &rt, &at, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 2 && nf == 2, "Correct number of args");
                ok(rt->category == INFIX_TYPE_PRIMITIVE, "Correct return type");
                ok(at[0].type->category == INFIX_TYPE_PRIMITIVE && at[1].type->category == INFIX_TYPE_PRIMITIVE,
                   "Correct arg types");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("No-arg function: () -> void") {
            plan(3);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * at = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("() -> void", &a, &rt, &at, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 0 && nf == 0, "Correct number of args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return type");
            }
            else
                skip(2, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic function with args: (int32; double) -> void") {
            plan(4);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * at = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("(int32; double) -> void", &a, &rt, &at, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 2, "Correct total number of args");
                ok(nf == 1, "Correct number of fixed args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return type");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic function with no variadic args passed: (int32;) -> void") {
            plan(4);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * at = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("(int32;) -> void", &a, &rt, &at, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds for empty variadic part");
            if (s == INFIX_SUCCESS) {
                ok(na == 1, "Correct total number of args");
                ok(nf == 1, "Correct number of fixed args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return type");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic-only function: (;int) -> void") {
            plan(4);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * at = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("(;int) -> void", &a, &rt, &at, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds for variadic-only function");
            if (s == INFIX_SUCCESS) {
                ok(na == 1, "Correct total number of args");
                ok(nf == 0, "Correct number of fixed args (zero)");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return type");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Complex nested function: (*( (int32) -> void )) -> void") {
            plan(4);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * args = NULL;
            size_t na, nf;
            infix_status s = infix_signature_parse("(*((int32) -> void)) -> void", &a, &rt, &args, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 1 && nf == 1, "Has 1 argument");
                ok(args[0].type->category == INFIX_TYPE_POINTER, "Argument is a pointer");
                ok(args[0].type->meta.pointer_info.pointee_type->category == INFIX_TYPE_REVERSE_TRAMPOLINE,
                   "It points to a function type");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("High-level API now active") {
            plan(2);
            infix_forward_t * fwd = NULL;
            infix_status fwd_status = infix_forward_create(&fwd, "() -> void");
            ok(fwd_status == INFIX_SUCCESS, "infix_forward_create now parses successfully");
            infix_forward_destroy(fwd);

            infix_reverse_t * rev = NULL;
            infix_status rev_status = infix_reverse_create(&rev, "() -> void", dummy_handler, NULL);
            ok(rev_status == INFIX_SUCCESS, "infix_reverse_create now parses successfully");
            infix_reverse_destroy(rev);
        }
        subtest("Function with named arguments") {
            plan(6);
            infix_arena_t * a = NULL;
            infix_type * rt = NULL;
            infix_function_argument * args = NULL;
            size_t na, nf;
            const char * sig = "(count: int32, name: *char) -> void";
            infix_status s = infix_signature_parse(sig, &a, &rt, &args, &na, &nf);
            ok(s == INFIX_SUCCESS, "Parsing succeeds for signature with named args");
            if (s == INFIX_SUCCESS) {
                ok(na == 2 && nf == 2, "Correct number of args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return type");
                // Introspection checks for names and types
                ok(strcmp(args[0].name, "count") == 0 && args[0].type->category == INFIX_TYPE_PRIMITIVE,
                   "Arg 0 is 'count: int32'");
                ok(strcmp(args[1].name, "name") == 0 && args[1].type->category == INFIX_TYPE_POINTER,
                   "Arg 1 is 'name: *char'");
                ok(args[1].type->meta.pointer_info.pointee_type->category == INFIX_TYPE_PRIMITIVE,
                   "Arg 1 points to a primitive (char)");
            }
            else
                skip(5, "Detail checks skipped");
            infix_arena_destroy(a);
        }
    }

    subtest("Invalid Syntax and Logic") {
        plan(20);
        test_type_fail("int32 junk", "Junk after valid type");
        test_type_fail("*", "Pointer to nothing");
        test_type_fail("[10:]", "Array with no type after colon");
        test_type_fail("() ->", "Function with no return type");
        test_type_fail("(int32,) -> void", "Trailing comma in arg list");
        test_type_fail("(int32 -> void)", "Missing parentheses around args");
        test_type_fail("e:double", "Enum with non-integer base");
        test_type_fail("{name:}", "Named member with no type");
        test_type_fail("!2:", "Incomplete packed struct definition");
        test_type_fail("[10:void]", "Array of void");
        test_type_fail("{int, void}", "Struct with void member");
        test_type_fail("(int; double; int) -> void", "Multiple variadic separators");
        test_type_fail("(int,;) -> void", "Empty argument before separator");
        test_type_fail("({)}", "Mismatched braces");
        test_type_fail("{[10:int}", "Unclosed struct brace");
        test_type_fail("\"stdcall", "Unclosed annotation string");
        test_type_fail("struct<>{}", "Named struct with empty name");
        test_type_fail("long long", "Space in keyword");
        test_type_fail(" - > ", "Space in arrow");
        test_type_fail("e<>:double", "Named enum with non-integer base");
    }

    subtest("Introspection Checks") {
        plan(1);
        subtest("Complex Introspection") {
            plan(8);
            infix_type * type = NULL;
            infix_arena_t * arena = NULL;
            const char * sig = "*[10:struct<Node>{val:e<V>:int, next:*struct<Node>}]";
            infix_status status = infix_type_from_signature(&type, &arena, sig);
            ok(status == INFIX_SUCCESS, "Parsing complex nested signature succeeds");
            if (status == INFIX_SUCCESS) {
                ok(type->category == INFIX_TYPE_POINTER, "Top level is pointer");
                infix_type * array_type = type->meta.pointer_info.pointee_type;
                ok(array_type && array_type->category == INFIX_TYPE_ARRAY, "Points to an array");
                infix_type * struct_def_type = array_type->meta.array_info.element_type;
                ok(struct_def_type && struct_def_type->category == INFIX_TYPE_STRUCT,
                   "Array element is a struct definition");
                infix_struct_member * member1 = &struct_def_type->meta.aggregate_info.members[0];
                ok(member1->type->category == INFIX_TYPE_ENUM, "Member 1 is an enum");
                infix_struct_member * member2 = &struct_def_type->meta.aggregate_info.members[1];
                ok(member2->type->category == INFIX_TYPE_POINTER, "Member 2 is a pointer");
                infix_type * pointee_type = member2->type->meta.pointer_info.pointee_type;
                ok(pointee_type && pointee_type->category == INFIX_TYPE_NAMED_REFERENCE,
                   "It points to a named reference");
                if (pointee_type)
                    ok(strcmp(pointee_type->meta.named_reference.name, "Node") == 0, "The reference is named 'Node'");
                else
                    fail("Pointee type was null");
            }
            else
                skip(7, "Skipping detail checks");
            infix_arena_destroy(arena);
        }
    }
}
