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
 * @brief Hardened test suite for the high-level signature API.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include <ctype.h>
#include <infix/infix.h>
#include <string.h>

/**
 * @brief Helper subtest to verify that a single type signature string parses correctly.
 */
static void test_type_ok(const char * signature, infix_type_category expected_cat, const char * name) {
    subtest(name) {
        plan(2);
        infix_type * type = nullptr;
        infix_arena_t * arena = nullptr;
        infix_status status = infix_type_from_signature(&type, &arena, signature, nullptr);

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
        infix_type * type = nullptr;
        infix_arena_t * arena = nullptr;
        infix_status status = infix_type_from_signature(&type, &arena, signature, nullptr);
        ok(status != INFIX_SUCCESS, "Parsing should fail for invalid signature '%s'", signature);
        infix_arena_destroy(arena);
    }
}

void dummy_handler() {}

// Helper to remove all whitespace from a string for canonical comparison.
static void normalize_string(char * s) {
    if (!s)
        return;
    char * d = s;
    do {
        while (isspace((unsigned char)*s)) {
            s++;
        }
    } while ((*d++ = *s++));
}

// Updated round-trip test to handle normalization of abstract types.
static void test_print_roundtrip(const char * signature, const char * expected_output) {
    if (!expected_output)
        expected_output = signature;

    subtest(signature) {
        plan(1);
        infix_type * type = NULL;
        infix_arena_t * arena = NULL;
        infix_status status = infix_type_from_signature(&type, &arena, signature, nullptr);

        if (status != INFIX_SUCCESS) {
            fail("Parsing failed, cannot test printing.");
            infix_arena_destroy(arena);
            return;
        }

        char buffer[1024];
        status = infix_type_print(buffer, sizeof(buffer), type, INFIX_DIALECT_SIGNATURE);
        if (status != INFIX_SUCCESS)
            fail("Printing failed.");
        else {
            char expected_normalized[1024];
            char printed_normalized[1024];
            snprintf(expected_normalized, sizeof(expected_normalized), "%s", expected_output);
            snprintf(printed_normalized, sizeof(printed_normalized), "%s", buffer);

            normalize_string(expected_normalized);
            normalize_string(printed_normalized);

            ok(strcmp(expected_normalized, printed_normalized) == 0,
               "Printed string should match expected canonical signature");
            if (strcmp(expected_normalized, printed_normalized) != 0) {
                diag("Original: %s", signature);
                diag("Expected (normalized): %s", expected_normalized);
                diag("Printed  (normalized): %s", printed_normalized);
            }
        }
        infix_arena_destroy(arena);
    }
}

TEST {
    plan(6);

    subtest("Valid Single Types") {
        plan(15);
        test_type_ok("void", INFIX_TYPE_VOID, "void");
        test_type_ok("bool", INFIX_TYPE_PRIMITIVE, "bool");
        test_type_ok("sint32", INFIX_TYPE_PRIMITIVE, "sint32");
        test_type_ok("*sint32", INFIX_TYPE_POINTER, "pointer to sint32");
        test_type_ok("[10:sint32]", INFIX_TYPE_ARRAY, "array of sint32");
        test_type_ok("*[10:sint32]", INFIX_TYPE_POINTER, "pointer to array");
        test_type_ok("[10:*sint32]", INFIX_TYPE_ARRAY, "array of pointers");
        test_type_ok("{sint32, double}", INFIX_TYPE_STRUCT, "simple struct");
        test_type_ok("<sint32, double>", INFIX_TYPE_UNION, "simple union");
        test_type_ok("{sint32, <double, *void>}", INFIX_TYPE_STRUCT, "nested aggregate");
        test_type_ok("(int) -> void", INFIX_TYPE_REVERSE_TRAMPOLINE, "simple function pointer");
        test_type_ok("(*void, sint32) -> *sint32", INFIX_TYPE_REVERSE_TRAMPOLINE, "complex function pointer");
        test_type_ok("*((sint32) -> void)", INFIX_TYPE_POINTER, "pointer to a function type");
        test_type_ok("e:sint32", INFIX_TYPE_ENUM, "simple enum");
        test_type_ok("!{char, sint64}", INFIX_TYPE_STRUCT, "simple packed struct (pack 1)");
    }

    subtest("Valid Edge Cases (Whitespace, Nesting, Empty)") {
        plan(8);
        test_type_ok("  { #comment \n } ", INFIX_TYPE_STRUCT, "Struct with heavy whitespace and comments");
        test_type_ok("<>", INFIX_TYPE_UNION, "Empty union");
        test_type_ok("{}", INFIX_TYPE_STRUCT, "Empty struct");
        test_type_ok("!{}", INFIX_TYPE_STRUCT, "Empty packed struct");
        test_type_ok("!2:{}", INFIX_TYPE_STRUCT, "Empty packed struct with alignment");
        test_type_ok("*(*((int)->void))", INFIX_TYPE_POINTER, "Pointer to pointer to function");
        test_type_ok("() -> !{char,int}", INFIX_TYPE_REVERSE_TRAMPOLINE, "Function returning a packed struct");
        test_type_ok("({*char, e:int}) -> void", INFIX_TYPE_REVERSE_TRAMPOLINE, "Function taking an anonymous struct");
    }

    subtest("Valid Full Function Signatures") {
        plan(8);
        subtest("Simple function: (sint32, double) -> sint64") {
            plan(4);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * at = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("(sint32, double) -> sint64", &a, &rt, &at, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 2 && nf == 2, "Correct arg count");
                ok(rt->category == INFIX_TYPE_PRIMITIVE, "Correct return");
                ok(at[0].type->category == INFIX_TYPE_PRIMITIVE && at[1].type->category == INFIX_TYPE_PRIMITIVE,
                   "Correct arg types");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("No-arg function: () -> void") {
            plan(3);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * at = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("() -> void", &a, &rt, &at, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 0 && nf == 0, "Correct arg count");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return");
            }
            else
                skip(2, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic function with args: (sint32; double) -> void") {
            plan(4);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * at = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("(sint32; double) -> void", &a, &rt, &at, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 2, "Correct total args");
                ok(nf == 1, "Correct fixed args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic function with no variadic args passed: (sint32;) -> void") {
            plan(4);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * at = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("(sint32;) -> void", &a, &rt, &at, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 1, "Correct total args");
                ok(nf == 1, "Correct fixed args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Variadic-only function: (;int) -> void") {
            plan(4);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * at = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("(;int) -> void", &a, &rt, &at, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 1, "Correct total args");
                ok(nf == 0, "Correct fixed args");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("Complex nested function: (*( (sint32) -> void )) -> void") {
            plan(4);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * args = nullptr;
            size_t na, nf;
            infix_status s = infix_signature_parse("(*((sint32) -> void)) -> void", &a, &rt, &args, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds");
            if (s == INFIX_SUCCESS) {
                ok(na == 1 && nf == 1, "Has 1 arg");
                ok(args[0].type->category == INFIX_TYPE_POINTER, "Arg is pointer");
                ok(args[0].type->meta.pointer_info.pointee_type->category == INFIX_TYPE_REVERSE_TRAMPOLINE,
                   "Points to func");
            }
            else
                skip(3, "Detail checks skipped");
            infix_arena_destroy(a);
        }
        subtest("High-level API now active") {
            plan(2);
            infix_forward_t * fwd = nullptr;
            infix_status fwd_status = infix_forward_create_unbound(&fwd, "() -> void", nullptr);
            ok(fwd_status == INFIX_SUCCESS, "infix_forward_create_unbound parses successfully");
            infix_forward_destroy(fwd);
            infix_reverse_t * rev = nullptr;
            infix_status rev_status = infix_reverse_create_callback(&rev, "()->void", (void *)dummy_handler, nullptr);
            ok(rev_status == INFIX_SUCCESS, "infix_reverse_create_callback parses successfully");
            infix_reverse_destroy(rev);
        }
        subtest("Function with named arguments") {
            plan(6);
            infix_arena_t * a = nullptr;
            infix_type * rt = nullptr;
            infix_function_argument * args = nullptr;
            size_t na, nf;
            const char * sig = "(count: sint32, name: *char) -> void";
            infix_status s = infix_signature_parse(sig, &a, &rt, &args, &na, &nf, nullptr);
            ok(s == INFIX_SUCCESS, "Parsing succeeds with named args");
            if (s == INFIX_SUCCESS) {
                ok(na == 2 && nf == 2, "Correct arg count");
                ok(rt->category == INFIX_TYPE_VOID, "Correct return");
                ok(strcmp(args[0].name, "count") == 0 && args[0].type->category == INFIX_TYPE_PRIMITIVE,
                   "Arg 0 correct");
                ok(strcmp(args[1].name, "name") == 0 && args[1].type->category == INFIX_TYPE_POINTER, "Arg 1 correct");
                ok(args[1].type->meta.pointer_info.pointee_type->category == INFIX_TYPE_PRIMITIVE,
                   "Arg 1 points to primitive");
            }
            else
                skip(5, "Detail checks skipped");
            infix_arena_destroy(a);
        }
    }

    subtest("Invalid Syntax and Logic") {
        plan(21);
        test_type_fail("sint32 junk", "Junk after valid type");
        test_type_fail("*", "Pointer to nothing");
        test_type_fail("[10:]", "Array with no type after colon");
        test_type_fail("() ->", "Function with no return type");
        test_type_fail("(sint32,) -> void", "Trailing comma in arg list");
        test_type_fail("(sint32 -> void)", "Missing parentheses around args");
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
        test_type_fail("long long", "Space in keyword");
        test_type_fail(" - > ", "Space in arrow");
        test_type_fail("e<>:double", "Named enum with non-integer base");
        test_type_fail("struct<Foo>{int}", "Old struct<Name> syntax is now invalid");
        test_type_fail("union<Bar><int>", "Old union<Name> syntax is now invalid");
    }

    subtest("Registry Type Introspection") {
        plan(6);
        infix_registry_t * registry = infix_registry_create();
        const char * defs = "@Node = { value: int, next: *@Node };";
        ok(infix_register_types(registry, defs) == INFIX_SUCCESS, "Setup: Registered recursive @Node type");

        infix_type * node_ptr_type = nullptr;
        infix_arena_t * temp_arena = nullptr;
        infix_status status = infix_type_from_signature(&node_ptr_type, &temp_arena, "*@Node", registry);

        if (ok(status == INFIX_SUCCESS, "Parsed `*@Node` using registry")) {
            ok(node_ptr_type->category == INFIX_TYPE_POINTER, "Top level is pointer");
            infix_type * node_type = node_ptr_type->meta.pointer_info.pointee_type;
            ok(node_type && node_type->category == INFIX_TYPE_STRUCT, "Points to a struct");

            const infix_struct_member * next_member = infix_type_get_member(node_type, 1);
            ok(next_member && next_member->type->category == INFIX_TYPE_POINTER, "Member 'next' is a pointer");

            infix_type * next_pointee = next_member->type->meta.pointer_info.pointee_type;
            ok(next_pointee == node_type, "Recursive pointer correctly points to the parent struct type");
        }
        else {
            skip(4, "Skipping detail checks due to parsing failure");
        }

        infix_arena_destroy(temp_arena);
        infix_registry_destroy(registry);
    }

    subtest("Round trip") {
        plan(7);
        test_print_roundtrip("int", "sint32");
        test_print_roundtrip("*[10:{int,float}]", "*[10:{sint32,float}]");
        test_print_roundtrip("<*void, double>", NULL);
        test_print_roundtrip("(*char;int,double)->void", "(*sint8;sint32,double)->void");
        test_print_roundtrip("{<int,char>, *char}", "{<sint32,sint8>,*sint8}");
        test_print_roundtrip("e:longlong", "e:sint64");
        test_print_roundtrip("v[4:float]", NULL);
    }
}
