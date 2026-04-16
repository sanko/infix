/**
 * @file 890_infix.c
 * @brief Unit test for the Infix programming language compiler.
 * @ingroup test_suite
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "compiler/infix_lang.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char * test_if_basic =
    "var x = 10\n"
    "if (x > 5) {\n"
    "    x = 100\n"
    "}\n";

static const char * test_if_elif_else =
    "var x = 5\n"
    "if (x > 10) {\n"
    "    x = 100\n"
    "}\n"
    "elif (x > 5) {\n"
    "    x = 50\n"
    "}\n"
    "else {\n"
    "    x = 0\n"
    "}\n";

static const char * test_while_loop =
    "var i = 0\n"
    "while (i < 10) {\n"
    "    i = i + 1\n"
    "}\n";

static const char * test_for_loop =
    "var sum = 0\n"
    "for (var i = 0; i < 10; i = i + 1) {\n"
    "    sum = sum + i\n"
    "}\n";

static const char * test_do_while =
    "var i = 0\n"
    "do {\n"
    "    i = i + 1\n"
    "} while (i < 5)\n";

static const char * test_break_continue =
    "var result = 0\n"
    "for (var i = 0; i < 10; i = i + 1) {\n"
    "    if (i == 5) {\n"
    "        break\n"
    "    }\n"
    "    result = result + i\n"
    "}\n";

static const char * test_try_catch =
    "var x = 10\n"
    "try {\n"
    "    throw \"error\"\n"
    "}\n"
    "catch (e) {\n"
    "    x = 20\n"
    "}\n";

static const char * test_try_finally =
    "var x = 0\n"
    "try {\n"
    "    x = 1\n"
    "}\n"
    "finally {\n"
    "    x = x + 10\n"
    "}\n";

static const char * test_function_decl =
    "fn add(a, b) {\n"
    "    return a + b\n"
    "}\n";

static const char * test_function_call =
    "fn double(x) {\n"
    "    return x * 2\n"
    "}\n"
    "var result = double(5)\n";

static const char * test_namespace =
    "namespace Math {\n"
    "    fn add(a, b) {\n"
    "        return a + b\n"
    "    }\n"
    "}\n";

static const char * test_class =
    "class Point {\n"
    "    var x\n"
    "    var y\n"
    "    fn init(x, y) {\n"
    "        this.x = x\n"
    "        this.y = y\n"
    "    }\n"
    "}\n";

static const char * test_fiber =
    "fn coro() {\n"
    "    yield 1\n"
    "    yield 2\n"
    "    return 3\n"
    "}\n";

TEST {
    plan(16);

    subtest("Lexer - Basic tokenization") {
        plan(3);

        lexer_t * lexer = lexer_create("var x = 42;");
        ok(lexer != NULL, "lexer_create returns non-NULL");

        token_t token = lexer_next_token(lexer);
        ok(token.type == TOKEN_VAR, "First token is VAR");

        token = lexer_next_token(lexer);
        ok(token.type == TOKEN_IDENTIFIER, "Second token is IDENTIFIER");

        lexer_destroy(lexer);
    }

    subtest("Parser - Simple var decl") {
        plan(2);

        lexer_t * lexer = lexer_create("var x = 10\n");
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
        ast_free_tree(ast);
    }

    subtest("Parser - If statement") {
        plan(2);

        lexer_t * lexer = lexer_create(test_if_basic);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - If/elif/else") {
        plan(2);

        lexer_t * lexer = lexer_create("var x = 5\nif (x > 10) {\n}\nelif (x > 5) {\n}\nelse {\n}\n");
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - While loop") {
        plan(2);

        lexer_t * lexer = lexer_create(test_while_loop);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - For loop") {
        plan(2);

        lexer_t * lexer = lexer_create(test_for_loop);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Do-while loop") {
        plan(2);

        lexer_t * lexer = lexer_create(test_do_while);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Break/Continue") {
        plan(2);

        lexer_t * lexer = lexer_create(test_break_continue);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Try/Catch") {
        plan(2);

        lexer_t * lexer = lexer_create(test_try_catch);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Try/Finally") {
        plan(2);

        lexer_t * lexer = lexer_create(test_try_finally);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Function declaration") {
        plan(2);

        lexer_t * lexer = lexer_create(test_function_decl);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Function call") {
        plan(2);

        lexer_t * lexer = lexer_create(test_function_call);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Namespace") {
        plan(2);

        lexer_t * lexer = lexer_create(test_namespace);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Class definition") {
        plan(2);

        lexer_t * lexer = lexer_create(test_class);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Fiber/Yield") {
        plan(2);

        lexer_t * lexer = lexer_create(test_fiber);
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }

    subtest("Parser - Array literal") {
        plan(2);

        lexer_t * lexer = lexer_create("var arr = [1, 2, 3]\n");
        parser_t * parser = parser_create(lexer);

        ast_node_t * ast = parser_parse(parser);
        ok(ast != NULL, "Parser creates AST");
        ok(!parser_had_error(parser), "Parser has no errors");

        parser_destroy(parser);
    }
}
