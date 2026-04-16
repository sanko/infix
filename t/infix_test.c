/**
 * @file infix_test.c
 * @brief Test harness for the Infix compiler
 */

#include "compiler/infix_lang.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char * test_source =
    "var x = 10\n"
    "var y = 20\n"
    "var sum = x + y\n"
    "sum\n";

static const char * test_factorial =
    "fn factorial(n) {\n"
    "    var result = 1\n"
    "    var i = 1\n"
    "    while (i <= n) {\n"
    "        result = result * i\n"
    "        i = i + 1\n"
    "    }\n"
    "    return result\n"
    "}\n"
    "factorial(5)\n";

static const char * test_fibonacci =
    "fn fib(n) {\n"
    "    if (n <= 0) { return 0 }\n"
    "    if (n == 1) { return 1 }\n"
    "    var a = 0\n"
    "    var b = 1\n"
    "    var i = 2\n"
    "    while (i <= n) {\n"
    "        var temp = a + b\n"
    "        a = b\n"
    "        b = temp\n"
    "        i = i + 1\n"
    "    }\n"
    "    return b\n"
    "}\n"
    "fib(10)\n";

static const char * test_if_else =
    "var x = 10\n"
    "var result = 0\n"
    "if (x > 5) {\n"
    "    result = 100\n"
    "} else {\n"
    "    result = 200\n"
    "}\n"
    "result\n";

static const char * test_array =
    "var arr = [1, 2, 3, 4, 5]\n"
    "arr.length\n";

static const char * test_closure =
    "fn make_adder(n) {\n"
    "    fn adder(x) {\n"
    "        return x + n\n"
    "    }\n"
    "    return adder\n"
    "}\n"
    "var add5 = make_adder(5)\n"
    "add5(10)\n";

static int run_test(const char * name, const char * source) {
    printf("Running test: %s\n", name);

    lexer_t * lexer = lexer_create(source);
    if (!lexer) {
        printf("  FAIL: Could not create lexer\n");
        return 1;
    }

    printf("  Lexer created successfully\n");

    // Test tokenization
    token_t token;
    int token_count = 0;
    do {
        token = lexer_next_token(lexer);
        token_count++;
        if (token.type == TOKEN_ERROR) {
            printf("  FAIL: Lexer error at line %d: %s\n", token.line, token.lexeme);
            lexer_destroy(lexer);
            return 1;
        }
    } while (token.type != TOKEN_EOF);

    printf("  Lexer: %d tokens processed\n", token_count - 1);
    lexer_destroy(lexer);

    // Test parsing
    lexer = lexer_create(source);
    parser_t * parser = parser_create(lexer);
    ast_node_t * ast = parser_parse(parser);

    if (parser_had_error(parser)) {
        printf("  FAIL: Parse error: %s\n", parser_get_error(parser));
        parser_destroy(parser);
        return 1;
    }

    printf("  Parser: AST created successfully\n");

    // Test semantic analysis and code generation
    sema_t * sema = sema_create();
    codegen_t * cg = codegen_create(sema);
    function_t * entry = codegen_compile(cg, ast);

    if (codegen_had_error(cg)) {
        printf("  FAIL: Codegen error: %s\n", codegen_get_error(cg));
        codegen_destroy(cg);
        sema_destroy(sema);
        parser_destroy(parser);
        ast_free_tree(ast);
        return 1;
    }

    printf("  Codegen: Bytecode generated successfully\n");

    // Test VM execution
    vm_t * vm = vm_create(1024 * 1024);
    vm_object_t * result = vm_execute(vm, entry);

    if (result)
        printf("  VM: Execution completed\n");

    vm_destroy(vm);
    codegen_destroy(cg);
    sema_destroy(sema);
    parser_destroy(parser);
    ast_free_tree(ast);

    printf("  PASS\n\n");
    return 0;
}

int main(int argc, char ** argv) {
    printf("=== Infix Programming Language Test Suite ===\n\n");

    int passed = 0;
    int total = 0;

    total++;
    if (run_test("Basic arithmetic", test_source) == 0)
        passed++;
    total++;
    if (run_test("Factorial", test_factorial) == 0)
        passed++;
    total++;
    if (run_test("Fibonacci", test_fibonacci) == 0)
        passed++;
    total++;
    if (run_test("If/Else", test_if_else) == 0)
        passed++;
    total++;
    if (run_test("Arrays", test_array) == 0)
        passed++;
    total++;
    if (run_test("Closures", test_closure) == 0)
        passed++;

    printf("=== Test Results: %d/%d passed ===\n", passed, total);

    return passed == total ? 0 : 1;
}
