/**
 * @file parser.c
 * @brief Stub parser implementation - replace with actual implementation as needed.
 */
#include "compiler/infix_lang.h"

parser_t * parser_create(lexer_t * lexer) {
    (void)lexer;
    return NULL;
}

void parser_destroy(parser_t * parser) { (void)parser; }

ast_node_t * parser_parse(parser_t * parser) {
    (void)parser;
    return NULL;
}

bool parser_had_error(parser_t * parser) {
    (void)parser;
    return true;
}

const char * parser_get_error(parser_t * parser) {
    (void)parser;
    return "Parser not implemented";
}

void ast_free_tree(ast_node_t * node) { (void)node; }
