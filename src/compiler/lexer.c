/**
 * @file lexer.c
 * @brief Stub lexer implementation - replace with actual implementation as needed.
 */
#include "compiler/infix_lang.h"

lexer_t * lexer_create(const char * source) {
    (void)source;
    return NULL;
}

void lexer_destroy(lexer_t * lexer) { (void)lexer; }

token_t lexer_next_token(lexer_t * lexer) {
    (void)lexer;
    token_t tok = {TOKEN_EOF, NULL, 0, 0, {0}};
    return tok;
}
