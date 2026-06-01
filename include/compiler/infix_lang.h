/**
 * @file infix_lang.h
 * @brief Infix Programming Language - Compiler Design
 *
 * A modern compiled scripting language targeting x86-64 via the emit library.
 * Features: OOP, fibers, exceptions, closures, namespaces
 */
#ifndef INFIX_LANG_H
#define INFIX_LANG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * LEXER (Tokenizer)
 * ============================================================================*/

typedef enum {
    /* Literals */
    TOKEN_INTEGER,
    TOKEN_FLOAT,
    TOKEN_STRING,
    TOKEN_IDENTIFIER,
    TOKEN_TRUE,
    TOKEN_FALSE,
    TOKEN_NULL,

    /* Keywords */
    TOKEN_NAMESPACE,
    TOKEN_CLASS,
    TOKEN_FN,
    TOKEN_VAR,
    TOKEN_CONST,
    TOKEN_IF,
    TOKEN_ELIF,
    TOKEN_ELSE,
    TOKEN_WHILE,
    TOKEN_FOR,
    TOKEN_DO,
    TOKEN_RETURN,
    TOKEN_BREAK,
    TOKEN_CONTINUE,
    TOKEN_THROW,
    TOKEN_TRY,
    TOKEN_CATCH,
    TOKEN_FINALLY,
    TOKEN_YIELD,
    TOKEN_AWAIT,
    TOKEN_IMPORT,
    TOKEN_EXPORT,
    TOKEN_PUBLIC,
    TOKEN_PRIVATE,
    TOKEN_STATIC,
    TOKEN_FIBER,
    TOKEN_NOT,
    TOKEN_AND,
    TOKEN_OR,

    /* Operators */
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_STAR,
    TOKEN_SLASH,
    TOKEN_PERCENT,
    TOKEN_AMPERSAND,
    TOKEN_PIPE,
    TOKEN_CARET,
    TOKEN_TILDE,
    TOKEN_BANG,
    TOKEN_QUESTION,
    TOKEN_COLON,
    TOKEN_SEMICOLON,
    TOKEN_COMMA,
    TOKEN_DOT,
    TOKEN_ARROW,
    TOKEN_EQ,
    TOKEN_EQEQ,
    TOKEN_BANGEQ,
    TOKEN_LT,
    TOKEN_LTEQ,
    TOKEN_GT,
    TOKEN_GTEQ,
    TOKEN_AMPAMP,
    TOKEN_PIPEPIPE,
    TOKEN_PLUSPLUS,
    TOKEN_MINUSMINUS,
    TOKEN_PLUSEQ,
    TOKEN_MINUSEQ,
    TOKEN_STAREQ,
    TOKEN_SLASHEQ,

    /* Delimiters */
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_LBRACKET,
    TOKEN_RBRACKET,

    /* Special */
    TOKEN_EOF,
    TOKEN_ERROR,
    TOKEN_COMMENT,
    TOKEN_NEWLINE
} token_type_t;

typedef struct {
    token_type_t type;
    char * lexeme;
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char * string_val;
    };
} infix_token_t;

typedef struct {
    const char * source;
    size_t length;
    size_t position;
    int line;
    int column;
    infix_token_t current_token;
    infix_token_t previous_token;
} lexer_t;

lexer_t * lexer_create(const char * source);
void lexer_destroy(lexer_t * lexer);
infix_token_t lexer_next_token(lexer_t * lexer);
infix_token_t lexer_peek(lexer_t * lexer);
bool lexer_match(lexer_t * lexer, token_type_t type);
bool lexer_expect(lexer_t * lexer, token_type_t type, const char * error_msg);

/* ============================================================================
 * AST (Abstract Syntax Tree)
 * ============================================================================*/

typedef enum {
    AST_PROGRAM,
    AST_NAMESPACE_DECL,
    AST_CLASS_DECL,
    AST_FUNCTION_DECL,
    AST_PARAM_LIST,
    AST_VAR_DECL,
    AST_CONST_DECL,
    AST_BLOCK,
    AST_IF_STMT,
    AST_WHILE_STMT,
    AST_FOR_STMT,
    AST_DO_WHILE_STMT,
    AST_RETURN_STMT,
    AST_BREAK_STMT,
    AST_CONTINUE_STMT,
    AST_THROW_STMT,
    AST_TRY_STMT,
    AST_EXPR_STMT,
    AST_YIELD_STMT,

    /* Expressions */
    AST_BINARY_EXPR,
    AST_UNARY_EXPR,
    AST_CALL_EXPR,
    AST_INDEX_EXPR,
    AST_MEMBER_EXPR,
    AST_ASSIGNMENT,
    AST_TERNARY_EXPR,
    AST_IDENTIFIER,
    AST_INTEGER_LITERAL,
    AST_FLOAT_LITERAL,
    AST_STRING_LITERAL,
    AST_BOOL_LITERAL,
    AST_NULL_LITERAL,
    AST_ARRAY_LITERAL,
    AST_OBJECT_LITERAL,
    AST_LAMBDA_EXPR,
    AST_NEW_EXPR,
    AST_THIS_EXPR,
    AST_SUPER_EXPR,
    AST_FIBER_EXPR,
    AST_AWAIT_EXPR,
    AST_METHOD_CALL
} ast_node_type_t;

typedef struct ast_node {
    ast_node_type_t type;
    int line;
    int column;
    struct ast_node * next; /* Sibling in linked lists */

    union {
        /* Program */
        struct {
            struct ast_node * declarations;
        } program;

        /* Namespace */
        struct {
            char * name;
            struct ast_node * declarations;
        } namespace_decl;

        /* Class */
        struct {
            char * name;
            char * superclass;
            struct ast_node * fields;
            struct ast_node * methods;
        } class_decl;

        /* Function */
        struct {
            char * name;
            struct ast_node * params;
            struct ast_node * body;
            struct ast_node * local_decls;
            int stack_frame_size;
        } function_decl;

        /* Parameters */
        struct {
            char * name;
            char * type_hint;
            bool is_variadic;
        } param;

        /* Variable/Constant */
        struct {
            char * name;
            struct ast_node * initializer;
            bool is_static;
            bool is_public;
        } var_decl;

        /* Block */
        struct {
            struct ast_node * statements;
        } block;

        /* If/Elif/Else */
        struct {
            struct ast_node * condition;
            struct ast_node * then_branch;
            struct ast_node * elif_list;
            struct ast_node * else_branch;
        } if_stmt;

        /* While loop */
        struct {
            struct ast_node * condition;
            struct ast_node * body;
        } while_stmt;

        /* For loop */
        struct {
            struct ast_node * initializer;
            struct ast_node * condition;
            struct ast_node * increment;
            struct ast_node * body;
        } for_stmt;

        /* Do-While loop */
        struct {
            struct ast_node * body;
            struct ast_node * condition;
        } do_while_stmt;

        /* Try/Catch */
        struct {
            struct ast_node * try_block;
            char * catch_var;
            struct ast_node * catch_block;
            struct ast_node * finally_block;
        } try_stmt;

        /* Return */
        struct {
            struct ast_node * value;
        } return_stmt;

        /* Throw */
        struct {
            struct ast_node * exception;
        } throw_stmt;

        /* Yield */
        struct {
            struct ast_node * value;
        } yield_stmt;

        /* Binary expression */
        struct {
            token_type_t operator;
            struct ast_node * left;
            struct ast_node * right;
        } binary_expr;

        /* Unary expression */
        struct {
            token_type_t operator;
            struct ast_node * operand;
            bool is_prefix;
        } unary_expr;

        /* Ternary expression */
        struct {
            struct ast_node * condition;
            struct ast_node * then_expr;
            struct ast_node * else_expr;
        } ternary_expr;

        /* Function call */
        struct {
            struct ast_node * callee;
            struct ast_node * arguments;
        } call_expr;

        /* Assignment */
        struct {
            struct ast_node * target;
            token_type_t operator;
            struct ast_node * value;
        } assignment;

        /* Identifier */
        struct {
            char * name;
        } identifier;

        /* Literals */
        struct {
            union {
                int64_t int_val;
                double float_val;
                char * string_val;
            };
        } literal;

        /* Array literal */
        struct {
            struct ast_node * elements;
        } array_literal;

        /* Object literal */
        struct {
            struct ast_node * properties;
        } object_literal;

        /* Property */
        struct {
            char * key;
            struct ast_node * value;
        } property;

        /* Lambda */
        struct {
            struct ast_node * params;
            struct ast_node * body;
        } lambda_expr;

        /* New instance */
        struct {
            struct ast_node * class_name;
            struct ast_node * arguments;
        } new_expr;

        /* Fiber (coroutine) */
        struct {
            struct ast_node * body;
        } fiber_expr;

        /* Member access */
        struct {
            struct ast_node * object;
            char * member;
        } member_expr;

        /* Index access */
        struct {
            struct ast_node * object;
            struct ast_node * index;
        } index_expr;

        /* Method call */
        struct {
            struct ast_node * object;
            char * method;
            struct ast_node * arguments;
        } method_call;
    };
} ast_node_t;

ast_node_t * ast_create_node(ast_node_type_t type);
void ast_free_node(ast_node_t * node);
void ast_free_tree(ast_node_t * root);

/* ============================================================================
 * PARSER
 * ============================================================================*/

typedef struct {
    lexer_t * lexer;
    infix_token_t current;
    infix_token_t previous;
    bool had_error;
    char error_message[256];
} parser_t;

parser_t * parser_create(lexer_t * lexer);
void parser_destroy(parser_t * parser);
ast_node_t * parser_parse(parser_t * parser);
bool parser_had_error(parser_t * parser);
const char * parser_get_error(parser_t * parser);

/* ============================================================================
 * SYMBOL TABLE & TYPE SYSTEM
 * ============================================================================*/

typedef enum {
    TYPE_VOID,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_OBJECT,
    TYPE_ARRAY,
    TYPE_FUNCTION,
    TYPE_FIBER,
    TYPE_CLASS,
    TYPE_NULL,
    TYPE_ANY
} type_kind_t;

typedef struct type {
    type_kind_t kind;
    char * class_name;          /* For TYPE_CLASS */
    struct type * element_type; /* For TYPE_ARRAY */
    struct type * return_type;  /* For TYPE_FUNCTION */
    struct type * param_types;  /* For TYPE_FUNCTION */
    int param_count;
} type_t;

typedef enum {
    SYM_VARIABLE,
    SYM_CONSTANT,
    SYM_FUNCTION,
    SYM_METHOD,
    SYM_CLASS,
    SYM_NAMESPACE,
    SYM_PARAMETER,
    SYM_LABEL,
    SYM_FIBER
} symbol_kind_t;

typedef struct symbol {
    char * name;
    symbol_kind_t kind;
    type_t * type;
    int stack_offset;
    int depth;
    bool is_captured;
    bool is_static;
    bool is_public;
    bool is_defined;
    ast_node_t * ast_node;
    struct symbol * next;
} symbol_t;

typedef struct scope {
    char * name;
    struct scope * parent;
    struct scope * child;
    symbol_t * symbols;
    int depth;
    int local_count;
    int max_locals;
    int stack_size;
} scope_t;

typedef struct {
    scope_t * current_scope;
    scope_t * global_scope;
    type_t ** types;
    int type_count;
    symbol_t * function_symbols;
    int label_counter;
    int stack_depth;
} sema_t;

sema_t * sema_create(void);
void sema_destroy(sema_t * sema);
scope_t * sema_push_scope(sema_t * sema, const char * name);
void sema_pop_scope(sema_t * sema);
symbol_t * sema_define(sema_t * sema, const char * name, symbol_kind_t kind, type_t * type);
symbol_t * sema_lookup(sema_t * sema, const char * name);
bool sema_analyze(sema_t * sema, ast_node_t * root);
type_t * sema_get_type(sema_t * sema, ast_node_t * node);
const char * sema_get_error(sema_t * sema);

/* ============================================================================
 * BYTECODE / CODE GENERATION
 * ============================================================================*/

typedef enum {
    OP_HALT,
    OP_LOAD_NULL,
    OP_LOAD_TRUE,
    OP_LOAD_FALSE,
    OP_LOAD_INT,
    OP_LOAD_FLOAT,
    OP_LOAD_STRING,
    OP_LOAD_LOCAL,
    OP_STORE_LOCAL,
    OP_LOAD_GLOBAL,
    OP_STORE_GLOBAL,
    OP_LOAD_UPVALUE,
    OP_STORE_UPVALUE,
    OP_LOAD_FIELD,
    OP_STORE_FIELD,
    OP_LOAD_INDEX,
    OP_STORE_INDEX,
    OP_POP,
    OP_DUP,
    OP_DUP2,
    OP_SWAP,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_NEG,
    OP_NOT,
    OP_BITNOT,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_SHL,
    OP_SHR,
    OP_CMP_EQ,
    OP_CMP_NE,
    OP_CMP_LT,
    OP_CMP_LE,
    OP_CMP_GT,
    OP_CMP_GE,
    OP_JUMP,
    OP_JUMP_IF_TRUE,
    OP_JUMP_IF_FALSE,
    OP_JUMP_IF_NULL,
    OP_JUMP_IF_NOT_NULL,
    OP_CALL,
    OP_RETURN,
    OP_TAIL_CALL,
    OP_CREATE_CLOSURE,
    OP_CREATE_FIBER,
    OP_SWITCH_FIBER,
    OP_YIELD,
    OP_AWAIT,
    OP_THROW,
    OP_CATCH,
    OP_NEW_OBJECT,
    OP_NEW_ARRAY,
    OP_TYPEOF,
    OP_LEN,
    OP_MAKE_FUNCTION,
    OP_MAKE_METHOD,
    OP_GET_SUPER,
    OP_DUP_TOP,
    OP_DEBUG
} opcode_t;

typedef struct instruction {
    opcode_t op;
    int arg;
    int line;
    struct instruction * next;
} instruction_t;

typedef struct constant {
    type_t type;
    union {
        int64_t int_val;
        double float_val;
        char * string_val;
    };
    struct constant * next;
} constant_t;

typedef struct upvalue {
    int index;
    bool is_local;
    struct upvalue * next;
} upvalue_t;

typedef struct function {
    char * name;
    instruction_t * code;
    instruction_t * code_tail;
    int local_count;
    constant_t * constants;
    constant_t * constants_tail;
    symbol_t ** locals;
    upvalue_t * upvalues;
    int max_stack;
    int line_count;
    struct function * next;
} function_t;

typedef struct {
    function_t * functions;
    function_t * current_function;
    sema_t * sema;
    instruction_t * current_instruction;
    constant_t * current_constants;
    int instruction_count;
    int max_stack;
    int error_count;
    char errors[256];
} codegen_t;

codegen_t * codegen_create(sema_t * sema);
void codegen_destroy(codegen_t * cg);
function_t * codegen_compile(codegen_t * cg, ast_node_t * root);
bool codegen_had_error(codegen_t * cg);
const char * codegen_get_error(codegen_t * cg);

/* ============================================================================
 * VIRTUAL MACHINE
 * ============================================================================*/

#define VM_STACK_SIZE 65536
#define VM_CALL_DEPTH 1024
#define VM_STRING_LEN_MAX 65536

typedef struct vm_frame {
    function_t * function;
    uint8_t * ip;
    uint8_t * locals;
    uint8_t * stack_base;
    struct vm_frame * parent;
    int return_address;
} vm_frame_t;

typedef struct vm_object {
    type_t type;
    int refcount;
    union {
        struct {
            char * data;
            size_t length;
        } string;
        struct {
            uint64_t * data;
            size_t count;
            size_t capacity;
        } array;
        struct {
            char ** keys;
            uint8_t ** values;
            size_t count;
            size_t capacity;
        } object;
        struct {
            struct vm_object * class;
            uint8_t * fields;
        } instance;
        struct {
            function_t * function;
            uint8_t * stack;
            uint8_t * ip;
            uint8_t * locals;
            int status;
        } fiber;
    };
    struct vm_object * next;
} vm_object_t;

typedef struct vm {
    uint8_t * memory;
    size_t memory_size;
    vm_object_t * heap;
    vm_object_t ** heap_free;
    uint8_t * stack;
    uint8_t * stack_top;
    vm_frame_t * frames;
    int frame_count;
    vm_object_t * globals;
    vm_object_t * exception;
    int gc_threshold;
    int gc_count;
} vm_t;

vm_t * vm_create(size_t heap_size);
void vm_destroy(vm_t * vm);
vm_object_t * vm_execute(vm_t * vm, function_t * entry);
vm_object_t * vm_gc(vm_t * vm);

/* ============================================================================
 * COMPILER API
 * ============================================================================*/

typedef struct {
    lexer_t * lexer;
    parser_t * parser;
    sema_t * sema;
    codegen_t * codegen;
    vm_t * vm;
    bool verbose;
    bool dump_ast;
    bool dump_bytecode;
} infix_compiler_t;

infix_compiler_t * infix_compiler_create(void);
void infix_compiler_destroy(infix_compiler_t * compiler);
bool infix_compile(infix_compiler_t * compiler, const char * source);
vm_object_t * infix_run(infix_compiler_t * compiler);
bool infix_load_file(infix_compiler_t * compiler, const char * filename);
void infix_set_verbose(infix_compiler_t * compiler, bool verbose);
void infix_set_dump_ast(infix_compiler_t * compiler, bool dump);
void infix_set_dump_bytecode(infix_compiler_t * compiler, bool dump);

#ifdef __cplusplus
}
#endif

#endif /* INFIX_LANG_H */
