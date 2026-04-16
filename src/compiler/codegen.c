/**
 * @file codegen.c
 * @brief Code generator for Infix language - generates bytecode
 */

#include "compiler/infix_lang.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void emit_instruction(codegen_t * cg, opcode_t op, int arg, int line);
static void compile_node(codegen_t * cg, ast_node_t * node);

sema_t * sema_create(void) {
    sema_t * sema = (sema_t *)calloc(1, sizeof(sema_t));
    sema->global_scope = (scope_t *)calloc(1, sizeof(scope_t));
    sema->global_scope->name = strdup("global");
    sema->global_scope->depth = 0;
    sema->current_scope = sema->global_scope;
    return sema;
}

void sema_destroy(sema_t * sema) {
    if (!sema)
        return;
    // Walk and free scopes
    free(sema);
}

scope_t * sema_push_scope(sema_t * sema, const char * name) {
    scope_t * scope = (scope_t *)calloc(1, sizeof(scope_t));
    scope->name = name ? strdup(name) : NULL;
    scope->parent = sema->current_scope;
    scope->depth = sema->current_scope->depth + 1;
    sema->current_scope->child = scope;
    sema->current_scope = scope;
    return scope;
}

void sema_pop_scope(sema_t * sema) {
    if (sema->current_scope->parent)
        sema->current_scope = sema->current_scope->parent;
}

symbol_t * sema_define(sema_t * sema, const char * name, symbol_kind_t kind, type_t * type) {
    symbol_t * sym = (symbol_t *)calloc(1, sizeof(symbol_t));
    sym->name = strdup(name);
    sym->kind = kind;
    sym->type = type;
    sym->stack_offset = sema->current_scope->local_count++;

    sym->next = sema->current_scope->symbols;
    sema->current_scope->symbols = sym;

    return sym;
}

symbol_t * sema_lookup(sema_t * sema, const char * name) {
    scope_t * scope = sema->current_scope;
    while (scope) {
        symbol_t * sym = scope->symbols;
        while (sym) {
            if (strcmp(sym->name, name) == 0)
                return sym;
            sym = sym->next;
        }
        scope = scope->parent;
    }
    return NULL;
}

type_t * type_create(type_kind_t kind) {
    type_t * type = (type_t *)calloc(1, sizeof(type_t));
    type->kind = kind;
    return type;
}

codegen_t * codegen_create(sema_t * sema) {
    codegen_t * cg = (codegen_t *)calloc(1, sizeof(codegen_t));
    cg->sema = sema;

    // Create entry function
    cg->current_function = (function_t *)calloc(1, sizeof(function_t));
    cg->current_function->name = strdup("<main>");
    cg->functions = cg->current_function;

    return cg;
}

void codegen_destroy(codegen_t * cg) {
    if (!cg)
        return;

    function_t * fn = cg->functions;
    while (fn) {
        function_t * next = fn->next;
        free(fn->name);
        free(fn);
        fn = next;
    }

    free(cg);
}

static void emit_instruction(codegen_t * cg, opcode_t op, int arg, int line) {
    instruction_t * inst = (instruction_t *)calloc(1, sizeof(instruction_t));
    inst->op = op;
    inst->arg = arg;
    inst->line = line;

    if (cg->current_instruction)
        cg->current_instruction->next = inst;
    else
        cg->current_function->code = inst;
    cg->current_instruction = inst;
    cg->instruction_count++;
    cg->current_function->line_count++;
}

static void emit_load_constant(codegen_t * cg, int64_t value, int line) {
    // Add to constants pool
    constant_t * c = (constant_t *)calloc(1, sizeof(constant_t));
    c->type.kind = TYPE_INT;
    c->int_val = value;

    if (cg->current_function->constants_tail)
        cg->current_function->constants_tail->next = c;
    else
        cg->current_function->constants = c;
    cg->current_function->constants_tail = c;

    int idx = cg->current_function->local_count++;  // Use as constant index
    emit_instruction(cg, OP_LOAD_INT, idx, line);
}

static void compile_expression(codegen_t * cg, ast_node_t * node);

static void compile_binary_op(codegen_t * cg, token_type_t op, int line) {
    switch (op) {
    case TOKEN_PLUS:
        emit_instruction(cg, OP_ADD, 0, line);
        break;
    case TOKEN_MINUS:
        emit_instruction(cg, OP_SUB, 0, line);
        break;
    case TOKEN_STAR:
        emit_instruction(cg, OP_MUL, 0, line);
        break;
    case TOKEN_SLASH:
        emit_instruction(cg, OP_DIV, 0, line);
        break;
    case TOKEN_PERCENT:
        emit_instruction(cg, OP_MOD, 0, line);
        break;
    case TOKEN_EQEQ:
        emit_instruction(cg, OP_CMP_EQ, 0, line);
        break;
    case TOKEN_BANGEQ:
        emit_instruction(cg, OP_CMP_NE, 0, line);
        break;
    case TOKEN_LT:
        emit_instruction(cg, OP_CMP_LT, 0, line);
        break;
    case TOKEN_LTEQ:
        emit_instruction(cg, OP_CMP_LE, 0, line);
        break;
    case TOKEN_GT:
        emit_instruction(cg, OP_CMP_GT, 0, line);
        break;
    case TOKEN_GTEQ:
        emit_instruction(cg, OP_CMP_GE, 0, line);
        break;
    case TOKEN_AMPAMP:
        emit_instruction(cg, OP_AND, 0, line);
        break;
    case TOKEN_PIPEPIPE:
        emit_instruction(cg, OP_OR, 0, line);
        break;
    default:
        break;
    }
}

static void compile_expression(codegen_t * cg, ast_node_t * node) {
    if (!node)
        return;

    switch (node->type) {
    case AST_INTEGER_LITERAL:
        emit_instruction(cg, OP_LOAD_INT, (int)node->literal.int_val, node->line);
        break;

    case AST_FLOAT_LITERAL:
        emit_instruction(cg, OP_LOAD_FLOAT, (int)node->literal.float_val, node->line);
        break;

    case AST_STRING_LITERAL:
        {
            constant_t * c = (constant_t *)calloc(1, sizeof(constant_t));
            c->type.kind = TYPE_STRING;
            c->string_val = node->literal.string_val;
            if (cg->current_function->constants_tail)
                cg->current_function->constants_tail->next = c;
            else
                cg->current_function->constants = c;
            cg->current_function->constants_tail = c;
            emit_instruction(cg, OP_LOAD_STRING, 0, node->line);
            break;
        }

    case AST_BOOL_LITERAL:
        if (node->literal.int_val)
            emit_instruction(cg, OP_LOAD_TRUE, 0, node->line);
        else
            emit_instruction(cg, OP_LOAD_FALSE, 0, node->line);
        break;

    case AST_NULL_LITERAL:
        emit_instruction(cg, OP_LOAD_NULL, 0, node->line);
        break;

    case AST_IDENTIFIER:
        {
            symbol_t * sym = sema_lookup(cg->sema, node->identifier.name);
            if (sym) {
                if (sym->depth == 0)
                    emit_instruction(cg, OP_LOAD_GLOBAL, sym->stack_offset, node->line);
                else
                    emit_instruction(cg, OP_LOAD_LOCAL, sym->stack_offset, node->line);
            }
            break;
        }

    case AST_BINARY_EXPR:
        compile_expression(cg, node->binary_expr.left);
        compile_expression(cg, node->binary_expr.right);
        compile_binary_op(cg, node->binary_expr.operator, node->line);
        break;

    case AST_UNARY_EXPR:
        compile_expression(cg, node->unary_expr.operand);
        if (node->unary_expr.operator== TOKEN_MINUS)
            emit_instruction(cg, OP_NEG, 0, node->line);
        else if (node->unary_expr.operator== TOKEN_BANG)
            emit_instruction(cg, OP_NOT, 0, node->line);
        break;

    case AST_CALL_EXPR:
        // Push arguments in reverse order
        if (node->call_expr.arguments) {
            ast_node_t * args = node->call_expr.arguments;
            int argc = 0;
            ast_node_t * arg;
            for (arg = args; arg; arg = arg->next)
                argc++;

            for (int i = argc - 1; i >= 0; i--) {
                arg = args;
                for (int j = 0; j < i; j++)
                    arg = arg->next;
                compile_expression(cg, arg);
            }
        }
        compile_expression(cg, node->call_expr.callee);
        emit_instruction(cg, OP_CALL, 0, node->line);
        break;

    case AST_ASSIGNMENT:
        compile_expression(cg, node->assignment.value);
        emit_instruction(cg, OP_DUP, 0, node->line);
        if (node->assignment.target->type == AST_IDENTIFIER) {
            symbol_t * sym = sema_lookup(cg->sema, node->assignment.target->identifier.name);
            if (sym) {
                if (sym->depth == 0)
                    emit_instruction(cg, OP_STORE_GLOBAL, sym->stack_offset, node->line);
                else
                    emit_instruction(cg, OP_STORE_LOCAL, sym->stack_offset, node->line);
            }
        }
        break;

    case AST_ARRAY_LITERAL:
        {
            if (node->array_literal.elements) {
                ast_node_t * elem = node->array_literal.elements;
                int count = 0;
                while (elem) {
                    count++;
                    elem = elem->next;
                }

                emit_instruction(cg, OP_LOAD_INT, count, node->line);
                emit_instruction(cg, OP_NEW_ARRAY, 0, node->line);

                elem = node->array_literal.elements;
                int idx = 0;
                while (elem) {
                    emit_instruction(cg, OP_DUP, 0, node->line);
                    emit_instruction(cg, OP_LOAD_INT, idx, node->line);
                    compile_expression(cg, elem);
                    emit_instruction(cg, OP_STORE_INDEX, 0, node->line);
                    emit_instruction(cg, OP_POP, 0, node->line);
                    elem = elem->next;
                    idx++;
                }
            }
            else {
                emit_instruction(cg, OP_LOAD_INT, 0, node->line);
                emit_instruction(cg, OP_NEW_ARRAY, 0, node->line);
            }
            break;
        }

    default:
        break;
    }
}

static void compile_statement(codegen_t * cg, ast_node_t * node);

static void compile_block(codegen_t * cg, ast_node_t * block) {
    sema_push_scope(cg->sema, "block");

    ast_node_t * stmt = block->block.statements;
    while (stmt) {
        compile_statement(cg, stmt);
        stmt = stmt->next;
    }

    sema_pop_scope(cg->sema);
}

static void compile_statement(codegen_t * cg, ast_node_t * node) {
    if (!node)
        return;

    switch (node->type) {
    case AST_VAR_DECL:
        {
            if (node->var_decl.initializer)
                compile_expression(cg, node->var_decl.initializer);
            else
                emit_instruction(cg, OP_LOAD_NULL, 0, node->line);

            symbol_t * sym = sema_define(cg->sema, node->var_decl.name, SYM_VARIABLE, NULL);
            emit_instruction(cg, OP_STORE_LOCAL, sym->stack_offset, node->line);
            emit_instruction(cg, OP_POP, 0, node->line);
            break;
        }

    case AST_EXPR_STMT:
        compile_expression(cg, node);
        emit_instruction(cg, OP_POP, 0, node->line);
        break;

    case AST_IF_STMT:
        {
            int * jumps = (int *)malloc(sizeof(int) * 16);
            int jump_count = 0;

            compile_expression(cg, node->if_stmt.condition);
            int else_jump = cg->instruction_count;
            emit_instruction(cg, OP_JUMP_IF_FALSE, 0, node->line);

            compile_block(cg, node->if_stmt.then_branch);
            int end_jump = cg->instruction_count;
            emit_instruction(cg, OP_JUMP, 0, node->line);

            // Patch else jump
            instruction_t * inst = cg->current_function->code;
            int idx = 0;
            while (inst && idx < else_jump)
                inst = inst->next;
            if (inst)
                inst->arg = cg->instruction_count;

            // Elif chains
            ast_node_t * elif = node->if_stmt.elif_list;
            while (elif) {
                compile_expression(cg, elif->if_stmt.condition);
                int elif_jump = cg->instruction_count;
                emit_instruction(cg, OP_JUMP_IF_FALSE, 0, node->line);
                compile_block(cg, elif->if_stmt.then_branch);
                emit_instruction(cg, OP_JUMP, end_jump, node->line);
                elif = elif->next;
            }

            // Else branch
            if (node->if_stmt.else_branch)
                compile_block(cg, node->if_stmt.else_branch);

            // Patch end jump
            inst = cg->current_function->code;
            idx = 0;
            while (inst && idx < end_jump)
                inst = inst->next;
            if (inst)
                inst->arg = cg->instruction_count;

            free(jumps);
            break;
        }

    case AST_WHILE_STMT:
        {
            int loop_start = cg->instruction_count;

            compile_expression(cg, node->while_stmt.condition);
            int exit_jump = cg->instruction_count;
            emit_instruction(cg, OP_JUMP_IF_FALSE, 0, node->line);

            compile_block(cg, node->while_stmt.body);
            emit_instruction(cg, OP_JUMP, loop_start, node->line);

            // Patch exit jump
            instruction_t * inst = cg->current_function->code;
            int idx = 0;
            while (inst && idx < exit_jump)
                inst = inst->next;
            if (inst)
                inst->arg = cg->instruction_count;
            break;
        }

    case AST_FOR_STMT:
        {
            if (node->for_stmt.initializer)
                compile_statement(cg, node->for_stmt.initializer);

            int loop_start = cg->instruction_count;
            int exit_jump = -1;

            if (node->for_stmt.condition) {
                compile_expression(cg, node->for_stmt.condition);
                exit_jump = cg->instruction_count;
                emit_instruction(cg, OP_JUMP_IF_FALSE, 0, node->line);
            }

            compile_block(cg, node->for_stmt.body);

            if (node->for_stmt.increment) {
                compile_expression(cg, node->for_stmt.increment);
                emit_instruction(cg, OP_POP, 0, node->line);
            }

            emit_instruction(cg, OP_JUMP, loop_start, node->line);

            if (exit_jump >= 0) {
                instruction_t * inst = cg->current_function->code;
                int idx = 0;
                while (inst && idx < exit_jump)
                    inst = inst->next;
                if (inst)
                    inst->arg = cg->instruction_count;
            }
            break;
        }

    case AST_DO_WHILE_STMT:
        {
            int loop_start = cg->instruction_count;

            compile_block(cg, node->do_while_stmt.body);
            compile_expression(cg, node->do_while_stmt.condition);
            emit_instruction(cg, OP_JUMP_IF_TRUE, loop_start, node->line);
            break;
        }

    case AST_RETURN_STMT:
        if (node->return_stmt.value)
            compile_expression(cg, node->return_stmt.value);
        else
            emit_instruction(cg, OP_LOAD_NULL, 0, node->line);
        emit_instruction(cg, OP_RETURN, 0, node->line);
        break;

    case AST_BREAK_STMT:
        emit_instruction(cg, OP_JUMP, -1, node->line);  // TODO: resolve break target
        break;

    case AST_CONTINUE_STMT:
        emit_instruction(cg, OP_JUMP, -1, node->line);  // TODO: resolve continue target
        break;

    case AST_TRY_STMT:
        {
            int try_start = cg->instruction_count;
            compile_block(cg, node->try_stmt.try_block);
            int try_end = cg->instruction_count;

            // Catch block
            if (node->try_stmt.catch_block) {
                sema_push_scope(cg->sema, "catch");
                if (node->try_stmt.catch_var)
                    sema_define(cg->sema, node->try_stmt.catch_var, SYM_VARIABLE, NULL);
                compile_block(cg, node->try_stmt.catch_block);
                sema_pop_scope(cg->sema);
            }

            // Finally block
            if (node->try_stmt.finally_block)
                compile_block(cg, node->try_stmt.finally_block);

            emit_instruction(cg, OP_CATCH, try_end, node->line);
            break;
        }

    case AST_THROW_STMT:
        compile_expression(cg, node->throw_stmt.exception);
        emit_instruction(cg, OP_THROW, 0, node->line);
        break;

    case AST_BLOCK:
        compile_block(cg, node);
        break;

    case AST_YIELD_STMT:
        if (node->yield_stmt.value)
            compile_expression(cg, node->yield_stmt.value);
        else
            emit_instruction(cg, OP_LOAD_NULL, 0, node->line);
        emit_instruction(cg, OP_YIELD, 0, node->line);
        break;

    case AST_FUNCTION_DECL:
        {
            // Save current function
            function_t * parent_fn = cg->current_function;
            instruction_t * parent_tail = cg->current_instruction;

            // Create new function
            cg->current_function = (function_t *)calloc(1, sizeof(function_t));
            cg->current_function->name = strdup(node->function_decl.name);
            cg->current_instruction = NULL;

            // Define symbol
            sema_define(cg->sema, node->function_decl.name, SYM_FUNCTION, NULL);

            // Compile parameters
            sema_push_scope(cg->sema, node->function_decl.name);
            ast_node_t * param = node->function_decl.params;
            while (param) {
                sema_define(cg->sema, param->param.name, SYM_PARAMETER, NULL);
                param = param->next;
            }

            // Compile body
            if (node->function_decl.body)
                compile_statement(cg, node->function_decl.body);

            emit_instruction(cg, OP_LOAD_NULL, 0, node->line);
            emit_instruction(cg, OP_RETURN, 0, node->line);

            sema_pop_scope(cg->sema);

            // Link function
            cg->current_function->next = parent_fn;
            cg->current_function = parent_fn;
            cg->current_instruction = parent_tail;
            break;
        }

    case AST_FIBER_EXPR:
        // Compile fiber body as a function
        if (node->fiber_expr.body)
            compile_block(cg, node->fiber_expr.body);
        emit_instruction(cg, OP_LOAD_NULL, 0, node->line);
        emit_instruction(cg, OP_RETURN, 0, node->line);
        emit_instruction(cg, OP_CREATE_FIBER, 0, node->line);
        break;

    default:
        compile_expression(cg, node);
        emit_instruction(cg, OP_POP, 0, node->line);
        break;
    }
}

static void compile_node(codegen_t * cg, ast_node_t * node) {
    while (node) {
        compile_statement(cg, node);
        node = node->next;
    }
}

function_t * codegen_compile(codegen_t * cg, ast_node_t * root) {
    compile_node(cg, root);
    emit_instruction(cg, OP_HALT, 0, 0);
    return cg->functions;
}

bool codegen_had_error(codegen_t * cg) { return cg->error_count > 0; }

const char * codegen_get_error(codegen_t * cg) { return cg->errors; }

/* Simple bytecode interpreter (VM) */

vm_t * vm_create(size_t heap_size) {
    vm_t * vm = (vm_t *)calloc(1, sizeof(vm_t));
    vm->memory_size = heap_size;
    vm->memory = (uint8_t *)calloc(1, heap_size);
    vm->stack = (uint8_t *)calloc(1, VM_STACK_SIZE);
    vm->stack_top = vm->stack;
    return vm;
}

void vm_destroy(vm_t * vm) {
    if (vm) {
        free(vm->memory);
        free(vm->stack);
        free(vm);
    }
}

static vm_object_t * alloc_object(vm_t * vm, type_kind_t type, size_t size) {
    vm_object_t * obj = (vm_object_t *)calloc(1, size);
    obj->type.kind = type;
    obj->refcount = 1;
    obj->next = vm->heap;
    vm->heap = obj;
    return obj;
}

static int64_t pop_int(vm_t * vm) {
    int64_t val = *(int64_t *)vm->stack_top;
    vm->stack_top -= sizeof(int64_t);
    return val;
}

static void push_int(vm_t * vm, int64_t val) {
    *(int64_t *)vm->stack_top = val;
    vm->stack_top += sizeof(int64_t);
}

vm_object_t * vm_execute(vm_t * vm, function_t * entry) {
    if (!entry || !entry->code)
        return NULL;

    uint8_t * ip = (uint8_t *)entry->code;
    vm_frame_t frame;
    frame.function = entry;
    frame.ip = ip;
    frame.locals = (uint8_t *)calloc(1, 1024);
    frame.stack_base = vm->stack_top;

    vm->frames = &frame;
    vm->frame_count = 1;

    while (true) {
        opcode_t op = (opcode_t)*ip++;

        switch (op) {
        case OP_HALT:
            goto done;

        case OP_LOAD_INT:
            push_int(vm, (int64_t)*(int32_t *)ip);
            ip += 4;
            break;

        case OP_LOAD_NULL:
            push_int(vm, 0);
            break;

        case OP_LOAD_TRUE:
            push_int(vm, 1);
            break;

        case OP_LOAD_FALSE:
            push_int(vm, 0);
            break;

        case OP_ADD:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a + b);
                break;
            }

        case OP_SUB:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a - b);
                break;
            }

        case OP_MUL:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a * b);
                break;
            }

        case OP_DIV:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a / b);
                break;
            }

        case OP_MOD:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a % b);
                break;
            }

        case OP_NEG:
            {
                int64_t a = pop_int(vm);
                push_int(vm, -a);
                break;
            }

        case OP_NOT:
            {
                int64_t a = pop_int(vm);
                push_int(vm, !a);
                break;
            }

        case OP_CMP_EQ:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a == b);
                break;
            }

        case OP_CMP_NE:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a != b);
                break;
            }

        case OP_CMP_LT:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a < b);
                break;
            }

        case OP_CMP_LE:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a <= b);
                break;
            }

        case OP_CMP_GT:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a > b);
                break;
            }

        case OP_CMP_GE:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a >= b);
                break;
            }

        case OP_AND:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a & b);
                break;
            }

        case OP_OR:
            {
                int64_t b = pop_int(vm);
                int64_t a = pop_int(vm);
                push_int(vm, a | b);
                break;
            }

        case OP_JUMP:
            {
                int32_t offset = *(int32_t *)ip;
                ip = (uint8_t *)offset;  // TODO: properly resolve jump targets
                break;
            }

        case OP_JUMP_IF_TRUE:
            {
                int64_t val = pop_int(vm);
                if (val) {
                    int32_t offset = *(int32_t *)ip;
                    ip = (uint8_t *)offset;
                }
                else {
                    ip += 4;
                }
                break;
            }

        case OP_JUMP_IF_FALSE:
            {
                int64_t val = pop_int(vm);
                if (!val) {
                    int32_t offset = *(int32_t *)ip;
                    ip = (uint8_t *)offset;
                }
                else {
                    ip += 4;
                }
                break;
            }

        case OP_RETURN:
            {
                goto done;
            }

        case OP_POP:
            vm->stack_top -= sizeof(int64_t);
            break;

        case OP_DUP:
            push_int(vm, *(int64_t *)(vm->stack_top - sizeof(int64_t)));
            break;

        case OP_NEW_ARRAY:
            {
                int64_t count = pop_int(vm);
                vm_object_t * arr = alloc_object(vm, TYPE_ARRAY, sizeof(vm_object_t));
                arr->array.data = (uint64_t *)calloc(count, sizeof(uint64_t));
                arr->array.count = count;
                arr->array.capacity = count;
                *(vm_object_t **)vm->stack_top = arr;
                vm->stack_top += sizeof(vm_object_t *);
                break;
            }

        case OP_STORE_INDEX:
            {
                int64_t idx = pop_int(vm);
                vm_object_t * arr = *(vm_object_t **)(vm->stack_top - sizeof(vm_object_t *) - sizeof(int64_t));
                int64_t val = pop_int(vm);
                if (arr && arr->type.kind == TYPE_ARRAY && idx >= 0 && idx < arr->array.count)
                    arr->array.data[idx] = val;
                break;
            }

        case OP_DEBUG:
            {
                int64_t val = pop_int(vm);
                printf("DEBUG: %lld\n", (long long)val);
                break;
            }

        default:
            break;
        }
    }

done:
    free(frame.locals);

    if (vm->stack_top > vm->stack) {
        vm_object_t * result = *(vm_object_t **)(vm->stack_top - sizeof(vm_object_t *));
        return result;
    }

    return NULL;
}

/* Compiler API */
infix_compiler_t * infix_compiler_create(void) {
    infix_compiler_t * compiler = (infix_compiler_t *)calloc(1, sizeof(infix_compiler_t));
    return compiler;
}

void infix_compiler_destroy(infix_compiler_t * compiler) {
    if (compiler)
        free(compiler);
}

bool infix_compile(infix_compiler_t * compiler, const char * source) {
    lexer_t * lexer = lexer_create(source);
    parser_t * parser = parser_create(lexer);

    ast_node_t * ast = parser_parse(parser);

    if (parser_had_error(parser)) {
        fprintf(stderr, "Parse error: %s\n", parser_get_error(parser));
        parser_destroy(parser);
        return false;
    }

    sema_t * sema = sema_create();
    codegen_t * cg = codegen_create(sema);

    function_t * entry = codegen_compile(cg, ast);

    if (codegen_had_error(cg)) {
        fprintf(stderr, "Codegen error: %s\n", codegen_get_error(cg));
        codegen_destroy(cg);
        sema_destroy(sema);
        parser_destroy(parser);
        ast_free_tree(ast);
        return false;
    }

    compiler->lexer = lexer;
    compiler->parser = parser;
    compiler->sema = sema;
    compiler->codegen = cg;

    return true;
}

vm_object_t * infix_run(infix_compiler_t * compiler) {
    if (!compiler->codegen)
        return NULL;

    vm_t * vm = vm_create(1024 * 1024);
    compiler->vm = vm;

    function_t * entry = compiler->codegen->functions;
    vm_object_t * result = vm_execute(vm, entry);

    return result;
}

void infix_set_verbose(infix_compiler_t * compiler, bool verbose) { compiler->verbose = verbose; }

void infix_set_dump_ast(infix_compiler_t * compiler, bool dump) { compiler->dump_ast = dump; }

void infix_set_dump_bytecode(infix_compiler_t * compiler, bool dump) { compiler->dump_bytecode = dump; }
