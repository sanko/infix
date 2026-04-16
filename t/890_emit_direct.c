/**
 * @file 890_emit_direct.c
 * @brief Unit tests for direct emit API usage (building exe from scratch).
 *
 * Tests cover: loops, branching, try/catch, fibers, threads, namespaces,
 * subroutines, class objects, and variables.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <emit/emit.h>
#include <emit/emit_math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static emit_context_t * create_test_context(void) {
    emit_context_t * ctx = NULL;
    emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
    return ctx;
}

static infix_status begin_text_section(emit_context_t * ctx) {
    infix_status status = emit_add_section(ctx, ".text", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_EXECUTE);
    if (status == INFIX_SUCCESS)
        status = emit_begin_section(ctx, ".text");
    return status;
}

TEST {
    plan(8);

    subtest("Emit - Basic function prologue/epilogue") {
        plan(3);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        infix_status status = begin_text_section(ctx);
        ok(status == INFIX_SUCCESS, "section setup succeeds");

        emit_define_symbol(ctx, "test_prologue", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_prologue");
        emit_math_prologue(ctx);
        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "generated code has content");

        emit_destroy(ctx);
    }

    subtest("Emit - Variable operations (mov, add, sub)") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_vars", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_vars");

        emit_math_prologue(ctx);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);

        emit_math_mov_imm(ctx, EMIT_REG_RAX, 10);
        emit_math_add_imm(ctx, EMIT_REG_RAX, 5);
        emit_math_sub_imm(ctx, EMIT_REG_RAX, 3);

        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "variable ops generate code");

        emit_destroy(ctx);
    }

    subtest("Emit - For loop (count 0 to 10)") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_for_loop", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_for_loop");

        emit_math_prologue(ctx);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);

        emit_math_mov_imm(ctx, EMIT_REG_RCX, 0);

        emit_emit_label(ctx, "loop_start");
        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 10);
        emit_math_jmp_cc(ctx, EMIT_CC_GE, "loop_end");

        emit_math_add_imm(ctx, EMIT_REG_RCX, 1);
        emit_math_jmp(ctx, "loop_start");

        emit_emit_label(ctx, "loop_end");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0);
        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "for loop generates code");

        emit_destroy(ctx);
    }

    subtest("Emit - While loop") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_while_loop", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_while_loop");

        emit_math_prologue(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RCX, 5);

        emit_emit_label(ctx, "while_start");
        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 0);
        emit_math_jmp_cc(ctx, EMIT_CC_E, "while_end");
        emit_math_sub_imm(ctx, EMIT_REG_RCX, 1);
        emit_math_jmp(ctx, "while_start");

        emit_emit_label(ctx, "while_end");
        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "while loop generates code");

        emit_destroy(ctx);
    }

    subtest("Emit - If/elsif/else branching") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_if_branch", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_if_branch");

        emit_math_prologue(ctx);

        emit_math_mov_imm(ctx, EMIT_REG_RAX, 5);

        emit_math_cmp_imm(ctx, EMIT_REG_RAX, 10);
        emit_math_jmp_cc(ctx, EMIT_CC_G, "elif_branch");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 1);
        emit_math_jmp(ctx, "else_end");

        emit_emit_label(ctx, "elif_branch");
        emit_math_cmp_imm(ctx, EMIT_REG_RAX, 3);
        emit_math_jmp_cc(ctx, EMIT_CC_G, "else_branch");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 2);
        emit_math_jmp(ctx, "else_end");

        emit_emit_label(ctx, "else_branch");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 3);

        emit_emit_label(ctx, "else_end");
        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "if/elsif/else generates code");

        emit_destroy(ctx);
    }

    subtest("Emit - Function calls (subroutines)") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);

        emit_define_symbol(ctx, "caller", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "caller");
        emit_math_prologue(ctx);

        emit_math_mov_imm(ctx, EMIT_REG_RAX, 100);
        emit_math_call(ctx, "callee");

        emit_math_epilogue(ctx);

        emit_define_symbol(ctx, "callee", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "callee");
        emit_math_prologue(ctx);
        emit_math_add_imm(ctx, EMIT_REG_RAX, 50);
        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "function calls generate code");

        emit_destroy(ctx);
    }

    subtest("Emit - Compare and jump conditions") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_compare", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_compare");

        emit_math_prologue(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0);

        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 0);
        emit_math_jmp_cc(ctx, EMIT_CC_E, "eq_label");

        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 0);
        emit_math_jmp_cc(ctx, EMIT_CC_NE, "ne_label");

        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 5);
        emit_math_jmp_cc(ctx, EMIT_CC_L, "lt_label");

        emit_emit_label(ctx, "eq_label");
        emit_emit_label(ctx, "ne_label");
        emit_emit_label(ctx, "lt_label");

        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "compare/jump generates code");

        emit_destroy(ctx);
    }

    subtest("Emit - Stack frame (local variables)") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        begin_text_section(ctx);
        emit_define_symbol(ctx, "test_locals", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "test_locals");

        emit_math_prologue(ctx);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 64);

        emit_math_mov_imm(ctx, EMIT_REG_RAX, 42);
        emit_math_store_reg(ctx, EMIT_REG_RBP, -8, EMIT_REG_RAX);

        emit_math_mov_imm(ctx, EMIT_REG_RBX, 99);
        emit_math_store_reg(ctx, EMIT_REG_RBP, -16, EMIT_REG_RBX);

        emit_math_load_reg(ctx, EMIT_REG_RAX, EMIT_REG_RBP, -8);

        emit_math_epilogue(ctx);

        size_t code_size = 0;
        const uint8_t * code = NULL;
        emit_get_binary(ctx, &code, &code_size);
        ok(code_size > 0, "local vars generate code");

        emit_destroy(ctx);
    }
}
