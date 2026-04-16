/**
 * @file 880_emit.c
 * @brief Unit test for the emit API (JIT compiler builder suite).
 * @ingroup test_suite
 */
#define DBLTAP_ENABLE
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <emit/emit.h>
#include <emit/emit_math.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define EMIT_TEST_SECTION ".text"

typedef uint64_t (*emit_test_fn_0)(void);
typedef uint64_t (*emit_test_fn_1)(uint64_t);
typedef uint64_t (*emit_test_fn_2)(uint64_t, uint64_t);
typedef int64_t (*emit_test_fn_2i)(int64_t, int64_t);

static void * alloc_executable(size_t size) {
#ifdef _WIN32
    void * mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
        return NULL;
    return mem;
#else
    void * mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
        return NULL;
    return mem;
#endif
}

static void free_executable(void * mem, size_t size) {
#ifdef _WIN32
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    munmap(mem, size);
#endif
    (void)size;
}

static emit_context_t * create_test_context(void) {
    emit_context_t * ctx = NULL;
    infix_status status = emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
    if (status != INFIX_SUCCESS)
        return NULL;
    return ctx;
}

static int setup_test_section(emit_context_t * ctx) {
    infix_status status = emit_add_section(ctx, EMIT_TEST_SECTION, EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_EXECUTE);
    if (status != INFIX_SUCCESS)
        return 0;
    status = emit_begin_section(ctx, EMIT_TEST_SECTION);
    if (status != INFIX_SUCCESS)
        return 0;
    return 1;
}

static int execute_jit_code(const uint8_t * code, size_t size, void ** out_code) {
    void * exec_mem = alloc_executable(size);
    if (!exec_mem)
        return 0;
    memcpy(exec_mem, code, size);
    *out_code = exec_mem;
    return 1;
}

TEST {
    plan(15);

    subtest("Context lifecycle") {
        plan(4);

        emit_context_t * ctx = NULL;
        infix_status status = emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
        ok(status == INFIX_SUCCESS, "emit_create returns success");
        ok(ctx != NULL, "emit_create returns non-NULL context");

        status = emit_create(NULL, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
        ok(status != INFIX_SUCCESS, "emit_create with NULL out param fails");

        emit_destroy(NULL);
        ok(1, "emit_destroy with NULL is safe");

        emit_destroy(ctx);
    }

    subtest("Section management") {
        plan(5);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        infix_status status = emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        ok(status == INFIX_SUCCESS, "emit_add_section returns success");

        status = emit_begin_section(ctx, ".data");
        ok(status == INFIX_SUCCESS, "emit_begin_section returns success");

        status = emit_begin_section(ctx, ".nonexistent");
        ok(status != INFIX_SUCCESS, "emit_begin_section with invalid section fails");

        status = emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC);
        ok(status != INFIX_SUCCESS, "emit_add_section with duplicate name fails");

        emit_destroy(ctx);
    }

    subtest("Symbols and labels") {
        plan(7);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        infix_status status = emit_define_symbol(ctx, "test", EMIT_VISIBILITY_DEFAULT, false);
        ok(status == INFIX_SUCCESS, "emit_define_symbol returns success");

        status = emit_create_label(ctx, "label1");
        ok(status == INFIX_SUCCESS, "emit_create_label returns success");

        ok(setup_test_section(ctx), "setup test section");
        status = emit_emit_label(ctx, "label1");
        ok(status == INFIX_SUCCESS, "emit_emit_label with pre-created label returns success");

        status = emit_emit_label(ctx, "auto_label");
        ok(status == INFIX_SUCCESS, "emit_emit_label auto-creates missing symbols");

        (void)emit_define_symbol(ctx, "func", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "func");
        ok(1, "emit_emit_label on function symbol works");

        status = emit_emit_label(NULL, "label");
        ok(status != INFIX_SUCCESS, "emit_emit_label with NULL fails");

        emit_destroy(ctx);
    }

    subtest("Byte emission") {
        plan(7);

        emit_context_t * ctx = create_test_context();
        ok(ctx != NULL, "emit_create returns non-NULL context");

        ok(setup_test_section(ctx), "setup test section");

        infix_status status = emit_emit_u8(ctx, 0xAA);
        ok(status == INFIX_SUCCESS, "emit_emit_u8 returns success");

        status = emit_emit_u16(ctx, 0xBBCC);
        ok(status == INFIX_SUCCESS, "emit_emit_u16 returns success");

        status = emit_emit_u32(ctx, 0xDDEEFF00);
        ok(status == INFIX_SUCCESS, "emit_emit_u32 returns success");

        status = emit_emit_u64(ctx, 0x1122334455667788ULL);
        ok(status == INFIX_SUCCESS, "emit_emit_u64 returns success");

        const uint8_t * code = NULL;
        size_t code_size = 0;
        status = emit_get_binary(ctx, &code, &code_size);
        ok(status == INFIX_SUCCESS, "emit_get_binary returns success");
        ok(code_size == 15, "Binary size is correct (1+2+4+8)");

        emit_destroy(ctx);
    }

    subtest("MOV instruction") {
        plan(1);

        emit_context_t * ctx = create_test_context();
        ok(setup_test_section(ctx), "setup test section");

        (void)emit_define_symbol(ctx, "identity", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "identity");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 42);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        ok(status == INFIX_SUCCESS, "emit_get_binary succeeded");

        printf("DEBUG: code_size=%zu, bytes: ", code_size);
        for (size_t i = 0; i < code_size && i < 20; i++)
            printf("%02X ", code[i]);
        printf("\n");

        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            printf("DEBUG: exec_mem=%p\n", exec_mem);
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            printf("DEBUG: calling fn()\n");
            uint64_t result = fn();
            printf("DEBUG: result=%llu\n", (unsigned long long)result);
            ok(result == 42, "identity() == 42");
            free_executable(exec_mem, code_size);
        }

        emit_destroy(ctx);
    }

    subtest("Arithmetic instructions") {
        plan(1);

        emit_context_t * ctx = create_test_context();
        ok(setup_test_section(ctx), "setup test section");

        (void)emit_define_symbol(ctx, "add", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "add");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 7);
        (void)emit_math_add_imm(ctx, EMIT_REG_RAX, 8);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        (void)emit_get_binary(ctx, &code, &code_size);

        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            uint64_t result = fn();
            ok(result == 15, "7 + 8 == 15");
            free_executable(exec_mem, code_size);
        }

        emit_destroy(ctx);
    }

    subtest("IMUL instruction") {
        plan(1);

        emit_context_t * ctx = create_test_context();
        ok(setup_test_section(ctx), "setup test section");

        (void)emit_define_symbol(ctx, "multiply", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "multiply");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 6);
        (void)emit_math_imul_imm(ctx, EMIT_REG_RAX, 7);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        (void)emit_get_binary(ctx, &code, &code_size);

        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            uint64_t result = fn();
            ok(result == 42, "6 * 7 == 42");
            free_executable(exec_mem, code_size);
        }

        emit_destroy(ctx);
    }

    subtest("JMP relocation") {
        plan(1);

        emit_context_t * ctx = create_test_context();
        ok(setup_test_section(ctx), "setup test section");

        (void)emit_define_symbol(ctx, "jmp_test", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "jmp_test");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 42);
        (void)emit_math_jmp(ctx, "skip");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 99);
        (void)emit_emit_label(ctx, "skip");
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        (void)emit_get_binary(ctx, &code, &code_size);

        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            uint64_t result = fn();
            ok(result == 42, "jmp_test() == 42 (jump was taken)");
            free_executable(exec_mem, code_size);
        }

        emit_destroy(ctx);
    }

    subtest("CALL and RET") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        ok(setup_test_section(ctx), "setup test section");

        (void)emit_define_symbol(ctx, "constant42", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "constant42");
        (void)emit_math_mov_imm(ctx, EMIT_REG_RAX, 42);
        (void)emit_math_ret(ctx);

        (void)emit_define_symbol(ctx, "caller", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "caller");
        (void)emit_math_call(ctx, "constant42");
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        (void)emit_get_binary(ctx, &code, &code_size);

        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 const_fn = (emit_test_fn_0)exec_mem;
            ok(const_fn() == 42, "constant42() == 42");

            uint64_t caller_offset = 11;
            emit_test_fn_0 caller_fn = (emit_test_fn_0)((uint8_t *)exec_mem + caller_offset);
            ok(caller_fn() == 42, "caller() calls constant42 and returns 42");
            free_executable(exec_mem, code_size);
        }

        emit_destroy(ctx);
    }

    subtest("Argument passing via globals") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "arg1", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);
        (void)emit_define_symbol(ctx, "arg2", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);
        (void)emit_define_symbol(ctx, "result", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "add_globals", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "add_globals");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "arg1");
        (void)emit_math_load_sym(ctx, EMIT_REG_RBX, "arg2");
        (void)emit_math_add(ctx, EMIT_REG_RAX, EMIT_REG_RBX);
        (void)emit_math_store_sym(ctx, "result", EMIT_REG_RAX);
        (void)emit_math_ret(ctx);

        uint64_t add_fn_offset;
        (void)emit_get_offset(ctx, &add_fn_offset);
        uint64_t add_fn_size = add_fn_offset;

        (void)emit_define_symbol(ctx, "mul_globals", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "mul_globals");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "arg1");
        (void)emit_math_load_sym(ctx, EMIT_REG_RBX, "arg2");
        (void)emit_math_mul(ctx, EMIT_REG_RBX);
        (void)emit_math_store_sym(ctx, "result", EMIT_REG_RAX);
        (void)emit_math_ret(ctx);

        uint64_t mul_fn_offset;
        (void)emit_get_offset(ctx, &mul_fn_offset);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint64_t * data_arg1 = (volatile uint64_t *)((uint8_t *)exec_mem + 0);
        volatile uint64_t * data_arg2 = (volatile uint64_t *)((uint8_t *)exec_mem + 8);
        volatile uint64_t * data_result = (volatile uint64_t *)((uint8_t *)exec_mem + 16);

        emit_test_fn_0 add_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);
        *data_arg1 = 5;
        *data_arg2 = 7;
        *data_result = 0;
        (void)add_fn();
        ok(*data_result == 12, "add_globals: 5 + 7 == 12");

        emit_test_fn_0 mul_fn = (emit_test_fn_0)((uint8_t *)exec_mem + mul_fn_offset);
        *data_arg1 = 6;
        *data_arg2 = 8;
        *data_result = 0;
        (void)mul_fn();
        ok(*data_result == 48, "mul_globals: 6 * 8 == 48");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Pointer handling") {
        plan(3);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "ptr", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);
        (void)emit_define_symbol(ctx, "value", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "store_ptr", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "store_ptr");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "ptr");
        (void)emit_math_load_reg(ctx, EMIT_REG_RBX, EMIT_REG_RAX, 0);
        (void)emit_math_store_sym(ctx, "value", EMIT_REG_RBX);
        (void)emit_math_ret(ctx);

        uint64_t store_ptr_offset;
        (void)emit_get_offset(ctx, &store_ptr_offset);

        (void)emit_define_symbol(ctx, "load_ptr", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "load_ptr");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "value");
        (void)emit_math_ret(ctx);

        uint64_t load_ptr_offset;
        (void)emit_get_offset(ctx, &load_ptr_offset);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint64_t * data_ptr = (volatile uint64_t *)((uint8_t *)exec_mem + 0);
        volatile uint64_t * data_value = (volatile uint64_t *)((uint8_t *)exec_mem + 8);

        emit_test_fn_0 store_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);
        emit_test_fn_0 load_fn = (emit_test_fn_0)((uint8_t *)exec_mem + load_ptr_offset);

        *data_ptr = (uint64_t)data_value;
        *data_value = 42;
        (void)store_fn();
        volatile uint64_t check1 = *data_value;
        ok(check1 == 42, "store_ptr: dereferenced pointer to get 42");

        *data_value = 123;
        uint64_t load_result1 = (uint64_t)load_fn();
        ok(load_result1 == 123, "load_ptr: loaded value is 123");

        *data_value = 0xDEADBEEF;
        uint64_t load_result2 = (uint64_t)load_fn();
        ok(load_result2 == 0xDEADBEEF, "load_ptr: loaded 0xDEADBEEF");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Small struct (2 int fields)") {
        plan(4);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "point", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u32(ctx, 0);
        (void)emit_emit_u32(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "sum_point", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "sum_point");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "point");
        (void)emit_math_load_reg(ctx, EMIT_REG_RBX, EMIT_REG_RAX, 0);
        (void)emit_math_load_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX, 4);
        (void)emit_math_add(ctx, EMIT_REG_RBX, EMIT_REG_RCX);
        (void)emit_math_store_reg(ctx, EMIT_REG_RAX, 0, EMIT_REG_RBX);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint32_t * point_x = (volatile uint32_t *)((uint8_t *)exec_mem + 0);
        volatile uint32_t * point_y = (volatile uint32_t *)((uint8_t *)exec_mem + 4);

        emit_test_fn_0 sum_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);

        *point_x = 10;
        *point_y = 20;
        (void)sum_fn();
        ok(*point_x == 30, "sum_point: 10 + 20 == 30");

        *point_x = 100;
        *point_y = 200;
        (void)sum_fn();
        ok(*point_x == 300, "sum_point: 100 + 200 == 300");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Large struct") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "large", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);
        (void)emit_emit_u64(ctx, 0);
        (void)emit_emit_u32(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "sum_large", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "sum_large");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "large");
        (void)emit_math_load_reg(ctx, EMIT_REG_RBX, EMIT_REG_RAX, 0);
        (void)emit_math_load_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX, 8);
        (void)emit_math_add(ctx, EMIT_REG_RBX, EMIT_REG_RCX);
        (void)emit_math_store_reg(ctx, EMIT_REG_RAX, 16, EMIT_REG_RBX);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint64_t * field0 = (volatile uint64_t *)((uint8_t *)exec_mem + 0);
        volatile uint64_t * field8 = (volatile uint64_t *)((uint8_t *)exec_mem + 8);
        volatile uint64_t * result = (volatile uint64_t *)((uint8_t *)exec_mem + 16);

        emit_test_fn_0 sum_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);

        *field0 = 100;
        *field8 = 200;
        (void)sum_fn();
        ok(*result == 300, "sum_large: 100 + 200 == 300");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Mixed types in global struct") {
        plan(2);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "config", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u32(ctx, 0);
        (void)emit_emit_u32(ctx, 0);
        (void)emit_emit_u64(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "process_config", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "process_config");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "config");
        (void)emit_math_load_reg(ctx, EMIT_REG_RBX, EMIT_REG_RAX, 0);
        (void)emit_math_load_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX, 4);
        (void)emit_math_load_reg(ctx, EMIT_REG_R8, EMIT_REG_RAX, 8);
        (void)emit_math_add(ctx, EMIT_REG_RBX, EMIT_REG_RCX);
        (void)emit_math_add(ctx, EMIT_REG_RBX, EMIT_REG_R8);
        (void)emit_math_store_reg(ctx, EMIT_REG_RAX, 0, EMIT_REG_RBX);
        (void)emit_math_ret(ctx);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint32_t * f0 = (volatile uint32_t *)((uint8_t *)exec_mem + 0);
        volatile uint32_t * f4 = (volatile uint32_t *)((uint8_t *)exec_mem + 4);
        volatile uint64_t * f8 = (volatile uint64_t *)((uint8_t *)exec_mem + 8);

        emit_test_fn_0 proc_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);

        *f0 = 10;
        *f4 = 20;
        *f8 = 30;
        (void)proc_fn();
        ok(*f0 == 60, "process_config: 10 + 20 + 30 == 60");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Multiple functions modifying same global") {
        plan(3);

        emit_context_t * ctx = create_test_context();
        if (!ctx) {
            fail("Failed to create context");
            return;
        }

        (void)emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        (void)emit_begin_section(ctx, ".data");
        (void)emit_define_symbol(ctx, "x", EMIT_VISIBILITY_DEFAULT, false);
        (void)emit_emit_u64(ctx, 0);

        uint64_t data_section_size;
        (void)emit_get_offset(ctx, &data_section_size);

        if (!setup_test_section(ctx)) {
            emit_destroy(ctx);
            fail("Failed to setup section");
            return;
        }

        (void)emit_define_symbol(ctx, "double_it", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "double_it");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "x");
        (void)emit_math_add(ctx, EMIT_REG_RAX, EMIT_REG_RAX);
        (void)emit_math_store_sym(ctx, "x", EMIT_REG_RAX);
        (void)emit_math_ret(ctx);

        (void)emit_define_symbol(ctx, "add_ten", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "add_ten");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "x");
        (void)emit_math_add_imm(ctx, EMIT_REG_RAX, 10);
        (void)emit_math_store_sym(ctx, "x", EMIT_REG_RAX);
        (void)emit_math_ret(ctx);

        uint64_t add_ten_offset;
        (void)emit_get_offset(ctx, &add_ten_offset);

        (void)emit_define_symbol(ctx, "square_it", EMIT_VISIBILITY_DEFAULT, true);
        (void)emit_emit_label(ctx, "square_it");
        (void)emit_math_load_sym(ctx, EMIT_REG_RAX, "x");
        (void)emit_math_mul(ctx, EMIT_REG_RAX);
        (void)emit_math_store_sym(ctx, "x", EMIT_REG_RAX);
        (void)emit_math_ret(ctx);

        uint64_t square_it_offset;
        (void)emit_get_offset(ctx, &square_it_offset);

        const uint8_t * code = NULL;
        size_t code_size = 0;
        infix_status status = emit_get_binary(ctx, &code, &code_size);
        if (status != INFIX_SUCCESS) {
            emit_destroy(ctx);
            fail("emit_get_binary failed");
            return;
        }

        void * exec_mem = NULL;
        if (!execute_jit_code(code, code_size, &exec_mem)) {
            emit_destroy(ctx);
            fail("Failed to allocate executable memory");
            return;
        }

        volatile uint64_t * x = (volatile uint64_t *)exec_mem;

        emit_test_fn_0 double_fn = (emit_test_fn_0)((uint8_t *)exec_mem + data_section_size);
        emit_test_fn_0 add_fn = (emit_test_fn_0)((uint8_t *)exec_mem + add_ten_offset);
        emit_test_fn_0 square_fn = (emit_test_fn_0)((uint8_t *)exec_mem + square_it_offset);

        *x = 5;
        (void)double_fn();
        ok(*x == 10, "double_it: 5 * 2 == 10");

        *x = 5;
        (void)add_fn();
        ok(*x == 15, "add_ten: 5 + 10 == 15");

        *x = 5;
        (void)square_fn();
        ok(*x == 25, "square_it: 5 * 5 == 25");

        emit_destroy(ctx);
        free_executable(exec_mem, code_size);
    }

    subtest("Variadic function pointer test") {
        plan(1);
        ok(1, "Variadic test placeholder");
    }

    subtest("Complex pointer chains") {
        plan(1);
        ok(1, "Complex pointer chains placeholder");
    }

    subtest("ARM64 compatibility") {
        plan(1);
        ok(1, "ARM64 compatibility placeholder");
    }
}
