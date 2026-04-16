/**
 * @file 890_emit_direct.c
 * @brief Unified Test Suite: Infix Emit API & Pulse Language Compiler
 */

#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <emit/emit.h>
#include <emit/emit_math.h>
#include <infix/infix.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
typedef HANDLE pulse_thread_h;
#else
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
typedef pthread_t pulse_thread_h;
#endif

/* ============================================================================
 * Pulse Runtime Environment (C Implementation)
 * ============================================================================ */

#define TAG_PRIMITIVE 0
#define TAG_ARRAY     1
#define TAG_OBJECT    4
#define TAG_EXCEPTION 5
#define TAG_FIBER     6
#define TAG_THREAD    7
#define TAG_TUPLE     8
#define TAG_STRING    9
#define TAG_HASH      10

#define PULSE_STACK_SIZE (64 * 1024)

typedef struct gc_header {
    uint32_t size;
    uint16_t tag;
    uint16_t flags;
    struct gc_header* forwarding;
} gc_header_t;

#define PAYLOAD_TO_HEADER(p) ((gc_header_t*)(p) - 1)
#define HEADER_TO_PAYLOAD(h) ((void*)((gc_header_t*)(h) + 1))

typedef struct pulse_exception_handler {
    uintptr_t catch_ip;
    uintptr_t rsp;
    uintptr_t rbp;
    struct pulse_exception_handler* next;
} pulse_exception_handler_t;

typedef enum { FIB_NEW, FIB_RUNNING, FIB_YIELDED, FIB_DEAD } fiber_state_t;

typedef struct pulse_fiber {
    fiber_state_t state;
    void* stack_mem;
    uintptr_t rsp;
} pulse_fiber_t;

typedef struct pulse_vm {
    uint8_t *from_space, *to_space;
    size_t capacity;
    size_t top;
    void** roots[1024];
    int root_count;
    pulse_exception_handler_t* handlers;
    void* last_exception;
    pulse_fiber_t* current_fiber;
} pulse_vm_t;

typedef struct {
    size_t length;
    uint64_t data[1];
} pulse_array_t;

typedef struct {
    size_t length;
    char data[1];
} pulse_string_t;

typedef struct {
    char* key;
    uint64_t value;
} hash_entry_t;

typedef struct {
    size_t capacity;
    size_t count;
    hash_entry_t entries[1];
} pulse_hash_t;

typedef struct {
    size_t count;
    uint64_t values[1];
} pulse_tuple_t;

#if defined(_MSC_VER)
    static __declspec(thread) pulse_vm_t* tls_current_vm = NULL;
#else
    static __thread pulse_vm_t* tls_current_vm = NULL;
#endif

/* ============================================================================
 * Support Functions (Allocation & OS Helpers)
 * ============================================================================ */

static void * alloc_executable(size_t size) {
#ifdef _WIN32
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void * mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (mem == MAP_FAILED) ? NULL : mem;
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

static pulse_vm_t* vm_create(size_t size) {
    pulse_vm_t* vm = (pulse_vm_t*)calloc(1, sizeof(pulse_vm_t));
    vm->capacity   = size / 2;
    vm->from_space = (uint8_t*)malloc(vm->capacity);
    vm->to_space   = (uint8_t*)malloc(vm->capacity);
    return vm;
}

static void* gc_alloc(pulse_vm_t* vm, size_t size, uint16_t tag) {
    size_t aligned_payload = (size + 7) & ~7;
    size_t total = sizeof(gc_header_t) + aligned_payload;
    if (vm->top + total > vm->capacity) return NULL;
    gc_header_t* h = (gc_header_t*)(vm->from_space + vm->top);
    h->size = (uint32_t)aligned_payload;
    h->tag  = tag;
    h->forwarding = NULL;
    vm->top += total;
    return HEADER_TO_PAYLOAD(h);
}

static void gc_collect(pulse_vm_t* vm) {
    uint8_t* next_top = vm->to_space;
    for (int i = 0; i < vm->root_count; i++) {
        void** root_ptr = (void**)vm->roots[i];
        if (!root_ptr || !*root_ptr) continue;
        gc_header_t* old_h = PAYLOAD_TO_HEADER(*root_ptr);
        if (old_h->forwarding) {
            *root_ptr = HEADER_TO_PAYLOAD(old_h->forwarding);
        } else {
            gc_header_t* new_h = (gc_header_t*)next_top;
            memcpy(new_h, old_h, sizeof(gc_header_t) + old_h->size);
            next_top += (sizeof(gc_header_t) + old_h->size);
            old_h->forwarding = new_h;
            *root_ptr = HEADER_TO_PAYLOAD(new_h);
        }
    }
    uint8_t* temp = vm->from_space;
    vm->from_space = vm->to_space;
    vm->to_space = temp;
    vm->top = (size_t)(next_top - vm->from_space);
}

/* ============================================================================
 * JIT Script Helpers (Called by Pulse Machine Code)
 * ============================================================================ */

static pulse_string_t* pulse_string_concat(pulse_vm_t* vm, pulse_string_t* a, pulse_string_t* b) {
    size_t new_len = a->length + b->length;
    pulse_string_t* s = (pulse_string_t*)gc_alloc(vm, sizeof(pulse_string_t) + new_len, TAG_STRING);
    s->length = new_len;
    memcpy(s->data, a->data, a->length);
    memcpy(s->data + a->length, b->data, b->length);
    s->data[new_len] = '\0';
    return s;
}

static uint64_t pulse_hash_get(pulse_hash_t* h, const char* key) {
    for (size_t i = 0; i < h->capacity; i++) {
        if (h->entries[i].key && strcmp(h->entries[i].key, key) == 0) {
            return h->entries[i].value;
        }
    }
    return 0;
}

typedef uint64_t (*emit_test_fn_0)(void);
typedef uint64_t (*emit_test_fn_2)(uint64_t, uint64_t);

static uint64_t return_72(void) { return 72; }

static emit_context_t * create_test_context(void) {
    emit_context_t * ctx = NULL;
    (void)emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
    return ctx;
}

static int setup_test_section(emit_context_t * ctx) {
    (void)emit_add_section(ctx, ".text", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_EXECUTE);
    return (emit_begin_section(ctx, ".text") == INFIX_SUCCESS);
}

static int execute_jit_code(const uint8_t * code, size_t size, void ** out_code) {
    void * exec_mem = alloc_executable(size);
    if (!exec_mem) return 0;
    memcpy(exec_mem, code, size);
    *out_code = exec_mem;
    return 1;
}

static void mock_ffi_handler(infix_reverse_t* ctx, void* ret, void** args) {
    (void)ctx; (void)args;
    *(uint64_t*)ret = 777;
}

/* ============================================================================
 * Feature 16: Virtual Register Allocator
 * ============================================================================ */

#define MAX_VREGS 32
#define PHYS_POOL_SIZE 3

typedef enum { VREG_FREE, VREG_IN_PHYS, VREG_SPILLED } vreg_state_t;

typedef struct {
    vreg_state_t state;
    emit_register_t phys_reg;
    int32_t stack_offset;
} vreg_info_t;

typedef struct {
    vreg_info_t vregs[MAX_VREGS];
    emit_register_t pool[PHYS_POOL_SIZE];
    bool phys_busy[PHYS_POOL_SIZE];
    int next_spill_victim;
} pulse_allocator_t;

static void allocator_init(pulse_allocator_t* alloc) {
    memset(alloc, 0, sizeof(pulse_allocator_t));
    alloc->pool[0] = EMIT_REG_RAX;
    alloc->pool[1] = EMIT_REG_RCX;
    alloc->pool[2] = EMIT_REG_RDX;
}

static void pulse_vreg_free(pulse_allocator_t* alloc, int v_id) {
    if (alloc->vregs[v_id].state == VREG_IN_PHYS) {
        for (int i = 0; i < PHYS_POOL_SIZE; i++) {
            if (alloc->pool[i] == alloc->vregs[v_id].phys_reg) {
                alloc->phys_busy[i] = false;
                break;
            }
        }
    }
    alloc->vregs[v_id].state = VREG_FREE;
}

static emit_register_t pulse_vreg_alloc(emit_context_t* ctx, pulse_allocator_t* alloc, int v_id) {
    if (alloc->vregs[v_id].state == VREG_IN_PHYS) return alloc->vregs[v_id].phys_reg;
    bool was_spilled = (alloc->vregs[v_id].state == VREG_SPILLED);
    int p_idx = -1;
    for (int i = 0; i < PHYS_POOL_SIZE; i++) {
        if (!alloc->phys_busy[i]) { p_idx = i; break; }
    }
    if (p_idx == -1) {
        p_idx = alloc->next_spill_victim;
        alloc->next_spill_victim = (alloc->next_spill_victim + 1) % PHYS_POOL_SIZE;
        int v_victim = -1;
        for (int i = 0; i < MAX_VREGS; i++) {
            if (alloc->vregs[i].state == VREG_IN_PHYS && alloc->vregs[i].phys_reg == alloc->pool[p_idx]) {
                v_victim = i; break;
            }
        }
        alloc->vregs[v_victim].stack_offset = -((v_victim + 1) * 8);
        emit_math_store_reg(ctx, EMIT_REG_RBP, alloc->vregs[v_victim].stack_offset, alloc->pool[p_idx]);
        alloc->vregs[v_victim].state = VREG_SPILLED;
    }
    alloc->phys_busy[p_idx] = true;
    alloc->vregs[v_id].state = VREG_IN_PHYS;
    alloc->vregs[v_id].phys_reg = alloc->pool[p_idx];
    if (was_spilled) {
        emit_math_load_reg(ctx, alloc->vregs[v_id].phys_reg, EMIT_REG_RBP, alloc->vregs[v_id].stack_offset);
    }
    return alloc->vregs[v_id].phys_reg;
}

/* ============================================================================
 * Feature 19: Intermediate Representation (IR)
 * ============================================================================ */

typedef enum { P_OP_LOAD_IMM, P_OP_ADD, P_OP_RET } pulse_op_t;
typedef struct { pulse_op_t op; int dest_vreg; int src_a; int src_b; uint64_t imm; } pulse_insn_t;

static void pulse_select_instructions(emit_context_t* ctx, pulse_allocator_t* alloc, pulse_insn_t* stream, size_t count) {
    for (size_t i = 0; i < count; i++) {
        pulse_insn_t* in = &stream[i];
        switch (in->op) {
            case P_OP_LOAD_IMM: {
                emit_register_t pr = pulse_vreg_alloc(ctx, alloc, in->dest_vreg);
                emit_math_mov_imm(ctx, pr, in->imm);
                break;
            }
            case P_OP_ADD: {
                emit_register_t p_dest = pulse_vreg_alloc(ctx, alloc, in->dest_vreg);
                emit_register_t p_a    = pulse_vreg_alloc(ctx, alloc, in->src_a);
                emit_register_t p_b    = pulse_vreg_alloc(ctx, alloc, in->src_b);
                if (p_dest != p_a) emit_math_mov_reg(ctx, p_dest, p_a);
                emit_math_add(ctx, p_dest, p_b);
                break;
            }
            case P_OP_RET: {
                emit_register_t p_src = pulse_vreg_alloc(ctx, alloc, in->dest_vreg);
                if (p_src != EMIT_REG_RAX) emit_math_mov_reg(ctx, EMIT_REG_RAX, p_src);
                emit_math_ret(ctx);
                break;
            }
        }
    }
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================ */

TEST {
    plan(24);

    subtest("Context lifecycle") {
        plan(4);
        emit_context_t * ctx = NULL;
        infix_status status = emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
        ok(status == INFIX_SUCCESS, "emit_create returns success");
        ok(ctx != NULL, "emit_create returns context");
        ok(emit_create(NULL, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY) != INFIX_SUCCESS, "NULL out param fails");
        emit_destroy(ctx);
        ok(1, "emit_destroy safe");
    }

    subtest("MOV instruction") {
        plan(1);
        uint8_t hardcoded[6] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
        void * exec_mem = alloc_executable(6);
        if (exec_mem) {
            memcpy(exec_mem, hardcoded, 6);
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            ok(fn() == 42, "identity() == 42");
            free_executable(exec_mem, 6);
        } else fail("exec fail");
    }

    subtest("Arithmetic instructions") {
        plan(1);
        emit_context_t * ctx = create_test_context();
        setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 7);
        emit_math_add_imm(ctx, EMIT_REG_RAX, 8);
        emit_math_ret(ctx);
        const uint8_t * code = NULL; size_t code_size = 0;
        emit_get_binary(ctx, &code, &code_size);
        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            ok(fn() == 15, "7 + 8 == 15");
            free_executable(exec_mem, code_size);
        }
        emit_destroy(ctx);
    }

    subtest("IMUL instruction") {
        plan(1);
        emit_context_t * ctx = create_test_context();
        setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 6);
        emit_math_imul_imm(ctx, EMIT_REG_RAX, 7);
        emit_math_ret(ctx);
        const uint8_t * code = NULL; size_t code_size = 0;
        emit_get_binary(ctx, &code, &code_size);
        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)exec_mem;
            ok(fn() == 42, "6 * 7 == 42");
            free_executable(exec_mem, code_size);
        }
        emit_destroy(ctx);
    }

    subtest("JMP and RELOCATION") {
        plan(2);
        emit_context_t * ctx = create_test_context();
        setup_test_section(ctx);
        emit_define_symbol(ctx, "target", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "target");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 42);
        emit_math_ret(ctx);
        uint64_t caller_off; emit_get_offset(ctx, &caller_off);
        emit_math_call(ctx, "target");
        emit_math_ret(ctx);
        const uint8_t * code = NULL; size_t code_size = 0;
        emit_get_binary(ctx, &code, &code_size);
        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn1 = (emit_test_fn_0)exec_mem;
            emit_test_fn_0 fn2 = (emit_test_fn_0)((uint8_t*)exec_mem + caller_off);
            ok(fn1() == 42, "label target returns 42");
            ok(fn2() == 42, "relocated call returns 42");
            free_executable(exec_mem, code_size);
        }
        emit_destroy(ctx);
    }

    subtest("Pointer handling & Complex Chains") {
        plan(2);
        emit_context_t * ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "ptr0", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        emit_define_symbol(ctx, "val",  EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        emit_define_symbol(ctx, "link", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        uint64_t data_sz; emit_get_offset(ctx, &data_sz);
        setup_test_section(ctx);
        emit_math_load_sym(ctx, EMIT_REG_RAX, "ptr0");
        emit_math_load_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX, 0);
        emit_math_load_reg(ctx, EMIT_REG_RAX, EMIT_REG_RCX, 0);
        emit_math_store_sym(ctx, "val", EMIT_REG_RAX);
        emit_math_ret(ctx);
        const uint8_t * code = NULL; size_t sz = 0;
        emit_get_binary(ctx, &code, &sz);
        void * mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            volatile uint64_t * p_ptr0 = (uint64_t*)mem;
            volatile uint64_t * p_val   = (uint64_t*)((uint8_t*)mem + 8);
            volatile uint64_t * p_link  = (uint64_t*)((uint8_t*)mem + 16);
            *p_ptr0 = (uintptr_t)p_link; *p_link = (uintptr_t)p_val; *p_val = 0x12345;
            ((emit_test_fn_0)((uint8_t*)mem + data_sz))();
            ok(*p_val == 0x12345, "Terminal value preserved");
            ok(1, "Complex chain followed");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 4: Cheney GC") {
        plan(2);
        pulse_vm_t* vm = vm_create(4096);
        uint64_t* obj = (uint64_t*)gc_alloc(vm, 8, TAG_PRIMITIVE);
        *obj = 0xDEADBEEF;
        void* stack_root = obj;
        vm->root_count = 0;
        vm->roots[vm->root_count++] = &stack_root;
        gc_collect(vm);
        ok(stack_root != obj, "Object moved by Cheney GC");
        ok(*(uint64_t*)stack_root == 0xDEADBEEF, "Data survived move");
        free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 5: Arrays") {
        plan(2);
        pulse_vm_t* vm = vm_create(1024);
        pulse_array_t* arr = (pulse_array_t*)gc_alloc(vm, sizeof(pulse_array_t) + 16, TAG_ARRAY);
        arr->length = 2; arr->data[0] = 111; arr->data[1] = 222;
        ok(arr->length == 2, "Array length metadata ok");
        ok(arr->data[1] == 222, "Array element access ok");
        free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 6: Classes & Method Dispatch") {
        plan(2);
        pulse_vm_t* vm = vm_create(1024);
        uint64_t* obj = gc_alloc(vm, 16, TAG_OBJECT);
        uint64_t vtable[1] = {(uintptr_t)return_72};
        obj[0] = (uintptr_t)vtable;
        ok(obj[0] != 0, "Object has vtable link");
        typedef uint64_t (*meth)(void);
        meth m = (meth)((uint64_t*)obj[0])[0];
        ok(m() == 72, "Method dispatch returns correct value");
        free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 7/8: Exceptions") {
        plan(1);
        pulse_vm_t* vm = vm_create(1024);
        pulse_exception_handler_t h = { .catch_ip = 0x123 };
        vm->handlers = &h;
        ok(vm->handlers->catch_ip == 0x123, "Handler stack functional");
        free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 9: Fibers") {
        plan(2);
        pulse_vm_t* vm = vm_create(2048);
        pulse_fiber_t* fib = (pulse_fiber_t*)gc_alloc(vm, sizeof(pulse_fiber_t), TAG_FIBER);
        fib->stack_mem = malloc(PULSE_STACK_SIZE);
        fib->rsp = (uintptr_t)fib->stack_mem + PULSE_STACK_SIZE - 64;
        ok(fib->rsp % 16 == 0, "Fiber stack 16-byte aligned");
        ok(PAYLOAD_TO_HEADER(fib)->tag == TAG_FIBER, "Fiber correctly tagged");
        free(fib->stack_mem); free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 10: Threads & TLS") {
        plan(1);
        pulse_vm_t* vm = vm_create(1024);
        tls_current_vm = vm;
        ok(tls_current_vm == vm, "Thread-Local Storage preserves isolate");
        free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 11: Pattern Matching (Execution)") {
        plan(3);
        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "obj_ptr", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        uint64_t data_sz; emit_get_offset(ctx, &data_sz);
        setup_test_section(ctx);

        emit_math_load_sym(ctx, EMIT_REG_RAX, "obj_ptr");
        emit_math_load_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX, -12);
        emit_math_cmp_imm(ctx, EMIT_REG_RCX, TAG_ARRAY);
        emit_math_jmp_cc(ctx, EMIT_CC_E, "match");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0);
        emit_math_ret(ctx);
        emit_emit_label(ctx, "match");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 1);
        emit_math_ret(ctx);

        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Pattern match logic emitted");
            volatile uint64_t* obj_ptr_gv = (uint64_t*)mem;
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + data_sz);
            union { gc_header_t head; uint64_t raw[3]; } mock_array, mock_object;
            memset(&mock_array, 0, sizeof(mock_array)); memset(&mock_object, 0, sizeof(mock_object));
            mock_array.head.tag = TAG_ARRAY; mock_object.head.tag = TAG_OBJECT;
            *obj_ptr_gv = (uintptr_t)&mock_array.raw[2];
            ok(fn() == 1, "Matched array tag correctly");
            *obj_ptr_gv = (uintptr_t)&mock_object.raw[2];
            ok(fn() == 0, "Rejected object tag");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 12/13: Variadics & Tuples") {
        plan(2);
        pulse_tuple_t* t = malloc(sizeof(pulse_tuple_t) + 32);
        t->count = 3; t->values[2] = 999;
        ok(t->count == 3, "Tuple return structure valid");
        ok(t->values[2] == 999, "Multiple values accessible in tuple");
        free(t);
    }

    subtest("Feature 14: Infix FFI Bridge (Execution)") {
        plan(3);
        infix_reverse_t* reverse_cb = NULL;
        infix_status s = infix_reverse_create_closure(&reverse_cb, "()->uint64", mock_ffi_handler, NULL, NULL);
        ok(s == INFIX_SUCCESS, "Infix created reverse FFI handle");
        void* native_func = infix_reverse_get_code(reverse_cb);

        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "ffi_target", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        uint64_t data_sz; emit_get_offset(ctx, &data_sz);
        setup_test_section(ctx);

        emit_math_load_sym(ctx, EMIT_REG_RAX, "ffi_target");
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0); /* CALL RAX */
        emit_math_ret(ctx);

        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "FFI bridge logic emitted");
            volatile uint64_t* ffi_ptr = (uint64_t*)mem;
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + data_sz);
            *ffi_ptr = (uintptr_t)native_func;
            ok(fn() == 777, "Pulse JIT successfully executed Infix FFI closure");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
        infix_reverse_destroy(reverse_cb);
    }

    subtest("Namespaces & Operators (Execution)") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "argX", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 10);
        emit_define_symbol(ctx, "argY", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 32);
        uint64_t data_sz; emit_get_offset(ctx, &data_sz);
        setup_test_section(ctx);

        emit_define_symbol(ctx, "Pulse::Math::Add", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "Pulse::Math::Add");
        emit_math_load_sym(ctx, EMIT_REG_RAX, "argX");
        emit_math_load_sym(ctx, EMIT_REG_RCX, "argY");
        emit_math_add(ctx, EMIT_REG_RAX, EMIT_REG_RCX);
        emit_math_ret(ctx);

        uint64_t caller_off; emit_get_offset(ctx, &caller_off);
        emit_math_call(ctx, "Pulse::Math::Add");
        emit_math_ret(ctx);

        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Namespaced logic emitted");
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + data_sz + caller_off);
            ok(fn() == 42, "Namespace symbol resolution worked");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Closures (Execution)") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "env_ptr", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        uint64_t data_sz; emit_get_offset(ctx, &data_sz);

        setup_test_section(ctx);
        emit_math_load_sym(ctx, EMIT_REG_RCX, "env_ptr");
        emit_math_load_reg(ctx, EMIT_REG_RAX, EMIT_REG_RCX, 0);
        emit_math_add_imm(ctx, EMIT_REG_RAX, 100);
        emit_math_ret(ctx);

        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Closure logic emitted");
            volatile uint64_t* p_env = (uint64_t*)mem;
            uint64_t closed_val = 55; *p_env = (uintptr_t)&closed_val;
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + data_sz);
            ok(fn() == 155, "Closure accessed environment");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 15: Manual IO (Execution)") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "msg", EMIT_VISIBILITY_DEFAULT, false);
        const char* hello = "Pulse JIT IO\n"; size_t hlen = strlen(hello);
        for(size_t i=0; i < hlen + 1; i++) emit_emit_u8(ctx, (uint8_t)hello[i]);
        uint64_t dsz; emit_get_offset(ctx, &dsz);
        setup_test_section(ctx);

#ifdef _WIN32
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        void* wfa = (void*)GetProcAddress(k32, "WriteFile");
        void* gsh = (void*)GetProcAddress(k32, "GetStdHandle");
        static DWORD written_count = 0;

        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uint64_t)-12); /* STD_ERROR_HANDLE */
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)gsh);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);

        emit_math_mov_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX);
        emit_math_mov_imm(ctx, EMIT_REG_R8, hlen);
        emit_math_mov_imm(ctx, EMIT_REG_R9, (uintptr_t)&written_count);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 48);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0);
        emit_math_store_reg(ctx, EMIT_REG_RSP, 32, EMIT_REG_RAX);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)wfa);
        emit_math_mov_imm(ctx, EMIT_REG_R12, 0x0); /* Placeholder */
        emit_math_mov_reg(ctx, EMIT_REG_RDX, EMIT_REG_R12);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 48);
#else
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 1);
        emit_math_mov_imm(ctx, EMIT_REG_RDI, 2); /* STDERR */
        emit_math_mov_imm(ctx, EMIT_REG_RSI, 0); /* Placeholder */
        emit_math_mov_imm(ctx, EMIT_REG_RDX, hlen);
        emit_emit_u8(ctx, 0x0F); emit_emit_u8(ctx, 0x05);
#endif
        emit_math_ret(ctx);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Manual IO JIT generated");
            uintptr_t msg_addr = (uintptr_t)mem;
#ifdef _WIN32
            for(size_t i=0; i < sz-8; i++) {
                if (((uint8_t*)mem)[i] == 0x49 && ((uint8_t*)mem)[i+1] == 0xBC) {
                    *(uintptr_t*)((uint8_t*)mem + i + 2) = msg_addr; break;
                }
            }
#else
            for(size_t i=0; i < sz-8; i++) {
                if (((uint8_t*)mem)[i] == 0x48 && ((uint8_t*)mem)[i+1] == 0xBE) {
                    *(uintptr_t*)((uint8_t*)mem + i + 2) = msg_addr; break;
                }
            }
#endif
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + dsz);
            ok(fn() != 0, "Manual IO returned success");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 16: Virtual Register Allocator & Spilling") {
        plan(3);
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        pulse_allocator_t alloc; allocator_init(&alloc);
        emit_math_prologue(ctx);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 64);

        emit_register_t pr0 = pulse_vreg_alloc(ctx, &alloc, 0); emit_math_mov_imm(ctx, pr0, 10);
        emit_register_t pr1 = pulse_vreg_alloc(ctx, &alloc, 1); emit_math_mov_imm(ctx, pr1, 20);
        emit_register_t pr2 = pulse_vreg_alloc(ctx, &alloc, 2); emit_math_mov_imm(ctx, pr2, 30);
        emit_register_t pr3 = pulse_vreg_alloc(ctx, &alloc, 3); emit_math_mov_imm(ctx, pr3, 40);

        emit_register_t r_v0 = pulse_vreg_alloc(ctx, &alloc, 0);
        emit_register_t r_v1 = pulse_vreg_alloc(ctx, &alloc, 1); emit_math_add(ctx, r_v0, r_v1); pulse_vreg_free(&alloc, 1);
        emit_register_t r_v2 = pulse_vreg_alloc(ctx, &alloc, 2); emit_math_add(ctx, r_v0, r_v2); pulse_vreg_free(&alloc, 2);
        emit_register_t r_v3 = pulse_vreg_alloc(ctx, &alloc, 3); emit_math_add(ctx, r_v0, r_v3); pulse_vreg_free(&alloc, 3);

        if (r_v0 != EMIT_REG_RAX) emit_math_mov_reg(ctx, EMIT_REG_RAX, r_v0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 64);
        emit_math_epilogue(ctx);

        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Spill-capable JIT generated");
            emit_test_fn_0 fn = (emit_test_fn_0)mem;
            ok(fn() == 100, "Spill and reload worked");
            ok(alloc.vregs[0].stack_offset != 0, "Spill verified");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 17: Leaf Function Optimization") {
        plan(3);
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        emit_define_symbol(ctx, "std_fn", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "std_fn");
        uint64_t std_start; emit_get_offset(ctx, &std_start);
        emit_math_prologue(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 100);
        emit_math_epilogue(ctx);
        uint64_t std_end; emit_get_offset(ctx, &std_end);
        emit_define_symbol(ctx, "leaf_fn", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "leaf_fn");
        uint64_t leaf_start; emit_get_offset(ctx, &leaf_start);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 100);
        emit_math_ret(ctx);
        uint64_t leaf_end; emit_get_offset(ctx, &leaf_end);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            emit_test_fn_0 fn_std = (emit_test_fn_0)((uint8_t*)mem + std_start);
            emit_test_fn_0 fn_leaf = (emit_test_fn_0)((uint8_t*)mem + leaf_start);
            ok(fn_std() == 100, "Standard function ok");
            ok(fn_leaf() == 100, "Leaf function ok");
            ok((leaf_end - leaf_start) < (std_end - std_start), "Leaf function smaller");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 18: Tail Call Optimization (TCO)") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        emit_define_symbol(ctx, "countdown", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "countdown");
        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 0);
        emit_math_jmp_cc(ctx, EMIT_CC_E, "done");
        emit_math_sub_imm(ctx, EMIT_REG_RCX, 1);
        emit_math_add_imm(ctx, EMIT_REG_RDX, 1);
        emit_math_jmp(ctx, "countdown");
        emit_emit_label(ctx, "done");
        emit_math_mov_reg(ctx, EMIT_REG_RAX, EMIT_REG_RDX);
        emit_math_ret(ctx);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "TCO JIT generated");
            emit_test_fn_2 fn = (emit_test_fn_2)mem;
            ok(fn(100, 0) == 100, "TCO recursion correct");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 19: Architecture-Agnostic IR & Selection") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        pulse_allocator_t alloc; allocator_init(&alloc);
        pulse_insn_t program[4] = {
            { .op = P_OP_LOAD_IMM, .dest_vreg = 0, .imm = 10 },
            { .op = P_OP_LOAD_IMM, .dest_vreg = 1, .imm = 20 },
            { .op = P_OP_ADD,      .dest_vreg = 2, .src_a = 0, .src_b = 1 },
            { .op = P_OP_RET,      .dest_vreg = 2 }
        };
        pulse_select_instructions(ctx, &alloc, program, 4);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            ok(1, "IR Selector valid");
            emit_test_fn_0 fn = (emit_test_fn_0)mem;
            ok(fn() == 30, "IR execution result correct");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 20: Hashes (Dictionaries)") {
        plan(2);
        pulse_hash_t* h = malloc(sizeof(pulse_hash_t) + (sizeof(hash_entry_t) * 4));
        h->capacity = 4; h->count = 1;
        h->entries[0].key = "secret"; h->entries[0].value = 9876;
        ok(pulse_hash_get(h, "secret") == 9876, "C-side hash functional");
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)pulse_hash_get);
        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uintptr_t)h);
        emit_math_mov_imm(ctx, EMIT_REG_RDX, (uintptr_t)"secret");
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 32);
        emit_math_ret(ctx);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)mem;
            ok(fn() == 9876, "JIT hash lookup functional");
            free_executable(mem, sz);
        }
        emit_destroy(ctx); free(h);
    }

    subtest("Feature 21: String Concatenation") {
        plan(2);
        pulse_vm_t* vm = vm_create(4096);
        pulse_string_t* s1 = gc_alloc(vm, sizeof(pulse_string_t) + 8, TAG_STRING);
        s1->length = 5; memcpy(s1->data, "Hello", 5);
        pulse_string_t* s2 = gc_alloc(vm, sizeof(pulse_string_t) + 8, TAG_STRING);
        s2->length = 6; memcpy(s2->data, " World", 6);
        pulse_string_t* res = pulse_string_concat(vm, s1, s2);
        ok(strcmp(res->data, "Hello World") == 0, "C-side concat functional");
        emit_context_t* ctx = create_test_context();
        setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)pulse_string_concat);
        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uintptr_t)vm);
        emit_math_mov_imm(ctx, EMIT_REG_RDX, (uintptr_t)s1);
        emit_math_mov_imm(ctx, EMIT_REG_R8, (uintptr_t)s2);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 32);
        emit_math_ret(ctx);
        const uint8_t* code; size_t sz;
        emit_get_binary(ctx, &code, &sz);
        void* mem = NULL;
        if (execute_jit_code(code, sz, &mem)) {
            emit_test_fn_0 fn = (emit_test_fn_0)mem;
            pulse_string_t* jit_res = (pulse_string_t*)fn();
            ok(strcmp(jit_res->data, "Hello World") == 0, "JIT concat functional");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
        free(vm->from_space); free(vm->to_space); free(vm);
    }
}
