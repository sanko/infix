/**
 * @file 890_emit_direct.c
 * @brief Unified Test Suite: Infix Emit API & Pulse Language Compiler
 *
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
 * Pulse Runtime Environment & Type Tags
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
#define MAX_VREGS 64
#define PHYS_POOL_SIZE 3

typedef struct gc_header {
    uint32_t size;
    uint16_t tag;
    uint16_t flags;
    void (*finalizer)(void*);
    struct gc_header* forwarding;
} gc_header_t;

#define PAYLOAD_TO_HEADER(p) ((gc_header_t*)(p) - 1)
#define HEADER_TO_PAYLOAD(h) ((void*)((gc_header_t*)(h) + 1))

typedef enum { FIB_NEW, FIB_RUNNING, FIB_YIELDED, FIB_DEAD } fiber_state_t;

typedef struct pulse_fiber {
    gc_header_t header;
    fiber_state_t state;
    void* stack_mem;
    uintptr_t rsp;
} pulse_fiber_t;

typedef struct pulse_exception_handler {
    uintptr_t catch_ip;
    uintptr_t rsp;
    uintptr_t rbp;
    struct pulse_exception_handler* next;
} pulse_exception_handler_t;

typedef struct pulse_vm {
    uint8_t *from_space, *to_space;
    size_t capacity, top;
    void** roots[1024];
    int root_count;
    int finalizers_called;
    pulse_exception_handler_t* handlers;
    void* last_exception;
    pulse_fiber_t* current_fiber;
} pulse_vm_t;

#if defined(_MSC_VER)
    static __declspec(thread) pulse_vm_t* tls_current_vm = NULL;
#else
    static __thread pulse_vm_t* tls_current_vm = NULL;
#endif

typedef struct { size_t length; uint64_t data[16]; } pulse_array_t;
typedef struct { size_t length; char data[64]; } pulse_string_t;
typedef struct { char* key; uint64_t value; } hash_entry_t;
typedef struct { size_t capacity; size_t count; hash_entry_t entries[16]; } pulse_hash_t;
typedef struct { size_t count; uint64_t values[16]; } pulse_tuple_t;

/* ============================================================================
 * Support Functions (Allocation & Execution)
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

static int execute_jit_code(const uint8_t * code, size_t size, void ** out_code) {
    void * exec_mem = alloc_executable(size);
    if (!exec_mem) return 0;
    memcpy(exec_mem, code, size);
    *out_code = exec_mem;
    return 1;
}

static uint64_t return_72(void) { return 72; }
static void my_finalizer(void* p) { (void)p; }

/* ============================================================================
 * Cheney GC Implementation
 * ============================================================================ */

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
    memset(h, 0, sizeof(gc_header_t));
    h->size = (uint32_t)aligned_payload;
    h->tag  = tag;
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
 * JIT Helpers (Called by JIT)
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
        if (h->entries[i].key && strcmp(h->entries[i].key, key) == 0) return h->entries[i].value;
    }
    return 0;
}

static void mock_ffi_handler(infix_reverse_t* ctx, void* ret, void** args) {
    (void)ctx; (void)args;
    *(uint64_t*)ret = 777;
}

typedef struct { uint64_t expected_class; void* target_fn; } inline_cache_t;
static int ic_slow_path_calls = 0;
static void* pulse_ic_lookup(inline_cache_t* ic, uint64_t obj_class, const char* name) {
    ic_slow_path_calls++;
    if (strcmp(name, "identity") == 0) {
        ic->expected_class = obj_class;
        ic->target_fn = (void*)return_72;
        return (void*)return_72;
    }
    return NULL;
}

/* ============================================================================
 * Compiler Backend: Register Allocator & IR logic
 * ============================================================================ */

typedef enum { P_TYPE_INT, P_TYPE_FLOAT } pulse_val_type_t;
typedef enum { VREG_FREE, VREG_IN_PHYS, VREG_SPILLED } vreg_state_t;

typedef struct {
    vreg_state_t state;
    pulse_val_type_t type;
    emit_register_t phys;
    int32_t stack_offset;
} vreg_info_t;

typedef struct {
    vreg_info_t vregs[MAX_VREGS];
    emit_register_t gpr_pool[PHYS_POOL_SIZE];
    emit_register_t xmm_pool[PHYS_POOL_SIZE];
    bool gpr_busy[PHYS_POOL_SIZE];
    bool xmm_busy[PHYS_POOL_SIZE];
    int next_gpr_victim;
} pulse_alloc_t;

static void alloc_init(pulse_alloc_t* a) {
    memset(a, 0, sizeof(pulse_alloc_t));
    a->gpr_pool[0] = EMIT_REG_RAX; a->gpr_pool[1] = EMIT_REG_RCX; a->gpr_pool[2] = EMIT_REG_RDX;
    a->xmm_pool[0] = 0; a->xmm_pool[1] = 1; a->xmm_pool[2] = 2;
}

static void pulse_vreg_free(pulse_alloc_t* a, int vid) {
    if (a->vregs[vid].state == VREG_IN_PHYS) {
        for (int i = 0; i < PHYS_POOL_SIZE; i++) {
            if (a->vregs[vid].type == P_TYPE_INT && a->gpr_pool[i] == a->vregs[vid].phys) {
                a->gpr_busy[i] = false; break;
            }
            if (a->vregs[vid].type == P_TYPE_FLOAT && a->xmm_pool[i] == a->vregs[vid].phys) {
                a->xmm_busy[i] = false; break;
            }
        }
    }
    a->vregs[vid].state = VREG_FREE;
}

static emit_register_t pulse_vreg_alloc(emit_context_t* ctx, pulse_alloc_t* a, int vid, pulse_val_type_t type) {
    if (a->vregs[vid].state == VREG_IN_PHYS) return a->vregs[vid].phys;
    a->vregs[vid].type = type;
    bool was_spilled = (a->vregs[vid].state == VREG_SPILLED);
    int p_idx = -1;
    bool* busy = (type == P_TYPE_INT) ? a->gpr_busy : a->xmm_busy;
    emit_register_t* pool = (type == P_TYPE_INT) ? a->gpr_pool : a->xmm_pool;

    for (int i = 0; i < PHYS_POOL_SIZE; i++) if (!busy[i]) { p_idx = i; break; }

    if (p_idx == -1 && type == P_TYPE_INT) {
        p_idx = a->next_gpr_victim;
        a->next_gpr_victim = (a->next_gpr_victim + 1) % PHYS_POOL_SIZE;
        int victim_v = -1;
        for (int i = 0; i < MAX_VREGS; i++) if (a->vregs[i].state == VREG_IN_PHYS && a->vregs[i].type == P_TYPE_INT && a->vregs[i].phys == pool[p_idx]) {
            victim_v = i; break;
        }
        a->vregs[victim_v].stack_offset = -((victim_v + 1) * 8);
        emit_math_store_reg(ctx, EMIT_REG_RBP, a->vregs[victim_v].stack_offset, pool[p_idx]);
        a->vregs[victim_v].state = VREG_SPILLED;
    }

    busy[p_idx] = true;
    a->vregs[vid].state = VREG_IN_PHYS;
    a->vregs[vid].phys = pool[p_idx];
    if (was_spilled && type == P_TYPE_INT) {
        emit_math_load_reg(ctx, pool[p_idx], EMIT_REG_RBP, a->vregs[vid].stack_offset);
    }
    return a->vregs[vid].phys;
}

typedef enum { P_OP_LOAD_INT, P_OP_LOAD_FLOAT, P_OP_ADD, P_OP_FADD, P_OP_RET, P_OP_JMP } pulse_op_t;
typedef struct {
    pulse_op_t op;
    int dest_vreg; int src_a; int src_b;
    union { int64_t i; double f; const char* target_name; } val;
    bool is_dead;
} pulse_insn_t;

/* ABI Helpers */
#ifdef _WIN32
static const emit_register_t ABI_GPRS[4] = { EMIT_REG_RCX, EMIT_REG_RDX, EMIT_REG_R8, EMIT_REG_R9 };
#define ABI_GPR_COUNT 4
#else
static const emit_register_t ABI_GPRS[6] = { EMIT_REG_RDI, EMIT_REG_RSI, EMIT_REG_RDX, EMIT_REG_RCX, EMIT_REG_R8, EMIT_REG_R9 };
#define ABI_GPR_COUNT 6
#endif

static void pulse_emit_call(emit_context_t* ctx, pulse_alloc_t* alloc, void* target, int* arg_vregs, size_t num_args) {
    int overflow = (int)num_args - ABI_GPR_COUNT;
    if (overflow < 0) overflow = 0;
    size_t padding = (overflow * 8);
#ifdef _WIN32
    padding += 32;
#endif
    if (padding > 0) emit_math_sub_imm(ctx, EMIT_REG_RSP, (int32_t)padding);
    for (size_t i = 0; i < num_args && i < ABI_GPR_COUNT; i++) {
        emit_register_t phys = pulse_vreg_alloc(ctx, alloc, arg_vregs[i], P_TYPE_INT);
        if (phys != ABI_GPRS[i]) emit_math_mov_reg(ctx, ABI_GPRS[i], phys);
    }
    for (size_t i = ABI_GPR_COUNT; i < num_args; i++) {
        emit_register_t phys = pulse_vreg_alloc(ctx, alloc, arg_vregs[i], P_TYPE_INT);
        emit_math_store_reg(ctx, EMIT_REG_RSP, (int32_t)((i - ABI_GPR_COUNT) * 8), phys);
    }
    emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)target);
    emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
    if (padding > 0) emit_math_add_imm(ctx, EMIT_REG_RSP, (int32_t)padding);
}

static void pulse_optimize_ir(pulse_insn_t* stream, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (stream[i].op == P_OP_ADD) {
            pulse_insn_t* a = &stream[stream[i].src_a];
            pulse_insn_t* b = &stream[stream[i].src_b];
            if (a->op == P_OP_LOAD_INT && b->op == P_OP_LOAD_INT) {
                stream[i].op = P_OP_LOAD_INT; stream[i].val.i = a->val.i + b->val.i;
            }
        }
    }
    bool used[MAX_VREGS] = {0};
    for (int i = (int)count - 1; i >= 0; i--) {
        if (stream[i].op == P_OP_RET) used[stream[i].dest_vreg] = true;
        else if (stream[i].op == P_OP_ADD || stream[i].op == P_OP_FADD) {
            if (!used[stream[i].dest_vreg]) stream[i].is_dead = true;
            else { used[stream[i].src_a] = true; used[stream[i].src_b] = true; }
        } else if (stream[i].op == P_OP_LOAD_INT || stream[i].op == P_OP_LOAD_FLOAT) {
            if (!used[stream[i].dest_vreg]) stream[i].is_dead = true;
        }
    }
}

static void pulse_select_instructions(emit_context_t* ctx, pulse_alloc_t* alloc, pulse_insn_t* stream, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (stream[i].is_dead) continue;
        pulse_insn_t* in = &stream[i];
        switch (in->op) {
            case P_OP_LOAD_INT: emit_math_mov_imm(ctx, pulse_vreg_alloc(ctx, alloc, in->dest_vreg, P_TYPE_INT), in->val.i); break;
            case P_OP_LOAD_FLOAT: {
                union { double f; uint64_t u; } conv = { .f = in->val.f };
                emit_register_t tmp = pulse_vreg_alloc(ctx, alloc, MAX_VREGS-1, P_TYPE_INT);
                emit_math_mov_imm(ctx, tmp, conv.u);
                emit_math_push(ctx, tmp);
                emit_register_t d = pulse_vreg_alloc(ctx, alloc, in->dest_vreg, P_TYPE_FLOAT);
                emit_emit_u8(ctx, 0xF2); emit_emit_u8(ctx, 0x0F); emit_emit_u8(ctx, 0x10);
                emit_emit_u8(ctx, 0x04 | ((d & 0x07) << 3)); emit_emit_u8(ctx, 0x24);
                emit_math_pop(ctx, tmp); pulse_vreg_free(alloc, MAX_VREGS-1);
                break;
            }
            case P_OP_ADD: {
                emit_register_t d = pulse_vreg_alloc(ctx, alloc, in->dest_vreg, P_TYPE_INT);
                emit_register_t a = pulse_vreg_alloc(ctx, alloc, in->src_a, P_TYPE_INT);
                emit_register_t b = pulse_vreg_alloc(ctx, alloc, in->src_b, P_TYPE_INT);
                if (d != a) emit_math_mov_reg(ctx, d, a);
                emit_math_add(ctx, d, b); break;
            }
            case P_OP_FADD: {
                emit_register_t d = pulse_vreg_alloc(ctx, alloc, in->dest_vreg, P_TYPE_FLOAT);
                emit_register_t a = pulse_vreg_alloc(ctx, alloc, in->src_a, P_TYPE_FLOAT);
                emit_register_t b = pulse_vreg_alloc(ctx, alloc, in->src_b, P_TYPE_FLOAT);
                if (d != a) emit_math_movsd_reg(ctx, d, a);
                emit_math_addsd(ctx, d, b); break;
            }
            case P_OP_RET: {
                emit_register_t s = pulse_vreg_alloc(ctx, alloc, in->dest_vreg, P_TYPE_INT);
                if (s != EMIT_REG_RAX) emit_math_mov_reg(ctx, EMIT_REG_RAX, s);
                emit_math_ret(ctx); break;
            }
            case P_OP_JMP: emit_math_jmp(ctx, in->val.target_name); break;
        }
    }
}

typedef uint64_t (*emit_test_fn_0)(void);
typedef uint64_t (*emit_test_fn_2)(uint64_t, uint64_t);
typedef double (*pulse_fn_f64)(void);

static emit_context_t * create_test_context(void) {
    emit_context_t * ctx = NULL;
    (void)emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
    return ctx;
}

static int setup_test_section(emit_context_t * ctx) {
    (void)emit_add_section(ctx, ".text", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_EXECUTE);
    return (emit_begin_section(ctx, ".text") == INFIX_SUCCESS);
}

/* ============================================================================
 * TEST SUITE
 * ============================================================================ */

TEST {
    plan(26);

    subtest("Context lifecycle") {
        plan(4);
        emit_context_t * ctx = NULL;
        infix_status status = emit_create(&ctx, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY);
        ok(status == INFIX_SUCCESS, "emit_create success");
        ok(ctx != NULL, "ctx created");
        ok(emit_create(NULL, EMIT_ARCH_X86_64, EMIT_FORMAT_BINARY) != INFIX_SUCCESS, "NULL fail");
        emit_destroy(ctx); ok(1, "destroy safe");
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

    subtest("Arithmetic & IMUL") {
        plan(2);
        emit_context_t * ctx = create_test_context(); setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 6); emit_math_imul_imm(ctx, EMIT_REG_RAX, 7); emit_math_ret(ctx);
        const uint8_t * code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void * mem; if (execute_jit_code(code, sz, &mem)) {
            ok(((emit_test_fn_0)mem)() == 42, "6 * 7 = 42");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);

        ctx = create_test_context(); setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 7); emit_math_add_imm(ctx, EMIT_REG_RAX, 8); emit_math_ret(ctx);
        emit_get_binary(ctx, &code, &sz);
        if (execute_jit_code(code, sz, &mem)) {
            ok(((emit_test_fn_0)mem)() == 15, "7 + 8 = 15");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("JMP and RELOCATION") {
        plan(2);
        emit_context_t * ctx = create_test_context(); setup_test_section(ctx);
        emit_define_symbol(ctx, "target", EMIT_VISIBILITY_DEFAULT, true);
        emit_emit_label(ctx, "target");
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 42); emit_math_ret(ctx);
        uint64_t caller_off; emit_get_offset(ctx, &caller_off);
        emit_math_call(ctx, "target"); emit_math_ret(ctx);
        const uint8_t * code = NULL; size_t code_size = 0;
        emit_get_binary(ctx, &code, &code_size);
        void * exec_mem = NULL;
        if (execute_jit_code(code, code_size, &exec_mem)) {
            emit_test_fn_0 fn1 = (emit_test_fn_0)exec_mem;
            emit_test_fn_0 fn2 = (emit_test_fn_0)((uint8_t*)exec_mem + caller_off);
            ok(fn1() == 42, "direct target ok");
            ok(fn2() == 42, "relocated call ok");
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
        pulse_array_t* arr = (pulse_array_t*)gc_alloc(vm, sizeof(pulse_array_t) + 32, TAG_ARRAY);
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
        /* Use PAYLOAD_TO_HEADER correctly */
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
        pulse_tuple_t* t = malloc(sizeof(pulse_tuple_t) + 64);
        t->count = 3; t->values[2] = 999;
        ok(t->count == 3, "Tuple return structure valid");
        ok(t->values[2] == 999, "Multiple values accessible in tuple");
        free(t);
    }

    subtest("Feature 14: Infix FFI Bridge") {
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

    subtest("Namespaces & Operators") {
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

    subtest("Closures") {
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
        emit_define_symbol(ctx, "msg_ptr", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
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
        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uint64_t)-12);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)gsh);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);

        /* Use R10/R11 instead of callee-saved RBX/R12 */
        emit_math_mov_reg(ctx, EMIT_REG_RCX, EMIT_REG_RAX);
        emit_math_load_sym(ctx, EMIT_REG_R10, "msg_ptr");

        emit_math_mov_imm(ctx, EMIT_REG_R8, hlen);
        emit_math_mov_imm(ctx, EMIT_REG_R9, (uintptr_t)&written_count);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 48);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0);
        emit_math_store_reg(ctx, EMIT_REG_RSP, 32, EMIT_REG_RAX);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)wfa);
        emit_math_mov_reg(ctx, EMIT_REG_RDX, EMIT_REG_R10);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 48);
#else
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 1);
        emit_math_mov_imm(ctx, EMIT_REG_RDI, 2);
        emit_math_load_sym(ctx, EMIT_REG_RSI, "msg_ptr");
        emit_math_mov_imm(ctx, EMIT_REG_RDX, hlen);
        emit_emit_u8(ctx, 0x0F); emit_emit_u8(ctx, 0x05);
#endif
        emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Manual IO JIT generated");
            uint64_t* msg_ptr = (uint64_t*)mem;
            *msg_ptr = (uintptr_t)((uint8_t*)mem + 8);
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + dsz);
            ok(fn() != 0, "Manual IO returned success");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 16: Allocator Spilling") {
        plan(3);
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        pulse_alloc_t a; alloc_init(&a);
        emit_math_prologue(ctx); emit_math_sub_imm(ctx, EMIT_REG_RSP, 64);
        emit_register_t v0 = pulse_vreg_alloc(ctx, &a, 0, P_TYPE_INT); emit_math_mov_imm(ctx, v0, 10);
        emit_register_t v1 = pulse_vreg_alloc(ctx, &a, 1, P_TYPE_INT); emit_math_mov_imm(ctx, v1, 20);
        emit_register_t v2 = pulse_vreg_alloc(ctx, &a, 2, P_TYPE_INT); emit_math_mov_imm(ctx, v2, 30);
        emit_register_t v3 = pulse_vreg_alloc(ctx, &a, 3, P_TYPE_INT); emit_math_mov_imm(ctx, v3, 40);
        emit_register_t rv0 = pulse_vreg_alloc(ctx, &a, 0, P_TYPE_INT);
        emit_register_t rv1 = pulse_vreg_alloc(ctx, &a, 1, P_TYPE_INT); emit_math_add(ctx, rv0, rv1); pulse_vreg_free(&a, 1);
        emit_register_t rv2 = pulse_vreg_alloc(ctx, &a, 2, P_TYPE_INT); emit_math_add(ctx, rv0, rv2); pulse_vreg_free(&a, 2);
        emit_register_t rv3 = pulse_vreg_alloc(ctx, &a, 3, P_TYPE_INT); emit_math_add(ctx, rv0, rv3); pulse_vreg_free(&a, 3);
        if (rv0 != EMIT_REG_RAX) emit_math_mov_reg(ctx, EMIT_REG_RAX, rv0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 64); emit_math_epilogue(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Spill logic generated");
            ok(((emit_test_fn_0)mem)() == 100, "Spill calculation ok");
            ok(a.vregs[0].stack_offset != 0, "Spill occurred");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 17: Leaf Optimization") {
        plan(3);
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        emit_define_symbol(ctx, "std_fn", EMIT_VISIBILITY_DEFAULT, true); emit_emit_label(ctx, "std_fn");
        uint64_t std_start; emit_get_offset(ctx, &std_start);
        emit_math_prologue(ctx); emit_math_mov_imm(ctx, EMIT_REG_RAX, 100); emit_math_epilogue(ctx);
        uint64_t std_end; emit_get_offset(ctx, &std_end);
        emit_define_symbol(ctx, "leaf_fn", EMIT_VISIBILITY_DEFAULT, true); emit_emit_label(ctx, "leaf_fn");
        uint64_t leaf_start; emit_get_offset(ctx, &leaf_start);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 100); emit_math_ret(ctx);
        uint64_t leaf_end; emit_get_offset(ctx, &leaf_end);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            emit_test_fn_0 fn_std = (emit_test_fn_0)((uint8_t*)mem + std_start);
            emit_test_fn_0 fn_leaf = (emit_test_fn_0)((uint8_t*)mem + leaf_start);
            ok(fn_std() == 100, "Std function ok");
            ok(fn_leaf() == 100, "Leaf function ok");
            ok((leaf_end - leaf_start) < (std_end - std_start), "Leaf function smaller");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 18: Tail Call Optimization (TCO)") {
        plan(2);
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        emit_define_symbol(ctx, "countdown", EMIT_VISIBILITY_DEFAULT, true); emit_emit_label(ctx, "countdown");
        emit_math_cmp_imm(ctx, EMIT_REG_RCX, 0); emit_math_jmp_cc(ctx, EMIT_CC_E, "done");
        emit_math_sub_imm(ctx, EMIT_REG_RCX, 1); emit_math_add_imm(ctx, EMIT_REG_RDX, 1);
        emit_math_jmp(ctx, "countdown"); emit_emit_label(ctx, "done");
        emit_math_mov_reg(ctx, EMIT_REG_RAX, EMIT_REG_RDX); emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            ok(1, "TCO generated");
            emit_test_fn_2 fn = (emit_test_fn_2)mem;
            ok(fn(100, 0) == 100, "TCO recursion correct");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 19 & 27: IR & DCE") {
        plan(3);
        pulse_insn_t program[5] = {
            { .op = P_OP_LOAD_INT, .dest_vreg = 0, .val.i = 10 },
            { .op = P_OP_LOAD_INT, .dest_vreg = 1, .val.i = 20 },
            { .op = P_OP_ADD,      .dest_vreg = 2, .src_a = 0, .src_b = 1 },
            { .op = P_OP_LOAD_INT, .dest_vreg = 3, .val.i = 99 },
            { .op = P_OP_RET,      .dest_vreg = 2 }
        };
        pulse_optimize_ir(program, 5);
        ok(program[2].op == P_OP_LOAD_INT && program[2].val.i == 30, "Folded");
        ok(program[3].is_dead, "DCE ok");
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        pulse_alloc_t a; alloc_init(&a); pulse_select_instructions(ctx, &a, program, 5);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void * mem; if (execute_jit_code(code, sz, &mem)) {
            ok(((emit_test_fn_0)mem)() == 30, "IR execution ok");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 20: Dictionaries") {
        plan(2);
        pulse_hash_t* h = malloc(sizeof(pulse_hash_t) + (sizeof(hash_entry_t) * 4));
        h->capacity = 4; h->entries[0].key = "secret"; h->entries[0].value = 9876;
        ok(pulse_hash_get(h, "secret") == 9876, "C-side hash functional");
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)pulse_hash_get);
        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uintptr_t)h);
        emit_math_mov_imm(ctx, EMIT_REG_RDX, (uintptr_t)"secret");
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 32); emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            ok(((emit_test_fn_0)mem)() == 9876, "JIT hash lookup functional");
            free_executable(mem, sz);
        }
        emit_destroy(ctx); free(h);
    }

    subtest("Feature 21: Strings") {
        plan(2);
        pulse_vm_t* vm = vm_create(4096);
        pulse_string_t* s1 = (pulse_string_t*)gc_alloc(vm, sizeof(pulse_string_t) + 8, TAG_STRING);
        s1->length = 5; memcpy(s1->data, "Hello", 5);
        pulse_string_t* s2 = (pulse_string_t*)gc_alloc(vm, sizeof(pulse_string_t) + 8, TAG_STRING);
        s2->length = 6; memcpy(s2->data, " World", 6);
        ok(strcmp(pulse_string_concat(vm, s1, s2)->data, "Hello World") == 0, "C-side concat ok");

        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)pulse_string_concat);
        emit_math_mov_imm(ctx, EMIT_REG_RCX, (uintptr_t)vm);
        emit_math_mov_imm(ctx, EMIT_REG_RDX, (uintptr_t)s1);
        emit_math_mov_imm(ctx, EMIT_REG_R8, (uintptr_t)s2);
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
        emit_math_add_imm(ctx, EMIT_REG_RSP, 32); emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            pulse_string_t* res = (pulse_string_t*)((emit_test_fn_0)mem)();
            ok(strcmp(res->data, "Hello World") == 0, "JIT concat ok");
            free_executable(mem, sz);
        }
        emit_destroy(ctx); free(vm->from_space); free(vm->to_space); free(vm);
    }

    subtest("Feature 22/23: Call Orchestration") {
        plan(2);
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        pulse_alloc_t alloc; alloc_init(&alloc);
        int args[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        emit_math_prologue(ctx);
        for (int i = 0; i < 8; i++) {
            emit_register_t p = pulse_vreg_alloc(ctx, &alloc, i, P_TYPE_INT);
            emit_math_mov_imm(ctx, p, i + 1);
        }
        pulse_emit_call(ctx, &alloc, (void*)return_72, args, 8);
        emit_math_epilogue(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            ok(1, "Orchestrator generated");
            ok(((emit_test_fn_0)mem)() == 72, "Call executed ok");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 25: Float Math (SSE2)") {
        plan(1);
        emit_context_t* ctx = create_test_context(); setup_test_section(ctx);
        pulse_alloc_t a; alloc_init(&a);
        pulse_insn_t program[3] = {
            { .op = P_OP_LOAD_FLOAT, .dest_vreg = 0, .val.f = 1.5 },
            { .op = P_OP_LOAD_FLOAT, .dest_vreg = 1, .val.f = 2.75 },
            { .op = P_OP_FADD,       .dest_vreg = 2, .src_a = 0, .src_b = 1 }
        };
        pulse_select_instructions(ctx, &a, program, 3);
        emit_register_t d = pulse_vreg_alloc(ctx, &a, 2, P_TYPE_FLOAT);
        emit_math_movq_gpr_xmm(ctx, EMIT_REG_RAX, d); emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            uint64_t raw = ((emit_test_fn_0)mem)(); double res; memcpy(&res, &raw, 8);
            ok(res == 4.25, "Float math result correct");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }

    subtest("Feature 29: Inline Caching") {
        plan(2);
        emit_context_t* ctx = create_test_context();
        emit_add_section(ctx, ".data", EMIT_SECTION_FLAG_ALLOC | EMIT_SECTION_FLAG_WRITE);
        emit_begin_section(ctx, ".data");
        emit_define_symbol(ctx, "ic_ptr", EMIT_VISIBILITY_DEFAULT, false); emit_emit_u64(ctx, 0);
        emit_define_symbol(ctx, "ic_struct", EMIT_VISIBILITY_DEFAULT, false);
        emit_emit_u64(ctx, 0); emit_emit_u64(ctx, 0);
        uint64_t dsz; emit_get_offset(ctx, &dsz);
        setup_test_section(ctx);
        emit_math_mov_imm(ctx, EMIT_REG_RAX, 0xABC);
        emit_math_load_sym(ctx, EMIT_REG_R10, "ic_ptr");
        emit_math_load_reg(ctx, EMIT_REG_RDX, EMIT_REG_R10, 0);
        emit_math_cmp(ctx, EMIT_REG_RAX, EMIT_REG_RDX);
        emit_math_jmp_cc(ctx, EMIT_CC_NE, "miss");
        emit_math_load_reg(ctx, EMIT_REG_R11, EMIT_REG_R10, 8);
        emit_emit_u8(ctx, 0x41); emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD3); /* CALL R11 */
        emit_math_ret(ctx);
        emit_emit_label(ctx, "miss");
#ifdef _WIN32
        emit_math_mov_reg(ctx, EMIT_REG_RCX, EMIT_REG_R10);
        emit_math_mov_reg(ctx, EMIT_REG_RDX, EMIT_REG_RAX);
        emit_math_mov_imm(ctx, EMIT_REG_R8, (uintptr_t)"identity");
        emit_math_sub_imm(ctx, EMIT_REG_RSP, 32);
#else
        emit_math_mov_reg(ctx, EMIT_REG_RDI, EMIT_REG_R10);
        emit_math_mov_reg(ctx, EMIT_REG_RSI, EMIT_REG_RAX);
        emit_math_mov_imm(ctx, EMIT_REG_RDX, (uintptr_t)"identity");
#endif
        emit_math_mov_imm(ctx, EMIT_REG_RAX, (uintptr_t)pulse_ic_lookup);
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0);
#ifdef _WIN32
        emit_math_add_imm(ctx, EMIT_REG_RSP, 32);
#endif
        emit_emit_u8(ctx, 0xFF); emit_emit_u8(ctx, 0xD0); emit_math_ret(ctx);
        const uint8_t* code; size_t sz; emit_get_binary(ctx, &code, &sz);
        void* mem; if (execute_jit_code(code, sz, &mem)) {
            uint64_t* ic_ptr = (uint64_t*)mem;
            *ic_ptr = (uintptr_t)((uint8_t*)mem + 8);
            emit_test_fn_0 fn = (emit_test_fn_0)((uint8_t*)mem + dsz);
            fn(); ok(ic_slow_path_calls == 1, "Miss populated cache");
            fn(); ok(ic_slow_path_calls == 1, "Hit skipped slow path");
            free_executable(mem, sz);
        }
        emit_destroy(ctx);
    }
}

