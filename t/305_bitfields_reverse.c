/**
 * @file 305_bitfields_reverse.c
 * @brief Unit test for receiving bitfield structs in reverse trampolines (callbacks).
 * @ingroup test_suite
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdint.h>
#include <string.h>

// Native C Definition
typedef struct {
    uint8_t a : 3;
    uint8_t b : 5;
} SmallBF;

typedef struct {
    uint32_t x : 10;
    uint32_t y : 10;
    uint32_t z : 10;
} LargeBF;

// Global state for callback verification
static int g_callback_called = 0;
static uint8_t g_received_a = 0;
static uint8_t g_received_b = 0;

static int g_large_called = 0;
static uint32_t g_received_x = 0;
static uint32_t g_received_y = 0;
static uint32_t g_received_z = 0;

// Callback Handlers
void small_bf_handler(SmallBF bf) {
    g_callback_called = 1;
    g_received_a = bf.a;
    g_received_b = bf.b;
}

void large_bf_handler(LargeBF bf) {
    g_large_called = 1;
    g_received_x = bf.x;
    g_received_y = bf.y;
    g_received_z = bf.z;
}

// Function pointer types
typedef void (*small_bf_fn)(SmallBF);
typedef void (*large_bf_fn)(LargeBF);

TEST {
    plan(2);
    infix_arena_t * arena = infix_arena_create(4096);

    subtest("Small bitfield (1 byte) in callback") {
        plan(4);

        infix_type * u8 = infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);
        infix_struct_member members[] = {infix_type_create_bitfield_member("a", u8, 0, 3),
                                         infix_type_create_bitfield_member("b", u8, 0, 5)};

        infix_type * bf_type = NULL;
        ok(infix_type_create_struct(arena, &bf_type, members, 2) == INFIX_SUCCESS, "Created small bitfield type");

        infix_reverse_t * ctx = NULL;
        infix_status status = infix_reverse_create_callback_manual(
            &ctx, infix_type_create_void(), &bf_type, 1, 1, (void *)small_bf_handler);
        ok(status == INFIX_SUCCESS, "Created reverse trampoline for small bitfield");

        small_bf_fn func = (small_bf_fn)infix_reverse_get_code(ctx);

        SmallBF arg;
        arg.a = 5;
        arg.b = 20;

        g_callback_called = 0;
        func(arg);

        ok(g_callback_called == 1, "Callback was invoked");
        ok(g_received_a == 5 && g_received_b == 20, "Bitfields received correctly (a=5, b=20)");

        infix_reverse_destroy(ctx);
    }

    subtest("Large bitfield (4 bytes) in callback") {
        plan(5);

        infix_type * u32 = infix_type_create_primitive(INFIX_PRIMITIVE_UINT32);
        infix_struct_member members[] = {infix_type_create_bitfield_member("x", u32, 0, 10),
                                         infix_type_create_bitfield_member("y", u32, 0, 10),
                                         infix_type_create_bitfield_member("z", u32, 0, 10)};

        infix_type * bf_type = NULL;
        ok(infix_type_create_struct(arena, &bf_type, members, 3) == INFIX_SUCCESS, "Created large bitfield type");
        ok(bf_type->size == 4, "Large bitfield struct size is 4 bytes");

        infix_reverse_t * ctx = NULL;
        infix_status status = infix_reverse_create_callback_manual(
            &ctx, infix_type_create_void(), &bf_type, 1, 1, (void *)large_bf_handler);
        ok(status == INFIX_SUCCESS, "Created reverse trampoline for large bitfield");

        large_bf_fn func = (large_bf_fn)infix_reverse_get_code(ctx);

        LargeBF arg;
        arg.x = 100;
        arg.y = 500;
        arg.z = 1000;

        g_large_called = 0;
        func(arg);

        ok(g_large_called == 1, "Callback was invoked");
        ok(g_received_x == 100 && g_received_y == 500 && g_received_z == 1000,
           "Bitfields received correctly (x=100, y=500, z=1000)");

        infix_reverse_destroy(ctx);
    }

    infix_arena_destroy(arena);
}
