/**
 * @file 407_float16.c
 * @brief Unit test for half-precision floating-point (float16_t) support.
 * @ingroup test_suite
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "common/platform.h"
#include <infix/infix.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)

// We use uint16_t to represent float16 bits in a portable way for the test handler,
// as not all compilers support _Float16 natively in the same way.
typedef uint16_t f16_bits;

// Basic bitwise conversion from float to half-precision (approximate, for testing)
// This is just to have some values to pass.
static f16_bits float_to_f16(float f) {
    union {
        float f;
        uint32_t i;
    } u = {.f = f};
    uint32_t i = u.i;
    uint32_t s = (i >> 16) & 0x8000;
    uint32_t e = ((i >> 23) & 0xFF) - (127 - 15);
    uint32_t m = (i >> 13) & 0x3FF;

    if (e <= 0)
        return (f16_bits)s;
    if (e >= 31)
        return (f16_bits)(s | 0x7C00);
    return (f16_bits)(s | (e << 10) | m);
}

static float f16_to_float(f16_bits h) {
    uint32_t s = (uint32_t)(h & 0x8000) << 16;
    int32_t e = (h & 0x7C00) >> 10;
    uint32_t m = (h & 0x03FF) << 13;

    if (e == 0) {
        if (m == 0) {
            union {
                uint32_t i;
                float f;
            } u = {.i = s};
            return u.f;
        }
        // Subnormal
        while (!(m & 0x00800000)) {
            m <<= 1;
            e--;
        }
        e++;
        e = e + (127 - 15);
    }
    else if (e == 31) {
        e = 255;
    }
    else {
        e = e + (127 - 15);
    }

    union {
        uint32_t i;
        float f;
    } u = {.i = s | ((uint32_t)e << 23) | m};
    return u.f;
}

// Handler for (f16, f16) -> f16
void f16_add_handler(infix_reverse_t * ctx, void * ret, void ** args) {
    (void)ctx;
    f16_bits a_bits = *(f16_bits *)args[0];
    f16_bits b_bits = *(f16_bits *)args[1];

    float a = f16_to_float(a_bits);
    float b = f16_to_float(b_bits);
    float sum = a + b;
    note("Handler: args[0]=%p, args[1]=%p, ret=%p", args[0], args[1], ret);
    note(
        "Handler: a=%f (bits: 0x%04X), b=%f (bits: 0x%04X), sum=%f", (double)a, a_bits, (double)b, b_bits, (double)sum);

    f16_bits res_bits = float_to_f16(sum);
    *(f16_bits *)ret = res_bits;
    note("Handler: returning bits 0x%04X to %p", res_bits, ret);
}

#endif

TEST {
#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
    plan(1);
    subtest("Float16 (Half-Precision) Reverse Callback") {
        plan(4);
        infix_arena_t * arena = infix_arena_create(2048);
        infix_type * f16_type = infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT16);
        ok(f16_type != NULL, "Created float16 type");
        ok(f16_type->size == 2, "Float16 size is 2 bytes (%llu)", (unsigned long long)f16_type->size);

        infix_reverse_t * ctx = NULL;
        // Use the high-level API to test the new keyword
        infix_status status =
            infix_reverse_create_closure(&ctx, "(float16, float16) -> float16", f16_add_handler, NULL, NULL);
        ok(status == INFIX_SUCCESS, "Created reverse closure for float16 function via signature");

        if (ctx) {
            // We use a forward trampoline to call it safely, avoiding compiler-specific _Float16 support issues.
            infix_forward_t * call_stub = NULL;
            status =
                infix_forward_create(&call_stub, "(float16, float16) -> float16", infix_reverse_get_code(ctx), NULL);

            if (status == INFIX_SUCCESS) {
                // Known bit patterns for half-precision:
                // 1.5  = 0x3E00 (0 01111 1000000000)
                // 2.25 = 0x4080 (0 10000 0010000000)
                // Sum: 3.75 = 0x4380 (0 10000 0111000000)
                f16_bits a = 0x3E00;
                f16_bits b = 0x4080;
                f16_bits result = 0;
                void * call_args[] = {&a, &b};

                infix_cif_func call_fn = infix_forward_get_code(call_stub);
                call_fn(&result, call_args);

                float res_val = f16_to_float(result);
                ok(result == 0x4380,
                   "Float16 add callback returned correct bits (0x%04X, expected 0x4380, val: %.2f)",
                   result,
                   (double)res_val);

                infix_forward_destroy(call_stub);
            }
        }

        if (ctx)
            infix_reverse_destroy(ctx);
        infix_arena_destroy(arena);
    }
#else
    plan(1);
    skip(1, "Float16 tests only implemented for x86-64 and AArch64");
#endif
}
