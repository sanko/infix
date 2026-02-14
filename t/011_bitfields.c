/**
 * @file 011_bitfields.c
 * @brief Unit test for bitfield support in structs.
 * @ingroup test_suite
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include "common/platform.h"
#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    unsigned int a : 3;
    unsigned int b : 5;
    unsigned int c : 8;
    unsigned int d : 1;
} BitfieldStruct;

void bitfield_handler(infix_reverse_t * ctx, void * ret, void ** args) {
    (void)ctx;
    BitfieldStruct * s = (BitfieldStruct *)args[0];
    ok(s->a == 5, "Member a is 5");
    ok(s->b == 10, "Member b is 10");
    ok(s->c == 100, "Member c is 100");
    ok(s->d == 1, "Member d is 1");

    // Modify and return via out-pointer if needed, but here we just check input.
    *(int *)ret = s->a + s->b + s->c + s->d;
}

TEST {
    plan(1);
    subtest("Basic Bitfields") {
        plan(8);
        infix_arena_t * arena = NULL;

        // signature: "{a: uint32:3, b: uint32:5, c: uint32:8, d: uint32:1}"
        const char * sig = "{a: uint32:3, b: uint32:5, c: uint32:8, d: uint32:1}";
        infix_type * stype = NULL;
        infix_status status = infix_type_from_signature(&stype, &arena, sig, NULL);
        ok(status == INFIX_SUCCESS, "Parsed bitfield struct signature");

        if (stype) {
            ok(stype->size == sizeof(BitfieldStruct),
               "Struct size matches native (%llu == %llu)",
               (unsigned long long)stype->size,
               (unsigned long long)sizeof(BitfieldStruct));

            infix_type * args[] = {stype};
            infix_reverse_t * ctx = NULL;
            status = infix_reverse_create_closure_manual(
                &ctx, infix_type_create_primitive(INFIX_PRIMITIVE_SINT32), args, 1, 1, bitfield_handler, NULL);
            ok(status == INFIX_SUCCESS, "Created reverse closure for bitfield function");

            if (ctx) {
                typedef int (*bitfield_fn)(BitfieldStruct);
                bitfield_fn fn = (bitfield_fn)infix_reverse_get_code(ctx);

                BitfieldStruct s = {.a = 5, .b = 10, .c = 100, .d = 1};
                int result = fn(s);
                ok(result == 116, "Bitfield handler returned correct sum (%d)", result);

                infix_reverse_destroy(ctx);
            }
        }

        infix_arena_destroy(arena);
    }
}
