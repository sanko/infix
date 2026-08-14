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

typedef struct {
    unsigned int a : 16;
    unsigned int b : 16;
    unsigned int c : 16;
    unsigned int d : 16;
} TrailingUnitBitfields;

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
    plan(3);
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
    subtest("Trailing Storage Unit Bitfield Offsets") {
        plan(6);
        infix_arena_t * arena = NULL;

        // signature: "{a: uint32:16, b: uint32:16, c: uint32:16, d: uint32:16}"
        const char * sig = "{a: uint32:16, b: uint32:16, c: uint32:16, d: uint32:16}";
        infix_type * stype = NULL;
        infix_status status = infix_type_from_signature(&stype, &arena, sig, NULL);
        ok(status == INFIX_SUCCESS, "Parsed trailing-unit bitfield struct signature");

        if (stype) {
            ok(stype->size == sizeof(TrailingUnitBitfields),
               "Struct size matches native (%llu == %llu)",
               (unsigned long long)stype->size,
               (unsigned long long)sizeof(TrailingUnitBitfields));

            // Regression: bitfield members record the storage-unit base in
            // `offset` with `bit_offset` relative to that unit, so unit-sized
            // loads/stores stay inside the aggregate. The old layout put `d`
            // at byte 6 (bit 0), driving 4-byte accesses 2 bytes past the end
            // of this 8-byte struct.
            const size_t exp_offset[] = {0, 0, 4, 4};
            const uint8_t exp_bit_offset[] = {0, 16, 0, 16};
            for (size_t i = 0; i < 4; ++i) {
                const infix_struct_member * m = infix_type_get_member(stype, i);
                ok(m && m->offset == exp_offset[i] && m->bit_offset == exp_bit_offset[i],
                   "Member %c offset %zu bit_offset %u",
                   (int)('a' + i),
                   exp_offset[i],
                   (unsigned)exp_bit_offset[i]);
            }
        }

        infix_arena_destroy(arena);
    }
    subtest("Wide Bitfield Round Trip") {
        // Regression (fuzz_roundtrip crash 9421a219): bitfield widths up to the
        // underlying type's bit size must survive parse -> print -> re-parse.
        // A flat cap of 64 rejected valid 128-bit-type widths (e.g. `sint128:93`).
        plan(13);
        const char * sigs[] = {
            "{a:sint64:64}",
            "{a:sint8:8}",
        };
        for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); ++i) {
            infix_type * t = NULL;
            infix_arena_t * a = NULL;
            infix_status s = infix_type_from_signature(&t, &a, sigs[i], NULL);
            ok(s == INFIX_SUCCESS, "Parsed %s", sigs[i]);
            if (s == INFIX_SUCCESS) {
                char buf[512];
                infix_status p = infix_type_print(buf, sizeof(buf), t, INFIX_DIALECT_SIGNATURE);
                ok(p == INFIX_SUCCESS, "Printed %s", sigs[i]);
                infix_type * t2 = NULL;
                infix_arena_t * a2 = NULL;
                infix_status r = infix_type_from_signature(&t2, &a2, buf, NULL);
                ok(r == INFIX_SUCCESS, "Re-parsed printed output %s", sigs[i]);
                if (a2)
                    infix_arena_destroy(a2);
            }
            if (a)
                infix_arena_destroy(a);
        }
        // `__int128` is a GCC/Clang extension; compilers without it (e.g. MSVC)
        // have no 128-bit integer type, so the 128-bit-width cases only exist
        // where the primitive is available.
        const bool have_int128 = infix_type_create_primitive(INFIX_PRIMITIVE_SINT128) != NULL;
        const char * wide_sigs[] = {
            "{fuzz_bf:sint128:93,fuzz:*void}",
            "{a:sint128:128}",
        };
        for (size_t i = 0; i < sizeof(wide_sigs) / sizeof(wide_sigs[0]); ++i) {
            if (!have_int128) {
                skip(3, "No 128-bit integer type on this compiler");
                continue;
            }
            infix_type * t = NULL;
            infix_arena_t * a = NULL;
            infix_status s = infix_type_from_signature(&t, &a, wide_sigs[i], NULL);
            ok(s == INFIX_SUCCESS, "Parsed %s", wide_sigs[i]);
            if (s == INFIX_SUCCESS) {
                char buf[512];
                infix_status p = infix_type_print(buf, sizeof(buf), t, INFIX_DIALECT_SIGNATURE);
                ok(p == INFIX_SUCCESS, "Printed %s", wide_sigs[i]);
                infix_type * t2 = NULL;
                infix_arena_t * a2 = NULL;
                infix_status r = infix_type_from_signature(&t2, &a2, buf, NULL);
                ok(r == INFIX_SUCCESS, "Re-parsed printed output %s", wide_sigs[i]);
                if (a2)
                    infix_arena_destroy(a2);
            }
            if (a)
                infix_arena_destroy(a);
        }
        // Over-wide bitfields must still be rejected.
        infix_type * bad = NULL;
        infix_arena_t * bad_arena = NULL;
        infix_status bs = infix_type_from_signature(&bad, &bad_arena, "{a:sint64:65}", NULL);
        ok(bs != INFIX_SUCCESS, "Rejected width beyond underlying type ({a:sint64:65})");
        if (bad_arena)
            infix_arena_destroy(bad_arena);
    }
}
