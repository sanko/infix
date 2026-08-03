/**
 * @file 863_signature_layout_recalc.c
 * @brief Regression test for layout recalculation of structs inside function signatures.
 * @ingroup test_suite
 *
 * @details Regression test for a bug where the Layout stage
 * (`_infix_type_recalculate_layout`) did not descend into
 * `INFIX_TYPE_REVERSE_TRAMPOLINE` roots. A struct declared inline in a
 * function signature whose members reference named types (e.g. `@png_uint_32`)
 * kept the member offsets computed at parse time, while its members were still
 * unresolved named references (size 0, alignment 1). Once the Resolve stage
 * replaced the references with concrete types, the offsets were never
 * recomputed, so every scalar member collapsed to the same offset.
 *
 * That produced wrong field reads and writes through FFI bindings that use
 * struct-typed arguments, e.g. libpng's `png_image_write_to_file` read back
 * `version == 0` because `version` was written at the wrong byte.
 *
 * The struct below mirrors png_image's shape: a leading pointer member that
 * pushes the scalar fields off offset 0, and scalar fields typed through a
 * named type so they are unresolved until the Resolve stage.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdint.h>

/** @internal Native C mirror of the struct declared inline in the signature. */
typedef struct {
    void * opaque;
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t flags;
} signature_layout_image;

TEST {
    plan(1);
    subtest("layout recalc descends into function args") {
        plan(15);
        infix_registry_t * registry = infix_registry_create();
        ok(registry != nullptr, "registry created");
        if (!registry) {
            skip(14, "Cannot proceed without a registry");
            return;
        }
        infix_status status = infix_register_types(registry, "@png_uint_32 = uint32;");
        ok(status == INFIX_SUCCESS, "registered @png_uint_32 alias");

        infix_arena_t * arena = nullptr;
        infix_type * ret_type = nullptr;
        infix_function_argument * args = nullptr;
        size_t num_args = 0;
        size_t num_fixed_args = 0;
        // Struct declared INLINE in the signature; its members are unresolved
        // named references until the Resolve stage, so the Layout stage must
        // recompute offsets *after* resolution.
        const char * sig =
            "(*{opaque:*void, version:@png_uint_32, width:@png_uint_32, height:@png_uint_32, "
            "format:@png_uint_32, flags:@png_uint_32}) -> bool";
        status = infix_signature_parse(sig, &arena, &ret_type, &args, &num_args, &num_fixed_args, registry);
        ok(status == INFIX_SUCCESS, "signature parses: %s", sig);
        if (status != INFIX_SUCCESS || !arena || !args) {
            diag("signature parse failed; cannot check layout");
            infix_registry_destroy(registry);
            skip(12, "Skipping layout checks due to parse failure");
            return;
        }
        ok(num_args == 1, "signature has one argument");

        const infix_type * arg0 = args[0].type;
        ok(arg0 != nullptr && arg0->category == INFIX_TYPE_POINTER, "argument is a pointer");
        if (!arg0 || arg0->category != INFIX_TYPE_POINTER) {
            infix_arena_destroy(arena);
            infix_registry_destroy(registry);
            skip(10, "Skipping layout checks: unexpected argument type");
            return;
        }
        const infix_type * st = arg0->meta.pointer_info.pointee_type;
        ok(st != nullptr && st->category == INFIX_TYPE_STRUCT, "pointee is a struct");
        if (!st || st->category != INFIX_TYPE_STRUCT) {
            infix_arena_destroy(arena);
            infix_registry_destroy(registry);
            skip(9, "Skipping layout checks: unexpected pointee type");
            return;
        }

        ok(infix_type_get_member_count(st) == 6, "struct has 6 members");
        ok(infix_type_get_size(st) == sizeof(signature_layout_image),
           "struct size %zu matches C sizeof %zu",
           infix_type_get_size(st),
           sizeof(signature_layout_image));
        ok(infix_type_get_alignment(st) == _Alignof(signature_layout_image),
           "struct alignment %zu matches C _Alignof %zu",
           infix_type_get_alignment(st),
           _Alignof(signature_layout_image));

        const infix_struct_member * m;
        m = infix_type_get_member(st, 0);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, opaque),
           "member 0 'opaque' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, opaque));
        m = infix_type_get_member(st, 1);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, version),
           "member 1 'version' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, version));
        m = infix_type_get_member(st, 2);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, width),
           "member 2 'width' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, width));
        m = infix_type_get_member(st, 3);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, height),
           "member 3 'height' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, height));
        m = infix_type_get_member(st, 4);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, format),
           "member 4 'format' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, format));
        m = infix_type_get_member(st, 5);
        ok(m != nullptr && m->offset == offsetof(signature_layout_image, flags),
           "member 5 'flags' offset %zu matches C %zu",
           m ? m->offset : (size_t)-1,
           offsetof(signature_layout_image, flags));

        infix_arena_destroy(arena);
        infix_registry_destroy(registry);
    }
}
