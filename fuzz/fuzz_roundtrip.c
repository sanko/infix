/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file fuzz_roundtrip.c
 * @brief Fuzzer target for Type -> String -> Type round-trip consistency.
 * @ingroup internal_fuzz
 *
 * @internal
 * This fuzzer validates the consistency between the Type System, the Printer,
 * and the Parser.
 *
 * Strategy:
 * 1. Generate a random valid type graph (Source).
 * 2. Print Source to String A.
 * 3. Parse String A to Type Graph B.
 * 4. Print Graph B to String B.
 * 5. Verify String A == String B.
 *
 * This ensures that:
 * - `infix_type_print` never crashes on valid types.
 * - `infix_type_print` produces output that `infix_signature_parse` accepts.
 * - `infix_signature_parse` correctly reconstructs the type attributes (including
 *   bitfield widths and flexible array flags) from the string.
 */

#include "fuzz_helpers.h"
#include <stdlib.h>
#include <string.h>

// Access internal error clearing function
extern void _infix_clear_error(void);

static void FuzzTest(fuzzer_input in) {
    // Clear thread-local error state to avoid stale pointers in g_infix_last_signature_context
    // from previous iterations (stack-use-after-scope).
    _infix_clear_error();

    infix_arena_t * arena = infix_arena_create(65536);
    if (!arena)
        return;

    // 1. Generate Random Type
    size_t total_fields = 0;
    infix_type * type_a = generate_random_type(arena, &in, 0, &total_fields);

    // If generation failed (e.g. out of data), abort
    if (!type_a) {
        infix_arena_destroy(arena);
        return;
    }

    // 2. Print to String A (Serialize)
    // We use a generous buffer. If the type is too complex for this buffer,
    // infix_type_print returns an error, which is a valid outcome, not a crash.
    char buffer_a[4096];
    infix_status status_print_a = infix_type_print(buffer_a, sizeof(buffer_a), type_a, INFIX_DIALECT_SIGNATURE);

    // If the buffer was too small, we simply skip this input.
    // (Ideally we'd realloc, but for fuzzing speed fixed buffer is fine).
    if (status_print_a != INFIX_SUCCESS) {
        infix_arena_destroy(arena);
        return;
    }

    // 3. Parse String A to Type B (Deserialize)
    infix_type * type_b = NULL;
    infix_arena_t * arena_b = NULL;

    // Note: We pass NULL for registry. generate_random_type currently doesn't
    // generate named references (@Name) unless we specifically add logic for it,
    // so this works for anonymous types.
    infix_status status_parse = infix_type_from_signature(&type_b, &arena_b, buffer_a, NULL);

    // CRITICAL CHECK: The parser MUST accept valid output from the printer.
    if (status_parse != INFIX_SUCCESS) {
        // If the generator created a type that exceeds the parser's safety limits,
        // that is acceptable behavior, not a bug. The generator's depth limit
        // is approximate/soft, while the parser's is strict/hard.
        if (infix_get_last_error().code == INFIX_CODE_RECURSION_DEPTH_EXCEEDED) {
            infix_arena_destroy(arena);
            infix_arena_destroy(arena_b);
            return;
        }
        // If the generator created a logically invalid type (e.g. flexible array of
        // zero-sized type), the parser/builder correctly rejects it.
        if (infix_get_last_error().code == INFIX_CODE_INVALID_MEMBER_TYPE) {
            infix_arena_destroy(arena);
            infix_arena_destroy(arena_b);
            return;
        }

        // Integer overflow during layout calculation is also a valid rejection
        // for pathological fuzzer inputs (e.g. [SIZE_MAX:int]).
        if (infix_get_last_error().code == INFIX_CODE_INTEGER_OVERFLOW) {
            infix_arena_destroy(arena);
            infix_arena_destroy(arena_b);
            return;
        }

        fprintf(stderr, "FATAL: Parser rejected valid printer output!\n");
        fprintf(stderr, "Signature: %s\n", buffer_a);
        fprintf(stderr, "Error: %s\n", infix_get_last_error().message);
        // Force a crash to alert the fuzzer
        abort();
    }

    // 4. Print Type B to String B (Reserialize)
    char buffer_b[4096];
    infix_status status_print_b = infix_type_print(buffer_b, sizeof(buffer_b), type_b, INFIX_DIALECT_SIGNATURE);

    if (status_print_b != INFIX_SUCCESS) {
        fprintf(stderr, "FATAL: Failed to print parsed type!\n");
        abort();
    }

    // 5. Verify Consistency
    // The canonical string representation must be identical.
    if (strcmp(buffer_a, buffer_b) != 0) {
        fprintf(stderr, "FATAL: Round-trip mismatch!\n");
        fprintf(stderr, "Original: %s\n", buffer_a);
        fprintf(stderr, "Roundtrip: %s\n", buffer_b);
        abort();
    }

    infix_arena_destroy(arena);
    infix_arena_destroy(arena_b);
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
    fuzzer_input in = {data, size};
    FuzzTest(in);
    return 0;
}
