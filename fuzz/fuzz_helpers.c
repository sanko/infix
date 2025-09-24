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
 * @file fuzz_helpers.c
 * @brief Implementation of the shared recursive infix_type generator for fuzzing.
 *
 * @details This file contains the implementation of the `generate_random_type` function,
 * which is the core of the fuzzing strategy. It is designed to be compiled and linked
 * into multiple fuzzing harnesses, providing a consistent and powerful way to generate
 * complex and pathological test cases for the infix library's type system and ABI logic.
 */

#include "fuzz_helpers.h"

// This is the core of the fuzzing logic. It builds complex types by consuming
// fuzzer data and recursively calling itself to create nested members.
// All allocations are now made from the provided arena.
infix_type * generate_random_type(infix_arena_t * arena, fuzzer_input * in, int depth, size_t * total_fields) {
    // Check total fields and recursion depth at the start of every call.
    if (depth >= MAX_RECURSION_DEPTH || *total_fields >= MAX_TOTAL_FUZZ_FIELDS) {
        // Force a simple type if we're too deep or complex.
        uint8_t prim_byte;
        if (!consume_uint8_t(in, &prim_byte))
            return NULL;
        return infix_type_create_primitive((infix_primitive_type_id)(prim_byte % (INFIX_PRIMITIVE_LONG_DOUBLE + 1)));
    }
    uint8_t type_choice;
    if (!consume_uint8_t(in, &type_choice))
        return NULL;

    // To prevent stack overflows and excessively slow tests, we terminate recursion
    // when the max depth is reached by only allowing simple types to be generated.
    if (depth >= MAX_RECURSION_DEPTH)
        type_choice %= 3;  // Force primitive or pointer.
    else
        type_choice %= 7;  // All choices are available: primitive, pointer, array, struct, union, packed_struct.

    switch (type_choice) {
    case 0:
    case 1:  // Primitive (given a higher probability for variety in generated aggregates)
        {
            uint8_t prim_byte;
            if (!consume_uint8_t(in, &prim_byte))
                return NULL;
            infix_primitive_type_id prim_id = (infix_primitive_type_id)(prim_byte % (INFIX_PRIMITIVE_LONG_DOUBLE + 1));
            // Primitives are static singletons, so this is a safe, non-leaking call.
            return infix_type_create_primitive(prim_id);
        }
    case 2:  // Pointer
        return infix_type_create_pointer();

    case 3:  // Array
        {
            uint8_t num_elements_byte;
            if (!consume_uint8_t(in, &num_elements_byte))
                return NULL;
            size_t num_elements = num_elements_byte % MAX_ARRAY_ELEMENTS;

            // Recursively generate the element type for the array.
            infix_type * element_type = generate_random_type(arena, in, depth + 1, total_fields);
            if (!element_type)
                return NULL;

            infix_type * array_type = NULL;
            (void)infix_type_create_array(arena, &array_type, element_type, num_elements);

            return array_type;  // On failure, array_type is NULL, which is the correct return.
        }
    case 4:  // Struct
    case 5:  // Union
    case 6:  // Packed Struct (shares most logic with struct/union)
        {
            uint8_t num_members_byte;
            if (!consume_uint8_t(in, &num_members_byte))
                return NULL;
            size_t num_members = (num_members_byte % MAX_MEMBERS) + 1;  // Ensure at least 1 member.

            infix_struct_member * members =
                infix_arena_alloc(arena, num_members * sizeof(infix_struct_member), _Alignof(infix_struct_member));

            if (!members)
                return nullptr;

            for (size_t i = 0; i < num_members; ++i) {
                // Abort generation of this aggregate if it's too complex.
                if (*total_fields >= MAX_TOTAL_FUZZ_FIELDS)
                    return nullptr;

                infix_type * member_type = generate_random_type(arena, in, depth + 1, total_fields);

                // If a nested type creation fails, we must clean up everything created so far.
                if (!member_type)
                    return nullptr;

                members[i].name = "fuzz";
                members[i].type = member_type;

                // Fuzzing the member offset is key to finding integer overflows in layout calculation.
                size_t fuzz_offset;
                if (!consume_size_t(in, &fuzz_offset))
                    // Not enough data for a random offset, use a sane default.
                    members[i].offset = (type_choice == 4 || type_choice == 6) ? (i * 8) : 0;
                else
                    members[i].offset = fuzz_offset;
            }

            infix_type * agg_type = NULL;

            if (type_choice == 6) {  // Handle Packed Struct case
                size_t total_size;
                uint8_t alignment_byte;

                // Consume fuzzed size and alignment from the input buffer.
                // These are the key inputs for finding packed struct bugs.
                if (!consume_size_t(in, &total_size))
                    total_size = num_members * 8;  // Fallback
                if (!consume_uint8_t(in, &alignment_byte))
                    alignment_byte = 1;  // Fallback

                // Ensure alignment is not zero, which is invalid.
                size_t alignment = (alignment_byte % 8) + 1;

                (void)infix_type_create_packed_struct(arena, &agg_type, total_size, alignment, members, num_members);
            }
            else {  // Handle regular Struct and Union
                if (type_choice == 4)
                    (void)infix_type_create_struct(arena, &agg_type, members, num_members);
                else
                    (void)infix_type_create_union(arena, &agg_type, members, num_members);
            }
            // On success, the new aggregate type takes ownership of the members array and its sub-types.
            return agg_type;
        }
    }
    return nullptr;
}
