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
 * @brief Implements the core logic for generating random `infix_type` graphs from fuzzer input.
 * @ingroup internal_fuzz
 *
 * @internal
 * This file contains the `generate_random_type` function, which is the heart of
 * the structure-aware fuzzing strategy for the `infix` library. It recursively
 * consumes bytes from the fuzzer's input data stream to build a tree of `infix_type`
 * objects, representing a randomly generated C type.
 *
 * The generation process is probabilistic, controlled by the input data, and is
 * constrained by depth and field count limits to prevent infinite recursion and
 * excessively large types that would lead to timeouts.
 * @endinternal
 */

#include "fuzz_helpers.h"

/**
 * @brief Recursively generates a random `infix_type` graph from a fuzzer input stream.
 *
 * @details This function consumes bytes from the `fuzzer_input` to make decisions
 * about what kind of type to generate. It can create primitives, pointers, arrays,
 * structs (packed and regular), and unions. For composite types, it calls itself
 * recursively to generate member or element types.
 *
 * To prevent timeouts and stack overflows from pathological inputs, the function
 * enforces two key limits:
 * - `MAX_RECURSION_DEPTH`: Limits how deeply types can be nested (e.g., struct within a struct).
 * - `MAX_TOTAL_FUZZ_FIELDS`: Limits the total number of primitive fields in the entire graph.
 *
 * Once a limit is reached, the recursion terminates by generating a simple primitive type.
 *
 * @param arena The memory arena to allocate the new `infix_type` objects into.
 * @param in A pointer to the fuzzer input stream. The stream is consumed as types are generated.
 * @param depth The current recursion depth.
 * @param total_fields A pointer to a counter for the total number of fields generated so far.
 * @return A pointer to the newly generated `infix_type`, or `nullptr` if generation fails or input is exhausted.
 */
infix_type * generate_random_type(infix_arena_t * arena, fuzzer_input * in, int depth, size_t * total_fields) {

    // Termination condition: If we've recursed too deeply or created too many fields,
    // we must stop creating complex types and generate a simple primitive instead.
    if (depth >= MAX_RECURSION_DEPTH || *total_fields >= MAX_TOTAL_FUZZ_FIELDS) {
        uint8_t prim_byte;
        if (!consume_uint8_t(in, &prim_byte))
            return NULL;  // Not enough data to even create a primitive.
        return infix_type_create_primitive((infix_primitive_type_id)(prim_byte % (INFIX_PRIMITIVE_LONG_DOUBLE + 1)));
    }

    // Consume a byte from the input to decide what kind of type to build next.
    uint8_t type_choice;
    if (!consume_uint8_t(in, &type_choice))
        return NULL;

    // To encourage variety, allow more complex types at shallower depths.
    if (depth >= MAX_RECURSION_DEPTH)
        type_choice %= 3;  // Force primitives or pointers
    else
        type_choice %= 7;  // Allow all types

    switch (type_choice) {
    // Cases 0, 1: Generate a Primitive Type
    case 0:
    case 1:
        {
            uint8_t prim_byte;
            if (!consume_uint8_t(in, &prim_byte))
                return NULL;
            infix_primitive_type_id prim_id = (infix_primitive_type_id)(prim_byte % (INFIX_PRIMITIVE_LONG_DOUBLE + 1));
            return infix_type_create_primitive(prim_id);
        }
    // Case 2: Generate a Generic Pointer Type
    case 2:
        return infix_type_create_pointer();

    // Case 3: Generate an Array Type
    case 3:
        {
            uint8_t num_elements_byte;
            if (!consume_uint8_t(in, &num_elements_byte))
                return NULL;
            size_t num_elements = num_elements_byte % MAX_ARRAY_ELEMENTS;

            // Recursively generate the element type.
            infix_type * element_type = generate_random_type(arena, in, depth + 1, total_fields);
            if (!element_type)
                return NULL;

            infix_type * array_type = NULL;
            (void)infix_type_create_array(arena, &array_type, element_type, num_elements);
            return array_type;
        }
    // Cases 4, 5, 6: Generate an Aggregate Type (Struct, Union, Packed Struct)
    case 4:
    case 5:
    case 6:
        {
            uint8_t num_members_byte;
            if (!consume_uint8_t(in, &num_members_byte))
                return NULL;
            size_t num_members = (num_members_byte % MAX_MEMBERS) + 1;

            infix_struct_member * members =
                infix_arena_alloc(arena, num_members * sizeof(infix_struct_member), _Alignof(infix_struct_member));
            if (!members)
                return nullptr;

            // Recursively generate types for each member.
            for (size_t i = 0; i < num_members; ++i) {
                if (*total_fields >= MAX_TOTAL_FUZZ_FIELDS)
                    return nullptr;

                infix_type * member_type = generate_random_type(arena, in, depth + 1, total_fields);
                if (!member_type)
                    return nullptr;

                members[i].name = "fuzz";  // Use a dummy name.
                members[i].type = member_type;

                // For packed structs, consume a random offset. For others, this is ignored
                // but still provides input variety.
                size_t fuzz_offset;
                if (!consume_size_t(in, &fuzz_offset))
                    members[i].offset = (type_choice == 4 || type_choice == 6) ? (i * 8) : 0;
                else
                    members[i].offset = fuzz_offset;
            }

            infix_type * agg_type = NULL;

            if (type_choice == 6) {  // Packed Struct
                size_t total_size;
                uint8_t alignment_byte;
                if (!consume_size_t(in, &total_size))
                    total_size = num_members * 8;
                if (!consume_uint8_t(in, &alignment_byte))
                    alignment_byte = 1;
                size_t alignment = (alignment_byte % 8) + 1;
                (void)infix_type_create_packed_struct(arena, &agg_type, total_size, alignment, members, num_members);
            }
            else {
                if (type_choice == 4)  // Regular Struct
                    (void)infix_type_create_struct(arena, &agg_type, members, num_members);
                else  // Union
                    (void)infix_type_create_union(arena, &agg_type, members, num_members);
            }

            return agg_type;
        }
    }
    return nullptr;
}
