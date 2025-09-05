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
 * @brief Implementation of the shared recursive ffi_type generator for fuzzing.
 *
 * @details This file contains the implementation of the `generate_random_type` function,
 * which is the core of the fuzzing strategy. It is designed to be compiled and linked
 * into multiple fuzzing harnesses, providing a consistent and powerful way to generate
 * complex and pathological test cases for the infix library's type system and ABI logic.
 */

#include "fuzz_helpers.h"

// This is the core of the fuzzing logic. It builds complex types by consuming
// fuzzer data and recursively calling itself to create nested members. Its memory
// management is critical: it must not leak on any internal failure path, otherwise
// it could lead to false positives from AddressSanitizer.
ffi_type * generate_random_type(fuzzer_input * in, int depth) {
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
            ffi_primitive_type_id prim_id = (ffi_primitive_type_id)(prim_byte % (FFI_PRIMITIVE_TYPE_LONG_DOUBLE + 1));
            // Primitives are static singletons, so this is a safe, non-leaking call.
            return ffi_type_create_primitive(prim_id);
        }
    case 2:  // Pointer
        return ffi_type_create_pointer();

    case 3:  // Array
        {
            uint8_t num_elements_byte;
            if (!consume_uint8_t(in, &num_elements_byte))
                return NULL;
            size_t num_elements = num_elements_byte % MAX_ARRAY_ELEMENTS;

            // Recursively generate the element type for the array.
            ffi_type * element_type = generate_random_type(in, depth + 1);
            if (!element_type)
                return NULL;

            ffi_type * array_type = NULL;
            ffi_status status = ffi_type_create_array(&array_type, element_type, num_elements);

            if (status != FFI_SUCCESS) {
                // Per the API contract, on failure, the caller retains ownership of element_type.
                // We must destroy it to prevent a memory leak in the fuzzer.
                ffi_type_destroy(element_type);
                return NULL;
            }
            // On success, the new array_type takes ownership of the element_type.
            return array_type;
        }
    case 4:  // Struct
    case 5:  // Union
    case 6:  // Packed Struct (shares most logic with struct/union)
        {
            uint8_t num_members_byte;
            if (!consume_uint8_t(in, &num_members_byte))
                return NULL;
            size_t num_members = (num_members_byte % MAX_MEMBERS) + 1;  // Ensure at least 1 member.

            ffi_struct_member * members = (ffi_struct_member *)calloc(num_members, sizeof(ffi_struct_member));
            if (!members)
                return NULL;

            for (size_t i = 0; i < num_members; ++i) {
                ffi_type * member_type = generate_random_type(in, depth + 1);
                if (!member_type) {
                    // If a nested type creation fails, we must clean up everything created so far.
                    for (size_t j = 0; j < i; ++j)
                        ffi_type_destroy(members[j].type);
                    free(members);
                    return NULL;
                }
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

            ffi_type * agg_type = NULL;
            ffi_status status;

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

                status = ffi_type_create_packed_struct(&agg_type, total_size, alignment, members, num_members);
            }
            else  // Handle regular Struct and Union
                status = (type_choice == 4) ? ffi_type_create_struct(&agg_type, members, num_members)
                                            : ffi_type_create_union(&agg_type, members, num_members);

            if (status != FFI_SUCCESS) {
                // On failure, we own and must clean up all created member types and the members array.
                for (size_t i = 0; i < num_members; ++i)
                    ffi_type_destroy(members[i].type);
                free(members);
                return NULL;
            }
            // On success, the new aggregate type takes ownership of the members array and its sub-types.
            return agg_type;
        }
    }
    return NULL;
}
