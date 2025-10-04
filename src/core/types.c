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
 * @file types.c
 * @brief Implements the public API for creating and managing type descriptions.
 * @ingroup type_system
 *
 * @internal
 * This file contains the definitions for the public API functions that create `infix_type`
 * objects. It defines static, singleton instances for all primitive C types to avoid
 * unnecessary allocations for common cases. It also provides the logic for dynamically
 * creating complex aggregate types like structs, unions, and arrays from a memory arena.
 *
 * The functions here are responsible for correctly calculating the size and alignment
 * of these types according to standard C layout rules, which is fundamental to ensuring
 * ABI compliance. A key design principle is security: the functions that create dynamic types
 * (`infix_type_create_struct`, `_union`, `_array`) are hardened against integer
 * overflows from potentially malicious input.
 * @endinternal
 */

#include "common/infix_internals.h"
#include "common/utility.h"
#include <limits.h>  // For SIZE_MAX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//=================================================================================================
// Static Singleton Instances for Primitive Types
//=================================================================================================

/*
 * Helper macro to initialize a static `infix_type` for a primitive.
 * This ensures size and alignment are correct for the compilation target at compile time.
 */
#define INFIX_TYPE_INIT(id, T)            \
    {                                     \
        .category = INFIX_TYPE_PRIMITIVE, \
        .size = sizeof(T),                \
        .alignment = _Alignof(T),         \
        .is_arena_allocated = false,      \
        .meta.primitive_id = id,          \
    }

/*
 * These statically allocated singletons are a performance optimization. They avoid
 * dynamic allocation for common types and simplify memory management for the user,
 * as they do not need to be freed.
 */
static infix_type _infix_type_void = {
    .category = INFIX_TYPE_VOID, .size = 0, .alignment = 0, .is_arena_allocated = false, .meta = {0}};

static infix_type _infix_type_pointer = {.category = INFIX_TYPE_POINTER,
                                         .size = sizeof(void *),
                                         .alignment = _Alignof(void *),
                                         .is_arena_allocated = false,
                                         .meta.pointer_info = {.pointee_type = &_infix_type_void}};

static infix_type _infix_type_bool = INFIX_TYPE_INIT(INFIX_PRIMITIVE_BOOL, bool);
static infix_type _infix_type_uint8 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT8, uint8_t);
static infix_type _infix_type_sint8 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT8, int8_t);
static infix_type _infix_type_uint16 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT16, uint16_t);
static infix_type _infix_type_sint16 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT16, int16_t);
static infix_type _infix_type_uint32 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT32, uint32_t);
static infix_type _infix_type_sint32 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT32, int32_t);
static infix_type _infix_type_uint64 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT64, uint64_t);
static infix_type _infix_type_sint64 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT64, int64_t);
#if !defined(INFIX_COMPILER_MSVC)
// 128-bit integers are a non-standard GCC/Clang extension.
static infix_type _infix_type_uint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT128, __uint128_t);
static infix_type _infix_type_sint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT128, __int128_t);
#endif
static infix_type _infix_type_float = INFIX_TYPE_INIT(INFIX_PRIMITIVE_FLOAT, float);
static infix_type _infix_type_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_DOUBLE, double);

// Only define a separate long double type if it's distinct from double on the target platform.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
// On these platforms, long double is an alias for double.
#else
static infix_type _infix_type_long_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_LONG_DOUBLE, long double);
#endif

/*
 * Implementation for infix_type_create_primitive.
 * This acts as a factory, returning a pointer to one of the static singletons.
 * It correctly handles platform-specific ABI differences, such as when `long double`
 * is just an alias for `double`.
 */
c23_nodiscard infix_type * infix_type_create_primitive(infix_primitive_type_id id) {
    switch (id) {
    case INFIX_PRIMITIVE_BOOL:
        return &_infix_type_bool;
    case INFIX_PRIMITIVE_UINT8:
        return &_infix_type_uint8;
    case INFIX_PRIMITIVE_SINT8:
        return &_infix_type_sint8;
    case INFIX_PRIMITIVE_UINT16:
        return &_infix_type_uint16;
    case INFIX_PRIMITIVE_SINT16:
        return &_infix_type_sint16;
    case INFIX_PRIMITIVE_UINT32:
        return &_infix_type_uint32;
    case INFIX_PRIMITIVE_SINT32:
        return &_infix_type_sint32;
    case INFIX_PRIMITIVE_UINT64:
        return &_infix_type_uint64;
    case INFIX_PRIMITIVE_SINT64:
        return &_infix_type_sint64;
#if !defined(INFIX_COMPILER_MSVC)
    case INFIX_PRIMITIVE_UINT128:
        return &_infix_type_uint128;
    case INFIX_PRIMITIVE_SINT128:
        return &_infix_type_sint128;
#endif
    case INFIX_PRIMITIVE_FLOAT:
        return &_infix_type_float;
    case INFIX_PRIMITIVE_DOUBLE:
        return &_infix_type_double;
    case INFIX_PRIMITIVE_LONG_DOUBLE:
// On MSVC, Clang-for-Windows, and all Apple platforms, long double is just an alias for double.
// Return the canonical double type to ensure correct ABI handling.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
        return &_infix_type_double;
#else
        return &_infix_type_long_double;
#endif
    default:
        return nullptr;
    }
}

/*
 * Implementation for infix_type_create_pointer.
 * Returns a pointer to the static singleton instance describing `void*`.
 */
c23_nodiscard infix_type * infix_type_create_pointer(void) {
    return &_infix_type_pointer;
}

/*
 * Implementation for infix_type_create_void.
 * Returns a pointer to the static singleton instance describing the `void` type.
 */
c23_nodiscard infix_type * infix_type_create_void(void) {
    return &_infix_type_void;
}

/*
 * Implementation for infix_type_create_member.
 * This is a simple helper function for creating an `infix_struct_member` value.
 */
infix_struct_member infix_type_create_member(const char * name, infix_type * type, size_t offset) {
    return (infix_struct_member){name, type, offset};
}

/*
 * @internal
 * This is a common setup function for creating any aggregate type (struct or union)
 * from an arena. It handles argument validation, allocates the main `infix_type`
 * struct, and crucially, copies the user-provided `members` array into the arena.
 * This copy makes the final `infix_type` object self-contained and immune to use-after-free
 * bugs if the original `members` array was stack-allocated.
 */
static infix_status _create_aggregate_setup(infix_arena_t * arena,
                                            infix_type ** out_type,
                                            infix_struct_member ** out_arena_members,
                                            infix_struct_member * members,
                                            size_t num_members) {
    if (out_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Validate that all member types are non-null before proceeding.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // Copy the caller's member data into the arena to make this type object self-contained.
    infix_struct_member * arena_members = nullptr;
    if (num_members > 0) {
        arena_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
        if (arena_members == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_ALLOCATION_FAILED;
        }
        memcpy(arena_members, members, sizeof(infix_struct_member) * num_members);
    }

    *out_type = type;
    *out_arena_members = arena_members;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_pointer_to.
 * Creates a pointer type that retains introspection information about its pointee.
 */
c23_nodiscard infix_status infix_type_create_pointer_to(infix_arena_t * arena,
                                                        infix_type ** out_type,
                                                        infix_type * pointee_type) {
    if (!out_type || !pointee_type)
        return INFIX_ERROR_INVALID_ARGUMENT;

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    *type = *infix_type_create_pointer();  // Copy base properties from the void* singleton
    type->is_arena_allocated = true;
    type->meta.pointer_info.pointee_type = pointee_type;
    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_array.
 * Calculates array layout, including a critical security check to prevent integer
 * overflow when calculating the total size from untrusted inputs (e.g., a fuzzer).
 */
c23_nodiscard infix_status infix_type_create_array(infix_arena_t * arena,
                                                   infix_type ** out_type,
                                                   infix_type * element_type,
                                                   size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Security: Check for integer overflow before calculating the total array size.
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_ARRAY;
    type->meta.array_info.element_type = element_type;
    type->meta.array_info.num_elements = num_elements;
    type->alignment = element_type->alignment;
    type->size = element_type->size * num_elements;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_enum.
 * For ABI purposes, an enum is just a wrapper around its underlying integer type.
 */
c23_nodiscard infix_status infix_type_create_enum(infix_arena_t * arena,
                                                  infix_type ** out_type,
                                                  infix_type * underlying_type) {
    if (out_type == nullptr || underlying_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Enums must be based on an integer type.
    if (underlying_type->category != INFIX_TYPE_PRIMITIVE ||
        underlying_type->meta.primitive_id > INFIX_PRIMITIVE_SINT128) {
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    INFIX_DEBUG_PRINTF("Created struct type. Size: %llu, Alignment: %llu",
                       (unsigned long long)type->size,
                       (unsigned long long)type->alignment);
    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_ENUM;
    type->size = underlying_type->size;
    type->alignment = underlying_type->alignment;
    type->meta.enum_info.underlying_type = underlying_type;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_complex.
 * A complex number is laid out in memory as two contiguous floating-point values.
 */
c23_nodiscard infix_status infix_type_create_complex(infix_arena_t * arena,
                                                     infix_type ** out_type,
                                                     infix_type * base_type) {
    if (out_type == nullptr || base_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // A complex number must be based on a float or double.
    if (!is_float(base_type) && !is_double(base_type))
        return INFIX_ERROR_INVALID_ARGUMENT;

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_COMPLEX;
    type->size = base_type->size * 2;
    type->alignment = base_type->alignment;
    type->meta.complex_info.base_type = base_type;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_vector.
 * Calculates vector layout, including overflow checks.
 */
c23_nodiscard infix_status infix_type_create_vector(infix_arena_t * arena,
                                                    infix_type ** out_type,
                                                    infix_type * element_type,
                                                    size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr || element_type->category != INFIX_TYPE_PRIMITIVE)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Security: Check for integer overflow before calculating the total vector size.
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_VECTOR;
    type->meta.vector_info.element_type = element_type;
    type->meta.vector_info.num_elements = num_elements;
    // A vector's size is the total size of its elements.
    type->size = element_type->size * num_elements;
    // Common ABIs require 128-bit vectors to be 16-byte aligned.
    // We will enforce this alignment, as it's the strictest requirement.
    type->alignment = type->size > 8 ? 16 : type->size;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_union.
 * This function calculates the size and alignment for a union according to standard
 * C layout rules: size is the max member size (padded), alignment is the max member alignment.
 */
c23_nodiscard infix_status infix_type_create_union(infix_arena_t * arena,
                                                   infix_type ** out_type,
                                                   infix_struct_member * members,
                                                   size_t num_members) {
    infix_type * type = nullptr;
    infix_struct_member * arena_members = nullptr;
    infix_status status = _create_aggregate_setup(arena, &type, &arena_members, members, num_members);
    if (status != INFIX_SUCCESS) {
        *out_type = nullptr;
        return status;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_UNION;
    type->meta.aggregate_info.members = arena_members;
    type->meta.aggregate_info.num_members = num_members;

    size_t max_size = 0;
    size_t max_alignment = 1;

    // A union's size is determined by its largest member, and its alignment
    // by the strictest alignment of any member.
    for (size_t i = 0; i < num_members; ++i) {
        arena_members[i].offset = 0;  // All union members are at offset 0.
        if (arena_members[i].type->size > max_size)
            max_size = arena_members[i].type->size;
        if (arena_members[i].type->alignment > max_alignment)
            max_alignment = arena_members[i].type->alignment;
    }
    type->alignment = max_alignment;

    // The final size is the size of the largest member, rounded up to a
    // multiple of the union's overall alignment.
    type->size = _infix_align_up(max_size, max_alignment);
    if (type->size < max_size) {  // Overflow check
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    INFIX_DEBUG_PRINTF("Created arena union type. Size: %llu, Alignment: %llu",
                       (unsigned long long)type->size,
                       (unsigned long long)type->alignment);

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_struct.
 * This function calculates the size and alignment of the struct based on its
 * members, adhering to standard C layout and padding rules.
 */
c23_nodiscard infix_status infix_type_create_struct(infix_arena_t * arena,
                                                    infix_type ** out_type,
                                                    infix_struct_member * members,
                                                    size_t num_members) {
    infix_type * type = nullptr;
    infix_struct_member * arena_members = nullptr;
    infix_status status = _create_aggregate_setup(arena, &type, &arena_members, members, num_members);
    if (status != INFIX_SUCCESS) {
        *out_type = nullptr;
        return status;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_STRUCT;
    type->meta.aggregate_info.members = arena_members;
    type->meta.aggregate_info.num_members = num_members;

    size_t current_offset = 0;
    size_t max_alignment = 1;  // Empty structs have an alignment of 1.

    // Calculate layout based on the safe, arena-allocated copy of members.
    for (size_t i = 0; i < num_members; ++i) {
        infix_struct_member * member = &arena_members[i];
        size_t member_align = member->type->alignment;

        if (member_align == 0) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        // Align the current offset for this member.
        size_t aligned_offset = _infix_align_up(current_offset, member_align);

        // Security: Check for integer overflow during alignment.
        if (aligned_offset < current_offset) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset = aligned_offset;
        member->offset = current_offset;

        // Security: Check for integer overflow before adding the member's size.
        if (current_offset > SIZE_MAX - member->type->size) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset += member->type->size;

        if (member_align > max_alignment)
            max_alignment = member_align;
    }

    type->alignment = max_alignment;

    // The final size is the calculated offset rounded up to the nearest multiple
    // of the struct's overall alignment to account for trailing padding.
    type->size = _infix_align_up(current_offset, max_alignment);
    // Security: Check for overflow during final alignment.
    if (type->size < current_offset) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_packed_struct.
 * This variant does not calculate layout; it trusts the user-provided size, alignment,
 * and member offsets, which is necessary for non-standard packed layouts.
 */
c23_nodiscard infix_status infix_type_create_packed_struct(infix_arena_t * arena,
                                                           infix_type ** out_type,
                                                           size_t total_size,
                                                           size_t alignment,
                                                           infix_struct_member * members,
                                                           size_t num_members) {
    if (out_type == nullptr || (num_members > 0 && members == nullptr) || alignment == 0)
        return INFIX_ERROR_INVALID_ARGUMENT;

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // Copy the caller's member data into the arena to make the type self-contained.
    infix_struct_member * arena_members = nullptr;
    if (num_members > 0) {
        arena_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
        if (arena_members == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_ALLOCATION_FAILED;
        }
        memcpy(arena_members, members, sizeof(infix_struct_member) * num_members);
    }

    type->is_arena_allocated = true;
    type->size = total_size;
    type->alignment = alignment;
    type->category = INFIX_TYPE_STRUCT;
    type->meta.aggregate_info.members = arena_members;
    type->meta.aggregate_info.num_members = num_members;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_type_create_named_reference.
 * Creates a placeholder for a type that is referenced by name but not yet defined.
 * A type graph containing this node cannot be used to generate a trampoline.
 */
c23_nodiscard infix_status infix_type_create_named_reference(infix_arena_t * arena,
                                                             infix_type ** out_type,
                                                             const char * name) {
    if (out_type == nullptr || name == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_NAMED_REFERENCE;
    // References are conceptual placeholders. Give them a minimal valid alignment
    // so that they can be stored as members in aggregates without causing
    // layout calculation errors in the parser. The FFI core will reject any
    // attempt to generate a trampoline from a type graph containing this type.
    type->size = 0;
    type->alignment = 1;
    type->meta.named_reference.name = name;

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * The following functions are simple, null-safe getters that form the public
 * Introspection API. They provide a stable way for users to query type and
 * trampoline properties without needing to know the internal layout of the
 * opaque `infix_type_t`, `infix_forward_t`, or `infix_reverse_t` structs.
 * The trampoline-related functions are implemented here for organizational
 * consistency, as they are part of the same conceptual API group.
 */

/*
 * Implementation for infix_type_get_category.
 * This is a simple, null-safe getter. It returns an invalid category enum
 * value if the type pointer is null, which is a safe failure mode.
 */
c23_nodiscard infix_type_category infix_type_get_category(const infix_type * type) {
    return type ? type->category : (infix_type_category)-1;
}

/*
 * Implementation for infix_type_get_size.
 * A simple, null-safe getter. Returns 0 if the type pointer is null, which
 * is a sensible default for an invalid type.
 */
c23_nodiscard size_t infix_type_get_size(const infix_type * type) {
    return type ? type->size : 0;
}

/*
 * Implementation for infix_type_get_alignment.
 * A simple, null-safe getter. Returns 0 if the type pointer is null.
 */
c23_nodiscard size_t infix_type_get_alignment(const infix_type * type) {
    return type ? type->alignment : 0;
}

/*
 * Implementation for infix_type_get_member_count.
 * This getter is both null-safe and type-safe, ensuring we only access
 * aggregate metadata for struct or union types.
 */
c23_nodiscard size_t infix_type_get_member_count(const infix_type * type) {
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION))
        return 0;
    return type->meta.aggregate_info.num_members;
}

/*
 * Implementation for infix_type_get_member.
 * Performs thorough validation (null-check, category check, and bounds check)
 * before returning a pointer to internal member data.
 */
c23_nodiscard const infix_struct_member * infix_type_get_member(const infix_type * type, size_t index) {
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION))
        return nullptr;
    if (index >= type->meta.aggregate_info.num_members)
        return nullptr;
    return &type->meta.aggregate_info.members[index];
}

/*
 * Implementation for infix_type_get_arg_name.
 * Performs validation to ensure the type is a function signature and the index
 * is within bounds before accessing argument metadata.
 */
c23_nodiscard const char * infix_type_get_arg_name(const infix_type * func_type, size_t index) {
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE)
        return nullptr;
    if (index >= func_type->meta.func_ptr_info.num_args)  // Allow access to variadic names if present
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].name;
}

/*
 * Implementation for infix_type_get_arg_type.
 * Performs validation to ensure the type is a function signature and the index
 * is within bounds before returning the argument's type.
 */
c23_nodiscard const infix_type * infix_type_get_arg_type(const infix_type * func_type, size_t index) {
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE)
        return nullptr;
    if (index >= func_type->meta.func_ptr_info.num_args)
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].type;
}


/*
 * Simple null-safe getter for the forward trampoline's argument count.
 */
c23_nodiscard size_t infix_forward_get_num_args(const infix_forward_t * trampoline) {
    return trampoline ? trampoline->num_args : 0;
}

/*
 * Simple null-safe getter for the forward trampoline's return type.
 */
c23_nodiscard const infix_type * infix_forward_get_return_type(const infix_forward_t * trampoline) {
    return trampoline ? trampoline->return_type : nullptr;
}

/*
 * Null-safe and bounds-checked getter for a forward trampoline's argument type.
 */
c23_nodiscard const infix_type * infix_forward_get_arg_type(const infix_forward_t * trampoline, size_t index) {
    if (!trampoline || index >= trampoline->num_args)
        return nullptr;
    return trampoline->arg_types[index];
}

/*
 * Simple null-safe getter for the reverse trampoline's argument count.
 */
c23_nodiscard size_t infix_reverse_get_num_args(const infix_reverse_t * trampoline) {
    return trampoline ? trampoline->num_args : 0;
}

/*
 * Simple null-safe getter for the reverse trampoline's return type.
 */
c23_nodiscard const infix_type * infix_reverse_get_return_type(const infix_reverse_t * trampoline) {
    return trampoline ? trampoline->return_type : nullptr;
}

/*
 * Null-safe and bounds-checked getter for a reverse trampoline's argument type.
 */
c23_nodiscard const infix_type * infix_reverse_get_arg_type(const infix_reverse_t * trampoline, size_t index) {
    if (!trampoline || index >= trampoline->num_args)
        return nullptr;
    return trampoline->arg_types[index];
}
