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
 * @brief Implements the FFI type system for creating and managing type descriptions.
 *
 * @details This file contains the definitions for the public API functions that
 * create `infix_type` objects. It defines static, singleton instances for all
 * primitive C types to avoid unnecessary allocations for common cases. It also provides
 * the logic for dynamically creating complex aggregate types like structs,
 * unions, and arrays from a memory arena.
 *
 * The functions here are responsible for correctly calculating the size and alignment
 * of these types according to standard C layout rules, which is fundamental to ensuring
 * ABI compliance. A key design principle is security: the functions that create dynamic types
 * (`infix_type_create_struct`, `_union`, `_array`) are hardened against integer
 * overflows from potentially malicious input. They also follow a strict memory
 * ownership model to prevent leaks in error-handling paths.
 */

#include "../common/infix_internals.h"
#include "../common/utility.h"
#include <limits.h>  // For SIZE_MAX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @def INFIX_TYPE_INIT
 * @brief (Internal) A helper macro to initialize a static `infix_type` for a primitive.
 * @details This macro simplifies the static initialization of the singleton primitive
 *          type instances. It sets the category, size, alignment, and primitive ID
 *          at compile time using the results of `sizeof` and `_Alignof`, ensuring
 *          that the type descriptors are correct for the compilation target.
 * @internal
 */
#define INFIX_TYPE_INIT(id, T)            \
    {                                     \
        .category = INFIX_TYPE_PRIMITIVE, \
        .size = sizeof(T),                \
        .alignment = _Alignof(T),         \
        .is_arena_allocated = false,      \
        .meta.primitive_id = id,          \
    }

// Statically allocated, singleton instances for all fundamental types.
// This is a performance optimization that avoids dynamic allocation and deallocation
// for common types. It allows them to be used without needing to be manually freed,
// simplifying the user's code.
static infix_type _infix_type_void = {
    .category = INFIX_TYPE_VOID, .size = 0, .alignment = 0, .is_arena_allocated = false, .meta = {0}};
// The generic pointer now explicitly points to void for introspection purposes.
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
// 128-bit integers are a non-standard GCC/Clang extension, so they are conditionally compiled.
static infix_type _infix_type_uint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT128, __uint128_t);
static infix_type _infix_type_sint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT128, __int128_t);
#endif
static infix_type _infix_type_float = INFIX_TYPE_INIT(INFIX_PRIMITIVE_FLOAT, float);
static infix_type _infix_type_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_DOUBLE, double);
// Only define a separate long double type if it's distinct from double.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
// On these platforms, long double is an alias for double, so no separate type is needed.
#else
static infix_type _infix_type_long_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_LONG_DOUBLE, long double);
#endif

/**
 * @brief Creates an `infix_type` descriptor for a primitive C type.
 * @details This function acts as a factory, returning a pointer to one of the
 *          statically allocated, singleton `infix_type` instances for primitives.
 *          It correctly handles platform-specific type definitions, such as `long double`
 *          being equivalent to `double` on MSVC and Clang for Windows, ensuring the
 *          correct type descriptor is used for the target ABI.
 *
 * @param id The ID of the primitive type (e.g., `INFIX_PRIMITIVE_SINT32`).
 * @return A pointer to the corresponding static `infix_type` structure.
 *         Returns `nullptr` if the ID is invalid or for a type not supported by the
 *         current compiler (e.g., `__int128_t` on MSVC).
 * @warning Do not free the returned pointer. It points to a static global variable.
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
    case INFIX_PRIMITIVE_LONG_DOUBLE:
        // On MSVC, Clang for Windows, and all Apple platforms, long double is just an alias for double.
        // Return the canonical double type to ensure correct ABI handling.
#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
        return &_infix_type_double;
#else
        return &_infix_type_long_double;
#endif
    case INFIX_PRIMITIVE_FLOAT:
        return &_infix_type_float;
    case INFIX_PRIMITIVE_DOUBLE:
        return &_infix_type_double;
    default:
        // An unknown or unsupported primitive ID was provided.
        return nullptr;
    }
}

/**
 * @brief Creates an `infix_type` descriptor for a generic pointer.
 * @details Returns a pointer to the static singleton instance describing `void*`.
 *          This should be used for all pointer types in a function signature, as the
 *          ABI treats all data pointers identically.
 *
 * @return A pointer to the statically-allocated `infix_type` for pointers.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard infix_type * infix_type_create_pointer() {
    return &_infix_type_pointer;
}

/**
 * @brief Creates an `infix_type` descriptor for the `void` type.
 * @details Returns a pointer to the static singleton instance describing the `void` type,
 *          used exclusively for the return type of a function that returns nothing.
 *
 * @return A pointer to the statically-allocated `infix_type` for void.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard infix_type * infix_type_create_void() {
    return &_infix_type_void;
}

/**
 * @brief Creates an `infix_type` for a pointer to a specific type, allocating from an arena.
 * @details This function is the designated way to create a pointer type that retains
 *          introspection information about what it points to.
 *
 * @param arena The arena to allocate the new pointer type from.
 * @param[out] out_type On success, will point to the new `infix_type`.
 * @param pointee_type The `infix_type` that the new pointer type points to.
 * @return `INFIX_SUCCESS` on success, `INFIX_ERROR_INVALID_ARGUMENT` if arguments are null,
 *         or `INFIX_ERROR_ALLOCATION_FAILED` on allocation failure.
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

/**
 * @brief Creates an `infix_type` for a struct, allocating from an arena.
 * @details This function calculates the size and alignment of the struct based on its
 *          members, adhering to standard C layout rules. It iterates through the members
 *          to find the maximum alignment requirement and calculates the total size, including
 *          any trailing padding needed to satisfy the struct's overall alignment.
 *
 *          To ensure the created `infix_type` is self-contained, this function
 *          allocates memory for the `members` array from the provided arena and
 *          copies the caller's member data into it. This prevents dangling
 *          pointers if the caller's `members` array was allocated on the stack.
 *
 * @param arena The memory arena from which to allocate the new `infix_type`.
 * @param[out] out_type On success, a pointer to an `infix_type*` that will receive the new type.
 * @param members An array of `infix_struct_member` describing the struct's layout.
 * @param num_members The number of members in the array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_type_create_struct(infix_arena_t * arena,
                                                    infix_type ** out_type,
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

    // Robustness: Copy the caller's member data into the arena to make this
    // type object self-contained and immune to use-after-free errors.
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
    type->category = INFIX_TYPE_STRUCT;
    type->meta.aggregate_info.members = arena_members;
    type->meta.aggregate_info.num_members = num_members;

    size_t current_offset = 0;
    // Initialize max_alignment to 1. This is the alignment of an empty struct
    // and a safe starting point for calculations.
    size_t max_alignment = 1;

    // Calculate layout based on the safe, arena-allocated copy of members.
    for (size_t i = 0; i < num_members; ++i) {
        infix_struct_member * member = &arena_members[i];
        size_t member_align = member->type->alignment;

        if (member_align == 0) {  // Should not happen for valid types.
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        // Calculate padding required to align the current offset for this member.
        size_t padding = (member_align - (current_offset % member_align)) % member_align;

        // Security: Check for integer overflow before adding padding.
        if (current_offset > SIZE_MAX - padding) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset += padding;

        // Set the final calculated offset for this member.
        member->offset = current_offset;

        // Security: Check for integer overflow before adding the member's size.
        if (current_offset > SIZE_MAX - member->type->size) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset += member->type->size;

        // Update the maximum alignment required by the struct.
        if (member_align > max_alignment)
            max_alignment = member_align;
    }

    type->alignment = max_alignment;

    // Security: Check for overflow when calculating the final rounded-up size.
    if (max_alignment > 0 && current_offset > SIZE_MAX - (max_alignment - 1)) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    // The final size is the calculated offset rounded up to the nearest multiple
    // of the struct's overall alignment to account for trailing padding.
    type->size = (current_offset + max_alignment - 1) & ~(max_alignment - 1);

    INFIX_DEBUG_PRINTF("Created struct type. Size: %llu, Alignment: %llu",
                       (unsigned long long)type->size,
                       (unsigned long long)type->alignment);
    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Creates an `infix_type` for a packed struct, allocating from an arena.
 * @details This is the designated way to describe C structs that use
 *          non-standard memory layouts (`__attribute__((packed))` or `#pragma pack`).
 *
 *          To ensure the created `infix_type` is self-contained, this function
 *          allocates memory for the `members` array from the provided arena and
 *          copies the caller's member data into it. This prevents dangling
 *          pointers if the caller's `members` array was allocated on the stack.
 *
 * @param arena The memory arena from which to allocate the new `infix_type`.
 * @param[out] out_type On success, this will point to a newly created `infix_type`.
 * @param total_size The exact size of the packed struct in bytes.
 * @param alignment The alignment requirement of the packed struct in bytes.
 * @param members An array of `infix_struct_member` describing each member,
 *                with offsets manually specified.
 * @param num_members The number of elements in the `members` array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
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

    // Robustness: Copy the caller's member data into the arena.
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

/**
 * @brief A factory function to create an `infix_struct_member`.
 * @details This is a convenient helper function for creating an `infix_struct_member`,
 *          which is needed to define the layout of structs and unions.
 *
 * @param name The member's name (for debugging purposes; can be `nullptr`).
 * @param type A pointer to the member's `infix_type`.
 * @param offset The byte offset of the member from the start of the aggregate. This
 *               value should be obtained using the standard `offsetof` macro.
 * @return An initialized `infix_struct_member`.
 */
infix_struct_member infix_struct_member_create(const char * name, infix_type * type, size_t offset) {
    return (infix_struct_member){name, type, offset};
}

/**
 * @brief Creates an `infix_type` for a union, allocating from an arena.
 * @details This function calculates the size and alignment for a union according to
 *          standard C layout rules. The alignment is the largest alignment of any
 *          member. The size is the size of the largest single member, padded to be
 *          a multiple of the union's final alignment.
 *
 *          To ensure the created `infix_type` is self-contained, this function
 *          allocates memory for the `members` array from the provided arena and
 *          copies the caller's member data into it.
 *
 * @param arena The memory arena from which to allocate the new `infix_type`.
 * @param[out] out_type On success, will point to the newly created `infix_type`.
 * @param members An array of `infix_struct_member` describing the union's members.
 * @param num_members The number of members in the array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_type_create_union(infix_arena_t * arena,
                                                   infix_type ** out_type,
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

    // Allocate the infix_type struct itself from the arena.
    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // Robustness: Copy the caller's member data into the arena.
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

    // Mark this type as arena-allocated so infix_type_destroy will ignore it.
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

    // Security: Check for integer overflow before calculating the final padded size.
    if (max_alignment > 0 && max_size > SIZE_MAX - (max_alignment - 1)) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;  // Overflow would occur
    }

    // The final size is the size of the largest member, rounded up to a
    // multiple of the union's overall alignment.
    type->size = (max_size + max_alignment - 1) & ~(max_alignment - 1);

    INFIX_DEBUG_PRINTF("Created arena union type. Size: %llu, Alignment: %llu",
                       (unsigned long long)type->size,
                       (unsigned long long)type->alignment);

    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Creates an `infix_type` for a fixed-size array, allocating from an arena.
 * @details This function calculates the size and alignment for a fixed-size array.
 *          The alignment is the same as the element type's alignment. The size is
 *          the element size multiplied by the number of elements, with a check to
 *          prevent integer overflow during the calculation.
 *
 * @param arena The memory arena from which to allocate the new `infix_type`.
 * @param[out] out_type On success, will point to the newly created `infix_type`.
 * @param element_type An `infix_type` describing the type of elements in the array.
 * @param num_elements The number of elements in the array.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_type_create_array(infix_arena_t * arena,
                                                   infix_type ** out_type,
                                                   infix_type * element_type,
                                                   size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Security: Check for integer overflow before calculating the total array size.
    // This is critical when dealing with inputs from a parser or other untrusted source.
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;  // Calculation would overflow.
    }

    // Allocate the infix_type struct itself from the arena.
    infix_type * type = infix_arena_alloc(arena, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // Mark this type as arena-allocated so infix_type_destroy will ignore it.
    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_ARRAY;
    type->meta.array_info.element_type = element_type;
    type->meta.array_info.num_elements = num_elements;

    // An array's alignment is the same as its element's alignment.
    type->alignment = element_type->alignment;
    type->size = element_type->size * num_elements;

    INFIX_DEBUG_PRINTF("Created arena array type. Size: %llu, Alignment: %llu",
                       (unsigned long long)type->size,
                       (unsigned long long)type->alignment);

    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Creates a new `infix_type` for an enum from an arena.
 * @details An enum is treated as a semantic alias for its underlying integer type for
 * ABI purposes. This function creates a type that has the same size and alignment
 * as its underlying type.
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, will point to the newly created `infix_type`.
 * @param underlying_type The integer `infix_type` that this enum is based on (e.g., `SINT32`).
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
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

    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_ENUM;
    type->size = underlying_type->size;
    type->alignment = underlying_type->alignment;
    type->meta.enum_info.underlying_type = underlying_type;

    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Creates a new `infix_type` for a named reference from an arena.
 * @details This is used by the parser when it encounters a reference to a named
 *          type like `struct<MyStruct>` that is NOT followed by a definition body.
 * @param arena The arena from which to allocate.
 * @param[out] out_type On success, will point to the newly created `infix_type`.
 * @param name The name of the type being referenced.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
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

/**
 * @brief Retrieves the fundamental category of an `infix_type`.
 * @param type A pointer to the `infix_type` to inspect. Can be `nullptr`.
 * @return The `infix_type_category` enum for the type. Returns `(infix_type_category)-1`
 *         if the provided `type` pointer is `nullptr`.
 */
c23_nodiscard infix_type_category infix_type_get_category(const infix_type * type) {
    // A simple null check provides safety. If the type is null, we return an
    // invalid category enum value.
    return type ? type->category : (infix_type_category)-1;
}

/**
 * @brief Retrieves the size of an `infix_type` in bytes.
 * @param type A pointer to the `infix_type` to inspect. Can be `nullptr`.
 * @return The size of the type, equivalent to `sizeof(T)`. Returns `0` if the
 *         provided `type` pointer is `nullptr`.
 */
c23_nodiscard size_t infix_type_get_size(const infix_type * type) {
    return type ? type->size : 0;
}

/**
 * @brief Retrieves the alignment requirement of an `infix_type` in bytes.
 * @param type A pointer to the `infix_type` to inspect. Can be `nullptr`.
 * @return The alignment of the type, equivalent to `_Alignof(T)`. Returns `0` if the
 *         provided `type` pointer is `nullptr`.
 */
c23_nodiscard size_t infix_type_get_alignment(const infix_type * type) {
    return type ? type->alignment : 0;
}

/**
 * @brief Retrieves the number of members in an aggregate type (struct or union).
 * @param type A pointer to the `infix_type` to inspect. Can be `nullptr`.
 * @return The number of members if the type is a struct or union. Returns `0` for
 *         all other type categories or if the `type` pointer is `nullptr`.
 */
c23_nodiscard size_t infix_type_get_member_count(const infix_type * type) {
    // Before accessing aggregate-specific metadata, we must validate both the
    // pointer and the type's category.
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION))
        return 0;
    return type->meta.aggregate_info.num_members;
}

/**
 * @brief Retrieves a specific member from an aggregate type by its index.
 * @param type A pointer to the `infix_type` to inspect. Can be `nullptr`.
 * @param index The zero-based index of the member to retrieve.
 * @return A constant pointer to the `infix_struct_member` on success. Returns `nullptr`
 *         if `type` is not a struct or union, if `type` is `nullptr`, or if the
 *         `index` is out of bounds.
 */
c23_nodiscard const infix_struct_member * infix_type_get_member(const infix_type * type, size_t index) {
    // Perform thorough validation before returning a pointer to internal data.
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION))
        return nullptr;
    if (index >= type->meta.aggregate_info.num_members)
        return nullptr;
    return &type->meta.aggregate_info.members[index];
}

/**
 * @brief Retrieves the name of a function argument by its index.
 * @param func_type A pointer to an `infix_type` of category `INFIX_TYPE_REVERSE_TRAMPOLINE`.
 * @param index The zero-based index of the argument to retrieve.
 * @return A constant string for the argument's name, or `nullptr` if the argument
 *         is anonymous, the index is out of bounds, or `func_type` is not a function type.
 */
c23_nodiscard const char * infix_type_get_arg_name(const infix_type * func_type, size_t index) {
    // Validate that we are operating on a function type and the index is valid.
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE)
        return nullptr;
    if (index >= func_type->meta.func_ptr_info.num_fixed_args)
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].name;
}

/**
 * @brief Retrieves the type of a function argument by its index.
 * @param func_type A pointer to an `infix_type` of category `INFIX_TYPE_REVERSE_TRAMPOLINE`.
 * @param index The zero-based index of the argument to retrieve.
 * @return A constant pointer to the argument's `infix_type`. Returns `nullptr` if the
 *         index is out of bounds or `func_type` is not a function type.
 */
c23_nodiscard const infix_type * infix_type_get_arg_type(const infix_type * func_type, size_t index) {
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE)
        return nullptr;
    if (index >= func_type->meta.func_ptr_info.num_fixed_args)
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].type;
}
