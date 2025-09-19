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
 * create and destroy `ffi_type` objects. It defines static, singleton instances for all
 * primitive C types to avoid unnecessary allocations for common cases. It also provides
 * the logic for dynamically creating and destroying complex aggregate types like structs,
 * unions, and arrays.
 *
 * The functions here are responsible for correctly calculating the size and alignment
 * of these types according to standard C layout rules, which is fundamental to ensuring
 * ABI compliance. A key design principle is security: the functions that create dynamic types
 * (`ffi_type_create_struct`, `_union`, `_array`) are hardened against integer
 * overflows from potentially malicious input. They also follow a strict memory
 * ownership model to prevent leaks in error-handling paths.
 */

#include <infix.h>
#include <limits.h>  // For SIZE_MAX
#include <stdio.h>
#include <stdlib.h>
#include <utility.h>

/**
 * @def FFI_TYPE_INIT
 * @brief (Internal) A helper macro to initialize a static `ffi_type` for a primitive.
 * @details This macro simplifies the static initialization of the singleton primitive
 *          type instances. It sets the category, size, alignment, and primitive ID
 *          at compile time using the results of `sizeof` and `_Alignof`, ensuring
 *          that the type descriptors are correct for the compilation target.
 * @internal
 */
#define FFI_TYPE_INIT(id, T) {FFI_TYPE_PRIMITIVE, sizeof(T), _Alignof(T), false, .meta.primitive_id = id}

// Statically allocated, singleton instances for all fundamental types.
// This is a performance optimization that avoids dynamic allocation and deallocation
// for common types. It allows them to be used without needing to be manually freed,
// simplifying the user's code.
static ffi_type _ffi_type_void = {FFI_TYPE_VOID, 0, 0, false, {0}};
static ffi_type _ffi_type_pointer = {FFI_TYPE_POINTER, sizeof(void *), _Alignof(void *), false, {0}};
static ffi_type _ffi_type_bool = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_BOOL, bool);
static ffi_type _ffi_type_uint8 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_UINT8, uint8_t);
static ffi_type _ffi_type_sint8 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_SINT8, int8_t);
static ffi_type _ffi_type_uint16 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_UINT16, uint16_t);
static ffi_type _ffi_type_sint16 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_SINT16, int16_t);
static ffi_type _ffi_type_uint32 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_UINT32, uint32_t);
static ffi_type _ffi_type_sint32 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_SINT32, int32_t);
static ffi_type _ffi_type_uint64 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_UINT64, uint64_t);
static ffi_type _ffi_type_sint64 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_SINT64, int64_t);
#if !defined(FFI_COMPILER_MSVC)
// 128-bit integers are a non-standard GCC/Clang extension, so they are conditionally compiled.
static ffi_type _ffi_type_uint128 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_UINT128, __uint128_t);
static ffi_type _ffi_type_sint128 = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_SINT128, __int128_t);
#endif
static ffi_type _ffi_type_float = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_FLOAT, float);
static ffi_type _ffi_type_double = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_DOUBLE, double);
// Only define a separate long double type if it's distinct from double.
#if defined(FFI_COMPILER_MSVC) || (defined(FFI_OS_WINDOWS) && defined(FFI_COMPILER_CLANG)) || defined(FFI_OS_MACOS)
// On these platforms, long double is an alias for double, so no separate type is needed.
#else
static ffi_type _ffi_type_long_double = FFI_TYPE_INIT(FFI_PRIMITIVE_TYPE_LONG_DOUBLE, long double);
#endif

/**
 * @brief Creates an `ffi_type` descriptor for a primitive C type.
 * @details This function acts as a factory, returning a pointer to one of the
 *          statically allocated, singleton `ffi_type` instances for primitives.
 *          It correctly handles platform-specific type definitions, such as `long double`
 *          being equivalent to `double` on MSVC and Clang for Windows, ensuring the
 *          correct type descriptor is used for the target ABI.
 *
 * @param id The ID of the primitive type (e.g., `FFI_PRIMITIVE_TYPE_SINT32`).
 * @return A pointer to the corresponding static `ffi_type` structure.
 *         Returns `nullptr` if the ID is invalid or for a type not supported by the
 *         current compiler (e.g., `__int128_t` on MSVC).
 * @warning Do not free the returned pointer. It points to a static global variable.
 */
c23_nodiscard ffi_type * ffi_type_create_primitive(ffi_primitive_type_id id) {
    switch (id) {
    case FFI_PRIMITIVE_TYPE_BOOL:
        return &_ffi_type_bool;
    case FFI_PRIMITIVE_TYPE_UINT8:
        return &_ffi_type_uint8;
    case FFI_PRIMITIVE_TYPE_SINT8:
        return &_ffi_type_sint8;
    case FFI_PRIMITIVE_TYPE_UINT16:
        return &_ffi_type_uint16;
    case FFI_PRIMITIVE_TYPE_SINT16:
        return &_ffi_type_sint16;
    case FFI_PRIMITIVE_TYPE_UINT32:
        return &_ffi_type_uint32;
    case FFI_PRIMITIVE_TYPE_SINT32:
        return &_ffi_type_sint32;
    case FFI_PRIMITIVE_TYPE_UINT64:
        return &_ffi_type_uint64;
    case FFI_PRIMITIVE_TYPE_SINT64:
        return &_ffi_type_sint64;
#if !defined(FFI_COMPILER_MSVC)
    case FFI_PRIMITIVE_TYPE_UINT128:
        return &_ffi_type_uint128;
    case FFI_PRIMITIVE_TYPE_SINT128:
        return &_ffi_type_sint128;
#endif
    case FFI_PRIMITIVE_TYPE_LONG_DOUBLE:
        // On MSVC, Clang for Windows, and all Apple platforms, long double is just an alias for double.
        // Return the canonical double type to ensure correct ABI handling.
#if defined(FFI_COMPILER_MSVC) || (defined(FFI_OS_WINDOWS) && defined(FFI_COMPILER_CLANG)) || defined(FFI_OS_MACOS)
        return &_ffi_type_double;
#else
        return &_ffi_type_long_double;
#endif
    case FFI_PRIMITIVE_TYPE_FLOAT:
        return &_ffi_type_float;
    case FFI_PRIMITIVE_TYPE_DOUBLE:
        return &_ffi_type_double;
    default:
        // An unknown or unsupported primitive ID was provided.
        return nullptr;
    }
}

/**
 * @brief Creates an `ffi_type` descriptor for a generic pointer.
 * @details Returns a pointer to the static singleton instance describing `void*`.
 *          This should be used for all pointer types in a function signature, as the
 *          ABI treats all data pointers identically.
 *
 * @return A pointer to the statically-allocated `ffi_type` for pointers.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard ffi_type * ffi_type_create_pointer() {
    return &_ffi_type_pointer;
}

/**
 * @brief Creates an `ffi_type` descriptor for `void`.
 * @details Returns a pointer to the static singleton instance describing the `void` type,
 *          used exclusively for the return type of a function that returns nothing.
 *
 * @return A pointer to the statically-allocated `ffi_type` for void.
 * @warning Do not free the returned pointer.
 */
c23_nodiscard ffi_type * ffi_type_create_void() {
    return &_ffi_type_void;
}

/**
 * @internal
 * @brief Creates an `ffi_type` for a struct, allocating from an arena.
 * @details This function calculates the size and alignment of the struct based on its
 *          members, adhering to standard C layout rules. It iterates through the members
 *          to find the maximum alignment requirement and calculates the total size, including
 *          any trailing padding needed to satisfy the struct's overall alignment. It is
 *          hardened against integer overflows that could arise from malformed member layouts.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, a pointer to an `ffi_type*` that will receive the new type.
 * @param members An array of `ffi_struct_member` describing the struct's layout.
 * @param num_members The number of members in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard ffi_status ffi_type_create_struct_arena(arena_t * arena,
                                                      ffi_type ** out_type,
                                                      ffi_struct_member * members,
                                                      size_t num_members) {
    if (out_type == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Validate that all member types are non-null.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    ffi_type * type = arena_alloc(arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = true;
    type->category = FFI_TYPE_STRUCT;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    size_t preliminary_size = 0;
    size_t max_alignment = 1;

    // First pass: determine the natural size and max alignment.
    for (size_t i = 0; i < num_members; ++i) {
        ffi_struct_member * member = &members[i];

        // Security: Check for integer overflow when calculating member end.
        if (member->offset > SIZE_MAX - member->type->size) {
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }

        size_t member_end = member->offset + member->type->size;
        if (member_end > preliminary_size)
            preliminary_size = member_end;
        if (member->type->alignment > max_alignment)
            max_alignment = member->type->alignment;
    }

    type->alignment = max_alignment;

    // Check for overflow when calculating padding.
    if (max_alignment > 0 && preliminary_size > SIZE_MAX - (max_alignment - 1)) {
        *out_type = nullptr;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // Final size is the preliminary size rounded up to the nearest multiple of the max alignment.
    if (max_alignment > 0)
        type->size = (preliminary_size + max_alignment - 1) & ~(max_alignment - 1);
    else
        type->size = preliminary_size;

    FFI_DEBUG_PRINTF("Created struct type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);
    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a struct.
 * @details This function calculates the size and alignment of the struct based on its
 *          members, adhering to standard C layout rules. It iterates through the members
 *          to find the maximum alignment requirement and calculates the total size, including
 *          any trailing padding needed to satisfy the struct's overall alignment. It is
 *          hardened against integer overflows that could arise from malformed member layouts.
 *
 *          **Memory Ownership:** The library takes ownership of the `members` pointer
 *          **only on success**. If this function fails for any reason, the caller
 *          is still responsible for freeing the `members` array.
 *
 * @param[out] out_type On success, a pointer to an `ffi_type*` that will receive the new type.
 * @param members An array of `ffi_struct_member` describing the struct's layout.
 * @param num_members The number of members in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned type is allocated on the heap and **must** be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_struct(ffi_type ** out_type, ffi_struct_member * members, size_t num_members) {
    // This public function now allocates from the heap as before, but a real
    // application would use an arena-based version internally.
    if (out_type == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Validate that all member types are non-null.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    ffi_type * type = infix_malloc(sizeof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = false;  // Malloc'd, not from arena.
    type->category = FFI_TYPE_STRUCT;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    size_t preliminary_size = 0;
    size_t max_alignment = 1;

    // First pass: determine the natural size and max alignment.
    for (size_t i = 0; i < num_members; ++i) {
        ffi_struct_member * member = &members[i];

        // Security: Check for integer overflow when calculating member end.
        if (member->offset > SIZE_MAX - member->type->size) {
            infix_free(type);  // Caller still owns `members` on failure.
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }

        size_t member_end = member->offset + member->type->size;
        if (member_end > preliminary_size)
            preliminary_size = member_end;
        if (member->type->alignment > max_alignment)
            max_alignment = member->type->alignment;
    }

    type->alignment = max_alignment;

    // Security: Check for overflow when calculating padding.
    if (max_alignment > 0 && preliminary_size > SIZE_MAX - (max_alignment - 1)) {
        infix_free(type);
        *out_type = nullptr;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // Final size is the preliminary size rounded up to the nearest multiple of the max alignment.
    if (max_alignment > 0)
        type->size = (preliminary_size + max_alignment - 1) & ~(max_alignment - 1);
    else
        type->size = preliminary_size;

    FFI_DEBUG_PRINTF("Created struct type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);
    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a packed struct.
 * @details This function is the designated way to describe C structs that use
 *          non-standard memory layouts, typically resulting from compiler directives
 *          like `__attribute__((packed))` or `#pragma pack(1)`.
 *
 *          The key difference between this function and `ffi_type_create_struct` is
 *          how the final size and alignment are determined. For standard structs, the
 *          library can calculate the layout based on C's padding and alignment rules.
 *          However, for packed structs, these rules are intentionally broken in a
 *          compiler-specific way. Therefore, this function delegates the responsibility
 *          of providing the final, correct layout to the caller.
 *
 *          The caller **must** provide the exact `total_size` and `alignment` as determined
 *          by their compiler (using the `sizeof` and `_Alignof` operators on the C struct
 *          type). The library then uses this trusted information, along with the member
 *          offsets, to correctly inform the ABI classification logic. This approach
 *          ensures that even though the layout is non-standard, the FFI can still make
 *          the correct decisions about how to pass the struct (e.g., in registers, on the
 *          stack, or by reference).
 *
 * @param[out] out_type On success, this will point to a newly allocated `ffi_type`
 *                      descriptor for the packed struct. The caller is responsible for
 *                      freeing this with `ffi_type_destroy`.
 * @param total_size    The exact size of the packed struct in bytes, as returned by
 *                      `sizeof(your_packed_struct)`.
 * @param alignment     The alignment requirement of the packed struct in bytes, as
 *                      returned by `_Alignof(your_packed_struct)`. This is often 1.
 * @param members       An array of `ffi_struct_member` describing each member of the
 *                      struct. The offsets within this array must be the correct,
 *                      packed offsets from `offsetof`. On success, the library takes
 *                      ownership of this pointer.
 * @param num_members   The number of elements in the `members` array.
 *
 * @return `FFI_SUCCESS` on successful creation.
 * @return `FFI_ERROR_INVALID_ARGUMENT` if `out_type` is nullptr, `alignment` is zero, or
 *         `members` is nullptr when `num_members` > 0.
 * @return `FFI_ERROR_ALLOCATION_FAILED` if memory for the `ffi_type` struct could not
 *         be allocated.
 *
 * @note **Memory Ownership:** On success, the library takes ownership of the `members`
 *       array. If the function fails, the caller retains ownership and is responsible
 *       for freeing it. The `ffi_type` written to `out_type` on success must be
 *       freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_packed_struct(
    ffi_type ** out_type, size_t total_size, size_t alignment, ffi_struct_member * members, size_t num_members) {
    if (out_type == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Validate that all member types are non-null.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    if (num_members > 0 && members == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;
    // A packed struct can have a size of 0, but not a zero alignment.
    if (alignment == 0)
        return FFI_ERROR_INVALID_ARGUMENT;

    //
    ffi_type * type = infix_calloc(1, sizeof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = false;

    // Instead of calculating layout, we trust the user-provided values.
    // This is the core of supporting packed structs.
    type->size = total_size;
    type->alignment = alignment;
    type->category = FFI_TYPE_STRUCT;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    FFI_DEBUG_PRINTF("Created packed struct type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);

    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @internal
 * @brief Creates an `ffi_type` for a packed struct, allocating from an arena.
 * @details This is an internal, arena-aware version of `ffi_type_create_packed_struct`.
 *          It is used exclusively by the signature parser, which requires the ability
 *          to allocate numerous temporary `ffi_type` objects that will be freed all at
 *          once when the arena is destroyed. The parser provides the layout metadata
 *          (size, alignment, offsets) which it extracts from the signature string.
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param total_size The exact size of the packed struct.
 * @param alignment The alignment requirement of the packed struct.
 * @param members An array of `ffi_struct_member` describing each member. The offsets
 *                within this array must be the correct, packed offsets.
 * @param num_members The number of elements in the `members` array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note All allocated memory is owned by the arena. The returned `ffi_type` should
 *       not be passed to `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_packed_struct_arena(arena_t * arena,
                                                             ffi_type ** out_type,
                                                             size_t total_size,
                                                             size_t alignment,
                                                             ffi_struct_member * members,
                                                             size_t num_members) {
    if (out_type == nullptr || (num_members > 0 && members == nullptr) || alignment == 0)
        return FFI_ERROR_INVALID_ARGUMENT;

    ffi_type * type = arena_alloc(arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    type->is_arena_allocated = true;
    type->size = total_size;
    type->alignment = alignment;
    type->category = FFI_TYPE_STRUCT;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @brief A factory function to create an `ffi_struct_member`.
 * @details This is a convenient helper function for creating an `ffi_struct_member`,
 *          which is needed to define the layout of structs and unions.
 *
 * @param name The member's name (for debugging purposes; can be `nullptr`).
 * @param type A pointer to the member's `ffi_type`.
 * @param offset The byte offset of the member from the start of the aggregate. This
 *               value should be obtained using the standard `offsetof` macro.
 * @return An initialized `ffi_struct_member`.
 */
ffi_struct_member ffi_struct_member_create(const char * name, ffi_type * type, size_t offset) {
    return (ffi_struct_member){name, type, offset};
}

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a union.
 * @details Calculates the size and alignment for a union. The alignment is the largest
 *          alignment of any member. The size is the size of the largest single member,
 *          padded to be a multiple of the union's final alignment.
 *
 *          **Memory Ownership:** The library takes ownership of the `members` pointer
 *          **only on success**. If this function fails, the caller must free `members`.
 *
 * @param[out] out_type On success, a pointer to an `ffi_type*` that will receive the new type.
 * @param members An array of `ffi_struct_member` describing the union's members.
 * @param num_members The number of members in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned type must be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_union(ffi_type ** out_type, ffi_struct_member * members, size_t num_members) {
    if (out_type == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    ffi_type * type = infix_malloc(sizeof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = false;
    type->category = FFI_TYPE_UNION;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    size_t max_size = 0;
    size_t max_alignment = 1;
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type->size > max_size)
            max_size = members[i].type->size;
        if (members[i].type->alignment > max_alignment)
            max_alignment = members[i].type->alignment;
    }
    type->alignment = max_alignment;

    if (max_alignment > 0 && max_size > SIZE_MAX - (max_alignment - 1)) {
        infix_free(type);
        *out_type = nullptr;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // A union's size is the size of its largest member, rounded up to a multiple of its alignment.
    type->size = (max_size + max_alignment - 1) & ~(max_alignment - 1);

    FFI_DEBUG_PRINTF("Created union type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);
    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @internal
 * @brief Creates an `ffi_type` for a union, allocating from an arena.
 * @details This function calculates the size and alignment for a union according to
 *          standard C layout rules. The alignment is the largest alignment of any
 *          member. The size is the size of the largest single member, padded to be
 *          a multiple of the union's final alignment. It is hardened against integer
 *          overflows.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param members An array of `ffi_struct_member` describing the union's members.
 * @param num_members The number of members in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard ffi_status ffi_type_create_union_arena(arena_t * arena,
                                                     ffi_type ** out_type,
                                                     ffi_struct_member * members,
                                                     size_t num_members) {
    if (out_type == NULL) {
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // Validate that all member types are non-null before proceeding.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == NULL) {
            *out_type = NULL;
            return FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    // Allocate the ffi_type struct itself from the arena.
    ffi_type * type = arena_alloc(arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (type == NULL) {
        *out_type = NULL;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    // Mark this type as arena-allocated so ffi_type_destroy will ignore it.
    type->is_arena_allocated = true;
    type->category = FFI_TYPE_UNION;
    type->meta.aggregate_info.members = members;
    type->meta.aggregate_info.num_members = num_members;

    size_t max_size = 0;
    size_t max_alignment = 1;

    // A union's size is determined by its largest member, and its alignment
    // by the strictest alignment of any member.
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type->size > max_size) {
            max_size = members[i].type->size;
        }
        if (members[i].type->alignment > max_alignment) {
            max_alignment = members[i].type->alignment;
        }
    }
    type->alignment = max_alignment;

    // Security: Check for integer overflow before calculating the final padded size.
    if (max_alignment > 0 && max_size > SIZE_MAX - (max_alignment - 1)) {
        *out_type = NULL;
        return FFI_ERROR_INVALID_ARGUMENT;  // Overflow would occur
    }

    // The final size is the size of the largest member, rounded up to a
    // multiple of the union's overall alignment.
    type->size = (max_size + max_alignment - 1) & ~(max_alignment - 1);

    FFI_DEBUG_PRINTF("Created arena union type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);

    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @brief Creates a new, dynamically-allocated `ffi_type` for a fixed-size array.
 * @details Calculates the size and alignment for a fixed-size array. The alignment
 *          is the same as the element type's alignment. The size is simply the
 *          element size multiplied by the number of elements, with a check to prevent
 *          integer overflow during the calculation.
 *
 *          **Memory Ownership:** The library takes ownership of the `element_type`
 *          pointer **only on success**. If this function fails, the caller is responsible
 *          for freeing it.
 *
 * @param[out] out_type On success, a pointer to an `ffi_type*` that will receive the new type.
 * @param element_type An `ffi_type` describing the type of elements in the array.
 * @param num_elements The number of elements in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 * @note The returned type must be freed with `ffi_type_destroy`.
 */
c23_nodiscard ffi_status ffi_type_create_array(ffi_type ** out_type, ffi_type * element_type, size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Security: Check for integer overflow before calculating the total array size.
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        //~ fprintf(stderr, "Error: array size calculation (element_size * num_elements) causes integer overflow.\n");
        // The caller still owns element_type in case of failure here, so we don't free it.
        *out_type = nullptr;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    ffi_type * type = infix_malloc(sizeof(ffi_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = false;
    type->category = FFI_TYPE_ARRAY;
    type->meta.array_info.element_type = element_type;
    type->meta.array_info.num_elements = num_elements;
    type->alignment = element_type->alignment;
    type->size = element_type->size * num_elements;
    FFI_DEBUG_PRINTF("Created array type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);
    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @internal
 * @brief Creates an `ffi_type` for a fixed-size array, allocating from an arena.
 * @details This function calculates the size and alignment for a fixed-size array.
 *          The alignment is the same as the element type's alignment. The size is
 *          the element size multiplied by the number of elements, with a check to
 *          prevent integer overflow during the calculation.
 *
 * @param arena The memory arena from which to allocate the new `ffi_type`.
 * @param[out] out_type On success, will point to the newly created `ffi_type`.
 * @param element_type An `ffi_type` describing the type of elements in the array.
 * @param num_elements The number of elements in the array.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard ffi_status ffi_type_create_array_arena(arena_t * arena,
                                                     ffi_type ** out_type,
                                                     ffi_type * element_type,
                                                     size_t num_elements) {
    if (out_type == NULL || element_type == NULL) {
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // Security: Check for integer overflow before calculating the total array size.
    // This is critical when dealing with inputs from a parser or other untrusted source.
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = NULL;
        return FFI_ERROR_INVALID_ARGUMENT;  // Calculation would overflow.
    }

    // Allocate the ffi_type struct itself from the arena.
    ffi_type * type = arena_alloc(arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (type == NULL) {
        *out_type = NULL;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    // Mark this type as arena-allocated so ffi_type_destroy will ignore it.
    type->is_arena_allocated = true;
    type->category = FFI_TYPE_ARRAY;
    type->meta.array_info.element_type = element_type;
    type->meta.array_info.num_elements = num_elements;

    // An array's alignment is the same as its element's alignment.
    type->alignment = element_type->alignment;
    type->size = element_type->size * num_elements;

    FFI_DEBUG_PRINTF("Created arena array type. Size: %llu, Alignment: %llu",
                     (unsigned long long)type->size,
                     (unsigned long long)type->alignment);

    *out_type = type;
    return FFI_SUCCESS;
}

/**
 * @brief Frees a dynamically-allocated `ffi_type` and any nested dynamic types.
 * @details This function is the designated destructor for `ffi_type` objects
 *          created with `ffi_type_create_struct`, `_union`, or `_array`. It correctly
 *          handles recursive destruction:
 *          - For structs/unions, it frees the `members` array after recursively calling
 *            `ffi_type_destroy` on each member's type.
 *          - For arrays, it recursively calls `ffi_type_destroy` on the `element_type`.
 *
 *          It is safe to call this function with a pointer to a static type (primitives,
 *          pointer, or void), as it will do nothing in those cases, preventing
 *          double-free errors and simplifying user code. It also correctly handles
 *          types allocated from an arena by doing nothing.
 *
 * @param type The `ffi_type` to destroy. Can be `nullptr`, in which case it is a no-op.
 */
void ffi_type_destroy(ffi_type * type) {
    if (type == nullptr || type->is_arena_allocated)
        return;
    switch (type->category) {
    case FFI_TYPE_STRUCT:
    case FFI_TYPE_UNION:
        // For aggregates, we recursively destroy the types held by members
        // before freeing the members array itself.
        if (type->meta.aggregate_info.members) {
            for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i)
                ffi_type_destroy(type->meta.aggregate_info.members[i].type);
            infix_free(type->meta.aggregate_info.members);
        }
        infix_free(type);  // Free the container struct itself.
        break;

    case FFI_TYPE_ARRAY:
        // Recursively destroy the element type before freeing the array type itself.
        ffi_type_destroy(type->meta.array_info.element_type);
        infix_free(type);
        break;

    case FFI_TYPE_REVERSE_TRAMPOLINE:
        if (type->meta.func_ptr_info.arg_types) {
            for (size_t i = 0; i < type->meta.func_ptr_info.num_args; ++i)
                ffi_type_destroy(type->meta.func_ptr_info.arg_types[i]);
            // The arg_types array itself is arena-allocated, so we don't free it here.
        }
        ffi_type_destroy(type->meta.func_ptr_info.return_type);
        infix_free(type);
        break;

    default:
        // Do nothing for static types (primitives, pointer, void) as they
        // were not dynamically allocated. This makes the function safe to
        // call on any ffi_type pointer.
        break;
    }
}
