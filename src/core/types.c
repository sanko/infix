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
 */

#include "common/infix_internals.h"
#include "common/utility.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INFIX_TYPE_INIT(id, T)         \
    {.category = INFIX_TYPE_PRIMITIVE, \
     .size = sizeof(T),                \
     .alignment = _Alignof(T),         \
     .is_arena_allocated = false,      \
     .meta.primitive_id = id}

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
static infix_type _infix_type_uint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_UINT128, __uint128_t);
static infix_type _infix_type_sint128 = INFIX_TYPE_INIT(INFIX_PRIMITIVE_SINT128, __int128_t);
#endif
static infix_type _infix_type_float = INFIX_TYPE_INIT(INFIX_PRIMITIVE_FLOAT, float);
static infix_type _infix_type_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_DOUBLE, double);

#if defined(INFIX_COMPILER_MSVC) || (defined(INFIX_OS_WINDOWS) && defined(INFIX_COMPILER_CLANG)) || \
    defined(INFIX_OS_MACOS)
#else
static infix_type _infix_type_long_double = INFIX_TYPE_INIT(INFIX_PRIMITIVE_LONG_DOUBLE, long double);
#endif

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

c23_nodiscard infix_type * infix_type_create_pointer(void) {
    return &_infix_type_pointer;
}
c23_nodiscard infix_type * infix_type_create_void(void) {
    return &_infix_type_void;
}
infix_struct_member infix_type_create_member(const char * name, infix_type * type, size_t offset) {
    return (infix_struct_member){name, type, offset};
}

static infix_status _create_aggregate_setup(infix_arena_t * arena,
                                            infix_type ** out_type,
                                            infix_struct_member ** out_arena_members,
                                            infix_struct_member * members,
                                            size_t num_members) {
    if (out_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    for (size_t i = 0; i < num_members; ++i) {
        if (members[i].type == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    infix_struct_member * arena_members = nullptr;
    if (num_members > 0) {
        arena_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
        if (arena_members == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_ALLOCATION_FAILED;
        }
        infix_memcpy(arena_members, members, sizeof(infix_struct_member) * num_members);
    }
    *out_type = type;
    *out_arena_members = arena_members;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_type_create_pointer_to(infix_arena_t * arena,
                                                        infix_type ** out_type,
                                                        infix_type * pointee_type) {
    if (!out_type || !pointee_type)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    *type = *infix_type_create_pointer();
    type->is_arena_allocated = true;
    type->meta.pointer_info.pointee_type = pointee_type;
    *out_type = type;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_type_create_array(infix_arena_t * arena,
                                                   infix_type ** out_type,
                                                   infix_type * element_type,
                                                   size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = nullptr;
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INTEGER_OVERFLOW, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
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

c23_nodiscard infix_status infix_type_create_enum(infix_arena_t * arena,
                                                  infix_type ** out_type,
                                                  infix_type * underlying_type) {
    if (out_type == nullptr || underlying_type == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    if (underlying_type->category != INFIX_TYPE_PRIMITIVE ||
        underlying_type->meta.primitive_id > INFIX_PRIMITIVE_SINT128) {
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
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

c23_nodiscard infix_status infix_type_create_complex(infix_arena_t * arena,
                                                     infix_type ** out_type,
                                                     infix_type * base_type) {
    if (out_type == nullptr || base_type == nullptr || (!is_float(base_type) && !is_double(base_type)))
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
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

c23_nodiscard infix_status infix_type_create_vector(infix_arena_t * arena,
                                                    infix_type ** out_type,
                                                    infix_type * element_type,
                                                    size_t num_elements) {
    if (out_type == nullptr || element_type == nullptr || element_type->category != INFIX_TYPE_PRIMITIVE)
        return INFIX_ERROR_INVALID_ARGUMENT;
    if (element_type->size > 0 && num_elements > SIZE_MAX / element_type->size) {
        *out_type = nullptr;
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INTEGER_OVERFLOW, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_VECTOR;
    type->meta.vector_info.element_type = element_type;
    type->meta.vector_info.num_elements = num_elements;
    type->size = element_type->size * num_elements;
    type->alignment = type->size > 8 ? 16 : type->size;
    *out_type = type;
    return INFIX_SUCCESS;
}

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
    for (size_t i = 0; i < num_members; ++i) {
        arena_members[i].offset = 0;
        if (arena_members[i].type->size > max_size)
            max_size = arena_members[i].type->size;
        if (arena_members[i].type->alignment > max_alignment)
            max_alignment = arena_members[i].type->alignment;
    }
    type->alignment = max_alignment;
    type->size = _infix_align_up(max_size, max_alignment);
    if (type->size < max_size) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    *out_type = type;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_type_create_struct(infix_arena_t * arena,
                                                    infix_type ** out_type,
                                                    infix_struct_member * members,
                                                    size_t num_members) {
    _infix_clear_error();
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
    size_t max_alignment = 1;
    for (size_t i = 0; i < num_members; ++i) {
        infix_struct_member * member = &arena_members[i];
        size_t member_align = member->type->alignment;
        if (member_align == 0 && member->type->category != INFIX_TYPE_NAMED_REFERENCE) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        if (member_align == 0)
            member_align = 1;
        size_t aligned_offset = _infix_align_up(current_offset, member_align);
        if (aligned_offset < current_offset) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset = aligned_offset;
        member->offset = current_offset;
        if (current_offset > SIZE_MAX - member->type->size) {
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        current_offset += member->type->size;
        if (member_align > max_alignment)
            max_alignment = member_align;
    }
    type->alignment = max_alignment;
    type->size = _infix_align_up(current_offset, max_alignment);
    if (type->size < current_offset) {
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    *out_type = type;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_type_create_packed_struct(infix_arena_t * arena,
                                                           infix_type ** out_type,
                                                           size_t total_size,
                                                           size_t alignment,
                                                           infix_struct_member * members,
                                                           size_t num_members) {
    if (out_type == nullptr || (num_members > 0 && members == nullptr) || alignment == 0)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    infix_struct_member * arena_members = nullptr;
    if (num_members > 0) {
        arena_members =
            infix_arena_alloc(arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
        if (arena_members == nullptr) {
            *out_type = nullptr;
            return INFIX_ERROR_ALLOCATION_FAILED;
        }
        infix_memcpy(arena_members, members, sizeof(infix_struct_member) * num_members);
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

c23_nodiscard infix_status infix_type_create_named_reference(infix_arena_t * arena,
                                                             infix_type ** out_type,
                                                             const char * name,
                                                             infix_aggregate_category_t agg_cat) {
    if (out_type == nullptr || name == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_type * type = infix_arena_calloc(arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (type == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    size_t name_len = strlen(name) + 1;
    char * arena_name = infix_arena_alloc(arena, name_len, 1);
    if (arena_name == nullptr) {
        *out_type = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    infix_memcpy(arena_name, name, name_len);
    type->is_arena_allocated = true;
    type->category = INFIX_TYPE_NAMED_REFERENCE;
    type->size = 0;
    type->alignment = 1;
    type->meta.named_reference.name = arena_name;
    type->meta.named_reference.aggregate_category = agg_cat;
    *out_type = type;
    return INFIX_SUCCESS;
}

typedef struct recalc_visited_node_t {
    infix_type * type;
    struct recalc_visited_node_t * next;
} recalc_visited_node_t;

static void _infix_type_recalculate_layout_recursive(infix_type * type, recalc_visited_node_t ** visited_head) {
    if (!type || !type->is_arena_allocated)
        return;
    for (recalc_visited_node_t * v = *visited_head; v != NULL; v = v->next) {
        if (v->type == type)
            return;
    }
    recalc_visited_node_t * visited_node = infix_malloc(sizeof(recalc_visited_node_t));
    if (!visited_node)
        return;
    visited_node->type = type;
    visited_node->next = *visited_head;
    *visited_head = visited_node;

    switch (type->category) {
    case INFIX_TYPE_POINTER:
        _infix_type_recalculate_layout_recursive(type->meta.pointer_info.pointee_type, visited_head);
        break;
    case INFIX_TYPE_ARRAY:
        _infix_type_recalculate_layout_recursive(type->meta.array_info.element_type, visited_head);
        break;
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            _infix_type_recalculate_layout_recursive(type->meta.aggregate_info.members[i].type, visited_head);
        }
        break;
    default:
        break;
    }

    if (type->category == INFIX_TYPE_STRUCT) {
        size_t current_offset = 0;
        size_t max_alignment = 1;
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            infix_struct_member * member = &type->meta.aggregate_info.members[i];
            size_t member_align = member->type->alignment;
            if (member_align > max_alignment)
                max_alignment = member_align;
            current_offset = _infix_align_up(current_offset, member_align);
            member->offset = current_offset;
            current_offset += member->type->size;
        }
        type->alignment = max_alignment;
        type->size = _infix_align_up(current_offset, max_alignment);
    }
    else if (type->category == INFIX_TYPE_UNION) {
        size_t max_size = 0;
        size_t max_alignment = 1;
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            infix_type * member_type = type->meta.aggregate_info.members[i].type;
            if (member_type->size > max_size)
                max_size = member_type->size;
            if (member_type->alignment > max_alignment)
                max_alignment = member_type->alignment;
        }
        type->alignment = max_alignment;
        type->size = _infix_align_up(max_size, max_alignment);
    }
    else if (type->category == INFIX_TYPE_ARRAY) {
        type->alignment = type->meta.array_info.element_type->alignment;
        type->size = type->meta.array_info.element_type->size * type->meta.array_info.num_elements;
    }
    *visited_head = visited_node->next;
    infix_free(visited_node);
}

void _infix_type_recalculate_layout(infix_type * type) {
    recalc_visited_node_t * visited_head = NULL;
    _infix_type_recalculate_layout_recursive(type, &visited_head);
}

typedef struct memo_node_t {
    const infix_type * src;
    infix_type * dest;
    struct memo_node_t * next;
} memo_node_t;

static infix_type * _copy_type_graph_to_arena_recursive(infix_arena_t * dest_arena,
                                                        const infix_type * src_type,
                                                        memo_node_t ** memo_head) {
    if (src_type == nullptr)
        return nullptr;
    if (!src_type->is_arena_allocated)
        return (infix_type *)src_type;
    for (memo_node_t * node = *memo_head; node != NULL; node = node->next) {
        if (node->src == src_type)
            return node->dest;
    }

    infix_type * dest_type = infix_arena_calloc(dest_arena, 1, sizeof(infix_type), _Alignof(infix_type));
    if (dest_type == nullptr)
        return nullptr;

    memo_node_t * new_memo_node = infix_arena_alloc(dest_arena, sizeof(memo_node_t), _Alignof(memo_node_t));
    if (!new_memo_node)
        return nullptr;
    new_memo_node->src = src_type;
    new_memo_node->dest = dest_type;
    new_memo_node->next = *memo_head;
    *memo_head = new_memo_node;

    *dest_type = *src_type;
    dest_type->is_arena_allocated = true;

    switch (src_type->category) {
    case INFIX_TYPE_POINTER:
        dest_type->meta.pointer_info.pointee_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.pointer_info.pointee_type, memo_head);
        break;
    case INFIX_TYPE_ARRAY:
        dest_type->meta.array_info.element_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.array_info.element_type, memo_head);
        break;
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        if (src_type->meta.aggregate_info.num_members > 0) {
            size_t members_size = sizeof(infix_struct_member) * src_type->meta.aggregate_info.num_members;
            dest_type->meta.aggregate_info.members =
                infix_arena_alloc(dest_arena, members_size, _Alignof(infix_struct_member));
            if (dest_type->meta.aggregate_info.members == nullptr)
                return nullptr;
            for (size_t i = 0; i < src_type->meta.aggregate_info.num_members; ++i) {
                dest_type->meta.aggregate_info.members[i] = src_type->meta.aggregate_info.members[i];
                dest_type->meta.aggregate_info.members[i].type = _copy_type_graph_to_arena_recursive(
                    dest_arena, src_type->meta.aggregate_info.members[i].type, memo_head);
                const char * src_name = src_type->meta.aggregate_info.members[i].name;
                if (src_name) {
                    size_t name_len = strlen(src_name) + 1;
                    char * dest_name = infix_arena_alloc(dest_arena, name_len, 1);
                    if (!dest_name)
                        return nullptr;
                    infix_memcpy(dest_name, src_name, name_len);
                    dest_type->meta.aggregate_info.members[i].name = dest_name;
                }
            }
        }
        break;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        dest_type->meta.func_ptr_info.return_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.func_ptr_info.return_type, memo_head);
        if (src_type->meta.func_ptr_info.num_args > 0) {
            size_t args_size = sizeof(infix_function_argument) * src_type->meta.func_ptr_info.num_args;
            dest_type->meta.func_ptr_info.args =
                infix_arena_alloc(dest_arena, args_size, _Alignof(infix_function_argument));
            if (dest_type->meta.func_ptr_info.args == nullptr)
                return nullptr;
            for (size_t i = 0; i < src_type->meta.func_ptr_info.num_args; ++i) {
                dest_type->meta.func_ptr_info.args[i] = src_type->meta.func_ptr_info.args[i];
                dest_type->meta.func_ptr_info.args[i].type = _copy_type_graph_to_arena_recursive(
                    dest_arena, src_type->meta.func_ptr_info.args[i].type, memo_head);
                const char * src_name = src_type->meta.func_ptr_info.args[i].name;
                if (src_name) {
                    size_t name_len = strlen(src_name) + 1;
                    char * dest_name = infix_arena_alloc(dest_arena, name_len, 1);
                    if (!dest_name)
                        return nullptr;
                    infix_memcpy(dest_name, src_name, name_len);
                    dest_type->meta.func_ptr_info.args[i].name = dest_name;
                }
            }
        }
        break;
    case INFIX_TYPE_ENUM:
        dest_type->meta.enum_info.underlying_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.enum_info.underlying_type, memo_head);
        break;
    case INFIX_TYPE_COMPLEX:
        dest_type->meta.complex_info.base_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.complex_info.base_type, memo_head);
        break;
    case INFIX_TYPE_VECTOR:
        dest_type->meta.vector_info.element_type =
            _copy_type_graph_to_arena_recursive(dest_arena, src_type->meta.vector_info.element_type, memo_head);
        break;
    default:
        break;
    }
    return dest_type;
}

infix_type * _copy_type_graph_to_arena(infix_arena_t * dest_arena, const infix_type * src_type) {
    memo_node_t * memo_head = NULL;
    return _copy_type_graph_to_arena_recursive(dest_arena, src_type, &memo_head);
}

c23_nodiscard infix_type_category infix_type_get_category(const infix_type * type) {
    return type ? type->category : (infix_type_category)-1;
}
c23_nodiscard size_t infix_type_get_size(const infix_type * type) {
    return type ? type->size : 0;
}
c23_nodiscard size_t infix_type_get_alignment(const infix_type * type) {
    return type ? type->alignment : 0;
}
c23_nodiscard size_t infix_type_get_member_count(const infix_type * type) {
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION))
        return 0;
    return type->meta.aggregate_info.num_members;
}
c23_nodiscard const infix_struct_member * infix_type_get_member(const infix_type * type, size_t index) {
    if (!type || (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_UNION) ||
        index >= type->meta.aggregate_info.num_members)
        return nullptr;
    return &type->meta.aggregate_info.members[index];
}
c23_nodiscard const char * infix_type_get_arg_name(const infix_type * func_type, size_t index) {
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE ||
        index >= func_type->meta.func_ptr_info.num_args)
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].name;
}
c23_nodiscard const infix_type * infix_type_get_arg_type(const infix_type * func_type, size_t index) {
    if (!func_type || func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE ||
        index >= func_type->meta.func_ptr_info.num_args)
        return nullptr;
    return func_type->meta.func_ptr_info.args[index].type;
}
c23_nodiscard size_t infix_forward_get_num_args(const infix_forward_t * trampoline) {
    return trampoline ? trampoline->num_args : 0;
}
c23_nodiscard size_t infix_forward_get_num_fixed_args(const infix_forward_t * trampoline) {
    return trampoline ? trampoline->num_fixed_args : 0;
}
c23_nodiscard const infix_type * infix_forward_get_return_type(const infix_forward_t * trampoline) {
    return trampoline ? trampoline->return_type : nullptr;
}
c23_nodiscard const infix_type * infix_forward_get_arg_type(const infix_forward_t * trampoline, size_t index) {
    if (!trampoline || index >= trampoline->num_args)
        return nullptr;
    return trampoline->arg_types[index];
}
c23_nodiscard size_t infix_reverse_get_num_args(const infix_reverse_t * trampoline) {
    return trampoline ? trampoline->num_args : 0;
}
c23_nodiscard size_t infix_reverse_get_num_fixed_args(const infix_reverse_t * trampoline) {
    return trampoline ? trampoline->num_fixed_args : 0;
}
c23_nodiscard const infix_type * infix_reverse_get_return_type(const infix_reverse_t * trampoline) {
    return trampoline ? trampoline->return_type : nullptr;
}
c23_nodiscard const infix_type * infix_reverse_get_arg_type(const infix_reverse_t * trampoline, size_t index) {
    if (!trampoline || index >= trampoline->num_args)
        return nullptr;
    return trampoline->arg_types[index];
}
