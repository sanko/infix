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
 * @file signature.c
 * @brief Implements the high-level v1.0 signature string parser.
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECURSION_DEPTH 32

typedef struct {
    const char * p;
    infix_arena_t * arena;
    int depth;
    infix_status last_error;
} parser_state;

// =================================================================================================
// Forward Declarations for Static Functions
// =================================================================================================
static infix_type * parse_type(parser_state * state);
static infix_status parse_function_signature_details(parser_state * state,
                                                     infix_type ** out_ret_type,
                                                     infix_type *** out_arg_types,
                                                     size_t * out_num_args,
                                                     size_t * out_num_fixed_args);
static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char, const char * name);

// =================================================================================================
// Lexer and Low-Level Parsers
// =================================================================================================

static void skip_whitespace(parser_state * state) {
    while (true) {
        while (isspace((unsigned char)*state->p)) {
            state->p++;
        }
        if (*state->p == '#') {
            while (*state->p != '\n' && *state->p != '\0') {
                state->p++;
            }
        }
        else {
            break;
        }
    }
}

static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    unsigned long long val = strtoull(start, &end, 10);
    if (end == start) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return false;
    }
    *out_val = (size_t)val;
    state->p = end;
    return true;
}

static const char * parse_identifier(parser_state * state) {
    skip_whitespace(state);
    const char * start = state->p;
    if (!isalpha((unsigned char)*start) && *start != '_')
        return NULL;
    while (isalnum((unsigned char)*state->p) || *state->p == '_')
        state->p++;
    size_t len = state->p - start;
    if (len == 0)
        return NULL;
    char * name = infix_arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

static bool consume_keyword(parser_state * state, const char * keyword) {
    skip_whitespace(state);
    size_t len = strlen(keyword);
    if (strncmp(state->p, keyword, len) == 0) {
        if (isalnum((unsigned char)state->p[len]) || state->p[len] == '_') {
            return false;
        }
        state->p += len;
        skip_whitespace(state);
        return true;
    }
    return false;
}

static infix_type * parse_primitive(parser_state * state) {
    if (consume_keyword(state, "int8"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT8);
    if (consume_keyword(state, "uint8"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);
    if (consume_keyword(state, "int16"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT16);
    if (consume_keyword(state, "uint16"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT16);
    if (consume_keyword(state, "int32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    if (consume_keyword(state, "uint32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT32);
    if (consume_keyword(state, "int64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT64);
    if (consume_keyword(state, "uint64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
    if (consume_keyword(state, "int128"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
    if (consume_keyword(state, "uint128"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
    if (consume_keyword(state, "float32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
    if (consume_keyword(state, "float64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
    if (consume_keyword(state, "float80"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
    if (consume_keyword(state, "float128"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
    if (consume_keyword(state, "void"))
        return infix_type_create_void();
    if (consume_keyword(state, "uchar"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);
    if (consume_keyword(state, "char"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT8);
    if (consume_keyword(state, "ushort"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT16);
    if (consume_keyword(state, "short"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT16);
    if (consume_keyword(state, "uint"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT32);
    if (consume_keyword(state, "int"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    if (consume_keyword(state, "ulonglong"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
    if (consume_keyword(state, "longlong"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT64);
    if (consume_keyword(state, "ulong"))
        return infix_type_create_primitive(sizeof(unsigned long) == 8 ? INFIX_PRIMITIVE_UINT64
                                                                      : INFIX_PRIMITIVE_UINT32);
    if (consume_keyword(state, "long"))
        return infix_type_create_primitive(sizeof(long) == 8 ? INFIX_PRIMITIVE_SINT64 : INFIX_PRIMITIVE_SINT32);
    if (consume_keyword(state, "double"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
    if (consume_keyword(state, "float"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
    return NULL;
}

static bool is_function_signature_ahead(const parser_state * state) {
    const char * p = state->p;
    if (*p != '(')
        return false;
    p++;
    int depth = 1;
    while (*p != '\0' && depth > 0) {
        if (*p == '(')
            depth++;
        else if (*p == ')')
            depth--;
        p++;
    }
    if (depth != 0)
        return false;
    while (isspace((unsigned char)*p) || *p == '#') {
        if (*p == '#') {
            while (*p != '\n' && *p != '\0')
                p++;
        }
        else {
            p++;
        }
    }
    return (p[0] == '-' && p[1] == '>');
}

// =================================================================================================
// Recursive-Descent Parsers
// =================================================================================================

static infix_type * parse_function_type(parser_state * state) {
    infix_type *ret_type = NULL, **arg_types = NULL;
    size_t num_args = 0, num_fixed = 0;
    if (parse_function_signature_details(state, &ret_type, &arg_types, &num_args, &num_fixed) != INFIX_SUCCESS)
        return NULL;
    infix_type * func_ptr_type = infix_arena_alloc(state->arena, sizeof(infix_type), _Alignof(infix_type));
    if (!func_ptr_type) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    *func_ptr_type = *infix_type_create_pointer();
    func_ptr_type->is_arena_allocated = true;
    func_ptr_type->category = INFIX_TYPE_REVERSE_TRAMPOLINE;
    func_ptr_type->meta.func_ptr_info.return_type = ret_type;
    func_ptr_type->meta.func_ptr_info.arg_types = arg_types;
    func_ptr_type->meta.func_ptr_info.num_args = num_args;
    func_ptr_type->meta.func_ptr_info.num_fixed_args = num_fixed;
    return func_ptr_type;
}

static infix_struct_member * parse_aggregate_members(parser_state * state, char end_char, size_t * out_num_members) {
    typedef struct member_node {
        infix_struct_member m;
        struct member_node * next;
    } member_node;
    member_node *head = NULL, *tail = NULL;
    size_t num_members = 0;
    skip_whitespace(state);
    if (*state->p != end_char) {
        while (1) {
            skip_whitespace(state);
            const char * p_before_member = state->p;
            const char * name = parse_identifier(state);
            skip_whitespace(state);
            if (name && *state->p == ':') {
                state->p++;
                skip_whitespace(state);
            }
            else {
                name = NULL;
                state->p = p_before_member;
            }
            infix_type * member_type = parse_type(state);
            if (!member_type)
                return NULL;
            if (member_type->category == INFIX_TYPE_VOID) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return NULL;
            }
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
                return NULL;
            }
            node->m = infix_struct_member_create(name, member_type, 0);
            node->next = NULL;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;
            skip_whitespace(state);
            if (*state->p == ',') {
                state->p++;
                if (*state->p == end_char) {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    return NULL;
                }
            }
            else if (*state->p == end_char) {
                break;
            }
            else {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return NULL;
            }
        }
    }
    *out_num_members = num_members;
    if (num_members == 0)
        return NULL;
    infix_struct_member * members =
        infix_arena_alloc(state->arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
    if (!members) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    member_node * current = head;
    for (size_t i = 0; i < num_members; i++) {
        members[i] = current->m;
        current = current->next;
    }
    return members;
}

static infix_type * parse_packed_struct(parser_state * state) {
    size_t alignment = 1;
    if (*state->p == '!') {
        state->p++;
        if (isdigit((unsigned char)*state->p)) {
            if (!parse_size_t(state, &alignment))
                return NULL;
            if (*state->p != ':') {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return NULL;
            }
            state->p++;
        }
    }
    skip_whitespace(state);
    if (*state->p != '{') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    state->p++;
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, '}', &num_members);
    if (state->last_error != INFIX_SUCCESS)
        return NULL;
    if (*state->p != '}') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    state->p++;
    infix_type * packed_type = NULL;
    size_t total_size = 0;
    for (size_t i = 0; i < num_members; ++i) {
        total_size += members[i].type->size;
    }
    infix_status status =
        infix_type_create_packed_struct(state->arena, &packed_type, total_size, alignment, members, num_members);
    if (status != INFIX_SUCCESS) {
        state->last_error = status;
        return NULL;
    }
    return packed_type;
}

static infix_type * parse_type(parser_state * state) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    state->depth++;
    skip_whitespace(state);
    infix_type * result_type = NULL;
    if (*state->p == '*') {
        state->p++;
        skip_whitespace(state);
        infix_type * pointee_type = parse_type(state);
        if (!pointee_type) {
            state->depth--;
            return NULL;
        }
        if (infix_type_create_pointer_to(state->arena, &result_type, pointee_type) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = NULL;
        }
    }
    else if (*state->p == '(') {
        if (is_function_signature_ahead(state)) {
            result_type = parse_function_type(state);
        }
        else {
            state->p++;
            skip_whitespace(state);
            result_type = parse_type(state);
            if (!result_type) {
                state->depth--;
                return NULL;
            }
            skip_whitespace(state);
            if (*state->p != ')') {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                result_type = NULL;
            }
            else {
                state->p++;
            }
        }
    }
    else if (*state->p == '[') {
        state->p++;
        skip_whitespace(state);
        size_t num_elements;
        if (!parse_size_t(state, &num_elements)) {
            state->depth--;
            return NULL;
        }
        skip_whitespace(state);
        if (*state->p != ':') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        skip_whitespace(state);
        infix_type * element_type = parse_type(state);
        if (!element_type) {
            state->depth--;
            return NULL;
        }
        if (element_type->category == INFIX_TYPE_VOID) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        skip_whitespace(state);
        if (*state->p != ']') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        if (infix_type_create_array(state->arena, &result_type, element_type, num_elements) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = NULL;
        }
    }
    else if (*state->p == '!') {
        result_type = parse_packed_struct(state);
    }
    else if (*state->p == '{') {
        result_type = parse_aggregate(state, '{', '}', NULL);
    }
    else if (*state->p == '<') {
        result_type = parse_aggregate(state, '<', '>', NULL);
    }
    else if (consume_keyword(state, "struct")) {  // *** BUG FIX: Separated struct/union logic ***
        if (*state->p != '<') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        if (*state->p != '>') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        skip_whitespace(state);
        if (*state->p == '{') {
            result_type = parse_aggregate(state, '{', '}', name);
        }
        else {
            infix_status status = infix_type_create_named_reference(state->arena, &result_type, name);
            if (status != INFIX_SUCCESS) {
                state->last_error = status;
                result_type = NULL;
            }
        }
    }
    else if (consume_keyword(state, "union")) {
        if (*state->p != '<') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        if (*state->p != '>') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        skip_whitespace(state);
        if (*state->p == '<') {
            result_type = parse_aggregate(state, '<', '>', name);
        }
        else {
            infix_status status = infix_type_create_named_reference(state->arena, &result_type, name);
            if (status != INFIX_SUCCESS) {
                state->last_error = status;
                result_type = NULL;
            }
        }
    }
    else if (*state->p == 'e') {
        state->p++;
        skip_whitespace(state);
        const char * name = NULL;
        if (*state->p == '<') {
            state->p++;
            name = parse_identifier(state);
            if (!name) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return NULL;
            }
            if (*state->p != '>') {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return NULL;
            }
            state->p++;
            skip_whitespace(state);
        }
        if (*state->p != ':') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        skip_whitespace(state);
        infix_type * underlying_type = parse_type(state);
        if (!underlying_type) {
            state->depth--;
            return NULL;
        }
        if (underlying_type->category != INFIX_TYPE_PRIMITIVE) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        if (infix_type_create_enum(state->arena, &result_type, underlying_type) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = NULL;
        }
        (void)name;
    }
    else {
        result_type = parse_primitive(state);
        if (!result_type) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    state->depth--;
    return result_type;
}

static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char, const char * name) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    state->depth++;
    if (*state->p != start_char) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return NULL;
    }
    state->p++;
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, end_char, &num_members);
    if (state->last_error != INFIX_SUCCESS) {
        state->depth--;
        return NULL;
    }
    if (*state->p != end_char) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return NULL;
    }
    state->p++;
    infix_type * agg_type = NULL;
    infix_status status = (start_char == '{') ? infix_type_create_struct(state->arena, &agg_type, members, num_members)
                                              : infix_type_create_union(state->arena, &agg_type, members, num_members);
    if (status != INFIX_SUCCESS) {
        state->last_error = status;
        state->depth--;
        return NULL;
    }
    (void)name;
    state->depth--;
    return agg_type;
}

// =================================================================================================
// Public API Implementations
// =================================================================================================

c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature) {
    if (!out_type || !out_arena || !signature || *signature == '\0')
        return INFIX_ERROR_INVALID_ARGUMENT;
    *out_arena = infix_arena_create(4096);
    if (!*out_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;
    parser_state state = {.p = signature, .arena = *out_arena, .depth = 0, .last_error = INFIX_SUCCESS};
    infix_type * type = parse_type(&state);
    if (type) {
        skip_whitespace(&state);
        if (*state.p != '\0') {
            type = NULL;
            state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    if (!type) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        *out_type = NULL;
        return state.last_error != INFIX_SUCCESS ? state.last_error : INFIX_ERROR_INVALID_ARGUMENT;
    }
    *out_type = type;
    return INFIX_SUCCESS;
}

static infix_status parse_function_signature_details(parser_state * state,
                                                     infix_type ** out_ret_type,
                                                     infix_type *** out_arg_types,
                                                     size_t * out_num_args,
                                                     size_t * out_num_fixed_args) {
    if (*state->p != '(')
        return INFIX_ERROR_INVALID_ARGUMENT;
    state->p++;
    skip_whitespace(state);
    typedef struct type_node {
        infix_type * type;
        struct type_node * next;
    } type_node;
    type_node *head = NULL, *tail = NULL;
    size_t num_args = 0;
    bool is_variadic = false;
    if (*state->p != ')') {
        while (1) {
            skip_whitespace(state);
            if (state->p[0] == '.' && state->p[1] == '.' && state->p[2] == '.') {
                if (is_variadic) {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    return state->last_error;
                }
                state->p += 3;
                is_variadic = true;
                skip_whitespace(state);
                if (*state->p != ')') {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    return state->last_error;
                }
                break;
            }
            infix_type * arg_type = parse_type(state);
            if (!arg_type)
                return state->last_error;
            type_node * node = infix_arena_alloc(state->arena, sizeof(type_node), _Alignof(type_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
                return INFIX_ERROR_ALLOCATION_FAILED;
            }
            node->type = arg_type;
            node->next = NULL;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_args++;
            skip_whitespace(state);
            if (*state->p == ',') {
                state->p++;
            }
            else {
                break;
            }
        }
    }
    skip_whitespace(state);
    if (*state->p != ')')
        return INFIX_ERROR_INVALID_ARGUMENT;
    state->p++;
    skip_whitespace(state);
    if (state->p[0] != '-' || state->p[1] != '>')
        return INFIX_ERROR_INVALID_ARGUMENT;
    state->p += 2;
    *out_ret_type = parse_type(state);
    if (!*out_ret_type)
        return state->last_error;
    if ((*out_ret_type)->category == INFIX_TYPE_VOID && num_args == 0 && !is_variadic) {
        // This is just a simple check for `() -> void` which has no args.
    }
    infix_type ** arg_types =
        num_args > 0 ? infix_arena_alloc(state->arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : NULL;
    if (num_args > 0 && !arg_types) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    type_node * current = head;
    for (size_t i = 0; i < num_args; i++) {
        arg_types[i] = current->type;
        current = current->next;
    }
    *out_arg_types = arg_types;
    *out_num_args = num_args;
    *out_num_fixed_args = num_args;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_type *** out_arg_types,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args) {
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args)
        return INFIX_ERROR_INVALID_ARGUMENT;
    *out_arena = infix_arena_create(8192);
    if (!*out_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;
    parser_state state = {.p = signature, .arena = *out_arena, .depth = 0, .last_error = INFIX_SUCCESS};
    infix_status status =
        parse_function_signature_details(&state, out_ret_type, out_arg_types, out_num_args, out_num_fixed_args);
    if (status == INFIX_SUCCESS) {
        skip_whitespace(&state);
        if (*state.p != '\0') {
            status = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        return state.last_error != INFIX_SUCCESS ? state.last_error : status;
    }
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_forward_create(infix_forward_t ** out_trampoline, const char * signature) {
    infix_arena_t * arena = NULL;
    infix_type * ret_type = NULL;
    infix_type ** arg_types = NULL;
    size_t num_args, num_fixed;
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;
    status = infix_forward_create_manual(out_trampoline, ret_type, arg_types, num_args, num_fixed);
    infix_arena_destroy(arena);
    return status;
}

c23_nodiscard infix_status infix_reverse_create(infix_reverse_t ** out_context,
                                                const char * signature,
                                                void * user_callback_fn,
                                                void * user_data) {
    infix_arena_t * arena = NULL;
    infix_type * ret_type = NULL;
    infix_type ** arg_types = NULL;
    size_t num_args, num_fixed;
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;
    status =
        infix_reverse_create_manual(out_context, ret_type, arg_types, num_args, num_fixed, user_callback_fn, user_data);
    infix_arena_destroy(arena);
    return status;
}
