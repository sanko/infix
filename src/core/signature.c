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
 * @brief Implements the high-level signature string parser.
 * @ingroup signature_parser
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern INFIX_TLS const char * g_infix_last_signature_context;

#define MAX_RECURSION_DEPTH 32

typedef struct {
    const char * p;
    const char * start;
    infix_arena_t * arena;
    int depth;
} parser_state;

static infix_type * parse_type(parser_state *);
static infix_status parse_function_signature_details(
    parser_state *, infix_type **, infix_function_argument **, size_t *, size_t *);

static void set_parser_error(parser_state * state, infix_error_code_t code) {
    _infix_set_error(INFIX_CATEGORY_PARSER, code, (size_t)(state->p - state->start));
}

static void skip_whitespace(parser_state * state) {
    while (true) {
        while (isspace((unsigned char)*state->p))
            state->p++;
        if (*state->p == '#') {
            while (*state->p != '\n' && *state->p != '\0')
                state->p++;
        }
        else
            break;
    }
}

static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    unsigned long long val = strtoull(start, &end, 10);
    if (end == start) {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
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
        return nullptr;
    while (isalnum((unsigned char)*state->p) || *state->p == '_' || *state->p == ':') {
        if (*state->p == ':' && state->p[1] != ':')
            break;
        if (*state->p == ':')
            state->p++;
        state->p++;
    }
    size_t len = state->p - start;
    if (len == 0)
        return nullptr;
    char * name = infix_arena_calloc(state->arena, 1, len + 1, 1);
    if (!name) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    infix_memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

static bool consume_keyword(parser_state * state, const char * keyword) {
    skip_whitespace(state);
    size_t len = strlen(keyword);
    if (strncmp(state->p, keyword, len) == 0) {
        if (isalnum((unsigned char)state->p[len]) || state->p[len] == '_')
            return false;
        state->p += len;
        skip_whitespace(state);
        return true;
    }
    return false;
}

static const char * parse_optional_name_prefix(parser_state * state) {
    skip_whitespace(state);
    const char * p_before = state->p;
    const char * name = parse_identifier(state);
    if (name) {
        skip_whitespace(state);
        if (*state->p == ':') {
            state->p++;
            return name;
        }
    }
    state->p = p_before;
    return nullptr;
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
        else
            p++;
    }
    return (p[0] == '-' && p[1] == '>');
}

static infix_struct_member * parse_aggregate_members(parser_state * state, char end_char, size_t * out_num_members) {
    typedef struct member_node {
        infix_struct_member m;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;
    skip_whitespace(state);
    if (*state->p != end_char) {
        while (1) {
            const char * p_before_member = state->p;
            const char * name = parse_optional_name_prefix(state);
            if (name && (*state->p == ',' || *state->p == end_char)) {
                state->p = p_before_member + strlen(name);
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            infix_type * member_type = parse_type(state);
            if (!member_type)
                return nullptr;
            if (member_type->category == INFIX_TYPE_VOID) {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            member_node * node = infix_arena_calloc(state->arena, 1, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                return nullptr;
            }
            node->m = infix_type_create_member(name, member_type, 0);
            node->next = nullptr;
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
                skip_whitespace(state);
                if (*state->p == end_char) {
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                    return nullptr;
                }
            }
            else if (*state->p == end_char)
                break;
            else {
                if (*state->p == '\0')
                    return nullptr;
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
        }
    }
    *out_num_members = num_members;
    if (num_members == 0)
        return nullptr;
    infix_struct_member * members =
        infix_arena_calloc(state->arena, num_members, sizeof(infix_struct_member), _Alignof(infix_struct_member));
    if (!members) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    member_node * current = head;
    for (size_t i = 0; i < num_members; i++) {
        members[i] = current->m;
        current = current->next;
    }
    return members;
}

static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        set_parser_error(state, INFIX_CODE_RECURSION_DEPTH_EXCEEDED);
        return nullptr;
    }
    state->depth++;
    if (*state->p != start_char) {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        state->depth--;
        return nullptr;
    }
    state->p++;
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, end_char, &num_members);
    if (!members && infix_get_last_error().code != INFIX_CODE_SUCCESS) {
        state->depth--;
        return nullptr;
    }
    if (*state->p != end_char) {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        state->depth--;
        return nullptr;
    }
    state->p++;
    infix_type * agg_type = nullptr;
    infix_status status = (start_char == '{') ? infix_type_create_struct(state->arena, &agg_type, members, num_members)
                                              : infix_type_create_union(state->arena, &agg_type, members, num_members);
    if (status != INFIX_SUCCESS) {
        _infix_set_error(INFIX_CATEGORY_GENERAL,
                         (status == INFIX_ERROR_ALLOCATION_FAILED) ? INFIX_CODE_OUT_OF_MEMORY : INFIX_CODE_UNKNOWN,
                         (size_t)(state->p - state->start));
        state->depth--;
        return nullptr;
    }
    state->depth--;
    return agg_type;
}

static infix_type * parse_packed_struct(parser_state * state) {
    size_t alignment = 1;
    if (*state->p == '!') {
        state->p++;
        if (isdigit((unsigned char)*state->p)) {
            if (!parse_size_t(state, &alignment))
                return nullptr;
            if (*state->p != ':') {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            state->p++;
        }
    }
    skip_whitespace(state);
    if (*state->p != '{') {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return nullptr;
    }
    state->p++;
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, '}', &num_members);
    if (!members && infix_get_last_error().code != INFIX_CODE_SUCCESS)
        return nullptr;
    if (*state->p != '}') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return nullptr;
    }
    state->p++;
    infix_type * packed_type = nullptr;
    size_t total_size = 0;
    for (size_t i = 0; i < num_members; ++i)
        total_size += members[i].type->size;
    infix_status status =
        infix_type_create_packed_struct(state->arena, &packed_type, total_size, alignment, members, num_members);
    if (status != INFIX_SUCCESS) {
        _infix_set_error(INFIX_CATEGORY_GENERAL,
                         (status == INFIX_ERROR_ALLOCATION_FAILED) ? INFIX_CODE_OUT_OF_MEMORY : INFIX_CODE_UNKNOWN,
                         (size_t)(state->p - state->start));
        return nullptr;
    }
    return packed_type;
}

static infix_type * parse_primitive(parser_state * state) {
    if (consume_keyword(state, "sint8") || consume_keyword(state, "int8"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT8);
    if (consume_keyword(state, "uint8"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT8);
    if (consume_keyword(state, "sint16") || consume_keyword(state, "int16"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT16);
    if (consume_keyword(state, "uint16"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT16);
    if (consume_keyword(state, "sint32") || consume_keyword(state, "int32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);
    if (consume_keyword(state, "uint32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT32);
    if (consume_keyword(state, "sint64") || consume_keyword(state, "int64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT64);
    if (consume_keyword(state, "uint64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT64);
    if (consume_keyword(state, "sint128") || consume_keyword(state, "int128"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_SINT128);
    if (consume_keyword(state, "uint128"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_UINT128);
    if (consume_keyword(state, "float32"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_FLOAT);
    if (consume_keyword(state, "float64"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_DOUBLE);
    if (consume_keyword(state, "bool"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_BOOL);
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
    if (consume_keyword(state, "longdouble"))
        return infix_type_create_primitive(INFIX_PRIMITIVE_LONG_DOUBLE);
    return nullptr;
}

static infix_type * parse_type(parser_state * state) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        set_parser_error(state, INFIX_CODE_RECURSION_DEPTH_EXCEEDED);
        return nullptr;
    }
    state->depth++;
    skip_whitespace(state);
    infix_type * result_type = nullptr;
    const char * p_before_type = state->p;

    if (*state->p == '@') {
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_named_reference(state->arena, &result_type, name, INFIX_AGGREGATE_STRUCT) !=
            INFIX_SUCCESS)
            result_type = nullptr;
    }
    else if (*state->p == '*') {
        state->p++;
        skip_whitespace(state);
        infix_type * pointee_type = parse_type(state);
        if (!pointee_type) {
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_pointer_to(state->arena, &result_type, pointee_type) != INFIX_SUCCESS)
            result_type = nullptr;
    }
    else if (*state->p == '(') {
        if (is_function_signature_ahead(state)) {
            infix_type * ret_type = nullptr;
            infix_function_argument * args = nullptr;
            size_t num_args = 0, num_fixed = 0;
            if (parse_function_signature_details(state, &ret_type, &args, &num_args, &num_fixed) != INFIX_SUCCESS) {
                state->depth--;
                return nullptr;
            }
            infix_type * func_type = infix_arena_calloc(state->arena, 1, sizeof(infix_type), _Alignof(infix_type));
            if (!func_type) {
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                state->depth--;
                return nullptr;
            }
            *func_type = *infix_type_create_pointer();
            func_type->is_arena_allocated = true;
            func_type->category = INFIX_TYPE_REVERSE_TRAMPOLINE;
            func_type->meta.func_ptr_info.return_type = ret_type;
            func_type->meta.func_ptr_info.args = args;
            func_type->meta.func_ptr_info.num_args = num_args;
            func_type->meta.func_ptr_info.num_fixed_args = num_fixed;
            result_type = func_type;
        }
        else {
            state->p++;
            skip_whitespace(state);
            result_type = parse_type(state);
            if (!result_type) {
                state->depth--;
                return nullptr;
            }
            skip_whitespace(state);
            if (*state->p != ')') {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                result_type = nullptr;
            }
            else
                state->p++;
        }
    }
    else if (*state->p == '[') {
        state->p++;
        skip_whitespace(state);
        size_t num_elements;
        if (!parse_size_t(state, &num_elements)) {
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
        if (*state->p != ':') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        skip_whitespace(state);
        infix_type * element_type = parse_type(state);
        if (!element_type) {
            state->depth--;
            return nullptr;
        }
        if (element_type->category == INFIX_TYPE_VOID) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
        if (*state->p != ']') {
            set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
            state->depth--;
            return nullptr;
        }
        state->p++;
        if (infix_type_create_array(state->arena, &result_type, element_type, num_elements) != INFIX_SUCCESS)
            result_type = nullptr;
    }
    else if (*state->p == '!')
        result_type = parse_packed_struct(state);
    else if (*state->p == '{')
        result_type = parse_aggregate(state, '{', '}');
    else if (*state->p == '<')
        result_type = parse_aggregate(state, '<', '>');
    else if (*state->p == 'e') {
        state->p++;
        if (*state->p != ':') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        skip_whitespace(state);
        infix_type * underlying_type = parse_type(state);
        if (!underlying_type || underlying_type->category != INFIX_TYPE_PRIMITIVE) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_enum(state->arena, &result_type, underlying_type) != INFIX_SUCCESS)
            result_type = nullptr;
    }
    else if (*state->p == 'c' && state->p[1] == '[') {
        state->p += 2;
        skip_whitespace(state);
        infix_type * base_type = parse_type(state);
        if (!base_type) {
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
        if (*state->p != ']') {
            set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
            state->depth--;
            return nullptr;
        }
        state->p++;
        if (infix_type_create_complex(state->arena, &result_type, base_type) != INFIX_SUCCESS)
            result_type = nullptr;
    }
    else if (*state->p == 'v' && state->p[1] == '[') {
        state->p += 2;
        skip_whitespace(state);
        size_t num_elements;
        if (!parse_size_t(state, &num_elements)) {
            state->depth--;
            return nullptr;
        }
        if (*state->p != ':') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        infix_type * element_type = parse_type(state);
        if (!element_type) {
            state->depth--;
            return nullptr;
        }
        if (*state->p != ']') {
            set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
            state->depth--;
            return nullptr;
        }
        state->p++;
        if (infix_type_create_vector(state->arena, &result_type, element_type, num_elements) != INFIX_SUCCESS)
            result_type = nullptr;
    }
    else {
        result_type = parse_primitive(state);
        if (!result_type) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS) {
                state->p = p_before_type;
                if (isalpha((unsigned char)*state->p) || *state->p == '_')
                    set_parser_error(state, INFIX_CODE_INVALID_KEYWORD);
                else
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            }
        }
    }
    state->depth--;
    return result_type;
}

static infix_status parse_function_signature_details(parser_state * state,
                                                     infix_type ** out_ret_type,
                                                     infix_function_argument ** out_args,
                                                     size_t * out_num_args,
                                                     size_t * out_num_fixed_args) {
    if (*state->p != '(') {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    state->p++;
    skip_whitespace(state);
    typedef struct arg_node {
        infix_function_argument arg;
        struct arg_node * next;
    } arg_node;
    arg_node *head = nullptr, *tail = nullptr;
    size_t num_args = 0;
    if (*state->p != ')') {
        while (1) {
            skip_whitespace(state);
            if (*state->p == ')' || *state->p == ';')
                break;
            const char * name = parse_optional_name_prefix(state);
            infix_type * arg_type = parse_type(state);
            if (!arg_type)
                return INFIX_ERROR_INVALID_ARGUMENT;
            arg_node * node = infix_arena_calloc(state->arena, 1, sizeof(arg_node), _Alignof(arg_node));
            if (!node)
                return INFIX_ERROR_ALLOCATION_FAILED;
            node->arg.type = arg_type;
            node->arg.name = name;
            node->next = nullptr;
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
                skip_whitespace(state);
                if (*state->p == ')' || *state->p == ';') {
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                    return INFIX_ERROR_INVALID_ARGUMENT;
                }
            }
            else if (*state->p != ')' && *state->p != ';') {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            else
                break;
        }
    }
    *out_num_fixed_args = num_args;
    if (*state->p == ';') {
        state->p++;
        if (*state->p != ')') {
            while (1) {
                skip_whitespace(state);
                if (*state->p == ')')
                    break;
                const char * name = parse_optional_name_prefix(state);
                infix_type * arg_type = parse_type(state);
                if (!arg_type)
                    return INFIX_ERROR_INVALID_ARGUMENT;
                arg_node * node = infix_arena_calloc(state->arena, 1, sizeof(arg_node), _Alignof(arg_node));
                if (!node)
                    return INFIX_ERROR_ALLOCATION_FAILED;
                node->arg.type = arg_type;
                node->arg.name = name;
                node->next = nullptr;
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
                    skip_whitespace(state);
                    if (*state->p == ')') {
                        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                        return INFIX_ERROR_INVALID_ARGUMENT;
                    }
                }
                else if (*state->p != ')') {
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                    return INFIX_ERROR_INVALID_ARGUMENT;
                }
                else
                    break;
            }
        }
    }
    skip_whitespace(state);
    if (*state->p != ')') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    state->p++;
    skip_whitespace(state);
    if (state->p[0] != '-' || state->p[1] != '>') {
        set_parser_error(state, INFIX_CODE_MISSING_RETURN_TYPE);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    state->p += 2;
    *out_ret_type = parse_type(state);
    if (!*out_ret_type)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_function_argument * args = (num_args > 0)
        ? infix_arena_calloc(state->arena, num_args, sizeof(infix_function_argument), _Alignof(infix_function_argument))
        : nullptr;
    if (num_args > 0 && !args)
        return INFIX_ERROR_ALLOCATION_FAILED;
    arg_node * current = head;
    for (size_t i = 0; i < num_args; i++) {
        args[i] = current->arg;
        current = current->next;
    }
    *out_args = args;
    *out_num_args = num_args;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status _infix_parse_type_internal(infix_type ** out_type,
                                                      infix_arena_t ** out_arena,
                                                      const char * signature) {
    if (!out_type || !out_arena || !signature || *signature == '\0') {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    g_infix_last_signature_context = signature;
    *out_arena = infix_arena_create(4096);
    if (!*out_arena) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    parser_state state = {.p = signature, .start = signature, .arena = *out_arena, .depth = 0};
    infix_type * type = parse_type(&state);
    if (type) {
        skip_whitespace(&state);
        if (state.p[0] != '\0') {
            set_parser_error(&state, INFIX_CODE_UNEXPECTED_TOKEN);
            type = nullptr;
        }
    }
    if (!type) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    *out_type = type;
    return INFIX_SUCCESS;
}

c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature,
                                                     infix_registry_t * registry) {
    _infix_clear_error();
    infix_type * raw_type = NULL;
    infix_arena_t * parser_arena = NULL;
    infix_status status = _infix_parse_type_internal(&raw_type, &parser_arena, signature);
    if (status != INFIX_SUCCESS)
        return status;
    *out_arena = infix_arena_create(4096);
    if (!*out_arena) {
        infix_arena_destroy(parser_arena);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    infix_type * final_type = _copy_type_graph_to_arena(*out_arena, raw_type);
    infix_arena_destroy(parser_arena);
    if (!final_type) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    status = _infix_resolve_type_graph_inplace(&final_type, registry);
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        *out_type = NULL;
    }
    else {
        _infix_type_recalculate_layout(final_type);
        *out_type = final_type;
    }
    return status;
}

c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_function_argument ** out_args,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args,
                                                 infix_registry_t * registry) {
    _infix_clear_error();
    if (!signature || !out_arena || !out_ret_type || !out_args || !out_num_args || !out_num_fixed_args)
        return INFIX_ERROR_INVALID_ARGUMENT;

    infix_type * raw_func_type = NULL;
    infix_arena_t * parser_arena = NULL;
    infix_status status = _infix_parse_type_internal(&raw_func_type, &parser_arena, signature);
    if (status != INFIX_SUCCESS)
        return status;

    if (raw_func_type->category != INFIX_TYPE_REVERSE_TRAMPOLINE) {
        infix_arena_destroy(parser_arena);
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    *out_arena = infix_arena_create(8192);
    if (!*out_arena) {
        infix_arena_destroy(parser_arena);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    infix_type * final_func_type = _copy_type_graph_to_arena(*out_arena, raw_func_type);
    infix_arena_destroy(parser_arena);
    if (!final_func_type) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    status = _infix_resolve_type_graph_inplace(&final_func_type, registry);
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = NULL;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    _infix_type_recalculate_layout(final_func_type);

    *out_ret_type = final_func_type->meta.func_ptr_info.return_type;
    *out_args = final_func_type->meta.func_ptr_info.args;
    *out_num_args = final_func_type->meta.func_ptr_info.num_args;
    *out_num_fixed_args = final_func_type->meta.func_ptr_info.num_fixed_args;

    return INFIX_SUCCESS;
}

typedef struct {
    char * p;
    size_t remaining;
    infix_status status;
} printer_state;

static void _print(printer_state * state, const char * fmt, ...) {
    if (state->status != INFIX_SUCCESS)
        return;
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(state->p, state->remaining, fmt, args);
    va_end(args);
    if (written < 0 || (size_t)written >= state->remaining)
        state->status = INFIX_ERROR_INVALID_ARGUMENT;
    else {
        state->p += written;
        state->remaining -= written;
    }
}

static void _infix_type_print_signature_recursive(printer_state * state, const infix_type * type) {
    if (state->status != INFIX_SUCCESS || !type) {
        if (state->status == INFIX_SUCCESS)
            state->status = INFIX_ERROR_INVALID_ARGUMENT;
        return;
    }
    switch (type->category) {
    case INFIX_TYPE_VOID:
        _print(state, "void");
        break;
    case INFIX_TYPE_NAMED_REFERENCE:
        _print(state, "@%s", type->meta.named_reference.name);
        break;
    case INFIX_TYPE_POINTER:
        _print(state, "*");
        if (type->meta.pointer_info.pointee_type == type || type->meta.pointer_info.pointee_type == nullptr ||
            type->meta.pointer_info.pointee_type->category == INFIX_TYPE_VOID)
            _print(state, "void");
        else
            _infix_type_print_signature_recursive(state, type->meta.pointer_info.pointee_type);
        break;
    case INFIX_TYPE_ARRAY:
        _print(state, "[%zu:", type->meta.array_info.num_elements);
        _infix_type_print_signature_recursive(state, type->meta.array_info.element_type);
        _print(state, "]");
        break;
    case INFIX_TYPE_STRUCT:
        if (type->meta.aggregate_info.name)
            _print(state, "@%s", type->meta.aggregate_info.name);
        else {
            _print(state, "{");
            for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
                if (i > 0)
                    _print(state, ",");
                const infix_struct_member * member = &type->meta.aggregate_info.members[i];
                if (member->name)
                    _print(state, "%s:", member->name);
                _infix_type_print_signature_recursive(state, member->type);
            }
            _print(state, "}");
        }
        break;
    case INFIX_TYPE_UNION:
        if (type->meta.aggregate_info.name)
            _print(state, "@%s", type->meta.aggregate_info.name);
        else {
            _print(state, "<");
            for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
                if (i > 0)
                    _print(state, ",");
                const infix_struct_member * member = &type->meta.aggregate_info.members[i];
                if (member->name)
                    _print(state, "%s:", member->name);
                _infix_type_print_signature_recursive(state, member->type);
            }
            _print(state, ">");
        }
        break;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        _print(state, "(");
        for (size_t i = 0; i < type->meta.func_ptr_info.num_fixed_args; ++i) {
            if (i > 0)
                _print(state, ",");
            const infix_function_argument * arg = &type->meta.func_ptr_info.args[i];
            if (arg->name)
                _print(state, "%s:", arg->name);
            _infix_type_print_signature_recursive(state, arg->type);
        }
        if (type->meta.func_ptr_info.num_args > type->meta.func_ptr_info.num_fixed_args) {
            _print(state, ";");
            for (size_t i = type->meta.func_ptr_info.num_fixed_args; i < type->meta.func_ptr_info.num_args; ++i) {
                if (i > type->meta.func_ptr_info.num_fixed_args)
                    _print(state, ",");
                const infix_function_argument * arg = &type->meta.func_ptr_info.args[i];
                if (arg->name)
                    _print(state, "%s:", arg->name);
                _infix_type_print_signature_recursive(state, arg->type);
            }
        }
        _print(state, ")->");
        _infix_type_print_signature_recursive(state, type->meta.func_ptr_info.return_type);
        break;
    case INFIX_TYPE_ENUM:
        _print(state, "e:");
        _infix_type_print_signature_recursive(state, type->meta.enum_info.underlying_type);
        break;
    case INFIX_TYPE_COMPLEX:
        _print(state, "c[");
        _infix_type_print_signature_recursive(state, type->meta.complex_info.base_type);
        _print(state, "]");
        break;
    case INFIX_TYPE_VECTOR:
        _print(state, "v[%zu:", type->meta.vector_info.num_elements);
        _infix_type_print_signature_recursive(state, type->meta.vector_info.element_type);
        _print(state, "]");
        break;
    case INFIX_TYPE_PRIMITIVE:
        switch (type->meta.primitive_id) {
        case INFIX_PRIMITIVE_BOOL:
            _print(state, "bool");
            break;
        case INFIX_PRIMITIVE_SINT8:
            _print(state, "sint8");
            break;
        case INFIX_PRIMITIVE_UINT8:
            _print(state, "uint8");
            break;
        case INFIX_PRIMITIVE_SINT16:
            _print(state, "sint16");
            break;
        case INFIX_PRIMITIVE_UINT16:
            _print(state, "uint16");
            break;
        case INFIX_PRIMITIVE_SINT32:
            _print(state, "sint32");
            break;
        case INFIX_PRIMITIVE_UINT32:
            _print(state, "uint32");
            break;
        case INFIX_PRIMITIVE_SINT64:
            _print(state, "sint64");
            break;
        case INFIX_PRIMITIVE_UINT64:
            _print(state, "uint64");
            break;
        case INFIX_PRIMITIVE_SINT128:
            _print(state, "sint128");
            break;
        case INFIX_PRIMITIVE_UINT128:
            _print(state, "uint128");
            break;
        case INFIX_PRIMITIVE_FLOAT:
            _print(state, "float");
            break;
        case INFIX_PRIMITIVE_DOUBLE:
            _print(state, "double");
            break;
        case INFIX_PRIMITIVE_LONG_DOUBLE:
            _print(state, "longdouble");
            break;
        }
        break;
    default:
        state->status = INFIX_ERROR_INVALID_ARGUMENT;
        break;
    }
}

infix_status infix_type_print(char * buffer,
                              size_t buffer_size,
                              const infix_type * type,
                              infix_print_dialect_t dialect) {
    _infix_clear_error();
    if (!buffer || buffer_size == 0 || !type)
        return INFIX_ERROR_INVALID_ARGUMENT;
    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};
    *buffer = '\0';
    if (dialect == INFIX_DIALECT_SIGNATURE)
        _infix_type_print_signature_recursive(&state, type);
    else {
        _print(&state, "unsupported_dialect");
        state.status = INFIX_ERROR_INVALID_ARGUMENT;
    }
    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';
        else {
            buffer[buffer_size - 1] = '\0';
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (buffer_size > 0)
        buffer[buffer_size - 1] = '\0';
    return state.status;
}

infix_status infix_function_print(char * buffer,
                                  size_t buffer_size,
                                  const char * function_name,
                                  const infix_type * ret_type,
                                  const infix_function_argument * args,
                                  size_t num_args,
                                  size_t num_fixed_args,
                                  infix_print_dialect_t dialect) {
    _infix_clear_error();
    if (!buffer || buffer_size == 0 || !ret_type || (num_args > 0 && !args))
        return INFIX_ERROR_INVALID_ARGUMENT;
    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};
    *buffer = '\0';
    (void)function_name;
    if (dialect == INFIX_DIALECT_SIGNATURE) {
        _print(&state, "(");
        for (size_t i = 0; i < num_fixed_args; ++i) {
            if (i > 0)
                _print(&state, ",");
            _infix_type_print_signature_recursive(&state, args[i].type);
        }
        if (num_args > num_fixed_args) {
            _print(&state, ";");
            for (size_t i = num_fixed_args; i < num_args; ++i) {
                if (i > num_fixed_args)
                    _print(&state, ",");
                _infix_type_print_signature_recursive(&state, args[i].type);
            }
        }
        _print(&state, ")->");
        _infix_type_print_signature_recursive(&state, ret_type);
    }
    else {
        _print(&state, "unsupported_dialect");
        state.status = INFIX_ERROR_INVALID_ARGUMENT;
    }
    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';
        else {
            if (buffer_size > 0)
                buffer[buffer_size - 1] = '\0';
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (buffer_size > 0)
        buffer[buffer_size - 1] = '\0';
    return state.status;
}
