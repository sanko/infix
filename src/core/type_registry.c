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
 * @file type_registry.c
 * @brief Implements the named type registry and definition parser.
 * @ingroup internal_core
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <string.h>

extern INFIX_TLS const char * g_infix_last_signature_context;

#define INITIAL_REGISTRY_BUCKETS 61

typedef struct resolve_memo_node_t {
    infix_type * src;
    struct resolve_memo_node_t * next;
} resolve_memo_node_t;

static uint64_t _registry_hash_string(const char * str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static _infix_registry_entry_t * _registry_lookup(infix_registry_t * registry, const char * name) {
    if (!registry || !name)
        return nullptr;
    size_t index = _registry_hash_string(name) % registry->num_buckets;
    for (_infix_registry_entry_t * current = registry->buckets[index]; current; current = current->next) {
        if (strcmp(current->name, name) == 0)
            return current;
    }
    return nullptr;
}

static _infix_registry_entry_t * _registry_insert(infix_registry_t * registry, const char * name) {
    size_t index = _registry_hash_string(name) % registry->num_buckets;
    _infix_registry_entry_t * new_entry =
        infix_arena_alloc(registry->arena, sizeof(_infix_registry_entry_t), _Alignof(_infix_registry_entry_t));
    if (!new_entry)
        return nullptr;
    size_t name_len = strlen(name) + 1;
    char * name_copy = infix_arena_alloc(registry->arena, name_len, 1);
    if (!name_copy)
        return nullptr;
    infix_memcpy(name_copy, name, name_len);
    new_entry->name = name_copy;
    new_entry->type = nullptr;
    new_entry->is_forward_declaration = false;
    new_entry->next = registry->buckets[index];
    registry->buckets[index] = new_entry;
    registry->num_items++;
    return new_entry;
}

c23_nodiscard infix_registry_t * infix_registry_create(void) {
    _infix_clear_error();
    infix_registry_t * registry = infix_malloc(sizeof(infix_registry_t));
    if (!registry) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }
    registry->arena = infix_arena_create(16384);
    if (!registry->arena) {
        infix_free(registry);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }
    registry->num_buckets = INITIAL_REGISTRY_BUCKETS;
    registry->buckets = infix_arena_calloc(
        registry->arena, registry->num_buckets, sizeof(_infix_registry_entry_t *), _Alignof(_infix_registry_entry_t *));
    if (!registry->buckets) {
        infix_arena_destroy(registry->arena);
        infix_free(registry);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }
    registry->num_items = 0;
    return registry;
}

void infix_registry_destroy(infix_registry_t * registry) {
    if (!registry)
        return;
    infix_arena_destroy(registry->arena);
    infix_free(registry);
}

static infix_status _resolve_type_graph_inplace_recursive(infix_type ** type_ptr,
                                                          infix_registry_t * registry,
                                                          resolve_memo_node_t ** memo_head) {
    if (!type_ptr || !*type_ptr || !(*type_ptr)->is_arena_allocated)
        return INFIX_SUCCESS;
    infix_type * type = *type_ptr;

    for (resolve_memo_node_t * node = *memo_head; node != NULL; node = node->next) {
        if (node->src == type)
            return INFIX_SUCCESS;
    }

    resolve_memo_node_t memo_node = {.src = type, .next = *memo_head};
    *memo_head = &memo_node;

    if (type->category == INFIX_TYPE_NAMED_REFERENCE) {
        if (!registry) {
            *memo_head = memo_node.next;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        const char * name = type->meta.named_reference.name;
        _infix_registry_entry_t * entry = _registry_lookup(registry, name);
        if (!entry || !entry->type) {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNRESOLVED_NAMED_TYPE, 0);
            *memo_head = memo_node.next;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        *type_ptr = entry->type;
        *memo_head = memo_node.next;
        return INFIX_SUCCESS;
    }

    infix_status status = INFIX_SUCCESS;
    switch (type->category) {
    case INFIX_TYPE_POINTER:
        status = _resolve_type_graph_inplace_recursive(&type->meta.pointer_info.pointee_type, registry, memo_head);
        break;
    case INFIX_TYPE_ARRAY:
        status = _resolve_type_graph_inplace_recursive(&type->meta.array_info.element_type, registry, memo_head);
        break;
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            status =
                _resolve_type_graph_inplace_recursive(&type->meta.aggregate_info.members[i].type, registry, memo_head);
            if (status != INFIX_SUCCESS)
                break;
        }
        break;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        status = _resolve_type_graph_inplace_recursive(&type->meta.func_ptr_info.return_type, registry, memo_head);
        if (status != INFIX_SUCCESS)
            break;
        for (size_t i = 0; i < type->meta.func_ptr_info.num_args; ++i) {
            status = _resolve_type_graph_inplace_recursive(&type->meta.func_ptr_info.args[i].type, registry, memo_head);
            if (status != INFIX_SUCCESS)
                break;
        }
        break;
    case INFIX_TYPE_ENUM:
        status = _resolve_type_graph_inplace_recursive(&type->meta.enum_info.underlying_type, registry, memo_head);
        break;
    case INFIX_TYPE_COMPLEX:
        status = _resolve_type_graph_inplace_recursive(&type->meta.complex_info.base_type, registry, memo_head);
        break;
    case INFIX_TYPE_VECTOR:
        status = _resolve_type_graph_inplace_recursive(&type->meta.vector_info.element_type, registry, memo_head);
        break;
    default:
        break;
    }

    *memo_head = memo_node.next;
    return status;
}

c23_nodiscard infix_status _infix_resolve_type_graph_inplace(infix_type ** type_ptr, infix_registry_t * registry) {
    resolve_memo_node_t * memo_head = NULL;
    return _resolve_type_graph_inplace_recursive(type_ptr, registry, &memo_head);
}

typedef struct {
    const char * p;
    const char * start;
} _registry_parser_state_t;
static void _registry_parser_skip_whitespace(_registry_parser_state_t * state) {
    while (1) {
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
static char * _registry_parser_parse_name(_registry_parser_state_t * state, char * buffer, size_t buf_size) {
    _registry_parser_skip_whitespace(state);
    const char * name_start = state->p;
    while (isalnum((unsigned char)*state->p) || *state->p == '_' || *state->p == ':') {
        if (*state->p == ':' && state->p[1] != ':')
            break;
        if (*state->p == ':')
            state->p++;
        state->p++;
    }
    size_t len = state->p - name_start;
    if (len == 0 || len >= buf_size)
        return nullptr;
    infix_memcpy(buffer, name_start, len);
    buffer[len] = '\0';
    return buffer;
}

c23_nodiscard infix_status infix_register_types(infix_registry_t * registry, const char * definitions) {
    _infix_clear_error();
    if (!registry || !definitions)
        return INFIX_ERROR_INVALID_ARGUMENT;
    _registry_parser_state_t state = {.p = definitions, .start = definitions};
    g_infix_last_signature_context = definitions;

    struct def_info {
        _infix_registry_entry_t * entry;
        const char * def_body_start;
        size_t def_body_len;
    };
    struct def_info defs_found[256];
    size_t num_defs_found = 0;

    while (*state.p != '\0') {
        _registry_parser_skip_whitespace(&state);
        if (*state.p == '\0')
            break;
        if (*state.p != '@') {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        state.p++;
        char name_buffer[256];
        if (!_registry_parser_parse_name(&state, name_buffer, sizeof(name_buffer))) {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        _infix_registry_entry_t * entry = _registry_lookup(registry, name_buffer);
        _registry_parser_skip_whitespace(&state);

        if (*state.p == '=') {
            state.p++;
            _registry_parser_skip_whitespace(&state);
            if (entry && !entry->is_forward_declaration) {
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            if (!entry) {
                entry = _registry_insert(registry, name_buffer);
                if (!entry)
                    return INFIX_ERROR_ALLOCATION_FAILED;
            }
            if (num_defs_found >= 256)
                return INFIX_ERROR_INVALID_ARGUMENT;
            defs_found[num_defs_found].entry = entry;
            defs_found[num_defs_found].def_body_start = state.p;
            int nest_level = 0;
            const char * body_end = state.p;
            while (*body_end != '\0' && !(*body_end == ';' && nest_level == 0)) {
                if (*body_end == '{' || *body_end == '<' || *body_end == '(' || *body_end == '[')
                    nest_level++;
                if (*body_end == '}' || *body_end == '>' || *body_end == ')' || *body_end == ']')
                    nest_level--;
                body_end++;
            }
            defs_found[num_defs_found].def_body_len = body_end - state.p;
            state.p = body_end;
            num_defs_found++;
        }
        else if (*state.p == ';') {
            if (entry) {
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            entry = _registry_insert(registry, name_buffer);
            if (!entry)
                return INFIX_ERROR_ALLOCATION_FAILED;
            entry->is_forward_declaration = true;
        }
        else {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        if (*state.p == ';')
            state.p++;
    }

    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        char * body_copy = infix_malloc(defs_found[i].def_body_len + 1);
        if (!body_copy)
            return INFIX_ERROR_ALLOCATION_FAILED;
        infix_memcpy(body_copy, defs_found[i].def_body_start, defs_found[i].def_body_len);
        body_copy[defs_found[i].def_body_len] = '\0';

        infix_type * raw_type = nullptr;
        infix_arena_t * parser_arena = nullptr;
        infix_status status = _infix_parse_type_internal(&raw_type, &parser_arena, body_copy);
        infix_free(body_copy);

        if (status != INFIX_SUCCESS) {
            infix_arena_destroy(parser_arena);
            infix_error_details_t err = infix_get_last_error();
            _infix_set_error(err.category, err.code, (defs_found[i].def_body_start - definitions) + err.position);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        entry->type = _copy_type_graph_to_arena(registry->arena, raw_type);
        infix_arena_destroy(parser_arena);
        if (!entry->type)
            return INFIX_ERROR_ALLOCATION_FAILED;

        if (entry->type->category == INFIX_TYPE_STRUCT || entry->type->category == INFIX_TYPE_UNION) {
            entry->type->meta.aggregate_info.name = entry->name;
        }
        entry->is_forward_declaration = false;
    }

    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        if (entry->type) {
            if (_infix_resolve_type_graph_inplace(&entry->type, registry) != INFIX_SUCCESS)
                return INFIX_ERROR_INVALID_ARGUMENT;
            _infix_type_recalculate_layout(entry->type);
        }
    }
    return INFIX_SUCCESS;
}
