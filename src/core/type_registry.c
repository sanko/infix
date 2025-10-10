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
 * @file registry.c
 * @brief Implements the named type registry and definition parser.
 * @ingroup internal_core
 *
 * @internal
 * This file contains the complete implementation for the `infix_registry_t` object.
 * It includes a self-contained, separate-chaining hash table for mapping type
 * names to their definitions, with all memory managed by an internal arena.
 *
 * It also implements the parser for the type definition language (`@Name = <def>;`)
 * and the crucial "resolver" logic that walks a parsed type graph to replace
 * named references with their concrete definitions just before trampoline generation.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <string.h>

/**
 * @internal
 * @brief The initial number of buckets for the registry's internal hash table.
 * @details A prime number is chosen to help with better key distribution.
 */
#define INITIAL_REGISTRY_BUCKETS 61

//=================================================================================================
// Internal Hash Table Implementation
//=================================================================================================

/**
 * @internal
 * @brief A simple and effective string hashing function (djb2 algorithm).
 * @param str The null-terminated string to hash.
 * @return A 64-bit hash value.
 */
static uint64_t _registry_hash_string(const char * str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

/**
 * @internal
 * @brief Finds an entry in the registry's hash table by name.
 * @param registry A valid registry handle.
 * @param name The name of the type to find.
 * @return A pointer to the internal registry entry, or `nullptr` if not found.
 */
static _infix_registry_entry_t * _registry_lookup(infix_registry_t * registry, const char * name) {
    if (!registry || !name)
        return nullptr;

    uint64_t hash = _registry_hash_string(name);
    size_t index = hash % registry->num_buckets;

    _infix_registry_entry_t * current = registry->buckets[index];
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return nullptr;
}

/**
 * @internal
 * @brief Adds a new, unresolved entry to the registry. Does NOT check for duplicates.
 * @param registry A valid registry handle.
 * @param name The name of the new type.
 * @return A pointer to the newly created entry, or `nullptr` on allocation failure.
 */
static _infix_registry_entry_t * _registry_insert(infix_registry_t * registry, const char * name) {
    uint64_t hash = _registry_hash_string(name);
    size_t index = hash % registry->num_buckets;

    _infix_registry_entry_t * new_entry =
        infix_arena_alloc(registry->arena, sizeof(_infix_registry_entry_t), _Alignof(_infix_registry_entry_t));
    if (!new_entry)
        return nullptr;

    size_t name_len = strlen(name) + 1;
    char * name_copy = infix_arena_alloc(registry->arena, name_len, 1);
    if (!name_copy)
        return nullptr;
    memcpy(name_copy, name, name_len);

    new_entry->name = name_copy;
    new_entry->type = nullptr;
    new_entry->is_forward_declaration = false;

    new_entry->next = registry->buckets[index];
    registry->buckets[index] = new_entry;

    registry->num_items++;
    return new_entry;
}

//=================================================================================================
// Public API: Registry Management
//=================================================================================================

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

//=================================================================================================
// Type Definition Parser for infix_register_types
//=================================================================================================

typedef struct {
    const char * p;
    const char * start;
    infix_registry_t * registry;
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

    memcpy(buffer, name_start, len);
    buffer[len] = '\0';
    return buffer;
}

c23_nodiscard infix_status infix_register_types(infix_registry_t * registry, const char * definitions) {
    _infix_clear_error();
    if (!registry || !definitions) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    _registry_parser_state_t state = {.p = definitions, .start = definitions, .registry = registry};

    struct def_info {
        _infix_registry_entry_t * entry;
        const char * def_body_start;
        size_t def_body_len;
    };
    struct def_info defs_found[256];
    size_t num_defs_found = 0;

    // Pass 1: Find all names, check for redefinitions, and create placeholder entries.
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

        if (*state.p == '=') {  // This is a full definition.
            state.p++;
            _registry_parser_skip_whitespace(&state);
            if (entry && !entry->is_forward_declaration) {
                // Error: Redefining an already fully-defined type.
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            if (!entry) {  // First time we see this name, create the entry.
                entry = _registry_insert(registry, name_buffer);
                if (!entry) {
                    _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, state.p - state.start);
                    return INFIX_ERROR_ALLOCATION_FAILED;
                }
            }
            // Record this definition to be parsed in Pass 2.
            if (num_defs_found >= 256) {
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_RECURSION_DEPTH_EXCEEDED, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
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
        else if (*state.p == ';') {  // This is a forward declaration.
            if (entry) {
                // Error: Duplicate declaration or trying to forward-declare an already defined type.
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            entry = _registry_insert(registry, name_buffer);
            if (!entry) {
                _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, state.p - state.start);
                return INFIX_ERROR_ALLOCATION_FAILED;
            }
            entry->is_forward_declaration = true;
        }
        else {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        if (*state.p == ';')
            state.p++;
    }

    // Pass 2: Parse all definitions into unresolved type graphs in the main arena.
    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;

        char * body_copy = malloc(defs_found[i].def_body_len + 1);
        if (!body_copy)
            return INFIX_ERROR_ALLOCATION_FAILED;
        memcpy(body_copy, defs_found[i].def_body_start, defs_found[i].def_body_len);
        body_copy[defs_found[i].def_body_len] = '\0';

        infix_type * parsed_type = nullptr;
        infix_arena_t * temp_arena = nullptr;
        infix_status status = _infix_parse_type_internal(&parsed_type, &temp_arena, body_copy, registry);

        free(body_copy);

        if (status != INFIX_SUCCESS) {
            infix_arena_destroy(temp_arena);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        infix_type * permanent_type = _copy_type_graph_to_arena(registry->arena, parsed_type);
        infix_arena_destroy(temp_arena);

        if (!permanent_type)
            return INFIX_ERROR_ALLOCATION_FAILED;

        entry->type = permanent_type;
        entry->is_forward_declaration = false;
    }

    // Pass 3: Resolve all types now that all definitions are parsed and stored.
    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        if (entry->type) {
            if (_infix_resolve_type_graph(&entry->type, registry) != INFIX_SUCCESS) {
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
        }
    }

    return INFIX_SUCCESS;
}

//=================================================================================================
// Type Graph Resolver
//=================================================================================================

c23_nodiscard infix_status _infix_resolve_type_graph(infix_type ** type_ptr, infix_registry_t * registry) {
    if (!type_ptr || !*type_ptr)
        return INFIX_SUCCESS;
    infix_type * type = *type_ptr;

    if (type->category == INFIX_TYPE_NAMED_REFERENCE) {
        const char * name = type->meta.named_reference.name;
        _infix_registry_entry_t * entry = _registry_lookup(registry, name);

        if (!entry || !entry->type) {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNRESOLVED_NAMED_TYPE, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        *type_ptr = entry->type;
        return INFIX_SUCCESS;
    }

    switch (type->category) {
    case INFIX_TYPE_POINTER:
        return _infix_resolve_type_graph(&type->meta.pointer_info.pointee_type, registry);
    case INFIX_TYPE_ARRAY:
        return _infix_resolve_type_graph(&type->meta.array_info.element_type, registry);
    case INFIX_TYPE_STRUCT:
    case INFIX_TYPE_UNION:
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (_infix_resolve_type_graph(&type->meta.aggregate_info.members[i].type, registry) != INFIX_SUCCESS) {
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
        }
        break;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        if (_infix_resolve_type_graph(&type->meta.func_ptr_info.return_type, registry) != INFIX_SUCCESS) {
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        for (size_t i = 0; i < type->meta.func_ptr_info.num_args; ++i) {
            if (_infix_resolve_type_graph(&type->meta.func_ptr_info.args[i].type, registry) != INFIX_SUCCESS) {
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
        }
        break;
    default:
        break;
    }
    return INFIX_SUCCESS;
}
