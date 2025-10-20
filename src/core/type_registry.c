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
 *
 * @internal
 * This file contains the complete implementation for the `infix_registry_t` object.
 * It includes a self-contained, separate-chaining hash table for mapping type
 * names to their definitions, with all memory managed by an internal arena.
 *
 * It also implements the parser for the type definition language (`@Name = <def>;`)
 * and the crucial "resolver" logic that walks a parsed type graph to replace
 * named references with their concrete definitions just before trampoline generation.
 * The parser uses a robust three-pass strategy to handle out-of-order definitions,
 * forward declarations, and recursive types correctly.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <string.h>

/**
 * @internal
 * @brief The initial number of buckets for the registry's internal hash table.
 * @details A prime number is chosen to help with better key distribution,
 *          reducing the likelihood of hash collisions.
 */
#define INITIAL_REGISTRY_BUCKETS 61

// Internal Hash Table Implementation
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

    // Calculate the hash to find the correct bucket.
    uint64_t hash = _registry_hash_string(name);
    size_t index = hash % registry->num_buckets;

    // Traverse the linked list (chain) at that bucket.
    _infix_registry_entry_t * current = registry->buckets[index];
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;  // Found a match.
        }
        current = current->next;
    }
    return nullptr;  // Not found.
}

/**
 * @internal
 * @brief Adds a new, unresolved entry to the registry. Does NOT check for duplicates.
 * @details The caller is responsible for checking for existing entries to enforce
 *          the "no redefinition" rule. This function allocates a copy of the
 *          name into the registry's arena to ensure the registry owns its keys.
 * @param registry A valid registry handle.
 * @param name The name of the new type.
 * @return A pointer to the newly created entry, or `nullptr` on allocation failure.
 */
static _infix_registry_entry_t * _registry_insert(infix_registry_t * registry, const char * name) {
    uint64_t hash = _registry_hash_string(name);
    size_t index = hash % registry->num_buckets;

    // Allocate a new entry node from the registry's main arena.
    _infix_registry_entry_t * new_entry =
        infix_arena_alloc(registry->arena, sizeof(_infix_registry_entry_t), _Alignof(_infix_registry_entry_t));
    if (!new_entry)
        return nullptr;

    // Allocate a permanent copy of the name string into the arena. This is critical
    // for making the registry self-contained.
    size_t name_len = strlen(name) + 1;
    char * name_copy = infix_arena_alloc(registry->arena, name_len, 1);
    if (!name_copy)
        return nullptr;
    infix_memcpy(name_copy, name, name_len);

    // Populate the new entry as a placeholder. The type will be linked later.
    new_entry->name = name_copy;
    new_entry->type = nullptr;
    new_entry->is_forward_declaration = false;

    // Insert the new entry at the head of the bucket's linked list (chain).
    new_entry->next = registry->buckets[index];
    registry->buckets[index] = new_entry;

    registry->num_items++;
    return new_entry;
}

// Public API: Registry Management
/**
 * @brief Implementation for the public `infix_registry_create` function.
 */
c23_nodiscard infix_registry_t * infix_registry_create(void) {
    _infix_clear_error();
    // 1. Allocate the main registry struct itself.
    infix_registry_t * registry = infix_malloc(sizeof(infix_registry_t));
    if (!registry) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }

    // 2. Create the arena that will manage all internal memory for this registry.
    registry->arena = infix_arena_create(16384);  // Start with 16KB
    if (!registry->arena) {
        infix_free(registry);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return nullptr;
    }

    // 3. Allocate the bucket array from the arena. Use calloc to zero-initialize.
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

/**
 * @brief Implementation for the public `infix_registry_destroy` function.
 */
void infix_registry_destroy(infix_registry_t * registry) {
    if (!registry)
        return;

    // The arena allocator handles all complex cleanup. This one call frees the
    // hash table, all entry nodes, all copied strings, and all infix_type graphs.
    infix_arena_destroy(registry->arena);

    // Finally, free the registry handle itself.
    infix_free(registry);
}

// Type Definition Parser for infix_register_types
/**
 * @internal
 * @brief The state for the registry's internal definition parser.
 */
typedef struct {
    const char * p;              /**< Current position in the definition string. */
    const char * start;          /**< Start of the entire definition string for error reporting. */
    infix_registry_t * registry; /**< The registry being populated. */
} _registry_parser_state_t;

/** @internal @brief Skips whitespace and comments in the definition string. */
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

/**
 * @internal
 * @brief Parses an identifier, which can include namespaces (e.g., `UI::Point`).
 * @param state The current parser state.
 * @param buffer A temporary buffer to store the parsed name.
 * @param buf_size The size of the temporary buffer.
 * @return A pointer to the `buffer` on success, or `nullptr` on failure.
 */
static char * _registry_parser_parse_name(_registry_parser_state_t * state, char * buffer, size_t buf_size) {
    _registry_parser_skip_whitespace(state);
    const char * name_start = state->p;
    while (isalnum((unsigned char)*state->p) || *state->p == '_' || *state->p == ':') {
        if (*state->p == ':' && state->p[1] != ':')
            break;  // Allow '::' but not single ':'
        if (*state->p == ':')
            state->p++;  // Skip the first ':' of '::'
        state->p++;
    }
    size_t len = state->p - name_start;
    if (len == 0 || len >= buf_size)
        return nullptr;

    infix_memcpy(buffer, name_start, len);
    buffer[len] = '\0';
    return buffer;
}

/**
 * @brief Implementation of the public `infix_register_types` function.
 */
c23_nodiscard infix_status infix_register_types(infix_registry_t * registry, const char * definitions) {
    _infix_clear_error();
    if (!registry || !definitions) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    _registry_parser_state_t state = {.p = definitions, .start = definitions, .registry = registry};

    // This parser uses a three-pass strategy to correctly handle forward
    // declarations and mutually recursive types.
    struct def_info {
        _infix_registry_entry_t * entry;
        const char * def_body_start;
        size_t def_body_len;
    };
    struct def_info defs_found[256];  // Support up to 256 definitions in one call
    size_t num_defs_found = 0;

    // PASS 1: NAME DISCOVERY
    // Find all type names (@Name), check for redefinitions, and create placeholder entries.
    // This allows definitions to appear in any order.
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

            // Scan to the end of the current definition, respecting nested delimiters.
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

    // PASS 2: PARSE DEFINITIONS
    // Parse all definition bodies into unresolved type graphs in the main arena.
    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        const char * body_start = defs_found[i].def_body_start;

        // Create a temporary, null-terminated string for the definition body.
        char * body_copy = infix_malloc(defs_found[i].def_body_len + 1);
        if (!body_copy)
            return INFIX_ERROR_ALLOCATION_FAILED;
        infix_memcpy(body_copy, body_start, defs_found[i].def_body_len);
        body_copy[defs_found[i].def_body_len] = '\0';

        infix_type * parsed_type = nullptr;
        infix_arena_t * temp_arena = nullptr;
        // Use the internal parser which does not perform resolution. This creates a raw type graph.
        infix_status status = _infix_parse_type_internal(&parsed_type, &temp_arena, body_copy, registry);

        infix_free(body_copy);

        if (status != INFIX_SUCCESS) {
            // Correct the error position to be relative to the original, full string.
            infix_error_details_t err = infix_get_last_error();
            size_t absolute_pos = (body_start - definitions) + err.position;
            _infix_set_error(err.category, err.code, absolute_pos);
            infix_arena_destroy(temp_arena);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        // Deep-copy the raw graph from the temporary arena to the registry's permanent arena.
        infix_type * permanent_type = _copy_type_graph_to_arena(registry->arena, parsed_type);
        infix_arena_destroy(temp_arena);  // The temp arena is no longer needed.

        if (!permanent_type)
            return INFIX_ERROR_ALLOCATION_FAILED;

        entry->type = permanent_type;
        entry->is_forward_declaration = false;
    }

    // PASS 3: RESOLVE TYPES
    // Now that all types have been parsed and stored, resolve all named references.
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


// Type Graph Resolver


/**
 * @internal
 * @brief Recursively walks a type graph, replacing all named references with their definitions from the registry.
 * @details This function is the core of the lazy resolution strategy. It takes a pointer-to-a-pointer
 *          to an `infix_type` so it can directly replace a reference node with a pointer to the
 *          actual type definition.
 *
 * @param type_ptr A pointer to the `infix_type*` to resolve.
 * @param registry The registry to use for lookups.
 * @return `INFIX_SUCCESS` if all references were resolved, or an error code on failure.
 */
c23_nodiscard infix_status _infix_resolve_type_graph(infix_type ** type_ptr, infix_registry_t * registry) {
    if (!type_ptr || !*type_ptr)
        return INFIX_SUCCESS;
    infix_type * type = *type_ptr;

    // The base case: we found a named reference.
    if (type->category == INFIX_TYPE_NAMED_REFERENCE) {
        const char * name = type->meta.named_reference.name;
        _infix_registry_entry_t * entry = _registry_lookup(registry, name);

        // Fail if the name is not in the registry or if it's an undefined forward declaration.
        if (!entry || !entry->type) {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNRESOLVED_NAMED_TYPE, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        // The magic: replace the reference node with the pointer to the real type.
        *type_ptr = entry->type;
        // Do NOT recurse further down this branch. The type from the registry is
        // assumed to be on its own path to resolution. This is the key to
        // breaking the infinite loop in recursive type definitions.
        return INFIX_SUCCESS;
    }

    // The recursive cases: traverse into composite types.
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
        // Primitives and other simple types have no children to resolve.
        break;
    }
    return INFIX_SUCCESS;
}
