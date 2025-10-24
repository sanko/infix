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
 * @brief Implements the named type registry system.
 * @ingroup internal_core
 *
 * @details This module provides the functionality for defining, storing, and resolving
 * complex C types by name. It is a critical component for handling recursive types
 * (e.g., linked lists) and mutually-dependent types, making the signature string
 * syntax much more powerful and manageable.
 *
 * The registry is built on a hash table for efficient lookups. Its most important
 * functions are:
 *
 * 1.  `infix_register_types()`: This function uses a robust **three-pass algorithm**
 *     to parse a string of definitions. This approach allows for out-of-order
 *     definitions and forward declarations, which is essential for complex type
 *     graphs.
 *
 * 2.  `_infix_resolve_type_graph_inplace()`: This internal function implements the
 *     **"Resolve"** stage of the library's core "Parse -> Copy -> Resolve -> Layout"
 *     data pipeline. It traverses a type graph and replaces all named placeholders
 *     (`@MyType`) with direct pointers to the canonical type objects stored in the
 *     registry.
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <string.h>

/** @internal A thread-local pointer to the full signature string for rich error reporting. */
extern INFIX_TLS const char * g_infix_last_signature_context;

/**
 * @internal
 * @brief The initial number of buckets for the registry's internal hash table.
 * @details A prime number is chosen to help with better key distribution,
 *          reducing the likelihood of hash collisions.
 */
#define INITIAL_REGISTRY_BUCKETS 61

/**
 * @internal
 * @struct resolve_memo_node_t
 * @brief A node for a "visited set" used during type resolution to handle cycles.
 * @details During the recursive traversal of a type graph in `_resolve_type_graph_inplace_recursive`,
 * this temporary, stack-allocated linked list tracks `infix_type` nodes that have
 * already been visited in the current recursion path. If a node is encountered a
 * second time, it indicates a cycle (e.g., `struct Node { struct Node* next; };`),
 * and the recursion must stop to prevent a stack overflow.
 */
typedef struct resolve_memo_node_t {
    infix_type * src;                  /**< The `infix_type` object that has been visited. */
    struct resolve_memo_node_t * next; /**< The next node in the visited list. */
} resolve_memo_node_t;

// Hash Table Implementation

/**
 * @internal
 * @brief Computes a hash for a string using the djb2 algorithm.
 * @details djb2 is chosen for its simplicity, speed, and good distribution properties.
 * @param[in] str The input string to hash.
 * @return The 64-bit hash value.
 */
static uint64_t _registry_hash_string(const char * str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    return hash;
}

/**
 * @internal
 * @brief Looks up an entry in the registry's hash table.
 * @param[in] registry The registry to search in.
 * @param[in] name The name of the type to find.
 * @return A pointer to the registry entry (`_infix_registry_entry_t`), or `nullptr` if not found.
 */
static _infix_registry_entry_t * _registry_lookup(infix_registry_t * registry, const char * name) {
    if (!registry || !name)
        return nullptr;
    size_t index = _registry_hash_string(name) % registry->num_buckets;
    // Traverse the linked list (chain) at the computed bucket index.
    for (_infix_registry_entry_t * current = registry->buckets[index]; current; current = current->next) {
        if (strcmp(current->name, name) == 0)
            return current;
    }
    return nullptr;
}

/**
 * @internal
 * @brief Inserts a new, empty entry into the registry's hash table.
 *
 * This function creates a new entry for a given name and adds it to the appropriate
 * hash bucket. The `type` field is initially `nullptr` and is populated later during
 * the parsing pass of `infix_register_types`. All allocations are made from the
 * registry's own arena.
 *
 * @param[in] registry The registry to insert into.
 * @param[in] name The name of the new type.
 * @return A pointer to the newly created entry, or `nullptr` on allocation failure.
 */
static _infix_registry_entry_t * _registry_insert(infix_registry_t * registry, const char * name) {
    size_t index = _registry_hash_string(name) % registry->num_buckets;
    _infix_registry_entry_t * new_entry =
        infix_arena_alloc(registry->arena, sizeof(_infix_registry_entry_t), _Alignof(_infix_registry_entry_t));
    if (!new_entry)
        return nullptr;
    // The name string must be copied into the registry's arena to ensure its lifetime.
    size_t name_len = strlen(name) + 1;
    char * name_copy = infix_arena_alloc(registry->arena, name_len, 1);
    if (!name_copy)
        return nullptr;
    infix_memcpy(name_copy, name, name_len);
    new_entry->name = name_copy;
    new_entry->type = nullptr;
    new_entry->is_forward_declaration = false;
    // Prepend to the linked list in the bucket.
    new_entry->next = registry->buckets[index];
    registry->buckets[index] = new_entry;
    registry->num_items++;
    return new_entry;
}

// Public API: Registry Lifecycle

/**
 * @brief Creates a new, empty named type registry.
 *
 * A registry acts as a dictionary for `infix` types, allowing you to define complex
 * structs, unions, or aliases once and refer to them by name (e.g., `@MyStruct`)
 * in any signature string. This is essential for managing complex, recursive, or
 * mutually-dependent types.
 *
 * @return A pointer to the new registry, or `nullptr` on allocation failure. The returned
 *         handle must be freed with `infix_registry_destroy`.
 */
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

/**
 * @brief Destroys a type registry and frees all associated memory.
 *
 * This includes freeing the registry handle itself and its internal arena, which in
 * turn frees the hash table, all entry structs, and all canonical `infix_type`
 * objects that were created as part of a type definition.
 *
 * @param[in] registry The registry to destroy. Safe to call with `nullptr`.
 */
void infix_registry_destroy(infix_registry_t * registry) {
    if (!registry)
        return;
    infix_arena_destroy(registry->arena);
    infix_free(registry);
}

// Internal Type Graph Resolution

/**
 * @internal
 * @brief Recursively walks a type graph and resolves all named type references in-place.
 *
 * This function implements the **"Resolve"** stage of the data pipeline. It modifies
 * the type graph by replacing `INFIX_TYPE_NAMED_REFERENCE` nodes with direct
 * pointers to the canonical types stored in the registry. It uses a "visited set"
 * (`memo_head`) to handle cycles correctly and avoid infinite recursion.
 *
 * @param[in,out] type_ptr A pointer to the `infix_type*` to resolve. This is a
 *        pointer-to-a-pointer, which is critical because it allows this function
 *        to *replace* the pointer at the call site (e.g., changing a member's
 *        type from a named reference to a concrete struct type).
 * @param[in] registry The registry to use for lookups.
 * @param[in,out] memo_head The head of the visited set for cycle detection.
 * @return `INFIX_SUCCESS` on success, or `INFIX_ERROR_INVALID_ARGUMENT` if a type
 *         cannot be resolved.
 */
static infix_status _resolve_type_graph_inplace_recursive(infix_type ** type_ptr,
                                                          infix_registry_t * registry,
                                                          resolve_memo_node_t ** memo_head) {
    if (!type_ptr || !*type_ptr || !(*type_ptr)->is_arena_allocated)
        return INFIX_SUCCESS;  // Base case: Don't touch static or null types.

    infix_type * type = *type_ptr;

    // Cycle detection: If we've seen this node before, we're in a cycle.
    // Return success to break the loop.
    for (resolve_memo_node_t * node = *memo_head; node != NULL; node = node->next) {
        if (node->src == type)
            return INFIX_SUCCESS;
    }
    // Add this node to the visited list before recursing.
    resolve_memo_node_t memo_node = {.src = type, .next = *memo_head};
    *memo_head = &memo_node;

    // Base case: Resolve a named reference.
    if (type->category == INFIX_TYPE_NAMED_REFERENCE) {
        if (!registry) {
            *memo_head = memo_node.next;          // Pop from list before returning.
            return INFIX_ERROR_INVALID_ARGUMENT;  // Cannot resolve without a registry.
        }
        const char * name = type->meta.named_reference.name;
        _infix_registry_entry_t * entry = _registry_lookup(registry, name);
        // Fail if the name is not in the registry or if it's an unresolved forward declaration.
        if (!entry || !entry->type) {
            _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNRESOLVED_NAMED_TYPE, 0);
            *memo_head = memo_node.next;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
        // This is the critical step: replace the pointer to the named reference
        // with a direct pointer to the canonical type from the registry.
        *type_ptr = entry->type;
        *memo_head = memo_node.next;
        return INFIX_SUCCESS;
    }

    // Recursive step: Recurse into all child types.
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

    *memo_head = memo_node.next;  // Pop from visited list before returning.
    return status;
}

/**
 * @internal
 * @brief Public-internal wrapper for the recursive resolution function.
 * @param[in,out] type_ptr A pointer to the root of the type graph to resolve.
 * @param[in] registry The registry to use for lookups.
 * @return `INFIX_SUCCESS` on success.
 */
c23_nodiscard infix_status _infix_resolve_type_graph_inplace(infix_type ** type_ptr, infix_registry_t * registry) {
    resolve_memo_node_t * memo_head = NULL;
    return _resolve_type_graph_inplace_recursive(type_ptr, registry, &memo_head);
}

// Public API: Type Registration

/**
 * @internal
 * @struct _registry_parser_state_t
 * @brief A minimal parser state for processing registry definition strings.
 * @details This is distinct from the main signature `parser_state` because the
 * grammar for definitions (`@Name=...;`) is much simpler and can be handled
 * with a simpler, non-recursive parser.
 */
typedef struct {
    const char * p;     /**< The current position in the definition string. */
    const char * start; /**< The start of the definition string for error reporting. */
} _registry_parser_state_t;

/** @internal Skips whitespace and C++-style line comments in a definition string. */
static void _registry_parser_skip_whitespace(_registry_parser_state_t * state) {
    while (1) {
        while (isspace((unsigned char)*state->p))
            state->p++;
        if (*state->p == '#') {  // Skip comments
            while (*state->p != '\n' && *state->p != '\0')
                state->p++;
        }
        else
            break;
    }
}

/** @internal Parses a type name (e.g., `MyType`, `NS::MyType`) from the definition string. */
static char * _registry_parser_parse_name(_registry_parser_state_t * state, char * buffer, size_t buf_size) {
    _registry_parser_skip_whitespace(state);
    const char * name_start = state->p;
    while (isalnum((unsigned char)*state->p) || *state->p == '_' || *state->p == ':') {
        if (*state->p == ':' && state->p[1] != ':')
            break;  // Handle single colon as non-identifier char.
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
 * @brief Parses a string of type definitions and adds them to a registry.
 *
 * This function uses a robust **three-pass approach** to handle complex dependencies,
 * including out-of-order and mutually recursive definitions.
 *
 * - **Pass 1 (Scan & Index):** The entire definition string is scanned. The parser
 *   identifies every type name being defined (`@Name = ...`) or forward-declared
 *   (`@Name;`). It creates an entry for each name in the registry's hash table and
 *   stores a pointer to the start of its definition body, without parsing it yet.
 *   This pass ensures that all type names are known before any parsing begins.
 *
 * - **Pass 2 (Parse & Copy):** The function iterates through the definitions
 *   indexed in Pass 1. For each one, it calls the main signature parser
 *   (`_infix_parse_type_internal`) on the definition body to create a raw,
 *   unresolved `infix_type` graph. This graph is then deep-copied into the
 *   registry's permanent arena. At the end of this pass, every defined name has a
 *   corresponding (but still unresolved) type graph associated with it in the registry.
 *
 * - **Pass 3 (Resolve & Layout):** The function iterates through all the newly
 *   created types from Pass 2. For each one, it performs the "Resolve" and
 *   "Layout" stages. Because all type graphs now exist, any `@Name` reference
 *   encountered during resolution is guaranteed to find a corresponding entry
 *   in the registry, successfully connecting the graph.
 *
 * @param[in] registry The registry to populate.
 * @param[in] definitions A semicolon-separated string of definitions.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
c23_nodiscard infix_status infix_register_types(infix_registry_t * registry, const char * definitions) {
    _infix_clear_error();
    if (!registry || !definitions)
        return INFIX_ERROR_INVALID_ARGUMENT;

    _registry_parser_state_t state = {.p = definitions, .start = definitions};
    g_infix_last_signature_context = definitions;

    // A temporary structure to hold information about each definition found in Pass 1.
    struct def_info {
        _infix_registry_entry_t * entry;
        const char * def_body_start;
        size_t def_body_len;
    };
    struct def_info defs_found[256];  // Max 256 definitions in a single call.
    size_t num_defs_found = 0;

    // Pass 1: Scan & Index all names and their definition bodies.
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
            // It's an error to redefine a type that wasn't a forward declaration.
            if (entry && !entry->is_forward_declaration) {
                _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_UNEXPECTED_TOKEN, state.p - state.start);
                return INFIX_ERROR_INVALID_ARGUMENT;
            }
            if (!entry) {  // If it doesn't exist, create it.
                entry = _registry_insert(registry, name_buffer);
                if (!entry)
                    return INFIX_ERROR_ALLOCATION_FAILED;
            }
            if (num_defs_found >= 256)
                return INFIX_ERROR_INVALID_ARGUMENT;  // Too many definitions.

            // Find the end of the type definition body (the next top-level ';').
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
            if (entry) {             // Cannot forward-declare an already-defined type.
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

    // Pass 2: Parse the bodies of all found definitions into the registry.
    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        // Make a temporary, null-terminated copy of the definition body substring.
        char * body_copy = infix_malloc(defs_found[i].def_body_len + 1);
        if (!body_copy)
            return INFIX_ERROR_ALLOCATION_FAILED;
        infix_memcpy(body_copy, defs_found[i].def_body_start, defs_found[i].def_body_len);
        body_copy[defs_found[i].def_body_len] = '\0';

        // "Parse" step: parse into a temporary arena.
        infix_type * raw_type = nullptr;
        infix_arena_t * parser_arena = nullptr;
        infix_status status = _infix_parse_type_internal(&raw_type, &parser_arena, body_copy);
        infix_free(body_copy);
        if (status != INFIX_SUCCESS) {
            infix_arena_destroy(parser_arena);
            // Adjust the error position to be relative to the full definition string.
            infix_error_details_t err = infix_get_last_error();
            _infix_set_error(err.category, err.code, (defs_found[i].def_body_start - definitions) + err.position);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }

        // "Copy" step: copy from temp arena to the registry's permanent arena.
        entry->type = _copy_type_graph_to_arena(registry->arena, raw_type);
        infix_arena_destroy(parser_arena);  // Destroy temp arena.
        if (!entry->type)
            return INFIX_ERROR_ALLOCATION_FAILED;

        // Annotate the type with its own name for printing and introspection.
        if (entry->type->category == INFIX_TYPE_STRUCT || entry->type->category == INFIX_TYPE_UNION) {
            entry->type->meta.aggregate_info.name = entry->name;
        }
        entry->is_forward_declaration = false;
    }

    // Pass 3: Resolve and layout all the newly defined types.
    for (size_t i = 0; i < num_defs_found; ++i) {
        _infix_registry_entry_t * entry = defs_found[i].entry;
        if (entry->type) {
            // "Resolve" and "Layout" steps.
            if (_infix_resolve_type_graph_inplace(&entry->type, registry) != INFIX_SUCCESS)
                return INFIX_ERROR_INVALID_ARGUMENT;
            _infix_type_recalculate_layout(entry->type);
        }
    }
    return INFIX_SUCCESS;
}
