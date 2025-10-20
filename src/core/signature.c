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
 *
 * @internal
 * This file contains a complete, self-contained recursive-descent parser for the
 * FFI Signature Format Specification. Its primary responsibility is to
 * transform a human-readable signature string into a graph of `infix_type` objects
 * that describe the data contract of a C function or data type.
 *
 * Key architectural principles:
 * - **Recursive Descent:** The parser is structured as a set of mutually recursive
 *   functions (e.g., `parse_type`, `parse_aggregate`, `parse_function_type`), each
 *   responsible for parsing a specific production rule in the grammar. `parse_type`
 *   is the main entry point that dispatches to other functions based on the
 *   current token (e.g., `*` for pointers, `[` for arrays).
 *
 * - **Lazy Resolution:** When parsing with a type registry, named types (e.g., `@Point`)
 *   are initially parsed into `INFIX_TYPE_NAMED_REFERENCE` placeholder nodes. This
 *   allows for out-of-order and mutually recursive type definitions. A separate
 *   resolution pass (`_infix_resolve_type_graph`) is performed after the initial
 *   parse to walk the generated type graph and replace these placeholders with pointers
 *   to the actual type definitions from the registry.
 *
 * - **Arena-Based Allocation:** All `infix_type` objects, member lists, argument arrays,
 *   and identifier strings generated during a parse are allocated from a single
 *   memory arena. This provides excellent performance by avoiding many small `malloc`
 *   calls and drastically simplifies memory management, as the entire type graph can
 *   be destroyed with a single call to `infix_arena_destroy`.
 *
 * - **Error Handling:** The parser is designed to fail gracefully. Parsing failures
 *   are signaled by returning `nullptr` or an error status. Detailed error information
 *   (the specific error code and the byte offset of the error in the original
 *   string) is recorded in a thread-local storage location, accessible via the
 *   public `infix_get_last_error()` API.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A thread-local variable to hold the signature string being parsed, giving context to the error handler.
extern INFIX_TLS const char * g_infix_last_signature_context;

/**
 * @internal
 * @def MAX_RECURSION_DEPTH
 * @brief A security limit on the nesting depth of type definitions.
 * @details This constant prevents the recursive-descent parser from causing a
 *          stack overflow when parsing maliciously crafted input with excessive
 *          nesting, such as `[[[[...[int]...]]]]`.
 */
#define MAX_RECURSION_DEPTH 32

/**
 * @internal
 * @struct parser_state
 * @brief Holds the complete state of the parser during a run.
 * @details This struct is passed by pointer to all parsing functions, allowing
 *          them to advance through the input string and allocate memory without
 *          relying on global variables. This design makes the parser re-entrant.
 */
typedef struct {
    const char * p;              /**< The current position (pointer) in the input string. */
    const char * start;          /**< The start of the original string (for calculating error positions). */
    infix_arena_t * arena;       /**< The arena from which all type objects are allocated. */
    infix_registry_t * registry; /**< The registry for resolving named types, or nullptr. */
    int depth;                   /**< The current recursion depth, checked against `MAX_RECURSION_DEPTH`. */
} parser_state;

// Forward declarations for the recursive parsing functions.
static infix_type * parse_type(parser_state *);
static infix_status parse_function_signature_details(
    parser_state *, infix_type **, infix_function_argument **, size_t *, size_t *);
static infix_type * parse_aggregate(parser_state *, char, char);
static infix_type * parse_vector_type(parser_state *);
static infix_type * parse_function_type(parser_state *);
static infix_type * parse_packed_struct(parser_state *);
static infix_type * parse_primitive(parser_state *);

/**
 * @internal
 * @brief Sets the thread-local error details with the current parser position.
 * @details This function centralizes error reporting for the parser. It uses
 *          the internal `_infix_set_error` function to record the category, code,
 *          and the byte offset of the error in the original signature string.
 * @param state The current parser state, used to calculate the error position.
 * @param code The specific error code to report.
 */
static void set_parser_error(parser_state * state, infix_error_code_t code) {
    // The error state is thread-local, so this is safe to call from any context.
    _infix_set_error(INFIX_CATEGORY_PARSER, code, (size_t)(state->p - state->start));
}

/**
 * @internal
 * @brief Skips over any insignificant whitespace and comments in the input string.
 * @details This function repeatedly consumes standard whitespace characters (`isspace`)
 *          and Perl- or INI-style line comments (from `#` to the end of the line), advancing
 *          the parser's position pointer `p` until it points to a significant token.
 * @param state The current parser state. The `p` pointer is advanced.
 */
static void skip_whitespace(parser_state * state) {
    while (true) {
        // First, consume all standard whitespace characters (space, tab, newline, etc.).
        while (isspace((unsigned char)*state->p))
            state->p++;

        // Next, check for the start of a line comment.
        if (*state->p == '#') {
            // If found, consume all characters until the next newline or the end of the string.
            while (*state->p != '\n' && *state->p != '\0')
                state->p++;
        }
        else  // If neither whitespace nor a comment is found, we're at a significant token.
            break;
    }
}

/**
 * @internal
 * @brief Parses an unsigned integer (size_t) from the input string.
 * @details This is a simple utility that wraps the standard `strtoull` function
 *          for robust parsing of decimal numbers used in array and vector sizes.
 * @param state The current parser state. `p` is advanced past the parsed number.
 * @param[out] out_val On success, this will contain the parsed integer value.
 * @return `true` on success, `false` if no valid number was parsed.
 */
static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    // Use strtoull for battle-tested parsing of 64-bit unsigned integers.
    unsigned long long val = strtoull(start, &end, 10);
    // If the end pointer hasn't moved, it means no digits were consumed.
    if (end == start) {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return false;
    }
    *out_val = (size_t)val;
    state->p = end;  // Advance the parser's pointer past the consumed number.
    return true;
}

/**
 * @internal
 * @brief Parses a C-style identifier from the input string, allowing for '::' namespaces.
 * @details An identifier must start with `[a-zA-Z_]` and can be followed by any
 *          combination of `[a-zA-Z0-9_]` or the `::` namespace separator.
 *          The parsed string is allocated from the parser's arena to make it self-contained.
 * @param state The current parser state.
 * @return A pointer to a new, arena-allocated identifier string, or `nullptr` on failure.
 */
static const char * parse_identifier(parser_state * state) {
    skip_whitespace(state);
    const char * start = state->p;
    // An identifier must start with an alphabetic character or an underscore.
    if (!isalpha((unsigned char)*start) && *start != '_')
        return nullptr;
    // Consume a valid identifier sequence.
    while (isalnum((unsigned char)*state->p) || *state->p == '_' || *state->p == ':') {
        // Special handling for the '::' namespace separator. A single ':' is not part of a valid identifier.
        if (*state->p == ':' && state->p[1] != ':')
            break;
        if (*state->p == ':')
            state->p++;  // Consume the first ':' of '::'
        state->p++;
    }
    size_t len = state->p - start;
    if (len == 0)
        return nullptr;
    // Allocate space for the identifier in the arena and copy it. This makes the
    // resulting type graph self-contained, with no pointers back to the original string.
    char * name = infix_arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    infix_memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

/**
 * @internal
 * @brief Attempts to consume a specific keyword from the input string.
 * @details This function performs a "whole word" check to prevent a signature like
 *          `"int32"` from being partially matched by the keyword `"int"`.
 * @param state The current parser state.
 * @param keyword The null-terminated keyword to match.
 * @return `true` if the keyword was successfully consumed, `false` otherwise.
 */
static bool consume_keyword(parser_state * state, const char * keyword) {
    skip_whitespace(state);
    size_t len = strlen(keyword);
    if (strncmp(state->p, keyword, len) == 0) {
        // This is the "whole word" check. The character immediately after the keyword
        // cannot be alphanumeric or '_', which would imply it's part of a larger word.
        if (isalnum((unsigned char)state->p[len]) || state->p[len] == '_')
            return false;
        // The keyword matched. Advance the pointer and return success.
        state->p += len;
        skip_whitespace(state);
        return true;
    }
    return false;
}

/**
 * @internal
 * @brief Parses an optional `name:` prefix for a member or argument.
 * @details This function attempts to parse an identifier followed by a colon. If this
 *          pattern is not found, it "backtracks" by resetting the parser's position
 *          pointer, ensuring that a simple type name is not accidentally consumed.
 * @param state The current parser state.
 * @return The parsed name string, or `nullptr` if the member is anonymous. The
 *         parser position is only advanced if a full `name:` pattern is found.
 */
static const char * parse_optional_name_prefix(parser_state * state) {
    skip_whitespace(state);
    // Save the current position in case we need to backtrack.
    const char * p_before = state->p;
    const char * name = parse_identifier(state);
    if (name) {
        skip_whitespace(state);
        if (*state->p == ':') {
            // Found "identifier:", so consume the colon and return the name.
            state->p++;
            return name;
        }
    }
    // If we get here, it wasn't a "name:" pattern (e.g., it was just a type name).
    // Backtrack the parser state to before the identifier was consumed.
    state->p = p_before;
    return nullptr;
}

/**
 * @internal
 * @brief Peeks ahead in the string to resolve the `(` token ambiguity.
 * @details The parser faces an ambiguity with `(`. It could be a grouped type like
 *          `*( (int)->void )` or a function type `(int)->void`. This function
 *          resolves this by peeking ahead to see if a matching `)` is followed by `->`.
 * @param state The current parser state (this is not modified).
 * @return `true` if the upcoming tokens form a function signature, `false` otherwise.
 */
static bool is_function_signature_ahead(const parser_state * state) {
    const char * p = state->p;
    // The ambiguity only exists if we start with '('.
    if (*p != '(')
        return false;
    p++;
    // Find the matching closing parenthesis, respecting nested parentheses.
    int depth = 1;
    while (*p != '\0' && depth > 0) {
        if (*p == '(')
            depth++;
        else if (*p == ')')
            depth--;
        p++;
    }
    // If we didn't find a matching parenthesis, it's malformed.
    if (depth != 0)
        return false;  // Malformed, not a function.
    // Skip any whitespace or comments between the ')' and the next token.
    while (isspace((unsigned char)*p) || *p == '#') {
        if (*p == '#') {
            while (*p != '\n' && *p != '\0')
                p++;
        }
        else
            p++;
    }
    // The construct is a function signature if and only if the next token is `->`.
    return (p[0] == '-' && p[1] == '>');
}

/**
 * @internal
 * @brief Parses the comma-separated member list of a struct or union.
 * @details This function handles a comma-separated list of members (e.g., `{int, name:*char}`).
 *          It uses a two-pass strategy for efficiency:
 *          1. **Pass 1:** Build a temporary singly-linked list of members on the arena.
 *             This is flexible and avoids needing to know the member count in advance.
 *          2. **Pass 2:** Allocate a single, correctly-sized array for the members and
 *             copy the data from the linked list into it. This ensures the final
 *             `infix_type` has a contiguous, cache-friendly member list.
 * @param state The current parser state.
 * @param end_char The character that terminates the list (either '}' or '>').
 * @param[out] out_num_members On success, the total number of members found.
 * @return A pointer to an arena-allocated array of `infix_struct_member`, or `nullptr`.
 */
static infix_struct_member * parse_aggregate_members(parser_state * state, char end_char, size_t * out_num_members) {
    // A temporary node for building the linked list of members on the arena.
    typedef struct member_node {
        infix_struct_member m;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->p != end_char) {  // Handle non-empty aggregates
        while (1) {
            // Parse one member
            const char * p_before_member = state->p;
            const char * name = parse_optional_name_prefix(state);
            // Check for a subtle syntax error: `name,` or `name}` with no type.
            if (name && (*state->p == ',' || *state->p == end_char)) {
                // Backtrack to the end of the name for a more accurate error position.
                state->p = p_before_member + strlen(name);
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            infix_type * member_type = parse_type(state);
            if (!member_type)
                return nullptr;                              // Propagate error from sub-parser.
            if (member_type->category == INFIX_TYPE_VOID) {  // C forbids members of type void.
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            // Add to linked list
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                return nullptr;
            }
            // Member offset is calculated later by the create_struct/union function.
            node->m = infix_type_create_member(name, member_type, 0);
            node->next = nullptr;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;
            // Check for next token: ',' or end_char
            skip_whitespace(state);
            if (*state->p == ',') {
                state->p++;  // Consume comma.
                skip_whitespace(state);
                // A trailing comma like `{int,}` is a syntax error.
                if (*state->p == end_char) {
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                    return nullptr;
                }
            }
            else if (*state->p == end_char)  // End of the list.
                break;
            else {                      // Anything else (e.g., another identifier) is a syntax error.
                if (*state->p == '\0')  // Check for unterminated string
                    return nullptr;
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
        }
    }
    *out_num_members = num_members;
    if (num_members == 0)
        return nullptr;  // Return null for empty aggregates, but without an error.
    // Pass 2: Convert the linked list to a contiguous array for the final `infix_type`.
    infix_struct_member * members =
        infix_arena_alloc(state->arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
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

/**
 * @internal
 * @brief Parses the complete `(fixed...; variadic...) -> ret` structure of a function signature.
 * @details This function is the core logic for both `infix_signature_parse` and the
 *          internal `parse_function_type`. It handles fixed arguments, the optional
 *          variadic separator `;`, variadic arguments, and the final return type.
 * @param state The current parser state.
 * @param[out] out_ret_type On success, the parsed return type.
 * @param[out] out_args On success, a new arena-allocated array of `infix_function_argument`.
 * @param[out] out_num_args On success, the total number of arguments.
 * @param[out] out_num_fixed_args On success, the number of non-variadic arguments.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
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
    // Use the same two-pass, linked-list approach as parse_aggregate_members for arguments.
    typedef struct arg_node {
        infix_function_argument arg;
        struct arg_node * next;
    } arg_node;
    arg_node *head = nullptr, *tail = nullptr;
    size_t num_args = 0;
    // Pass 1: Parse fixed arguments (before the ';')
    if (*state->p != ')') {
        while (1) {
            skip_whitespace(state);
            // Stop if we hit the end of the argument list or the variadic separator.
            if (*state->p == ')' || *state->p == ';')
                break;
            const char * name = parse_optional_name_prefix(state);
            infix_type * arg_type = parse_type(state);
            if (!arg_type)
                return INFIX_ERROR_INVALID_ARGUMENT;
            // Add the parsed argument to our linked list.
            arg_node * node = infix_arena_alloc(state->arena, sizeof(arg_node), _Alignof(arg_node));
            if (!node) {
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                return INFIX_ERROR_ALLOCATION_FAILED;
            }
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
                // Handle trailing comma error before ')' or ';'.
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
    // Pass 2: Parse variadic arguments (after the ';')
    if (*state->p == ';') {
        state->p++;
        // The loop is nearly identical to the one for fixed args.
        if (*state->p != ')') {
            while (1) {
                skip_whitespace(state);
                if (*state->p == ')')
                    break;
                const char * name = parse_optional_name_prefix(state);
                infix_type * arg_type = parse_type(state);
                if (!arg_type)
                    return INFIX_ERROR_INVALID_ARGUMENT;
                arg_node * node = infix_arena_alloc(state->arena, sizeof(arg_node), _Alignof(arg_node));
                if (!node) {
                    _infix_set_error(
                        INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                    return INFIX_ERROR_ALLOCATION_FAILED;
                }
                node->arg.type = arg_type;
                node->arg.name = name;
                node->next = nullptr;
                if (!head)
                    head = tail = node;
                else {
                    tail->next = node;
                    tail = node;
                }
                num_args++;  // Increment the *total* number of arguments.
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
    // Finalize and Parse Return Type
    skip_whitespace(state);
    if (*state->p != ')') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    state->p++;  // Consume ')'
    skip_whitespace(state);
    if (state->p[0] != '-' || state->p[1] != '>') {
        set_parser_error(state, INFIX_CODE_MISSING_RETURN_TYPE);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    state->p += 2;  // Consume '->'
    *out_ret_type = parse_type(state);
    if (!*out_ret_type)
        return INFIX_ERROR_INVALID_ARGUMENT;
    // Convert linked list to array
    infix_function_argument * args = (num_args > 0)
        ? infix_arena_alloc(state->arena, sizeof(infix_function_argument) * num_args, _Alignof(infix_function_argument))
        : nullptr;
    if (num_args > 0 && !args) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    arg_node * current = head;
    for (size_t i = 0; i < num_args; i++) {
        args[i] = current->arg;
        current = current->next;
    }
    *out_args = args;
    *out_num_args = num_args;
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Parses a packed struct, e.g., `!{...}` or `!4:{...}`.
 * @details It consumes the optional alignment specifier and then calls into the
 *          standard aggregate member parsing logic. It uses the dedicated
 *          `infix_type_create_packed_struct` factory, which trusts the user-provided
 *          offsets instead of calculating its own layout.
 * @param state The current parser state.
 * @return A pointer to the generated `infix_type`, or `nullptr` on failure.
 */
static infix_type * parse_packed_struct(parser_state * state) {
    // Default alignment for `!{...}` is 1.
    size_t alignment = 1;
    if (*state->p == '!') {
        state->p++;
        // Check for an optional alignment specifier like `!4:...`
        if (isdigit((unsigned char)*state->p)) {
            if (!parse_size_t(state, &alignment))
                return nullptr;
            if (*state->p != ':') {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }
            state->p++;  // Consume ':'
        }
    }
    skip_whitespace(state);
    if (*state->p != '{') {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return nullptr;
    }
    state->p++;  // Consume '{'
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, '}', &num_members);
    if (!members && infix_get_last_error().code != INFIX_CODE_SUCCESS) {
        return nullptr;  // Propagate error.
    }
    if (*state->p != '}') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return nullptr;
    }
    state->p++;  // Consume '}'
    infix_type * packed_type = nullptr;
    // For packed structs, we sum the member sizes as a simple heuristic for total size.
    // The user can override this with a more precise manual API call if needed.
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

/**
 * @internal
 * @brief Parses a SIMD vector type, e.g., `v[4:float]`.
 * @param state The current parser state.
 * @return A pointer to the generated `infix_type`, or `nullptr` on failure.
 */
static infix_type * parse_vector_type(parser_state * state) {
    state->p++;  // Consume 'v'
    skip_whitespace(state);
    if (*state->p != '[') {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return nullptr;
    }
    state->p++;  // Consume '['
    skip_whitespace(state);
    size_t num_elements;
    if (!parse_size_t(state, &num_elements))
        return nullptr;
    skip_whitespace(state);
    if (*state->p != ':') {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return nullptr;
    }
    state->p++;  // Consume ':'
    skip_whitespace(state);
    infix_type * element_type = parse_type(state);
    // Vector elements must be primitives.
    if (!element_type || element_type->category != INFIX_TYPE_PRIMITIVE) {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p != ']') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return nullptr;
    }
    state->p++;  // Consume ']'
    infix_type * vector_type = nullptr;
    if (infix_type_create_vector(state->arena, &vector_type, element_type, num_elements) != INFIX_SUCCESS) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    return vector_type;
}

/**
 * @internal
 * @brief Parses a function signature string into a function type descriptor.
 * @details This function is called when `parse_type` encounters a `(...) -> ...`
 *          pattern. It delegates the complex parsing of the argument and return
 *          types to `parse_function_signature_details`.
 * @param state The current parser state.
 * @return A pointer to the generated `infix_type`, or `nullptr` on failure.
 */
static infix_type * parse_function_type(parser_state * state) {
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args = 0, num_fixed = 0;

    // Delegate the heavy lifting of parsing the argument list, arrow, and return type.
    if (parse_function_signature_details(state, &ret_type, &args, &num_args, &num_fixed) != INFIX_SUCCESS)
        return nullptr;
    // Manually construct an `infix_type` of category INFIX_TYPE_REVERSE_TRAMPOLINE.
    infix_type * func_type = infix_arena_alloc(state->arena, sizeof(infix_type), _Alignof(infix_type));
    if (!func_type) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    // A function type itself is treated like a pointer for size/alignment purposes.
    *func_type = *infix_type_create_pointer();
    func_type->is_arena_allocated = true;
    func_type->category = INFIX_TYPE_REVERSE_TRAMPOLINE;

    // Populate the metadata with the parsed components.
    func_type->meta.func_ptr_info.return_type = ret_type;
    func_type->meta.func_ptr_info.args = args;
    func_type->meta.func_ptr_info.num_args = num_args;
    func_type->meta.func_ptr_info.num_fixed_args = num_fixed;
    return func_type;
}

/**
 * @internal
 * @brief A generic helper for parsing anonymous aggregate type bodies (`{...}` for structs
 *        or `<...>` for unions).
 * @param state The current parser state.
 * @param start_char The opening delimiter (`{` or `<`).
 * @param end_char The closing delimiter (`}` or `>`).
 * @return A pointer to the generated `infix_type`, or `nullptr` on failure.
 */
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
    state->p++;  // Consume start_char
    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, end_char, &num_members);
    // Check if member parsing failed with a specific error.
    if (!members && infix_get_last_error().code != INFIX_CODE_SUCCESS) {
        state->depth--;
        return nullptr;
    }
    if (*state->p != end_char) {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        state->depth--;
        return nullptr;
    }
    state->p++;  // Consume end_char
    infix_type * agg_type = nullptr;
    // Dispatch to the correct factory function based on the delimiter.
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
/**
 * @internal
 * @brief Parses a primitive type keyword from the input string.
 * @details This function attempts to match and consume one of the known primitive
 *          type keywords (e.g., "int", "float64"). It uses `consume_keyword` to
 *          ensure whole-word matching.
 * @param state The current parser state.
 * @return A pointer to the corresponding static singleton `infix_type`, or `nullptr`.
 */
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

    // Abstract C types
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

/**
 * @internal
 * @brief The main entry point for the recursive-descent parser.
 * @details This function is the central dispatcher. It examines the current token
 *          and calls the appropriate sub-parser for that token's grammar rule
 *          (e.g., `*` calls `parse_type` recursively for the pointee, `{` calls
 *          `parse_aggregate`, etc.). If no special token is found, it attempts to
 *          parse a primitive type keyword.
 * @param state The current parser state.
 * @return A pointer to the generated `infix_type` graph, or `nullptr` on failure.
 */
static infix_type * parse_type(parser_state * state) {
    // Prevent stack overflow from malicious, deeply nested input.
    if (state->depth >= MAX_RECURSION_DEPTH) {
        set_parser_error(state, INFIX_CODE_RECURSION_DEPTH_EXCEEDED);
        return nullptr;
    }
    state->depth++;
    skip_whitespace(state);
    infix_type * result_type = nullptr;
    const char * p_before_type = state->p;  // For error reporting on unknown tokens.

    // Dispatch based on the current token.
    if (*state->p == '@') {
        // Handle a named type reference like `@Point`.
        if (state->registry == nullptr) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);  // Can't use @ without a registry.
            state->depth--;
            return nullptr;
        }
        state->p++;  // Consume '@'.
        const char * name = parse_identifier(state);
        if (!name) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        // Create a placeholder. This will be replaced later by the resolver.
        if (infix_type_create_named_reference(state->arena, &result_type, name, INFIX_AGGREGATE_STRUCT) !=
            INFIX_SUCCESS) {
            _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == '*') {
        // Handle a pointer type.
        state->p++;
        skip_whitespace(state);
        // Recursively call parse_type to get the pointee's type.
        infix_type * pointee_type = parse_type(state);
        if (!pointee_type) {
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_pointer_to(state->arena, &result_type, pointee_type) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == '(') {
        // Ambiguous token: could be a function type or a grouped type.
        if (is_function_signature_ahead(state))
            result_type = parse_function_type(state);
        else {
            // It's a grouped type, e.g., `*( (int)->void )`.
            state->p++;  // Consume '('.
            skip_whitespace(state);
            result_type = parse_type(state);  // Parse the inner type.
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
                state->p++;  // Consume ')'.
        }
    }
    else if (*state->p == '[') {
        // Handle an array type.
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
        // C forbids arrays of `void`.
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
        if (infix_type_create_array(state->arena, &result_type, element_type, num_elements) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == '!')
        result_type = parse_packed_struct(state);
    else if (*state->p == '{')
        result_type = parse_aggregate(state, '{', '}');
    else if (*state->p == '<')
        result_type = parse_aggregate(state, '<', '>');
    else if (*state->p == 'e') {
        // Handle an enum type.
        state->p++;
        skip_whitespace(state);
        if (*state->p == '<') {  // Old syntax `e<...>` is no longer supported.
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        if (*state->p != ':') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        skip_whitespace(state);
        // An enum must have an explicit underlying integer type.
        infix_type * underlying_type = parse_type(state);
        if (!underlying_type) {
            state->depth--;
            return nullptr;
        }
        if (underlying_type->category != INFIX_TYPE_PRIMITIVE) {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);  // Must be based on a primitive.
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_enum(state->arena, &result_type, underlying_type) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == 'c' && state->p[1] == '[') {
        // Handle a _Complex type.
        state->p++;
        skip_whitespace(state);
        if (*state->p != '[') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
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
        if (infix_type_create_complex(state->arena, &result_type, base_type) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == 'v' && state->p[1] == '[')
        // VECTOR TYPE: v[<N>:<type>]
        result_type = parse_vector_type(state);
    else {
        // PRIMITIVE TYPE
        // If no other constructor token matches, it must be a primitive type.
        result_type = parse_primitive(state);
        if (!result_type) {
            // If primitive parsing failed and no error was set, it means we have
            // an unknown token. Set the error details now.
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

// Public API Implementation & Internal Parser
/**
 * @internal
 * @brief The internal-only parsing logic that creates a type graph but does NOT resolve named types.
 * @details This is the core parser entry point used by the public API functions. It
 *          sets up the parser state and kicks off the recursive descent process. It
 *          does not perform the final name resolution step, allowing the public
 *          API functions to control when and if resolution occurs.
 * @param[out] out_type On success, will point to the root of the generated type graph.
 * @param[out] out_arena On success, will point to the new arena that owns the graph.
 * @param signature The null-terminated signature string to parse.
 * @param registry An optional type registry. If not NULL, `@Name` syntax is enabled.
 * @return `INFIX_SUCCESS` on success, `INFIX_ERROR_INVALID_ARGUMENT` on parsing failure.
 */
c23_nodiscard infix_status _infix_parse_type_internal(infix_type ** out_type,
                                                      infix_arena_t ** out_arena,
                                                      const char * signature,
                                                      infix_registry_t * registry) {
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

    parser_state state = {.p = signature, .start = signature, .arena = *out_arena, .registry = registry, .depth = 0};
    infix_type * type = parse_type(&state);

    if (type) {
        // After parsing, check if we consumed the entire string.
        // If not, there's trailing garbage, which is a syntax error.
        skip_whitespace(&state);
        if (state.p[0] != '\0') {
            set_parser_error(&state, INFIX_CODE_UNEXPECTED_TOKEN);
            type = nullptr;
        }
    }

    // If parsing failed at any point, `type` will be null.
    if (!type) {
        // Clean up the arena we created, as the caller will not receive it.
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Implementation of the public `infix_type_from_signature` API function.
 * @details This function orchestrates the full process for parsing a single type:
 *          1. Clears any previous thread-local error state.
 *          2. Calls the internal parser to generate a raw type graph.
 *          3. If a registry was provided, it calls the resolver to replace all `@Name`
 *             references with their concrete definitions.
 *          4. On failure, it ensures all allocated resources are cleaned up.
 */
c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature,
                                                     infix_registry_t * registry) {
    _infix_clear_error();

    // Step 1: Parse the string into a (potentially unresolved) type graph.
    infix_status status = _infix_parse_type_internal(out_type, out_arena, signature, registry);
    if (status != INFIX_SUCCESS) {
        return status;
    }

    // Step 2: If a registry was used, resolve all @Name placeholders.
    if (registry) {
        if (_infix_resolve_type_graph(out_type, registry) != INFIX_SUCCESS) {
            // If resolution fails (e.g., name not found), destroy the partially
            // created resources and return an error.
            infix_arena_destroy(*out_arena);
            *out_arena = nullptr;
            *out_type = nullptr;
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    return INFIX_SUCCESS;
}

/**
 * @brief Implementation of the public `infix_signature_parse` API function.
 * @details This function orchestrates the full process for parsing a complete
 *          function signature, including the lazy resolution pass if a registry
 *          is provided.
 */
c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_function_argument ** out_args,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args,
                                                 infix_registry_t * registry) {
    _infix_clear_error();

    if (!signature || !out_arena || !out_ret_type || !out_args || !out_num_args || !out_num_fixed_args) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    g_infix_last_signature_context = signature;

    *out_arena = infix_arena_create(8192);
    if (!*out_arena) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    parser_state state = {.p = signature, .start = signature, .arena = *out_arena, .registry = registry, .depth = 0};

    // This is the main entry point for parsing a full function signature.
    infix_status status =
        parse_function_signature_details(&state, out_ret_type, out_args, out_num_args, out_num_fixed_args);

    // Check for trailing garbage data after a valid signature.
    if (status == INFIX_SUCCESS) {
        skip_whitespace(&state);
        if (state.p[0] != '\0') {
            set_parser_error(&state, INFIX_CODE_UNEXPECTED_TOKEN);
            status = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    // If parsing succeeded and a registry was used, resolve all named types.
    if (status == INFIX_SUCCESS && registry) {
        // Resolve the return type.
        if (_infix_resolve_type_graph(out_ret_type, registry) != INFIX_SUCCESS) {
            status = INFIX_ERROR_INVALID_ARGUMENT;
        }
        else {
            // Resolve each argument type.
            for (size_t i = 0; i < *out_num_args; ++i) {
                if (_infix_resolve_type_graph(&(*out_args)[i].type, registry) != INFIX_SUCCESS) {
                    status = INFIX_ERROR_INVALID_ARGUMENT;
                    break;
                }
            }
        }
    }

    // If anything failed, clean up and return an error.
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Holds the state for the signature printing functions.
 */
typedef struct {
    char * p;            /**< Current pointer into the output buffer. */
    size_t remaining;    /**< Remaining space in the buffer. */
    infix_status status; /**< Set to an error if the buffer overflows. */
} printer_state;

/**
 * @internal
 * @brief A safe, vsnprintf-based helper for building the output string.
 */
static void _print(printer_state * state, const char * fmt, ...) {
    if (state->status != INFIX_SUCCESS)
        return;
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(state->p, state->remaining, fmt, args);
    va_end(args);
    // If vsnprintf failed or indicated truncation, set an error.
    if (written < 0 || (size_t)written >= state->remaining)
        state->status = INFIX_ERROR_INVALID_ARGUMENT;
    else {
        state->p += written;
        state->remaining -= written;
    }
}

/**
 * @internal
 * @brief The recursive core of the `infix_type_print` function.
 * @details This function walks an `infix_type` graph and recursively calls itself
 *          to print the signature string for the type and all its nested members.
 * @param state The printer state, including the output buffer.
 * @param type The current `infix_type` node to print.
 */
static void _infix_type_print_signature_recursive(printer_state * state, const infix_type * type) {
    if (state->status != INFIX_SUCCESS || !type) {
        if (state->status == INFIX_SUCCESS)
            state->status = INFIX_ERROR_INVALID_ARGUMENT;
        return;
    }
    // Dispatch to the correct printing logic based on the type category.
    switch (type->category) {
    case INFIX_TYPE_VOID:
        _print(state, "void");
        break;
    case INFIX_TYPE_NAMED_REFERENCE:
        _print(state, "@%s", type->meta.named_reference.name);
        break;  // Print @Name for unresolved references
    case INFIX_TYPE_POINTER:
        _print(state, "*");
        // Handle special cases for `void*` or recursive pointer types to avoid infinite loops.
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
        // If a struct has a registered name, prefer printing that for conciseness.
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
        // Print fixed arguments, separated by commas.
        for (size_t i = 0; i < type->meta.func_ptr_info.num_fixed_args; ++i) {
            if (i > 0)
                _print(state, ",");
            const infix_function_argument * arg = &type->meta.func_ptr_info.args[i];
            if (arg->name)
                _print(state, "%s:", arg->name);
            _infix_type_print_signature_recursive(state, arg->type);
        }

        // The parser does not distinguish between "(int)->void" and "(int;)->void".
        // The presence of variadic args is determined by num_args > num_fixed_args.
        bool is_variadic = type->meta.func_ptr_info.num_args > type->meta.func_ptr_info.num_fixed_args;
        if (is_variadic) {
            _print(state, ";");
            // Print variadic arguments, separated by commas.
            for (size_t i = type->meta.func_ptr_info.num_fixed_args; i < type->meta.func_ptr_info.num_args; ++i) {
                // Add a comma only if it's not the very first variadic argument.
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
        // Map the internal primitive ID back to a canonical keyword.
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
        case INFIX_PRIMITIVE_FLOAT:
            _print(state, "float");
            break;
        case INFIX_PRIMITIVE_DOUBLE:
            _print(state, "double");
            break;
        case INFIX_PRIMITIVE_LONG_DOUBLE:
            _print(state, "longdouble");
            break;
        default:
            state->status = INFIX_ERROR_INVALID_ARGUMENT;
            break;
        }
        break;
    default:
        state->status = INFIX_ERROR_INVALID_ARGUMENT;
        break;
    }
}

/**
 * @brief Implementation of the public `infix_type_print` API function.
 */
infix_status infix_type_print(char * buffer,
                              size_t buffer_size,
                              const infix_type * type,
                              infix_print_dialect_t dialect) {
    _infix_clear_error();
    if (!buffer || buffer_size == 0 || !type) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};
    *buffer = '\0';  // Ensure buffer is empty initially

    switch (dialect) {
    case INFIX_DIALECT_SIGNATURE:
        _infix_type_print_signature_recursive(&state, type);
        break;
    case INFIX_DIALECT_ITANIUM_MANGLING:
    case INFIX_DIALECT_MSVC_MANGLING:
        // Not yet implemented
        _print(&state, "mangling_not_implemented");
        break;
    default:
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    // Check for buffer overflow and ensure null termination.
    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';  // Null-terminate the string
        else {
            // Buffer was too small, but vsnprintf might not have returned an error.
            // Ensure the last character is null to prevent overflow.
            buffer[buffer_size - 1] = '\0';  // Truncate
            _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;  // Indicate buffer was too small
        }
    }
    else if (buffer_size > 0)
        buffer[buffer_size - 1] = '\0';  // Ensure null termination on error too.
    return state.status;
}

/**
 * @brief Implementation of the public `infix_function_print` API function.
 */
infix_status infix_function_print(char * buffer,
                                  size_t buffer_size,
                                  const char * function_name,
                                  const infix_type * ret_type,
                                  const infix_function_argument * args,
                                  size_t num_args,
                                  size_t num_fixed_args,
                                  infix_print_dialect_t dialect) {
    _infix_clear_error();
    if (!buffer || buffer_size == 0 || !ret_type || (num_args > 0 && !args)) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }
    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};
    *buffer = '\0';
    (void)function_name;  // function_name is currently unused, for future mangling support.
    switch (dialect) {
    case INFIX_DIALECT_SIGNATURE:
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
        break;
    default:
        _print(&state, "unsupported_dialect");
        break;
    }
    // Final buffer state check and null termination.
    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';
        else {
            if (buffer_size > 0)
                buffer[buffer_size - 1] = '\0';
            _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    else if (buffer_size > 0)
        buffer[buffer_size - 1] = '\0';
    return state.status;
}
