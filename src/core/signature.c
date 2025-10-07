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
 * - **Recursive Descent:** The parser is structured as a set of functions, each
 *   responsible for parsing a specific part of the grammar (e.g., `parse_type`,
 *   `parse_aggregate`).
 * - **Arena-Based Allocation:** All `infix_type` objects and associated metadata
 *   are allocated from a single memory arena for performance and simple cleanup.
 * - **Error Handling:** Parsing failures are signaled by returning `nullptr` or an
 *   error status. Detailed error information (error code and position) is
 *   recorded in a thread-local storage location, accessible via the public
 *   `infix_get_last_error()` API.
 * @endinternal
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/*
 * @internal
 * A security limit on the nesting depth of type definitions.
 * This constant prevents the recursive-descent parser from causing a
 * stack overflow when parsing maliciously crafted input with excessive
 * nesting, such as `[[[[...[int]...]]]]`.
 */
#define MAX_RECURSION_DEPTH 32

/*
 * @internal
 * @struct parser_state
 * @brief Holds the complete state of the parser during a run.
 * @details This struct is passed by pointer to all parsing functions, allowing
 *          them to advance through the input string and allocate memory without
 *          relying on global variables. This design makes the parser re-entrant.
 */
typedef struct {
    const char * p;        /**< The current position (pointer) in the input string. */
    const char * start;    /**< The start of the original string (for calculating error positions). */
    infix_arena_t * arena; /**< The arena from which all type objects are allocated. */
    int depth;             /**< The current recursion depth, checked against `MAX_RECURSION_DEPTH`. */
} parser_state;

// Forward declarations for recursive functions
static infix_type * parse_type(parser_state *);
static infix_status parse_function_signature_details(
    parser_state *, infix_type **, infix_function_argument **, size_t *, size_t *);
static infix_type * parse_aggregate(parser_state *, char, char, const char *);
static infix_type * parse_vector_type(parser_state *);
static infix_type * parse_function_type(parser_state *);

/**
 * @internal
 * @brief A helper function to set the thread-local error details with the current parser position.
 * @param state The current parser state.
 * @param code The specific error code to set.
 */
static void set_parser_error(parser_state * state, infix_error_code_t code) {
    _infix_set_error(INFIX_CATEGORY_PARSER, code, (size_t)(state->p - state->start));
}

/**
 * @internal
 * @brief Skips over any insignificant whitespace and comments in the input string.
 * @details Consumes spaces, tabs, newlines, and comments (from '#' to end-of-line).
 * @param state The current parser state. The `p` pointer is advanced.
 */
static void skip_whitespace(parser_state * state) {
    while (true) {
        // First, consume all standard whitespace characters.
        while (isspace((unsigned char)*state->p))
            state->p++;
        // Next, check for the start of a line comment.
        if (*state->p == '#') {
            // If found, consume all characters until the next newline or the end of the string.
            while (*state->p != '\n' && *state->p != '\0')
                state->p++;
        }
        else
            // If neither whitespace nor a comment is found, we're done.
            break;
    }
}

/**
 * @internal
 * @brief Parses an unsigned integer (size_t) from the input string.
 * @details A simple utility that wraps `strtoull` for parsing decimal numbers.
 * @param state The current parser state. `p` is advanced past the parsed number.
 * @param[out] out_val On success, this will contain the parsed integer value.
 * @return `true` on success, `false` if no valid number was parsed.
 */
static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    // Use strtoull for battle tested parsing of 64-bit unsigned integers.
    unsigned long long val = strtoull(start, &end, 10);
    // If the end pointer hasn't moved, no digits were consumed.
    if (end == start) {
        set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
        return false;
    }
    *out_val = (size_t)val;
    state->p = end;  // Advance the parser's pointer.
    return true;
}

/**
 * @internal
 * @brief Parses a C-style identifier from the input string.
 * @details An identifier must start with `[a-zA-Z_]` and be followed by `[a-zA-Z0-9_]`.
 *          The parsed string is allocated from the parser's arena.
 * @param state The current parser state.
 * @return A pointer to the newly allocated identifier string, or `nullptr` on failure.
 */
static const char * parse_identifier(parser_state * state) {
    skip_whitespace(state);
    const char * start = state->p;
    // An identifier must start with an alphabetic character or an underscore.
    if (!isalpha((unsigned char)*start) && *start != '_')
        return nullptr;
    // Consume subsequent alphanumeric characters or underscores.
    while (isalnum((unsigned char)*state->p) || *state->p == '_')
        state->p++;
    size_t len = state->p - start;
    if (len == 0)
        return nullptr;

    // Allocate space for the identifier in the arena and copy it.
    char * name = infix_arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }
    memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

/**
 * @internal
 * @brief Attempts to consume a specific keyword from the input string.
 * @details This function performs a "whole word" check to prevent "int32" from
 *          partially matching the keyword "int".
 * @param state The current parser state.
 * @param keyword The null-terminated keyword to match (e.g., "struct").
 * @return `true` if the keyword was successfully consumed, `false` otherwise.
 */
static bool consume_keyword(parser_state * state, const char * keyword) {
    skip_whitespace(state);
    size_t len = strlen(keyword);
    if (strncmp(state->p, keyword, len) == 0) {
        // This is the "whole word" check. The character after the keyword
        // cannot be alphanumeric, which would imply it's part of a larger word.
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
 * @param state The current parser state.
 * @return The parsed name string, or `nullptr` if the member is anonymous.
 *         The parser position is only advanced if a `name:` pattern is found.
 */
static const char * parse_optional_name_prefix(parser_state * state) {
    skip_whitespace(state);
    const char * p_before = state->p;

    const char * name = parse_identifier(state);
    if (name) {
        skip_whitespace(state);
        if (*state->p == ':') {
            state->p++;  // Consume colon
            return name;
        }
    }

    // If it wasn't a "name:" pattern, backtrack.
    state->p = p_before;
    return nullptr;
}

/**
 * @internal
 * @brief Parses a primitive type keyword from the input string.
 * @details This function attempts to match and consume one of the keywords
 *          for primitive types. The order of checks is important to consume the
 *          longest possible match (e.g., `longlong` before `long`).
 * @param state The current parser state.
 * @return A pointer to the corresponding static `infix_type`, or `nullptr` if no match.
 */
static infix_type * parse_primitive(parser_state * state) {
    // Tier 2: Explicit fixed-width types are checked first as they are more specific.
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
    // Tier 1: Abstract C types.
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
    // Crucially, 'longlong' must be checked before 'long' to ensure the longest match.
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
    // If no keyword matches, it's not a primitive type.
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
        return false;

    // Skip any whitespace or comments between the ')' and the next token.
    while (isspace((unsigned char)*p) || *p == '#') {
        if (*p == '#') {
            while (*p != '\n' && *p != '\0')
                p++;
        }
        else
            p++;
    }

    // The upcoming construct is a function signature if and only if the next
    // non-whitespace token is the arrow '->'.
    return (p[0] == '-' && p[1] == '>');
}

/**
 * @internal
 * @brief Parses the member list of a struct or union.
 * @details This function handles a comma-separated list of members, such as
 *          `{int, name:*char, double}`. It uses a two-pass strategy for efficiency:
 *          1. Build a temporary singly-linked list of members on the arena.
 *          2. Allocate a single, correctly-sized array and copy the member data into it.
 * @param state The current parser state.
 * @param end_char The character that terminates the list (either '}' or '>').
 * @param[out] out_num_members On success, the total number of members found.
 * @return A pointer to an arena-allocated array of `infix_struct_member`, or `nullptr`.
 */

static infix_struct_member * parse_aggregate_members(parser_state * state, char end_char, size_t * out_num_members) {
    // A temporary node for building the linked list of members.
    typedef struct member_node {
        infix_struct_member m;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    skip_whitespace(state);
    // Handle empty aggregates like `{}` or `<>` by checking for the end character immediately.
    if (*state->p != end_char) {
        while (1) {
            const char * p_before_member = state->p;
            const char * name = parse_optional_name_prefix(state);

            if (name && (*state->p == ',' || *state->p == end_char)) {
                state->p = p_before_member + strlen(name);
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }

            // The C standard forbids members of type void.
            infix_type * member_type = parse_type(state);
            if (!member_type)
                return nullptr;

            if (member_type->category == INFIX_TYPE_VOID) {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                return nullptr;
            }

            // Add the parsed member to our linked list.
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
                return nullptr;
            }
            node->m = infix_type_create_member(name, member_type, 0);  // Offset is calculated later.
            node->next = nullptr;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;

            skip_whitespace(state);
            // After a member, we expect either a comma or the end character.
            if (*state->p == ',') {
                state->p++;
                skip_whitespace(state);
                // A trailing comma like `{int,}` is a syntax error.
                if (*state->p == end_char) {
                    set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                    return nullptr;
                }
            }
            else if (*state->p == end_char)
                break;  // End of the list.
            else {
                // Anything else is a syntax error.
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

    // Pass 2: Convert the linked list to a contiguous array.
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
 * @brief Parses a packed struct, including the optional alignment specifier.
 * @details Handles `!{...}` and `!N:{...}` syntax.
 * @param state The current parser state.
 * @return A new arena-allocated `infix_type` for the packed struct, or `nullptr`.
 */
static infix_type * parse_packed_struct(parser_state * state) {
    size_t alignment = 1;  // The default alignment for a packed struct is 1.
    if (*state->p == '!') {
        state->p++;
        // Check for an explicit alignment override, e.g., `!4:{...}`.
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
    if (!members && infix_get_last_error().code != INFIX_CODE_SUCCESS) {
        return nullptr;
    }

    if (*state->p != '}') {
        set_parser_error(state, INFIX_CODE_UNTERMINATED_AGGREGATE);
        return nullptr;
    }
    state->p++;

    infix_type * packed_type = nullptr;
    // For packed structs, the size is simply the sum of member sizes, as there's
    // no internal padding. The final layout calculation is handled by the `_create` function.
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
 * @brief Parses a SIMD vector type from the input string: `v[<N>:<type>]`.
 * @param state The current parser state.
 * @return A new arena-allocated `infix_type` for the vector, or `nullptr`.
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
    if (!element_type)
        return nullptr;
    if (element_type->category != INFIX_TYPE_PRIMITIVE) {
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
 * @details This orchestrates parsing `(args) -> ret` and wraps the result in an
 *          `INFIX_TYPE_REVERSE_TRAMPOLINE` type.
 * @param state The current parser state.
 * @return A pointer to a new, arena-allocated `infix_type` for the function, or `nullptr`.
 */
static infix_type * parse_function_type(parser_state * state) {
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args = 0, num_fixed = 0;

    // Delegate the heavy lifting of parsing the argument list, arrow, and return type.
    if (parse_function_signature_details(state, &ret_type, &args, &num_args, &num_fixed) != INFIX_SUCCESS)
        return nullptr;

    // If parsing was successful, allocate a new type descriptor to represent the function signature.
    infix_type * func_type = infix_arena_alloc(state->arena, sizeof(infix_type), _Alignof(infix_type));
    if (!func_type) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
        return nullptr;
    }

    // A function signature type itself has the size and alignment of a pointer.
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
 * @brief A generic helper for parsing aggregate type bodies (structs or unions).
 * @param state The current parser state.
 * @param start_char The opening delimiter ('{' for structs, '<' for unions).
 * @param end_char The closing delimiter ('}' for structs, '>' for unions).
 * @param name The optional name of the aggregate type.
 * @return A new arena-allocated `infix_type` for the aggregate, or `nullptr` on failure.
 */
static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char, const char * name) {
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
    // Dispatch to the correct creation function based on the delimiter.
    infix_status status = (start_char == '{') ? infix_type_create_struct(state->arena, &agg_type, members, num_members)
                                              : infix_type_create_union(state->arena, &agg_type, members, num_members);

    if (status != INFIX_SUCCESS) {
        _infix_set_error(INFIX_CATEGORY_GENERAL,
                         (status == INFIX_ERROR_ALLOCATION_FAILED) ? INFIX_CODE_OUT_OF_MEMORY : INFIX_CODE_UNKNOWN,
                         (size_t)(state->p - state->start));
        state->depth--;
        return nullptr;
    }

    // If a name was parsed, copy it into the arena and store it in the new type.
    if (name) {
        size_t name_len = strlen(name) + 1;
        char * arena_name = infix_arena_alloc(state->arena, name_len, 1);
        if (arena_name) {
            memcpy(arena_name, name, name_len);
            agg_type->meta.aggregate_info.name = arena_name;
        }
        else {  // If allocation fails, we can't store the name but the type is still valid.
                // TODO: This is a soft failure, but we should log it for debugging...
            ;
        }
    }


    state->depth--;
    return agg_type;
}

/**
 * @internal
 * @brief The main entry point for the recursive-descent parser.
 * @details This is the heart of the parser. It determines the kind of type to be
 *          parsed based on the current character and delegates to a specialized
 *          function. It also manages recursion depth and resolves the `(` ambiguity.
 * @param state The current parser state.
 * @return A new arena-allocated `infix_type` object, or `nullptr` on failure.
 */
static infix_type * parse_type(parser_state * state) {
    // Prevent stack overflow from deeply nested type definitions.
    if (state->depth >= MAX_RECURSION_DEPTH) {
        set_parser_error(state, INFIX_CODE_RECURSION_DEPTH_EXCEEDED);
        return nullptr;
    }
    state->depth++;

    skip_whitespace(state);
    infix_type * result_type = nullptr;
    const char * p_before_type = state->p;  // Save position for backtracking on error.

    // The dispatch logic begins here, checking one token at a time.
    if (*state->p == '*') {
        // POINTER TYPE: *<type>
        state->p++;  // Consume the '*'.
        skip_whitespace(state);
        // Recursively call parse_type to get the type the pointer points to.
        infix_type * pointee_type = parse_type(state);
        if (!pointee_type) {
            state->depth--;
            return nullptr;
        }  // Propagate failure.
        // Create the final pointer type.
        if (infix_type_create_pointer_to(state->arena, &result_type, pointee_type) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));
            result_type = nullptr;
        }
    }
    else if (*state->p == '(') {
        // GROUPED TYPE or FUNCTION TYPE
        // This is the ambiguous case. We must look ahead to see if it's a function.
        if (is_function_signature_ahead(state))
            result_type = parse_function_type(state);
        else {
            // It's a simple grouped type, e.g., *( (int)->void ).
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
        // ARRAY TYPE: [<size>:<type>]
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
        // Arrays of void are illegal in C.
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
        // PACKED STRUCT TYPE: !<align>?:{...}
        result_type = parse_packed_struct(state);
    else if (*state->p == '{')
        // ANONYMOUS STRUCT TYPE: {...}
        result_type = parse_aggregate(state, '{', '}', nullptr);
    else if (*state->p == '<')
        // ANONYMOUS UNION TYPE: <...>
        result_type = parse_aggregate(state, '<', '>', nullptr);
    else if (consume_keyword(state, "struct")) {
        // NAMED STRUCT or REFERENCE: struct<Name>{...} or struct<Name>
        if (*state->p != '<') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            set_parser_error(state, INFIX_CODE_EMPTY_MEMBER_NAME);
            state->depth--;
            return nullptr;
        }
        if (*state->p != '>') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        skip_whitespace(state);
        // If a body follows, it's a definition.
        if (*state->p == '{')
            result_type = parse_aggregate(state, '{', '}', name);
        else {
            // Otherwise, it's a forward declaration (a named reference).
            if (infix_type_create_named_reference(state->arena, &result_type, name, INFIX_AGGREGATE_STRUCT) !=
                INFIX_SUCCESS) {
                if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                    _infix_set_error(
                        INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));

                result_type = nullptr;
            }
        }
    }
    else if (consume_keyword(state, "union")) {
        // NAMED UNION or REFERENCE: union<Name><...> or union<Name>
        if (*state->p != '<') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            set_parser_error(state, INFIX_CODE_EMPTY_MEMBER_NAME);
            state->depth--;
            return nullptr;
        }
        if (*state->p != '>') {
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        state->p++;
        skip_whitespace(state);
        // If a body follows, it's a definition.
        if (*state->p == '<')
            result_type = parse_aggregate(state, '<', '>', name);
        else {
            // Otherwise, it's a forward declaration (a named reference).
            if (infix_type_create_named_reference(state->arena, &result_type, name, INFIX_AGGREGATE_UNION) !=
                INFIX_SUCCESS) {
                if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                    _infix_set_error(
                        INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));

                result_type = nullptr;
            }
        }
    }
    else if (*state->p == 'e') {
        // ENUM TYPE: e<Name>?:<type>
        state->p++;
        skip_whitespace(state);
        const char * name = nullptr;
        // Check for optional name, e.g., e<MyEnum>:.
        if (*state->p == '<') {
            state->p++;
            name = parse_identifier(state);
            if (!name) {
                set_parser_error(state, INFIX_CODE_EMPTY_MEMBER_NAME);
                state->depth--;
                return nullptr;
            }
            if (*state->p != '>') {
                set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
                state->depth--;
                return nullptr;
            }
            state->p++;
            skip_whitespace(state);
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
            set_parser_error(state, INFIX_CODE_UNEXPECTED_TOKEN);
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_enum(state->arena, &result_type, underlying_type) != INFIX_SUCCESS) {
            if (infix_get_last_error().code == INFIX_CODE_SUCCESS)
                _infix_set_error(
                    INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, (size_t)(state->p - state->start));

            result_type = nullptr;
        }
        (void)name;
    }
    else if (*state->p == 'c' && state->p[1] == '[') {
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
        // If none of the above constructors match, it must be a primitive type.
        result_type = parse_primitive(state);
        if (!result_type) {
            // If even that fails, this is an unrecognized token. Backtrack and report error.
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

/**
 * @internal
 * @brief Parses the complete `(fixed...; variadic...) -> ret` structure.
 * @details This is the internal workhorse for the public signature parsing APIs.
 *          It uses the same two-phase (linked-list -> array) strategy as
 *          `parse_aggregate_members` to efficiently handle an unknown number of arguments.
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

    typedef struct arg_node {
        infix_function_argument arg;
        struct arg_node * next;
    } arg_node;
    arg_node *head = nullptr, *tail = nullptr;
    size_t num_args = 0;

    // Phase 1: Parse Fixed Arguments
    if (*state->p != ')') {
        while (1) {
            skip_whitespace(state);
            // The list of fixed arguments can be terminated by a ')' or a ';'.
            if (*state->p == ')' || *state->p == ';')
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
            num_args++;

            skip_whitespace(state);
            if (*state->p == ',') {
                state->p++;
                skip_whitespace(state);
                // A comma must be followed by another type, not the end of the list.
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
                break;  // End of the fixed argument list.
        }
    }
    *out_num_fixed_args = num_args;

    // Phase 2: Parse Variadic Arguments (if any)
    if (*state->p == ';') {
        state->p++;
        if (*state->p != ')') {  // Check for arguments after the separator.
            while (1) {
                skip_whitespace(state);
                if (*state->p == ')')
                    break;  // End of variadic list.

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
                num_args++;

                skip_whitespace(state);
                if (*state->p == ',') {
                    state->p++;
                    skip_whitespace(state);
                    // A comma must be followed by another type, not the end of the list.
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

    // Convert the linked list into a final, contiguous array.
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

/*
 * Implementation for infix_type_from_signature.
 * This sets up a dedicated arena and parser state, invokes the core `parse_type`
 * function, and ensures the entire signature string was consumed.
 */
c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature) {
    _infix_clear_error();

    if (!out_type || !out_arena || !signature || *signature == '\0') {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    // Each parse operation creates its own arena for the resulting type graph.
    *out_arena = infix_arena_create(4096);
    if (!*out_arena) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // Initialize the parser state.
    parser_state state = {.p = signature, .start = signature, .arena = *out_arena, .depth = 0};
    infix_type * type = parse_type(&state);

    if (type) {
        skip_whitespace(&state);
        // A successful parse of a single type should consume the entire string.
        // If there are trailing characters, the signature is considered invalid.
        if (state.p[0] != '\0') {
            set_parser_error(&state, INFIX_CODE_UNEXPECTED_TOKEN);
            type = nullptr;
        }
    }

    // On any failure, we must destroy the arena to prevent memory leaks.
    if (!type) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    *out_type = type;
    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_signature_parse.
 * Sets up a dedicated arena and parser state, then delegates to the internal
 * implementation that handles the full function signature grammar.
 */
c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_function_argument ** out_args,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args) {
    _infix_clear_error();

    if (!signature || !out_arena || !out_ret_type || !out_args || !out_num_args || !out_num_fixed_args) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    // Create a new arena for this specific parsing operation.
    *out_arena = infix_arena_create(8192);  // 8KB default for potentially complex signatures.
    if (!*out_arena) {
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    parser_state state = {.p = signature, .start = signature, .arena = *out_arena, .depth = 0};

    // Delegate to the internal implementation.
    infix_status status =
        parse_function_signature_details(&state, out_ret_type, out_args, out_num_args, out_num_fixed_args);

    if (status == INFIX_SUCCESS) {
        skip_whitespace(&state);
        // Ensure the entire string was consumed.
        if (state.p[0] != '\0') {
            set_parser_error(&state, INFIX_CODE_UNEXPECTED_TOKEN);
            status = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    // Clean up the arena on any failure.
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    return INFIX_SUCCESS;
}

/*
 * Implementation for infix_forward_create_unbound.
 * This is the high-level API for creating unbound trampolines.
 */
c23_nodiscard infix_status infix_forward_create_unbound(infix_forward_t ** out_trampoline, const char * signature) {
    return infix_forward_create(out_trampoline, signature, nullptr);
}

/**
 * @brief Generates a "bound" forward-call trampoline from a signature string.
 * @details Creates a trampoline where the target function address is hardcoded into
 * the JIT-compiled code.
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param signature A null-terminated string describing the function signature.
 * @param target_function The native C function pointer to bind to the trampoline.
 * @return `INFIX_SUCCESS` on success.
 * @note The returned trampoline must be freed with `infix_forward_destroy`.
 */
c23_nodiscard infix_status infix_forward_create(infix_forward_t ** out_trampoline,
                                                const char * signature,
                                                void * target_function) {
    _infix_clear_error();
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args = 0, num_fixed = 0;  // Initialize to zero

    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;

    infix_type ** arg_types =
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : nullptr;
    if (num_args > 0 && !arg_types) {
        infix_arena_destroy(arena);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    for (size_t i = 0; i < num_args; ++i)
        arg_types[i] = args[i].type;

    status = _infix_forward_create_internal(
        out_trampoline, ret_type, arg_types, num_args, num_fixed, arena, target_function);

    infix_arena_destroy(arena);
    return status;
}

/*
 * Implementation for infix_reverse_create.
 * The high-level API for creating callbacks. Like its forward counterpart, it
 * handles the parsing, bridging, and cleanup automatically.
 */
c23_nodiscard infix_status infix_reverse_create(infix_reverse_t ** out_context,
                                                const char * signature,
                                                void * user_callback_fn,
                                                void * user_data) {
    _infix_clear_error();
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args = 0, num_fixed = 0;  // Initialize to zero

    // First, parse the signature string.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;

    // Bridge logic, same as in infix_forward_create.
    infix_type ** arg_types =
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : nullptr;
    if (num_args > 0 && !arg_types) {
        infix_arena_destroy(arena);
        _infix_set_error(INFIX_CATEGORY_ALLOCATION, INFIX_CODE_OUT_OF_MEMORY, 0);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    for (size_t i = 0; i < num_args; ++i)
        arg_types[i] = args[i].type;

    // Then, create the reverse trampoline from the parsed types.
    status =
        infix_reverse_create_manual(out_context, ret_type, arg_types, num_args, num_fixed, user_callback_fn, user_data);

    // Finally, clean up the temporary arena.
    infix_arena_destroy(arena);
    return status;
}

/**
 * @internal
 * @brief Holds the state for a print operation, managing the output buffer.
 */
typedef struct {
    char * p;
    size_t remaining;
    infix_status status;
} printer_state;

/**
 * @internal
 * @brief Safely appends formatted text to the output buffer.
 */
static void _print(printer_state * state, const char * fmt, ...) {
    if (state->status != INFIX_SUCCESS)
        return;
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(state->p, state->remaining, fmt, args);
    va_end(args);

    if (written < 0 || (size_t)written >= state->remaining)
        state->status = INFIX_ERROR_INVALID_ARGUMENT;  // Indicates buffer was too small
    else {
        state->p += written;
        state->remaining -= written;
    }
}

// Forward declaration for recursion
static void _infix_type_print_signature_recursive(printer_state *, const infix_type *);

/**
 * @internal
 * @brief The recursive worker for printing a type graph in Infix Signature format.
 */
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
    case INFIX_TYPE_POINTER:
        _print(state, "*");
        // For a generic void*, the pointee can be itself. Avoid infinite recursion.
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
            _print(state, "struct<%s>", type->meta.aggregate_info.name);
        _print(state, "{");
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (i > 0)
                _print(state, ",");
            _infix_type_print_signature_recursive(state, type->meta.aggregate_info.members[i].type);
        }
        _print(state, "}");
        break;
    case INFIX_TYPE_UNION:
        if (type->meta.aggregate_info.name)
            _print(state, "union<%s>", type->meta.aggregate_info.name);
        _print(state, "<");
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (i > 0)
                _print(state, ",");
            _infix_type_print_signature_recursive(state, type->meta.aggregate_info.members[i].type);
        }
        _print(state, ">");
        break;
    case INFIX_TYPE_REVERSE_TRAMPOLINE:
        _print(state, "(");
        // Print fixed arguments, separated by commas.
        for (size_t i = 0; i < type->meta.func_ptr_info.num_fixed_args; ++i) {
            if (i > 0)
                _print(state, ",");
            _infix_type_print_signature_recursive(state, type->meta.func_ptr_info.args[i].type);
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
                _infix_type_print_signature_recursive(state, type->meta.func_ptr_info.args[i].type);
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
    case INFIX_TYPE_NAMED_REFERENCE:
        if (type->meta.named_reference.aggregate_category == INFIX_AGGREGATE_UNION)
            _print(state, "union<%s>", type->meta.named_reference.name);
        else
            _print(state, "struct<%s>", type->meta.named_reference.name);
        break;
    case INFIX_TYPE_PRIMITIVE:
        switch (type->meta.primitive_id) {
        case INFIX_PRIMITIVE_BOOL:
            _print(state, "bool");
            break;
        case INFIX_PRIMITIVE_SINT8:
            _print(state, "char");
            break;
        case INFIX_PRIMITIVE_UINT8:
            _print(state, "uchar");
            break;
        case INFIX_PRIMITIVE_SINT16:
            _print(state, "short");
            break;
        case INFIX_PRIMITIVE_UINT16:
            _print(state, "ushort");
            break;
        case INFIX_PRIMITIVE_SINT32:
            _print(state, "int");
            break;
        case INFIX_PRIMITIVE_UINT32:
            _print(state, "uint");
            break;
        case INFIX_PRIMITIVE_SINT64:
            _print(state, "longlong");
            break;
        case INFIX_PRIMITIVE_UINT64:
            _print(state, "ulonglong");
            break;
        case INFIX_PRIMITIVE_FLOAT:
            _print(state, "float");
            break;
        case INFIX_PRIMITIVE_DOUBLE:
            _print(state, "double");
            break;
        case INFIX_PRIMITIVE_LONG_DOUBLE:
            _print(state, "long double");
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
 * Public API implementation for infix_type_print
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

    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';  // Null-terminate the string
        else {
            // Buffer was too small, but vsnprintf might not have returned an error.
            // Ensure the last character is null to prevent overflow.
            buffer[buffer_size - 1] = '\0';
            _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;  // Indicate buffer was too small
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
    if (!buffer || buffer_size == 0 || !ret_type || (num_args > 0 && !args)) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};
    *buffer = '\0';

    (void)function_name;  // Will be used for mangling dialects.

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
