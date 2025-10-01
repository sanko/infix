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
 * @details This file contains a complete, self-contained recursive-descent parser
 *          for the FFI Signature Format Specification v1.0. Its primary
 *          responsibility is to transform a human-readable signature string into a
 *          graph of `infix_type` objects that describe the data contract of a C
 *          function or data type.
 *
 *          Key architectural principles:
 *          - **Recursive Descent:** The parser is structured as a set of functions,
 *            each responsible for parsing a specific part of the grammar (e.g., a
 *            pointer, an array, a struct). This makes the code easy to map to the
 *            formal EBNF grammar.
 *          - **Arena-Based Allocation:** All `infix_type` objects and associated
 *            metadata are allocated from a single memory arena. This provides
 *            excellent performance and simplifies memory management, as the entire
 *            type graph can be freed with a single call to `infix_arena_destroy`.
 *          - **Statelessness:** The parser itself is stateless. All necessary context
 *            (the current position in the string, the memory arena, recursion depth)
 *            is passed around in a `parser_state` struct.
 *          - **Error Handling:** Parsing failures are signaled by returning `nullptr`.
 *            The `parser_state` struct contains a `last_error` field to provide a
 *            more specific reason for the failure.
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @def MAX_RECURSION_DEPTH
 * @brief (Internal) A security limit on the nesting depth of type definitions.
 * @details This constant prevents the recursive-descent parser from causing a
 *          stack overflow when parsing maliciously crafted input with excessive
 *          nesting, such as `[[[[...[int]...]]]]`.
 */
#define MAX_RECURSION_DEPTH 32

/**
 * @struct parser_state
 * @brief (Internal) Holds the complete state of the parser during a run.
 * @details This struct is passed by pointer to all parsing functions, allowing
 *          them to advance through the input string and allocate memory without
 *          relying on global variables. This design makes the parser re-entrant
 *          and thread-safe.
 */
typedef struct {
    const char * p;          /**< The current position (pointer) in the input string. */
    infix_arena_t * arena;   /**< The arena from which all type objects are allocated. */
    int depth;               /**< The current recursion depth, checked against `MAX_RECURSION_DEPTH`. */
    infix_status last_error; /**< Stores the reason for the most recent parsing failure. */
} parser_state;

/** @brief The main recursive function for parsing any single value type. */
static infix_type * parse_type(parser_state *);
/** @brief Parses the components of a full function signature: `(fixed...; variadic...) -> ret`. */
static infix_status parse_function_signature_details(
    parser_state *, infix_type **, infix_function_argument **, size_t *, size_t *);
/** @brief A helper for parsing the body of an aggregate type (struct or union). */
static infix_type * parse_aggregate(parser_state *, char, char, const char *);
/** @brief Parses a SIMD vector type from a signature string: `v[<N>:<type>]`. */
static infix_type * parse_vector_type(parser_state *);

/**
 * @internal
 * @brief Skips over any insignificant whitespace and comments in the input string.
 * @details This function is called at the beginning of most parsing functions to
 *          ensure that the parser is insensitive to formatting. It consumes
 *          spaces, tabs, and newlines. It also handles comments, which start
 *          with a hash symbol (`#`) and continue to the end of the line, as
 *          specified in the v1.0 grammar.
 * @param state The current state of the parser. The `p` pointer is advanced past
 *              any whitespace or comments.
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
 * @details This is a simple utility that wraps `strtoull` to parse a decimal
 *          number. It's used for parsing array sizes and pack alignments.
 * @param state The current parser state. `p` is advanced past the parsed number.
 * @param[out] out_val On success, this will contain the parsed integer value.
 * @return `true` on success, `false` if no valid number could be parsed.
 */
static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    // Use strtoull for battle tested parsing of 64-bit unsigned integers.
    unsigned long long val = strtoull(start, &end, 10);
    // If the end pointer hasn't moved, no digits were consumed.
    if (end == start) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return false;
    }
    *out_val = (size_t)val;
    state->p = end;  // Advance the parser's pointer.
    return true;
}

/**
 * @internal
 * @brief Parses a C-style identifier from the input string.
 * @details An identifier must start with a letter or underscore, and may be
 *          followed by letters, numbers, or underscores. The parsed identifier
 *          is allocated as a new, null-terminated string from the parser's arena.
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
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

/**
 * @internal
 * @brief Attempts to consume a specific keyword from the input string.
 * @details This function checks if the string at the current parser position
 *          matches the given keyword. For a match to be valid, the character
 *          immediately following the keyword must not be part of a larger
 *          identifier (i.e., it must be whitespace, a symbol, or null). This
 *          prevents "int32" from partially matching the keyword "int".
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
 * @brief Parses a primitive type keyword from the input string.
 * @details This function attempts to match and consume one of the keywords
 *          defined in the v1.0 specification for primitive types. The order of
 *          checks is important to prevent ambiguity. For example, `longlong` is
 *          checked before `long` to ensure the longest possible match is consumed.
 *          It handles both Tier 1 (e.g., `int`) and Tier 2 (e.g., `int32`) types.
 *
 * @param state The current parser state.
 * @return A pointer to the corresponding static `infix_type` for the primitive.
 *         Returns `nullptr` if no primitive keyword is found at the current position.
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
 * @brief Peeks ahead in the string to resolve a grammatical ambiguity.
 * @details The parser faces an ambiguity when it encounters an open parenthesis `(`.
 *          This could be the start of a grouped type like `*( (int) -> void )` or it
 *          could be the start of an argument list for a function type like
 *          `(int) -> void`.
 *
 *          This function resolves this by peeking ahead *without consuming input*. It
 *          scans for the matching `)` and checks if it is followed by the `->` arrow
 *          token. This lookahead allows `parse_type` to correctly decide whether to
 *          parse a grouped type or call the function-type parser.
 *
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
 * @brief Parses a function signature string and creates a function type descriptor.
 * @details This is a high-level helper that orchestrates the parsing of a full
 *          `(args) -> ret` signature. It delegates the complex parsing of the
 *          argument list and return type to `parse_function_signature_details` and
 *          then wraps the result in an `infix_type` struct.
 *
 *          The resulting type has the category `INFIX_TYPE_REVERSE_TRAMPOLINE`.
 *          From the parser's perspective, this is the canonical representation for a
 *          "function signature type", which can then be pointed to (to form a
 *          function pointer) or used as a standalone type.
 *
 * @param state The current parser state.
 * @return A pointer to a new, arena-allocated `infix_type` for the function,
 *         or `nullptr` on failure.
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
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
 * @brief Parses the member list of a struct or union.
 * @details This is a workhorse function that handles a comma-separated list of
 *          members, such as `{int, name:*char, double}`. It is responsible for
 *          parsing optional member names and their associated types.
 *
 *          Because the number of members is not known in advance, it uses a
 *          two-pass strategy for efficiency:
 *          1. It builds a temporary singly-linked list of `member_node`s on the arena.
 *          2. Once all members are parsed, it allocates a single, correctly-sized
 *             array from the arena and copies the member data into it.
 *          This avoids costly reallocations and results in a final, contiguous
 *          array of members.
 *
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
            skip_whitespace(state);
            const char * p_before_member = state->p;

            // Tentatively parse an identifier. This could be a member name.
            const char * name = parse_identifier(state);
            skip_whitespace(state);

            // A valid named member has the form "name : type". If we found an
            // identifier and it's followed by a colon, we treat it as a name.
            if (name && *state->p == ':') {
                state->p++;  // Consume the colon.
                skip_whitespace(state);
            }
            else {
                // If there's no colon, the identifier was actually the start of a
                // type keyword (e.g., "int"). We must backtrack the parser to the
                // position before we tried to parse it as a name.
                name = nullptr;
                state->p = p_before_member;
            }

            // A syntax error: `{name:}` with no type.
            if (name && (*state->p == end_char || *state->p == ',')) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return nullptr;
            }

            // Now, recursively parse the member's type.
            infix_type * member_type = parse_type(state);
            if (!member_type) {
                // Propagate the error from the recursive call.
                return nullptr;
            }
            // The C standard forbids members of type void.
            if (member_type->category == INFIX_TYPE_VOID) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return nullptr;
            }

            // Add the parsed member to our linked list.
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
                // A trailing comma like `{int,}` is a syntax error.
                if (*state->p == end_char) {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    return nullptr;
                }
            }
            else if (*state->p == end_char)
                break;  // End of the list.
            else {
                // Anything else is a syntax error.
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
 * @details This function handles the `!{...}` and `!N:{...}` syntax. It parses
 *          the optional alignment value `N`, then delegates the parsing of the
 *          struct body to `parse_aggregate_members`. Finally, it calls the
 *          appropriate type creation function to build the packed struct type.
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
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                return nullptr;
            }
            state->p++;
        }
    }

    skip_whitespace(state);
    if (*state->p != '{') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;

    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, '}', &num_members);
    if (state->last_error != INFIX_SUCCESS && num_members > 0)
        return nullptr;

    if (*state->p != '}') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
        state->last_error = status;
        return nullptr;
    }
    return packed_type;
}

/**
 * @internal
 * @brief The main entry point for the recursive-descent parser.
 * @details This is the heart of the parser. It determines the kind of type to be
 *          parsed based on the current character in the input stream and delegates
 *          to a more specialized function (e.g., `parse_aggregate`, `parse_primitive`).
 *          It handles all type constructors from the v1.0 specification, including
 *          pointers (`*`), arrays (`[]`), aggregates (`{}`, `<>`), enums (`e:`),
 *          and grouped types (`()`).
 *
 *          It also manages recursion depth to protect against stack overflow and
 *          is responsible for the crucial lookahead check via
 *          `is_function_signature_ahead` to resolve the ambiguity of the `(` token.
 *
 * @param state The current parser state.
 * @return A new arena-allocated `infix_type` object representing the parsed type,
 *         or `nullptr` on failure.
 */
static infix_type * parse_type(parser_state * state) {
    // Security: Prevent stack overflow from deeply nested type definitions.
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                result_type = nullptr;
            }
            else {
                state->p++;  // Consume ')'.
            }
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
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
        if (*state->p != ']') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        state->p++;
        if (infix_type_create_array(state->arena, &result_type, element_type, num_elements) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        if (*state->p != '>') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
            infix_status status = infix_type_create_named_reference(state->arena, &result_type, name);
            if (status != INFIX_SUCCESS) {
                state->last_error = status;
                result_type = nullptr;
            }
        }
    }
    else if (consume_keyword(state, "union")) {
        // NAMED UNION or REFERENCE: union<Name><...> or union<Name>
        if (*state->p != '<') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        state->p++;
        const char * name = parse_identifier(state);
        if (!name) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        if (*state->p != '>') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
            infix_status status = infix_type_create_named_reference(state->arena, &result_type, name);
            if (status != INFIX_SUCCESS) {
                state->last_error = status;
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
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
            if (*state->p != '>') {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
            state->p++;
            skip_whitespace(state);
        }
        if (*state->p != ':') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
        // The spec requires the underlying type to be an integer.
        if (underlying_type->category != INFIX_TYPE_PRIMITIVE) {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        if (infix_type_create_enum(state->arena, &result_type, underlying_type) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = nullptr;
        }
        (void)name;  // Name is stored for introspection but not used by the core ABI.
    }
    else if (*state->p == 'c' && state->p[1] == '[') {  // extra test to make sure we avoid eating `char`
        // COMPLEX TYPE: c[<type>]
        state->p++;
        skip_whitespace(state);
        if (*state->p != '[') {
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return NULL;
        }
        state->p++;
        skip_whitespace(state);
        infix_type * base_type = parse_type(state);
        if (!base_type) {
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
        if (infix_type_create_complex(state->arena, &result_type, base_type) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = NULL;
        }
    }
    else if (*state->p == 'v' && state->p[1] == '[') {
        // VECTOR TYPE: v[<N>:<type>]
        result_type = parse_vector_type(state);
    }
    else {
        // PRIMITIVE TYPE
        // If none of the above constructors match, it must be a primitive type.
        result_type = parse_primitive(state);
        if (!result_type) {
            // If even that fails, this is an unrecognized token. Backtrack and report error.
            state->p = p_before_type;
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    state->depth--;
    return result_type;
}

/**
 * @internal
 * @brief A generic helper function for parsing aggregate type bodies (structs or unions).
 * @details This function centralizes the logic for parsing the body of a struct
 *          (`{...}`) or a union (`<...>`). It consumes the start character, delegates
 *          the complex task of parsing the member list to `parse_aggregate_members`,
 *          consumes the end character, and then calls the appropriate `infix_type_create`
 *          function to construct the final `infix_type` object with the correct
 *          size and alignment.
 *
 * @param state The current parser state.
 * @param start_char The opening delimiter ('{' for structs, '<' for unions).
 * @param end_char The closing delimiter ('}' for structs, '>' for unions).
 * @param name The optional name of the aggregate type (can be nullptr for anonymous ones).
 * @return A new arena-allocated `infix_type` for the aggregate, or `nullptr` on failure.
 */
static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char, const char * name) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    if (*state->p != start_char) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    state->p++;

    size_t num_members = 0;
    infix_struct_member * members = parse_aggregate_members(state, end_char, &num_members);
    if (state->last_error != INFIX_SUCCESS) {
        state->depth--;
        return nullptr;
    }

    if (*state->p != end_char) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    state->p++;

    infix_type * agg_type = nullptr;
    // Dispatch to the correct creation function based on the delimiter.
    infix_status status = (start_char == '{') ? infix_type_create_struct(state->arena, &agg_type, members, num_members)
                                              : infix_type_create_union(state->arena, &agg_type, members, num_members);

    if (status != INFIX_SUCCESS) {
        state->last_error = status;
        state->depth--;
        return nullptr;
    }
    (void)name;  // Name is stored for introspection.

    state->depth--;
    return agg_type;
}

/**
 * @internal
 * @brief Parses a SIMD vector type from the input string.
 * @details This function handles the `v[<N>:<type>]` syntax. It parses the
 *          number of elements `N` and the primitive element `<type>`, then calls
 *          `infix_type_create_vector` to construct the final type object.
 *
 * @param state The current parser state.
 * @return A new arena-allocated `infix_type` for the vector, or `nullptr` on a parsing or allocation error.
 */
static infix_type * parse_vector_type(parser_state * state) {
    state->p++;  // Consume 'v'
    skip_whitespace(state);

    if (*state->p != '[') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;  // Consume '['
    skip_whitespace(state);

    size_t num_elements;
    if (!parse_size_t(state, &num_elements)) {
        return nullptr;
    }
    skip_whitespace(state);

    if (*state->p != ':') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;  // Consume ':'
    skip_whitespace(state);

    infix_type * element_type = parse_type(state);
    if (!element_type) {
        return nullptr;
    }
    if (element_type->category != INFIX_TYPE_PRIMITIVE) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }

    skip_whitespace(state);
    if (*state->p != ']') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;  // Consume ']'

    infix_type * vector_type = nullptr;
    if (infix_type_create_vector(state->arena, &vector_type, element_type, num_elements) != INFIX_SUCCESS) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    return vector_type;
}

/**
 * @internal
 * @brief Parses the complete structure of a function signature string.
 * @details This is the internal workhorse for `infix_signature_parse`. It handles
 *          the entire `(fixed...; variadic...) -> ret` structure. It uses a
 *          two-phase approach: first parsing all comma-separated fixed arguments,
 *          then, if a semicolon is found, parsing all comma-separated variadic
 *          arguments. It also enforces stricter grammar rules, such as forbidding
 *          trailing commas.
 *
 * @param state The current parser state.
 * @param[out] out_ret_type A pointer to the parsed return `infix_type`.
 * @param[out] out_args A pointer to an array of parsed function arguments.
 * @param[out] out_num_args The total number of arguments parsed.
 * @param[out] out_num_fixed_args The number of non-variadic arguments.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
static infix_status parse_function_signature_details(parser_state * state,
                                                     infix_type ** out_ret_type,
                                                     infix_function_argument ** out_args,
                                                     size_t * out_num_args,
                                                     size_t * out_num_fixed_args) {
    if (*state->p != '(')
        return INFIX_ERROR_INVALID_ARGUMENT;
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

            const char * p_before_arg = state->p;
            const char * name = parse_identifier(state);
            skip_whitespace(state);
            if (name && *state->p == ':')
                state->p++;
            else {
                name = nullptr;
                state->p = p_before_arg;
            }

            infix_type * arg_type = parse_type(state);
            if (!arg_type)
                return state->last_error;

            arg_node * node = infix_arena_alloc(state->arena, sizeof(arg_node), _Alignof(arg_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    return INFIX_ERROR_INVALID_ARGUMENT;
                }
            }
            else if (*state->p != ')' && *state->p != ';')
                return INFIX_ERROR_INVALID_ARGUMENT;
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

                const char * p_before_arg = state->p;
                const char * name = parse_identifier(state);
                skip_whitespace(state);
                if (name && *state->p == ':')
                    state->p++;
                else {
                    name = nullptr;
                    state->p = p_before_arg;
                }

                infix_type * arg_type = parse_type(state);
                if (!arg_type)
                    return state->last_error;

                arg_node * node = infix_arena_alloc(state->arena, sizeof(arg_node), _Alignof(arg_node));
                if (!node) {
                    state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
                        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                        return INFIX_ERROR_INVALID_ARGUMENT;
                    }
                }
                else if (*state->p != ')')
                    return INFIX_ERROR_INVALID_ARGUMENT;
                else
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

    // Convert the linked list into a final, contiguous array.
    infix_function_argument * args = num_args > 0
        ? infix_arena_alloc(state->arena, sizeof(infix_function_argument) * num_args, _Alignof(infix_function_argument))
        : nullptr;
    if (num_args > 0 && !args) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
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
 * @brief Parses a signature string representing a single data type.
 * @details This is a specialized version of the v1.0 parser for use cases like data
 *          marshalling, serialization, or dynamic type inspection, where you need
 *          to describe a single data type rather than a full function signature.
 *          It creates a dedicated arena to hold the resulting `infix_type` object
 *          graph for the specified type.
 *
 * @param[out] out_type On success, will point to the newly created `infix_type`. This
 *                      pointer is valid for the lifetime of the returned arena.
 * @param[out] out_arena On success, will point to the new arena that owns the type
 *                       object graph. The caller is responsible for destroying this
 *                       arena with `infix_arena_destroy()`.
 * @param[in]  signature A string describing the data type (e.g., `"int32"`, `"*void"`, `"{int, float}"`).
 *
 * @return Returns `INFIX_SUCCESS` if parsing is successful.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any parameters are null or the
 *         signature string is malformed or contains trailing characters.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if the internal arena could not be created.
 *
 * @note **Memory Management:** On success, the caller takes ownership of the arena
 *       returned in `*out_arena` and is responsible for its destruction.
 */
c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature) {
    if (!out_type || !out_arena || !signature || *signature == '\0')
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Each parse operation creates its own arena for the resulting type graph.
    *out_arena = infix_arena_create(4096);
    if (!*out_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    // Initialize the parser state.
    parser_state state = {.p = signature, .arena = *out_arena, .depth = 0, .last_error = INFIX_SUCCESS};
    infix_type * type = parse_type(&state);

    if (type) {
        skip_whitespace(&state);
        // A successful parse of a single type should consume the entire string.
        // If there are trailing characters, the signature is considered invalid.
        if (state.p[0] != '\0') {
            type = nullptr;
            state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    // On any failure, we must destroy the arena to prevent memory leaks.
    if (!type) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        return state.last_error != INFIX_SUCCESS ? state.last_error : INFIX_ERROR_INVALID_ARGUMENT;
    }

    *out_type = type;
    return INFIX_SUCCESS;
}

/**
 * @brief Parses a full function signature string into its constituent infix_type parts.
 * @details This function provides direct access to the v1.0 signature parser. It creates a
 *          dedicated memory arena to hold the resulting `infix_type` object graph for the
 *          entire function signature.
 *
 * @param[in]  signature A null-terminated string describing the function signature.
 * @param[out] out_arena On success, will be populated with a pointer to the new arena.
 * @param[out] out_ret_type On success, will point to the `infix_type` for the return value.
 * @param[out] out_args On success, will point to an array of `infix_function_argument`.
 * @param[out] out_num_args On success, will be set to the total number of arguments (including `...`).
 * @param[out] out_num_fixed_args On success, will be set to the number of non-variadic arguments.
 * @return Returns `INFIX_SUCCESS` if parsing is successful.
 */
c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_function_argument ** out_args,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args) {
    if (!signature || !out_arena || !out_ret_type || !out_args || !out_num_args || !out_num_fixed_args)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Create a new arena for this specific parsing operation.
    *out_arena = infix_arena_create(8192);  // 8KB default for potentially complex signatures.
    if (!*out_arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    parser_state state = {.p = signature, .arena = *out_arena, .depth = 0, .last_error = INFIX_SUCCESS};

    // Delegate to the internal implementation.
    infix_status status =
        parse_function_signature_details(&state, out_ret_type, out_args, out_num_args, out_num_fixed_args);

    if (status == INFIX_SUCCESS) {
        skip_whitespace(&state);
        // Ensure the entire string was consumed.
        if (state.p[0] != '\0')
            status = INFIX_ERROR_INVALID_ARGUMENT;
    }

    // Clean up the arena on any failure.
    if (status != INFIX_SUCCESS) {
        infix_arena_destroy(*out_arena);
        *out_arena = nullptr;
        return state.last_error != INFIX_SUCCESS ? state.last_error : status;
    }

    return INFIX_SUCCESS;
}

/**
 * @brief Generates a forward-call trampoline from a signature string.
 *
 * This is the primary function of the high-level API. It parses a v1.0 signature
 * string, constructs the necessary `infix_type` objects internally, generates the
 * trampoline, and cleans up all intermediate type descriptions. The resulting
 * trampoline is self-contained and ready for use.
 *
 * @param[out] out_trampoline On success, will point to the handle for the new trampoline.
 * @param signature A null-terminated string describing the function signature.
 * @return `INFIX_SUCCESS` on success.
 * @note The returned trampoline must be freed with `infix_forward_destroy`.
 */
c23_nodiscard infix_status infix_forward_create(infix_forward_t ** out_trampoline, const char * signature) {
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args, num_fixed;

    // First, parse the signature string into a type graph.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;

    // Bridge: The manual API expects an array of `infix_type*`. We must extract
    // the type pointers from our parsed arguments to build this temporary array.
    infix_type ** arg_types =
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : NULL;
    if (num_args > 0 && !arg_types) {
        infix_arena_destroy(arena);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    for (size_t i = 0; i < num_args; ++i)
        arg_types[i] = args[i].type;

    // Then, pass the resulting types to the manual creation function.
    status = infix_forward_create_manual(out_trampoline, ret_type, arg_types, num_args, num_fixed);

    // Finally, destroy the temporary arena used for parsing.
    infix_arena_destroy(arena);
    return status;
}

/**
 * @brief Generates a reverse-call trampoline (callback) from a signature string.
 *
 * This function parses a v1.0 signature string to create a native, C-callable function
 * pointer that invokes the provided user handler.
 *
 * @param[out] out_context On success, will point to the new reverse trampoline context.
 * @param signature A null-terminated string describing the callback's signature.
 * @param user_callback_fn A function pointer to the user's C callback handler.
 * @param user_data A user-defined pointer for passing state to the handler.
 * @return `INFIX_SUCCESS` on success.
 * @note The returned context must be freed with `infix_reverse_destroy`.
 */
c23_nodiscard infix_status infix_reverse_create(infix_reverse_t ** out_context,
                                                const char * signature,
                                                void * user_callback_fn,
                                                void * user_data) {
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
    infix_function_argument * args = nullptr;
    size_t num_args, num_fixed;

    // First, parse the signature string.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;

    // Bridge logic, same as in infix_forward_create.
    infix_type ** arg_types =
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : NULL;
    if (num_args > 0 && !arg_types) {
        infix_arena_destroy(arena);
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
