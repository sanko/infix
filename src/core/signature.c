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
<<<<<<< HEAD
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
=======
 * @brief Implements the high-level signature string parser.
 *
 * @details
 * Honestly, this is probably the most complex code in the entire project... it must parse
 * human generated strings.
 *
 * This file contains the "complete" implementation of the signature string parser, which is the
 * engine behind the library's high-level API. Its primary responsibility is to translate
 * a human-readable string representation of a C type or function signature into a graph
 * of `infix_type` objects that the core FFI generation logic can understand.
 *
 * # Parser Design and Strategy
 *
 * The parser is implemented using a **recursive-descent** model. The main entry point for
 * parsing a single, self-contained type is the `parse_type` function. This function can
 * recursively call itself to handle arbitrarily complex nested constructs, such as an array
 * of structs that contains a pointer to another array.
 *
 * For full function signatures (e.g., `"i,d=>v"`), the top-level `infix_signature_parse`
 * function orchestrates the process:
 * 1.  It first performs a nest-aware scan to locate the top-level return separator (`=>`).
 * 2.  It splits the string into an "arguments part" and a "return part".
 * 3.  It calls `parse_type` to parse the return part.
 * 4.  It tokenizes the arguments part, splitting by `,` and `;` while respecting nested
 *     brackets, and then calls `parse_type` on each resulting argument token.
 *
 * ## Key Features and Syntax Handled
 *
 * - **Full Type System**: Supports all fundamental type categories: primitives (`i`, `d`),
 *   pointers (`*`), arrays (`[10]`), structs (`{}`), and unions (`<>`).
 * - **Nested Types**: Correctly parses complex nested declarations like `[10]{i, [5]c*}`.
 * - **Packed Structs**: Provides a special syntax `p(size,align){...}` for describing
 *   structs with non-standard, compiler-specific layouts, where each member must have
 *   an explicit byte offset (e.g., `{c@0, i@1}`).
 * - **Function Pointers**: Recognizes function pointer syntax like `(i,d=>v)` within a
 *   type definition and correctly treats it as a simple pointer for ABI purposes.
 * - **Named Members**: Supports optional member names in aggregates, e.g., `{id:i, name:c*}`.
 * - **Variadic Functions**: Understands the variadic separator (`;`) to distinguish fixed
 *   arguments from variable arguments.
 *
 * ## Memory Management
 *
 * A critical design principle of this parser is its use of an **arena allocator** (`infix_arena_t`).
 * **All `infix_type` objects and associated data (like member names) created during a parsing
 * operation are allocated from a single, temporary arena.** This has two major benefits:
 * 1.  **Performance**: It avoids the overhead of numerous small `malloc` calls.
 * 2.  **Simplicity**: It dramatically simplifies memory cleanup. The entire complex graph of
 *     `infix_type` objects can be freed with a single call to `infix_arena_destroy`.
 *
 * The public API functions reflect this: `infix_signature_parse` transfers ownership of the
 * arena to the caller, while the higher-level `infix_forward_create` and `infix_reverse_create` functions
 * manage the arena internally, destroying it automatically before returning.
 *
 * ## Security Considerations
 *
 * To mitigate the risk of a denial-of-service attack via stack overflow, the recursive
 * parser enforces a hard-coded recursion depth limit (`MAX_RECURSION_DEPTH`). Any signature
 * with nesting deeper than this limit will be rejected as invalid.
>>>>>>> main
 */

#include "common/infix_internals.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @def MAX_RECURSION_DEPTH
<<<<<<< HEAD
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
=======
 * @brief A security limit on the nesting depth of type definitions.
 * @details This prevents a deeply nested signature (e.g., `{{{{...}}}}`) from
 *          causing a stack overflow in the recursive parser, which could be a
 *          denial-of-service vector.
 */
#define MAX_RECURSION_DEPTH 32

/**
 * @internal
 * @struct parser_state
 * @brief Holds the current state of the parser as it consumes the signature string.
 * @details This struct is passed by reference through the parsing functions, allowing
 *          them to advance the input pointer and report errors in a centralized way.
 */
typedef struct {
    const char * p;           ///< A pointer to the current position in the signature string.
    infix_arena_t * arena;    ///< The memory arena for allocating `infix_type` objects.
    int depth;                ///< The current recursion depth, checked against `MAX_RECURSION_DEPTH`.
    infix_status last_error;  ///< A sticky error flag to propagate failures up the call stack.
} parser_state;

// Forward declarations for the recursive parsing functions.
static infix_type * parse_type(parser_state * state);
static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char);
static infix_type * parse_packed_struct(parser_state * state);
static infix_type * parse_function_pointer(parser_state * state);

/**
 * @internal
 * @brief Advances the parser's pointer past any leading whitespace characters.
 * @param state The current state of the parser.
 */
static void skip_whitespace(parser_state * state) {
    while (isspace((unsigned char)*state->p))
        state->p++;
>>>>>>> main
}

/**
 * @internal
<<<<<<< HEAD
 * @brief Parses an optional name and colon prefix for a member/argument.
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
=======
 * @brief Parses an unsigned integer (`size_t`) from the current parser position.
 * @details Uses `strtoull` for parsing numbers. Sets the parser's error state
 *          if no digits are found.
 * @param state The current state of the parser.
 * @param[out] out_val On success, this will contain the parsed numeric value.
 * @return `true` on success, `false` on parsing failure.
 */
static bool parse_size_t(parser_state * state, size_t * out_val) {
    const char * start = state->p;
    char * end;
    unsigned long long val = strtoull(start, &end, 10);
    if (end == start) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
>>>>>>> main
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
<<<<<<< HEAD
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
=======
    *out_val = (size_t)val;
    state->p = end;
    return true;
}

/**
 * @internal
 * @brief Parses a C-style identifier (e.g., for a struct member name).
 * @details An identifier must start with a letter or underscore, and can be
 *          followed by letters, numbers, or underscores. The parsed name is
 *          allocated from the arena.
 * @param state The current state of the parser.
 * @return A pointer to the null-terminated identifier string, or `nullptr` if
 *         no valid identifier was found.
 */
static const char * parse_identifier(parser_state * state) {
    skip_whitespace(state);
    const char * start = state->p;
    if (!isalpha((unsigned char)*start) && *start != '_')
        return nullptr;
    while (isalnum((unsigned char)*state->p) || *state->p == '_')
        state->p++;
    size_t len = state->p - start;
    if (len == 0)
        return nullptr;

    char * name = infix_arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    infix_memcpy(name, start, len);
    name[len] = '\0';
    return name;
>>>>>>> main
}

/**
 * @internal
<<<<<<< HEAD
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
=======
 * @brief Parses a single-character primitive type specifier.
 * @details Maps a character like 'i' or 'd' to its corresponding static,
 *          singleton `infix_type` object.
 * @param state The current state of the parser.
 * @return A pointer to the static `infix_type` for the primitive, or `nullptr` if
 *         the character is not a valid primitive specifier.
 */
static infix_type * parse_primitive(parser_state * state) {
    if (*state->p == INFIX_SIG_VOID) {
        state->p++;
        return infix_type_create_void();
    }
    infix_primitive_type_id id;
    switch (*state->p) {
    case INFIX_SIG_BOOL:
        id = INFIX_PRIMITIVE_BOOL;
        break;
    case INFIX_SIG_SINT8:
        id = INFIX_PRIMITIVE_SINT8;
        break;
    case INFIX_SIG_UINT8:
    case INFIX_SIG_CHAR:
        id = INFIX_PRIMITIVE_UINT8;
        break;
    case INFIX_SIG_SINT16:
        id = INFIX_PRIMITIVE_SINT16;
        break;
    case INFIX_SIG_UINT16:
        id = INFIX_PRIMITIVE_UINT16;
        break;
    case INFIX_SIG_SINT32:
        id = INFIX_PRIMITIVE_SINT32;
        break;
    case INFIX_SIG_UINT32:
        id = INFIX_PRIMITIVE_UINT32;
        break;
    case INFIX_SIG_SINT64:
    case INFIX_SIG_LONG:
        id = INFIX_PRIMITIVE_SINT64;
        break;
    case INFIX_SIG_UINT64:
    case INFIX_SIG_ULONG:
        id = INFIX_PRIMITIVE_UINT64;
        break;
    case INFIX_SIG_SINT128:
        id = INFIX_PRIMITIVE_SINT128;
        break;
    case INFIX_SIG_UINT128:
        id = INFIX_PRIMITIVE_UINT128;
        break;
    case INFIX_SIG_FLOAT:
        id = INFIX_PRIMITIVE_FLOAT;
        break;
    case INFIX_SIG_DOUBLE:
        id = INFIX_PRIMITIVE_DOUBLE;
        break;
    case INFIX_SIG_LONG_DOUBLE:
        id = INFIX_PRIMITIVE_LONG_DOUBLE;
        break;
    default:
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;
    return infix_type_create_primitive(id);
>>>>>>> main
}

/**
 * @internal
<<<<<<< HEAD
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
            const char * name = parse_optional_name_prefix(state);
            infix_type * member_type = parse_type(state);

            if (!member_type) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
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
                skip_whitespace(state);
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
=======
 * @brief Parses a function pointer signature: `(...) => ...`
 *
 * @details This function is called by `parse_type` when it detects a function pointer.
 * It extracts the inner signature string, recursively calls `infix_signature_parse` on it,
 * and then constructs an `infix_type` of category `INFIX_TYPE_REVERSE_TRAMPOLINE` with the
 * fully parsed signature metadata.
 *
 * @param state The current state of the parser. The pointer will be advanced past the
 *              entire function pointer signature.
 * @return An `infix_type*` with detailed function pointer info, or `nullptr` on error.
 */
static infix_type * parse_function_pointer(parser_state * state) {
    const char * start = state->p;  // Points to '('
    int nest = 0;
    const char * end = start + 1;

    // Find the matching ')' for the function pointer signature
    while (*end != '\0') {
        if (*end == INFIX_SIG_FUNC_PTR_START)
            nest++;
        else if (*end == INFIX_SIG_FUNC_PTR_END) {
            if (nest == 0)
                break;
            nest--;
>>>>>>> main
        }
        end++;
    }

<<<<<<< HEAD
    skip_whitespace(state);
    if (*state->p != '{') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
=======
    if (*end != INFIX_SIG_FUNC_PTR_END) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;  // Unmatched parenthesis
>>>>>>> main
        return nullptr;
    }
    state->p++;

<<<<<<< HEAD
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
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        state->p++;
        if (infix_type_create_complex(state->arena, &result_type, base_type) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            result_type = nullptr;
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
=======
    // We now have the substring for the inner signature, e.g., "i,d=>v"
    size_t len = end - (start + 1);
    char * sub_signature = infix_arena_alloc(state->arena, len + 1, 1);
    if (!sub_signature) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    infix_memcpy(sub_signature, start + 1, len);
    sub_signature[len] = '\0';

    // Recursively parse the inner signature.
    // CRITICAL FIX: Pass the *current* arena to the recursive call so that all
    // allocations happen in the same memory block. The `infix_signature_parse`
    // function is designed to use the provided arena if the pointer is not NULL.
    infix_type * ret_type = nullptr;
    infix_type ** arg_types = nullptr;
    size_t num_args, num_fixed;
    infix_status status =
        infix_signature_parse(sub_signature, &state->arena, &ret_type, &arg_types, &num_args, &num_fixed);

    if (status != INFIX_SUCCESS) {
        // The nested call failed. Its cleanup logic has already run.
        // We just need to propagate the error. The main arena will be cleaned
        // up by the top-level caller.
        state->last_error = status;
        return nullptr;
    }

    // Now, create the infix_type that represents this function pointer.
    infix_type * func_ptr_type = infix_arena_alloc(state->arena, sizeof(infix_type), _Alignof(infix_type));
    if (!func_ptr_type) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }

    // A function pointer has the size and alignment of a regular pointer.
    func_ptr_type->category = INFIX_TYPE_REVERSE_TRAMPOLINE;
    func_ptr_type->size = sizeof(void *);
    func_ptr_type->alignment = _Alignof(void *);
    func_ptr_type->is_arena_allocated = true;

    // Populate the metadata with the parsed signature.
    func_ptr_type->meta.func_ptr_info.return_type = ret_type;
    func_ptr_type->meta.func_ptr_info.arg_types = arg_types;
    func_ptr_type->meta.func_ptr_info.num_args = num_args;
    func_ptr_type->meta.func_ptr_info.num_fixed_args = num_fixed;

    // Advance the main parser's state past the entire `(...)` block.
    state->p = end + 1;

    return func_ptr_type;
>>>>>>> main
}

/**
 * @internal
<<<<<<< HEAD
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
=======
 * @brief The core recursive-descent function for parsing a single data type from a signature string.
 *
 * @details
 * This function is the engine of the signature parser. It is responsible for parsing a
 * single, complete type definition, which may be simple (like a primitive) or arbitrarily
 * complex and nested (like a pointer to an array of structs). It is designed to correctly
 * handle C's right-to-left type declaration precedence.
 *
 * ### Parsing Process Walkthrough:
 * The function executes in a specific, well-defined order to correctly interpret C type syntax:
 *
 * 1.  **Prefix Parsing (Array Specifiers):** It first scans for and consumes any and all
 *     array specifiers at the beginning of the type string (e.g., `[10][5]`). The dimensions
 *     are temporarily stored. This handles the "left-hand" part of a C type declaration.
 *
 * 2.  **Base Type Parsing:** After consuming array prefixes, it parses the central "base type".
 *     This is the core, non-modifier part of the type, which can be:
 *     - A primitive (`i`, `d`, `c`, etc.).
 *     - An aggregate (`{...}` for structs, `<...>` for unions), which calls `parse_aggregate`.
 *     - A packed struct (`p(...){...}`), which calls `parse_packed_struct`.
 *     - A parenthesized expression `(...)`. This is the most complex case, as the function
 *       must perform a lookahead scan to determine if the parentheses denote a **grouped type**
 *       (e.g., `([10]i)`) or a **function pointer type** (e.g., `(i=>v)`). If it's a
 *       grouped type, `parse_type` calls itself recursively to parse the contents. If it is a
 *       function pointer, it delegates to the specialized `parse_function_pointer` helper.
 *
 * 3.  **Postfix Parsing (Pointer Specifiers):** After a base type has been successfully parsed,
 *     the function scans for and consumes any trailing pointer specifiers (`*`). Each `*`
 *     wraps the current type in a new pointer type. This handles the "right-hand" part of a
 *     C type declaration.
 *
 * 4.  **Array Construction:** Finally, if any array dimensions were parsed in step 1, the
 *     function constructs the final `infix_type`. It iterates through the stored dimensions
 *     in reverse order, wrapping the result of the previous steps in `infix_type` objects for
 *     arrays. This "inside-out" construction correctly models C's array nesting (e.g.,
 *     `[10][5]f` becomes an "array of 10" of "array of 5" of "float").
 *
 * This entire process is protected by a recursion depth check to prevent stack overflow
 * from maliciously crafted, deeply nested signatures.
 *
 * @param state [in, out] The current state of the parser. The function will advance the
 *              internal pointer `state->p` as it consumes the type string. It will also
 *              update `state->last_error` on failure.
 *
 * @return Returns a pointer to a newly created `infix_type` object allocated from the
 *         parser's arena. On any parsing failure, it returns `nullptr` and sets the
 *         error state.
 */
static infix_type * parse_type(parser_state * state) {

    // Prevent a stack overflow from a malicious signature like `{{{{...}}}`.
    if (state->depth >= MAX_RECURSION_DEPTH) {
>>>>>>> main
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    skip_whitespace(state);
    if (*state->p != ']') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;  // Consume ']'

<<<<<<< HEAD
    infix_type * vector_type = nullptr;
    if (infix_type_create_vector(state->arena, &vector_type, element_type, num_elements) != INFIX_SUCCESS) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    return vector_type;
=======
    // Parse all prefix array specifiers (e.g., `[10][5]`).
    // These are stored temporarily and applied at the end to correctly handle
    // C's declaration precedence (e.g., array of pointers vs. pointer to array).
    size_t array_dims[MAX_RECURSION_DEPTH];
    int num_dims = 0;
    while (*state->p == INFIX_SIG_ARRAY_START) {
        state->p++;  // Consume '['
        skip_whitespace(state);

        // Ensure we don't overflow our temporary dimension storage.
        if (num_dims >= MAX_RECURSION_DEPTH || !parse_size_t(state, &array_dims[num_dims++])) {
            state->depth--;
            return nullptr;
        }

        skip_whitespace(state);
        if (*state->p++ != INFIX_SIG_ARRAY_END) {  // Expect a matching ']'
            state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
    }

    // Parse the core base type.
    // This can be a primitive, an aggregate, or a parenthesized expression.
    infix_type * base_type = nullptr;
    switch (*state->p) {
    case INFIX_SIG_STRUCT_START:
        base_type = parse_aggregate(state, INFIX_SIG_STRUCT_START, INFIX_SIG_STRUCT_END);
        break;
    case INFIX_SIG_UNION_START:
        base_type = parse_aggregate(state, INFIX_SIG_UNION_START, INFIX_SIG_UNION_END);
        break;
    case INFIX_SIG_PACKED_STRUCT:
        base_type = parse_packed_struct(state);
        break;
    case INFIX_SIG_FUNC_PTR_START:
        {
            // This is the most complex case, requiring a lookahead to distinguish
            // a grouped type `([10]i)` from a function pointer `(i=>v)`.

            // Perform a forward scan to find the matching ')' and see if a
            // top-level "=>" appears within this scope.
            const char * scanner = state->p + 1;
            int nest = 0;
            bool is_func_ptr = false;
            while (*scanner != '\0') {
                if (*scanner == INFIX_SIG_FUNC_PTR_START || *scanner == INFIX_SIG_STRUCT_START ||
                    *scanner == INFIX_SIG_UNION_START) {
                    nest++;
                }
                else if (*scanner == INFIX_SIG_FUNC_PTR_END || *scanner == INFIX_SIG_STRUCT_END ||
                         *scanner == INFIX_SIG_UNION_END) {
                    // If we find a closing bracket at our current nesting level,
                    // that's the end of the group we're interested in.
                    if (nest == 0 && *scanner == INFIX_SIG_FUNC_PTR_END)
                        break;
                    if (nest > 0)
                        nest--;
                }
                else if (nest == 0 && strncmp(scanner, INFIX_SIG_RETURN_SEPARATOR, 2) == 0) {
                    // A "=>" at the top level of this group means it MUST be a function pointer.
                    is_func_ptr = true;
                    // We can break early here because we know it's a function pointer.
                    break;
                }
                scanner++;
            }

            if (is_func_ptr) {
                // It's a function pointer. Delegate to the specialized parser
                // which will recursively parse the inner signature.
                base_type = parse_function_pointer(state);
            }
            else {
                // It's a grouped type. Consume '(', parse the inner content recursively,
                // and then ensure we land on the closing ')'.
                state->p++;
                base_type = parse_type(state);
                if (base_type) {
                    skip_whitespace(state);
                    if (*state->p++ != INFIX_SIG_FUNC_PTR_END) {
                        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                        base_type = nullptr;
                    }
                }
            }
            break;
        }
    default:
        base_type = parse_primitive(state);
        break;
    }

    // If parsing the base type failed, propagate the error up.
    if (!base_type) {
        state->depth--;
        return nullptr;
    }


    // Parse all postfix pointer specifiers (`*`).

    skip_whitespace(state);
    while (*state->p == INFIX_SIG_POINTER) {
        infix_type * arena_ptr_type = infix_arena_alloc(state->arena, sizeof(infix_type), _Alignof(infix_type));
        if (!arena_ptr_type) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            state->depth--;
            return nullptr;
        }
        // For ABI purposes, all data pointers are identical in size and alignment,
        // so we just wrap the current type in a generic pointer type.
        *arena_ptr_type = *infix_type_create_pointer();
        arena_ptr_type->is_arena_allocated = true;
        base_type = arena_ptr_type;
        state->p++;
        skip_whitespace(state);
    }


    // Construct array types by wrapping the base type.
    // We loop backwards through the collected dimensions to get the nesting correct.
    // E.g., for `[10][5]f`, `base_type` is `f`.
    // 1st iteration (i=1, dim=5): wraps `f` to create `[5]f`. `base_type` is now `[5]f`.
    // 2nd iteration (i=0, dim=10): wraps `[5]f` to create `[10][5]f`. `base_type` is correct.

    for (int i = num_dims - 1; i >= 0; i--) {
        infix_type * array_type = nullptr;
        if (infix_type_create_array(state->arena, &array_type, base_type, array_dims[i]) != INFIX_SUCCESS) {
            state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
            state->depth--;
            return nullptr;
        }
        base_type = array_type;
    }


    // Decrement recursion depth and return the fully constructed type.
    state->depth--;
    return base_type;
>>>>>>> main
}

/**
 * @internal
<<<<<<< HEAD
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
=======
 * @brief Parses a packed struct with an explicit layout: `p(size,align){...}`.
 *
 * @details
 * This function is invoked by `parse_type` when it encounters the `p` character, which
 * designates a packed struct with a user-defined, non-standard memory layout. Unlike
 * standard aggregates, the parser does not calculate the size and alignment; it extracts
 * these values directly from the signature string. This is necessary to support layouts
 * created by compiler directives like `__attribute__((packed))` or `#pragma pack`.
 *
 * ### Parsing Process Walkthrough:
 * The parsing follows the strict `p(size,align){members...}` format:
 *
 * 1.  **Consume Specifier**: It begins by consuming the `p` character.
 * 2.  **Parse Header**: It parses the mandatory header `(size,align)`.
 *     a.  It expects and consumes an opening parenthesis `(`.
 *     b.  It calls `parse_size_t` to read the struct's total `size`.
 *     c.  It expects and consumes a comma `,`.
 *     d.  It calls `parse_size_t` to read the struct's required `alignment`.
 *     e.  It expects and consumes a closing parenthesis `)`.
 *     Failure at any of these steps results in a parsing error.
 * 3.  **Parse Members**: After the header, it expects an opening brace `{` and proceeds
 *     to parse the member list. This process is similar to `parse_aggregate`, but with
 *     one critical difference:
 *     - **Mandatory Offsets**: Each member declaration *must* be followed by an offset
 *       specifier (`@`) and a numeric value indicating the member's byte offset from
 *       the start of the struct (e.g., `c@0`, `i@1`). The parser enforces this syntax.
 * 4.  **Error Handling**: Like `parse_aggregate`, it performs robust error checking for
 *     syntax errors like trailing commas or empty member lists (`p(1,1){}`).
 * 5.  **Member List Construction**: It uses the same linked-list-to-array strategy as
 *     `parse_aggregate` for efficient construction of the member list.
 * 6.  **Packed Struct Creation**: Once parsing is complete, it calls
 *     `infix_type_create_packed_struct`, passing the user-provided `total_size`,
 *     `alignment`, and the parsed member list to create the final `infix_type`.
 *
 * @param state [in, out] The current state of the parser. The pointer `state->p` will be
 *              advanced as the packed struct signature is consumed.
 *
 * @return Returns a pointer to a newly created `infix_type` for the packed struct, allocated
 *         from the parser's arena. Returns `nullptr` on any parsing failure.
 */
static infix_type * parse_packed_struct(parser_state * state) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    state->p++;  // Consume the 'p' specifier.
    skip_whitespace(state);

    // Parse the (size,align) header.
    if (*state->p++ != INFIX_SIG_FUNC_PTR_START) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }

    size_t total_size, alignment;
    skip_whitespace(state);
    if (!parse_size_t(state, &total_size)) {
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p++ != ',') {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (!parse_size_t(state, &alignment)) {
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p++ != INFIX_SIG_FUNC_PTR_END) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p++ != INFIX_SIG_STRUCT_START) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }

    // Parse the member list into a temporary linked list.
    // This is similar to parse_aggregate but enforces the `@offset` syntax.
    typedef struct member_node {
        infix_struct_member member;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->p != INFIX_SIG_STRUCT_END) {
        while (1) {
            skip_whitespace(state);
            // Check for empty/trailing members.
            if (*state->p == INFIX_SIG_STRUCT_END) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }

            const char * p_before_member = state->p;
            const char * name = parse_identifier(state);
            skip_whitespace(state);
            infix_type * member_type = nullptr;
            size_t offset;

            if (name && *state->p == INFIX_SIG_NAME_SEPARATOR) {
                state->p++;
                skip_whitespace(state);
                member_type = parse_type(state);
            }
            else {
                name = nullptr;
                state->p = p_before_member;
                member_type = parse_type(state);
            }
            if (!member_type) {
                state->depth--;
                return nullptr;
            }

            // Each member MUST have an offset specifier.
            skip_whitespace(state);
            if (*state->p++ != INFIX_SIG_OFFSET_SEPARATOR) {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
            skip_whitespace(state);
            if (!parse_size_t(state, &offset)) {
                state->depth--;
                return nullptr;
            }

            // Add the parsed member to the linked list.
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
                state->depth--;
                return nullptr;
            }
            node->member = (infix_struct_member){.name = name, .type = member_type, .offset = offset};
            node->next = nullptr;
            if (!head) {
                head = tail = node;
            }
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;
>>>>>>> main

            const char * name = parse_optional_name_prefix(state);
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
<<<<<<< HEAD
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

                const char * name = parse_optional_name_prefix(state);
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
=======
            if (*state->p == INFIX_SIG_MEMBER_SEPARATOR) {
                state->p++;
                skip_whitespace(state);
                if (*state->p == INFIX_SIG_STRUCT_END) {  // Trailing comma.
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    state->depth--;
                    return nullptr;
                }
            }
            else if (*state->p == INFIX_SIG_STRUCT_END) {
                break;
            }
            else {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
>>>>>>> main
            }
        }
    }
    state->p++;  // Consume '}'.

<<<<<<< HEAD
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

=======
    // An empty member list `p(1,1){}` is considered invalid.
    if (num_members == 0) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }

    // Convert the linked list into a contiguous array.
    infix_struct_member * members =
        infix_arena_alloc(state->arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member));
    if (!members) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        state->depth--;
        return nullptr;
    }

    member_node * current = head;
    for (size_t i = 0; i < num_members; ++i) {
        members[i] = current->member;
        current = current->next;
    }

    // Create the final infix_type for the packed struct.
    infix_type * packed_type = nullptr;
    if (infix_type_create_packed_struct(state->arena, &packed_type, total_size, alignment, members, num_members) !=
        INFIX_SUCCESS) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        state->depth--;
        return nullptr;
    }


    state->depth--;
    return packed_type;
}

/**
 * @internal
 * @brief Parses the members of a standard struct (`{...}`) or union (`<...>`).
 *
 * @details
 * This function is invoked by `parse_type` when it encounters a `{` or `<` character,
 * indicating the start of an aggregate type definition. Its sole responsibility is to
 * parse the comma-separated list of member types contained within the enclosing brackets.
 *
 * ### Parsing Process Walkthrough:
 * 1.  **Consume Start Character**: It begins by consuming the opening bracket (`{` or `<`).
 * 2.  **Iterative Member Parsing**: It enters a loop that continues until the closing
 *     bracket is found. In each iteration, it:
 *     a.  **Parses an optional member name**: It looks for a C identifier followed by a
 *         colon (`:`). If found, the name is stored. If not, the member is anonymous.
 *     b.  **Parses the member type**: It makes a recursive call to `parse_type` to parse the
 *         member's complete data type. This allows for arbitrary nesting, such as a
 *         struct containing another struct or a pointer to an array.
 *     c.  **Handles Separators**: After successfully parsing a member, it expects to find
 *         either a comma (`,`) to continue the list or the closing bracket to end it.
 * 3.  **Error Handling**: The loop is carefully constructed to detect and reject common
 *     syntax errors, such as:
 *     - A leading comma (e.g., `{,i}`).
 *     - A trailing comma (e.g., `{i,}`).
 *     - An empty member entry (e.g., `{i,,d}`).
 *     - A named member with no type (e.g., `{name:}`).
 * 4.  **Member List Construction**: For performance and to avoid memory reallocations,
 *     the parsed members are first stored in a temporary, singly-linked list.
 * 5.  **Final Array Allocation**: Once all members have been parsed, a single, contiguous
 *     array of `infix_struct_member` is allocated from the arena with the exact size required.
 *     The data from the linked list is then copied into this final array.
 * 6.  **Aggregate Type Creation**: Finally, it calls either `infix_type_create_struct` or
 *     `infix_type_create_union` to construct the final `infix_type` object for the
 *     aggregate, which calculates the aggregate's final size and alignment based on its members.
 *
 * @param state [in, out] The current state of the parser. The pointer `state->p` will be
 *              advanced as the aggregate is consumed.
 * @param start_char [in] The opening character that triggered the call (`{` or `<`).
 * @param end_char [in] The expected closing character (`}` or `>`).
 *
 * @return Returns a pointer to a newly created `infix_type` for the struct or union,
 *         allocated from the parser's arena. Returns `nullptr` on any parsing failure.
 */
static infix_type * parse_aggregate(parser_state * state, char start_char, char end_char) {

    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    state->p++;  // Consume the start character ('{' or '<').
    skip_whitespace(state);

    // Parse members into a temporary linked list.
    // This avoids reallocating an array of members as we discover them one by one.
    typedef struct member_node {
        infix_struct_member member;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    // If the next character is not the end character, we expect a list of members.
    if (*state->p != end_char) {
        while (1) {
            skip_whitespace(state);
            // Check for syntax errors like a leading comma `{,i}` or an empty member `{i,,d}`.
            if (*state->p == end_char || *state->p == INFIX_SIG_MEMBER_SEPARATOR || *state->p == '\0') {
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }

            // Store current position in case we don't find a named member.
            const char * p_before_member = state->p;

            // Attempt to parse an optional name, e.g., "my_member:".
            const char * name = parse_identifier(state);
            skip_whitespace(state);

            if (name && *state->p == INFIX_SIG_NAME_SEPARATOR) {
                state->p++;  // Consume ':'
                skip_whitespace(state);
                // Check for a name with no type, e.g., `{name:}`.
                if (*state->p == end_char) {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    state->depth--;
                    return nullptr;
                }
            }
            else {
                // It was not a named member, so reset the pointer and treat it as anonymous.
                name = nullptr;
                state->p = p_before_member;
            }

            // Recursively call `parse_type` to parse the member's type.
            infix_type * member_type = parse_type(state);
            if (!member_type) {
                state->depth--;
                return nullptr;  // Propagate failure.
            }

            // Add the successfully parsed member to our linked list.
            member_node * node = infix_arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
                state->depth--;
                return nullptr;
            }
            node->member = (infix_struct_member){.name = name, .type = member_type, .offset = 0};
            node->next = nullptr;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;

            skip_whitespace(state);
            if (*state->p == INFIX_SIG_MEMBER_SEPARATOR) {
                // Found a comma, so we expect another member.
                state->p++;
                skip_whitespace(state);
                // Check for a trailing comma, e.g., `{i,}`.
                if (*state->p == end_char) {
                    state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    state->depth--;
                    return nullptr;
                }
            }
            else if (*state->p == end_char)
                // Found the end character, so this is the last member.
                break;
            else {
                // Found an invalid character between members.
                state->last_error = INFIX_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
        }
    }
    state->p++;  // Consume the end character ('}' or '>').

    // Convert the linked list into a contiguous array.
    infix_struct_member * members = num_members > 0
        ? infix_arena_alloc(state->arena, sizeof(infix_struct_member) * num_members, _Alignof(infix_struct_member))
        : nullptr;
    if (num_members > 0 && !members) {
        state->last_error = INFIX_ERROR_ALLOCATION_FAILED;
        state->depth--;
        return nullptr;
    }

    member_node * current = head;
    for (size_t i = 0; i < num_members; ++i) {
        members[i] = current->member;
        current = current->next;
    }

    // Create the final infix_type for the aggregate.
    // This call will also calculate the aggregate's size and alignment.
    infix_type * agg_type = nullptr;
    infix_status status = (start_char == INFIX_SIG_STRUCT_START)
        ? infix_type_create_struct(state->arena, &agg_type, members, num_members)
        : infix_type_create_union(state->arena, &agg_type, members, num_members);

    if (status != INFIX_SUCCESS) {
        state->last_error = status;
        state->depth--;
        return nullptr;
    }


    state->depth--;
    return agg_type;
}


/**
 * @brief Parses a signature string representing a single data type.
 *
 * @details
 * This is a high-level public API function that serves as a specialized entry point
 * into the parsing engine. Its purpose is to parse a string that represents a single,
 * complete data type (such as `"i"`, `"d*"`, or `"{s,[10]c}"`), rather than a full
 * function signature.
 *
 * This function is ideal for use cases like data marshalling, serialization, dynamic
 * type inspection, or any scenario where an `infix_type` object graph is needed to
 * describe data outside the context of a function call.
 *
 * ### Process Walkthrough:
 * 1.  **Input Validation**: It performs initial null checks on the input parameters.
 * 2.  **Arena Creation**: It creates a new, dedicated `infix_arena_t` to own all memory
 *     for the resulting `infix_type` object graph.
 * 3.  **Parser Invocation**: It initializes a `parser_state` and calls the core `parse_type`
 *     function to perform the actual parsing of the signature string.
 * 4.  **Completeness Check**: After `parse_type` returns, this function performs a crucial
 *     validation step: it checks if the *entire* input string has been consumed. If any
 *     characters remain (e.g., junk after a valid type like `"i*d"`), it is considered
 *     a syntax error. A valid type signature must describe a single, complete type and
 *     nothing more.
 * 5.  **Ownership Transfer**: On success, it populates the `out_type` and `out_arena`
 *     pointers and transfers ownership of the arena to the caller.
 * 6.  **Cleanup on Failure**: If parsing fails at any stage, it ensures the created arena
 *     is properly destroyed before returning, preventing any memory leaks.
 *
 * @param[out] out_type On success, this will point to the newly created `infix_type` that
 *                      represents the parsed signature. This pointer is an allocation
 *                      within the returned arena and is valid only for its lifetime.
 *
 * @param[out] out_arena On success, this will point to the new `infix_arena_t` that owns the
 *                       entire `infix_type` object graph. The caller is responsible for
 *                       destroying this arena with `infix_arena_destroy()`. On failure, this
 *                       will be set to `NULL`.
 *
 * @param[in]  signature A null-terminated string describing the data type to be parsed.
 *                       e.g., `"i"`, `"d*"`, `"{s,[10]c}"`, `"[10]{name:c*, id:i}"`
 *
 * @return Returns `INFIX_SUCCESS` if the entire string was successfully parsed into a single,
 *         valid type.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any parameters are null, the signature
 *         string is malformed, or if the string contains trailing characters after a
 *         valid type definition.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if the internal memory arena could not be
 *         created.
 *
 * @note **Memory Management**: On a successful return (`INFIX_SUCCESS`), the caller assumes
 *       ownership of the arena returned via the `out_arena` parameter. A single call to
 *       `infix_arena_destroy(*out_arena)` is the necessary and sufficient action to free all
 *       memory associated with the parsed type graph.
 */
c23_nodiscard infix_status infix_type_from_signature(infix_type ** out_type,
                                                     infix_arena_t ** out_arena,
                                                     const char * signature) {

    if (!out_type || !out_arena || !signature)
        return INFIX_ERROR_INVALID_ARGUMENT;
    if (*signature == '\0')
        return INFIX_ERROR_INVALID_ARGUMENT;  // Empty string is not a valid type.

    // Create a dedicated arena for this parsing operation.
    // All subsequent allocations for the infix_type graph will come from this arena.
    infix_arena_t * arena = infix_arena_create(4096);
    if (!arena)
        return INFIX_ERROR_ALLOCATION_FAILED;

    // Initialize the parser state and invoke the core parsing engine.
    parser_state state = {.p = signature, .arena = arena, .depth = 0, .last_error = INFIX_SUCCESS};
    infix_type * type = parse_type(&state);

    // Validate the result.
    if (type) {
        skip_whitespace(&state);
        // A successful parse must consume the ENTIRE string. If characters are
        // left over, it's a syntax error (e.g., "i* d" or "i[10]").
        if (*state.p != '\0') {
            type = nullptr;  // Invalidate the result.
            state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
        }
    }

    // Handle success or failure.
    if (!type) {
        // If parsing failed for any reason (syntax error, allocation failure, etc.),
        // destroy the arena and all its contents before returning.
        infix_arena_destroy(arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        // Return the specific error captured by the parser, or a generic one.
        return state.last_error != INFIX_SUCCESS ? state.last_error : INFIX_ERROR_INVALID_ARGUMENT;
    }

    // Transfer ownership of the arena and the parsed type to the caller.
    *out_type = type;
    *out_arena = arena;
>>>>>>> main
    return INFIX_SUCCESS;
}

/**
<<<<<<< HEAD
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
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : nullptr;
    if (num_args > 0 && !arg_types) {
        infix_arena_destroy(arena);
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    for (size_t i = 0; i < num_args; ++i)
        arg_types[i] = args[i].type;

    //  Instead of calling the public manual API, we now need
    // a way to tell the creation function about our temporary arena so it can
    // calculate the exact memory needed. Let's assume an internal function
    // _infix_forward_create_from_parsed_arena exists for this.
    status = _infix_forward_create_internal(out_trampoline, ret_type, arg_types, num_args, num_fixed, arena);

    // The temporary arena has now been measured and its types copied. It can be safely destroyed.
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
=======
 * @brief Parses a full function signature string into its constituent infix_type parts.
 *
 * @details
 * This is a key high-level function that acts as the primary bridge from the user-friendly
 * string format to the library's internal `infix_type` graph representation. It is designed
 * for advanced use cases where the caller needs to inspect the parsed type information
 * before generating a trampoline, or for manually driving the FFI generation process.
 *
 * For simpler use cases, it is recommended to use `infix_forward_create`
 * or `infix_reverse_create`, which wrap this function and handle
 * all memory management automatically.
 *
 * ### Parsing Process Walkthrough:
 * The function executes in a well-defined sequence:
 * 1.  **Locate Return Separator**: It first performs a nest-aware scan of the input string
 *     to find the top-level return separator (`=>`). This is critical to correctly
 *     distinguish the main separator from any `=>` characters that might appear inside a
 *     function pointer argument, e.g., `(i=>v),i=>v`.
 * 2.  **Parse Return Type**: Once the signature is split, the portion of the string *after*
 *     the `=>` is parsed by recursively calling `parse_type`.
 * 3.  **Tokenize Arguments**: The portion of the string *before* the `=>` is then processed.
 *     It is tokenized by splitting on the argument separator (`,`) and the variadic
 *     separator (`;`). This tokenization is also nest-aware to correctly handle
 *     commas inside complex aggregate types like `{i,d}`.
 * 4.  **Parse Each Argument**: The `parse_type` function is called on each resulting token
 *     to generate its corresponding `infix_type` object.
 * 5.  **Assemble Final Structures**: The parsed `infix_type` objects for the arguments are
 *     collected from a temporary linked list into a final, contiguous array. All
 *     allocations are made from the single arena created at the start of the process.
 *
 * @param[in]  signature A null-terminated string describing the function signature.
 *                       See the project's main documentation for the full signature language grammar.
 *                       Example: `"{i,d*}, [10]c; p(1,1){c@0} => (i=>v)*`
 *
 * @param[out] out_arena On success, this parameter will be populated with a pointer to the newly
 *                       created `infix_arena_t`. This arena owns the memory for the *entire* parsed
 *                       type graph, including the return type, the argument types, and the array
 *                       that holds the argument type pointers. On failure, this will be `NULL`.
 *                       **The caller is responsible for destroying this arena** with `infix_arena_destroy()`.
 *
 * @param[out] out_ret_type On success, this will point to the `infix_type` for the return value.
 *                          This pointer is an allocation within the `*out_arena` and is valid only
 *                          for the lifetime of that arena.
 *
 * @param[out] out_arg_types On success, this will point to an array of `infix_type*` pointers, one
 *                           for each argument. This array and the types it points to are all
 *                           allocated within the `*out_arena`.
 *
 * @param[out] out_num_args On success, this will be set to the total number of parsed arguments
 *                          (both fixed and variadic).
 *
 * @param[out] out_num_fixed_args On success, this will be set to the number of non-variadic
 *                                arguments (i.e., the arguments that appear before a `;` separator).
 *
 * @return Returns `INFIX_SUCCESS` if the entire signature was parsed successfully.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any of the `out` parameters are null, or if the
 *         signature string is empty, malformed, or contains syntax errors.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if the internal arena or any of its sub-allocations
 *         could not be completed.
 *
 * @note **Memory Ownership**: On a successful return (`INFIX_SUCCESS`), this function transfers
 *       ownership of the newly created arena to the caller. A single call to
 *       `infix_arena_destroy(*out_arena)` is the correct and only way to free all memory
 *       associated with the parsed types. If the function fails, it performs its own cleanup,
 *       and `*out_arena` will be set to `NULL`.
 */
c23_nodiscard infix_status infix_signature_parse(const char * signature,
                                                 infix_arena_t ** out_arena,
                                                 infix_type ** out_ret_type,
                                                 infix_type *** out_arg_types,
                                                 size_t * out_num_args,
                                                 size_t * out_num_fixed_args) {
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Find the top-level return separator "=>".
    const char * p = signature;
    int nest_level = 0;
    const char * return_sep = NULL;
    while (*p != '\0') {
        if (*p == INFIX_SIG_FUNC_PTR_START || *p == INFIX_SIG_STRUCT_START || *p == INFIX_SIG_UNION_START)
            nest_level++;
        else if (*p == INFIX_SIG_FUNC_PTR_END || *p == INFIX_SIG_STRUCT_END || *p == INFIX_SIG_UNION_END) {
            if (nest_level > 0)
                nest_level--;
        }
        else if (nest_level == 0 && strncmp(p, INFIX_SIG_RETURN_SEPARATOR, 2) == 0) {
            return_sep = p;
            break;
        }
        p++;
    }

    if (!return_sep)
        return INFIX_ERROR_INVALID_ARGUMENT;

    const char * ret_part_str = return_sep + strlen(INFIX_SIG_RETURN_SEPARATOR);
    {
        parser_state temp_state = {.p = ret_part_str};
        skip_whitespace(&temp_state);
        if (*temp_state.p == '\0')
            return INFIX_ERROR_INVALID_ARGUMENT;
    }

    // CRITICAL FIX: The arena logic is now robust for both top-level and recursive calls.
    bool created_arena_in_this_call = false;
    infix_arena_t * arena = *out_arena;
    if (arena == NULL) {
        arena = infix_arena_create(8192);
        if (!arena)
            return INFIX_ERROR_ALLOCATION_FAILED;
        created_arena_in_this_call = true;
    }

    parser_state state = {.p = ret_part_str, .arena = arena, .depth = 0, .last_error = INFIX_SUCCESS};

    *out_ret_type = parse_type(&state);
    if (!*out_ret_type)
        goto error;
    skip_whitespace(&state);
    if (*state.p != '\0') {
        state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    size_t args_part_len = return_sep - signature;
    char * args_str_mut = infix_arena_alloc(arena, args_part_len + 1, 1);
    if (!args_str_mut) {
        state.last_error = INFIX_ERROR_ALLOCATION_FAILED;
        goto error;
    }
    infix_memcpy(args_str_mut, signature, args_part_len);
    args_str_mut[args_part_len] = '\0';

    typedef struct type_node {
        infix_type * type;
        struct type_node * next;
    } type_node;
    type_node *head = nullptr, *tail = nullptr;
    size_t num_args = 0, num_fixed = 0;
    bool in_variadic = false;

    const char * p_arg = args_str_mut;
    parser_state temp_arg_state = {.p = p_arg};
    skip_whitespace(&temp_arg_state);
    p_arg = temp_arg_state.p;
    if (*p_arg == INFIX_SIG_VARIADIC_SEPARATOR) {
        in_variadic = true;
        p_arg++;
    }

    const char * arg_start = p_arg;
    nest_level = 0;

    if (*arg_start != '\0') {
        for (;; p_arg++) {
            char current_char = *p_arg;
            if (nest_level == 0 &&
                (current_char == INFIX_SIG_MEMBER_SEPARATOR || current_char == INFIX_SIG_VARIADIC_SEPARATOR ||
                 current_char == '\0')) {
                size_t len = p_arg - arg_start;
                char * token = infix_arena_alloc(arena, len + 1, 1);
                if (!token) {
                    state.last_error = INFIX_ERROR_ALLOCATION_FAILED;
                    goto error;
                }
                infix_memcpy(token, arg_start, len);
                token[len] = '\0';

                parser_state token_state = {.p = token, .arena = arena, .depth = 0};
                skip_whitespace(&token_state);

                if (*token_state.p == '\0') {
                    if (args_part_len > 0) {
                        state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }
                }
                else {
                    infix_type * arg_type = parse_type(&token_state);
                    if (!arg_type) {
                        state.last_error =
                            token_state.last_error ? token_state.last_error : INFIX_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }

                    skip_whitespace(&token_state);
                    if (*token_state.p != '\0') {
                        state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }

                    type_node * node = infix_arena_alloc(arena, sizeof(type_node), _Alignof(type_node));
                    if (!node) {
                        state.last_error = INFIX_ERROR_ALLOCATION_FAILED;
                        goto error;
                    }
                    node->type = arg_type;
                    node->next = nullptr;
                    if (!head)
                        head = tail = node;
                    else {
                        tail->next = node;
                        tail = node;
                    }
                    num_args++;
                    if (!in_variadic)
                        num_fixed++;
                }

                if (current_char == INFIX_SIG_VARIADIC_SEPARATOR) {
                    if (in_variadic) {
                        state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }
                    in_variadic = true;
                }
                if (current_char == '\0')
                    break;
                arg_start = p_arg + 1;
            }
            else if (current_char == INFIX_SIG_STRUCT_START || current_char == INFIX_SIG_UNION_START ||
                     current_char == INFIX_SIG_FUNC_PTR_START)
                nest_level++;
            else if (current_char == INFIX_SIG_STRUCT_END || current_char == INFIX_SIG_UNION_END ||
                     current_char == INFIX_SIG_FUNC_PTR_END) {
                if (nest_level > 0)
                    nest_level--;
            }
            else if (current_char == '\0') {
                if (nest_level != 0) {
                    state.last_error = INFIX_ERROR_INVALID_ARGUMENT;
                    goto error;
                }
                p_arg--;
            }
        }
    }

    infix_type ** arg_types =
        num_args > 0 ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : nullptr;
    if (num_args > 0 && !arg_types) {
        state.last_error = INFIX_ERROR_ALLOCATION_FAILED;
        goto error;
    }

    type_node * current = head;
    for (size_t i = 0; i < num_args; ++i) {
        arg_types[i] = current->type;
        current = current->next;
    }

    // On success, only transfer ownership if we created the arena.
    if (created_arena_in_this_call) {
        *out_arena = arena;
    }

    *out_arg_types = arg_types;
    *out_num_args = num_args;
    *out_num_fixed_args = num_fixed;
    return INFIX_SUCCESS;

error:
    // Only destroy the arena if this function call created it.
    if (created_arena_in_this_call) {
        infix_arena_destroy(arena);
    }
    return state.last_error != INFIX_SUCCESS ? state.last_error : INFIX_ERROR_INVALID_ARGUMENT;
}


/**
 * @brief Generates a forward-call trampoline from a high-level signature string.
 *
 * @details
 * This is the primary, recommended public API function for creating a **forward trampoline**.
 * It serves as a convenient and memory-safe wrapper around the lower-level FFI functions,
 * automating the entire process from string parsing to JIT compilation.
 *
 * A forward trampoline is a small, dynamically generated function that enables calls *from*
 * a generic environment (like an embedded script) *into* a specific, native C function.
 * The generated trampoline handles the complex, platform-specific details of the
 * Application Binary Interface (ABI), such as placing arguments into the correct CPU
 * registers or arranging them on the stack.
 *
 * ### Process Walkthrough:
 * 1.  **Parse Signature**: It first calls `infix_signature_parse` to parse the input string.
 *     This step creates a temporary memory arena and populates it with the `infix_type`
 *     object graph that describes the function's return type and argument types.
 * 2.  **Generate Trampoline**: If parsing succeeds, it passes the resulting `infix_type`
 *     graph and other metadata (number of arguments, etc.) to the core `infix_forward_create_manual`
 *     function. This is the step where the machine code is actually generated and placed
 *     into executable memory.
 * 3.  **Automatic Cleanup**: Crucially, regardless of whether the trampoline generation
 *     succeeds or fails, this function ensures that the temporary arena and all the
 *     `infix_type` objects created in step 1 are destroyed before returning. This completely
 *     automates memory management for the type system, preventing leaks and simplifying
 *     the caller's code.
 *
 * @param[out] out_trampoline On success, this will be populated with a pointer to a newly
 *                            allocated `infix_forward_t` handle. This handle is the primary
 *                            object used to interact with the JIT-compiled code. The caller
 *                            is responsible for freeing this handle with `infix_forward_destroy()`.
 *
 * @param[in] signature A null-terminated string describing the C function's signature.
 *                      The format is `"arg1,arg2;variadic_arg=>ret_type"`. See the main
 *                      project documentation for the full grammar.
 *                      Example: `"i*,i=>i"` for `int printf(const char*, int)`.
 *
 * @return Returns `INFIX_SUCCESS` if the trampoline was successfully created.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if the `out_trampoline` parameter is null or
 *         if the signature string is malformed.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if any internal memory allocation fails during
 *         either parsing or JIT compilation.
 * @return Returns other `infix_status` error codes on failures during the JIT compilation
 *         process (e.g., `INFIX_ERROR_PROTECTION_FAILED`).
 *
 * @note **Memory Ownership**: The caller is responsible for destroying the `infix_forward_t` object
 *       returned via the `out_trampoline` parameter by calling `infix_forward_destroy()`. All
 *       intermediate memory used for parsing the signature is managed automatically by this function.
 *
 * @see infix_signature_parse()
 * @see infix_forward_create_manual()
 * @see infix_forward_destroy()
 * @see infix_forward_get_code()
 */
c23_nodiscard infix_status infix_forward_create(infix_forward_t ** out_trampoline, const char * signature) {
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
    infix_type ** arg_types = nullptr;
    size_t num_args, num_fixed;

    // Parse the signature string into a infix_type graph.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);

    // If parsing failed, `arena` will be null, and we can return the error immediately.
    if (status != INFIX_SUCCESS)
        return status;

    // Generate the trampoline using the parsed type information.
    status = infix_forward_create_manual(out_trampoline, ret_type, arg_types, num_args, num_fixed);

    // It is critical to destroy the arena here, regardless of whether the
    // trampoline generation succeeded or failed. This frees the entire infix_type
    // object graph with a single call because we no longer need it.
    infix_arena_destroy(arena);
    return status;
}
/**
 * @brief Generates a reverse-call trampoline (callback) from a high-level signature string.
 *
 * @details
 * This is the primary, recommended public API function for creating a **reverse trampoline**,
 * also known as a **callback**. It provides a convenient and memory-safe wrapper around the
 * lower-level FFI functions, automating the entire process from string parsing to the
 * JIT compilation of the callback stub.
 *
 * A reverse trampoline is a native, C-callable function pointer that, when invoked by C code,
 * redirects the call to a user-provided handler function (the `user_callback_fn`). The
 * JIT-compiled stub is responsible for marshalling the arguments from the native C calling
 * convention (registers and stack) into a generic format that can be passed to the user's
 * handler.
 *
 * This function is essential for interoperability with C libraries that require function
 * pointers for callbacks, notifications, or event handling.
 *
 * ### Process Walkthrough:
 * 1.  **Parse Signature**: It first calls `infix_signature_parse` to parse the input string.
 *     This step creates a temporary memory arena and populates it with the `infix_type`
 *     object graph that describes the callback's return type and argument types.
 * 2.  **Generate Trampoline**: If parsing succeeds, it passes the resulting `infix_type`
 *     graph, along with the user-provided callback function and user data, to the core
 *     `infix_reverse_create_manual` function. This step JIT-compiles the callable stub
 *     and sets up the internal context required for the callback mechanism.
 * 3.  **Automatic Cleanup**: Just like its forward-trampoline counterpart, this function
 *     ensures that the temporary arena and all the `infix_type` objects created during
 *     parsing are destroyed before returning. This happens regardless of whether the
 *     trampoline generation succeeds or fails, guaranteeing that no memory is leaked.
 *
 * @param[out] out_context On success, this will be populated with a pointer to a newly
 *                         allocated `infix_reverse_t` handle. This handle contains
 *                         the executable code pointer and all the context for the callback.
 *                         The caller is responsible for freeing this handle with
 *                         `infix_reverse_destroy()`.
 *
 * @param[in] signature A null-terminated string describing the C callback's signature.
 *                      The format is `"arg1,arg2;variadic_arg=>ret_type"`.
 *                      Example: `"i,i=>i"` for a callback that takes two `int`s and returns an `int`.
 *
 * @param[in] user_callback_fn A function pointer to the user's actual C handler. Its C signature
 *                             must logically match the signature described in the string.
 *
 * @param[in] user_data An arbitrary, opaque pointer that will be associated with this callback.
 *                      It can be retrieved later using `infix_reverse_get_user_data()`.
 *                      This is useful for passing state to a stateful callback.
 *
 * @return Returns `INFIX_SUCCESS` if the callback trampoline was successfully created.
 * @return Returns `INFIX_ERROR_INVALID_ARGUMENT` if any of the `out` parameters are null or
 *         if the signature string is malformed.
 * @return Returns `INFIX_ERROR_ALLOCATION_FAILED` if any internal memory allocation fails.
 * @return Returns other `infix_status` error codes on failures during the JIT compilation
 *         process.
 *
 * @note **Memory Ownership**: The caller is responsible for destroying the `infix_reverse_t`
 *       object returned via the `out_context` parameter by calling `infix_reverse_destroy()`.
 *       All intermediate memory used for parsing the signature is managed automatically.
 *
 * @see infix_signature_parse()
 * @see infix_reverse_create_manual()
 * @see infix_reverse_destroy()
 * @see infix_reverse_get_code()
 * @see infix_reverse_get_user_data()
>>>>>>> main
 */
c23_nodiscard infix_status infix_reverse_create(infix_reverse_t ** out_context,
                                                const char * signature,
                                                void * user_callback_fn,
                                                void * user_data) {
    infix_arena_t * arena = nullptr;
    infix_type * ret_type = nullptr;
<<<<<<< HEAD
    infix_function_argument * args = nullptr;
    size_t num_args, num_fixed;

    // First, parse the signature string.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &args, &num_args, &num_fixed);
    if (status != INFIX_SUCCESS)
        return status;

    // Bridge logic, same as in infix_forward_create.
    infix_type ** arg_types =
        (num_args > 0) ? infix_arena_alloc(arena, sizeof(infix_type *) * num_args, _Alignof(infix_type *)) : nullptr;
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
=======
    infix_type ** arg_types = nullptr;
    size_t num_args, num_fixed;

    // This creates a temporary arena and populates it with the infix_type graph.
    infix_status status = infix_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);

    // If parsing failed, `arena` will be null, and we can return the error immediately.
    if (status != INFIX_SUCCESS)
        return status;

    // Generate the trampoline using the parsed type information and user data.
    status =
        infix_reverse_create_manual(out_context, ret_type, arg_types, num_args, num_fixed, user_callback_fn, user_data);

>>>>>>> main
    infix_arena_destroy(arena);
    return status;
}
