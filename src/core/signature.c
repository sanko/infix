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
 *
 * @details
 * Honestly, this is probably the most complex code in the entire project... it must parse
 * human generated strings.
 *
 * This file contains the "complete" implementation of the signature string parser, which is the
 * engine behind the library's high-level API. Its primary responsibility is to translate
 * a human-readable string representation of a C type or function signature into a graph
 * of `ffi_type` objects that the core FFI generation logic can understand.
 *
 * # Parser Design and Strategy
 *
 * The parser is implemented using a **recursive-descent** model. The main entry point for
 * parsing a single, self-contained type is the `parse_type` function. This function can
 * recursively call itself to handle arbitrarily complex nested constructs, such as an array
 * of structs that contains a pointer to another array.
 *
 * For full function signatures (e.g., `"i,d=>v"`), the top-level `ffi_signature_parse`
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
 * A critical design principle of this parser is its use of an **arena allocator** (`arena_t`).
 * **All `ffi_type` objects and associated data (like member names) created during a parsing
 * operation are allocated from a single, temporary arena.** This has two major benefits:
 * 1.  **Performance**: It avoids the overhead of numerous small `malloc` calls.
 * 2.  **Simplicity**: It dramatically simplifies memory cleanup. The entire complex graph of
 *     `ffi_type` objects can be freed with a single call to `arena_destroy`.
 *
 * The public API functions reflect this: `ffi_signature_parse` transfers ownership of the
 * arena to the caller, while the higher-level `ffi_create_*_from_signature` functions
 * manage the arena internally, destroying it automatically before returning.
 *
 * ## Security Considerations
 *
 * To mitigate the risk of a denial-of-service attack via stack overflow, the recursive
 * parser enforces a hard-coded recursion depth limit (`MAX_RECURSION_DEPTH`). Any signature
 * with nesting deeper than this limit will be rejected as invalid.
 */

#include <ctype.h>
#include <infix_internals.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @def MAX_RECURSION_DEPTH
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
    const char * p;         ///< A pointer to the current position in the signature string.
    arena_t * arena;        ///< The memory arena for allocating `ffi_type` objects.
    int depth;              ///< The current recursion depth, checked against `MAX_RECURSION_DEPTH`.
    ffi_status last_error;  ///< A sticky error flag to propagate failures up the call stack.
} parser_state;

// Forward declarations for the recursive parsing functions.
static ffi_type * parse_type(parser_state * state);
static ffi_type * parse_aggregate(parser_state * state, char start_char, char end_char);
static ffi_type * parse_packed_struct(parser_state * state);
static ffi_type * parse_function_pointer(parser_state * state);

/**
 * @internal
 * @brief Advances the parser's pointer past any leading whitespace characters.
 * @param state The current state of the parser.
 */
static void skip_whitespace(parser_state * state) {
    while (isspace((unsigned char)*state->p))
        state->p++;
}

/**
 * @internal
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
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        return false;
    }
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

    char * name = arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    infix_memcpy(name, start, len);
    name[len] = '\0';
    return name;
}

/**
 * @internal
 * @brief Parses a single-character primitive type specifier.
 * @details Maps a character like 'i' or 'd' to its corresponding static,
 *          singleton `ffi_type` object.
 * @param state The current state of the parser.
 * @return A pointer to the static `ffi_type` for the primitive, or `nullptr` if
 *         the character is not a valid primitive specifier.
 */
static ffi_type * parse_primitive(parser_state * state) {
    if (*state->p == FFI_SIG_VOID) {
        state->p++;
        return ffi_type_create_void();
    }
    ffi_primitive_type_id id;
    switch (*state->p) {
    case FFI_SIG_BOOL:
        id = FFI_PRIMITIVE_TYPE_BOOL;
        break;
    case FFI_SIG_SINT8:
        id = FFI_PRIMITIVE_TYPE_SINT8;
        break;
    case FFI_SIG_UINT8:
    case FFI_SIG_CHAR:
        id = FFI_PRIMITIVE_TYPE_UINT8;
        break;
    case FFI_SIG_SINT16:
        id = FFI_PRIMITIVE_TYPE_SINT16;
        break;
    case FFI_SIG_UINT16:
        id = FFI_PRIMITIVE_TYPE_UINT16;
        break;
    case FFI_SIG_SINT32:
        id = FFI_PRIMITIVE_TYPE_SINT32;
        break;
    case FFI_SIG_UINT32:
        id = FFI_PRIMITIVE_TYPE_UINT32;
        break;
    case FFI_SIG_SINT64:
    case FFI_SIG_LONG:
        id = FFI_PRIMITIVE_TYPE_SINT64;
        break;
    case FFI_SIG_UINT64:
    case FFI_SIG_ULONG:
        id = FFI_PRIMITIVE_TYPE_UINT64;
        break;
    case FFI_SIG_SINT128:
        id = FFI_PRIMITIVE_TYPE_SINT128;
        break;
    case FFI_SIG_UINT128:
        id = FFI_PRIMITIVE_TYPE_UINT128;
        break;
    case FFI_SIG_FLOAT:
        id = FFI_PRIMITIVE_TYPE_FLOAT;
        break;
    case FFI_SIG_DOUBLE:
        id = FFI_PRIMITIVE_TYPE_DOUBLE;
        break;
    case FFI_SIG_LONG_DOUBLE:
        id = FFI_PRIMITIVE_TYPE_LONG_DOUBLE;
        break;
    default:
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->p++;
    return ffi_type_create_primitive(id);
}

/**
 * @internal
 * @brief Parses a function pointer signature: `(...) => ...`
 *
 * @details This function is called by `parse_type` when it detects a function pointer.
 * It extracts the inner signature string, recursively calls `ffi_signature_parse` on it,
 * and then constructs an `ffi_type` of category `FFI_TYPE_REVERSE_TRAMPOLINE` with the
 * fully parsed signature metadata.
 *
 * @param state The current state of the parser. The pointer will be advanced past the
 *              entire function pointer signature.
 * @return An `ffi_type*` with detailed function pointer info, or `nullptr` on error.
 */
static ffi_type * parse_function_pointer(parser_state * state) {
    const char * start = state->p;  // Points to '('
    int nest = 0;
    const char * end = start + 1;

    // Find the matching ')' for the function pointer signature
    while (*end != '\0') {
        if (*end == FFI_SIG_FUNC_PTR_START)
            nest++;
        else if (*end == FFI_SIG_FUNC_PTR_END) {
            if (nest == 0)
                break;
            nest--;
        }
        end++;
    }

    if (*end != FFI_SIG_FUNC_PTR_END) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;  // Unmatched parenthesis
        return nullptr;
    }

    // We now have the substring for the inner signature, e.g., "i,d=>v"
    size_t len = end - (start + 1);
    char * sub_signature = arena_alloc(state->arena, len + 1, 1);
    if (!sub_signature) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }
    infix_memcpy(sub_signature, start + 1, len);
    sub_signature[len] = '\0';

    // Recursively parse the inner signature. Note that this uses the same arena,
    // so all memory is managed correctly.
    ffi_type * ret_type = nullptr;
    ffi_type ** arg_types = nullptr;
    size_t num_args, num_fixed;
    ffi_status status = ffi_signature_parse(sub_signature, &state->arena, &ret_type, &arg_types, &num_args, &num_fixed);

    if (status != FFI_SUCCESS) {
        state->last_error = status;
        return nullptr;
    }

    // Now, create the ffi_type that represents this function pointer.
    ffi_type * func_ptr_type = arena_alloc(state->arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (!func_ptr_type) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
        return nullptr;
    }

    // A function pointer has the size and alignment of a regular pointer.
    func_ptr_type->category = FFI_TYPE_REVERSE_TRAMPOLINE;
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
}

/**
 * @internal
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
 *     function constructs the final `ffi_type`. It iterates through the stored dimensions
 *     in reverse order, wrapping the result of the previous steps in `ffi_type` objects for
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
 * @return Returns a pointer to a newly created `ffi_type` object allocated from the
 *         parser's arena. On any parsing failure, it returns `nullptr` and sets the
 *         error state.
 */
static ffi_type * parse_type(parser_state * state) {

    // Prevent a stack overflow from a malicious signature like `{{{{...}}}`.
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    skip_whitespace(state);

    // Parse all prefix array specifiers (e.g., `[10][5]`).
    // These are stored temporarily and applied at the end to correctly handle
    // C's declaration precedence (e.g., array of pointers vs. pointer to array).
    size_t array_dims[MAX_RECURSION_DEPTH];
    int num_dims = 0;
    while (*state->p == FFI_SIG_ARRAY_START) {
        state->p++;  // Consume '['
        skip_whitespace(state);

        // Ensure we don't overflow our temporary dimension storage.
        if (num_dims >= MAX_RECURSION_DEPTH || !parse_size_t(state, &array_dims[num_dims++])) {
            state->depth--;
            return nullptr;
        }

        skip_whitespace(state);
        if (*state->p++ != FFI_SIG_ARRAY_END) {  // Expect a matching ']'
            state->last_error = FFI_ERROR_INVALID_ARGUMENT;
            state->depth--;
            return nullptr;
        }
        skip_whitespace(state);
    }

    // Parse the core base type.
    // This can be a primitive, an aggregate, or a parenthesized expression.
    ffi_type * base_type = nullptr;
    switch (*state->p) {
    case FFI_SIG_STRUCT_START:
        base_type = parse_aggregate(state, FFI_SIG_STRUCT_START, FFI_SIG_STRUCT_END);
        break;
    case FFI_SIG_UNION_START:
        base_type = parse_aggregate(state, FFI_SIG_UNION_START, FFI_SIG_UNION_END);
        break;
    case FFI_SIG_PACKED_STRUCT:
        base_type = parse_packed_struct(state);
        break;
    case FFI_SIG_FUNC_PTR_START:
        {
            // This is the most complex case, requiring a lookahead to distinguish
            // a grouped type `([10]i)` from a function pointer `(i=>v)`.

            // Perform a forward scan to find the matching ')' and see if a
            // top-level "=>" appears within this scope.
            const char * scanner = state->p + 1;
            int nest = 0;
            bool is_func_ptr = false;
            while (*scanner != '\0') {
                if (*scanner == FFI_SIG_FUNC_PTR_START || *scanner == FFI_SIG_STRUCT_START ||
                    *scanner == FFI_SIG_UNION_START) {
                    nest++;
                }
                else if (*scanner == FFI_SIG_FUNC_PTR_END || *scanner == FFI_SIG_STRUCT_END ||
                         *scanner == FFI_SIG_UNION_END) {
                    // If we find a closing bracket at our current nesting level,
                    // that's the end of the group we're interested in.
                    if (nest == 0 && *scanner == FFI_SIG_FUNC_PTR_END)
                        break;
                    if (nest > 0)
                        nest--;
                }
                else if (nest == 0 && strncmp(scanner, FFI_SIG_RETURN_SEPARATOR, 2) == 0) {
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
                    if (*state->p++ != FFI_SIG_FUNC_PTR_END) {
                        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
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
    while (*state->p == FFI_SIG_POINTER) {
        ffi_type * arena_ptr_type = arena_alloc(state->arena, sizeof(ffi_type), _Alignof(ffi_type));
        if (!arena_ptr_type) {
            state->last_error = FFI_ERROR_ALLOCATION_FAILED;
            state->depth--;
            return nullptr;
        }
        // For ABI purposes, all data pointers are identical in size and alignment,
        // so we just wrap the current type in a generic pointer type.
        *arena_ptr_type = *ffi_type_create_pointer();
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
        ffi_type * array_type = nullptr;
        if (ffi_type_create_array_arena(state->arena, &array_type, base_type, array_dims[i]) != FFI_SUCCESS) {
            state->last_error = FFI_ERROR_ALLOCATION_FAILED;
            state->depth--;
            return nullptr;
        }
        base_type = array_type;
    }


    // Decrement recursion depth and return the fully constructed type.
    state->depth--;
    return base_type;
}

/**
 * @internal
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
 *     `ffi_type_create_packed_struct_arena`, passing the user-provided `total_size`,
 *     `alignment`, and the parsed member list to create the final `ffi_type`.
 *
 * @param state [in, out] The current state of the parser. The pointer `state->p` will be
 *              advanced as the packed struct signature is consumed.
 *
 * @return Returns a pointer to a newly created `ffi_type` for the packed struct, allocated
 *         from the parser's arena. Returns `nullptr` on any parsing failure.
 */
static ffi_type * parse_packed_struct(parser_state * state) {
    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    state->p++;  // Consume the 'p' specifier.
    skip_whitespace(state);

    // Parse the (size,align) header.
    if (*state->p++ != FFI_SIG_FUNC_PTR_START) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
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
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (!parse_size_t(state, &alignment)) {
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p++ != FFI_SIG_FUNC_PTR_END) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }
    skip_whitespace(state);
    if (*state->p++ != FFI_SIG_STRUCT_START) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }

    // Parse the member list into a temporary linked list.
    // This is similar to parse_aggregate but enforces the `@offset` syntax.
    typedef struct member_node {
        ffi_struct_member member;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->p != FFI_SIG_STRUCT_END) {
        while (1) {
            skip_whitespace(state);
            // Check for empty/trailing members.
            if (*state->p == FFI_SIG_STRUCT_END) {
                state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }

            const char * p_before_member = state->p;
            const char * name = parse_identifier(state);
            skip_whitespace(state);
            ffi_type * member_type = nullptr;
            size_t offset;

            if (name && *state->p == FFI_SIG_NAME_SEPARATOR) {
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
            if (*state->p++ != FFI_SIG_OFFSET_SEPARATOR) {
                state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
            skip_whitespace(state);
            if (!parse_size_t(state, &offset)) {
                state->depth--;
                return nullptr;
            }

            // Add the parsed member to the linked list.
            member_node * node = arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = FFI_ERROR_ALLOCATION_FAILED;
                state->depth--;
                return nullptr;
            }
            node->member = (ffi_struct_member){.name = name, .type = member_type, .offset = offset};
            node->next = nullptr;
            if (!head) {
                head = tail = node;
            }
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;

            skip_whitespace(state);
            if (*state->p == FFI_SIG_MEMBER_SEPARATOR) {
                state->p++;
                skip_whitespace(state);
                if (*state->p == FFI_SIG_STRUCT_END) {  // Trailing comma.
                    state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                    state->depth--;
                    return nullptr;
                }
            }
            else if (*state->p == FFI_SIG_STRUCT_END) {
                break;
            }
            else {
                state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
        }
    }
    state->p++;  // Consume '}'.

    // An empty member list `p(1,1){}` is considered invalid.
    if (num_members == 0) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        state->depth--;
        return nullptr;
    }

    // Convert the linked list into a contiguous array.
    ffi_struct_member * members =
        arena_alloc(state->arena, sizeof(ffi_struct_member) * num_members, _Alignof(ffi_struct_member));
    if (!members) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
        state->depth--;
        return nullptr;
    }

    member_node * current = head;
    for (size_t i = 0; i < num_members; ++i) {
        members[i] = current->member;
        current = current->next;
    }

    // Create the final ffi_type for the packed struct.
    ffi_type * packed_type = nullptr;
    if (ffi_type_create_packed_struct_arena(state->arena, &packed_type, total_size, alignment, members, num_members) !=
        FFI_SUCCESS) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
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
 *     array of `ffi_struct_member` is allocated from the arena with the exact size required.
 *     The data from the linked list is then copied into this final array.
 * 6.  **Aggregate Type Creation**: Finally, it calls either `ffi_type_create_struct_arena` or
 *     `ffi_type_create_union_arena` to construct the final `ffi_type` object for the
 *     aggregate, which calculates the aggregate's final size and alignment based on its members.
 *
 * @param state [in, out] The current state of the parser. The pointer `state->p` will be
 *              advanced as the aggregate is consumed.
 * @param start_char [in] The opening character that triggered the call (`{` or `<`).
 * @param end_char [in] The expected closing character (`}` or `>`).
 *
 * @return Returns a pointer to a newly created `ffi_type` for the struct or union,
 *         allocated from the parser's arena. Returns `nullptr` on any parsing failure.
 */
static ffi_type * parse_aggregate(parser_state * state, char start_char, char end_char) {

    if (state->depth >= MAX_RECURSION_DEPTH) {
        state->last_error = FFI_ERROR_INVALID_ARGUMENT;
        return nullptr;
    }
    state->depth++;

    state->p++;  // Consume the start character ('{' or '<').
    skip_whitespace(state);

    // Parse members into a temporary linked list.
    // This avoids reallocating an array of members as we discover them one by one.
    typedef struct member_node {
        ffi_struct_member member;
        struct member_node * next;
    } member_node;
    member_node *head = nullptr, *tail = nullptr;
    size_t num_members = 0;

    // If the next character is not the end character, we expect a list of members.
    if (*state->p != end_char) {
        while (1) {
            skip_whitespace(state);
            // Check for syntax errors like a leading comma `{,i}` or an empty member `{i,,d}`.
            if (*state->p == end_char || *state->p == FFI_SIG_MEMBER_SEPARATOR || *state->p == '\0') {
                state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }

            // Store current position in case we don't find a named member.
            const char * p_before_member = state->p;

            // Attempt to parse an optional name, e.g., "my_member:".
            const char * name = parse_identifier(state);
            skip_whitespace(state);

            if (name && *state->p == FFI_SIG_NAME_SEPARATOR) {
                state->p++;  // Consume ':'
                skip_whitespace(state);
                // Check for a name with no type, e.g., `{name:}`.
                if (*state->p == end_char) {
                    state->last_error = FFI_ERROR_INVALID_ARGUMENT;
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
            ffi_type * member_type = parse_type(state);
            if (!member_type) {
                state->depth--;
                return nullptr;  // Propagate failure.
            }

            // Add the successfully parsed member to our linked list.
            member_node * node = arena_alloc(state->arena, sizeof(member_node), _Alignof(member_node));
            if (!node) {
                state->last_error = FFI_ERROR_ALLOCATION_FAILED;
                state->depth--;
                return nullptr;
            }
            node->member = (ffi_struct_member){.name = name, .type = member_type, .offset = 0};
            node->next = nullptr;
            if (!head)
                head = tail = node;
            else {
                tail->next = node;
                tail = node;
            }
            num_members++;

            skip_whitespace(state);
            if (*state->p == FFI_SIG_MEMBER_SEPARATOR) {
                // Found a comma, so we expect another member.
                state->p++;
                skip_whitespace(state);
                // Check for a trailing comma, e.g., `{i,}`.
                if (*state->p == end_char) {
                    state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                    state->depth--;
                    return nullptr;
                }
            }
            else if (*state->p == end_char)
                // Found the end character, so this is the last member.
                break;
            else {
                // Found an invalid character between members.
                state->last_error = FFI_ERROR_INVALID_ARGUMENT;
                state->depth--;
                return nullptr;
            }
        }
    }
    state->p++;  // Consume the end character ('}' or '>').

    // Convert the linked list into a contiguous array.
    ffi_struct_member * members = num_members > 0
        ? arena_alloc(state->arena, sizeof(ffi_struct_member) * num_members, _Alignof(ffi_struct_member))
        : nullptr;
    if (num_members > 0 && !members) {
        state->last_error = FFI_ERROR_ALLOCATION_FAILED;
        state->depth--;
        return nullptr;
    }

    member_node * current = head;
    for (size_t i = 0; i < num_members; ++i) {
        members[i] = current->member;
        current = current->next;
    }

    // Create the final ffi_type for the aggregate.
    // This call will also calculate the aggregate's size and alignment.
    ffi_type * agg_type = nullptr;
    ffi_status status = (start_char == FFI_SIG_STRUCT_START)
        ? ffi_type_create_struct_arena(state->arena, &agg_type, members, num_members)
        : ffi_type_create_union_arena(state->arena, &agg_type, members, num_members);

    if (status != FFI_SUCCESS) {
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
 * type inspection, or any scenario where an `ffi_type` object graph is needed to
 * describe data outside the context of a function call.
 *
 * ### Process Walkthrough:
 * 1.  **Input Validation**: It performs initial null checks on the input parameters.
 * 2.  **Arena Creation**: It creates a new, dedicated `arena_t` to own all memory
 *     for the resulting `ffi_type` object graph.
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
 * @param[out] out_type On success, this will point to the newly created `ffi_type` that
 *                      represents the parsed signature. This pointer is an allocation
 *                      within the returned arena and is valid only for its lifetime.
 *
 * @param[out] out_arena On success, this will point to the new `arena_t` that owns the
 *                       entire `ffi_type` object graph. The caller is responsible for
 *                       destroying this arena with `arena_destroy()`. On failure, this
 *                       will be set to `NULL`.
 *
 * @param[in]  signature A null-terminated string describing the data type to be parsed.
 *                       e.g., `"i"`, `"d*"`, `"{s,[10]c}"`, `"[10]{name:c*, id:i}"`
 *
 * @return Returns `FFI_SUCCESS` if the entire string was successfully parsed into a single,
 *         valid type.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if any parameters are null, the signature
 *         string is malformed, or if the string contains trailing characters after a
 *         valid type definition.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if the internal memory arena could not be
 *         created.
 *
 * @note **Memory Management**: On a successful return (`FFI_SUCCESS`), the caller assumes
 *       ownership of the arena returned via the `out_arena` parameter. A single call to
 *       `arena_destroy(*out_arena)` is the necessary and sufficient action to free all
 *       memory associated with the parsed type graph.
 */
c23_nodiscard ffi_status ffi_type_from_signature(ffi_type ** out_type, arena_t ** out_arena, const char * signature) {

    if (!out_type || !out_arena || !signature)
        return FFI_ERROR_INVALID_ARGUMENT;
    if (*signature == '\0')
        return FFI_ERROR_INVALID_ARGUMENT;  // Empty string is not a valid type.

    // Create a dedicated arena for this parsing operation.
    // All subsequent allocations for the ffi_type graph will come from this arena.
    arena_t * arena = arena_create(4096);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    // Initialize the parser state and invoke the core parsing engine.
    parser_state state = {.p = signature, .arena = arena, .depth = 0, .last_error = FFI_SUCCESS};
    ffi_type * type = parse_type(&state);

    // Validate the result.
    if (type) {
        skip_whitespace(&state);
        // A successful parse must consume the ENTIRE string. If characters are
        // left over, it's a syntax error (e.g., "i* d" or "i[10]").
        if (*state.p != '\0') {
            type = nullptr;  // Invalidate the result.
            state.last_error = FFI_ERROR_INVALID_ARGUMENT;
        }
    }

    // Handle success or failure.
    if (!type) {
        // If parsing failed for any reason (syntax error, allocation failure, etc.),
        // destroy the arena and all its contents before returning.
        arena_destroy(arena);
        *out_arena = nullptr;
        *out_type = nullptr;
        // Return the specific error captured by the parser, or a generic one.
        return state.last_error != FFI_SUCCESS ? state.last_error : FFI_ERROR_INVALID_ARGUMENT;
    }

    // Transfer ownership of the arena and the parsed type to the caller.
    *out_type = type;
    *out_arena = arena;
    return FFI_SUCCESS;
}

/**
 * @brief Parses a full function signature string into its constituent ffi_type parts.
 *
 * @details
 * This is a key high-level function that acts as the primary bridge from the user-friendly
 * string format to the library's internal `ffi_type` graph representation. It is designed
 * for advanced use cases where the caller needs to inspect the parsed type information
 * before generating a trampoline, or for manually driving the FFI generation process.
 *
 * For simpler use cases, it is recommended to use `ffi_create_forward_trampoline_from_signature`
 * or `ffi_create_reverse_trampoline_from_signature`, which wrap this function and handle
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
 *     to generate its corresponding `ffi_type` object.
 * 5.  **Assemble Final Structures**: The parsed `ffi_type` objects for the arguments are
 *     collected from a temporary linked list into a final, contiguous array. All
 *     allocations are made from the single arena created at the start of the process.
 *
 * @param[in]  signature A null-terminated string describing the function signature.
 *                       See the project's main documentation for the full signature language grammar.
 *                       Example: `"{i,d*}, [10]c; p(1,1){c@0} => (i=>v)*`
 *
 * @param[out] out_arena On success, this parameter will be populated with a pointer to the newly
 *                       created `arena_t`. This arena owns the memory for the *entire* parsed
 *                       type graph, including the return type, the argument types, and the array
 *                       that holds the argument type pointers. On failure, this will be `NULL`.
 *                       **The caller is responsible for destroying this arena** with `arena_destroy()`.
 *
 * @param[out] out_ret_type On success, this will point to the `ffi_type` for the return value.
 *                          This pointer is an allocation within the `*out_arena` and is valid only
 *                          for the lifetime of that arena.
 *
 * @param[out] out_arg_types On success, this will point to an array of `ffi_type*` pointers, one
 *                           for each argument. This array and the types it points to are all
 *                           allocated within the `*out_arena`.
 *
 * @param[out] out_num_args On success, this will be set to the total number of parsed arguments
 *                          (both fixed and variadic).
 *
 * @param[out] out_num_fixed_args On success, this will be set to the number of non-variadic
 *                                arguments (i.e., the arguments that appear before a `;` separator).
 *
 * @return Returns `FFI_SUCCESS` if the entire signature was parsed successfully.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if any of the `out` parameters are null, or if the
 *         signature string is empty, malformed, or contains syntax errors.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if the internal arena or any of its sub-allocations
 *         could not be completed.
 *
 * @note **Memory Ownership**: On a successful return (`FFI_SUCCESS`), this function transfers
 *       ownership of the newly created arena to the caller. A single call to
 *       `arena_destroy(*out_arena)` is the correct and only way to free all memory
 *       associated with the parsed types. If the function fails, it performs its own cleanup,
 *       and `*out_arena` will be set to `NULL`.
 */
c23_nodiscard ffi_status ffi_signature_parse(const char * signature,
                                             arena_t ** out_arena,
                                             ffi_type ** out_ret_type,
                                             ffi_type *** out_arg_types,
                                             size_t * out_num_args,
                                             size_t * out_num_fixed_args) {
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args)
        return FFI_ERROR_INVALID_ARGUMENT;
    *out_arena = nullptr;  // Ensure out-parameter is null on early exit.

    // Find the top-level return separator "=>".
    // We cannot use a simple `strstr` because a function pointer argument might
    // also contain "=>". We must perform a scan that respects nesting levels
    // of parentheses `()`, braces `{}`, and angle brackets `<>`.
    const char * p = signature;
    int nest_level = 0;
    const char * return_sep = NULL;
    while (*p != '\0') {
        if (*p == FFI_SIG_FUNC_PTR_START || *p == FFI_SIG_STRUCT_START || *p == FFI_SIG_UNION_START)
            nest_level++;
        else if (*p == FFI_SIG_FUNC_PTR_END || *p == FFI_SIG_STRUCT_END || *p == FFI_SIG_UNION_END) {
            if (nest_level > 0)
                nest_level--;
        }
        else if (nest_level == 0 && strncmp(p, FFI_SIG_RETURN_SEPARATOR, 2) == 0) {
            return_sep = p;  // Found the separator at the top level.
            break;
        }
        p++;
    }

    // If no separator was found, the signature is invalid.
    if (!return_sep)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Parse the return type part (everything after "=>").
    const char * ret_part_str = return_sep + strlen(FFI_SIG_RETURN_SEPARATOR);
    {  // A quick sanity check to ensure there's something to parse after "=>".
        parser_state temp_state = {.p = ret_part_str};
        skip_whitespace(&temp_state);
        if (*temp_state.p == '\0')
            return FFI_ERROR_INVALID_ARGUMENT;  // No return type specified.
    }

    // The arena will hold all allocated types for this signature.
    // If the caller (like `parse_function_pointer`) provides an arena, we use it.
    // Otherwise, we create a new one and transfer ownership to the caller on success.
    arena_t * arena = *out_arena;
    if (arena == NULL) {
        arena = arena_create(8192);
        if (!arena)
            return FFI_ERROR_ALLOCATION_FAILED;
    }

    parser_state state = {.p = ret_part_str, .arena = arena, .depth = 0, .last_error = FFI_SUCCESS};

    *out_ret_type = parse_type(&state);
    if (!*out_ret_type)
        goto error;  // `parse_type` failed.
    skip_whitespace(&state);
    if (*state.p != '\0') {  // Check for junk after a valid return type.
        state.last_error = FFI_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    // Isolate and copy the arguments part into a mutable buffer.
    // This is necessary because the tokenization process needs to work with a
    // substring, and we can't modify the original `const char *`.
    size_t args_part_len = return_sep - signature;
    char * args_str_mut = arena_alloc(arena, args_part_len + 1, 1);
    if (!args_str_mut) {
        state.last_error = FFI_ERROR_ALLOCATION_FAILED;
        goto error;
    }
    infix_memcpy(args_str_mut, signature, args_part_len);
    args_str_mut[args_part_len] = '\0';

    // Tokenize and parse the arguments string.
    // This loop identifies argument tokens separated by `,` or `;` while respecting
    // nested structures.
    typedef struct type_node {
        ffi_type * type;
        struct type_node * next;
    } type_node;
    type_node *head = nullptr, *tail = nullptr;
    size_t num_args = 0, num_fixed = 0;
    bool in_variadic = false;

    const char * p_arg = args_str_mut;

    // Handle the case where the function is variadic-only, e.g., ";i=>v"
    parser_state temp_arg_state = {.p = p_arg};
    skip_whitespace(&temp_arg_state);
    p_arg = temp_arg_state.p;
    if (*p_arg == FFI_SIG_VARIADIC_SEPARATOR) {
        in_variadic = true;
        p_arg++;
    }

    const char * arg_start = p_arg;
    nest_level = 0;

    // We only enter the loop if the argument string is not empty.
    if (*arg_start != '\0') {
        for (;; p_arg++) {
            char current_char = *p_arg;
            // A token ends at a separator (`,` or `;`) or at the end of the string,
            // but only if we are not inside a nested group.
            if (nest_level == 0 &&
                (current_char == FFI_SIG_MEMBER_SEPARATOR || current_char == FFI_SIG_VARIADIC_SEPARATOR ||
                 current_char == '\0')) {
                size_t len = p_arg - arg_start;
                char * token = arena_alloc(arena, len + 1, 1);
                if (!token) {
                    state.last_error = FFI_ERROR_ALLOCATION_FAILED;
                    goto error;
                }
                infix_memcpy(token, arg_start, len);
                token[len] = '\0';

                parser_state token_state = {.p = token, .arena = arena, .depth = 0};
                skip_whitespace(&token_state);

                // An empty token is a syntax error (e.g., `i,,d` or `i, => v`).
                // It's only valid if the entire argument string part was empty (for no-arg functions).
                if (*token_state.p == '\0') {
                    if (args_part_len > 0) {  // Fails "i,=>v", "i,;d=>v", etc.
                        state.last_error = FFI_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }
                }
                else {
                    // Parse the extracted token as a type.
                    ffi_type * arg_type = parse_type(&token_state);
                    if (!arg_type) {
                        state.last_error = token_state.last_error ? token_state.last_error : FFI_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }

                    skip_whitespace(&token_state);
                    if (*token_state.p != '\0') {
                        state.last_error = FFI_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }  // Junk after arg type

                    // Add the parsed type to our temporary linked list.
                    type_node * node = arena_alloc(arena, sizeof(type_node), _Alignof(type_node));
                    if (!node) {
                        state.last_error = FFI_ERROR_ALLOCATION_FAILED;
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

                if (current_char == FFI_SIG_VARIADIC_SEPARATOR) {
                    if (in_variadic) {
                        state.last_error = FFI_ERROR_INVALID_ARGUMENT;
                        goto error;
                    }  // Multiple semicolons
                    in_variadic = true;
                }
                if (current_char == '\0')
                    break;              // End of arguments string.
                arg_start = p_arg + 1;  // Start of the next token.
            }
            else if (current_char == FFI_SIG_STRUCT_START || current_char == FFI_SIG_UNION_START ||
                     current_char == FFI_SIG_FUNC_PTR_START)
                nest_level++;
            else if (current_char == FFI_SIG_STRUCT_END || current_char == FFI_SIG_UNION_END ||
                     current_char == FFI_SIG_FUNC_PTR_END) {
                if (nest_level > 0)
                    nest_level--;
            }
            else if (current_char == '\0') {
                if (nest_level != 0) {
                    state.last_error = FFI_ERROR_INVALID_ARGUMENT;
                    goto error;
                }  // Mismatched brackets
                p_arg--;  // Re-align for loop termination condition.
            }
        }
    }

    // Convert the temporary linked list of types into a final array.
    // This provides a standard C array for the caller to use.
    ffi_type ** arg_types =
        num_args > 0 ? arena_alloc(arena, sizeof(ffi_type *) * num_args, _Alignof(ffi_type *)) : nullptr;
    if (num_args > 0 && !arg_types) {
        state.last_error = FFI_ERROR_ALLOCATION_FAILED;
        goto error;
    }

    type_node * current = head;
    for (size_t i = 0; i < num_args; ++i) {
        arg_types[i] = current->type;
        current = current->next;
    }

    // If we created the arena, transfer its ownership to the caller.
    if (*out_arena == NULL)
        *out_arena = arena;

    *out_arg_types = arg_types;
    *out_num_args = num_args;
    *out_num_fixed_args = num_fixed;
    return FFI_SUCCESS;

// A single cleanup point for all failure paths.
error:
    // Only destroy the arena if this function created it. If it was passed in
    // (e.g., from a recursive call in `parse_function_pointer`), the original
    // caller is responsible for its cleanup.
    if (*out_arena == NULL)
        arena_destroy(arena);
    // The last recorded error is returned, defaulting to a generic invalid argument.
    return state.last_error != FFI_SUCCESS ? state.last_error : FFI_ERROR_INVALID_ARGUMENT;
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
 * 1.  **Parse Signature**: It first calls `ffi_signature_parse` to parse the input string.
 *     This step creates a temporary memory arena and populates it with the `ffi_type`
 *     object graph that describes the function's return type and argument types.
 * 2.  **Generate Trampoline**: If parsing succeeds, it passes the resulting `ffi_type`
 *     graph and other metadata (number of arguments, etc.) to the core `generate_forward_trampoline`
 *     function. This is the step where the machine code is actually generated and placed
 *     into executable memory.
 * 3.  **Automatic Cleanup**: Crucially, regardless of whether the trampoline generation
 *     succeeds or fails, this function ensures that the temporary arena and all the
 *     `ffi_type` objects created in step 1 are destroyed before returning. This completely
 *     automates memory management for the type system, preventing leaks and simplifying
 *     the caller's code.
 *
 * @param[out] out_trampoline On success, this will be populated with a pointer to a newly
 *                            allocated `ffi_trampoline_t` handle. This handle is the primary
 *                            object used to interact with the JIT-compiled code. The caller
 *                            is responsible for freeing this handle with `ffi_trampoline_free()`.
 *
 * @param[in] signature A null-terminated string describing the C function's signature.
 *                      The format is `"arg1,arg2;variadic_arg=>ret_type"`. See the main
 *                      project documentation for the full grammar.
 *                      Example: `"i*,i=>i"` for `int printf(const char*, int)`.
 *
 * @return Returns `FFI_SUCCESS` if the trampoline was successfully created.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if the `out_trampoline` parameter is null or
 *         if the signature string is malformed.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if any internal memory allocation fails during
 *         either parsing or JIT compilation.
 * @return Returns other `ffi_status` error codes on failures during the JIT compilation
 *         process (e.g., `FFI_ERROR_PROTECTION_FAILED`).
 *
 * @note **Memory Ownership**: The caller is responsible for destroying the `ffi_trampoline_t` object
 *       returned via the `out_trampoline` parameter by calling `ffi_trampoline_free()`. All
 *       intermediate memory used for parsing the signature is managed automatically by this function.
 *
 * @see ffi_signature_parse()
 * @see generate_forward_trampoline()
 * @see ffi_trampoline_free()
 * @see ffi_trampoline_get_code()
 */
c23_nodiscard ffi_status ffi_create_forward_trampoline_from_signature(ffi_trampoline_t ** out_trampoline,
                                                                      const char * signature) {
    arena_t * arena = nullptr;
    ffi_type * ret_type = nullptr;
    ffi_type ** arg_types = nullptr;
    size_t num_args, num_fixed;

    // Parse the signature string into a ffi_type graph.
    ffi_status status = ffi_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);

    // If parsing failed, `arena` will be null, and we can return the error immediately.
    if (status != FFI_SUCCESS)
        return status;

    // Generate the trampoline using the parsed type information.
    status = generate_forward_trampoline(out_trampoline, ret_type, arg_types, num_args, num_fixed);

    // It is critical to destroy the arena here, regardless of whether the
    // trampoline generation succeeded or failed. This frees the entire ffi_type
    // object graph with a single call because we no longer need it.
    arena_destroy(arena);
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
 * 1.  **Parse Signature**: It first calls `ffi_signature_parse` to parse the input string.
 *     This step creates a temporary memory arena and populates it with the `ffi_type`
 *     object graph that describes the callback's return type and argument types.
 * 2.  **Generate Trampoline**: If parsing succeeds, it passes the resulting `ffi_type`
 *     graph, along with the user-provided callback function and user data, to the core
 *     `generate_reverse_trampoline` function. This step JIT-compiles the callable stub
 *     and sets up the internal context required for the callback mechanism.
 * 3.  **Automatic Cleanup**: Just like its forward-trampoline counterpart, this function
 *     ensures that the temporary arena and all the `ffi_type` objects created during
 *     parsing are destroyed before returning. This happens regardless of whether the
 *     trampoline generation succeeds or fails, guaranteeing that no memory is leaked.
 *
 * @param[out] out_context On success, this will be populated with a pointer to a newly
 *                         allocated `ffi_reverse_trampoline_t` handle. This handle contains
 *                         the executable code pointer and all the context for the callback.
 *                         The caller is responsible for freeing this handle with
 *                         `ffi_reverse_trampoline_free()`.
 *
 * @param[in] signature A null-terminated string describing the C callback's signature.
 *                      The format is `"arg1,arg2;variadic_arg=>ret_type"`.
 *                      Example: `"i,i=>i"` for a callback that takes two `int`s and returns an `int`.
 *
 * @param[in] user_callback_fn A function pointer to the user's actual C handler. Its C signature
 *                             must logically match the signature described in the string.
 *
 * @param[in] user_data An arbitrary, opaque pointer that will be associated with this callback.
 *                      It can be retrieved later using `ffi_reverse_trampoline_get_user_data()`.
 *                      This is useful for passing state to a stateful callback.
 *
 * @return Returns `FFI_SUCCESS` if the callback trampoline was successfully created.
 * @return Returns `FFI_ERROR_INVALID_ARGUMENT` if any of the `out` parameters are null or
 *         if the signature string is malformed.
 * @return Returns `FFI_ERROR_ALLOCATION_FAILED` if any internal memory allocation fails.
 * @return Returns other `ffi_status` error codes on failures during the JIT compilation
 *         process.
 *
 * @note **Memory Ownership**: The caller is responsible for destroying the `ffi_reverse_trampoline_t`
 *       object returned via the `out_context` parameter by calling `ffi_reverse_trampoline_free()`.
 *       All intermediate memory used for parsing the signature is managed automatically.
 *
 * @see ffi_signature_parse()
 * @see generate_reverse_trampoline()
 * @see ffi_reverse_trampoline_free()
 * @see ffi_reverse_trampoline_get_code()
 * @see ffi_reverse_trampoline_get_user_data()
 */
c23_nodiscard ffi_status ffi_create_reverse_trampoline_from_signature(ffi_reverse_trampoline_t ** out_context,
                                                                      const char * signature,
                                                                      void * user_callback_fn,
                                                                      void * user_data) {
    arena_t * arena = nullptr;
    ffi_type * ret_type = nullptr;
    ffi_type ** arg_types = nullptr;
    size_t num_args, num_fixed;

    // This creates a temporary arena and populates it with the ffi_type graph.
    ffi_status status = ffi_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed);

    // If parsing failed, `arena` will be null, and we can return the error immediately.
    if (status != FFI_SUCCESS)
        return status;

    // Generate the trampoline using the parsed type information and user data.
    status =
        generate_reverse_trampoline(out_context, ret_type, arg_types, num_args, num_fixed, user_callback_fn, user_data);

    arena_destroy(arena);
    return status;
}
