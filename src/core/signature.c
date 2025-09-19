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
 * @brief Implements the high-level FFI signature parsing API.
 * @details This file contains a recursive-descent parser that translates a
 * human-readable signature string into the `ffi_type` object graph required
 * by the core trampoline generator. The parser is designed to be robust,
 * handling complex nested types, variadic arguments, and packed structs.
 *
 * ### Parser Strategy
 * The parser follows a classic recursive-descent approach. The main entry point
 * for parsing any type is the `parse_type` function, which acts as a dispatcher.
 * It determines the kind of type to parse based on the leading character(s)
 * and calls a specialized function for that construct (e.g., `parse_aggregate` for
 * structs, `parse_array` for arrays). This design allows for natural handling of
 * nested types, like an array of structs.
 *
 * ### Memory Management
 * All `ffi_type` and `ffi_struct_member` objects created during a parse are
 * allocated from a single memory arena. This strategy is highly efficient,
 * replacing potentially thousands of small `malloc` calls with simple pointer
 * bumps. More importantly, it dramatically simplifies memory management. The
 * high-level public API functions (`ffi_create_*_from_signature`) create an
 * arena, use it for the entire parsing and trampoline generation process, and then
 * destroy the arena in a single call, freeing all associated memory at once.
 *
 * ### Error Handling
 * The parser uses a "sticky" error flag within the `parser_state_t` struct.
 * If any parsing function encounters a syntax error, it sets `state->error`
 * and returns `NULL`. All other parsing functions check this flag at entry and
 * will immediately return `NULL` if it is set, preventing cascading error
 * messages and ensuring a clean, fast failure.
 */

#include <ctype.h>
#include <infix.h>
#include <stdlib.h>
#include <string.h>

//================================================================================
// Internal Parser State and Helpers
//================================================================================

/**
 * @internal
 * @brief Holds the state of the parser as it consumes the signature string.
 * @details This struct is passed by pointer to all parsing functions, allowing
 * them to advance through the input string and share state (like the arena
 * and a sticky error flag) without using global variables.
 */
typedef struct {
    const char * current;  ///< A pointer to the current character being processed in the signature string.
    arena_t * arena;       ///< The arena from which all `ffi_type` objects for this parse will be allocated.
    ffi_status error;  ///< A sticky error flag. If set, subsequent parsing functions will immediately return `NULL`.
} parser_state_t;

// Forward declarations for recursive parsing functions
static ffi_type * parse_type(parser_state_t * state);
static ffi_type * parse_primitive(parser_state_t * state);
static ffi_type * parse_aggregate(parser_state_t * state, char open, char close, bool is_union);
static ffi_type * parse_packed_struct(parser_state_t * state);
static ffi_type * parse_array(parser_state_t * state);
static ffi_type * parse_function_pointer(parser_state_t * state);

/** @internal @brief Advances the parser's cursor past any leading whitespace. */
static void skip_whitespace(parser_state_t * state) {
    while (isspace((unsigned char)*state->current)) {
        state->current++;
    }
}

/**
 * @internal
 * @brief Consumes the next non-whitespace character if it matches `expected`.
 * @return `true` if the character was found and consumed, `false` otherwise.
 */
static bool consume(parser_state_t * state, char expected) {
    skip_whitespace(state);
    if (*state->current == expected) {
        state->current++;
        return true;
    }
    return false;
}

/**
 * @internal
 * @brief Parses an unsigned integer from the string and advances the cursor.
 * @return `true` on success, `false` on parsing failure.
 */
static bool parse_size_t(parser_state_t * state, size_t * out_val) {
    skip_whitespace(state);
    char * end;
    // Use strtoull for C89 compatibility and portability with 64-bit size_t.
    unsigned long long val = strtoull(state->current, &end, 10);
    if (end == state->current) {  // No digits were parsed
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return false;
    }
    *out_val = (size_t)val;
    state->current = end;
    return true;
}

/**
 * @internal
 * @brief Parses a C-style identifier (e.g., for a struct field name).
 *        An identifier must start with a letter or underscore, and may be
 *        followed by letters, numbers, or underscores.
 * @return A pointer to a null-terminated string allocated within the arena,
 *         or `NULL` if a valid identifier is not found at the current position.
 */
static const char * parse_identifier(parser_state_t * state) {
    skip_whitespace(state);
    const char * start = state->current;
    if (!isalpha((unsigned char)*start) && *start != '_') {
        return NULL;  // Not a valid start for an identifier.
    }
    while (isalnum((unsigned char)*state->current) || *state->current == '_') {
        state->current++;
    }
    const char * end = state->current;
    size_t len = end - start;
    if (len == 0)
        return NULL;

    // Allocate space in the arena for the identifier and copy it.
    char * name = arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    memcpy(name, start, len);
    name[len] = '\0';
    return name;
}


//================================================================================
// Core Parsing Logic
//================================================================================

/**
 * @internal
 * @brief The main dispatcher for parsing a single type. It handles prefix
 *        constructs (like `[`, `{`, `p`) and then checks for any postfix
 *        modifiers (like `*` for pointers). This recursive structure allows
 *        it to handle arbitrarily complex nested types like `[10]{i,d*}*`.
 * @param state The current state of the parser.
 * @return A pointer to the parsed `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_type(parser_state_t * state) {
    // If a previous parsing step failed, abort immediately.
    if (state->error)
        return NULL;
    skip_whitespace(state);

    ffi_type * base_type = NULL;

    // Dispatch to a specialized parsing function based on the next character.
    if (isalpha((unsigned char)*state->current)) {
        if (*state->current == 'p') {
            base_type = parse_packed_struct(state);
        }
        else {
            base_type = parse_primitive(state);
        }
    }
    else if (*state->current == '{') {
        base_type = parse_aggregate(state, '{', '}', false);
    }
    else if (*state->current == '<') {
        base_type = parse_aggregate(state, '<', '>', true);
    }
    else if (*state->current == '[') {
        base_type = parse_array(state);
    }
    else if (*state->current == '(') {
        base_type = parse_function_pointer(state);
    }
    else {
        // If the character doesn't start a known type, it's a syntax error.
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // If the base type failed to parse, propagate the failure up.
    if (!base_type)
        return NULL;

    // After parsing a base type, loop to handle any postfix pointer modifiers.
    // This correctly handles multiple levels of indirection, e.g., `i**`.
    while (consume(state, '*')) {
        ffi_type * ptr_type = arena_alloc(state->arena, sizeof(ffi_type), _Alignof(ffi_type));
        if (!ptr_type) {
            state->error = FFI_ERROR_ALLOCATION_FAILED;
            return NULL;
        }
        *ptr_type = *ffi_type_create_pointer();  // Copy the static singleton pointer type.
        ptr_type->is_arena_allocated = true;
        base_type = ptr_type;  // The new base type is now the pointer type.
    }

    return base_type;
}

/**
 * @internal
 * @brief Parses a single-character primitive type code from the Itanium ABI mapping.
 * @param state The current state of the parser.
 * @return A pointer to the corresponding static primitive `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_primitive(parser_state_t * state) {
    if (state->error)
        return NULL;
    ffi_primitive_type_id id;
    switch (*state->current++) {
    case 'v':
        return ffi_type_create_void();
    case 'b':
        id = FFI_PRIMITIVE_TYPE_BOOL;
        break;
    case 'a':
        id = FFI_PRIMITIVE_TYPE_SINT8;
        break;
    case 'c':
        {
            // `char` is special; its signedness is implementation-defined.
            // This compile-time check resolves it to the correct concrete type for the target platform.
            char x = -1;
            if (x < 0) {
                id = FFI_PRIMITIVE_TYPE_SINT8;
            }
            else {
                id = FFI_PRIMITIVE_TYPE_UINT8;
            }
            break;
        }
    case 'h':
        id = FFI_PRIMITIVE_TYPE_UINT8;
        break;
    case 's':
        id = FFI_PRIMITIVE_TYPE_SINT16;
        break;
    case 't':
        id = FFI_PRIMITIVE_TYPE_UINT16;
        break;
    case 'i':
        id = FFI_PRIMITIVE_TYPE_SINT32;
        break;
    case 'j':
        id = FFI_PRIMITIVE_TYPE_UINT32;
        break;
    case 'l':
        id = (sizeof(long) == 8) ? FFI_PRIMITIVE_TYPE_SINT64 : FFI_PRIMITIVE_TYPE_SINT32;
        break;
    case 'm':
        id = (sizeof(unsigned long) == 8) ? FFI_PRIMITIVE_TYPE_UINT64 : FFI_PRIMITIVE_TYPE_UINT32;
        break;
    case 'x':
        id = FFI_PRIMITIVE_TYPE_SINT64;
        break;
    case 'y':
        id = FFI_PRIMITIVE_TYPE_UINT64;
        break;
    case 'n':
        id = FFI_PRIMITIVE_TYPE_SINT128;
        break;
    case 'o':
        id = FFI_PRIMITIVE_TYPE_UINT128;
        break;
    case 'f':
        id = FFI_PRIMITIVE_TYPE_FLOAT;
        break;
    case 'd':
        id = FFI_PRIMITIVE_TYPE_DOUBLE;
        break;
    case 'e':
        id = FFI_PRIMITIVE_TYPE_LONG_DOUBLE;
        break;
    default:
        state->current--;  // Un-consume the invalid character for better error reporting.
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    return ffi_type_create_primitive(id);
}

/**
 * @internal
 * @brief Parses a standard (non-packed) struct `{...}` or union `<...>`, including support for named fields.
 * @param state The current state of the parser.
 * @param open The opening delimiter (`{` or `<`).
 * @param close The closing delimiter (`}` or `>`).
 * @param is_union If true, creates a union; otherwise, creates a struct.
 * @return A pointer to the parsed aggregate `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_aggregate(parser_state_t * state, char open, char close, bool is_union) {
    if (!consume(state, open)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // Members are first parsed into a temporary on-stack array for efficiency.
    ffi_struct_member temp_members[64];
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->current != close) {
        while (1) {
            if (num_members >= 64) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return NULL;
            }  // Exceeded max members

            // This is the core lookahead logic to handle optional field names.
            const char * checkpoint = state->current;  // Save position before trying to parse an identifier.
            const char * name = parse_identifier(state);

            if (name && consume(state, ':')) {
                // Success: we parsed "name:", so this is a named field.
                temp_members[num_members].name = name;
                temp_members[num_members].type = parse_type(state);
            }
            else {
                // Failure: No ":" found. The identifier we parsed (if any)
                // must have been the start of a type (e.g., 'i' in "{i,d}").
                // Rewind the parser to the checkpoint and parse the whole thing as a type.
                state->current = checkpoint;
                temp_members[num_members].name = NULL;
                temp_members[num_members].type = parse_type(state);
            }

            if (!temp_members[num_members].type)
                return NULL;                       // Propagate error
            temp_members[num_members].offset = 0;  // Offsets are calculated by the Core API for standard layouts.
            num_members++;

            if (!consume(state, ','))
                break;  // If no comma, this must be the last member.
        }
    }

    if (!consume(state, close)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // Commit the members to a correctly-sized arena allocation.
    ffi_struct_member * members =
        arena_alloc(state->arena, num_members * sizeof(ffi_struct_member), _Alignof(ffi_struct_member));
    if (!members && num_members > 0) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    memcpy(members, temp_members, num_members * sizeof(ffi_struct_member));

    // Create the final ffi_type using the arena-aware Core API functions.
    ffi_type * agg_type = NULL;
    ffi_status status = is_union ? ffi_type_create_union_arena(state->arena, &agg_type, members, num_members)
                                 : ffi_type_create_struct_arena(state->arena, &agg_type, members, num_members);
    if (status != FFI_SUCCESS) {
        state->error = status;
        return NULL;
    }
    return agg_type;
}

/**
 * @internal
 * @brief Parses a packed struct with explicit layout: `p(size,align){type@offset,...}`.
 * @param state The current state of the parser.
 * @return A pointer to the parsed packed struct `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_packed_struct(parser_state_t * state) {
    if (!consume(state, 'p') || !consume(state, '(')) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    size_t total_size, alignment;
    if (!parse_size_t(state, &total_size) || !consume(state, ',') || !parse_size_t(state, &alignment) ||
        !consume(state, ')')) {
        return NULL;
    }
    if (!consume(state, '{')) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    ffi_struct_member temp_members[64];
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->current != '}') {
        while (1) {
            if (num_members >= 64) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return NULL;
            }

            const char * checkpoint = state->current;
            const char * name = parse_identifier(state);
            if (name && consume(state, ':')) {
                temp_members[num_members].name = name;
                temp_members[num_members].type = parse_type(state);
            }
            else {
                state->current = checkpoint;
                temp_members[num_members].name = NULL;
                temp_members[num_members].type = parse_type(state);
            }

            if (!temp_members[num_members].type)
                return NULL;
            // The "@offset" part is mandatory for every member of a packed struct.
            if (!consume(state, '@') || !parse_size_t(state, &temp_members[num_members].offset)) {
                return NULL;
            }
            num_members++;

            if (!consume(state, ','))
                break;
        }
    }

    if (!consume(state, '}')) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    ffi_struct_member * members =
        arena_alloc(state->arena, num_members * sizeof(ffi_struct_member), _Alignof(ffi_struct_member));
    if (!members && num_members > 0) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    memcpy(members, temp_members, num_members * sizeof(ffi_struct_member));

    ffi_type * packed_type = NULL;
    ffi_status status =
        ffi_type_create_packed_struct_arena(state->arena, &packed_type, total_size, alignment, members, num_members);
    if (status != FFI_SUCCESS) {
        state->error = status;
        return NULL;
    }
    return packed_type;
}

/**
 * @internal
 * @brief Parses a fixed-size array `[size]type`. This handles nested arrays
 *        by recursively calling `parse_type` for the element type.
 * @param state The current state of the parser.
 * @return A pointer to the parsed array `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_array(parser_state_t * state) {
    if (!consume(state, '[')) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    size_t num_elements;
    if (!parse_size_t(state, &num_elements) || !consume(state, ']')) {
        return NULL;
    }

    // Recursively call the main type parser for the element type.
    // This allows for complex types like arrays of structs or arrays of pointers.
    ffi_type * element_type = parse_type(state);
    if (!element_type)
        return NULL;

    ffi_type * array_type = NULL;
    ffi_status status = ffi_type_create_array_arena(state->arena, &array_type, element_type, num_elements);
    if (status != FFI_SUCCESS) {
        state->error = status;
        return NULL;
    }
    return array_type;
}

/**
 * @internal
 * @brief Parses a function pointer type `(...)`.
 * @note This is currently a placeholder implementation. It validates the parenthesis
 *       balancing but does not perform a deep parse of the inner signature. From
 *       an ABI perspective, all function pointers are treated as generic `void*`,
 *       so this is sufficient for correct code generation.
 * @param state The current state of the parser.
 * @return A pointer to a generic pointer `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_function_pointer(parser_state_t * state) {
    // These variables are marked as maybe_unused because this function currently
    // only validates and consumes the syntax. A future implementation could
    // perform a deep parse of the inner signature to create a more descriptive
    // ffi_type for reflection purposes.
    c23_maybe_unused ffi_type * ret_type_inner = NULL;
    c23_maybe_unused ffi_type ** arg_types_inner = NULL;
    c23_maybe_unused size_t num_args_inner = 0, num_fixed_inner = 0;

    if (!consume(state, '(')) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // Scan ahead to find the matching closing parenthesis, correctly handling nested parentheses.
    int open_paren = 1;
    while (*state->current && open_paren > 0) {
        if (*state->current == '(')
            open_paren++;
        if (*state->current == ')') {
            open_paren--;
            if (open_paren == 0)
                break;  // Found the match
        }
        state->current++;
    }
    if (open_paren > 0) {  // Unmatched parenthesis
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // For now, we just consume the content without a deep parse.
    state->current++;  // Consume the final ')'

    // From an ABI perspective, all function pointers are treated as a generic `void*`.
    // Therefore, we return the singleton pointer type.
    ffi_type * func_ptr_type = arena_alloc(state->arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (!func_ptr_type) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    *func_ptr_type = *ffi_type_create_pointer();
    func_ptr_type->is_arena_allocated = true;
    return func_ptr_type;
}

//================================================================================
// Public API Implementation
//================================================================================

ffi_status ffi_signature_parse(const char * signature,
                               arena_t ** out_arena,
                               ffi_type ** out_ret_type,
                               ffi_type *** out_arg_types,
                               size_t * out_num_args,
                               size_t * out_num_fixed_args) {
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args) {
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    *out_arena = arena_create(65536);
    if (!*out_arena) {
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    parser_state_t state = {.current = signature, .arena = *out_arena, .error = FFI_SUCCESS};

    ffi_type * temp_args[256];
    size_t num_args = 0;
    size_t num_fixed = 0;
    bool in_variadic_part = false;

    // A valid signature MUST contain the return type separator "=>".
    const char * ret_sep = strstr(signature, "=>");
    if (!ret_sep) {
        arena_destroy(*out_arena);
        *out_arena = NULL;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    skip_whitespace(&state);

    // Check if there are any arguments to parse before the "=>".
    if (state.current < ret_sep) {
        // Handle the edge case of a variadic-only function, e.g., ";i=>v"
        if (*state.current == ';') {
            in_variadic_part = true;
            num_fixed = 0;
            state.current++;
            skip_whitespace(&state);
            // It's a syntax error if there's nothing between ';' and '=>'.
            if (state.current >= ret_sep) {
                state.error = FFI_ERROR_INVALID_ARGUMENT;
                goto cleanup_fail;
            }
        }

        // Main loop for parsing comma- or semicolon-separated arguments.
        while (state.current < ret_sep) {
            if (num_args >= 256) {
                state.error = FFI_ERROR_INVALID_ARGUMENT;
                goto cleanup_fail;
            }

            temp_args[num_args++] = parse_type(&state);
            if (state.error || !temp_args[num_args - 1])
                goto cleanup_fail;

            skip_whitespace(&state);

            // Check for a separator. ',' is a normal separator.
            bool has_sep = consume(&state, ',');
            // ';' is a special separator that marks the transition to variadic args.
            if (!has_sep && consume(&state, ';')) {
                if (in_variadic_part) {
                    state.error = FFI_ERROR_INVALID_ARGUMENT;
                    goto cleanup_fail;
                }  // Error: multiple ';'
                in_variadic_part = true;
                num_fixed = num_args;
                has_sep = true;
            }

            if (!has_sep)
                break;  // No more separators, must be at the end of the arg list.

            // If we consumed a separator, there MUST be another argument.
            skip_whitespace(&state);
            if (state.current >= ret_sep) {
                state.error = FFI_ERROR_INVALID_ARGUMENT;
                goto cleanup_fail;
            }  // Trailing separator
        }
    }

    // If we never saw a ';', then all arguments are fixed.
    if (!in_variadic_part) {
        num_fixed = num_args;
    }

    // The cursor must now be at the return separator. Advance past it.
    state.current = ret_sep + 2;
    *out_ret_type = parse_type(&state);
    if (state.error || !*out_ret_type)
        goto cleanup_fail;

    // After parsing the return type, we must be at the end of the string.
    skip_whitespace(&state);
    if (*state.current != '\0') {
        state.error = FFI_ERROR_INVALID_ARGUMENT;  // Trailing junk characters
        goto cleanup_fail;
    }

    // Success. Finalize the output parameters.
    *out_num_args = num_args;
    *out_num_fixed_args = num_fixed;
    *out_arg_types = arena_alloc(state.arena, num_args * sizeof(ffi_type *), sizeof(void *));
    if (!*out_arg_types && num_args > 0) {
        state.error = FFI_ERROR_ALLOCATION_FAILED;
        goto cleanup_fail;
    }
    if (num_args > 0) {
        memcpy(*out_arg_types, temp_args, num_args * sizeof(ffi_type *));
    }

    return FFI_SUCCESS;

cleanup_fail:
    // This is the single cleanup point for all failure modes. It ensures the
    // arena is always destroyed on error, preventing memory leaks.
    arena_destroy(*out_arena);
    *out_arena = NULL;
    return state.error;
}

ffi_status ffi_type_from_signature(ffi_type ** out_type, arena_t ** out_arena, const char * signature) {
    if (!out_type || !out_arena || !signature) {
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    *out_arena = arena_create(16384);
    if (!*out_arena) {
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    parser_state_t state = {.current = signature, .arena = *out_arena, .error = FFI_SUCCESS};
    *out_type = parse_type(&state);

    skip_whitespace(&state);
    // For a single type, we must have consumed the entire string.
    if (state.error != FFI_SUCCESS || *state.current != '\0' || !*out_type) {
        arena_destroy(*out_arena);
        *out_arena = NULL;
        return (state.error != FFI_SUCCESS) ? state.error : FFI_ERROR_INVALID_ARGUMENT;
    }
    return FFI_SUCCESS;
}

ffi_status ffi_create_forward_trampoline_from_signature(ffi_trampoline_t ** out_trampoline, const char * signature) {
    arena_t * arena = NULL;
    ffi_type * ret_type = NULL;
    ffi_type ** arg_types = NULL;
    size_t num_args, num_fixed_args;

    // Step 1: Parse the signature string. This creates the arena and all ffi_type objects.
    ffi_status status = ffi_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed_args);
    if (status != FFI_SUCCESS) {
        return status;  // On failure, ffi_signature_parse has already cleaned up the arena.
    }

    // Step 2: Generate the trampoline using the parsed types.
    status = generate_forward_trampoline(out_trampoline, ret_type, arg_types, num_args, num_fixed_args);

    // Step 3: Destroy the arena and all the temporary ffi_type objects it contains.
    // The generated trampoline is now self-contained and does not depend on them.
    arena_destroy(arena);
    return status;
}

ffi_status ffi_create_reverse_trampoline_from_signature(ffi_reverse_trampoline_t ** out_context,
                                                        const char * signature,
                                                        void * user_callback_fn,
                                                        void * user_data) {
    arena_t * arena = NULL;
    ffi_type * ret_type = NULL;
    ffi_type ** arg_types = NULL;
    size_t num_args, num_fixed_args;

    // The flow is identical to the forward trampoline version.
    ffi_status status = ffi_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed_args);
    if (status != FFI_SUCCESS) {
        return status;
    }

    status = generate_reverse_trampoline(
        out_context, ret_type, arg_types, num_args, num_fixed_args, user_callback_fn, user_data);

    arena_destroy(arena);
    return status;
}
