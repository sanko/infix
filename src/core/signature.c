
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
 * by the core trampoline generator. The parser is designed to handle complex
 * nested types, variadic arguments, and packed structs.
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
 * ### Error Handling and Security
 * The parser uses a "sticky" error flag within the `parser_state_t` struct.
 * If any parsing function encounters a syntax error, it sets `state->error`
 * and returns `NULL`. All other parsing functions check this flag at entry and
 * will immediately return `NULL` if it is set, preventing cascading error
 * messages and ensuring a clean, fast failure.
 *
 * To prevent stack overflow vulnerabilities from maliciously crafted, deeply
 * nested type signatures (e.g., `{{{{...}}}}`), all recursive parsing functions
 * track their current recursion depth and will fail if `MAX_RECURSION_DEPTH`
 * is exceeded.
 */

#include <ctype.h>
#include <infix_internals.h>
#include <stdlib.h>
#include <string.h>

/**
 * @internal
 * @def MAX_RECURSION_DEPTH
 * @brief A safe limit for nested type definitions in the parser.
 * @details This constant prevents the recursive-descent parser from causing a
 * stack overflow when parsing a malicious or excessively complex signature string.
 */
#define MAX_RECURSION_DEPTH 32

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

// Forward declarations for recursive parsing functions, now including recursion depth tracking.
static ffi_type * parse_type(parser_state_t * state, int depth);
static ffi_type * parse_primitive(parser_state_t * state);
static ffi_type * parse_aggregate(parser_state_t * state, char open, char close, bool is_union, int depth);
static ffi_type * parse_packed_struct(parser_state_t * state, int depth);
static ffi_type * parse_array(parser_state_t * state, int depth);
static ffi_type * parse_function_pointer(parser_state_t * state, int depth);
static bool parse_signature_content(parser_state_t * state,
                                    const char * end_delimiter,
                                    ffi_type ** out_ret_type,
                                    ffi_type *** out_arg_types,
                                    size_t * out_num_args,
                                    size_t * out_num_fixed_args,
                                    int depth);
/** @internal @brief Advances the parser's cursor past any leading whitespace. */
static void skip_whitespace(parser_state_t * state) {
    while (isspace((unsigned char)*state->current))
        state->current++;
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
    unsigned long long val = strtoull(state->current, &end, 10);
    if (end == state->current) {
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
    if (!isalpha((unsigned char)*start) && *start != '_')
        return NULL;

    while (isalnum((unsigned char)*state->current) || *state->current == '_')
        state->current++;

    const char * end = state->current;
    size_t len = end - start;
    if (len == 0)
        return NULL;

    char * name = arena_alloc(state->arena, len + 1, 1);
    if (!name) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    infix_memcpy(name, start, len);
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
 * @param depth The current recursion depth, to prevent stack overflows.
 * @return A pointer to the parsed `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_type(parser_state_t * state, int depth) {
    // If a previous parsing step failed, abort immediately.
    if (state->error)  // We do this before we clobber an actual error
        return NULL;
    // If we've gone deep enough, also abort.
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    skip_whitespace(state);

    ffi_type * base_type = NULL;

    // Dispatch to a specialized parsing function based on the next character.
    if (isalpha((unsigned char)*state->current)) {
        if (*state->current == FFI_SIG_PACKED_STRUCT)
            base_type = parse_packed_struct(state, depth + 1);
        else
            base_type = parse_primitive(state);
    }
    else if (*state->current == FFI_SIG_STRUCT_START)
        base_type = parse_aggregate(state, FFI_SIG_STRUCT_START, FFI_SIG_STRUCT_END, false, depth + 1);
    else if (*state->current == FFI_SIG_UNION_START)
        base_type = parse_aggregate(state, FFI_SIG_UNION_START, FFI_SIG_UNION_END, true, depth + 1);
    else if (*state->current == FFI_SIG_ARRAY_START)
        base_type = parse_array(state, depth + 1);
    else if (*state->current == FFI_SIG_FUNC_PTR_START)
        base_type = parse_function_pointer(state, depth + 1);
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
    while (consume(state, FFI_SIG_POINTER)) {
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
    case FFI_SIG_VOID:
        return ffi_type_create_void();
    case FFI_SIG_BOOL:
        id = FFI_PRIMITIVE_TYPE_BOOL;
        break;
    case FFI_SIG_SINT8:
        id = FFI_PRIMITIVE_TYPE_SINT8;
        break;
    case FFI_SIG_CHAR:
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
    case FFI_SIG_UINT8:
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
    case FFI_SIG_LONG:
        id = (sizeof(long) == 8) ? FFI_PRIMITIVE_TYPE_SINT64 : FFI_PRIMITIVE_TYPE_SINT32;
        break;
    case FFI_SIG_ULONG:
        id = (sizeof(unsigned long) == 8) ? FFI_PRIMITIVE_TYPE_UINT64 : FFI_PRIMITIVE_TYPE_UINT32;
        break;
    case FFI_SIG_SINT64:
        id = FFI_PRIMITIVE_TYPE_SINT64;
        break;
    case FFI_SIG_UINT64:
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
 * @param depth The current recursion depth.
 * @return A pointer to the parsed aggregate `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_aggregate(parser_state_t * state, char open, char close, bool is_union, int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
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
            if (num_members >= 64) {  // Exceeded max members
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return NULL;
            }

            // This is the core lookahead logic to handle optional field names.
            const char * checkpoint = state->current;  // Save position before trying to parse an identifier.
            const char * name = parse_identifier(state);

            if (name && consume(state, FFI_SIG_NAME_SEPARATOR)) {
                // Success: we parsed "name:", so this is a named field.
                temp_members[num_members].name = name;
                temp_members[num_members].type = parse_type(state, depth + 1);
            }
            else {
                // Failure: No ":" found. The identifier we parsed (if any)
                // must have been the start of a type (e.g., 'i' in "{i,d}").
                // Rewind the parser to the checkpoint and parse the whole thing as a type.
                state->current = checkpoint;
                temp_members[num_members].name = NULL;
                temp_members[num_members].type = parse_type(state, depth + 1);
            }

            if (!temp_members[num_members].type)
                return NULL;                       // Propagate error
            temp_members[num_members].offset = 0;  // Offsets are calculated by the Core API for standard layouts.
            num_members++;

            if (!consume(state, FFI_SIG_MEMBER_SEPARATOR))
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
    infix_memcpy(members, temp_members, num_members * sizeof(ffi_struct_member));

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
 * @param depth The current recursion depth.
 * @return A pointer to the parsed packed struct `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_packed_struct(parser_state_t * state, int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    if (!consume(state, FFI_SIG_PACKED_STRUCT) || !consume(state, FFI_SIG_FUNC_PTR_START)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    size_t total_size, alignment;
    if (!parse_size_t(state, &total_size) || !consume(state, FFI_SIG_MEMBER_SEPARATOR) ||
        !parse_size_t(state, &alignment) || !consume(state, FFI_SIG_FUNC_PTR_END)) {
        return NULL;
    }
    if (!consume(state, FFI_SIG_STRUCT_START)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    ffi_struct_member temp_members[64];
    size_t num_members = 0;

    skip_whitespace(state);
    if (*state->current != FFI_SIG_STRUCT_END) {
        while (1) {
            if (num_members >= 64) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return NULL;
            }

            const char * checkpoint = state->current;
            const char * name = parse_identifier(state);
            if (name && consume(state, FFI_SIG_NAME_SEPARATOR)) {
                temp_members[num_members].name = name;
                temp_members[num_members].type = parse_type(state, depth + 1);
            }
            else {
                state->current = checkpoint;
                temp_members[num_members].name = NULL;
                temp_members[num_members].type = parse_type(state, depth + 1);
            }

            if (!temp_members[num_members].type)
                return NULL;
            // The "@offset" part is mandatory for every member of a packed struct.
            if (!consume(state, FFI_SIG_OFFSET_SEPARATOR) || !parse_size_t(state, &temp_members[num_members].offset))
                return NULL;

            num_members++;

            if (!consume(state, FFI_SIG_MEMBER_SEPARATOR))
                break;
        }
    }

    if (!consume(state, FFI_SIG_STRUCT_END)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    ffi_struct_member * members =
        arena_alloc(state->arena, num_members * sizeof(ffi_struct_member), _Alignof(ffi_struct_member));
    if (!members && num_members > 0) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }
    infix_memcpy(members, temp_members, num_members * sizeof(ffi_struct_member));

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
 * @param depth The current recursion depth.
 * @return A pointer to the parsed array `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_array(parser_state_t * state, int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    if (!consume(state, FFI_SIG_ARRAY_START)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }
    size_t num_elements;
    if (!parse_size_t(state, &num_elements) || !consume(state, FFI_SIG_ARRAY_END))
        return NULL;

    // Recursively call the main type parser for the element type.
    // This allows for complex types like arrays of structs or arrays of pointers.
    ffi_type * element_type = parse_type(state, depth + 1);
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
 * @param depth The current recursion depth.
 * @return A pointer to a generic pointer `ffi_type`, or `NULL` on failure.
 */
static ffi_type * parse_function_pointer(parser_state_t * state, int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    if (!consume(state, FFI_SIG_FUNC_PTR_START)) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return NULL;
    }

    // Scan ahead to find the matching closing parenthesis, correctly handling nested parentheses.
    const char * start = state->current;
    int open_paren = 1;
    while (*state->current && open_paren > 0) {
        if (*state->current == FFI_SIG_FUNC_PTR_START)
            open_paren++;
        if (*state->current == FFI_SIG_FUNC_PTR_END) {
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

    const char * end = state->current;  // Consume the final ')'

    // Now, recursively parse the content *within* the parentheses.
    parser_state_t sub_state = {.current = start, .arena = state->arena, .error = FFI_SUCCESS};

    ffi_type * ret_type = NULL;
    ffi_type ** arg_types = NULL;
    size_t num_args = 0, num_fixed_args = 0;

    if (!parse_signature_content(&sub_state, end, &ret_type, &arg_types, &num_args, &num_fixed_args, depth + 1)) {
        state->error = sub_state.error;
        return NULL;
    }

    // Advance the main parser's cursor past the function pointer signature.
    state->current = end + 1;

    // Create a new ffi_type to represent this function pointer.
    // We reuse FFI_TYPE_REVERSE_TRAMPOLINE as it has the correct fields to store the signature.
    ffi_type * func_ptr_type = arena_alloc(state->arena, sizeof(ffi_type), _Alignof(ffi_type));
    if (!func_ptr_type) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return NULL;
    }

    *func_ptr_type = *ffi_type_create_pointer();  // Inherit base properties from a pointer.
    func_ptr_type->category = FFI_TYPE_REVERSE_TRAMPOLINE;
    func_ptr_type->is_arena_allocated = true;
    func_ptr_type->meta.func_ptr_info.return_type = ret_type;
    func_ptr_type->meta.func_ptr_info.arg_types = arg_types;
    func_ptr_type->meta.func_ptr_info.num_args = num_args;
    func_ptr_type->meta.func_ptr_info.num_fixed_args = num_fixed_args;

    return func_ptr_type;
}

/**
 * @internal
 * @brief The core logic for parsing a signature's content, shared by the public API and the function pointer parser.
 * @param state The parser state, operating on the substring to be parsed.
 * @param end_delimiter A pointer to the character that marks the end of parsing (e.g., the '=>' or ')').
 * @param out_ret_type [out] Pointer to store the parsed return type.
 * @param out_arg_types [out] Pointer to store the array of parsed argument types.
 * @param out_num_args [out] Pointer to store the total number of arguments.
 * @param out_num_fixed_args [out] Pointer to store the number of fixed arguments.
 * @param depth The current recursion depth.
 * @return `true` on success, `false` on failure.
 */
static bool parse_signature_content(parser_state_t * state,
                                    const char * end_delimiter,
                                    ffi_type ** out_ret_type,
                                    ffi_type *** out_arg_types,
                                    size_t * out_num_args,
                                    size_t * out_num_fixed_args,
                                    int depth) {
    if (depth > MAX_RECURSION_DEPTH) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return false;
    }

    ffi_type * temp_args[256];
    size_t num_args = 0;
    size_t num_fixed = 0;
    bool in_variadic_part = false;

    const char * ret_sep = strstr(state->current, FFI_SIG_RETURN_SEPARATOR);
    if (!ret_sep || ret_sep > end_delimiter) {
        state->error = FFI_ERROR_INVALID_ARGUMENT;
        return false;
    }

    skip_whitespace(state);

    if (state->current < ret_sep) {
        if (*state->current == FFI_SIG_VARIADIC_SEPARATOR) {
            in_variadic_part = true;
            num_fixed = 0;
            state->current++;
            skip_whitespace(state);
            if (state->current >= ret_sep) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return false;
            }
        }

        while (state->current < ret_sep) {
            if (num_args >= 256) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return false;
            }
            temp_args[num_args++] = parse_type(state, depth + 1);
            if (state->error || !temp_args[num_args - 1])
                return false;

            skip_whitespace(state);

            bool has_sep = consume(state, FFI_SIG_MEMBER_SEPARATOR);
            if (!has_sep && consume(state, FFI_SIG_VARIADIC_SEPARATOR)) {
                if (in_variadic_part) {
                    state->error = FFI_ERROR_INVALID_ARGUMENT;
                    return false;
                }
                in_variadic_part = true;
                num_fixed = num_args;
                has_sep = true;
            }

            if (!has_sep)
                break;

            skip_whitespace(state);
            if (state->current >= ret_sep) {
                state->error = FFI_ERROR_INVALID_ARGUMENT;
                return false;
            }
        }
    }

    if (!in_variadic_part)
        num_fixed = num_args;

    state->current = ret_sep + 2;
    *out_ret_type = parse_type(state, depth + 1);
    if (state->error || !*out_ret_type)
        return false;

    *out_num_args = num_args;
    *out_num_fixed_args = num_fixed;
    *out_arg_types = arena_alloc(state->arena, num_args * sizeof(ffi_type *), sizeof(void *));
    if (!*out_arg_types && num_args > 0) {
        state->error = FFI_ERROR_ALLOCATION_FAILED;
        return false;
    }
    if (num_args > 0)
        memcpy(*out_arg_types, temp_args, num_args * sizeof(ffi_type *));

    return true;
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
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args)
        return FFI_ERROR_INVALID_ARGUMENT;

    *out_arena = arena_create(65536);
    if (!*out_arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    parser_state_t state = {.current = signature, .arena = *out_arena, .error = FFI_SUCCESS};

    ffi_type * temp_args[256];
    size_t num_args = 0;
    size_t num_fixed = 0;
    bool in_variadic_part = false;

    // A valid signature MUST contain the return type separator "=>".
    const char * ret_sep = strstr(signature, FFI_SIG_RETURN_SEPARATOR);
    if (!ret_sep) {
        arena_destroy(*out_arena);
        *out_arena = NULL;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    skip_whitespace(&state);

    // Check if there are any arguments to parse before the "=>".
    if (state.current < ret_sep) {
        // Handle the edge case of a variadic-only function, e.g., ";i=>v"
        if (*state.current == FFI_SIG_VARIADIC_SEPARATOR) {
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

            temp_args[num_args++] = parse_type(&state, 1);
            if (state.error || !temp_args[num_args - 1])
                goto cleanup_fail;

            skip_whitespace(&state);

            // Check for a separator. ',' is a normal separator.
            bool has_sep = consume(&state, FFI_SIG_MEMBER_SEPARATOR);
            // ';' is a special separator that marks the transition to variadic args.
            if (!has_sep && consume(&state, FFI_SIG_VARIADIC_SEPARATOR)) {
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
    if (!in_variadic_part)
        num_fixed = num_args;

    // The cursor must now be at the return separator. Advance past it.
    state.current = ret_sep + 2;
    *out_ret_type = parse_type(&state, +1);
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
    if (num_args > 0)
        infix_memcpy(*out_arg_types, temp_args, num_args * sizeof(ffi_type *));

    return FFI_SUCCESS;

cleanup_fail:
    // This is the single cleanup point for all failure modes. It ensures the
    // arena is always destroyed on error, preventing memory leaks.
    arena_destroy(*out_arena);
    *out_arena = NULL;
    return state.error;
}

ffi_status ffi_type_from_signature(ffi_type ** out_type, arena_t ** out_arena, const char * signature) {
    if (!out_type || !out_arena || !signature)
        return FFI_ERROR_INVALID_ARGUMENT;

    *out_arena = arena_create(16384);
    if (!*out_arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    parser_state_t state = {.current = signature, .arena = *out_arena, .error = FFI_SUCCESS};
    *out_type = parse_type(&state, 1);

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

    // Parse the signature string. This creates the arena and all ffi_type objects.
    ffi_status status = ffi_signature_parse(signature, &arena, &ret_type, &arg_types, &num_args, &num_fixed_args);
    if (status != FFI_SUCCESS)
        return status;  // On failure, ffi_signature_parse has already cleaned up the arena.

    // Generate the trampoline using the parsed types.
    status = generate_forward_trampoline(out_trampoline, ret_type, arg_types, num_args, num_fixed_args);

    // Destroy the arena and all the temporary ffi_type objects it contains.
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
    if (status != FFI_SUCCESS)
        return status;

    status = generate_reverse_trampoline(
        out_context, ret_type, arg_types, num_args, num_fixed_args, user_callback_fn, user_data);

    arena_destroy(arena);
    return status;
}
