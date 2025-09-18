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
 * @brief Implements the string-based signature parser and high-level API.
 *
 * @details This file provides a recursive-descent parser for the infix signature
 * language. It is responsible for translating a signature string into a collection
 * of `ffi_type` objects, which are then used by the core library to generate
 * trampolines. All memory for the intermediate `ffi_type` objects is allocated
 * from a temporary arena, ensuring efficient memory usage and automatic cleanup.
 */

#include <infix.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @internal Consumes whitespace characters from the input stream. */
static void consume_whitespace(parser_context_t * ctx) {
    while (*ctx->current == ' ' || *ctx->current == '\t' || *ctx->current == '\n') {
        ctx->current++;
    }
}

/** @internal Sets an error message and returns NULL to halt parsing. */
static void * parse_error(parser_context_t * ctx, const char * message) {
    if (!ctx->error_message) {  // Only record the first error encountered.
        ctx->error_message = message;
    }
    return NULL;
}

/**
 * @internal
 * @brief Parses a function pointer type signature for validation.
 * @details This function is called when a '(' is encountered. It recursively parses
 *          the argument and return types of the function pointer to ensure the
 *          syntax is valid and to advance the parser's cursor correctly.
 *          It does not need to build a complex ffi_type, as all function pointers
 *          are treated as a single `void*` by the ABI.
 * @return `ffi_type_create_pointer()` on success, or NULL on error.
 */
static ffi_type * parse_function_pointer(parser_context_t * ctx) {
    ctx->current++;  // Consume '('

    // Parse argument types for validation
    while (*ctx->current != '=' && *ctx->current != '\0') {
        if (*ctx->current == ')')
            break;  // End of arguments for a function with no return value (e.g. in a struct)
        if (!parse_type(ctx))
            return NULL;  // Propagate error
    }

    if (*ctx->current == '=') {
        if (*(++ctx->current) != '>')
            return parse_error(ctx, "Expected '=>' in function pointer");
        ctx->current++;  // Consume '>'

        // Parse return type for validation
        if (!parse_type(ctx))
            return NULL;
    }

    if (*ctx->current != ')')
        return parse_error(ctx, "Unterminated function pointer signature");
    ctx->current++;  // Consume ')'

    // All function pointers are treated as a generic pointer by the FFI.
    return ffi_type_create_pointer();
}

// Recursive-Descent Parser

/**
 * @internal
 * @brief Parses a primitive type from a single character in the signature.
 * @return A pointer to the static `ffi_type` for the primitive, or NULL on error.
 */
static ffi_type * parse_primitive(parser_context_t * ctx) {
    char c = *ctx->current++;
    switch (c) {
    case 'v':
        return ffi_type_create_void();
    case 'b':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_BOOL);
    case 'c':  // char is signed by default on many platforms
    case 'a':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT8);
    case 'h':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT8);
    case 's':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT16);
    case 't':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT16);
    case 'i':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
    case 'j':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT32);
    case 'l':  // Assume 64-bit long on modern POSIX, which matches long long.
    case 'x':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT64);
    case 'm':  // Assume 64-bit unsigned long
    case 'y':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT64);
    case 'f':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_FLOAT);
    case 'd':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE);
    case 'e':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_LONG_DOUBLE);
#if !defined(FFI_COMPILER_MSVC)
    case 'n':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT128);
    case 'o':
        return ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_UINT128);
#endif
    default:
        return parse_error(ctx, "Invalid primitive type character");
    }
}

/**
 * @internal
 * @brief A generic parser for aggregates (structs and unions), including packed structs.
 * @return An arena-allocated `ffi_type*` for the aggregate, or NULL on error.
 */
static ffi_type * parse_aggregate(
    parser_context_t * ctx, char start_delim, char end_delim, ffi_type_category category, bool is_packed) {
    size_t packed_size = 0;
    size_t packed_align = 0;

    if (is_packed) {
        if (*ctx->current != '(')
            return parse_error(ctx, "Expected '(size,align)' after 'p'");
        ctx->current++;  // Consume '('

        char * end_ptr;
        packed_size = strtoul(ctx->current, &end_ptr, 10);
        if (end_ptr == ctx->current)
            return parse_error(ctx, "Invalid packed struct size");
        ctx->current = end_ptr;

        if (*ctx->current != ',')
            return parse_error(ctx, "Expected ',' separator in '(size,align)'");
        ctx->current++;  // Consume ','

        packed_align = strtoul(ctx->current, &end_ptr, 10);
        if (end_ptr == ctx->current)
            return parse_error(ctx, "Invalid packed struct alignment");
        ctx->current = end_ptr;

        if (*ctx->current != ')')
            return parse_error(ctx, "Expected ')' to close '(size,align)'");
        ctx->current++;  // Consume ')'
    }

    if (*ctx->current != start_delim)
        return parse_error(ctx, "Expected aggregate start delimiter");
    ctx->current++;  // Consume start delimiter

    ffi_struct_member * members = arena_alloc(ctx->arena, sizeof(ffi_struct_member) * 32, _Alignof(ffi_struct_member));
    if (!members)
        return parse_error(ctx, "Arena allocation failed for members");

    size_t num_members = 0;
    size_t current_offset = 0;  // Needed for non-packed layout calculation

    while (*ctx->current != end_delim && *ctx->current != '\0') {
        if (num_members >= 32)
            return parse_error(ctx, "Exceeded maximum number of aggregate members (32)");

        members[num_members].type = parse_type(ctx);
        if (!members[num_members].type)
            return NULL;

        members[num_members].name = NULL;

        // Member names are now parsed for all struct types.
        consume_whitespace(ctx);
        if (*ctx->current == '\'') {
            ctx->current++;  // Consume opening quote
            const char * name_start = ctx->current;
            while (*ctx->current != '\'' && *ctx->current != '\0') {
                ctx->current++;
            }
            if (*ctx->current == '\'') {
                size_t name_len = ctx->current - name_start;
                char * name_buf = arena_alloc(ctx->arena, name_len + 1, 1);
                if (name_buf) {
                    memcpy(name_buf, name_start, name_len);
                    name_buf[name_len] = '\0';
                    members[num_members].name = name_buf;
                }
                ctx->current++;  // Consume closing quote
            }
        }
        else
            members[num_members].name = NULL;

        if (is_packed) {
            if (*ctx->current != ':')
                return parse_error(ctx, "Packed struct members must have a ':offset'");
            ctx->current++;  // Consume ':'
            char * end_ptr;
            members[num_members].offset = strtoul(ctx->current, &end_ptr, 10);
            if (end_ptr == ctx->current)
                return parse_error(ctx, "Invalid member offset");
            ctx->current = end_ptr;
        }
        else {
            // For standard structs, we must calculate the offset.
            if (category == FFI_TYPE_STRUCT) {
                // Align the current offset up to the member's alignment requirement.
                size_t alignment = members[num_members].type->alignment;
                if (alignment > 0) {
                    current_offset = (current_offset + alignment - 1) & ~(alignment - 1);
                }
                members[num_members].offset = current_offset;
                current_offset += members[num_members].type->size;
            }
            else  // For unions, offset is always 0.
                members[num_members].offset = 0;
        }

        num_members++;

        consume_whitespace(ctx);
        if (*ctx->current == ';')
            ctx->current++;
        else if (*ctx->current != end_delim)
            return parse_error(ctx, "Expected ';' or end delimiter");
    }

    if (*ctx->current != end_delim)
        return parse_error(ctx, "Unterminated aggregate");
    ctx->current++;  // Consume end delimiter

    ffi_type * agg_type = NULL;
    ffi_status status;

    if (is_packed)
        status =
            ffi_type_create_packed_struct_arena(ctx->arena, &agg_type, packed_size, packed_align, members, num_members);
    else if (category == FFI_TYPE_STRUCT)
        status = ffi_type_create_struct_arena(ctx->arena, &agg_type, members, num_members);
    else
        status = ffi_type_create_union_arena(ctx->arena, &agg_type, members, num_members);

    if (status != FFI_SUCCESS)
        return parse_error(ctx, "Failed to create aggregate type layout");
    return agg_type;
}

/**
 * @internal
 * @brief The main recursive parsing function. Dispatches to other parsers and handles postfix operators.
 * @return An `ffi_type*` (either static or arena-allocated), or NULL on error.
 */
ffi_type * parse_type(parser_context_t * ctx) {
    consume_whitespace(ctx);

    ffi_type * base_type = NULL;

    if (*ctx->current == '(')
        base_type = parse_function_pointer(ctx);
    else if (*ctx->current == '{')
        base_type = parse_aggregate(ctx, '{', '}', FFI_TYPE_STRUCT, false);
    else if (*ctx->current == '<')
        base_type = parse_aggregate(ctx, '<', '>', FFI_TYPE_UNION, false);
    else if (*ctx->current == 'p') {
        ctx->current++;  // Consume 'p'
        base_type = parse_aggregate(ctx, '{', '}', FFI_TYPE_STRUCT, true);
    }
    else
        base_type = parse_primitive(ctx);

    if (!base_type)
        return NULL;  // Error occurred in a sub-parser

    // After parsing a base type, check for postfix operators like '*' or '[...]'.
    while (true) {
        consume_whitespace(ctx);
        if (*ctx->current == '*') {
            ctx->current++;
            base_type = ffi_type_create_pointer();
        }
        else if (*ctx->current == '[') {
            ctx->current++;  // Consume '['
            char * end_ptr;
            long num_elements = strtol(ctx->current, &end_ptr, 10);
            if (end_ptr == ctx->current || num_elements <= 0)
                return parse_error(ctx, "Invalid or non-positive array size");

            ctx->current = end_ptr;
            if (*ctx->current != ']')
                return parse_error(ctx, "Unterminated array size");

            ctx->current++;  // Consume ']'

            ffi_type * array_type = NULL;
            if (ffi_type_create_array_arena(ctx->arena, &array_type, base_type, num_elements) != FFI_SUCCESS)
                return parse_error(ctx, "Failed to create array type");

            base_type = array_type;
        }
        else
            break;  // No more postfix operators
    }

    return base_type;
}

/**
 * @internal
 * @brief Parses a full signature string into its constituent ffi_type parts.
 * @details This is the core parsing engine used by both the forward and reverse
 *          high-level API functions. It handles memory allocation for types
 *          via an arena and populates the output parameters.
 * @return `FFI_SUCCESS` on successful parse, or `FFI_ERROR_INVALID_ARGUMENT`.
 */
static ffi_status parse_full_signature(const char * signature,
                                       arena_t * arena,
                                       ffi_type ** out_ret_type,
                                       ffi_type *** out_arg_types,
                                       size_t * out_num_args,
                                       size_t * out_num_fixed_args) {
    const char * ret_sep = strstr(signature, "=>");
    if (!ret_sep || ret_sep == signature)
        return FFI_ERROR_INVALID_ARGUMENT;

    parser_context_t ctx = {.current = NULL, .arena = arena, .error_message = NULL};

    // Parse Return Type
    ctx.current = ret_sep + 2;
    *out_ret_type = parse_type(&ctx);
    consume_whitespace(&ctx);
    if (!*out_ret_type || *ctx.current != '\0')
        return FFI_ERROR_INVALID_ARGUMENT;

    // Parse Argument Types
    *out_arg_types = arena_alloc(arena, sizeof(ffi_type *) * 64, _Alignof(ffi_type *));
    if (!*out_arg_types)
        return FFI_ERROR_ALLOCATION_FAILED;

    *out_num_args = 0;
    *out_num_fixed_args = 0;
    bool in_variadic_part = false;
    ctx.current = signature;

    while (ctx.current < ret_sep) {
        consume_whitespace(&ctx);
        if (ctx.current >= ret_sep)
            break;

        if (*ctx.current == '.') {
            if (in_variadic_part)
                return FFI_ERROR_INVALID_ARGUMENT;
            in_variadic_part = true;
            *out_num_fixed_args = *out_num_args;
            ctx.current++;
            continue;
        }

        if (*out_num_args >= 64)
            return FFI_ERROR_INVALID_ARGUMENT;

        ffi_type * arg_type = parse_type(&ctx);
        if (!arg_type)
            return FFI_ERROR_INVALID_ARGUMENT;

        if (in_variadic_part) {
            if (arg_type->category == FFI_TYPE_PRIMITIVE) {
                if (arg_type->meta.primitive_id == FFI_PRIMITIVE_TYPE_FLOAT)
                    arg_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_DOUBLE);
                else if (arg_type->size < sizeof(int))
                    arg_type = ffi_type_create_primitive(FFI_PRIMITIVE_TYPE_SINT32);
            }
        }

        if (arg_type->category == FFI_TYPE_VOID) {
            consume_whitespace(&ctx);
            if (*out_num_args > 0 || ctx.current < ret_sep)
                return FFI_ERROR_INVALID_ARGUMENT;
            break;
        }
        else
            (*out_arg_types)[(*out_num_args)++] = arg_type;
    }

    if (!in_variadic_part)
        *out_num_fixed_args = *out_num_args;

    if (ctx.error_message)
        return FFI_ERROR_INVALID_ARGUMENT;

    return FFI_SUCCESS;
}

/**
 * @brief Generates a forward-call trampoline from a signature string.
 *
 * @details This is the primary function of the high-level API. It parses a signature
 *          string, constructs the necessary `ffi_type` objects internally using a
 *          memory arena, generates the trampoline, and then automatically cleans
 *          up all intermediate type descriptions. The resulting trampoline is
 *          self-contained, performance-optimized, and ready for immediate use.
 *
 * @param[out] out_trampoline On success, this will be populated with a pointer to the
 *                            handle for the new trampoline. The handle must be freed
 *                            by the caller.
 * @param[in] signature A null-terminated string describing the function signature.
 *                      The format is `"arg_types... => ret_type"`. For details on the
 *                      signature language, including the advanced syntax for packed
 *                      structs (`p(size,align){type:offset;...}`), please see the
 *                      Signature Language Reference in the project's `README.md`.
 *
 * @return `FFI_SUCCESS` on success.
 * @return `FFI_ERROR_INVALID_ARGUMENT` if `out_trampoline` is NULL, `signature` is NULL,
 *         or the signature string is malformed.
 * @return `FFI_ERROR_ALLOCATION_FAILED` if an internal memory allocation fails.
 * @return Other `ffi_status` codes on ABI-specific layout or code generation failures.
 *
 * @note The returned trampoline must be freed with `ffi_trampoline_free`.
 */
ffi_status ffi_create_forward_trampoline_from_signature(ffi_trampoline_t ** out_trampoline, const char * signature) {
    if (!out_trampoline || !signature)
        return FFI_ERROR_INVALID_ARGUMENT;

    arena_t * arena = arena_create(4096);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    ffi_type * ret_type = NULL;
    ffi_type ** arg_types = NULL;
    size_t num_args = 0;
    size_t num_fixed_args = 0;

    ffi_status status = parse_full_signature(signature, arena, &ret_type, &arg_types, &num_args, &num_fixed_args);
    if (status == FFI_SUCCESS)
        status = generate_forward_trampoline(out_trampoline, ret_type, arg_types, num_args, num_fixed_args);

    arena_destroy(arena);
    return status;
}

/**
 * @brief Generates a reverse-call trampoline (callback) from a signature string.
 *
 * @details This function parses a signature string to create a native, C-callable function
 *          pointer that invokes the provided user handler. It simplifies the creation
 *          of callbacks by managing the underlying `ffi_type` objects automatically,
 *          making it the ideal way to interface with C libraries that require callbacks.
 *
 * @param[out] out_context On success, will be populated with a pointer to the new
 *                         reverse trampoline context. This context owns the executable
 *                         code and must be kept alive as long as the callback is in use.
 * @param[in] signature A null-terminated string describing the callback's signature.
 *                      See the Signature Language Reference in the `README.md` for details.
 * @param[in] user_callback_fn A function pointer to the user's C callback handler.
 *                             Its signature must logically match the one described
 *                             in the string.
 * @param[in] user_data An arbitrary, user-defined pointer for passing state to the
 *                      handler. This pointer is stored in the trampoline's context and can
 *                      be retrieved within the handler via the `ffi_reverse_trampoline_t*`
 *                      context passed to the internal dispatcher.
 *
 * @return `FFI_SUCCESS` on success.
 * @return `FFI_ERROR_INVALID_ARGUMENT` if any parameters are invalid or the signature
 *         string is malformed.
 * @return `FFI_ERROR_ALLOCATION_FAILED` if an internal memory allocation fails.
 *
 * @note The returned context must be freed with `ffi_reverse_trampoline_free`. The
 *       context must remain alive for as long as the native function pointer might
 *       be called by external code.
 */
ffi_status ffi_create_reverse_trampoline_from_signature(ffi_reverse_trampoline_t ** out_context,
                                                        const char * signature,
                                                        void * user_callback_fn,
                                                        void * user_data) {
    if (!out_context || !signature)
        return FFI_ERROR_INVALID_ARGUMENT;

    arena_t * arena = arena_create(4096);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    ffi_type * ret_type = NULL;
    ffi_type ** arg_types = NULL;
    size_t num_args = 0;
    size_t num_fixed_args = 0;

    ffi_status status = parse_full_signature(signature, arena, &ret_type, &arg_types, &num_args, &num_fixed_args);
    if (status == FFI_SUCCESS)
        status = generate_reverse_trampoline(
            out_context, ret_type, arg_types, num_args, num_fixed_args, user_callback_fn, user_data);

    arena_destroy(arena);
    return status;
}

/**
 * @brief Parses a full function signature string into its constituent ffi_type parts.
 * @details This function provides direct access to the signature parser. It creates a
 *          dedicated arena to hold the resulting `ffi_type` object graph for the
 *          entire function signature. This is an advanced function for callers who
 *          need to inspect the type information before or after generating a
 *          trampoline, or for those who wish to use the lower-level
 *          `generate_forward_trampoline` function directly.
 */
ffi_status ffi_signature_parse(const char * signature,
                               arena_t ** out_arena,
                               ffi_type ** out_ret_type,
                               ffi_type *** out_arg_types,
                               size_t * out_num_args,
                               size_t * out_num_fixed_args) {
    // Validate all output pointers.
    if (!signature || !out_arena || !out_ret_type || !out_arg_types || !out_num_args || !out_num_fixed_args)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Create a dedicated arena for this parse operation.
    arena_t * arena = arena_create(4096);
    if (!arena) {
        *out_arena = NULL;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    // Call the internal parsing engine.
    ffi_status status =
        parse_full_signature(signature, arena, out_ret_type, out_arg_types, out_num_args, out_num_fixed_args);

    // Handle success or failure.
    if (status != FFI_SUCCESS) {
        // If parsing failed, destroy the arena we created and nullify the output.
        arena_destroy(arena);
        *out_arena = NULL;
        // The other out-params are assumed to be garbage at this point.
    }
    else
        // On success, transfer ownership of the arena to the caller.
        *out_arena = arena;

    return status;
}

/**
 * @brief Parses a signature string representing a single data type.
 * @details This is a specialized version of the parser for use cases like data
 *          marshalling, serialization, or dynamic type inspection, where you need
 *          to describe a single data type rather than a full function signature.
 *          It creates a dedicated arena to hold the resulting `ffi_type` object
 *          graph for the specified type.
 */
ffi_status ffi_type_from_signature(ffi_type ** out_type, arena_t ** out_arena, const char * signature) {
    if (!out_type || !out_arena || !signature)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Create and manage the arena internally.
    arena_t * arena = arena_create(4096);
    if (!arena)
        return FFI_ERROR_ALLOCATION_FAILED;

    // Set up the internal parser context. The user never sees this.
    parser_context_t ctx = {.current = signature, .arena = arena, .error_message = NULL};

    // Call the internal, "unsafe" parse function.
    ffi_type * parsed_type = parse_type(&ctx);

    // Crucially, perform robust error checking
    consume_whitespace(&ctx);
    if (ctx.error_message || !parsed_type || *ctx.current != '\0') {
        // If there's a parser error OR the entire string wasn't consumed, it's an error.
        arena_destroy(arena);  // Clean up on failure.
        *out_type = NULL;
        *out_arena = NULL;
        return FFI_ERROR_INVALID_ARGUMENT;
    }

    // On success, transfer ownership of the results to the caller.
    *out_type = parsed_type;
    *out_arena = arena;
    return FFI_SUCCESS;
}
