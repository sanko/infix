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
 * @file serialization.c
 * @brief Implements the infix_type to string serialization logic.
 * @ingroup internal_core
 */

#include "common/infix_internals.h"
#include <stdarg.h>
#include <stdio.h>

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
static void _infix_type_print_signature_recursive(printer_state * state, const infix_type * type);

/**
 * @internal
 * @brief The recursive worker for printing a type graph in Infix Signature format.
 */
static void _infix_type_print_signature_recursive(printer_state * state, const infix_type * type) {
    if (state->status != INFIX_SUCCESS || !type)
        return;

    switch (type->category) {
    case INFIX_TYPE_VOID:
        _print(state, "void");
        break;
    case INFIX_TYPE_POINTER:
        _print(state, "*");
        // For a generic void*, the pointee can be itself. Avoid infinite recursion.
        if (type->meta.pointer_info.pointee_type == type ||
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
        _print(state, "{");
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (i > 0)
                _print(state, ",");
            _infix_type_print_signature_recursive(state, type->meta.aggregate_info.members[i].type);
        }
        _print(state, "}");
        break;
    case INFIX_TYPE_UNION:
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

        // Check if there is a variadic part to the signature.
        if (type->meta.func_ptr_info.num_args >= type->meta.func_ptr_info.num_fixed_args) {
            // Always print the separator if the signature was intended to be variadic,
            // which is true if num_args != num_fixed_args OR if there are no fixed args but some variadic ones.
            bool is_variadic = type->meta.func_ptr_info.num_args != type->meta.func_ptr_info.num_fixed_args;
            if (is_variadic)
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

    switch (dialect) {
    case INFIX_DIALECT_SIGNATURE:
        _infix_type_print_signature_recursive(&state, type);
        break;
    case INFIX_DIALECT_ITANIUM_MANGLING:
    case INFIX_DIALECT_MSVC_MANGLING:
        _print(&state, "mangling_not_implemented");
        break;
    default:
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (state.status == INFIX_SUCCESS) {
        if (state.remaining > 0)
            *state.p = '\0';
        else {
            _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
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
    if (!buffer || buffer_size == 0 || !ret_type) {
        _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    printer_state state = {buffer, buffer_size, INFIX_SUCCESS};

    (void)function_name;  // Will be used for mangling dialects.

    // This block is essentially a duplication of the recursive helper's logic,
    // but operating on the raw components of a signature.
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
            _infix_set_error(INFIX_CATEGORY_GENERAL, INFIX_CODE_UNKNOWN, 0);
            return INFIX_ERROR_INVALID_ARGUMENT;
        }
    }
    return state.status;
}
