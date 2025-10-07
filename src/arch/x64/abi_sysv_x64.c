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
 * @file abi_sysv_x64.c
 * @brief Implements the FFI logic for the System V AMD64 ABI.
 * @ingroup internal_abi_x64
 *
 * @internal
 * This file provides the concrete implementation of the ABI spec for the System V
 * x86-64 ABI, the standard calling convention for Linux, macOS, BSD, and other
 * UNIX-like operating systems on this architecture.
 *
 * Key features of the System V ABI implemented here:
 *
 * - **Register Usage:**
 *   - GPRs for integers/pointers: RDI, RSI, RDX, RCX, R8, R9.
 *   - XMMs for floats/doubles: XMM0-XMM7.
 *
 * - **Aggregate Classification:** Structs up to 16 bytes are recursively classified
 *   into one or two "eightbytes" (64-bit chunks). Based on the classes of these
 *   eightbytes (INTEGER, SSE, MEMORY), the aggregate can be passed in up to two
 *   registers (GPRs and/or XMMs) or on the stack.
 *
 * - **Return Values:**
 *   - Small aggregates (<= 16 bytes) are returned in RAX/RDX and/or XMM0/XMM1.
 *   - Larger aggregates (> 16 bytes) are returned via a hidden pointer in RDI.
 *   - `long double` is a special case and is returned on the x87 FPU stack `st(0)`.
 *
 * - **Variadic Functions:** Before calling a variadic function, the `AL` register
 *   must be set to the number of XMM registers used for arguments.
 * @endinternal
 */

#include "common/infix_internals.h"
#include "common/utility.h"
#include <abi_x64_common.h>
#include <abi_x64_emitters.h>
#include <stdbool.h>
#include <stdlib.h>

/** An array of GPRs used for passing the first 6 integer/pointer arguments, in order. */
static const x64_gpr GPR_ARGS[] = {RDI_REG, RSI_REG, RDX_REG, RCX_REG, R8_REG, R9_REG};
/** An array of XMM registers used for passing the first 8 floating-point arguments, in order. */
static const x64_xmm XMM_ARGS[] = {XMM0_REG, XMM1_REG, XMM2_REG, XMM3_REG, XMM4_REG, XMM5_REG, XMM6_REG, XMM7_REG};
/** The number of GPRs available for argument passing. */
#define NUM_GPR_ARGS 6
/** The number of XMM registers available for argument passing. */
#define NUM_XMM_ARGS 8
/** A safe recursion limit for the aggregate classification algorithm to prevent stack overflow. */
#define MAX_CLASSIFY_DEPTH 32
/** A safe limit on the number of fields to classify to prevent DoS from exponential complexity. */
#define MAX_AGGREGATE_FIELDS_TO_CLASSIFY 32

/**
 * @internal
 * @brief The System V classification for an "eightbyte" (a 64-bit chunk of a type).
 */
typedef enum {
    NO_CLASS,  ///< This eightbyte has not been classified yet. It's the initial state.
    INTEGER,   ///< This eightbyte should be passed in a general-purpose register (GPR).
    SSE,       ///< This eightbyte should be passed in an SSE register (XMM).
    MEMORY     ///< The argument is too complex or large and must be passed on the stack.
} arg_class_t;

// Forward Declarations
static infix_status prepare_forward_call_frame_sysv_x64(infix_arena_t * arena,
                                                        infix_call_frame_layout ** out_layout,
                                                        infix_type * ret_type,
                                                        infix_type ** arg_types,
                                                        size_t num_args,
                                                        size_t num_fixed_args,
                                                        void * target_fn);
static infix_status generate_forward_prologue_sysv_x64(code_buffer * buf, infix_call_frame_layout * layout);
static infix_status generate_forward_argument_moves_sysv_x64(code_buffer * buf,
                                                             infix_call_frame_layout * layout,
                                                             infix_type ** arg_types,
                                                             size_t num_args,
                                                             size_t num_fixed_args);
static infix_status generate_forward_call_instruction_sysv_x64(code_buffer *, infix_call_frame_layout *);

static infix_status generate_forward_epilogue_sysv_x64(code_buffer * buf,
                                                       infix_call_frame_layout * layout,
                                                       infix_type * ret_type);
static infix_status prepare_reverse_call_frame_sysv_x64(infix_arena_t * arena,
                                                        infix_reverse_call_frame_layout ** out_layout,
                                                        infix_reverse_t * context);
static infix_status generate_reverse_prologue_sysv_x64(code_buffer * buf, infix_reverse_call_frame_layout * layout);
static infix_status generate_reverse_argument_marshalling_sysv_x64(code_buffer * buf,
                                                                   infix_reverse_call_frame_layout * layout,
                                                                   infix_reverse_t * context);
static infix_status generate_reverse_dispatcher_call_sysv_x64(code_buffer * buf,
                                                              infix_reverse_call_frame_layout * layout,
                                                              infix_reverse_t * context);
static infix_status generate_reverse_epilogue_sysv_x64(code_buffer * buf,
                                                       infix_reverse_call_frame_layout * layout,
                                                       infix_reverse_t * context);

/** The v-table of System V x64 functions for generating forward trampolines. */
const infix_forward_abi_spec g_sysv_x64_forward_spec = {
    .prepare_forward_call_frame = prepare_forward_call_frame_sysv_x64,
    .generate_forward_prologue = generate_forward_prologue_sysv_x64,
    .generate_forward_argument_moves = generate_forward_argument_moves_sysv_x64,
    .generate_forward_call_instruction = generate_forward_call_instruction_sysv_x64,
    .generate_forward_epilogue = generate_forward_epilogue_sysv_x64};
/** The v-table of System V x64 functions for generating reverse trampolines. */
const infix_reverse_abi_spec g_sysv_x64_reverse_spec = {
    .prepare_reverse_call_frame = prepare_reverse_call_frame_sysv_x64,
    .generate_reverse_prologue = generate_reverse_prologue_sysv_x64,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_sysv_x64,
    .generate_reverse_dispatcher_call = generate_reverse_dispatcher_call_sysv_x64,
    .generate_reverse_epilogue = generate_reverse_epilogue_sysv_x64};

/**
 * @internal
 * @brief Recursively classifies the eightbytes of an aggregate type.
 * @details This is the core of the complex System V classification algorithm. It traverses
 * the fields of a struct/array, examining each 8-byte chunk ("eightbyte") and assigning it a
 * class (INTEGER, SSE, MEMORY). The classification is "merged" according to ABI rules
 * (e.g., if an eightbyte contains both INTEGER and SSE parts, it becomes INTEGER).
 *
 * @param type The type of the current member/element being examined.
 * @param offset The byte offset of this member from the start of the aggregate.
 * @param[in,out] classes An array of two `arg_class_t` that is updated during classification.
 * @param depth The current recursion depth (to prevent stack overflow on malicious input).
 * @param field_count A counter to prevent DoS from excessively complex types.
 * @return `true` if a condition forcing MEMORY classification is found, `false` otherwise.
 */
static bool classify_recursive(
    infix_type * type, size_t offset, arg_class_t classes[2], int depth, size_t * field_count) {
    // A recursive call can be made with a NULL type (e.g., from a malformed array from fuzzer).
    if (type == nullptr)
        return false;  // Terminate recusion path.
    // Abort classification if the type is excessively complex or too deep. Give up and pass in memory.
    if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY || depth > MAX_CLASSIFY_DEPTH) {
        classes[0] = MEMORY;
        return true;
    }

    // The ABI requires natural alignment. If a fuzzer creates a type with an unaligned
    // member, it must be passed in memory. A zero alignment would cause a crash.
    if (type->alignment != 0 && offset % type->alignment != 0) {
        classes[0] = MEMORY;
        return true;
    }
    // If a struct is packed, its layout is explicit and should not be inferred
    // by recursive classification. Treat it as an opaque block of memory.
    // For classification purposes, this is equivalent to an integer array.

    if (type->category == INFIX_TYPE_PRIMITIVE) {
        (*field_count)++;
        // `long double` is a special case. It is passed in memory on the stack, not x87 registers.
        if (is_long_double(type)) {
            classes[0] = MEMORY;
            return true;
        }

        // Consider all eightbytes that the primitive occupies, not just the starting offset.
        size_t start_offset = offset;
        // Check for overflow before calculating end_offset
        if (type->size == 0)
            return false;
        if (start_offset > SIZE_MAX - (type->size - 1)) {
            classes[0] = MEMORY;
            return true;
        }
        size_t end_offset = start_offset + type->size - 1;

        size_t start_eightbyte = start_offset / 8;
        size_t end_eightbyte = end_offset / 8;

        arg_class_t new_class = (is_float(type) || is_double(type)) ? SSE : INTEGER;

        for (size_t index = start_eightbyte; index <= end_eightbyte && index < 2; ++index) {
            // Merge the new class with the existing class for this eightbyte.
            // The rule is: if an eightbyte contains both SSE and INTEGER parts, it is classified as INTEGER.
            if (classes[index] != new_class)
                classes[index] = (classes[index] == NO_CLASS) ? new_class : INTEGER;
        }
        return false;
    }
    if (type->category == INFIX_TYPE_POINTER) {
        (*field_count)++;
        size_t index = offset / 8;
        if (index < 2 && classes[index] != INTEGER)
            classes[index] = INTEGER;  // Pointers are always INTEGER class. Merge with existing class.
        return false;
    }
    if (type->category == INFIX_TYPE_ARRAY) {
        if (type->meta.array_info.element_type == nullptr)
            return false;

        // If the array elements have no size, iterating over them is pointless
        // and can cause a timeout if num_elements is large, as the offset never advances.
        // We only need to classify the element type once at the starting offset.
        if (type->meta.array_info.element_type->size == 0) {
            if (type->meta.array_info.num_elements > 0)
                // Classify the zero-sized element just once.
                return classify_recursive(type->meta.array_info.element_type, offset, classes, depth + 1, field_count);
            return false;  // An empty array of zero-sized structs has no effect on classification.
        }

        for (size_t i = 0; i < type->meta.array_info.num_elements; ++i) {
            // Check count *before* each recursive call inside the loop.
            if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY) {
                classes[0] = MEMORY;
                return true;
            }
            size_t element_offset = offset + i * type->meta.array_info.element_type->size;
            // If we are already past the 16-byte boundary relevant for
            // register passing, there is no need to classify further. This prunes
            // the recursion tree for large arrays.
            if (element_offset >= 16)
                break;

            if (classify_recursive(type->meta.array_info.element_type, element_offset, classes, depth + 1, field_count))
                return true;  // Propagate unaligned discovery up the call stack
        }
        return false;
    }
    if (type->category == INFIX_TYPE_COMPLEX) {
        infix_type * base = type->meta.complex_info.base_type;
        // A zero-sized base type would cause infinite recursion.
        // Treat this as a malformed type and stop classification.
        if (base == nullptr || base->size == 0)
            return false;
        // A complex number is just like a struct { base_type real; base_type imag; }
        // So we classify the first element at offset 0.
        if (classify_recursive(base, offset, classes, depth + 1, field_count))
            return true;  // Propagate unaligned discovery
        // And the second element at offset + size of the base.
        if (classify_recursive(base, offset + base->size, classes, depth + 1, field_count))
            return true;  // Propagate unaligned discovery
        return false;
    }
    if (type->category == INFIX_TYPE_STRUCT || type->category == INFIX_TYPE_UNION) {
        // A generated type can have num_members > 0 but a NULL members pointer.
        // This is invalid and must be passed in memory.
        if (type->meta.aggregate_info.members == nullptr) {
            classes[0] = MEMORY;
            return true;
        }
        // Recursively classify each member of the struct/union.
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            // Check count *before* each recursive call inside the loop.
            if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY) {
                classes[0] = MEMORY;
                return true;
            }

            infix_struct_member * member = &type->meta.aggregate_info.members[i];

            // A generated type can have a NULL member type.
            // This is invalid, and the aggregate must be passed in memory.
            if (member->type == nullptr) {
                classes[0] = MEMORY;
                return true;
            }
            size_t member_offset = offset + member->offset;
            // If this member starts at or after the 16-byte boundary,
            // it cannot influence register classification, so we can skip it.
            if (member_offset >= 16)
                continue;

            if (classify_recursive(member->type, member_offset, classes, depth + 1, field_count))
                return true;  // Propagate unaligned discovery
        }
        return false;
    }
    return false;
}

/**
 * @internal
 * @brief Classifies an aggregate type for argument passing according to the System V ABI.
 * @details This function implements the complete classification algorithm. An aggregate
 *          is broken down into up to two "eightbytes". Each is classified as INTEGER,
 *          SSE, or MEMORY. If the size is > 16 bytes or classification fails, it's MEMORY.
 *
 * @param type The aggregate type to classify.
 * @param[out] classes An array of two `arg_class_t` to be filled.
 * @param[out] num_classes The number of valid classes (1 or 2).
 */
static void classify_aggregate_sysv(infix_type * type, arg_class_t classes[2], size_t * num_classes) {
    // Initialize to a clean state.
    classes[0] = NO_CLASS;
    classes[1] = NO_CLASS;
    *num_classes = 0;

    // If the size is greater than 16 bytes, it's passed in memory.
    if (type->size > 16) {
        classes[0] = MEMORY;
        *num_classes = 1;
        return;
    }

    // Run the recursive classification. If it returns true, an unaligned
    // field was found, and the class is already set to MEMORY. We can stop.
    size_t field_count = 0;                                       // Initialize the counter for this aggregate.
    if (classify_recursive(type, 0, classes, 0, &field_count)) {  // Pass counter to initial call
        *num_classes = 1;
        return;
    }

    // Post-processing for alignment padding.
    if (type->size > 0 && classes[0] == NO_CLASS)
        classes[0] = INTEGER;
    if (type->size > 8 && classes[1] == NO_CLASS)
        classes[1] = INTEGER;

    // Count the number of valid, classified eightbytes.
    if (classes[0] != NO_CLASS)
        (*num_classes)++;
    if (classes[1] != NO_CLASS)
        (*num_classes)++;
}

/**
 * @internal
 * @brief Stage 1 (Forward): Analyzes a signature and creates a call frame layout for System V.
 * @details This function iterates through a function's arguments, classifying each one
 *          to determine its location (GPR, XMM, or stack) according to the SysV ABI rules.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
static infix_status prepare_forward_call_frame_sysv_x64(infix_arena_t * arena,
                                                        infix_call_frame_layout ** out_layout,
                                                        infix_type * ret_type,
                                                        infix_type ** arg_types,
                                                        size_t num_args,
                                                        size_t num_fixed_args,
                                                        void * target_fn) {
    if (out_layout == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;

    // Allocate the layout struct that will hold our results.
    infix_call_frame_layout * layout =
        infix_arena_calloc(arena, 1, sizeof(infix_call_frame_layout), _Alignof(infix_call_frame_layout));
    if (layout == nullptr) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    layout->is_variadic = num_args > num_fixed_args;
    layout->target_fn = target_fn;
    layout->arg_locations =
        infix_arena_calloc(arena, num_args, sizeof(infix_arg_location), _Alignof(infix_arg_location));
    if (layout->arg_locations == nullptr && num_args > 0) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    // gpr_count and xmm_count track the next available GPR and XMM argument registers.
    // current_stack_offset tracks the next available stack slot for arguments.
    size_t gpr_count = 0, xmm_count = 0, current_stack_offset = 0;

    // Determine if the return value requires a hidden pointer argument passed in RDI.
    bool ret_is_aggregate = (ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                             ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX);

    // Rule 1: Aggregates larger than 16 bytes are always returned via hidden pointer.
    // Exception: 256-bit vectors are returned in YMM0.
    layout->return_value_in_memory =
        (ret_is_aggregate && ret_type->size > 16) || (ret_type->category == INFIX_TYPE_VECTOR && ret_type->size > 32);


    // Rule 2: Small aggregates (<= 16 bytes) must also be returned via hidden pointer
    // if their classification is MEMORY. This is critical for types like packed structs
    // with unaligned members.
    if (ret_is_aggregate && !layout->return_value_in_memory) {
        arg_class_t ret_classes[2];
        size_t num_ret_classes;
        classify_aggregate_sysv(ret_type, ret_classes, &num_ret_classes);
        if (num_ret_classes > 0 && ret_classes[0] == MEMORY)
            layout->return_value_in_memory = true;
    }

    // Exception: `long double` is a special case and is always returned on the x87
    // FPU stack, never via a hidden pointer.
    if (is_long_double(ret_type))
        layout->return_value_in_memory = false;

    // If a hidden pointer is used, it consumes the first GPR (RDI).
    if (layout->return_value_in_memory)
        gpr_count++;

    layout->num_stack_args = 0;

    // Main Argument Classification Loop
    for (size_t i = 0; i < num_args; ++i) {
        infix_type * type = arg_types[i];

        // Security: Reject excessively large types before they reach the code generator.
        if (type->size > INFIX_MAX_ARG_SIZE) {
            *out_layout = nullptr;
            return INFIX_ERROR_LAYOUT_FAILED;
        }

        // Step 1: Classify the argument type
        // Special case: `long double` is always passed on the stack.
        if (is_long_double(type)) {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = current_stack_offset;
            current_stack_offset += (type->size + 7) & ~7;  // Align to 8 bytes.
            layout->num_stack_args++;
            continue;  // Go to next argument
        }

        bool is_aggregate = type->category == INFIX_TYPE_STRUCT || type->category == INFIX_TYPE_UNION ||
            type->category == INFIX_TYPE_ARRAY || type->category == INFIX_TYPE_COMPLEX;
        arg_class_t classes[2] = {NO_CLASS, NO_CLASS};
        size_t num_classes = 0;
        bool placed_in_register = false;

        if (is_aggregate)
            // Complex types need the full classification algorithm.
            classify_aggregate_sysv(type, classes, &num_classes);
        else {
            // Simple primitive and vector types are classified directly.
            if (is_float(type) || is_double(type) || type->category == INFIX_TYPE_VECTOR) {
                classes[0] = SSE;
                num_classes = 1;
                // Special classification for 256-bit AVX vectors.
                // They are passed in a single YMM register, which we model as a single SSE class.
                // The size check distinguishes it from 128-bit vectors.
                if (type->category == INFIX_TYPE_VECTOR && type->size == 32)
                    num_classes = 1;  // Treat as a single unit for classification
            }
            else {
                classes[0] = INTEGER;
                num_classes = 1;
                // Primitives > 8 bytes (like __int128) are treated as two INTEGER parts.
                if (type->size > 8) {
                    classes[1] = INTEGER;
                    num_classes = 2;
                }
            }
        }

        // If classification resulted in MEMORY, it must go on the stack.
        placed_in_register = false;
        if (num_classes > 0 && classes[0] != MEMORY) {
            if (num_classes == 1) {
                // Case 1: Argument fits in a single register.
                // Check for available GPR or XMM registers individually. This is the core of the bug fix.
                if (classes[0] == INTEGER && gpr_count < NUM_GPR_ARGS) {
                    layout->arg_locations[i].type = ARG_LOCATION_GPR;
                    layout->arg_locations[i].reg_index = gpr_count++;
                    placed_in_register = true;
                }
                else if (classes[0] == SSE && type->category == INFIX_TYPE_VECTOR && type->size == 32 &&
                         xmm_count < NUM_XMM_ARGS) {
                    // AVX/256-bit vector case
                    layout->arg_locations[i].type = ARG_LOCATION_XMM;  // Re-use XMM type
                    layout->arg_locations[i].reg_index = xmm_count++;
                    placed_in_register = true;
                }
                else if (classes[0] == SSE && xmm_count < NUM_XMM_ARGS) {
                    layout->arg_locations[i].type = ARG_LOCATION_XMM;
                    layout->arg_locations[i].reg_index = xmm_count++;
                    placed_in_register = true;
                }
            }
            else {  // num_classes == 2
                // Case 2: Argument is passed in two registers.
                // Here, a combined check is correct, as we must have room for both parts.
                size_t gpr_needed = (classes[0] == INTEGER) + (classes[1] == INTEGER);
                size_t xmm_needed = (classes[0] == SSE) + (classes[1] == SSE);

                if (gpr_count + gpr_needed <= NUM_GPR_ARGS && xmm_count + xmm_needed <= NUM_XMM_ARGS) {
                    if (classes[0] == INTEGER && classes[1] == INTEGER) {
                        layout->arg_locations[i].type = ARG_LOCATION_GPR_PAIR;
                        layout->arg_locations[i].reg_index = gpr_count;
                        layout->arg_locations[i].reg_index2 = gpr_count + 1;
                    }
                    else if (classes[0] == SSE && classes[1] == SSE) {
                        layout->arg_locations[i].type = ARG_LOCATION_SSE_SSE_PAIR;
                        layout->arg_locations[i].reg_index = xmm_count;
                        layout->arg_locations[i].reg_index2 = xmm_count + 1;
                    }
                    else {  // Mixed GPR and SSE
                        if (classes[0] == INTEGER) {
                            layout->arg_locations[i].type = ARG_LOCATION_INTEGER_SSE_PAIR;
                            layout->arg_locations[i].reg_index = gpr_count;
                            layout->arg_locations[i].reg_index2 = xmm_count;
                        }
                        else {
                            layout->arg_locations[i].type = ARG_LOCATION_SSE_INTEGER_PAIR;
                            layout->arg_locations[i].reg_index = xmm_count;
                            layout->arg_locations[i].reg_index2 = gpr_count;
                        }
                    }
                    gpr_count += gpr_needed;
                    xmm_count += xmm_needed;
                    placed_in_register = true;
                }
            }
        }

        // Step 4: Fallback to stack
        if (!placed_in_register) {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = current_stack_offset;
            current_stack_offset += (type->size + 7) & ~7;  // Align to 8 bytes.
            layout->num_stack_args++;
        }
    }

    // Finalize the layout properties.
    layout->num_gpr_args = gpr_count;
    layout->num_xmm_args = xmm_count;
    // The total stack space for arguments must be 16-byte aligned before the call.
    layout->total_stack_alloc = (current_stack_offset + 15) & ~15;

    // Safety check against excessive stack allocation.
    if (layout->total_stack_alloc > INFIX_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    *out_layout = layout;
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 2 (Forward): Generates the function prologue for the System V trampoline.
 * @details Sets up a standard stack frame, saves registers for the trampoline's context,
 *          and allocates stack space for arguments.
 */
static infix_status generate_forward_prologue_sysv_x64(code_buffer * buf, infix_call_frame_layout * layout) {
    // Standard Function Prologue
    emit_push_reg(buf, RBP_REG);              // push rbp
    emit_mov_reg_reg(buf, RBP_REG, RSP_REG);  // mov rbp, rsp

    // Save Callee-Saved Registers
    // We will use these registers to store our context (target_fn, ret_ptr, args_ptr)
    // across the native function call, so we must save their original values first.
    emit_push_reg(buf, R12_REG);  // push r12
    emit_push_reg(buf, R13_REG);  // push r13
    emit_push_reg(buf, R14_REG);  // push r14
    emit_push_reg(buf, R15_REG);  // push r15

    // Move Trampoline Arguments to Persistent Registers
    if (layout->target_fn == nullptr) {  // Unbound trampoline
        // The trampoline is called with (target_fn, ret_ptr, args_ptr) in RDI, RSI, RDX.
        // We move these into our saved callee-saved registers to protect them.
        emit_mov_reg_reg(buf, R12_REG, RDI_REG);  // r12 = target_fn
        emit_mov_reg_reg(buf, R13_REG, RSI_REG);  // r13 = ret_ptr
        emit_mov_reg_reg(buf, R14_REG, RDX_REG);  // r14 = args_ptr
    }
    else {  // Bound trampoline
        // The trampoline is called with (ret_ptr, args_ptr) in RDI, RSI.
        emit_mov_reg_reg(buf, R13_REG, RDI_REG);  // r13 = ret_ptr
        emit_mov_reg_reg(buf, R14_REG, RSI_REG);  // r14 = args_ptr
    }


    // Allocate Stack Space
    // If any arguments are passed on the stack, allocate space for them.
    // The ABI requires this space to be 16-byte aligned.
    if (layout->total_stack_alloc > 0)
        emit_sub_reg_imm32(buf, RSP_REG, layout->total_stack_alloc);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 3 (Forward): Generates code to move arguments from the `void**` array
 *          into their correct native locations (registers or stack).
 */
static infix_status generate_forward_argument_moves_sysv_x64(code_buffer * buf,
                                                             infix_call_frame_layout * layout,
                                                             infix_type ** arg_types,
                                                             size_t num_args,
                                                             c23_maybe_unused size_t num_fixed_args) {
    // If returning a large struct, the hidden pointer (stored in r13) must be moved to RDI.
    if (layout->return_value_in_memory)
        emit_mov_reg_reg(buf, GPR_ARGS[0], R13_REG);  // mov rdi, r13

    // Marshall Register Arguments
    // Loop over all arguments that are passed in registers.
    for (size_t i = 0; i < num_args; ++i) {
        infix_arg_location * loc = &layout->arg_locations[i];
        if (loc->type == ARG_LOCATION_STACK)
            continue;  // Handle stack arguments in a separate pass.

        // Load the pointer to the argument's data into a scratch register (r15).
        // r14 holds the base of the `void** args_array`.
        // r15 = args_array[i]
        emit_mov_reg_mem(buf, R15_REG, R14_REG, i * sizeof(void *));

        switch (loc->type) {
        case ARG_LOCATION_GPR:
            {
                infix_type * current_type = arg_types[i];
                bool is_signed = current_type->category == INFIX_TYPE_PRIMITIVE &&
                    (current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT8 ||
                     current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT16 ||
                     current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT32);
                if (is_signed) {
                    if (current_type->size == 1)
                        emit_movsx_reg64_mem8(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else if (current_type->size == 2)
                        emit_movsx_reg64_mem16(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else
                        emit_movsxd_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                }
                else {
                    if (current_type->size == 1)
                        emit_movzx_reg64_mem8(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else if (current_type->size == 2)
                        emit_movzx_reg64_mem16(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else if (current_type->size == 4)
                        emit_mov_reg32_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else
                        emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                }
                break;
            }
        case ARG_LOCATION_XMM:
            if (is_float(arg_types[i]))
                // movss xmm_reg, [r15] (Move Scalar Single-Precision)
                emit_movss_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            else if (arg_types[i]->category == INFIX_TYPE_VECTOR && arg_types[i]->size == 32)
                // AVX case: Use the new 256-bit move emitter
                emit_vmovupd_ymm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            else if (arg_types[i]->category == INFIX_TYPE_VECTOR)
                emit_movups_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            else
                // movsd xmm_reg, [r15] (Move Scalar Double-Precision)
                emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            break;
        case ARG_LOCATION_GPR_PAIR:
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);   // mov gpr, [r15]
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index2], R15_REG, 8);  // movsd xmm, [r15 + 8]
            break;
        case ARG_LOCATION_INTEGER_SSE_PAIR:
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);     // mov gpr, [r15]
            emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index2], R15_REG, 8);  // movsd xmm2, [r15 + 8]
            break;
        case ARG_LOCATION_SSE_INTEGER_PAIR:
            emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);  // movsd xmm, [r15]
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index2], R15_REG, 8);   // mov gpr, [r15 + 8]
            break;
        case ARG_LOCATION_SSE_SSE_PAIR:
            emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);   // movsd xmm1, [r15]
            emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index2], R15_REG, 8);  // movsd xmm2, [r15 + 8]
            break;
        default:
            // Should be unreachable if layout is correct.
            break;
        }
    }

    // Marshall Stack Arguments
    if (layout->num_stack_args > 0) {
        for (size_t i = 0; i < num_args; ++i) {
            if (layout->arg_locations[i].type != ARG_LOCATION_STACK)
                continue;

            // Load pointer to argument data into r15.
            emit_mov_reg_mem(buf, R15_REG, R14_REG, i * sizeof(void *));  // r15 = args_array[i]

            size_t size = arg_types[i]->size;
            // Copy the argument data from the user-provided buffer to the stack, 8 bytes at a time.
            for (size_t offset = 0; offset < size; offset += 8) {
                // mov rax, [r15 + offset] (load 8 bytes into scratch register)
                emit_mov_reg_mem(buf, RAX_REG, R15_REG, offset);
                // mov [rsp + stack_offset], rax (store 8 bytes onto the stack)
                emit_mov_mem_reg(buf, RSP_REG, layout->arg_locations[i].stack_offset + offset, RAX_REG);
            }
        }
    }

    // Handle Variadic Calls
    // The ABI requires that AL contains the number of XMM registers used for arguments.
    if (layout->is_variadic)
        // mov al, num_xmm_args (or mov eax, num_xmm_args)
        emit_mov_reg_imm32(buf, RAX_REG, (int32_t)layout->num_xmm_args);

    return INFIX_SUCCESS;
}

/*
 * @internal
 * @brief Stage 3.5 (Forward): Generates the null-check and call instruction.
 */
static infix_status generate_forward_call_instruction_sysv_x64(code_buffer * buf,
                                                               c23_maybe_unused infix_call_frame_layout * layout) {
    // For a bound trampoline, load the hardcoded address into R12.
    // For an unbound trampoline, R12 was already loaded from RDI in the prologue.
    if (layout->target_fn) {
        emit_mov_reg_imm64(buf, R12_REG, (uint64_t)layout->target_fn);
    }

    // On SysV x64, the target function pointer is stored in R12.
    emit_test_reg_reg(buf, R12_REG, R12_REG);  // test r12, r12 ; check if function pointer is null
    emit_jnz_short(buf, 2);                    // jnz +2       ; if not null, skip the crash instruction
    emit_ud2(buf);                             // ud2          ; crash safely if null
    emit_call_reg(buf, R12_REG);               // call r12     ; call the function
    return INFIX_SUCCESS;
}
/**
 * @internal
 * @brief Stage 4 (Forward): Generates the function epilogue for the System V trampoline.
 * @details Emits code to handle the function's return value (from RAX/RDX, XMM0/XMM1, or
 *          the x87 FPU stack for `long double`) and properly tear down the stack frame.
 */
static infix_status generate_forward_epilogue_sysv_x64(code_buffer * buf,
                                                       infix_call_frame_layout * layout,
                                                       infix_type * ret_type) {
    // Handle Return Value
    // If the function returns something and it wasn't via a hidden pointer...
    if (ret_type->category != INFIX_TYPE_VOID && !layout->return_value_in_memory) {
        if (is_long_double(ret_type))
            // `long double` is returned on the x87 FPU stack (st0).
            // We store it into the user's return buffer (pointer held in r13).
            // fstpt [r13] (Store Floating Point value and Pop)
            emit_fstpt_mem(buf, R13_REG, 0);
        else {
            // For other types, we must classify the return type just like an argument.
            arg_class_t classes[2];
            size_t num_classes = 0;
            bool is_aggregate = ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX;

            if (is_aggregate)
                classify_aggregate_sysv(ret_type, classes, &num_classes);
            else {
                if (is_float(ret_type) || is_double(ret_type) || (ret_type->category == INFIX_TYPE_VECTOR)) {
                    classes[0] = SSE;
                    num_classes = 1;
                }
                else {
                    classes[0] = INTEGER;
                    num_classes = 1;
                    if (ret_type->size > 8) {
                        classes[1] = INTEGER;
                        num_classes = 2;
                    }
                }
            }

            if (num_classes == 1) {  // Returned in a single register
                if (classes[0] == SSE) {
                    if (is_float(ret_type))
                        emit_movss_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movss [r13], xmm0
                    else if (ret_type->category == INFIX_TYPE_VECTOR && ret_type->size == 32)
                        emit_vmovupd_mem_ymm(buf, R13_REG, 0, XMM0_REG);  // AVX case
                    else if (ret_type->category == INFIX_TYPE_VECTOR)
                        emit_movups_mem_xmm(buf, R13_REG, 0, XMM0_REG);
                    else
                        emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movsd [r13], xmm0
                }
                else {  // INTEGER class
                    // Use a size-appropriate move to avoid writing past the end of the buffer.
                    switch (ret_type->size) {
                    case 1:
                        emit_mov_mem_reg8(buf, R13_REG, 0, RAX_REG);  // mov [r13], al
                        break;
                    case 2:
                        emit_mov_mem_reg16(buf, R13_REG, 0, RAX_REG);  // mov [r13], ax
                        break;
                    case 4:
                        emit_mov_mem_reg32(buf, R13_REG, 0, RAX_REG);  // mov [r13], eax
                        break;
                    default:
                        emit_mov_mem_reg(buf, R13_REG, 0, RAX_REG);  // mov [r13], rax
                        break;
                    }
                }
            }
            else if (num_classes == 2) {  // Returned in two registers
                if (classes[0] == INTEGER && classes[1] == INTEGER) {
                    emit_mov_mem_reg(buf, R13_REG, 0, RAX_REG);  // mov [r13], rax
                    emit_mov_mem_reg(buf, R13_REG, 8, RDX_REG);  // mov [r13 + 8], rdx
                }
                else if (classes[0] == SSE && classes[1] == SSE) {
                    if (ret_type->category == INFIX_TYPE_VECTOR && ret_type->size == 32) {
                        emit_vmovupd_mem_ymm(buf, R13_REG, 0, XMM0_REG);
                        emit_vmovupd_mem_ymm(buf, R13_REG, 32, XMM1_REG);
                    }
                    else if (ret_type->category == INFIX_TYPE_VECTOR) {
                        emit_movups_mem_xmm(buf, R13_REG, 0, XMM0_REG);
                        emit_movups_mem_xmm(buf, R13_REG, 16, XMM1_REG);
                    }
                    else {
                        emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movsd [r13], xmm0
                        emit_movsd_mem_xmm(buf, R13_REG, 8, XMM1_REG);  // movsd [r13 + 8], xmm1
                    }
                }
                else if (classes[0] == INTEGER && classes[1] == SSE) {
                    emit_mov_mem_reg(buf, R13_REG, 0, RAX_REG);     // mov [r13], rax
                    emit_movsd_mem_xmm(buf, R13_REG, 8, XMM0_REG);  // movsd [r13 + 8], xmm0
                }
                else {                                              // SSE, INTEGER
                    emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movsd [r13], xmm0
                    emit_mov_mem_reg(buf, R13_REG, 8, RAX_REG);     // mov [r13 + 8], rax
                }
            }
        }
    }

    // Deallocate Stack
    if (layout->total_stack_alloc > 0)
        emit_add_reg_imm32(buf, RSP_REG, layout->total_stack_alloc);

    // Restore Registers and Return
    emit_pop_reg(buf, R15_REG);
    emit_pop_reg(buf, R14_REG);
    emit_pop_reg(buf, R13_REG);
    emit_pop_reg(buf, R12_REG);
    emit_pop_reg(buf, RBP_REG);
    emit_ret(buf);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 1 (Reverse): Calculates the stack layout for a reverse trampoline stub.
 * @details Determines the total stack space needed for the stub's local variables,
 *          including the return buffer, the `void**` args_array, and the saved argument data.
 */
static infix_status prepare_reverse_call_frame_sysv_x64(infix_arena_t * arena,
                                                        infix_reverse_call_frame_layout ** out_layout,
                                                        infix_reverse_t * context) {
    infix_reverse_call_frame_layout * layout = infix_arena_calloc(
        arena, 1, sizeof(infix_reverse_call_frame_layout), _Alignof(infix_reverse_call_frame_layout));
    if (!layout)
        return INFIX_ERROR_ALLOCATION_FAILED;

    // Calculate space for each component, ensuring 16-byte alignment for safety and simplicity.
    size_t return_size = (context->return_type->size + 15) & ~15;
    size_t args_array_size = (context->num_args * sizeof(void *) + 15) & ~15;
    size_t saved_args_data_size = 0;
    for (size_t i = 0; i < context->num_args; ++i)
        saved_args_data_size += (context->arg_types[i]->size + 15) & ~15;

    if (saved_args_data_size > INFIX_MAX_ARG_SIZE) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    size_t total_local_space = return_size + args_array_size + saved_args_data_size;

    // Safety check against allocating too much stack.
    if (total_local_space > INFIX_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    // The total allocation for the stack frame must be 16-byte aligned.
    layout->total_stack_alloc = (total_local_space + 15) & ~15;

    // Local variables are accessed via negative offsets from the frame pointer (RBP).
    // The layout is [ return_buffer | args_array | saved_args_data ]
    layout->return_buffer_offset = -(int32_t)layout->total_stack_alloc;
    layout->args_array_offset = layout->return_buffer_offset + return_size;
    layout->saved_args_offset = layout->args_array_offset + args_array_size;

    *out_layout = layout;
    return INFIX_SUCCESS;
}


/**
 * @internal
 * @brief Stage 2 (Reverse): Generates the prologue for the reverse trampoline stub.
 * @details Emits standard System V function entry code, creates a stack frame,
 *          and allocates all necessary local stack space.
 */
static infix_status generate_reverse_prologue_sysv_x64(code_buffer * buf, infix_reverse_call_frame_layout * layout) {
    emit_push_reg(buf, RBP_REG);                                  // push rbp
    emit_mov_reg_reg(buf, RBP_REG, RSP_REG);                      // mov rbp, rsp
    emit_sub_reg_imm32(buf, RSP_REG, layout->total_stack_alloc);  // Allocate our calculated space.
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 3 (Reverse): Generates code to marshal arguments from their native
 *          locations into the generic `void**` array for the C dispatcher.
 */
static infix_status generate_reverse_argument_marshalling_sysv_x64(code_buffer * buf,
                                                                   infix_reverse_call_frame_layout * layout,
                                                                   infix_reverse_t * context) {
    size_t gpr_idx = 0, xmm_idx = 0, current_saved_data_offset = 0;

    // Correctly determine if the return value uses a hidden pointer by performing a full ABI classification.
    bool return_in_memory = false;
    infix_type * ret_type = context->return_type;
    bool ret_is_aggregate = (ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                             ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX);

    if (ret_is_aggregate) {
        if (ret_type->size > 16)
            return_in_memory = true;
        else {
            arg_class_t ret_classes[2];
            size_t num_ret_classes;
            classify_aggregate_sysv(ret_type, ret_classes, &num_ret_classes);
            if (num_ret_classes > 0 && ret_classes[0] == MEMORY)
                return_in_memory = true;
        }
    }
    // The long double primitive is a special case that does not use the hidden pointer.
    if (is_long_double(ret_type))
        return_in_memory = false;

    // If the return value is passed by reference, save the pointer from RDI.
    if (return_in_memory)
        emit_mov_mem_reg(buf, RBP_REG, layout->return_buffer_offset, GPR_ARGS[gpr_idx++]);  // mov [rbp + offset], rdi

    // Stack arguments passed by the caller start at [rbp + 16].
    size_t stack_arg_offset = 16;

    for (size_t i = 0; i < context->num_args; i++) {
        int32_t arg_save_loc = layout->saved_args_offset + current_saved_data_offset;
        infix_type * current_type = context->arg_types[i];

        arg_class_t classes[2];
        size_t num_classes;
        classify_aggregate_sysv(current_type, classes, &num_classes);

        bool is_from_stack = false;

        // Determine if the argument is in registers or on the stack.
        if (classes[0] == MEMORY)
            is_from_stack = true;
        else if (num_classes == 1) {
            if (classes[0] == SSE) {
                if (xmm_idx < NUM_XMM_ARGS)
                    emit_movsd_mem_xmm(buf, RBP_REG, arg_save_loc, XMM_ARGS[xmm_idx++]);
                else
                    is_from_stack = true;
            }
            else {  // INTEGER
                if (gpr_idx < NUM_GPR_ARGS)
                    emit_mov_mem_reg(buf, RBP_REG, arg_save_loc, GPR_ARGS[gpr_idx++]);
                else
                    is_from_stack = true;
            }
        }
        else if (num_classes == 2) {
            size_t gprs_needed = (classes[0] == INTEGER) + (classes[1] == INTEGER);
            size_t xmms_needed = (classes[0] == SSE) + (classes[1] == SSE);

            if (gpr_idx + gprs_needed <= NUM_GPR_ARGS && xmm_idx + xmms_needed <= NUM_XMM_ARGS) {
                if (classes[0] == SSE)
                    emit_movsd_mem_xmm(buf, RBP_REG, arg_save_loc, XMM_ARGS[xmm_idx++]);
                else
                    emit_mov_mem_reg(buf, RBP_REG, arg_save_loc, GPR_ARGS[gpr_idx++]);
                if (classes[1] == SSE)
                    emit_movsd_mem_xmm(buf, RBP_REG, arg_save_loc + 8, XMM_ARGS[xmm_idx++]);
                else
                    emit_mov_mem_reg(buf, RBP_REG, arg_save_loc + 8, GPR_ARGS[gpr_idx++]);
            }
            else
                is_from_stack = true;
        }

        if (is_from_stack) {
            for (size_t offset = 0; offset < current_type->size; offset += 8) {
                emit_mov_reg_mem(buf, RAX_REG, RBP_REG, stack_arg_offset + offset);
                emit_mov_mem_reg(buf, RBP_REG, arg_save_loc + offset, RAX_REG);
            }
            stack_arg_offset += (current_type->size + 7) & ~7;
        }

        emit_lea_reg_mem(buf, RAX_REG, RBP_REG, arg_save_loc);
        emit_mov_mem_reg(buf, RBP_REG, layout->args_array_offset + i * sizeof(void *), RAX_REG);

        current_saved_data_offset += (current_type->size + 15) & ~15;
    }
    return INFIX_SUCCESS;
}

/*
 * @internal
 * @brief Stage 4 (Reverse): Generates the code to call the high-level C dispatcher function.
 * @details Emits code to load the dispatcher's arguments into the correct registers
 *          according to the System V ABI, then calls the dispatcher.
 *
 *          The C dispatcher's signature is:
 *          `void fn(infix_reverse_t* context, void* return_value_ptr, void** args_array)`
 *
 *          The generated code performs the following argument setup:
 *          1. `RDI` (Arg 1): The `context` pointer (a 64-bit immediate).
 *          2. `RSI` (Arg 2): The pointer to the return value buffer. This is either a
 *             pointer to local stack space, or the original pointer passed by the
 *             caller in RDI if the function returns a large struct by reference.
 *          3. `RDX` (Arg 3): The pointer to the `args_array` on the local stack.
 *          4. The address of the dispatcher function itself is loaded into a scratch
 *             register (`RAX`), which is then called.
 */
static infix_status generate_reverse_dispatcher_call_sysv_x64(code_buffer * buf,
                                                              infix_reverse_call_frame_layout * layout,
                                                              infix_reverse_t * context) {
    // Arg 1 (RDI): The infix_reverse_t context pointer.
    emit_mov_reg_imm64(buf, RDI_REG, (uint64_t)context);  // mov rdi, #context_addr

    // Arg 2 (RSI): Pointer to the return buffer.
    // Correctly determine if the hidden pointer was used for the return value.
    bool return_in_memory = false;
    infix_type * ret_type = context->return_type;
    bool ret_is_aggregate = (ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                             ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX);
    if (ret_is_aggregate) {
        if (ret_type->size > 16)
            return_in_memory = true;
        else {
            arg_class_t ret_classes[2];
            size_t num_ret_classes;
            classify_aggregate_sysv(ret_type, ret_classes, &num_ret_classes);
            if (num_ret_classes > 0 && ret_classes[0] == MEMORY)
                return_in_memory = true;
        }
    }
    if (is_long_double(ret_type))
        return_in_memory = false;

    if (return_in_memory)
        // The pointer was passed to us in RDI and saved. Load it back.
        emit_mov_reg_mem(buf, RSI_REG, RBP_REG, layout->return_buffer_offset);  // mov rsi, [rbp + return_buffer_offset]
    else
        // The return buffer is a local variable. Calculate its address.
        emit_lea_reg_mem(buf, RSI_REG, RBP_REG, layout->return_buffer_offset);  // lea rsi, [rbp + return_buffer_offset]

    // Arg 3 (RDX): Pointer to the args_array we just built.
    emit_lea_reg_mem(buf, RDX_REG, RBP_REG, layout->args_array_offset);  // lea rdx, [rbp + args_array_offset]

    // Load the dispatcher's address into a scratch register and call it.
    emit_mov_reg_imm64(buf, RAX_REG, (uint64_t)context->internal_dispatcher);  // mov rax, #dispatcher_addr

    emit_call_reg(buf, RAX_REG);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 5 (Reverse): Generates the epilogue for the reverse trampoline stub.
 * @details Retrieves the return value from the local buffer and places it into the
 *          correct return registers (RAX/RDX, XMM0/XMM1) or the x87 FPU stack. Then,
 *          it tears down the stack frame and returns to the native caller.
 */
static infix_status generate_reverse_epilogue_sysv_x64(code_buffer * buf,
                                                       infix_reverse_call_frame_layout * layout,
                                                       infix_reverse_t * context) {
    if (context->return_type->category != INFIX_TYPE_VOID) {
        // Correctly determine if the return value uses a hidden pointer by performing a full ABI classification.
        bool return_in_memory = false;
        infix_type * ret_type = context->return_type;
        bool ret_is_aggregate = (ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                                 ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX);

        if (ret_is_aggregate) {
            if (ret_type->size > 16)
                return_in_memory = true;
            else {
                arg_class_t ret_classes[2];
                size_t num_ret_classes;
                classify_aggregate_sysv(ret_type, ret_classes, &num_ret_classes);
                if (num_ret_classes > 0 && ret_classes[0] == MEMORY)
                    return_in_memory = true;
            }
        }
        if (is_long_double(ret_type))
            return_in_memory = false;

        // Now, handle the return value based on the correct classification.
        if (is_long_double(context->return_type))
            emit_fldt_mem(buf, RBP_REG, layout->return_buffer_offset);
        else if (return_in_memory)
            // The return value was written directly via the hidden pointer.
            // The ABI requires this pointer to be returned in RAX.
            emit_mov_reg_mem(buf, RAX_REG, RBP_REG, layout->return_buffer_offset);
        else {
            // Classify the return type to determine which registers to load.
            arg_class_t classes[2];
            size_t num_classes;
            if (context->return_type->category == INFIX_TYPE_VECTOR && context->return_type->size == 32) {
                classes[0] = SSE;
                num_classes = 1;
            }
            else
                classify_aggregate_sysv(context->return_type, classes, &num_classes);

            if (num_classes >= 1) {  // First eightbyte
                if (classes[0] == SSE) {
                    if (is_float(context->return_type))
                        emit_movss_xmm_mem(buf, XMM0_REG, RBP_REG, layout->return_buffer_offset);
                    else if (context->return_type->category == INFIX_TYPE_VECTOR && context->return_type->size == 32)
                        emit_vmovupd_ymm_mem(buf, XMM0_REG, RBP_REG, layout->return_buffer_offset);
                    else
                        emit_movsd_xmm_mem(buf, XMM0_REG, RBP_REG, layout->return_buffer_offset);
                }
                else  // INTEGER
                    emit_mov_reg_mem(buf, RAX_REG, RBP_REG, layout->return_buffer_offset);
            }
            if (num_classes == 2) {  // Second eightbyte
                if (classes[1] == SSE) {
                    if (context->return_type->category == INFIX_TYPE_VECTOR && context->return_type->size == 32)
                        emit_vmovupd_ymm_mem(buf, XMM1_REG, RBP_REG, layout->return_buffer_offset + 32);
                    else
                        emit_movsd_xmm_mem(buf, XMM1_REG, RBP_REG, layout->return_buffer_offset + 8);
                }
                else  // INTEGER
                    emit_mov_reg_mem(buf, RDX_REG, RBP_REG, layout->return_buffer_offset + 8);
            }
        }
    }

    // Standard function epilogue: tear down stack frame and return.
    emit_mov_reg_reg(buf, RSP_REG, RBP_REG);
    emit_pop_reg(buf, RBP_REG);
    emit_ret(buf);
    return INFIX_SUCCESS;
}
