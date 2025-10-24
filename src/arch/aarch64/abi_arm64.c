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
 * @file abi_arm64.c
 * @brief Implements the FFI logic for the AArch64 (ARM64) architecture.
 * @ingroup internal_abi_aarch64
 *
 * @internal
 * This file provides the concrete implementation of the `infix_forward_abi_spec`
 * and `infix_reverse_abi_spec` for the ARM64 architecture. It primarily follows
 * the standard "Procedure Call Standard for the ARM 64-bit Architecture" (AAPCS64),
 * but also contains critical conditional logic to handle deviations for specific
 * platforms like Apple macOS and Windows on ARM.
 *
 * @section aapcs64_rules Key AAPCS64 Rules Implemented
 *
 * - **Register Usage:**
 *   - The first 8 integer/pointer arguments are passed in GPRs (X0-X7).
 *   - The first 8 floating-point/vector arguments are passed in VPRs (V0-V7).
 *
 * - **Homogeneous Floating-point Aggregates (HFAs):** Structs or arrays composed
 *   entirely of 1 to 4 identical floating-point types (`float` or `double`) are
 *   passed in consecutive VPRs.
 *
 * - **Return Values:**
 *   - Aggregates up to 16 bytes are returned in registers (GPRs and/or VPRs).
 *   - Larger aggregates are returned via a hidden pointer passed by the caller
 *     in the dedicated "indirect result location register", `X8`.
 *
 * @section platform_deviations Platform-Specific Deviations
 *
 * - **Variadic Calls (Apple macOS):** All variadic arguments are passed on the
 *   stack. Arguments smaller than 8 bytes are promoted to fill 8-byte stack slots.
 *
 * - **Variadic Calls (Windows on ARM):** The HFA rule is disabled for variadic
 *   arguments. Floating-point scalars are passed in GPRs, not VPRs.
 *
 * - **16-Byte Argument Alignment:**
 *   - **Standard/macOS:** 16-byte aggregates passed in GPRs must start in an
 *     even-numbered register (X0, X2, X4, X6).
 *   - **macOS Exception:** `__int128_t` does NOT require even-GPR alignment.
 *   - **Windows Exception:** Variadic 16-byte aggregates do NOT require even-GPR alignment.
 * @endinternal
 */

#include "arch/aarch64/abi_arm64_common.h"
#include "arch/aarch64/abi_arm64_emitters.h"
#include "common/infix_internals.h"
#include "common/utility.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/** @internal The General-Purpose Registers used for the first 8 integer/pointer arguments. */
static const arm64_gpr GPR_ARGS[] = {X0_REG, X1_REG, X2_REG, X3_REG, X4_REG, X5_REG, X6_REG, X7_REG};
/** @internal The SIMD/Floating-Point Registers used for the first 8 float/double/vector arguments. */
static const arm64_vpr VPR_ARGS[] = {V0_REG, V1_REG, V2_REG, V3_REG, V4_REG, V5_REG, V6_REG, V7_REG};
/** @internal The total number of GPRs available for argument passing. */
#define NUM_GPR_ARGS 8
/** @internal The total number of VPRs available for argument passing. */
#define NUM_VPR_ARGS 8
/** @internal A safe limit on the number of fields to classify to prevent DoS from exponential complexity. */
#define MAX_AGGREGATE_FIELDS_TO_CLASSIFY 32

// Forward Declarations for the ABI v-table functions
static infix_status prepare_forward_call_frame_arm64(infix_arena_t * arena,
                                                     infix_call_frame_layout ** out_layout,
                                                     infix_type * ret_type,
                                                     infix_type ** arg_types,
                                                     size_t num_args,
                                                     size_t num_fixed_args,
                                                     void * target_fn);
static infix_status generate_forward_prologue_arm64(code_buffer * buf, infix_call_frame_layout * layout);
static infix_status generate_forward_argument_moves_arm64(code_buffer * buf,
                                                          infix_call_frame_layout * layout,
                                                          infix_type ** arg_types,
                                                          size_t num_args,
                                                          c23_maybe_unused size_t num_fixed_args);
static infix_status generate_forward_call_instruction_arm64(code_buffer *, infix_call_frame_layout *);
static infix_status generate_forward_epilogue_arm64(code_buffer * buf,
                                                    infix_call_frame_layout * layout,
                                                    infix_type * ret_type);
static bool is_hfa(infix_type * type, infix_type ** base_type);

static infix_status prepare_reverse_call_frame_arm64(infix_arena_t * arena,
                                                     infix_reverse_call_frame_layout ** out_layout,
                                                     infix_reverse_t * context);
static infix_status generate_reverse_prologue_arm64(code_buffer * buf, infix_reverse_call_frame_layout * layout);
static infix_status generate_reverse_argument_marshalling_arm64(code_buffer * buf,
                                                                infix_reverse_call_frame_layout * layout,
                                                                infix_reverse_t * context);
static infix_status generate_reverse_dispatcher_call_arm64(code_buffer * buf,
                                                           infix_reverse_call_frame_layout * layout,
                                                           infix_reverse_t * context);
static infix_status generate_reverse_epilogue_arm64(code_buffer * buf,
                                                    infix_reverse_call_frame_layout * layout,
                                                    infix_reverse_t * context);
/** @internal The v-table of AArch64 functions for generating forward trampolines. */
const infix_forward_abi_spec g_arm64_forward_spec = {
    .prepare_forward_call_frame = prepare_forward_call_frame_arm64,
    .generate_forward_prologue = generate_forward_prologue_arm64,
    .generate_forward_argument_moves = generate_forward_argument_moves_arm64,
    .generate_forward_call_instruction = generate_forward_call_instruction_arm64,
    .generate_forward_epilogue = generate_forward_epilogue_arm64};

/** @internal The v-table of AArch64 functions for generating reverse trampolines. */
const infix_reverse_abi_spec g_arm64_reverse_spec = {
    .prepare_reverse_call_frame = prepare_reverse_call_frame_arm64,
    .generate_reverse_prologue = generate_reverse_prologue_arm64,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_arm64,
    .generate_reverse_dispatcher_call = generate_reverse_dispatcher_call_arm64,
    .generate_reverse_epilogue = generate_reverse_epilogue_arm64};

/**
 * @internal
 * @brief Recursively finds the first primitive floating-point type in a potential HFA.
 * @details This function performs a depth-first search to find the very first `float`
 *          or `double` primitive within an aggregate. This becomes the candidate
 *          "base type" that all other members of the aggregate will be compared against.
 * @return A pointer to the `infix_type` of the base element, or `nullptr` if not found.
 */
static infix_type * get_hfa_base_type(infix_type * type) {
    if (type == nullptr)
        return nullptr;
    // Base case: we've found a primitive float or double.
    if (is_float(type) || is_double(type))
        return type;
    // Recursive step for arrays.
    if (type->category == INFIX_TYPE_ARRAY)
        return get_hfa_base_type(type->meta.array_info.element_type);
    // Recursive step for structs: check the first member.
    if (type->category == INFIX_TYPE_STRUCT && type->meta.aggregate_info.num_members > 0)
        return get_hfa_base_type(type->meta.aggregate_info.members[0].type);
    // Recursive step for _Complex.
    if (type->category == INFIX_TYPE_COMPLEX)
        return get_hfa_base_type(type->meta.complex_info.base_type);
    return nullptr;  // Not a float-based type.
}

/**
 * @internal
 * @brief Recursively verifies that all primitive members of a type are identical to a given base type.
 * @details After `get_hfa_base_type` finds a potential base type, this function traverses
 *          the entire aggregate to ensure every single primitive member is of that exact same type.
 * @param type The current type/member being checked.
 * @param base_type The required base type (e.g., `float`) to check against.
 * @param field_count A counter to prevent stack overflow/DoS from excessively complex types.
 * @return `true` if all constituent members of `type` are of `base_type`, `false` otherwise.
 */
static bool is_hfa_recursive_check(infix_type * type, infix_type * base_type, size_t * field_count) {
    if (type == nullptr)
        return false;
    // Abort if the type is excessively complex.
    if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY)
        return false;

    // Base case: A primitive must match the base type.
    if (is_float(type) || is_double(type)) {
        (*field_count)++;
        return type == base_type;
    }

    // Recursive step for _Complex: both parts must match the base type.
    if (type->category == INFIX_TYPE_COMPLEX)
        return type->meta.complex_info.base_type == base_type;

    // Recursive step for arrays: check the element type.
    if (type->category == INFIX_TYPE_ARRAY)
        return is_hfa_recursive_check(type->meta.array_info.element_type, base_type, field_count);
    // Recursive step for structs: check every member.
    if (type->category == INFIX_TYPE_STRUCT) {
        if (type->meta.aggregate_info.num_members == 0)
            return false;
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (!is_hfa_recursive_check(type->meta.aggregate_info.members[i].type, base_type, field_count))
                return false;
        }
        return true;
    }
    // If it's not a float, complex, array, or struct, it cannot be part of an HFA.
    return false;
}

/**
 * @internal
 * @brief Determines if a type is a Homogeneous Floating-point Aggregate (HFA).
 * @details An HFA is a struct or array containing 1 to 4 elements of the same, single
 *          floating-point type (`float` or `double`), including in nested aggregates.
 *
 * @param type The `infix_type` to check.
 * @param[out] out_base_type If the type is an HFA, this is set to its base `float` or `double` type.
 * @return `true` if the type is a valid HFA, `false` otherwise.
 */
static bool is_hfa(infix_type * type, infix_type ** out_base_type) {
    if (type->category != INFIX_TYPE_STRUCT && type->category != INFIX_TYPE_ARRAY &&
        type->category != INFIX_TYPE_COMPLEX)
        return false;

    // HFAs cannot be excessively large.
    if (type->size == 0 || type->size > 64)  // Max HFA size is 4 * sizeof(double) = 32 on standard, 4*16=64 on others
        return false;

    // 1. Find the base float/double type of the first primitive element.
    infix_type * base = get_hfa_base_type(type);
    if (base == nullptr)
        return false;

    // 2. Check that the total size is a multiple of the base type, with 1 to 4 elements.
    size_t num_elements = type->size / base->size;
    if (num_elements < 1 || num_elements > 4 || type->size != num_elements * base->size)
        return false;

    // 3. Verify that ALL members recursively conform to this single base type.
    size_t field_count = 0;
    if (!is_hfa_recursive_check(type, base, &field_count))
        return false;

    if (out_base_type)
        *out_base_type = base;
    return true;
}

/**
 * @internal
 * @brief Stage 1 (Forward): Analyzes a signature and creates a call frame layout for AAPCS64.
 * @details This function assigns each argument to a location (GPR, VPR, or Stack) according
 *          to the AAPCS64 rules. It contains extensive conditional logic to handle ABI
 *          deviations on Apple and Windows platforms, especially for variadic arguments
 *          and 16-byte aggregate alignment.
 *
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
static infix_status prepare_forward_call_frame_arm64(infix_arena_t * arena,
                                                     infix_call_frame_layout ** out_layout,
                                                     infix_type * ret_type,
                                                     infix_type ** arg_types,
                                                     size_t num_args,
                                                     size_t num_fixed_args,
                                                     void * target_fn) {
    if (out_layout == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_call_frame_layout * layout =
        infix_arena_calloc(arena, 1, sizeof(infix_call_frame_layout), _Alignof(infix_call_frame_layout));
    if (layout == nullptr) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    layout->arg_locations =
        infix_arena_calloc(arena, num_args, sizeof(infix_arg_location), _Alignof(infix_arg_location));
    if (layout->arg_locations == nullptr && num_args > 0) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }

    size_t gpr_count = 0, vpr_count = 0, stack_offset = 0;
    layout->is_variadic = (num_fixed_args < num_args);
    layout->target_fn = target_fn;
    layout->num_args = num_args;
    layout->num_stack_args = 0;

    // Determine if the return value is passed by reference (via hidden pointer in X8).
    // This is true for aggregates larger than 16 bytes.
    bool ret_is_aggregate = (ret_type->category == INFIX_TYPE_STRUCT || ret_type->category == INFIX_TYPE_UNION ||
                             ret_type->category == INFIX_TYPE_ARRAY || ret_type->category == INFIX_TYPE_COMPLEX);

    layout->return_value_in_memory = (ret_is_aggregate && ret_type->size > 16);

    // Main Argument Classification Loop
    for (size_t i = 0; i < num_args; ++i) {
        infix_type * type = arg_types[i];

        // Security: Reject excessively large types.
        if (type->size > INFIX_MAX_ARG_SIZE) {
            *out_layout = nullptr;
            return INFIX_ERROR_LAYOUT_FAILED;
        }

        bool placed_in_register = false;
        c23_maybe_unused bool is_variadic_arg = (i >= num_fixed_args);

#if defined(INFIX_OS_MACOS)
        // Apple ABI Deviation: All variadic arguments are passed on the stack.
        if (layout->is_variadic && is_variadic_arg) {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = (uint32_t)stack_offset;

            // Any argument smaller than 8 bytes must be promoted to an 8-byte slot on the stack.
            size_t arg_size_on_stack = (type->size < 8) ? 8 : type->size;
            stack_offset += (arg_size_on_stack + 7) & ~7;
            layout->num_stack_args++;
            continue;  // Argument classified, proceed to the next one.
        }
#endif

        bool pass_fp_in_vpr =
            is_float(type) || is_double(type) || is_long_double(type) || type->category == INFIX_TYPE_VECTOR;

        infix_type * hfa_base_type = nullptr;
        bool is_hfa_candidate = is_hfa(type, &hfa_base_type);

#if defined(INFIX_OS_WINDOWS)
        // Windows on ARM ABI Deviation: If the function is variadic, HFA rules are ignored,
        // and all floating-point scalars are passed in GPRs.
        if (layout->is_variadic) {
            pass_fp_in_vpr = false;
            is_hfa_candidate = false;
        }
#endif
        // The order of these checks is critical to follow the ABI specification correctly.
        if (is_hfa_candidate) {
            size_t num_elements = type->size / hfa_base_type->size;
            if (vpr_count + num_elements <= NUM_VPR_ARGS) {
                layout->arg_locations[i].type = ARG_LOCATION_VPR_HFA;
                layout->arg_locations[i].reg_index = (uint8_t)vpr_count;
                layout->arg_locations[i].num_regs = (uint8_t)num_elements;
                vpr_count += num_elements;
                placed_in_register = true;
            }
        }
        else if (type->size > 16) {
            // Aggregates > 16 bytes are passed by reference (a pointer in a GPR).
            if (gpr_count < NUM_GPR_ARGS) {
                layout->arg_locations[i].type = ARG_LOCATION_GPR_REFERENCE;
                layout->arg_locations[i].reg_index = (uint8_t)gpr_count++;
                placed_in_register = true;
            }
        }
        else if (pass_fp_in_vpr) {
            if (vpr_count < NUM_VPR_ARGS) {
                layout->arg_locations[i].type = ARG_LOCATION_VPR;
                layout->arg_locations[i].reg_index = (uint8_t)vpr_count++;
                placed_in_register = true;
            }
        }
        else {                     // Integers, pointers, small aggregates, and variadic floats on Windows.
            if (type->size > 8) {  // Types > 8 and <= 16 bytes are passed in a pair of GPRs.
                bool needs_alignment = true;
#if defined(INFIX_OS_MACOS)
                // macOS Deviation: `__int128_t` does not require even-GPR alignment.
                if (type->category == INFIX_TYPE_PRIMITIVE)
                    needs_alignment = false;
#elif defined(INFIX_OS_WINDOWS)
                // Windows Deviation: Variadic 16-byte arguments do not require even-GPR alignment.
                if (is_variadic_arg)
                    needs_alignment = false;
#endif
                // Standard rule: 16-byte args must start in an even-numbered GPR.
                if (needs_alignment && (gpr_count % 2 != 0))
                    gpr_count++;

                if (gpr_count + 1 < NUM_GPR_ARGS) {
                    layout->arg_locations[i].type = ARG_LOCATION_GPR_PAIR;
                    layout->arg_locations[i].reg_index = (uint8_t)gpr_count;
                    gpr_count += 2;
                    placed_in_register = true;
                }
            }
            else {  // Types <= 8 bytes passed in a single GPR.
                if (gpr_count < NUM_GPR_ARGS) {
                    layout->arg_locations[i].type = ARG_LOCATION_GPR;
                    layout->arg_locations[i].reg_index = (uint8_t)gpr_count++;
                    placed_in_register = true;
                }
            }
        }

        // If it couldn't be placed in a register, it must go on the stack.
        if (!placed_in_register) {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = (uint32_t)stack_offset;
            stack_offset += (type->size + 7) & ~7;  // Stack slots are 8-byte aligned.
            layout->num_stack_args++;
        }
    }

    // The total stack space for arguments must be 16-byte aligned before the call.
    layout->total_stack_alloc = (stack_offset + 15) & ~15;
    layout->num_gpr_args = (uint8_t)gpr_count;
    layout->num_vpr_args = (uint8_t)vpr_count;

    // Security: Prevent excessive stack allocation.
    if (layout->total_stack_alloc > INFIX_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    *out_layout = layout;
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 2 (Forward): Generates the function prologue for the AArch64 trampoline.
 * @details Sets up the stack frame by saving the frame pointer (X29) and link register (X30),
 *          saves callee-saved registers (X19-X22) that will be used to hold the trampoline's
 *          context, moves the trampoline's arguments into those preserved registers, and
 *          allocates the necessary stack space for stack-passed arguments.
 */
static infix_status generate_forward_prologue_arm64(code_buffer * buf, infix_call_frame_layout * layout) {
    // `stp x29, x30, [sp, #-16]!` : Push Frame Pointer and Link Register to the stack, pre-decrementing SP.
    emit_arm64_stp_pre_index(buf, true, X29_FP_REG, X30_LR_REG, SP_REG, -16);
    // `mov x29, sp` : Establish the new Frame Pointer.
    emit_arm64_mov_reg(buf, true, X29_FP_REG, SP_REG);
    // `stp x19, x20, [sp, #-16]!` : Save callee-saved registers that we will use for our context.
    emit_arm64_stp_pre_index(buf, true, X19_REG, X20_REG, SP_REG, -16);
    // `stp x21, x22, [sp, #-16]!`
    emit_arm64_stp_pre_index(buf, true, X21_REG, X22_REG, SP_REG, -16);

    // Move the trampoline's own arguments into these now-safe callee-saved registers.
    if (layout->target_fn == nullptr) {  // Unbound trampoline args: (target_fn, ret_ptr, args_ptr) in X0, X1, X2.
        emit_arm64_mov_reg(buf, true, X19_REG, X0_REG);  // mov x19, x0 (x19 will hold target_fn)
        emit_arm64_mov_reg(buf, true, X20_REG, X1_REG);  // mov x20, x1 (x20 will hold ret_ptr)
        emit_arm64_mov_reg(buf, true, X21_REG, X2_REG);  // mov x21, x2 (x21 will hold args_ptr)
    }
    else {                                               // Bound trampoline args: (ret_ptr, args_ptr) in X0, X1.
        emit_arm64_mov_reg(buf, true, X20_REG, X0_REG);  // mov x20, x0 (x20 = ret_ptr)
        emit_arm64_mov_reg(buf, true, X21_REG, X1_REG);  // mov x21, x1 (x21 = args_ptr)
    }

    // Allocate stack space for arguments that will be passed on the stack.
    if (layout->total_stack_alloc > 0)
        emit_arm64_sub_imm(buf, true, false, SP_REG, SP_REG, (uint32_t)layout->total_stack_alloc);

    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 3 (Forward): Generates code to move arguments into their native locations.
 * @details This function marshals arguments from the generic `void**` array (pointed to by X21)
 *          into the correct GPRs, VPRs, or stack slots, respecting HFA rules and platform-specific
 *          variadic conventions like Apple's stack-only approach.
 */
static infix_status generate_forward_argument_moves_arm64(code_buffer * buf,
                                                          infix_call_frame_layout * layout,
                                                          infix_type ** arg_types,
                                                          size_t num_args,
                                                          c23_maybe_unused size_t num_fixed_args) {
    // If returning a large struct, the ABI requires the hidden pointer (our return buffer, in X20)
    // to be passed in the indirect result location register, x8.
    if (layout->return_value_in_memory)
        emit_arm64_mov_reg(buf, true, X8_REG, X20_REG);  // mov x8, x20

    // Standard AAPCS64 Quirk: For variadic calls, a GPR must contain the number of VPRs used.
    // This rule does NOT apply to Apple's ABI, so we exclude it for macOS.
#if !defined(INFIX_OS_MACOS)
    else if (layout->is_variadic)
        // Since we don't know the types of variadic arguments at compile time, the ABI
        // states the safest value is 0. A callee like printf will use this to determine
        // how to process its va_list. We use x8 as it's a volatile register.
        // A safe default is 0. Callee (like printf) uses this to interpret its va_list.
        emit_arm64_load_u64_immediate(buf, X8_REG, 0);  // mov x8, #0
#endif
    // Main argument marshalling loop.
    for (size_t i = 0; i < num_args; ++i) {
        infix_arg_location * loc = &layout->arg_locations[i];
        infix_type * type = arg_types[i];

        // Load the pointer to the current argument's data into scratch register x9.
        // x21 holds the base of the void** args_array.
        emit_arm64_ldr_imm(buf, true, X9_REG, X21_REG, (int32_t)(i * sizeof(void *)));  // ldr x9, [x21, #offset]

        switch (loc->type) {
        case ARG_LOCATION_GPR:
            {
                // C requires that signed integer types smaller than a full register be
                // sign-extended when passed. We check for this case here.
                bool is_signed_lt_64 = type->category == INFIX_TYPE_PRIMITIVE && type->size < 8 &&
                    (type->meta.primitive_id == INFIX_PRIMITIVE_SINT8 ||
                     type->meta.primitive_id == INFIX_PRIMITIVE_SINT16 ||
                     type->meta.primitive_id == INFIX_PRIMITIVE_SINT32);

                if (is_signed_lt_64)
                    // Use Load Register Signed Word to sign-extend a 32-bit value to 64 bits.
                    emit_arm64_ldrsw_imm(buf, GPR_ARGS[loc->reg_index], X9_REG, 0);  // ldrsw xN, [x9]
                else
                    // For all other types, a standard load is correct. A 32-bit load into a 64-bit
                    // register automatically zero-extends, which is correct for unsigned types.
                    emit_arm64_ldr_imm(buf, type->size == 8, GPR_ARGS[loc->reg_index], X9_REG, 0);  // ldr xN/wN, [x9]
                break;
            }
        case ARG_LOCATION_GPR_PAIR:
            // For types > 8 and <= 16 bytes passed in two GPRs (e.g., __int128_t).
            emit_arm64_ldr_imm(buf, true, GPR_ARGS[loc->reg_index], X9_REG, 0);      // ldr xN, [x9]
            emit_arm64_ldr_imm(buf, true, GPR_ARGS[loc->reg_index + 1], X9_REG, 8);  // ldr xN+1, [x9, #8]
            break;
        case ARG_LOCATION_GPR_REFERENCE:
            // For large aggregates passed by reference, the pointer *is* the argument.
            // x9 already holds this pointer, so we just move it to the target GPR.
            emit_arm64_mov_reg(buf, true, GPR_ARGS[loc->reg_index], X9_REG);  // mov xN, x9
            break;
        case ARG_LOCATION_VPR:
            if (is_long_double(type) || (type->category == INFIX_TYPE_VECTOR && type->size == 16))
                emit_arm64_ldr_q_imm(buf, VPR_ARGS[loc->reg_index], X9_REG, 0);  // ldr qN, [x9] (128-bit load)
            else
                emit_arm64_ldr_vpr(buf, is_double(type), VPR_ARGS[loc->reg_index], X9_REG, 0);  // ldr dN/sN, [x9]
            break;
        case ARG_LOCATION_VPR_HFA:
            {
                infix_type * base = nullptr;
                is_hfa(type, &base);
                for (uint8_t j = 0; j < loc->num_regs; ++j)
                    emit_arm64_ldr_vpr(
                        buf, is_double(base), VPR_ARGS[loc->reg_index + j], X9_REG, (int32_t)(j * base->size));
                break;
            }
        case ARG_LOCATION_STACK:
            {
#if defined(INFIX_OS_MACOS)
                if (layout->is_variadic && i >= num_fixed_args) {
                    // Apple ABI: All variadic arguments are on the stack and promoted to 8 bytes if smaller.
                    const int32_t max_imm_offset = 0xFFF * 8;

                    // Handle promotable primitive types first.
                    if (type->category == INFIX_TYPE_PRIMITIVE || type->category == INFIX_TYPE_POINTER) {
                        if (is_float(type) || is_double(type)) {
                            // Floats are promoted to doubles.
                            emit_arm64_ldr_vpr(buf, true, V16_REG, X9_REG, 0);  // Load as double
                            if (loc->stack_offset < (unsigned)max_imm_offset)
                                emit_arm64_str_vpr(buf, true, V16_REG, SP_REG, loc->stack_offset);
                            else {
                                emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, loc->stack_offset);
                                emit_arm64_str_vpr(buf, true, V16_REG, X10_REG, 0);
                            }
                        }
                        else {  // Integer and pointer types
                            bool is_signed_lt_64 = type->category == INFIX_TYPE_PRIMITIVE && type->size < 8 &&
                                (type->meta.primitive_id == INFIX_PRIMITIVE_SINT8 ||
                                 type->meta.primitive_id == INFIX_PRIMITIVE_SINT16 ||
                                 type->meta.primitive_id == INFIX_PRIMITIVE_SINT32);

                            // Load into scratch GPR X10, applying correct promotion.
                            if (type->size >= 8)  // 64-bit integers and pointers
                                emit_arm64_ldr_imm(buf, true, X10_REG, X9_REG, 0);
                            else if (is_signed_lt_64)  // Signed types < 64-bit
                                emit_arm64_ldrsw_imm(buf, X10_REG, X9_REG, 0);
                            else  // Unsigned types < 64-bit
                                emit_arm64_ldr_imm(buf, false, X10_REG, X9_REG, 0);

                            // Store the promoted 64-bit value.
                            if (loc->stack_offset < (unsigned)max_imm_offset)
                                emit_arm64_str_imm(buf, true, X10_REG, SP_REG, loc->stack_offset);
                            else {
                                emit_arm64_add_imm(buf, true, false, X11_REG, SP_REG, loc->stack_offset);
                                emit_arm64_str_imm(buf, true, X10_REG, X11_REG, 0);
                            }
                        }
                        // This primitive/pointer has been handled, so break from the switch.
                        break;
                    }
                    // If it's a struct, fall through to the generic copy loop.
                }
#endif
                // Generic stack argument handling (for non-macOS, or for structs on macOS)
                const int32_t max_imm_offset = 0xFFF * 8;
                for (size_t offset = 0; offset < type->size; offset += 8) {
                    emit_arm64_ldr_imm(buf, true, X10_REG, X9_REG, (int32_t)offset);
                    int32_t current_stack_offset = (int32_t)(loc->stack_offset + offset);
                    if (current_stack_offset >= 0 && current_stack_offset < max_imm_offset &&
                        (current_stack_offset % 8 == 0))
                        emit_arm64_str_imm(buf, true, X10_REG, SP_REG, current_stack_offset);
                    else {
                        emit_arm64_add_imm(buf, true, false, X11_REG, SP_REG, current_stack_offset);
                        emit_arm64_str_imm(buf, true, X10_REG, X11_REG, 0);
                    }
                }
                break;
            }
        }
    }
    return INFIX_SUCCESS;
}


/**
 * @internal
 * @brief Stage 3.5 (Forward): Generates the call instruction.
 * @details Emits a null-check on the target function pointer followed by a
 *          `BLR` (Branch with Link to Register) instruction. If the pointer
 *          is null, a `BRK` instruction is executed to crash safely.
 */
static infix_status generate_forward_call_instruction_arm64(code_buffer * buf,
                                                            c23_maybe_unused infix_call_frame_layout * layout) {
    if (layout->target_fn)
        // For a bound trampoline, the target is hardcoded. Load it into X19.
        emit_arm64_load_u64_immediate(buf, X19_REG, (uint64_t)layout->target_fn);

    // For an unbound trampoline, X19 was already loaded from the first argument in the prologue.

    // `cbnz x19, #8` : If the target function pointer in x19 is not zero, branch 8 bytes forward.
    emit_arm64_cbnz(buf, true, X19_REG, 8);
    // `brk #0` : If the pointer was null, execute a breakpoint instruction to cause a deliberate crash.
    emit_arm64_brk(buf, 0);
    // `blr x19` : Branch with link to the target function address in x19.
    emit_arm64_blr_reg(buf, X19_REG);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 4 (Forward): Generates the function epilogue.
 * @details Emits code to handle the return value (from X0/X1 or V0-V3), deallocates
 *          the stack frame, restores callee-saved registers, and returns to the caller.
 */
static infix_status generate_forward_epilogue_arm64(code_buffer * buf,
                                                    infix_call_frame_layout * layout,
                                                    infix_type * ret_type) {
    // If the function returns a value and it wasn't returned via hidden pointer...
    if (ret_type->category != INFIX_TYPE_VOID && !layout->return_value_in_memory) {
        // ...copy the result from the appropriate return register(s) into the user's return buffer (pointer in X20).
        infix_type * hfa_base = nullptr;
        // The order of these checks is critical. Handle the most specific cases first.
        if (is_long_double(ret_type) || (ret_type->category == INFIX_TYPE_VECTOR && ret_type->size == 16))
            // On non-Apple AArch64, long double is 16 bytes and returned in V0.
            // On Apple, this case is never hit because types.c aliases it to a standard double.
            emit_arm64_str_q_imm(buf, V0_REG, X20_REG, 0);  // str q0, [x20]
        else if (is_hfa(ret_type, &hfa_base)) {
            size_t num_elements = ret_type->size / hfa_base->size;
            for (size_t i = 0; i < num_elements; ++i)
                emit_arm64_str_vpr(buf, is_double(hfa_base), VPR_ARGS[i], X20_REG, i * hfa_base->size);
        }
        else if (is_float(ret_type))
            emit_arm64_str_vpr(buf, false, V0_REG, X20_REG, 0);  // str s0, [x20]
        else if (is_double(ret_type))
            emit_arm64_str_vpr(buf, true, V0_REG, X20_REG, 0);  // str d0, [x20]
        else {
            // Integer, pointer, or small aggregate return.
            switch (ret_type->size) {
            case 1:
                emit_arm64_strb_imm(buf, X0_REG, X20_REG, 0);
                break;
            case 2:
                emit_arm64_strh_imm(buf, X0_REG, X20_REG, 0);
                break;
            case 4:
                emit_arm64_str_imm(buf, false, X0_REG, X20_REG, 0);
                break;
            case 8:
                emit_arm64_str_imm(buf, true, X0_REG, X20_REG, 0);
                break;
            case 16:  // For __int128_t or small structs
                emit_arm64_str_imm(buf, true, X0_REG, X20_REG, 0);
                emit_arm64_str_imm(buf, true, X1_REG, X20_REG, 8);
                break;
            default:
                break;
            }
        }
    }

    // Deallocate stack space allocated for stack arguments.
    if (layout->total_stack_alloc > 0)
        emit_arm64_add_imm(buf, true, false, SP_REG, SP_REG, (uint32_t)layout->total_stack_alloc);  // add sp, sp, #...

    emit_arm64_ldp_post_index(buf, true, X21_REG, X22_REG, SP_REG, 16);        // ldp x21, x22, [sp], #16
    emit_arm64_ldp_post_index(buf, true, X19_REG, X20_REG, SP_REG, 16);        // ldp x19, x20, [sp], #16
    emit_arm64_ldp_post_index(buf, true, X29_FP_REG, X30_LR_REG, SP_REG, 16);  // ldp x29, x30, [sp], #16
    emit_arm64_ret(buf, X30_LR_REG);                                           // ret
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 1 (Reverse): Calculates the stack layout for a reverse trampoline stub.
 * @details This function determines the total stack space the JIT-compiled stub will need
 *          for its local variables. This space includes:
 *          1. A buffer to store the return value before it's placed in registers.
 *          2. An array of `void*` pointers (`args_array`) to pass to the C dispatcher.
 *          3. A contiguous data area where the contents of all incoming arguments
 *             (from registers or the caller's stack) will be saved.
 *
 * @param[out] out_layout The resulting reverse call frame layout blueprint, populated with offsets.
 * @param context The reverse trampoline context with full signature information.
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
static infix_status prepare_reverse_call_frame_arm64(infix_arena_t * arena,
                                                     infix_reverse_call_frame_layout ** out_layout,
                                                     infix_reverse_t * context) {
    infix_reverse_call_frame_layout * layout = infix_arena_calloc(
        arena, 1, sizeof(infix_reverse_call_frame_layout), _Alignof(infix_reverse_call_frame_layout));
    if (!layout)
        return INFIX_ERROR_ALLOCATION_FAILED;

    // The return buffer must be large enough and aligned for any type.
    size_t return_size = (context->return_type->size + 15) & ~15;
    // The array of pointers that will be passed to the C dispatcher.
    size_t args_array_size = (context->num_args * sizeof(void *) + 15) & ~15;
    // The contiguous block where we will save the actual argument data.
    size_t saved_args_data_size = 0;
    for (size_t i = 0; i < context->num_args; ++i) {
        if (context->arg_types[i]->size > INFIX_MAX_ARG_SIZE) {
            *out_layout = nullptr;
            return INFIX_ERROR_LAYOUT_FAILED;
        }
        // Ensure each saved argument slot is 16-byte aligned for simplicity and correctness.
        saved_args_data_size += (context->arg_types[i]->size + 15) & ~15;
    }
    // Security check against excessively large aggregate argument data size.
    if (saved_args_data_size > INFIX_MAX_ARG_SIZE) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    size_t total_local_space = return_size + args_array_size + saved_args_data_size;
    // The total stack allocation for the frame must be 16-byte aligned.
    if (total_local_space > INFIX_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }
    layout->total_stack_alloc = (total_local_space + 15) & ~15;

    // Local variables are accessed via positive offsets from the stack pointer (SP)
    // after the initial `sub sp, sp, #alloc` in the prologue.
    // The layout on our local stack will be: [ return_buffer | args_array | saved_args_data ]
    layout->return_buffer_offset = 0;
    layout->args_array_offset = layout->return_buffer_offset + return_size;
    layout->saved_args_offset = layout->args_array_offset + args_array_size;

    *out_layout = layout;
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 2 (Reverse): Generates the prologue for the reverse trampoline stub.
 * @details This function emits the standard AArch64 function entry code. It saves the
 *          caller's frame pointer (X29) and the link register (X30, the return address)
 *          to the stack, establishes a new frame by pointing X29 to the current stack
 *          pointer, and allocates the pre-calculated stack space for local variables.
 *
 * @param buf The code buffer to write to.
 * @param layout The blueprint containing the total stack space to allocate.
 * @return `INFIX_SUCCESS` on success.
 */
static infix_status generate_reverse_prologue_arm64(code_buffer * buf, infix_reverse_call_frame_layout * layout) {
    // `stp x29, x30, [sp, #-16]!` : Save Frame Pointer and Link Register, pre-decrementing SP.
    emit_arm64_stp_pre_index(buf, true, X29_FP_REG, X30_LR_REG, SP_REG, -16);

    // `mov x29, sp` : Establish the new frame pointer.
    emit_arm64_mov_reg(buf, true, X29_FP_REG, SP_REG);

    // `sub sp, sp, #total_stack_alloc` : Allocate space for our local variables.
    if (layout->total_stack_alloc > 0)
        emit_arm64_sub_imm(buf, true, false, SP_REG, SP_REG, layout->total_stack_alloc);
    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 3 (Reverse): Generates code to marshal arguments into the `void**` array.
 * @details This generates `STR` instructions to copy argument data from their native
 *          locations (GPRs, VPRs, or the caller's stack) into a contiguous "saved args"
 *          area on the stub's local stack. It then populates the `args_array` with
 *          pointers to this saved data, respecting all platform-specific ABI deviations.
 */
static infix_status generate_reverse_argument_marshalling_arm64(code_buffer * buf,
                                                                infix_reverse_call_frame_layout * layout,
                                                                infix_reverse_t * context) {
    // If the return type is a large struct, the caller passes a hidden pointer in X8.
    // We must save this pointer into our return buffer location immediately, as X8 is volatile.
    bool ret_is_aggregate =
        (context->return_type->category == INFIX_TYPE_STRUCT || context->return_type->category == INFIX_TYPE_UNION ||
         context->return_type->category == INFIX_TYPE_ARRAY || context->return_type->category == INFIX_TYPE_COMPLEX);

    bool return_in_memory = ret_is_aggregate && context->return_type->size > 16;

    if (return_in_memory)  // str x8, [sp, #return_buffer_offset]
        emit_arm64_str_imm(buf, true, X8_REG, SP_REG, layout->return_buffer_offset);

    size_t gpr_idx = 0, vpr_idx = 0, current_saved_data_offset = 0;
    // Arguments passed on the caller's stack start at an offset from our new frame pointer.
    // [fp] points to old fp, [fp, #8] points to old lr. Args start at [fp, #16].
    size_t caller_stack_offset = 16;

    for (size_t i = 0; i < context->num_args; ++i) {
        infix_type * type = context->arg_types[i];
        bool is_variadic_arg = i >= context->num_fixed_args;
        int32_t arg_save_loc = (int32_t)(layout->saved_args_offset + current_saved_data_offset);

#if defined(INFIX_OS_MACOS)
        // On macOS, all variadic arguments are passed on the stack.
        // This is a special case that bypasses all register logic.
        if (is_variadic_arg) {
            // On macOS, variadic args smaller than 8 bytes are promoted to an 8-byte stack slot.
            // We must copy the entire slot, not just the type's smaller size.
            size_t size_on_stack = (type->size < 8) ? 8 : type->size;
            size_on_stack = (size_on_stack + 7) & ~7;  // Ensure it's a multiple of 8

            for (size_t offset = 0; offset < size_on_stack; offset += 8) {
                emit_arm64_ldr_imm(buf, true, X9_REG, X29_FP_REG, caller_stack_offset + offset);
                int32_t dest_offset = arg_save_loc + offset;
                if (dest_offset >= 0 && ((unsigned)dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
                    emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
                else {
                    emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                    emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
                }
            }
            caller_stack_offset += size_on_stack;

            // Set the pointer in args_array to point to the saved data
            int32_t dest_offset = layout->args_array_offset + i * sizeof(void *);
            emit_arm64_add_imm(buf, true, false, X9_REG, SP_REG, arg_save_loc);
            if (dest_offset >= 0 && ((unsigned)dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
                emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
            else {
                emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
            }
            current_saved_data_offset += (type->size + 15) & ~15;
            continue;  // Skip to the next argument
        }
#endif

        // Standard logic for non-macOS or non-variadic arguments
        bool is_pass_by_ref = (type->size > 16) && !is_variadic_arg;
        bool is_from_stack = false;

        // Determine if the argument is expected in a VPR based on type and platform.
        bool expect_in_vpr = is_float(type) || is_double(type) || is_long_double(type);
#if defined(INFIX_OS_WINDOWS)
        if (context->is_variadic)
            expect_in_vpr = false;
#endif
        if (is_pass_by_ref) {
            int32_t dest_offset = layout->args_array_offset + i * sizeof(void *);
            arm64_gpr src_reg;

            if (gpr_idx < NUM_GPR_ARGS)
                src_reg = GPR_ARGS[gpr_idx++];
            else {
                emit_arm64_ldr_imm(buf, true, X9_REG, X29_FP_REG, caller_stack_offset);
                src_reg = X9_REG;
                caller_stack_offset += 8;
            }

            // Correctly check offset for an 8-byte store.
            if (dest_offset >= 0 && (dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
                emit_arm64_str_imm(buf, true, src_reg, SP_REG, dest_offset);
            else {
                emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                emit_arm64_str_imm(buf, true, src_reg, X10_REG, 0);
            }
            continue;
        }

        infix_type * hfa_base_type = nullptr;
        bool is_hfa_candidate = !is_variadic_arg && is_hfa(type, &hfa_base_type);

#if defined(INFIX_OS_WINDOWS)
        // Windows on ARM ABI disables HFA for variadic arguments.
        if (context->is_variadic)
            is_hfa_candidate = false;
#endif

        if (is_hfa_candidate) {
            size_t num_elements = type->size / hfa_base_type->size;
            if (vpr_idx + num_elements <= NUM_VPR_ARGS) {
                const int scale = is_double(hfa_base_type) ? 8 : 4;
                for (size_t j = 0; j < num_elements; ++j) {
                    int32_t dest_offset = arg_save_loc + j * hfa_base_type->size;
                    if (dest_offset >= 0 && ((unsigned)dest_offset / scale) <= 0xFFF && (dest_offset % scale == 0))
                        emit_arm64_str_vpr(buf, is_double(hfa_base_type), VPR_ARGS[vpr_idx++], SP_REG, dest_offset);
                    else {
                        emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                        emit_arm64_str_vpr(buf, is_double(hfa_base_type), VPR_ARGS[vpr_idx++], X10_REG, 0);
                    }
                }
            }
            else
                is_from_stack = true;
        }
        else if (expect_in_vpr) {
            if (vpr_idx < NUM_VPR_ARGS) {
                const int scale = is_long_double(type) ? 16 : (is_double(type) ? 8 : 4);
                if (arg_save_loc >= 0 && ((unsigned)arg_save_loc / scale) <= 0xFFF && (arg_save_loc % scale == 0)) {
                    if (is_long_double(type))
                        emit_arm64_str_q_imm(buf, VPR_ARGS[vpr_idx++], SP_REG, arg_save_loc);
                    else
                        emit_arm64_str_vpr(buf, is_double(type), VPR_ARGS[vpr_idx++], SP_REG, arg_save_loc);
                }
                else {
                    emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, arg_save_loc);
                    if (is_long_double(type))
                        emit_arm64_str_q_imm(buf, VPR_ARGS[vpr_idx++], X10_REG, 0);
                    else
                        emit_arm64_str_vpr(buf, is_double(type), VPR_ARGS[vpr_idx++], X10_REG, 0);
                }
            }
            else
                is_from_stack = true;
        }
        else {                     // Argument is in a GPR
            if (type->size > 8) {  // 16-byte value in two GPRs
                bool needs_alignment = true;
#if defined(INFIX_OS_MACOS)
                if (type->category == INFIX_TYPE_PRIMITIVE)
                    needs_alignment = false;
#elif defined(INFIX_OS_WINDOWS)
                if (is_variadic_arg)
                    needs_alignment = false;
#endif
                if (needs_alignment && (gpr_idx % 2 != 0))
                    gpr_idx++;

                if (gpr_idx + 1 < NUM_GPR_ARGS) {
                    if (arg_save_loc >= 0 && (((unsigned)arg_save_loc + 8) / 8) <= 0xFFF && (arg_save_loc % 8 == 0)) {
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], SP_REG, arg_save_loc);
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], SP_REG, arg_save_loc + 8);
                    }
                    else {
                        emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, arg_save_loc);
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], X10_REG, 0);
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], X10_REG, 8);
                    }
                }
                else
                    is_from_stack = true;
            }
            else {
                if (gpr_idx < NUM_GPR_ARGS) {
                    if (arg_save_loc >= 0 && ((unsigned)arg_save_loc / 8) <= 0xFFF && (arg_save_loc % 8 == 0))
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], SP_REG, arg_save_loc);
                    else {
                        emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, arg_save_loc);
                        emit_arm64_str_imm(buf, true, GPR_ARGS[gpr_idx++], X10_REG, 0);
                    }
                }
                else
                    is_from_stack = true;
            }
        }

        if (is_from_stack) {
            // On macOS, variadic args smaller than 8 bytes are promoted to an 8-byte stack slot.
            // We must copy the entire slot, not just the type's smaller size.
            size_t size_on_stack = (is_variadic_arg && type->size < 8) ? 8 : type->size;
            size_on_stack = (size_on_stack + 7) & ~7;  // Ensure it's a multiple of 8

            for (size_t offset = 0; offset < size_on_stack; offset += 8) {
                emit_arm64_ldr_imm(buf, true, X9_REG, X29_FP_REG, caller_stack_offset + offset);
                int32_t dest_offset = arg_save_loc + offset;
                if (dest_offset >= 0 && ((unsigned)dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
                    emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
                else {
                    emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                    emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
                }
            }
            caller_stack_offset += size_on_stack;
        }

        int32_t dest_offset = layout->args_array_offset + i * sizeof(void *);
        emit_arm64_add_imm(buf, true, false, X9_REG, SP_REG, arg_save_loc);
        if (dest_offset >= 0 && ((unsigned)dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
            emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
        else {
            emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
            emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
        }
        current_saved_data_offset += (type->size + 15) & ~15;
    }
    return INFIX_SUCCESS;
}


/**
 * @internal
 * @brief Stage 4 (Reverse): Generates the code to call the high-level C dispatcher function.
 * @details This emits the instructions to load the three arguments for the dispatcher
 *          (`context`, `return_buffer_ptr`, `args_array_ptr`) into the correct registers
 *          (X0, X1, X2) and then calls the dispatcher via `blr` (branch with link to register).
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context, containing the dispatcher's address.
 * @return `INFIX_SUCCESS` on success.
 */
static infix_status generate_reverse_dispatcher_call_arm64(code_buffer * buf,
                                                           infix_reverse_call_frame_layout * layout,
                                                           infix_reverse_t * context) {
    // Arg 1: Load context pointer into X0.
    emit_arm64_load_u64_immediate(buf, X0_REG, (uint64_t)context);

    bool ret_is_aggregate =
        (context->return_type->category == INFIX_TYPE_STRUCT || context->return_type->category == INFIX_TYPE_UNION ||
         context->return_type->category == INFIX_TYPE_ARRAY || context->return_type->category == INFIX_TYPE_COMPLEX);
    bool return_in_memory = ret_is_aggregate && context->return_type->size > 16;

    // Arg 2: Load pointer to return buffer into X1.
    if (return_in_memory)
        // We saved the pointer from X8 earlier, now we load it back.
        emit_arm64_ldr_imm(buf, true, X1_REG, SP_REG, layout->return_buffer_offset);
    else
        // The return buffer is on our stack, so we calculate its address.
        emit_arm64_add_imm(buf, true, false, X1_REG, SP_REG, layout->return_buffer_offset);

    // Arg 3: Load pointer to args_array into X2.
    emit_arm64_add_imm(buf, true, false, X2_REG, SP_REG, layout->args_array_offset);

    // Load the C dispatcher's address into a scratch register (X9) and call it.
    emit_arm64_load_u64_immediate(buf, X9_REG, (uint64_t)context->internal_dispatcher);
    emit_arm64_blr_reg(buf, X9_REG);  // blr x9

    return INFIX_SUCCESS;
}

/**
 * @internal
 * @brief Stage 5 (Reverse): Generates the epilogue for the reverse trampoline stub.
 * @details After the C dispatcher returns, this code retrieves the return value from the
 *          return buffer on the stub's local stack and places it into the correct native return
 *          registers (X0, X1, V0, etc.) as required by the AAPCS64. It then tears down the
 *          stack frame and returns control to the native caller.
 */
static infix_status generate_reverse_epilogue_arm64(code_buffer * buf,
                                                    infix_reverse_call_frame_layout * layout,
                                                    infix_reverse_t * context) {
    bool ret_is_aggregate =
        (context->return_type->category == INFIX_TYPE_STRUCT || context->return_type->category == INFIX_TYPE_UNION ||
         context->return_type->category == INFIX_TYPE_ARRAY || context->return_type->category == INFIX_TYPE_COMPLEX);
    bool return_in_memory = ret_is_aggregate && context->return_type->size > 16;
    if (context->return_type->category != INFIX_TYPE_VOID && !return_in_memory) {
        infix_type * base = nullptr;
        if (is_hfa(context->return_type, &base)) {
            size_t num_elements = context->return_type->size / base->size;
            for (size_t i = 0; i < num_elements; ++i) {
                emit_arm64_ldr_vpr(
                    buf, is_double(base), VPR_ARGS[i], SP_REG, layout->return_buffer_offset + i * base->size);
            }
        }
        else if (is_long_double(context->return_type))
            emit_arm64_ldr_q_imm(buf, V0_REG, SP_REG, layout->return_buffer_offset);
        else if (is_float(context->return_type) || is_double(context->return_type))
            emit_arm64_ldr_vpr(buf, is_double(context->return_type), V0_REG, SP_REG, layout->return_buffer_offset);
        else {
            // Integer, pointer, or small struct returned in GPRs.
            emit_arm64_ldr_imm(buf, true, X0_REG, SP_REG, layout->return_buffer_offset);
            if (context->return_type->size > 8)
                emit_arm64_ldr_imm(buf, true, X1_REG, SP_REG, layout->return_buffer_offset + 8);
        }
    }

    // Deallocate stack and restore frame.
    if (layout->total_stack_alloc > 0)
        // add sp, sp, #total_stack_alloc
        emit_arm64_add_imm(buf, true, false, SP_REG, SP_REG, layout->total_stack_alloc);

    // Restore Frame Pointer and Link Register, then return.
    emit_arm64_ldp_post_index(
        buf, true, X29_FP_REG, X30_LR_REG, SP_REG, 16);  // ldp x29, x30, [sp], #16 (Load pair, post-indexed)
    emit_arm64_ret(buf, X30_LR_REG);                     // ret

    return INFIX_SUCCESS;
}
