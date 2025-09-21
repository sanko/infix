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
 * @brief Implements the FFI logic for the AArch64 (ARM64) architecture
 *        following the AAPCS64 calling convention, with specific handling for
 *        the Apple and Microsoft variants.
 *
 * @details This file provides the concrete implementation of the `ffi_forward_abi_spec`
 * and `ffi_reverse_abi_spec` for the ARM64 architecture. It handles the nuances
 * of the standard Procedure Call Standard for the ARM 64-bit Architecture (AAPCS64),
 * which is used by Linux, Android, and other non-Windows platforms.
 *
 * A key complexity handled here is the deviation of Apple's ABI for macOS on ARM64,
 * particularly concerning variadic functions, where all variadic arguments are
 * passed on the stack, unlike the standard ABI.
 *
 * The key responsibilities of this file are:
 *
 * - **Argument Classification:** Determining whether function arguments are passed in
 *   general-purpose registers (GPRs, X0-X7), floating-point/SIMD registers
 *   (VPRs, V0-V7), or on the stack. This includes handling the Apple-specific
 *   rules for variadic arguments.
 *
 * - **Homogeneous Aggregate Handling:** Correctly identifying and handling Homogeneous
 *   Floating-point Aggregates (HFAs), which are passed in VPRs.
 *
 * - **Code Generation:** Emitting the precise AArch64 machine code for:
 *   - Function prologues (setting up the stack frame).
 *   - Argument marshalling (moving arguments from the FFI's generic format into
 *     the correct registers and stack locations for a native call).
 *   - Function epilogues (handling return values and tearing down the frame).
 *
 * - **Reverse Trampolines:** Generating native, callable function stubs for user-provided
 *   callbacks, correctly un-marshalling arguments from the native ABI to the FFI's
 *   generic format, again respecting platform differences.
 *
 * The file is organized into two main sections:
 *
 * 1.  **Forward Call Implementation:** Contains the logic for generating a "forward"
 *     trampoline, a function that takes a generic set of arguments and calls a
 *     native C function with the correct, ABI-compliant register and stack layout.
 *     This includes handling complex cases like Homogeneous Floating-point Aggregates (HFAs)
 *     and large structs returned by value.
 *
 * 2.  **Reverse Call Implementation (Refactored):** Contains the logic for generating a
 *     "reverse" trampoline (or callback stub). This is a native C-callable function
 *     pointer that, when invoked, marshals its native arguments into a generic format
 *     and calls a user-provided C handler. This implementation has been decomposed
 *     into five distinct steps for clarity and maintainability.
 */

#include <infix_internals.h>
//
#include <abi_arm64_common.h>
#include <abi_arm64_emitters.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // For memcpy
#include <utility.h>

/** @brief The General-Purpose Registers used for the first 8 integer/pointer arguments. */
static const arm64_gpr GPR_ARGS[] = {X0_REG, X1_REG, X2_REG, X3_REG, X4_REG, X5_REG, X6_REG, X7_REG};
/** @brief The SIMD/Floating-Point Registers used for the first 8 float/double/vector arguments. */
static const arm64_vpr VPR_ARGS[] = {V0_REG, V1_REG, V2_REG, V3_REG, V4_REG, V5_REG, V6_REG, V7_REG};
/** @brief The total number of GPRs available for argument passing. */
#define NUM_GPR_ARGS 8
/** @brief The total number of VPRs available for argument passing. */
#define NUM_VPR_ARGS 8
/** @brief A safe limit on the number of fields to classify to prevent DoS from exponential complexity. */
#define MAX_AGGREGATE_FIELDS_TO_CLASSIFY 32

// Forward Declarations
static ffi_status prepare_forward_call_frame_arm64(arena_t * arena,
                                                   ffi_call_frame_layout ** out_layout,
                                                   ffi_type * ret_type,
                                                   ffi_type ** arg_types,
                                                   size_t num_args,
                                                   size_t num_fixed_args);
static ffi_status generate_forward_prologue_arm64(code_buffer * buf, ffi_call_frame_layout * layout);
static ffi_status generate_forward_argument_moves_arm64(code_buffer * buf,
                                                        ffi_call_frame_layout * layout,
                                                        ffi_type ** arg_types,
                                                        size_t num_args,
                                                        c23_maybe_unused size_t num_fixed_args);
static ffi_status generate_forward_epilogue_arm64(code_buffer * buf,
                                                  ffi_call_frame_layout * layout,
                                                  ffi_type * ret_type);
static bool is_hfa(ffi_type * type, ffi_type ** base_type);

static ffi_status prepare_reverse_call_frame_arm64(arena_t * arena,
                                                   ffi_reverse_call_frame_layout ** out_layout,
                                                   ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_prologue_arm64(code_buffer * buf, ffi_reverse_call_frame_layout * layout);
static ffi_status generate_reverse_argument_marshalling_arm64(code_buffer * buf,
                                                              ffi_reverse_call_frame_layout * layout,
                                                              ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_dispatcher_call_arm64(code_buffer * buf,
                                                         ffi_reverse_call_frame_layout * layout,
                                                         ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_epilogue_arm64(code_buffer * buf,
                                                  ffi_reverse_call_frame_layout * layout,
                                                  ffi_reverse_trampoline_t * context);

/**
 * @brief The v-table of AArch64-specific functions for generating forward trampolines.
 * @details This structure is passed to the generic trampoline generator in `trampoline.c`,
 * plugging in the platform-specific logic.
 */
const ffi_forward_abi_spec g_arm64_forward_spec = {.prepare_forward_call_frame = prepare_forward_call_frame_arm64,
                                                   .generate_forward_prologue = generate_forward_prologue_arm64,
                                                   .generate_forward_argument_moves =
                                                       generate_forward_argument_moves_arm64,
                                                   .generate_forward_epilogue = generate_forward_epilogue_arm64};

/**
 * @brief The v-table of AArch64-specific functions for generating reverse trampolines.
 * @details This structure provides the five-stage implementation for creating
 * a native callback stub on AArch64.
 */
const ffi_reverse_abi_spec g_arm64_reverse_spec = {
    .prepare_reverse_call_frame = prepare_reverse_call_frame_arm64,
    .generate_reverse_prologue = generate_reverse_prologue_arm64,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_arm64,
    .generate_reverse_dispatcher_call = generate_reverse_dispatcher_call_arm64,
    .generate_reverse_epilogue = generate_reverse_epilogue_arm64};

/**
 * @brief (Internal) Recursively finds the first primitive floating-point type in a potential HFA.
 * @details This function traverses a nested aggregate (struct or array) to find the
 *          `ffi_type` of the very first floating-point primitive (`float` or `double`)
 *          it contains. This is the first step in HFA classification.
 *
 * @param type The type to inspect.
 * @return A pointer to the `ffi_type` of the base element, or `nullptr` if not found.
 */
static ffi_type * get_hfa_base_type(ffi_type * type) {
    if (type == nullptr)
        return nullptr;
    // Base case: we've found a primitive float or double.
    if (is_float(type) || is_double(type))
        return type;
    // Recursive step for arrays.
    if (type->category == FFI_TYPE_ARRAY)
        return get_hfa_base_type(type->meta.array_info.element_type);
    // Recursive step for structs: check the first member.
    if (type->category == FFI_TYPE_STRUCT && type->meta.aggregate_info.num_members > 0)
        return get_hfa_base_type(type->meta.aggregate_info.members[0].type);
    return nullptr;  // Not a float-based type
}

/**
 * @brief Recursively verifies that all members of a type conform to a given base floating-point type.
 * @details After `get_hfa_base_type` finds a potential base type, this function
 *          recursively checks every single primitive member of the aggregate to ensure
 *          they are all of the exact same floating-point type.
 *
 * @param type The type to check (e.g., a struct or array).
 * @param base_type The required base type (e.g., `float`) to check against.
 * @return `true` if all constituent members of `type` are of `base_type`, `false` otherwise.
 */
static bool is_hfa_recursive_check(ffi_type * type, ffi_type * base_type, size_t * field_count) {
    // Limit the number of fields we are willing to inspect for a single aggregate.
    if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY)
        return false;

    // Base case: A primitive must match the base type.
    if (is_float(type) || is_double(type)) {
        (*field_count)++;
        return type == base_type;
    }
    // Recursive step for arrays.
    if (type->category == FFI_TYPE_ARRAY)
        return is_hfa_recursive_check(type->meta.array_info.element_type, base_type, field_count);
    // Recursive step for structs: check every member.
    if (type->category == FFI_TYPE_STRUCT) {
        if (type->meta.aggregate_info.num_members == 0)
            return false;
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            if (!is_hfa_recursive_check(type->meta.aggregate_info.members[i].type, base_type, field_count))
                return false;
        }
        return true;
    }
    return false;
}

/**
 * @brief Determines if a type is a Homogeneous Floating-point Aggregate (HFA).
 * @details This function implements the complete HFA classification rules from the AAPCS64.
 *          An HFA is a struct or array containing 1 to 4 elements of the same, single
 *          floating-point type (`float` or `double`), including nested aggregates.
 *          HFAs are a special case passed directly in consecutive floating-point (V) registers.
 *
 * @param type The `ffi_type` to check.
 * @param[out] out_base_type If the type is a valid HFA, this output parameter will be
 *                           set to point to the `ffi_type` of its base element (`float` or `double`).
 * @return `true` if the type is a valid HFA, `false` otherwise.
 */
static bool is_hfa(ffi_type * type, ffi_type ** out_base_type) {
    if (type->category != FFI_TYPE_STRUCT && type->category != FFI_TYPE_ARRAY)
        return false;

    if (type->size == 0 || type->size > 64)
        return false;

    // Find the base float/double type of the first primitive element.
    ffi_type * base = get_hfa_base_type(type);
    if (base == nullptr)
        return false;  // Not composed of floating-point types.

    // Check that the total size is a multiple of the base type, with 1 to 4 elements.
    size_t num_elements = type->size / base->size;
    if (num_elements < 1 || num_elements > 4)
        return false;
    if (type->size != num_elements * base->size)
        return false;

    // Initialize a counter for the recursive check to prevent DoS.
    size_t field_count = 0;

    // Verify that ALL members recursively conform to this single base type.
    if (!is_hfa_recursive_check(type, base, &field_count))
        return false;

    if (out_base_type)
        *out_base_type = base;
    return true;
}

/**
 * @brief Analyzes a function signature and determines the argument passing layout for AAPCS64.
 * @details This is the primary classification function for the ARM64 ABI. It assigns each
 *          argument to a location (GPR, VPR, or Stack) according to the rules.
 *
 *          Key ABI rules implemented:
 *          - **Register Assignment:** It independently tracks General-Purpose Registers (X0-X7)
 *            and SIMD/Floating-Point Registers (V0-V7).
 *          - **HFA Handling:** Correctly identifies HFAs using `is_hfa` and passes them in
 *            up to four consecutive V-registers.
 *          - **Large Aggregates:** Structs/unions larger than 16 bytes are passed by reference.
 *          - **Platform-Specific Variadic Calls:**
 *            - **Apple (macOS/iOS):** All variadic arguments (after the `...`) are passed on the stack.
 *              Crucially, any argument smaller than 8 bytes is promoted to fill an 8-byte stack slot.
 *            - **Standard Linux/BSD:** Variadic arguments are passed in registers if available.
 *          - **Return Value:** Large aggregates (> 16 bytes) are returned via a hidden pointer passed
 *            by the caller in the dedicated register `X8`.
 *
 * @param[out] out_layout On success, will point to a newly allocated `ffi_call_frame_layout`.
 * @param ret_type The `ffi_type` of the function's return value.
 * @param arg_types An array of `ffi_type` pointers for the arguments.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of non-variadic arguments.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
static ffi_status prepare_forward_call_frame_arm64(arena_t * arena,
                                                   ffi_call_frame_layout ** out_layout,
                                                   ffi_type * ret_type,
                                                   ffi_type ** arg_types,
                                                   size_t num_args,
                                                   size_t num_fixed_args) {
    if (out_layout == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;
    ffi_call_frame_layout * layout =
        arena_calloc(arena, 1, sizeof(ffi_call_frame_layout), _Alignof(ffi_call_frame_layout));
    if (layout == nullptr) {
        *out_layout = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    layout->arg_locations = arena_calloc(arena, num_args, sizeof(ffi_arg_location), _Alignof(ffi_arg_location));
    if (layout->arg_locations == nullptr && num_args > 0) {
        *out_layout = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    size_t gpr_count = 0, vpr_count = 0, stack_offset = 0;
    layout->is_variadic = (num_fixed_args < num_args);
    layout->num_args = num_args;
    layout->num_stack_args = 0;
    layout->return_value_in_memory = return_uses_hidden_pointer_abi(ret_type);

    for (size_t i = 0; i < num_args; ++i) {
        ffi_type * type = arg_types[i];

        // Step 0: Make sure we aren't blowing ourselves up
        if (type->size > FFI_MAX_ARG_SIZE) {
            *out_layout = NULL;
            return FFI_ERROR_LAYOUT_FAILED;
        }

        bool placed_in_register = false;
        bool is_variadic_arg = (i >= num_fixed_args);

#if defined(FFI_OS_MACOS)
        // Apple's ABI mandates that all variadic arguments are passed on the stack.
        if (layout->is_variadic && is_variadic_arg) {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = (uint32_t)stack_offset;

            // Any argument smaller than 8 bytes must be promoted to an 8-byte slot on the stack. This calculation
            // ensures the stack offset for subsequent arguments is correct.
            size_t arg_size_on_stack = (type->size < 8) ? 8 : type->size;
            stack_offset += (arg_size_on_stack + 7) & ~7;
            layout->num_stack_args++;
            continue;  // Argument classified, proceed to the next one.
        }
#endif

        bool pass_fp_in_vpr = is_float(type) || is_double(type) || is_long_double(type);
#if defined(FFI_OS_WINDOWS)
        // Windows on ARM ABI: If the function is variadic, ALL floating-point
        // arguments are passed in general-purpose registers.
        if (layout->is_variadic)
            pass_fp_in_vpr = false;
#endif
        ffi_type * hfa_base_type = nullptr;
        // The order of these checks is critical to prevent incorrect classification.
        // Check for HFA first, as it's the most specific aggregate rule.

        // Classification for non-variadic arguments (or all arguments on non-Apple platforms).
        if (!is_variadic_arg && is_hfa(type, &hfa_base_type)) {
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

    // The total stack space for arguments must be 16-byte aligned.
    layout->total_stack_alloc = (stack_offset + 15) & ~15;
    layout->num_gpr_args = (uint8_t)gpr_count;
    layout->num_vpr_args = (uint8_t)vpr_count;

    // Prevent integer overflow and excessive stack allocation.
    if (layout->total_stack_alloc > FFI_MAX_STACK_ALLOC) {
        fprintf(stderr, "Error: Calculated stack allocation exceeds safe limit of %d bytes.\n", FFI_MAX_STACK_ALLOC);
        *out_layout = nullptr;
        return FFI_ERROR_LAYOUT_FAILED;
    }

    *out_layout = layout;
    return FFI_SUCCESS;
}

/**
 * @brief Generates the function prologue for the ARM64 forward trampoline.
 * @details This function emits the standard machine code required at the beginning of a function.
 *          The generated assembly performs these steps:
 *          1.  `stp x29, x30, [sp, #-16]!`: Saves the frame pointer (FP/x29) and link
 *              register (LR/x30) to the stack. This is the standard function entry.
 *          2.  `mov x29, sp`: Sets the new frame pointer to the current stack pointer.
 *          3.  `stp x19, x20, [sp, #-16]!`, etc.: Saves callee-saved registers (X19-X22)
 *              that the trampoline will use to hold its context.
 *          4.  `mov x19, x0`, etc.: Moves the trampoline's own arguments (which arrive in
 *              X0, X1, X2) into the preserved registers for use across the native call.
 *          5.  `sub sp, sp, #imm`: Allocates the required space on the stack for any
 *              arguments that will be passed on the stack.
 *
 * @param buf The code buffer to write the assembly into.
 * @param layout The call frame layout containing stack allocation information.
 * @return `FFI_SUCCESS` on success.
 */
static ffi_status generate_forward_prologue_arm64(code_buffer * buf, ffi_call_frame_layout * layout) {
    emit_int32(buf, 0xA9BF7BFD);  // stp x29, x30, [sp, #-16]! (Save Frame Pointer and Link Register)
    emit_int32(buf, 0x910003FD);  // mov x29, sp               (Set new Frame Pointer)
    emit_int32(buf, 0xA9BF53F3);  // stp x19, x20, [sp, #-16]! (Save callee-saved regs for our context)
    emit_int32(buf, 0xA9BF5BF5);  // stp x21, x22, [sp, #-16]!
    emit_int32(buf, 0xAA0003F3);  // mov x19, x0               (x19 = target_func)
    emit_int32(buf, 0xAA0103F4);  // mov x20, x1               (x20 = return_value_ptr)
    emit_int32(buf, 0xAA0203F5);  // mov x21, x2               (x21 = args_array)

    if (layout->total_stack_alloc > 0)
        emit_arm64_sub_imm(buf, true, false, SP_REG, SP_REG, (uint32_t)layout->total_stack_alloc);

    return FFI_SUCCESS;
}

/**
 * @brief Generates machine code to move arguments from the generic FFI format into their native locations.
 * @details This function is a critical part of the trampoline generation process. It iterates
 *          through the `ffi_call_frame_layout` blueprint and emits the necessary AArch64
 *          machine code to place each argument into its assigned register (GPR or VPR) or
 *          stack slot for the upcoming native function call.
 *
 *          Key behaviors implemented:
 *
 *          - **Register Context:** It assumes that the trampoline's own arguments have been saved
 *            in callee-saved registers during the prologue:
 *            - `x19`: Holds the pointer to the native C function to be called.
 *            - `x20`: Holds the pointer to the buffer for the return value.
 *            - `x21`: Holds the base address of the `void** args_array`.
 *
 *          - **Argument Loading:** For each argument, it first loads the pointer to that
 *            argument's data from the `args_array` into a caller-saved scratch register (`x9`).
 *
 *          - **Register Arguments:** It generates code to move data from the location pointed
 *            to by `x9` into the correct GPR (for integers/pointers) or VPR (for floats/doubles).
 *
 *          - **Sign-Extension:** It correctly uses the `LDRSW` instruction for signed integers
 *            smaller than 64 bits to ensure they are properly sign-extended in the destination
 *            register, a requirement of the C language and the ABI.
 *
 *          - **Stack Arguments & Platform Specificity:**
 *            - **Standard (Linux/BSD):** It copies data for stack-based arguments from the
 *              user's buffer to the correct offset on the callee's stack frame. It now
 *              handles large offsets that exceed the instruction's immediate range by using
 *              a scratch register.
 *            - **Apple (macOS/iOS) Variadic Calls:** It implements the specific rules for
 *              Apple's ABI where all variadic arguments are passed on the stack.
 *                - It correctly sign-extends and promotes smaller integer types (e.g., `int`)
 *                  to fill a full 8-byte stack slot.
 *                - It uses a caller-saved scratch VPR (`v16`) to correctly move floating-point
 *                  values to the stack, avoiding ABI violations and data corruption.
 *
 *          - **ABI Quirks:**
 *            - If the function returns a large struct, it moves the return buffer pointer (`x20`)
 *              into the indirect result location register (`x8`).
 *            - For variadic calls on standard AArch64 (non-Apple platforms), this implementation
 *              sets a GPR to 0, which is a safe value indicating the number of VPRs used.
 *
 * @param buf The code buffer to which the machine code will be written.
 * @param layout The call frame layout blueprint that specifies where each argument must go.
 * @param arg_types The array of `ffi_type` pointers for the function's arguments.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of fixed (non-variadic) arguments.
 * @return `FFI_SUCCESS` on successful code generation.
 */
static ffi_status generate_forward_argument_moves_arm64(code_buffer * buf,
                                                        ffi_call_frame_layout * layout,
                                                        ffi_type ** arg_types,
                                                        size_t num_args,
                                                        c23_maybe_unused size_t num_fixed_args) {
    // If returning a large struct, the ABI requires the hidden pointer (our return buffer)
    // to be passed in the indirect result location register, x8.
    if (layout->return_value_in_memory)
        emit_int32(buf, 0xAA1403E8);  // mov x8, x20

    // Standard AAPCS64 Quirk: For variadic calls, a GPR must contain the number of VPRs used.
    // This rule does NOT apply to Apple's ABI, so we exclude it for macOS.
#if !defined(FFI_OS_MACOS)
    else if (layout->is_variadic)
        // Since we don't know the types of variadic arguments at compile time, the ABI
        // states the safest value is 0. A callee like printf will use this to determine
        // how to process its va_list. We use x8 as it's a volatile register.
        // A safe default is 0. Callee (like printf) uses this to interpret its va_list.
        emit_int32(buf, 0xd2800008);  // mov x8, #0
#endif

    for (size_t i = 0; i < num_args; ++i) {
        ffi_arg_location * loc = &layout->arg_locations[i];
        ffi_type * type = arg_types[i];

        // Load the pointer to the current argument's data into scratch register x9.
        // x21 holds the base of the void** args_array.
        emit_arm64_ldr_imm(buf, true, X9_REG, X21_REG, (int32_t)(i * sizeof(void *)));  // ldr x9, [x21, #offset]

        switch (loc->type) {
        case ARG_LOCATION_GPR:
            {
                // C requires that signed integer types smaller than a full register be
                // sign-extended when passed. We check for this case here.
                bool is_signed_lt_64 = type->category == FFI_TYPE_PRIMITIVE && type->size < 8 &&
                    (type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT8 ||
                     type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT16 ||
                     type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT32);

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
            emit_int32(buf, 0xAA0903E0 | GPR_ARGS[loc->reg_index]);  // mov xN, x9
            break;
        case ARG_LOCATION_VPR:
            if (is_long_double(type))
                emit_arm64_ldr_q_imm(buf, VPR_ARGS[loc->reg_index], X9_REG, 0);  // ldr qN, [x9]
            else
                emit_arm64_ldr_vpr(buf, is_double(type), VPR_ARGS[loc->reg_index], X9_REG, 0);  // ldr dN/sN, [x9]
            break;
        case ARG_LOCATION_VPR_HFA:
            {
                ffi_type * base = nullptr;
                is_hfa(type, &base);
                for (uint8_t j = 0; j < loc->num_regs; ++j)
                    emit_arm64_ldr_vpr(
                        buf, is_double(base), VPR_ARGS[loc->reg_index + j], X9_REG, (int32_t)(j * base->size));
                break;
            }
        case ARG_LOCATION_STACK:
            {
#if defined(FFI_OS_MACOS)
                if (layout->is_variadic && i >= num_fixed_args) {
                    // Apple ABI: All variadic arguments are on the stack and promoted to 8 bytes if smaller.
                    const int32_t max_imm_offset = 0xFFF * 8;

                    // Handle promotable primitive types first.
                    if (type->category == FFI_TYPE_PRIMITIVE || type->category == FFI_TYPE_POINTER) {
                        if (is_float(type) || is_double(type)) {
                            // Floats are promoted to doubles.
                            emit_arm64_ldr_vpr(buf, true, V16_REG, X9_REG, 0);  // Load as double
                            if (loc->stack_offset < max_imm_offset)
                                emit_arm64_str_vpr(buf, true, V16_REG, SP_REG, loc->stack_offset);
                            else {
                                emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, loc->stack_offset);
                                emit_arm64_str_vpr(buf, true, V16_REG, X10_REG, 0);
                            }
                        }
                        else {  // Integer and pointer types
                            bool is_signed_lt_64 = type->category == FFI_TYPE_PRIMITIVE && type->size < 8 &&
                                (type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT8 ||
                                 type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT16 ||
                                 type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT32);

                            // Load into scratch GPR X10, applying correct promotion.
                            if (type->size >= 8)  // 64-bit integers and pointers
                                emit_arm64_ldr_imm(buf, true, X10_REG, X9_REG, 0);
                            else if (is_signed_lt_64)  // Signed types < 64-bit
                                emit_arm64_ldrsw_imm(buf, X10_REG, X9_REG, 0);
                            else  // Unsigned types < 64-bit
                                emit_arm64_ldr_imm(buf, false, X10_REG, X9_REG, 0);


                            // Store the promoted 64-bit value.
                            if (loc->stack_offset < max_imm_offset)
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
    return FFI_SUCCESS;
}

/**
 * @brief Generates the function epilogue for the ARM64 forward trampoline.
 * @details This function emits the code to handle the function's return value and
 *          properly tear down the stack frame.
 *
 *          Key behaviors implemented:
 *          - **Return Value Handling:** After the native `blr` returns, it copies the result
 *            from the return registers (`X0`/`X1` for integer/struct, `V0`-`V3` for HFA)
 *            into the user-provided return buffer. It now uses correctly sized store
 *            instructions (`strb`, `strh`, `str`) to prevent buffer overruns.
 *          - **Stack Cleanup:** Deallocates the stack space that was reserved in the prologue.
 *          - **Register Restoration:** Restores the saved callee-saved registers (X19-X22) and
 *            the caller's frame pointer (`x29`) and link register (`x30`).
 *          - **Return:** Executes a `ret` instruction to return to the trampoline's caller.
 *
 * @param buf The code buffer.
 * @param layout The call frame layout.
 * @param ret_type The `ffi_type` of the function's return value.
 * @return `FFI_SUCCESS` on success.
 */
static ffi_status generate_forward_epilogue_arm64(code_buffer * buf,
                                                  ffi_call_frame_layout * layout,
                                                  ffi_type * ret_type) {
    if (ret_type->category != FFI_TYPE_VOID && !layout->return_value_in_memory) {
        ffi_type * hfa_base = nullptr;
        // The order of these checks is critical. Handle the most specific cases first.
        if (is_long_double(ret_type))
            // On non-Apple AArch64, long double is 16 bytes and returned in V0.
            // On Apple, this case is never hit because types.c aliases it to a standard double.
            emit_arm64_str_q_imm(buf, V0_REG, X20_REG, 0);  // str q0, [x20]
        else if (is_hfa(ret_type, &hfa_base)) {
            size_t num_elements = ret_type->size / hfa_base->size;
            for (size_t i = 0; i < num_elements; ++i)
                emit_arm64_str_vpr(buf, is_double(hfa_base), VPR_ARGS[i], X20_REG, i * hfa_base->size);
        }
        else if (is_float(ret_type))
            emit_arm64_str_vpr(buf, false, V0_REG, X20_REG, 0);  // Use 32-bit store for float
        else if (is_double(ret_type))
            emit_arm64_str_vpr(buf, true, V0_REG, X20_REG, 0);  // Use 64-bit store for double
        else {
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
            }
        }
    }

    if (layout->total_stack_alloc > 0)
        emit_arm64_add_imm(buf, true, false, SP_REG, SP_REG, layout->total_stack_alloc);  // add sp, sp, #...

    emit_int32(buf, 0xA8C15BF5);  // ldp x21, x22, [sp], #16
    emit_int32(buf, 0xA8C153F3);  // ldp x19, x20, [sp], #16
    emit_int32(buf, 0xA8C17BFD);  // ldp x29, x30, [sp], #16
    emit_int32(buf, 0xD65F03C0);  // ret

    return FFI_SUCCESS;
}

/**
 * @brief (AArch64) Stage 1: Calculates the stack layout for a reverse trampoline stub.
 * @details This function calculates the total stack space needed by the JIT-compiled
 *          callback stub for all its local variables. This includes space for:
 *          - A buffer to store the return value before it's placed in registers.
 *          - The `void** args_array` that will be passed to the C dispatcher.
 *          - A contiguous save area where the data from all incoming arguments will be stored.
 *
 * @param[out] out_layout The resulting reverse call frame layout blueprint, populated with offsets.
 * @param context The reverse trampoline context with full signature information.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
static ffi_status prepare_reverse_call_frame_arm64(arena_t * arena,
                                                   ffi_reverse_call_frame_layout ** out_layout,
                                                   ffi_reverse_trampoline_t * context) {
    ffi_reverse_call_frame_layout * layout =
        arena_calloc(arena, 1, sizeof(ffi_reverse_call_frame_layout), _Alignof(ffi_reverse_call_frame_layout));
    if (!layout)
        return FFI_ERROR_ALLOCATION_FAILED;

    // The return buffer must be large enough and aligned for any type.
    size_t return_size = (context->return_type->size + 15) & ~15;
    // The array of pointers to arguments.
    size_t args_array_size = (context->num_args * sizeof(void *) + 15) & ~15;
    // The contiguous block where we will save the actual argument data.
    size_t saved_args_data_size = 0;
    for (size_t i = 0; i < context->num_args; ++i)
        // Ensure each saved argument is 16-byte aligned for simplicity.
        saved_args_data_size += (context->arg_types[i]->size + 15) & ~15;

    if (saved_args_data_size > FFI_MAX_ARG_SIZE) {
        *out_layout = NULL;
        return FFI_ERROR_LAYOUT_FAILED;
    }

    size_t total_local_space = return_size + args_array_size + saved_args_data_size;
    // The total stack allocation must be 16-byte aligned.
    // Prevent integer overflow from fuzzer-provided types that are impractically large by ensuring the total
    // required stack space is within a safe limit.
    if (total_local_space > FFI_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return FFI_ERROR_LAYOUT_FAILED;
    }
    layout->total_stack_alloc = (total_local_space + 15) & ~15;

    // Define layout of our local stack variables relative to SP after allocation.
    // Offsets are positive from the stack pointer.
    // We must perform these checks sequentially to prevent overflow when calculating each offset.
    layout->return_buffer_offset = 0;
    layout->args_array_offset = layout->return_buffer_offset + return_size;
    layout->saved_args_offset = layout->args_array_offset + args_array_size;

    *out_layout = layout;
    return FFI_SUCCESS;
}

/**
 * @brief Stage 2: Generates the machine code for the reverse trampoline's prologue.
 * @details This function emits the standard AArch64 function entry code. It saves the
 *          caller's frame pointer (X29) and the link register (X30, the return address)
 *          to the stack, establishes a new frame by pointing X29 to the current stack
 *          pointer, and allocates the pre-calculated stack space for local variables.
 *
 * @param buf The code buffer to write to.
 * @param layout The blueprint containing the total stack space to allocate.
 * @return `FFI_SUCCESS` on success.
 */
static ffi_status generate_reverse_prologue_arm64(code_buffer * buf, ffi_reverse_call_frame_layout * layout) {
    emit_int32(buf, 0xA9BF7BFD);  // stp x29, x30, [sp, #-16]!
    emit_int32(buf, 0x910003FD);  // mov x29, sp
    if (layout->total_stack_alloc > 0)
        emit_arm64_sub_imm(buf, true, false, SP_REG, SP_REG, layout->total_stack_alloc);
    return FFI_SUCCESS;
}

/**
 * @brief (AArch64) Stage 3: Generates code to un-marshal arguments into the generic `void**` array.
 * @details This is the core logic of the reverse trampoline. It generates the machine code
 *          that performs the "un-marshalling" of arguments from their native, ABI-specific
 *          locations (GPRs, VPRs, or the caller's stack) into the generic `void**` array
 *          format expected by the internal C dispatcher.
 *
 *          The process for each argument is as follows:
 *          1.  **Determine Source:** It identifies where the incoming argument is located based on
 *              the AAPCS64 calling convention (e.g., in register `X0`, `V1`, or at `[fp, #16]`).
 *
 *          2.  **Save Data (for by-value args):** For arguments passed by value, it generates
 *              `STR` (store) instructions to copy the data from its source location into a
 *              contiguous "saved args data" area on the local stack frame of the stub.
 *
 *          3.  **Populate Pointer Array:** It then generates code to store a pointer to this
 *              saved data (or, for by-reference arguments, the original pointer itself) into
 *              the `args_array` on the local stack.
 *
 * @param buf The code buffer to which the machine code will be written.
 * @param layout The blueprint containing stack offsets for the save areas and `args_array`.
 * @param context The context containing the full argument type information for the callback.
 * @return `FFI_SUCCESS` on success, or `FFI_ERROR_LAYOUT_FAILED` if any calculated offset
 *         would violate architectural limits.
 */
static ffi_status generate_reverse_argument_marshalling_arm64(code_buffer * buf,
                                                              ffi_reverse_call_frame_layout * layout,
                                                              ffi_reverse_trampoline_t * context) {
    // If the return type is a large struct, the caller passes a hidden pointer in X8.
    // We must save this pointer into our return buffer location immediately.
    if (context->return_type->size > 16)
        // str x8, [sp, #return_buffer_offset]
        emit_arm64_str_imm(buf, true, X8_REG, SP_REG, layout->return_buffer_offset);

    size_t gpr_idx = 0, vpr_idx = 0, current_saved_data_offset = 0;
    size_t caller_stack_offset = 16;  // Caller args start at [fp, #16]

    for (size_t i = 0; i < context->num_args; i++) {
        ffi_type * type = context->arg_types[i];
        bool is_variadic_arg = i >= context->num_fixed_args;
        bool is_pass_by_ref = (type->size > 16) && !is_variadic_arg;
        bool is_from_stack = false;

        // Determine if the argument is expected in a VPR based on type and platform.
        bool expect_in_vpr = is_float(type) || is_double(type) || is_long_double(type);
#if defined(FFI_OS_WINDOWS)
        if (context->is_variadic)
            expect_in_vpr = false;
#elif defined(FFI_OS_MACOS)
        // On macOS, all variadic arguments are on the stack.
        if (is_variadic_arg)
            is_from_stack = true;
#endif
        // Case 1: Argument is passed by reference (a pointer in a GPR).
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

        // Case 2: Argument is passed by value.
        int32_t arg_save_loc = (int32_t)(layout->saved_args_offset + current_saved_data_offset);

        ffi_type * hfa_base_type = NULL;

        if (!is_from_stack) {
            if (!is_variadic_arg && is_hfa(type, &hfa_base_type)) {
                size_t num_elements = type->size / hfa_base_type->size;
                if (vpr_idx + num_elements <= NUM_VPR_ARGS) {
                    const int scale = is_double(hfa_base_type) ? 8 : 4;
                    for (size_t j = 0; j < num_elements; ++j) {
                        int32_t dest_offset = arg_save_loc + j * hfa_base_type->size;
                        if (dest_offset >= 0 && (dest_offset / scale) <= 0xFFF && (dest_offset % scale == 0))
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
                    if (arg_save_loc >= 0 && (arg_save_loc / scale) <= 0xFFF && (arg_save_loc % scale == 0)) {
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
                    if (gpr_idx + 1 < NUM_GPR_ARGS) {
                        if (arg_save_loc >= 0 && ((arg_save_loc + 8) / 8) <= 0xFFF && (arg_save_loc % 8 == 0)) {
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
                else {  // <= 8-byte value in one GPR
                    if (gpr_idx < NUM_GPR_ARGS) {
                        if (arg_save_loc >= 0 && (arg_save_loc / 8) <= 0xFFF && (arg_save_loc % 8 == 0))
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
        }

        if (is_from_stack) {
            for (size_t offset = 0; offset < type->size; offset += 8) {
                emit_arm64_ldr_imm(buf, true, X9_REG, X29_FP_REG, caller_stack_offset + offset);
                int32_t dest_offset = arg_save_loc + offset;
                if (dest_offset >= 0 && (dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
                    emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
                else {
                    emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
                    emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
                }
            }
            caller_stack_offset += (type->size + 7) & ~7;
        }

        int32_t dest_offset = layout->args_array_offset + i * sizeof(void *);
        emit_arm64_add_imm(buf, true, false, X9_REG, SP_REG, arg_save_loc);
        if (dest_offset >= 0 && (dest_offset / 8) <= 0xFFF && (dest_offset % 8 == 0))
            emit_arm64_str_imm(buf, true, X9_REG, SP_REG, dest_offset);
        else {
            emit_arm64_add_imm(buf, true, false, X10_REG, SP_REG, dest_offset);
            emit_arm64_str_imm(buf, true, X9_REG, X10_REG, 0);
        }
        current_saved_data_offset += (type->size + 15) & ~15;
    }
    return FFI_SUCCESS;
}

/**
 * @brief Stage 4: Generates the code to call the high-level C dispatcher function.
 * @details This emits the instructions to load the three arguments for the dispatcher
 * (`context`, `return_buffer_ptr`, `args_array_ptr`) into the correct registers
 * (X0, X1, X2) and then calls the dispatcher via `blr` (branch with link to register).
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context, containing the dispatcher's address.
 * @return `FFI_SUCCESS` on success.
 */
static ffi_status generate_reverse_dispatcher_call_arm64(code_buffer * buf,
                                                         ffi_reverse_call_frame_layout * layout,
                                                         ffi_reverse_trampoline_t * context) {
    // Arg 1: Load context pointer into X0.
    emit_arm64_load_u64_immediate(buf, X0_REG, (uint64_t)context);
    // Arg 2: Load pointer to return buffer into X1.
    if (context->return_type->size > 16)
        // We saved the pointer from X8 earlier, now we load it back.
        emit_arm64_ldr_imm(buf, true, X1_REG, SP_REG, layout->return_buffer_offset);
    else
        // The return buffer is on our stack, so we calculate its address.
        emit_arm64_add_imm(buf, true, false, X1_REG, SP_REG, layout->return_buffer_offset);

    // Arg 3: Load pointer to args_array into X2.
    emit_arm64_add_imm(buf, true, false, X2_REG, SP_REG, layout->args_array_offset);

    // Load the C dispatcher's address into a scratch register (X9) and call it.
    emit_arm64_load_u64_immediate(buf, X9_REG, (uint64_t)context->internal_dispatcher);
    emit_int32(buf, 0xD63F0120);  // blr x9
    return FFI_SUCCESS;
}

/**
 * @brief (AArch64) Stage 5: Generates code to handle the return value and tear down the stack frame.
 * @details After the C dispatcher returns, this code retrieves the return value from the
 *          return buffer on the stub's stack and places it into the correct native return
 *          registers (X0, X1, V0, etc.) as required by the AAPCS64. It then deallocates
 *          the stack frame, restores the caller's frame/link registers, and returns.
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing the return buffer's offset.
 * @param context The context containing the return type information.
 * @return `FFI_SUCCESS` on success.
 */
static ffi_status generate_reverse_epilogue_arm64(code_buffer * buf,
                                                  ffi_reverse_call_frame_layout * layout,
                                                  ffi_reverse_trampoline_t * context) {
    // If the function returns a value and it's not passed via hidden pointer...
    if (context->return_type->category != FFI_TYPE_VOID && context->return_type->size <= 16) {
        ffi_type * base = nullptr;
        if (is_hfa(context->return_type, &base)) {
            size_t num_elements = context->return_type->size / base->size;
            for (size_t i = 0; i < num_elements; ++i)
                emit_arm64_ldr_vpr(
                    buf, is_double(base), VPR_ARGS[i], SP_REG, layout->return_buffer_offset + i * base->size);
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

    emit_int32(buf, 0xA8C17BFD);  // ldp x29, x30, [sp], #16 (Load pair, post-indexed)
    emit_int32(buf, 0xD65F03C0);  // ret
    return FFI_SUCCESS;
}
