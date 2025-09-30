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
 * @file abi_win_x64.c
 * @brief Implements the FFI logic for the Windows x64 calling convention.
 *
 * @details This file provides the concrete implementation of the `infix_forward_abi_spec`
 * and `infix_reverse_abi_spec` for the Microsoft x64 calling convention. This ABI is
 * used on all 64-bit versions of the Windows operating system.
 *
 * Key features and differences from the System V ABI implemented here:
 * 1.  **Register Usage:** The first four integer/pointer arguments are passed in
 *     RCX, RDX, R8, and R9 respectively. The first four floating-point arguments
 *     are passed in XMM0, XMM1, XMM2, and XMM3. Each argument corresponds to a
 *     single "slot," regardless of type.
 * 2.  **Shadow Space:** The caller is required to allocate a 32-byte "shadow space"
 *     on the stack just above the arguments. The callee may use this space to spill
 *     the argument registers.
 * 3.  **By-Reference Passing:** A core difference is that aggregates (structs/unions)
 *     and large primitives are passed by reference (a pointer is passed) if their
 *     size is not a power of two (1, 2, 4, or 8 bytes). This is a simpler rule than
 *     System V's complex classification scheme.
 * 4.  **Return Values:** Structs are returned in RAX if their size is 1, 2, 4, or 8.
 *     Larger structs are returned via a hidden pointer. For GCC/Clang, 16-byte primitives
 *     (like `__int128_t` and `long double`) are returned in `XMM0`.
 */

// This file performs many safe conversions from size_t to int32_t for instruction
// offsets. The library's internal limits (INFIX_MAX_STACK_ALLOC) ensure these
// conversions do not lose data. We disable the warning to produce a clean build.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4267)  // conversion from 'size_t' to 'int32_t'
#endif

#include "common/infix_internals.h"
#include "common/utility.h"
#include <abi_x64_common.h>
#include <abi_x64_emitters.h>
#include <stdbool.h>
#include <stdlib.h>

/** @brief An array of GPRs used for passing the first four integer/pointer arguments. */
static const x64_gpr GPR_ARGS[] = {RCX_REG, RDX_REG, R8_REG, R9_REG};
/** @brief An array of XMM registers used for passing the first four floating-point arguments. */
static const x64_xmm XMM_ARGS[] = {XMM0_REG, XMM1_REG, XMM2_REG, XMM3_REG};
/** @brief The number of register "slots" available for arguments. */
#define NUM_GPR_ARGS 4
/** @brief The number of XMM registers used for arguments. */
#define NUM_XMM_ARGS 4
/** @brief The size in bytes of the mandatory stack space reserved by the caller for the callee. */
#define SHADOW_SPACE 32

// Forward Declarations
static infix_status prepare_forward_call_frame_win_x64(infix_arena_t * arena,
                                                       infix_call_frame_layout ** out_layout,
                                                       infix_type * ret_type,
                                                       infix_type ** arg_types,
                                                       size_t num_args,
                                                       size_t num_fixed_args);
static infix_status generate_forward_prologue_win_x64(code_buffer * buf, infix_call_frame_layout * layout);
static infix_status generate_forward_argument_moves_win_x64(code_buffer * buf,
                                                            infix_call_frame_layout * layout,
                                                            infix_type ** arg_types,
                                                            size_t num_args,
                                                            size_t num_fixed_args);
static infix_status generate_forward_epilogue_win_x64(code_buffer * buf,
                                                      infix_call_frame_layout * layout,
                                                      infix_type * ret_type);
static infix_status prepare_reverse_call_frame_win_x64(infix_arena_t * arena,
                                                       infix_reverse_call_frame_layout ** out_layout,
                                                       infix_reverse_t * context);
static infix_status generate_reverse_prologue_win_x64(code_buffer * buf, infix_reverse_call_frame_layout * layout);
static infix_status generate_reverse_argument_marshalling_win_x64(code_buffer * buf,
                                                                  infix_reverse_call_frame_layout * layout,
                                                                  infix_reverse_t * context);
static infix_status generate_reverse_dispatcher_call_win_x64(code_buffer * buf,
                                                             infix_reverse_call_frame_layout * layout,
                                                             infix_reverse_t * context);
static infix_status generate_reverse_epilogue_win_x64(code_buffer * buf,
                                                      infix_reverse_call_frame_layout * layout,
                                                      infix_reverse_t * context);
/** @brief The v-table of Windows x64 functions for generating forward trampolines. */
const infix_forward_abi_spec g_win_x64_forward_spec = {.prepare_forward_call_frame = prepare_forward_call_frame_win_x64,
                                                       .generate_forward_prologue = generate_forward_prologue_win_x64,
                                                       .generate_forward_argument_moves =
                                                           generate_forward_argument_moves_win_x64,
                                                       .generate_forward_epilogue = generate_forward_epilogue_win_x64};
/** @brief The v-table of Windows x64 functions for generating reverse trampolines. */
const infix_reverse_abi_spec g_win_x64_reverse_spec = {
    .prepare_reverse_call_frame = prepare_reverse_call_frame_win_x64,
    .generate_reverse_prologue = generate_reverse_prologue_win_x64,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_win_x64,
    .generate_reverse_dispatcher_call = generate_reverse_dispatcher_call_win_x64,
    .generate_reverse_epilogue = generate_reverse_epilogue_win_x64};

/**
 * @internal
 * @brief Determines if a return value should be passed by reference (via hidden pointer)
 *        according to the Windows x64 ABI.
 * @param type The infix_type of the return value.
 * @return `true` if the type should be returned by reference, `false` otherwise.
 */
static bool return_value_is_by_reference(infix_type * type) {
    if (type->category == INFIX_TYPE_STRUCT || type->category == INFIX_TYPE_UNION ||
        type->category == INFIX_TYPE_ARRAY || type->category == INFIX_TYPE_COMPLEX)
        // According to the Microsoft x64 ABI, aggregates are returned by reference
        // if their size is NOT 1, 2, 4, or 8 bytes. This correctly includes 16-byte structs.
        return type->size != 1 && type->size != 2 && type->size != 4 && type->size != 8;

#if defined(INFIX_COMPILER_GCC)
    // GCC/Clang have a special case for returning long double by reference on Windows.
    if (is_long_double(type))
        return true;
#endif
    return false;
}

/**
 * @brief Analyzes a function signature and determines the argument passing layout for Windows x64.
 * @details This is the primary classification function for the Windows x64 ABI. It iterates
 *          through each argument and assigns it to a register or stack location.
 *
 *          Key ABI rules implemented:
 *          - **Register Slots:** The first four arguments are passed in registers. These "slots"
 *            are shared between GPRs (RCX, RDX, R8, R9) and XMM registers (XMM0-XMM3).
 *            For example, if the first argument is a `double` (in XMM0), the second integer
 *            argument will be in `RDX` (the second slot), not `RCX`.
 *          - **Return Value:** Large structs are returned via a hidden pointer passed by the
 *            caller in `RCX`, consuming the first argument slot.
 *          - **By-Reference Passing:** Any type (struct, union, or primitive like `long double`)
 *            is passed by reference (a pointer is passed in a GPR) if its size is not a
 *            power of two (1, 2, 4, or 8 bytes). Otherwise, it is passed by value.
 *          - **Stack Arguments:** All arguments after the fourth slot are passed on the stack.
 *            The caller is responsible for allocating space for these.
 *
 * @param[out] out_layout On success, will point to a newly allocated `infix_call_frame_layout`
 *                        that contains the "blueprint" for the call.
 * @param ret_type The `infix_type` of the function's return value.
 * @param arg_types An array of `infix_type` pointers for the arguments.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of non-variadic arguments. (Note: Variadic handling is
 *                       the same as non-variadic for register/stack assignment in Win x64).
 * @return `INFIX_SUCCESS` on success, or an error code on failure.
 */
static infix_status prepare_forward_call_frame_win_x64(infix_arena_t * arena,
                                                       infix_call_frame_layout ** out_layout,
                                                       infix_type * ret_type,
                                                       infix_type ** arg_types,
                                                       size_t num_args,
                                                       size_t num_fixed_args) {
    if (out_layout == nullptr)
        return INFIX_ERROR_INVALID_ARGUMENT;
    infix_call_frame_layout * layout =
        infix_arena_calloc(arena, 1, sizeof(infix_call_frame_layout), _Alignof(infix_call_frame_layout));
    if (layout == nullptr) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    layout->is_variadic = num_args > num_fixed_args;
    layout->arg_locations =
        infix_arena_calloc(arena, num_args, sizeof(infix_arg_location), _Alignof(infix_arg_location));
    if (layout->arg_locations == nullptr && num_args > 0) {
        *out_layout = nullptr;
        return INFIX_ERROR_ALLOCATION_FAILED;
    }
    layout->return_value_in_memory = return_value_is_by_reference(ret_type);
    size_t arg_position = 0;
    if (layout->return_value_in_memory)
        arg_position++;  // The hidden return pointer consumes the first slot (RCX).

    size_t current_stack_offset = SHADOW_SPACE;
    layout->num_stack_args = 0;
    for (size_t i = 0; i < num_args; ++i) {
        infix_type * current_type = arg_types[i];

        bool is_fp = is_float(current_type) || is_double(current_type);
        bool is_ref = is_passed_by_reference(current_type);
        bool is_variadic_arg = (i >= num_fixed_args);
        if (arg_position < 4) {
            if (is_fp && !is_ref && !is_variadic_arg) {
                layout->arg_locations[i].type = ARG_LOCATION_XMM;
                layout->arg_locations[i].reg_index = (uint8_t)arg_position++;
            }
            else {
                layout->arg_locations[i].type = ARG_LOCATION_GPR;
                layout->arg_locations[i].reg_index = (uint8_t)arg_position++;
            }
        }
        else {
            layout->arg_locations[i].type = ARG_LOCATION_STACK;
            layout->arg_locations[i].stack_offset = (uint32_t)current_stack_offset;
            layout->num_stack_args++;
            // Calculate space needed on the stack for this argument.
            // By-reference types are just a pointer (8 bytes).
            size_t arg_stack_space = is_ref ? 8 : ((current_type->size + 7) & ~7);
            current_stack_offset += arg_stack_space;
            // Step 0: Make sure we aren't blowing ourselves up
            if (current_stack_offset > INFIX_MAX_ARG_SIZE) {
                *out_layout = nullptr;
                return INFIX_ERROR_LAYOUT_FAILED;
            }
        }
    }

    size_t total_stack_arg_size = current_stack_offset - SHADOW_SPACE;


    // Total allocation must include shadow space and be 16-byte aligned.
    layout->total_stack_alloc = (SHADOW_SPACE + total_stack_arg_size + 15) & ~15;

    // Prevent integer overflow and excessive stack allocation.
    if (layout->total_stack_alloc > INFIX_MAX_STACK_ALLOC) {
        fprintf(stderr, "Error: Calculated stack allocation exceeds safe limit of %d bytes.\n", INFIX_MAX_STACK_ALLOC);
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }
    *out_layout = layout;
    return INFIX_SUCCESS;
}

/**
 * @brief Generates the function prologue for the Windows x64 forward trampoline.
 * @details This function emits the standard machine code required at the beginning of a function.
 *          The generated assembly performs these steps:
 *          1.  `push rbp` / `mov rbp, rsp`: Creates a standard stack frame.
 *          2.  `push r12-r15`: Saves all callee-saved registers that the trampoline will
 *              use to hold its context (target function pointer, return buffer, args array).
 *          3.  `mov r12, rcx`, etc.: Moves the trampoline's own arguments (which arrive in
 *              RCX, RDX, R8) into the preserved registers (R12, R13, R14).
 *          4.  `sub rsp, imm32`: Allocates the required space on the stack. This allocation
 *              **must** include the 32-byte "shadow space" (or "home space") that the
 *              callee is free to use, in addition to space for any arguments passed on the stack.
 *
 * @param buf The code buffer to write the assembly into.
 * @param layout The call frame layout containing total stack allocation information.
 * @return `INFIX_SUCCESS` on successful code generation.
 */
static infix_status generate_forward_prologue_win_x64(code_buffer * buf, infix_call_frame_layout * layout) {
    emit_byte(buf, 0x55);               // push rbp
    EMIT_BYTES(buf, 0x48, 0x89, 0xE5);  // mov rbp, rsp

    // Save callee-saved registers we will use to hold our context.
    EMIT_BYTES(buf, 0x41, 0x54);  // push r12 (will hold target function address)
    EMIT_BYTES(buf, 0x41, 0x55);  // push r13 (will hold return value pointer)
    EMIT_BYTES(buf, 0x41, 0x56);  // push r14 (will hold argument pointers array)
    EMIT_BYTES(buf, 0x41, 0x57);  // push r15 (will be a scratch register for data moves)

    // Move incoming trampoline arguments (which are in RCX, RDX, R8)
    // to non-volatile registers so they persist across the function call.
    emit_mov_reg_reg(buf, R12_REG, RCX_REG);  // R12 = target function
    emit_mov_reg_reg(buf, R13_REG, RDX_REG);  // R13 = return value buffer
    emit_mov_reg_reg(buf, R14_REG, R8_REG);   // R14 = argument values array

    // Allocate stack space for arguments and shadow space.
    if (layout->total_stack_alloc > 0) {
        EMIT_BYTES(buf, 0x48, 0x81, 0xEC);  // sub rsp, imm32 ...
        emit_int32(buf, (int32_t)layout->total_stack_alloc);
    }
    return INFIX_SUCCESS;
}

/**
 * @brief Generates code to move arguments from the `args_array` into their correct locations.
 * @details This function iterates through the `infix_call_frame_layout` blueprint and emits
 *          the necessary `mov` instructions to place each argument into its assigned
 *          register or stack slot for the upcoming native call.
 *
 *          Key behaviors implemented:
 *          - **Register Arguments:** Loads data from the `void**` array into the correct
 *            GPR (RCX, RDX, R8, R9) or XMM register (XMM0-XMM3) based on the argument's slot.
 *          - **Sign-Extension:** Correctly uses `movsxd` for signed integers smaller than
 *            64 bits to ensure they are properly sign-extended in the destination register.
 *          - **By-Reference Arguments:** If an argument is passed by reference (e.g., a large
 *            struct or long double), it loads the pointer directly into the GPR.
 *          - **Stack Arguments:** Copies data for stack-based arguments (the 5th argument and
 *            onward) from the `void**` array to the stack, at an offset that is *past* the
 *            32-byte shadow space. An optimization is used to bulk-copy homogeneous arguments.
 *
 * @param buf The code buffer.
 * @param layout The call frame layout specifying where each argument goes.
 * @param arg_types The array of argument types.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of fixed (non-variadic) arguments.
 * @return `INFIX_SUCCESS` on success, or `INFIX_ERROR_LAYOUT_FAILED` if the layout is invalid.
 */
static infix_status generate_forward_argument_moves_win_x64(code_buffer * buf,
                                                            infix_call_frame_layout * layout,
                                                            infix_type ** arg_types,
                                                            size_t num_args,
                                                            size_t num_fixed_args) {
    if (layout->return_value_in_memory)
        emit_mov_reg_reg(buf, GPR_ARGS[0], R13_REG);
    for (size_t i = 0; i < num_args; ++i) {
        infix_type * current_type = arg_types[i];
        infix_arg_location * loc = &layout->arg_locations[i];
        bool is_variadic_arg = (i >= num_fixed_args);
        if (loc->type == ARG_LOCATION_STACK)
            continue;
        // R15 = pointer to the argument's data.
        emit_mov_reg_mem(buf, R15_REG, R14_REG, (int32_t)(i * sizeof(void *)));
        if (loc->type == ARG_LOCATION_GPR) {
            if (is_passed_by_reference(current_type)) {
                emit_mov_reg_reg(buf, GPR_ARGS[loc->reg_index], R15_REG);
            }
            else if (layout->is_variadic && is_variadic_arg && (is_float(current_type) || is_double(current_type))) {
                x64_xmm xmm_reg = XMM_ARGS[loc->reg_index];
                x64_gpr gpr_reg = GPR_ARGS[loc->reg_index];
                if (is_float(current_type)) {
                    emit_movss_xmm_mem(buf, xmm_reg, R15_REG, 0);
                    EMIT_BYTES(buf, 0xF3);
                    emit_rex_prefix(buf, 0, xmm_reg >= XMM8_REG, 0, xmm_reg >= XMM8_REG);
                    EMIT_BYTES(buf, 0x0F, 0x5A);
                    emit_modrm(buf, 3, xmm_reg % 8, xmm_reg % 8);
                }
                else {
                    emit_movsd_xmm_mem(buf, xmm_reg, R15_REG, 0);
                }
                emit_movq_gpr_xmm(buf, gpr_reg, xmm_reg);
            }
            else {
                bool is_signed = current_type->category == INFIX_TYPE_PRIMITIVE &&
                    (current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT8 ||
                     current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT16 ||
                     current_type->meta.primitive_id == INFIX_PRIMITIVE_SINT32);
                if (is_variadic_arg && current_type->size < 4 && is_signed) {
                    if (current_type->size == 1)
                        emit_movsx_reg64_mem8(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    else if (current_type->size == 2)
                        emit_movsx_reg64_mem16(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                }
                else if (is_signed && current_type->size <= 4) {
                    emit_movsxd_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                }
                else {
                    emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                }
            }
        }
        else {
            if (is_float(current_type))
                emit_movss_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            else
                emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
        }
    }
    for (size_t i = 0; i < num_args; ++i) {
        if (layout->arg_locations[i].type != ARG_LOCATION_STACK)
            continue;
        infix_type * current_type = arg_types[i];
        infix_arg_location * loc = &layout->arg_locations[i];
        emit_mov_reg_mem(buf, R15_REG, R14_REG, i * sizeof(void *));
        if (is_passed_by_reference(current_type))
            emit_mov_mem_reg(buf, RSP_REG, loc->stack_offset, R15_REG);
        else {
            size_t arg_size_on_stack = (current_type->size + 7) & ~7;
            for (size_t offset = 0; offset < arg_size_on_stack; offset += 8) {
                emit_mov_reg_mem(buf, RAX_REG, R15_REG, offset);
                emit_mov_mem_reg(buf, RSP_REG, loc->stack_offset + offset, RAX_REG);
            }
        }
    }
    return INFIX_SUCCESS;
}

/**
 * @brief Generates the function epilogue for the Windows x64 forward trampoline.
 * @details This function emits the code to handle the function's return value and
 *          properly tear down the stack frame.
 *
 *          Key behaviors implemented:
 *          - **Return Value Handling:** After the native `call` returns, it copies the
 *            result from the return register (`RAX` for integers/pointers, `XMM0` for
 *            floats/doubles) into the user-provided return buffer.
 *          - **Stack Cleanup:** Deallocates the stack space that was reserved in the prologue.
 *          - **Register Restoration:** Restores the saved callee-saved registers (r12-r15)
 *            and the caller's base pointer (`rbp`).
 *          - **Return:** Executes a `ret` instruction to return to the trampoline's caller.
 *
 * @param buf The code buffer.
 * @param layout The call frame layout.
 * @param ret_type The `infix_type` of the function's return value.
 * @return `INFIX_SUCCESS` on successful code generation.
 */
static infix_status generate_forward_epilogue_win_x64(code_buffer * buf,
                                                      infix_call_frame_layout * layout,
                                                      infix_type * ret_type) {
    // Move the result from the return register (RAX/XMM0) into the FFI return buffer.
    // This must be done BEFORE cleaning up the stack.
    if (ret_type->category != INFIX_TYPE_VOID && !layout->return_value_in_memory) {
        if (is_float(ret_type))
            emit_movss_mem_xmm(buf, R13_REG, 0, XMM0_REG);
        else if (is_double(ret_type))
            emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);
#if !defined(INFIX_COMPILER_MSVC)
        // On GCC/Clang on Windows, 16-byte primitives (__int128_t, long double)
        // are returned in XMM0.
        else if (ret_type->size == 16 && ret_type->category == INFIX_TYPE_PRIMITIVE)
            // We need to emit 'movups [r13], xmm0'. Opcode: 0F 11.
            EMIT_BYTES(buf, 0x41, 0x0f, 0x11, 0x45, 0x00);  // movups [r13], xmm0
#endif
        else {
            // All other returnable-by-value types are in RAX.
            switch (ret_type->size) {
            case 1:  // bool, char
                emit_mov_mem_reg8(buf, R13_REG, 0, RAX_REG);
                break;
            case 2:  // short
                emit_mov_mem_reg16(buf, R13_REG, 0, RAX_REG);
                break;
            case 4:  // int
                emit_mov_mem_reg32(buf, R13_REG, 0, RAX_REG);
                break;
            case 8:  // long long, pointer
                emit_mov_mem_reg(buf, R13_REG, 0, RAX_REG);
                break;
            default:
                // This case should not be reachable due to `is_passed_by_reference`
                // and `return_value_in_memory` checks.
                break;
            }
        }
    }

    // Deallocate stack space
    if (layout->total_stack_alloc > 0) {
        EMIT_BYTES(buf, 0x48, 0x81, 0xC4);  // add rsp, imm32
        emit_int32(buf, layout->total_stack_alloc);
    }
    // Restore callee-saved registers in reverse order of push.
    EMIT_BYTES(buf, 0x41, 0x5F);  // pop r15
    EMIT_BYTES(buf, 0x41, 0x5E);  // pop r14
    EMIT_BYTES(buf, 0x41, 0x5D);  // pop r13
    EMIT_BYTES(buf, 0x41, 0x5C);  // pop r12
    emit_byte(buf, 0x5D);         // pop rbp
    emit_byte(buf, 0xC3);         // ret

    return INFIX_SUCCESS;
}

/**
 * @brief Stage 1: Calculates the stack layout for a reverse trampoline stub.
 * @details This function determines the total stack space needed by the JIT-compiled stub.
 * This space includes areas to save all incoming argument registers, a buffer for the
 * return value, the `args_array`, and a data area for by-value arguments. It also
 * includes the shadow space the stub must provide for the C dispatcher it calls.
 * @return `INFIX_SUCCESS` on success, or `INFIX_ERROR_ALLOCATION_FAILED`.
 */
static infix_status prepare_reverse_call_frame_win_x64(infix_arena_t * arena,
                                                       infix_reverse_call_frame_layout ** out_layout,
                                                       infix_reverse_t * context) {
    infix_reverse_call_frame_layout * layout = infix_arena_calloc(
        arena, 1, sizeof(infix_reverse_call_frame_layout), _Alignof(infix_reverse_call_frame_layout));
    if (!layout)
        return INFIX_ERROR_ALLOCATION_FAILED;
    size_t return_size = (context->return_type->size + 15) & ~15;
    size_t args_array_size = context->num_args * sizeof(void *);
    size_t saved_args_data_size = 0;
    for (size_t i = 0; i < context->num_args; ++i) {
        if (!is_passed_by_reference(context->arg_types[i]))
            saved_args_data_size += (context->arg_types[i]->size + 15) & ~15;
    }

    if (saved_args_data_size > INFIX_MAX_ARG_SIZE) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }

    size_t gpr_reg_save_area_size = NUM_GPR_ARGS * 8;
    size_t xmm_reg_save_area_size = NUM_XMM_ARGS * 16;
    size_t total_local_space = return_size + args_array_size + saved_args_data_size + gpr_reg_save_area_size +
        xmm_reg_save_area_size + SHADOW_SPACE;

    // Prevent integer overflow from fuzzer-provided types that are impractically large by ensuring the total required
    // stack space is within a safe limit.
    if (total_local_space > INFIX_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return INFIX_ERROR_LAYOUT_FAILED;
    }
    layout->total_stack_alloc = (total_local_space + 15) & ~15;
    layout->return_buffer_offset = SHADOW_SPACE;
    layout->gpr_save_area_offset = layout->return_buffer_offset + return_size;
    layout->xmm_save_area_offset = layout->gpr_save_area_offset + gpr_reg_save_area_size;
    layout->args_array_offset = layout->xmm_save_area_offset + xmm_reg_save_area_size;
    layout->saved_args_offset = layout->args_array_offset + args_array_size;
    *out_layout = layout;
    return INFIX_SUCCESS;
}

/**
 * @brief Stage 2: Generates the prologue for the reverse trampoline stub.
 * @details Emits the standard Windows x64 function entry code, creating a stack frame,
 * saving non-volatile registers, and allocating all necessary local stack space.
 * @param buf The code buffer.
 * @param layout The blueprint containing the total stack space to allocate.
 * @return `INFIX_SUCCESS`.
 */
static infix_status generate_reverse_prologue_win_x64(code_buffer * buf, infix_reverse_call_frame_layout * layout) {
    emit_byte(buf, 0x55);               // push rbp
    EMIT_BYTES(buf, 0x48, 0x89, 0xE5);  // mov rbp, rsp
    emit_byte(buf, 0x56);               // push rsi
    emit_byte(buf, 0x57);               // push rdi

    //
    EMIT_BYTES(buf, 0x48, 0x81, 0xEC);  // sub rsp, imm32
    emit_int32(buf, layout->total_stack_alloc);

    return INFIX_SUCCESS;
}

/**
 * @brief (Win x64) Stage 3: Generates code to marshal arguments into the generic `void**` array.
 * @details This function first saves all potential argument registers (RCX, RDX, R8, R9, XMM0-3)
 * to a dedicated area on the stack. Then, it iterates through the expected arguments, determines
 * their source (register save area or caller's stack), and populates the `args_array` with
 * pointers to them.
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context containing the argument type information.
 * @return `INFIX_SUCCESS`.
 */
static infix_status generate_reverse_argument_marshalling_win_x64(code_buffer * buf,
                                                                  infix_reverse_call_frame_layout * layout,
                                                                  infix_reverse_t * context) {
    // Save the incoming argument registers into their save area on our stack.
    emit_mov_mem_reg(buf, RSP_REG, layout->gpr_save_area_offset + 0 * 8, RCX_REG);
    emit_mov_mem_reg(buf, RSP_REG, layout->gpr_save_area_offset + 1 * 8, RDX_REG);
    emit_mov_mem_reg(buf, RSP_REG, layout->gpr_save_area_offset + 2 * 8, R8_REG);
    emit_mov_mem_reg(buf, RSP_REG, layout->gpr_save_area_offset + 3 * 8, R9_REG);
    emit_movups_mem_xmm(buf, RSP_REG, layout->xmm_save_area_offset + 0 * 16, XMM0_REG);
    emit_movups_mem_xmm(buf, RSP_REG, layout->xmm_save_area_offset + 1 * 16, XMM1_REG);
    emit_movups_mem_xmm(buf, RSP_REG, layout->xmm_save_area_offset + 2 * 16, XMM2_REG);
    emit_movups_mem_xmm(buf, RSP_REG, layout->xmm_save_area_offset + 3 * 16, XMM3_REG);

    size_t arg_pos_offset = return_value_is_by_reference(context->return_type) ? 1 : 0;
    size_t stack_slot_offset = 0;

    for (size_t i = 0; i < context->num_args; i++) {
        infix_type * current_type = context->arg_types[i];
        bool is_fp = is_float(current_type) || is_double(current_type);
        bool passed_by_ref = is_passed_by_reference(current_type);
        size_t arg_pos = i + arg_pos_offset;
        bool is_variadic_arg = (i >= context->num_fixed_args);

        if (arg_pos < 4) {
            // Determine the source of the argument data in our register save area.
            int32_t source_offset;
            bool use_xmm = is_fp && !is_variadic_arg;
            if (use_xmm) {
                source_offset = layout->xmm_save_area_offset + arg_pos * 16;
            }
            else {
                source_offset = layout->gpr_save_area_offset + arg_pos * 8;
            }

            // Is the source data the final argument, or a pointer to it?
            if (passed_by_ref) {
                // The value in the register IS the pointer we need for the args_array.
                emit_mov_reg_mem(buf, RAX_REG, RSP_REG, source_offset);
            }
            else {
                // The value in the register is the data. We must save it, then get a pointer to the saved copy.
                emit_lea_reg_mem(buf, RAX_REG, RSP_REG, source_offset);
            }
            emit_mov_mem_reg(buf, RSP_REG, layout->args_array_offset + i * sizeof(void *), RAX_REG);
        }
        else {
            // After our prologue `push rbp, mov rbp, rsp, push rsi, push rdi`, the stack layout is:
            // [RBP]      -> Old RBP
            // [RBP + 8]  -> Return Address
            // The caller's stack arguments start after their own shadow space.
            // So, the 5th argument is at [RBP + 8 (ret) + 8 (old RBP) + 32 (shadow space)] = [RBP + 48]
            int32_t caller_stack_offset = 16 + SHADOW_SPACE + (stack_slot_offset * 8);

            if (passed_by_ref) {
                emit_mov_reg_mem(buf, RAX_REG, RBP_REG, caller_stack_offset);
            }
            else {
                emit_lea_reg_mem(buf, RAX_REG, RBP_REG, caller_stack_offset);
            }
            emit_mov_mem_reg(buf, RSP_REG, layout->args_array_offset + i * sizeof(void *), RAX_REG);

            size_t size_on_stack = (passed_by_ref) ? 8 : current_type->size;
            stack_slot_offset += (size_on_stack + 7) / 8;
        }
    }
    return INFIX_SUCCESS;
}

/**
 * @brief Stage 4: Generates the code to call the high-level C dispatcher function.
 * @details Emits code to load the dispatcher's arguments (context, return buffer pointer, args
 * array pointer) into RCX, RDX, and R8, then calls the dispatcher function.
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context, containing the dispatcher's address.
 * @return `INFIX_SUCCESS`.
 */
static infix_status generate_reverse_dispatcher_call_win_x64(code_buffer * buf,
                                                             infix_reverse_call_frame_layout * layout,
                                                             infix_reverse_t * context) {
    EMIT_BYTES(buf, 0x48, 0xB9);  // mov rcx, #context
    emit_int64(buf, (int64_t)context);

    if (return_value_is_by_reference(context->return_type)) {
        emit_mov_reg_mem(buf, RDX_REG, RSP_REG, layout->gpr_save_area_offset + 0 * 8);
    }
    else {
        emit_lea_reg_mem(buf, RDX_REG, RSP_REG, layout->return_buffer_offset);
    }

    emit_lea_reg_mem(buf, R8_REG, RSP_REG, layout->args_array_offset);
    EMIT_BYTES(buf, 0x49, 0xBB);  // mov r9, #internal_dispatcher_func_ptr
    emit_int64(buf, (int64_t)context->internal_dispatcher);
    EMIT_BYTES(buf, 0x41, 0xFF, 0xD3);  // call r9

    return INFIX_SUCCESS;
}

/**
 * @brief (Win x64) Stage 5: Generates the epilogue for the reverse trampoline stub.
 * @details After the C dispatcher returns, this code retrieves the return value from the
 *          return buffer on the stub's stack and places it into the correct native return
 *          register (RAX or XMM0). It then deallocates the stack frame, restores saved
 *          registers, and returns to the original native caller.
 * @param buf The code buffer.
 * @param layout The blueprint containing the return buffer's offset.
 * @param context The context containing the return type information.
 * @return `INFIX_SUCCESS`.
 */
static infix_status generate_reverse_epilogue_win_x64(code_buffer * buf,
                                                      infix_reverse_call_frame_layout * layout,
                                                      infix_reverse_t * context) {
    // Handle the return value after the dispatcher returns.
    if (context->return_type->category != INFIX_TYPE_VOID) {
        if (return_value_is_by_reference(context->return_type)) {
            emit_mov_reg_mem(buf, RAX_REG, RSP_REG, layout->gpr_save_area_offset + 0 * 8);
        }
#if !defined(INFIX_COMPILER_MSVC)
        else if (context->return_type->size == 16 && context->return_type->category == INFIX_TYPE_PRIMITIVE) {
            // GCC/Clang on Windows returns 128-bit integers and long double in XMM0
            // We need to emit 'movups xmm0, [rsp + layout->return_buffer_offset]'. Opcode 0F 10.
            EMIT_BYTES(buf, 0x0f, 0x10, 0x84, 0x24);  // movups xmm0, [rsp+...]
            emit_int32(buf, layout->return_buffer_offset);
        }
#endif
        else if (is_float(context->return_type))
            emit_movss_xmm_mem(buf, XMM0_REG, RSP_REG, layout->return_buffer_offset);
        else if (is_double(context->return_type))
            emit_movsd_xmm_mem(buf, XMM0_REG, RSP_REG, layout->return_buffer_offset);
        else
            emit_mov_reg_mem(buf, RAX_REG, RSP_REG, layout->return_buffer_offset);
    }

    // Epilogue: deallocate stack and restore registers.
    EMIT_BYTES(buf, 0x48, 0x81, 0xC4);  // add rsp, imm32
    emit_int32(buf, layout->total_stack_alloc);
    emit_pop_reg(buf, RDI_REG);
    emit_pop_reg(buf, RSI_REG);
    emit_pop_reg(buf, RBP_REG);
    emit_byte(buf, 0xC3);  // ret

    return INFIX_SUCCESS;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
