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
 *
 * @details This file provides the concrete implementation of the `ffi_abi_spec`
 * for the System V x86-64 ABI, which is the standard calling convention for
 * Linux, macOS, BSD, and other UNIX-like operating systems on this architecture.
 *
 * The logic herein is responsible for generating the machine code for "trampolines"—small,
 * dynamically-created functions that bridge the gap between the generic FFI call format
 * and the specific, native calling convention of the target platform.
 *
 * Key features of the System V ABI implemented here:
 *
 * 1.  **Register Usage:** The first six integer/pointer arguments are passed in
 *     RDI, RSI, RDX, RCX, R8, and R9. The first eight floating-point arguments
 *     are passed in XMM0-XMM7. Unlike Windows, these register sets are handled
 *     independently.
 *
 * 2.  **Aggregate Classification:** Structs and unions up to 16 bytes are classified
 *     recursively based on the types of their fields. The classification process examines
 *     the aggregate in 8-byte chunks ("eightbytes"). Based on the classes of these
 *     eightbytes (INTEGER, SSE, MEMORY), the aggregate can be passed in up to two
 *     registers, which can be a mix of GPRs and XMMs. Aggregates larger than 16
 *     bytes, or those with complex layouts, are passed by reference on the stack.
 *
 * 3.  **Return Values:**
 *     - Small aggregates (<= 16 bytes) are returned in registers based on their classification.
 *       For example, a `{int, int}` is returned in RAX and RDX. A `{double, int}` is
 *       returned in XMM0 and RAX.
 *     - Larger aggregates (> 16 bytes) are returned via a hidden pointer passed by the
 *       caller as the first (hidden) argument in RDI.
 *     - **`long double` is a special case and is returned in the x87 FPU register `st(0)`.**
 *
 * 4.  **Red Zone:** A 128-byte area below the stack pointer that leaf functions can
 *     use without explicitly adjusting the stack pointer. This FFI implementation avoids
 *     using the red zone to ensure compatibility with non-leaf functions (as our
 *     trampolines call other functions).
 *
 * 5.  **Variadic Functions:** Before calling a variadic function, the value in the `AL`
 *     register (the lowest 8 bits of RAX) must be set to the number of XMM registers
 *     used for arguments. This allows the callee (e.g., `printf`) to correctly process
 *     `va_list` for floating-point arguments.
 */

#include <abi_x64_common.h>
#include <abi_x64_emitters.h>
#include <infix.h>
#include <stdbool.h>
#include <stdlib.h>
#include <utility.h>

/** @brief An array of GPRs used for passing the first 6 integer/pointer arguments, in order. */
static const x64_gpr GPR_ARGS[] = {RDI_REG, RSI_REG, RDX_REG, RCX_REG, R8_REG, R9_REG};
/** @brief An array of XMM registers used for passing the first 8 floating-point arguments, in order. */
static const x64_xmm XMM_ARGS[] = {XMM0_REG, XMM1_REG, XMM2_REG, XMM3_REG, XMM4_REG, XMM5_REG, XMM6_REG, XMM7_REG};
/** @brief The number of GPRs available for argument passing. */
#define NUM_GPR_ARGS 6
/** @brief The number of XMM registers available for argument passing. */
#define NUM_XMM_ARGS 8

/** @brief A safe recursion limit for the aggregate classification algorithm to prevent stack overflow. */
#define MAX_CLASSIFY_DEPTH 32
/** @brief A safe limit on the number of fields to classify to prevent DoS from exponential complexity. */
#define MAX_AGGREGATE_FIELDS_TO_CLASSIFY 32

/**
 * @brief The System V classification for an "eightbyte" (a 64-bit chunk of a type).
 * @internal This enum represents the classes defined by the ABI for each 8-byte portion of an argument.
 *           An aggregate (struct/union) is analyzed as one or two of these eightbytes to determine
 *           how it should be passed.
 */
typedef enum {
    NO_CLASS,  ///< This eightbyte has not been classified yet. It's the initial state.
    INTEGER,   ///< This eightbyte should be passed in a general-purpose register (GPR).
    SSE,       ///< This eightbyte should be passed in an SSE register (XMM).
    MEMORY     ///< The argument is too complex or large and must be passed on the stack.
} arg_class_t;

// Forward Declarations
static ffi_status prepare_forward_call_frame_sysv_x64(arena_t * arena,
                                                      ffi_call_frame_layout ** out_layout,
                                                      ffi_type * ret_type,
                                                      ffi_type ** arg_types,
                                                      size_t num_args,
                                                      size_t num_fixed_args);
static ffi_status generate_forward_prologue_sysv_x64(code_buffer * buf, ffi_call_frame_layout * layout);
static ffi_status generate_forward_argument_moves_sysv_x64(
    code_buffer * buf, ffi_call_frame_layout * layout, ffi_type ** arg_types, size_t num_args, size_t num_fixed_args);
static ffi_status generate_forward_epilogue_sysv_x64(code_buffer * buf,
                                                     ffi_call_frame_layout * layout,
                                                     ffi_type * ret_type);
static ffi_status prepare_reverse_call_frame_sysv_x64(arena_t * arena,
                                                      ffi_reverse_call_frame_layout ** out_layout,
                                                      ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_prologue_sysv_x64(code_buffer * buf, ffi_reverse_call_frame_layout * layout);
static ffi_status generate_reverse_argument_marshalling_sysv_x64(code_buffer * buf,
                                                                 ffi_reverse_call_frame_layout * layout,
                                                                 ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_dispatcher_call_sysv_x64(code_buffer * buf,
                                                            ffi_reverse_call_frame_layout * layout,
                                                            ffi_reverse_trampoline_t * context);
static ffi_status generate_reverse_epilogue_sysv_x64(code_buffer * buf,
                                                     ffi_reverse_call_frame_layout * layout,
                                                     ffi_reverse_trampoline_t * context);

/** @brief The v-table of System V x64 functions for generating forward trampolines. */
const ffi_forward_abi_spec g_sysv_x64_forward_spec = {.prepare_forward_call_frame = prepare_forward_call_frame_sysv_x64,
                                                      .generate_forward_prologue = generate_forward_prologue_sysv_x64,
                                                      .generate_forward_argument_moves =
                                                          generate_forward_argument_moves_sysv_x64,
                                                      .generate_forward_epilogue = generate_forward_epilogue_sysv_x64};
/** @brief The v-table of System V x64 functions for generating reverse trampolines. */
const ffi_reverse_abi_spec g_sysv_x64_reverse_spec = {
    .prepare_reverse_call_frame = prepare_reverse_call_frame_sysv_x64,
    .generate_reverse_prologue = generate_reverse_prologue_sysv_x64,
    .generate_reverse_argument_marshalling = generate_reverse_argument_marshalling_sysv_x64,
    .generate_reverse_dispatcher_call = generate_reverse_dispatcher_call_sysv_x64,
    .generate_reverse_epilogue = generate_reverse_epilogue_sysv_x64};

/**
 * @brief Recursively classifies the eightbytes of an aggregate type.
 * @details This is the core of the complex System V classification algorithm. It traverses
 * the fields of a struct/array, examining each 8-byte chunk ("eightbyte") and assigning it a
 * class (INTEGER, SSE, etc.).
 *
 * This function now also detects unaligned fields. According to the ABI, if any
 * field within a struct is not aligned to its natural boundary (e.g., a uint64_t at offset 1),
 * the entire struct must be classified as MEMORY.
 *
 * @param type The ffi_type of the current member/element being examined.
 * @param offset The byte offset of this member from the start of the aggregate.
 * @param[in,out] classes An array of two `arg_class_t` that is updated during classification.
 * @param depth The current recursion depth.
 * @param field_count [in,out] A counter for the total number of fields inspected for this aggregate.
 * @return `true` if an unaligned field was found (forcing MEMORY classification), `false` otherwise.
 */
static bool classify_recursive(
    ffi_type * type, size_t offset, arg_class_t classes[2], int depth, size_t * field_count) {
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

    if (type->category == FFI_TYPE_PRIMITIVE) {
        (*field_count)++;
        // `long double` is a special case. It is passed in memory on the stack, not x87 registers.
        if (is_long_double(type)) {
            classes[0] = MEMORY;
            return true;
        }
        // Determine which eightbyte this primitive falls into.
        size_t index = offset / 8;
        if (index < 2) {
            // Classify based on whether it's a floating-point or integer type.
            arg_class_t new_class = (is_float(type) || is_double(type)) ? SSE : INTEGER;

            // Merge the new class with the existing class for this eightbyte.
            // The rule is: if an eightbyte contains both SSE and INTEGER parts, it is classified as INTEGER.
            if (classes[index] != new_class)
                classes[index] = (classes[index] == NO_CLASS) ? new_class : INTEGER;
        }
        return false;
    }
    if (type->category == FFI_TYPE_POINTER) {
        (*field_count)++;
        size_t index = offset / 8;
        if (index < 2 && classes[index] != INTEGER)
            classes[index] = INTEGER;  // Pointers are always INTEGER class. Merge with existing class.
        return false;
    }
    if (type->category == FFI_TYPE_ARRAY) {
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
    if (type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION) {
        // Recursively classify each member of the struct/union.
        for (size_t i = 0; i < type->meta.aggregate_info.num_members; ++i) {
            // Check count *before* each recursive call inside the loop.
            if (*field_count > MAX_AGGREGATE_FIELDS_TO_CLASSIFY) {
                classes[0] = MEMORY;
                return true;
            }
            ffi_struct_member * member = &type->meta.aggregate_info.members[i];
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
 * @brief Classifies an aggregate type (struct/union) for argument passing according to the System V ABI.
 * @details This function implements the complete, recursive System V classification algorithm.
 *          An aggregate is broken down into up to two "eightbytes" (64-bit chunks).
 *          Each eightbyte is then classified as INTEGER, SSE, or MEMORY.
 *
 * @param type The aggregate type to classify.
 * @param[out] classes An array of two `arg_class_t` that will be filled with the
 *                     classification for the first and second eightbytes.
 * @param[out] num_classes A pointer that will be set to the number of valid classes (1 or 2).
 */
static void classify_aggregate_sysv(ffi_type * type, arg_class_t classes[2], size_t * num_classes) {
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
 * @brief Analyzes a function signature and creates a "blueprint" for calling it under the System V AMD64 ABI.
 * @details This is the primary classification function for the System V ABI. It is responsible for
 *          iterating through a function's arguments and return type to determine precisely where
 *          each piece of data must be placed (in which registers or on the stack) for a native
 *          call. It allocates and populates an `ffi_call_frame_layout` structure that contains all
 *          the information the code generator needs to emit a valid trampoline.
 *
 * @param[out] out_layout On success, this will point to a newly allocated `ffi_call_frame_layout`
 *                        structure containing the blueprint for the function call. The caller is
 *                        responsible for freeing this structure.
 * @param ret_type The `ffi_type` describing the function's return value.
 * @param arg_types An array of `ffi_type` pointers for the function's arguments.
 * @param num_args The total number of arguments in the `arg_types` array.
 * @param num_fixed_args The number of non-variadic arguments.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
static ffi_status prepare_forward_call_frame_sysv_x64(arena_t * arena,
                                                      ffi_call_frame_layout ** out_layout,
                                                      ffi_type * ret_type,
                                                      ffi_type ** arg_types,
                                                      size_t num_args,
                                                      size_t num_fixed_args) {
    if (out_layout == nullptr)
        return FFI_ERROR_INVALID_ARGUMENT;

    // Allocate the layout struct that will hold our results.
    ffi_call_frame_layout * layout =
        arena_calloc(arena, 1, sizeof(ffi_call_frame_layout), _Alignof(ffi_call_frame_layout));
    if (layout == nullptr) {
        *out_layout = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }
    layout->is_variadic = num_args > num_fixed_args;
    layout->arg_locations = arena_calloc(arena, num_args, sizeof(ffi_arg_location), _Alignof(ffi_arg_location));
    if (layout->arg_locations == nullptr && num_args > 0) {
        *out_layout = nullptr;
        return FFI_ERROR_ALLOCATION_FAILED;
    }

    // gpr_count and xmm_count track the next available GPR and XMM argument registers.
    // current_stack_offset tracks the next available stack slot for arguments.
    size_t gpr_count = 0, xmm_count = 0, current_stack_offset = 0;

    // Determine if the return value requires a hidden pointer argument passed in RDI.
    bool ret_is_aggregate = (ret_type->category == FFI_TYPE_STRUCT || ret_type->category == FFI_TYPE_UNION ||
                             ret_type->category == FFI_TYPE_ARRAY);

    // Rule 1: Aggregates larger than 16 bytes are always returned via hidden pointer.
    layout->return_value_in_memory = (ret_is_aggregate && ret_type->size > 16);

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
        ffi_type * type = arg_types[i];

        // Security: Reject excessively large types before they reach the code generator.
        if (type->size > FFI_MAX_ARG_SIZE) {
            *out_layout = NULL;
            return FFI_ERROR_LAYOUT_FAILED;
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

        bool is_aggregate =
            type->category == FFI_TYPE_STRUCT || type->category == FFI_TYPE_UNION || type->category == FFI_TYPE_ARRAY;
        arg_class_t classes[2] = {NO_CLASS, NO_CLASS};
        size_t num_classes = 0;
        bool placed_in_register = false;

        if (is_aggregate)
            // Complex types need the full classification algorithm.
            classify_aggregate_sysv(type, classes, &num_classes);
        else {
            // Simple primitive types are classified directly.
            if (is_float(type) || is_double(type))
                classes[0] = SSE;
            else
                classes[0] = INTEGER;
            num_classes = 1;
            // Primitives > 8 bytes (like __int128) are treated as two INTEGER parts.
            if (type->size > 8) {
                classes[1] = INTEGER;
                num_classes = 2;
            }
        }

        // If classification resulted in MEMORY, it must go on the stack.
        if (!(num_classes == 1 && classes[0] == MEMORY)) {
            // Step 2: Check for available registers
            size_t gpr_needed = 0, xmm_needed = 0;
            for (size_t j = 0; j < num_classes; ++j) {
                if (classes[j] == INTEGER)
                    gpr_needed++;
                else if (classes[j] == SSE)
                    xmm_needed++;
            }

            // Check if there are enough of BOTH register types available.
            if (gpr_count + gpr_needed <= NUM_GPR_ARGS && xmm_count + xmm_needed <= NUM_XMM_ARGS) {
                // Step 3: Assign registers
                if (num_classes == 1) {
                    // Argument fits in a single register.
                    layout->arg_locations[i].type = (classes[0] == INTEGER) ? ARG_LOCATION_GPR : ARG_LOCATION_XMM;
                    if (classes[0] == INTEGER)
                        layout->arg_locations[i].reg_index = gpr_count;
                    else
                        layout->arg_locations[i].reg_index = xmm_count;
                }
                else {
                    // Argument is passed in two registers.
                    if (classes[0] == INTEGER && classes[1] == INTEGER) {
                        layout->arg_locations[i].type = ARG_LOCATION_GPR_PAIR;
                        layout->arg_locations[i].reg_index = gpr_count;
                        layout->arg_locations[i].reg_index2 = gpr_count + 1;
                    }
                    else if (classes[0] == SSE && classes[1] == SSE) {
                        layout->arg_locations[i].type =
                            ARG_LOCATION_GPR_SSE_PAIR;  // Name is misleading, this is SSE_SSE
                        layout->arg_locations[i].reg_index = xmm_count;
                        layout->arg_locations[i].reg_index2 = xmm_count + 1;
                    }
                    else {  // Mixed GPR and SSE
                        layout->arg_locations[i].type = ARG_LOCATION_GPR_SSE_PAIR;
                        if (classes[0] == INTEGER) {
                            layout->arg_locations[i].reg_index = gpr_count;
                            layout->arg_locations[i].reg_index2 = xmm_count;
                        }
                        else {
                            layout->arg_locations[i].reg_index = xmm_count;
                            layout->arg_locations[i].reg_index2 = gpr_count;
                        }
                    }
                }
                gpr_count += gpr_needed;
                xmm_count += xmm_needed;
                placed_in_register = true;
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
    if (layout->total_stack_alloc > FFI_MAX_STACK_ALLOC) {
        *out_layout = nullptr;
        return FFI_ERROR_LAYOUT_FAILED;
    }

    *out_layout = layout;
    return FFI_SUCCESS;
}

/**
 * @brief Generates the function prologue for the System V forward trampoline.
 * @details This function emits the standard machine code required at the beginning of a function.
 *          It sets up a standard stack frame, saves registers that will be used to hold
 *          the trampoline's context, and allocates stack space for arguments.
 *
 * @param buf The code buffer where the machine code bytes will be written.
 * @param layout The call frame layout containing total stack allocation information.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_forward_prologue_sysv_x64(code_buffer * buf, ffi_call_frame_layout * layout) {
    // Standard Function Prologue
    emit_byte(buf, 0x55);               // push rbp
    EMIT_BYTES(buf, 0x48, 0x89, 0xE5);  // mov rbp, rsp

    // Save Callee-Saved Registers
    // We will use these registers to store our context (target_fn, ret_ptr, args_ptr)
    // across the native function call, so we must save their original values first.
    EMIT_BYTES(buf, 0x41, 0x54);  // push r12
    EMIT_BYTES(buf, 0x41, 0x55);  // push r13
    EMIT_BYTES(buf, 0x41, 0x56);  // push r14
    EMIT_BYTES(buf, 0x41, 0x57);  // push r15

    // Move Trampoline Arguments to Persistent Registers
    // The trampoline itself is called with (target_fn, ret_ptr, args_ptr) in RDI, RSI, RDX.
    // We move these into our saved callee-saved registers to protect them.
    emit_mov_reg_reg(buf, R12_REG, RDI_REG);  // r12 = target_fn
    emit_mov_reg_reg(buf, R13_REG, RSI_REG);  // r13 = ret_ptr
    emit_mov_reg_reg(buf, R14_REG, RDX_REG);  // r14 = args_ptr

    // Allocate Stack Space
    // If any arguments are passed on the stack, allocate space for them.
    // The ABI requires this space to be 16-byte aligned.
    if (layout->total_stack_alloc > 0) {
        EMIT_BYTES(buf, 0x48, 0x81, 0xEC);  // sub rsp, imm32
        emit_int32(buf, layout->total_stack_alloc);
    }
    return FFI_SUCCESS;
}

/**
 * @brief Generates code to move arguments from the `void**` array into their correct locations.
 * @details This is the core marshalling function of the forward trampoline. It generates the
 *          machine code that reads each argument from the FFI-provided array and places it
 *          into the correct register or stack slot as dictated by the ABI and the `layout`
 *          blueprint.
 *
 * @param buf The code buffer to which the machine code will be written.
 * @param layout The call frame layout blueprint that specifies where each argument must go.
 * @param arg_types The array of `ffi_type` pointers for the function's arguments.
 * @param num_args The total number of arguments.
 * @param num_fixed_args The number of fixed (non-variadic) arguments.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_forward_argument_moves_sysv_x64(code_buffer * buf,
                                                           ffi_call_frame_layout * layout,
                                                           ffi_type ** arg_types,
                                                           size_t num_args,
                                                           c23_maybe_unused size_t num_fixed_args) {
    // If returning a large struct, the hidden pointer (stored in r13) must be moved to RDI.
    if (layout->return_value_in_memory)
        emit_mov_reg_reg(buf, GPR_ARGS[0], R13_REG);  // mov rdi, r13

    // Marshall Register Arguments
    // Loop over all arguments that are passed in registers.
    for (size_t i = 0; i < num_args; ++i) {
        ffi_arg_location * loc = &layout->arg_locations[i];
        if (loc->type == ARG_LOCATION_STACK)
            continue;  // Handle stack arguments in a separate pass.

        // Load the pointer to the argument's data into a scratch register (r15).
        // r14 holds the base of the `void** args_array`.
        // r15 = args_array[i]
        emit_mov_reg_mem(buf, R15_REG, R14_REG, i * sizeof(void *));

        if (loc->type == ARG_LOCATION_GPR) {
            ffi_type * current_type = arg_types[i];

            bool is_signed = current_type->category == FFI_TYPE_PRIMITIVE &&
                (current_type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT8 ||
                 current_type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT16 ||
                 current_type->meta.primitive_id == FFI_PRIMITIVE_TYPE_SINT32);

            if (is_signed) {
                switch (current_type->size) {
                case 1:  // signed char
                    emit_movsx_reg64_mem8(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                case 2:  // signed short
                    emit_movsx_reg64_mem16(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                case 4:  // signed int
                    emit_movsxd_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                default:  // 64-bit+ integers do not get promoted
                    emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                }
            }
            else {  // Unsigned integers, pointers, bools
                switch (current_type->size) {
                case 1:  // unsigned char, bool
                    emit_movzx_reg64_mem8(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                case 2:  // unsigned short
                    emit_movzx_reg64_mem16(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                case 4:  // unsigned int
                    emit_mov_reg32_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                default:  // Pointers and 64-bit+ integers
                    emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);
                    break;
                }
            }
        }
        else if (loc->type == ARG_LOCATION_XMM) {
            if (is_float(arg_types[i]))
                // movss xmm_reg, [r15] (Move Scalar Single-Precision)
                emit_movss_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
            else
                // movsd xmm_reg, [r15] (Move Scalar Double-Precision)
                emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);
        }
        else if (loc->type == ARG_LOCATION_GPR_PAIR) {
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);   // mov reg1, [r15]
            emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index2], R15_REG, 8);  // mov reg2, [r15 + 8]
        }
        else if (loc->type == ARG_LOCATION_GPR_SSE_PAIR) {
            arg_class_t classes[2];
            size_t num_classes;
            classify_aggregate_sysv(arg_types[i], classes, &num_classes);
            if (num_classes > 1) {
                if (classes[0] == INTEGER && classes[1] == SSE) {
                    emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index], R15_REG, 0);     // mov gpr, [r15]
                    emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index2], R15_REG, 8);  // movsd xmm, [r15 + 8]
                }
                else if (classes[0] == SSE && classes[1] == INTEGER) {
                    emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);  // movsd xmm, [r15]
                    emit_mov_reg_mem(buf, GPR_ARGS[loc->reg_index2], R15_REG, 8);   // mov gpr, [r15 + 8]
                }
                else if (classes[0] == SSE && classes[1] == SSE) {
                    emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index], R15_REG, 0);   // movsd xmm1, [r15]
                    emit_movsd_xmm_mem(buf, XMM_ARGS[loc->reg_index2], R15_REG, 8);  // movsd xmm2, [r15 + 8]
                }
            }
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
            size_t offset = 0;

            // Copy the argument data from the user-provided buffer to the stack, 8 bytes at a time.
            for (; offset + 8 <= size; offset += 8) {
                // mov rax, [r15 + offset] (load 8 bytes into scratch register)
                emit_mov_reg_mem(buf, RAX_REG, R15_REG, offset);
                // mov [rsp + stack_offset], rax (store 8 bytes onto the stack)
                emit_mov_mem_reg(buf, RSP_REG, layout->arg_locations[i].stack_offset + offset, RAX_REG);
            }
            // Handle any remaining bytes (1 to 7).
            if (offset < size) {
                // A simple and effective way to handle the remainder is byte by byte.
                for (; offset < size; ++offset) {
                    // movzx rax, byte ptr [r15 + offset] (using movzx to get a byte into al)
                    emit_movzx_reg64_mem8(buf, RAX_REG, R15_REG, (int32_t)offset);
                    // mov [rsp + stack_offset], al
                    emit_mov_mem_reg8(buf, RSP_REG, (int32_t)(layout->arg_locations[i].stack_offset + offset), RAX_REG);
                }
            }
        }
    }

    // Handle Variadic Calls
    // The ABI requires that AL contains the number of XMM registers used for arguments.
    if (layout->is_variadic)
        // mov al, num_xmm_args (or mov eax, num_xmm_args)
        emit_mov_reg_imm32(buf, RAX_REG, (int32_t)layout->num_xmm_args);

    return FFI_SUCCESS;
}

/**
 * @brief Generates the function epilogue for the System V forward trampoline.
 * @details This function emits the code to handle the function's return value and
 *          properly tear down the stack frame after the native call returns.
 *
 * @param buf The code buffer.
 * @param layout The call frame layout.
 * @param ret_type The `ffi_type` of the function's return value.
 * @return `FFI_SUCCESS` on successful code generation.
 */
static ffi_status generate_forward_epilogue_sysv_x64(code_buffer * buf,
                                                     ffi_call_frame_layout * layout,
                                                     ffi_type * ret_type) {
    // Handle Return Value
    // If the function returns something and it wasn't via a hidden pointer...
    if (ret_type->category != FFI_TYPE_VOID && !layout->return_value_in_memory) {
        if (is_long_double(ret_type))
            // `long double` is returned on the x87 FPU stack (st0).
            // We store it into the user's return buffer (pointer held in r13).
            // fstpt [r13] (Store Floating Point value and Pop)
            emit_fstpt_mem(buf, R13_REG, 0);
        else {
            // For other types, we must classify the return type just like an argument.
            arg_class_t classes[2];
            size_t num_classes;
            classify_aggregate_sysv(ret_type, classes, &num_classes);

            if (num_classes == 1) {  // Returned in a single register
                if (classes[0] == SSE) {
                    if (is_float(ret_type))
                        emit_movss_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movss [r13], xmm0
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
                    case 8:
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
                    emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movsd [r13], xmm0
                    emit_movsd_mem_xmm(buf, R13_REG, 8, XMM1_REG);  // movsd [r13 + 8], xmm1
                }
                else if (classes[0] == INTEGER && classes[1] == SSE) {
                    emit_mov_mem_reg(buf, R13_REG, 0, RAX_REG);     // mov [r13], rax
                    emit_movsd_mem_xmm(buf, R13_REG, 8, XMM0_REG);  // movsd [r13 + 8], xmm0
                }
                else {                                              // SSE, INTEGER
                    emit_movsd_mem_xmm(buf, R13_REG, 0, XMM0_REG);  // movsd [r13], xmm0
                    emit_mov_mem_reg(buf, R13_REG, 8, RDX_REG);     // mov [r13 + 8], rdx
                }
            }
        }
    }

    // Deallocate Stack
    if (layout->total_stack_alloc > 0) {
        // add rsp, imm32
        EMIT_BYTES(buf, 0x48, 0x81, 0xC4);
        emit_int32(buf, layout->total_stack_alloc);
    }

    // Restore Registers and Return
    EMIT_BYTES(buf, 0x41, 0x5F);  // pop r15
    EMIT_BYTES(buf, 0x41, 0x5E);  // pop r14
    EMIT_BYTES(buf, 0x41, 0x5D);  // pop r13
    EMIT_BYTES(buf, 0x41, 0x5C);  // pop r12
    emit_byte(buf, 0x5D);         // pop rbp
    emit_byte(buf, 0xC3);         // ret
    return FFI_SUCCESS;
}

/**
 * @brief Stage 1: Calculates the stack layout for a reverse trampoline stub.
 * @details This function determines the total stack space needed by the JIT-compiled
 *          callback stub for all its local variables. This includes space for:
 *          - A buffer to store the return value before it's placed in registers.
 *          - The `void** args_array` that will be passed to the C dispatcher.
 *          - A contiguous save area where the data from all incoming arguments will be stored.
 *
 * @param[out] out_layout The resulting reverse call frame layout blueprint, populated with offsets.
 * @param context The reverse trampoline context with full signature information.
 * @return `FFI_SUCCESS` on success, or an error code on failure.
 */
static ffi_status prepare_reverse_call_frame_sysv_x64(arena_t * arena,
                                                      ffi_reverse_call_frame_layout ** out_layout,
                                                      ffi_reverse_trampoline_t * context) {
    ffi_reverse_call_frame_layout * layout =
        arena_calloc(arena, 1, sizeof(ffi_reverse_call_frame_layout), _Alignof(ffi_reverse_call_frame_layout));
    if (!layout)
        return FFI_ERROR_ALLOCATION_FAILED;

    // Calculate space for each component, ensuring 16-byte alignment for safety and simplicity.
    size_t return_size = (context->return_type->size + 15) & ~15;
    size_t args_array_size = (context->num_args * sizeof(void *) + 15) & ~15;
    size_t saved_args_data_size = 0;
    for (size_t i = 0; i < context->num_args; ++i)
        saved_args_data_size += (context->arg_types[i]->size + 15) & ~15;

    if (saved_args_data_size > FFI_MAX_ARG_SIZE) {
        *out_layout = NULL;
        return FFI_ERROR_LAYOUT_FAILED;
    }

    size_t total_local_space = return_size + args_array_size + saved_args_data_size;

    // Safety check against allocating too much stack.
    if (total_local_space > FFI_MAX_STACK_ALLOC) {
        *out_layout = NULL;
        return FFI_ERROR_LAYOUT_FAILED;
    }

    // The total allocation for the stack frame must be 16-byte aligned.
    layout->total_stack_alloc = (total_local_space + 15) & ~15;

    // Local variables are accessed via negative offsets from the frame pointer (RBP).
    // The layout is [ return_buffer | args_array | saved_args_data ]
    layout->return_buffer_offset = -layout->total_stack_alloc;
    layout->args_array_offset = layout->return_buffer_offset + return_size;
    layout->saved_args_offset = layout->args_array_offset + args_array_size;

    *out_layout = layout;
    return FFI_SUCCESS;
}

/**
 * @brief Stage 2: Generates the prologue for the reverse trampoline stub.
 * @details Emits the standard System V function entry code, creating a stack frame,
 *          and allocating all necessary local stack space for our internal structures.
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing the total stack space to allocate.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_reverse_prologue_sysv_x64(code_buffer * buf, ffi_reverse_call_frame_layout * layout) {
    emit_byte(buf, 0x55);                        // push rbp
    EMIT_BYTES(buf, 0x48, 0x89, 0xE5);           // mov rbp, rsp
    EMIT_BYTES(buf, 0x48, 0x81, 0xEC);           // sub rsp, imm32
    emit_int32(buf, layout->total_stack_alloc);  // Allocate our calculated space.
    return FFI_SUCCESS;
}
/**
 * @brief Stage 3: Generates code to marshal arguments into the generic `void**` array.
 * @details This function has been corrected to use the full System V classification logic
 *          to determine if a hidden return pointer is present in RDI. This fixes bugs
 *          where MEMORY-class aggregates (like unions with long double) were not
 *          handled correctly, leading to argument corruption.
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context containing the argument type information for the callback.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_reverse_argument_marshalling_sysv_x64(code_buffer * buf,
                                                                 ffi_reverse_call_frame_layout * layout,
                                                                 ffi_reverse_trampoline_t * context) {
    size_t gpr_idx = 0, xmm_idx = 0, current_saved_data_offset = 0;

    // Correctly determine if the return value uses a hidden pointer by performing a full ABI classification.
    bool return_in_memory = false;
    ffi_type * ret_type = context->return_type;
    bool ret_is_aggregate = (ret_type->category == FFI_TYPE_STRUCT || ret_type->category == FFI_TYPE_UNION ||
                             ret_type->category == FFI_TYPE_ARRAY);

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
        ffi_type * current_type = context->arg_types[i];

        arg_class_t classes[2];
        size_t num_classes;
        classify_aggregate_sysv(current_type, classes, &num_classes);

        bool is_from_stack = false;

        // Determine if the argument is in registers or on the stack.
        if (classes[0] == MEMORY) {
            is_from_stack = true;
        }
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
    return FFI_SUCCESS;
}

/**
 * @brief Stage 4: Generates the code to call the high-level C dispatcher function.
 * @details Emits code to load the dispatcher's arguments (context, return buffer pointer, args
 *          array pointer) into RDI, RSI, and RDX, then calls the dispatcher function. This
 *          function correctly determines whether the return buffer pointer was passed in by the
 *          original caller (for MEMORY-class returns) or if it's a pointer to local stack space.
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing stack offsets.
 * @param context The context, containing the dispatcher's address.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_reverse_dispatcher_call_sysv_x64(code_buffer * buf,
                                                            ffi_reverse_call_frame_layout * layout,
                                                            ffi_reverse_trampoline_t * context) {
    // Arg 1 (RDI): The ffi_reverse_trampoline_t context pointer.
    emit_mov_reg_imm64(buf, RDI_REG, (uint64_t)context);  // mov rdi, #context_addr

    // Arg 2 (RSI): Pointer to the return buffer.
    // Correctly determine if the hidden pointer was used for the return value.
    bool return_in_memory = false;
    ffi_type * ret_type = context->return_type;
    bool ret_is_aggregate = (ret_type->category == FFI_TYPE_STRUCT || ret_type->category == FFI_TYPE_UNION ||
                             ret_type->category == FFI_TYPE_ARRAY);
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

    EMIT_BYTES(buf, 0xFF, 0xD0);  // call rax
    return FFI_SUCCESS;
}

/**
 * @brief Stage 5: Generates the epilogue for the reverse trampoline stub.
 * @details This function has been corrected to use the full System V classification logic
 *          for return values. It now correctly identifies MEMORY-class aggregates that
 *          are returned via a hidden pointer and places that pointer in RAX as required,
 *          preventing stack corruption and incorrect return values.
 *
 * @param buf The code buffer.
 * @param layout The blueprint containing the return buffer's offset.
 * @param context The context containing the return type information.
 * @return `FFI_SUCCESS`.
 */
static ffi_status generate_reverse_epilogue_sysv_x64(code_buffer * buf,
                                                     ffi_reverse_call_frame_layout * layout,
                                                     ffi_reverse_trampoline_t * context) {
    if (context->return_type->category != FFI_TYPE_VOID) {
        // Correctly determine if the return value uses a hidden pointer by performing a full ABI classification.
        bool return_in_memory = false;
        ffi_type * ret_type = context->return_type;
        bool ret_is_aggregate = (ret_type->category == FFI_TYPE_STRUCT || ret_type->category == FFI_TYPE_UNION ||
                                 ret_type->category == FFI_TYPE_ARRAY);

        if (ret_is_aggregate) {
            if (ret_type->size > 16) {
                return_in_memory = true;
            }
            else {
                arg_class_t ret_classes[2];
                size_t num_ret_classes;
                classify_aggregate_sysv(ret_type, ret_classes, &num_ret_classes);
                if (num_ret_classes > 0 && ret_classes[0] == MEMORY) {
                    return_in_memory = true;
                }
            }
        }
        if (is_long_double(ret_type)) {
            return_in_memory = false;
        }

        // Now, handle the return value based on the correct classification.
        if (is_long_double(context->return_type)) {
            emit_fldt_mem(buf, RBP_REG, layout->return_buffer_offset);
        }
        else if (return_in_memory) {
            // The return value was written directly via the hidden pointer.
            // The ABI requires this pointer to be returned in RAX.
            emit_mov_reg_mem(buf, RAX_REG, RBP_REG, layout->return_buffer_offset);
        }
        else {
            // Classify the return type to determine which registers to load.
            arg_class_t classes[2];
            size_t num_classes;
            classify_aggregate_sysv(context->return_type, classes, &num_classes);

            if (num_classes >= 1) {  // First eightbyte
                if (classes[0] == SSE) {
                    if (is_float(context->return_type))
                        emit_movss_xmm_mem(buf, XMM0_REG, RBP_REG, layout->return_buffer_offset);
                    else
                        emit_movsd_xmm_mem(buf, XMM0_REG, RBP_REG, layout->return_buffer_offset);
                }
                else {  // INTEGER
                    emit_mov_reg_mem(buf, RAX_REG, RBP_REG, layout->return_buffer_offset);
                }
            }
            if (num_classes == 2) {  // Second eightbyte
                if (classes[1] == SSE) {
                    emit_movsd_xmm_mem(buf, XMM1_REG, RBP_REG, layout->return_buffer_offset + 8);
                }
                else {  // INTEGER
                    emit_mov_reg_mem(buf, RDX_REG, RBP_REG, layout->return_buffer_offset + 8);
                }
            }
        }
    }

    // Standard function epilogue: tear down stack frame and return.
    EMIT_BYTES(buf, 0x48, 0x89, 0xEC);  // mov rsp, rbp
    emit_byte(buf, 0x5D);               // pop rbp
    emit_byte(buf, 0xC3);               // ret
    return FFI_SUCCESS;
}
