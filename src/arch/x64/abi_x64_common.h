#pragma once
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
 * @file abi_x64_common.h
 * @brief Common definitions for the x86-64 architecture.
 *
 * @details This header defines enums for the general-purpose (GPR) and SSE (XMM)
 * registers available on the x86-64 architecture. These enums are used by both
 * the Windows x64 and System V x64 ABI implementations to provide a clear,
 * type-safe way to refer to specific registers when emitting machine code.
 *
 * While the *usage* of these registers for argument passing differs significantly
 * between the two ABIs, the registers themselves and their numerical encoding are
 * universal. This header provides that common, universal definition.
 */

#include <stdint.h>

/**
 * @enum x64_gpr
 * @brief Enumerates the 64-bit General-Purpose Registers (GPRs) for x86-64.
 *
 * @details The enum values correspond to the 3-bit or 4-bit register numbers used in the
 * ModR/M and REX byte encodings of x86-64 instructions. The comments on each
 * register describe its primary role and whether it is caller-saved (volatile)
 * or callee-saved (must be preserved across a function call), highlighting the
 * key differences between the Windows and System V ABIs.
 */
typedef enum {
    RAX_REG =
        0,  ///< Volatile (caller-saved). Typically used for the primary integer/pointer return value in both ABIs.
    RCX_REG = 1,  ///< Volatile. Used for the 1st integer argument on Windows x64, or the 4th on System V.
    RDX_REG = 2,  ///< Volatile. Used for the 2nd integer argument on Windows x64, or the 3rd on System V.
    RBX_REG = 3,  ///< Callee-saved register. A called function must preserve its value.
    RSP_REG = 4,  ///< Stack Pointer. Points to the top of the current stack. Its value is preserved with respect to the
                  ///< frame pointer.
    RBP_REG = 5,  ///< Frame Pointer (or Base Pointer). Typically used to point to the base of the current stack frame.
                  ///< Callee-saved.
    RSI_REG = 6,  ///< Volatile. Used for the 2nd integer argument on System V.
    RDI_REG = 7,  ///< Volatile. Used for the 1st integer argument on System V.
    R8_REG = 8,   ///< Volatile. Used for the 3rd integer argument on Windows x64, or the 5th on System V.
    R9_REG,       ///< Volatile. Used for the 4th integer argument on Windows x64, or the 6th on System V.
    R10_REG,      ///< Volatile (caller-saved) scratch register.
    R11_REG,      ///< Volatile (caller-saved) scratch register.
    R12_REG,      ///< Callee-saved register.
    R13_REG,      ///< Callee-saved register.
    R14_REG,      ///< Callee-saved register.
    R15_REG       ///< Callee-saved register.
} x64_gpr;

/**
 * @enum x64_xmm
 * @brief Enumerates the 128-bit SSE registers (XMM0-XMM15) for x86-64.
 *
 * @details These registers are used for passing and returning floating-point arguments
 * (`float`, `double`) in both Windows x64 and System V ABIs. They are also
 * used for passing small aggregate types under certain System V rules. Note the
 * difference in volatility for registers XMM6-XMM15 between the two ABIs.
 */
typedef enum {
    XMM0_REG,   ///< Volatile. Used for the 1st float/double argument and for float/double return values.
    XMM1_REG,   ///< Volatile. Used for the 2nd float/double argument.
    XMM2_REG,   ///< Volatile. Used for the 3rd float/double argument.
    XMM3_REG,   ///< Volatile. Used for the 4th float/double argument.
    XMM4_REG,   ///< Volatile. Used for the 5th (System V) float/double argument.
    XMM5_REG,   ///< Volatile. Used for the 6th (System V) float/double argument.
    XMM6_REG,   ///< Callee-saved on Windows x64, volatile on System V.
    XMM7_REG,   ///< Callee-saved on Windows x64, volatile on System V.
    XMM8_REG,   ///< Volatile in both ABIs.
    XMM9_REG,   ///< Volatile in both ABIs.
    XMM10_REG,  ///< Volatile in both ABIs.
    XMM11_REG,  ///< Volatile in both ABIs.
    XMM12_REG,  ///< Volatile in both ABIs.
    XMM13_REG,  ///< Volatile in both ABIs.
    XMM14_REG,  ///< Volatile in both ABIs.
    XMM15_REG   ///< Volatile in both ABIs.
} x64_xmm;
