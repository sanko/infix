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
 * @file abi_arm64_common.h
 * @brief Common register definitions for the AArch64 (ARM64) architecture.
 * @ingroup internal_abi_aarch64
 *
 * @internal
 * This header defines enums for the general-purpose registers (GPRs) and
 * the floating-point/SIMD registers (VPRs) available on the ARM64 architecture.
 * These enums provide a clear, type-safe, and self-documenting way to refer to
 * specific registers when emitting machine code or implementing the ABI logic.
 *
 * Using enums instead of raw integer literals (e.g., `X0_REG` instead of `0`)
 * prevents "magic number" bugs and makes the code in `abi_arm64.c` and
 * `abi_arm64_emitters.c` significantly more readable.
 * @endinternal
 */

#include <stdint.h>

/**
 * @internal
 * @enum arm64_gpr
 * @brief Enumerates the ARM64 General-Purpose Registers (GPRs), X0-X30 and SP.
 *
 * @details The enum values correspond to the 5-bit register numbers used in machine
 * code instructions. The comments on each register describe its primary role
 * according to the standard Procedure Call Standard for the ARM 64-bit
 * Architecture (AAPCS64), indicating whether it is used for arguments, return
 * values, or must be preserved across function calls (callee-saved).
 */
typedef enum {
    X0_REG = 0,   ///< Argument 1 / Return value / Volatile (caller-saved).
    X1_REG,       ///< Argument 2 / Volatile.
    X2_REG,       ///< Argument 3 / Volatile.
    X3_REG,       ///< Argument 4 / Volatile.
    X4_REG,       ///< Argument 5 / Volatile.
    X5_REG,       ///< Argument 6 / Volatile.
    X6_REG,       ///< Argument 7 / Volatile.
    X7_REG,       ///< Argument 8 / Volatile.
    X8_REG,       ///< Indirect result location register (holds address for large struct returns) / Volatile.
    X9_REG,       ///< Volatile (caller-saved) scratch register.
    X10_REG,      ///< Volatile scratch register.
    X11_REG,      ///< Volatile scratch register.
    X12_REG,      ///< Volatile scratch register.
    X13_REG,      ///< Volatile scratch register.
    X14_REG,      ///< Volatile scratch register.
    X15_REG,      ///< Volatile scratch register.
    X16_REG,      ///< Intra-Procedure-call scratch register (IP0) / Volatile. Linker-modifiable.
    X17_REG,      ///< Intra-Procedure-call scratch register (IP1) / Volatile. Linker-modifiable.
    X18_REG,      ///< Platform Register (reserved, usage is platform-specific) / May be callee-saved. Avoid use.
    X19_REG,      ///< Callee-saved. Must be preserved by a called function.
    X20_REG,      ///< Callee-saved.
    X21_REG,      ///< Callee-saved.
    X22_REG,      ///< Callee-saved.
    X23_REG,      ///< Callee-saved.
    X24_REG,      ///< Callee-saved.
    X25_REG,      ///< Callee-saved.
    X26_REG,      ///< Callee-saved.
    X27_REG,      ///< Callee-saved.
    X28_REG,      ///< Callee-saved.
    X29_FP_REG,   ///< Frame Pointer (FP) / Callee-saved.
    X30_LR_REG,   ///< Link Register (LR), holds the return address / Callee-saved by convention, but volatile on call.
    SP_REG = 31,  ///< Stack Pointer (SP). In some instructions, encoding 31 refers to the Zero Register (XZR/WZR).
} arm64_gpr;

/**
 * @internal
 * @enum arm64_vpr
 * @brief Enumerates the ARM64 Floating-Point/SIMD (NEON) registers (V-registers).
 *
 * @details These registers (V0-V31) are 128 bits wide and are used for passing and
 * returning floating-point arguments, Homogeneous Floating-point Aggregates (HFAs),
 * and short vector types. The comments describe their role in the AAPCS64.
 */
typedef enum {
    V0_REG = 0,  ///< Argument 1 / Return value / Volatile (caller-saved).
    V1_REG,      ///< Argument 2 / Volatile.
    V2_REG,      ///< Argument 3 / Volatile.
    V3_REG,      ///< Argument 4 / Volatile.
    V4_REG,      ///< Argument 5 / Volatile.
    V5_REG,      ///< Argument 6 / Volatile.
    V6_REG,      ///< Argument 7 / Volatile.
    V7_REG,      ///< Argument 8 / Volatile.
    V8_REG,      ///< Callee-saved (Note: only the lower 64 bits must be preserved).
    V9_REG,      ///< Callee-saved (only lower 64 bits).
    V10_REG,     ///< Callee-saved (only lower 64 bits).
    V11_REG,     ///< Callee-saved (only lower 64 bits).
    V12_REG,     ///< Callee-saved (only lower 64 bits).
    V13_REG,     ///< Callee-saved (only lower 64 bits).
    V14_REG,     ///< Callee-saved (only lower 64 bits).
    V15_REG,     ///< Callee-saved (only lower 64 bits).
    V16_REG,     ///< Volatile (caller-saved) scratch register.
    V17_REG,     ///< Volatile scratch register.
    V18_REG,     ///< Volatile scratch register.
    V19_REG,     ///< Volatile scratch register.
    V20_REG,     ///< Volatile scratch register.
    V21_REG,     ///< Volatile scratch register.
    V22_REG,     ///< Volatile scratch register.
    V23_REG,     ///< Volatile scratch register.
    V24_REG,     ///< Volatile scratch register.
    V25_REG,     ///< Volatile scratch register.
    V26_REG,     ///< Volatile scratch register.
    V27_REG,     ///< Volatile scratch register.
    V28_REG,     ///< Volatile scratch register.
    V29_REG,     ///< Volatile scratch register.
    V30_REG,     ///< Volatile scratch register.
    V31_REG,     ///< Volatile scratch register.
} arm64_vpr;
