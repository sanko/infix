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
 * @file abi_arm64_emitters.h
 * @brief Declares the internal helper functions for emitting AArch64 machine code.
 *
 * @details This is a non-public, internal-only header. It provides the function
 * prototypes for all low-level AArch64 instruction emitters. These functions are the
 * fundamental building blocks used by `abi_arm64.c` to generate the machine code for
 * both forward and reverse trampolines.
 *
 * This module was created to cleanly separate the low-level, bit-twiddling details
 * of AArch64 instruction set encoding from the higher-level logic of applying the
 * AAPCS64 ABI rules (like argument classification and stack layout).
 */

#include <abi_arm64_common.h>
#include <infix_internals.h>

/** @brief Emits an ARM64 `LDR <Wt/Xt>, [Xn, #imm]` instruction (load GPR from memory). */
void emit_arm64_ldr_imm(code_buffer * buf, bool is64, arm64_gpr dest, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `LDRSW <Xt>, [Xn, #imm]` instruction (load 32-bit value and sign-extend to 64-bit). */
void emit_arm64_ldrsw_imm(code_buffer * buf, arm64_gpr dest, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `STR <Wt/Xt>, [Xn, #imm]` instruction (store GPR to memory). */
void emit_arm64_str_imm(code_buffer * buf, bool is64, arm64_gpr src, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `STRB <Wt>, [Xn, #imm]` instruction (store byte to memory). */
void emit_arm64_strb_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `STRH <Wt>, [Xn, #imm]` instruction (store half-word to memory). */
void emit_arm64_strh_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `LDR <St/Dt>, [Xn, #imm]` instruction (load SIMD&FP register from memory). */
void emit_arm64_ldr_vpr(code_buffer * buf, bool is64, arm64_vpr dest, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `STR <St/Dt>, [Xn, #imm]` instruction (store SIMD&FP register to memory). */
void emit_arm64_str_vpr(code_buffer * buf, bool is64, arm64_vpr src, arm64_gpr base, int32_t offset);

/** @brief Emits an ARM64 `ADD(S) <Xd/Wd>, <Xn/Wn>, #imm` instruction (add immediate to GPR). */
void emit_arm64_add_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm);

/** @brief Emits an ARM64 `SUB(S) <Xd/Wd>, <Xn/Wn>, #imm` instruction (subtract immediate from GPR). */
void emit_arm64_sub_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm);

/** @brief Emits an instruction sequence (`MOVZ`/`MOVK`) to load an arbitrary 64-bit immediate into a GPR. */
void emit_arm64_load_u64_immediate(code_buffer * buf, arm64_gpr dest, uint64_t value);

/** @brief Emits an AArch64 `LDR <Qt>, [Xn, #imm]` for a 128-bit load into a SIMD&FP register. */
void emit_arm64_ldr_q_imm(code_buffer * buf, arm64_vpr dest, arm64_gpr base, int32_t offset);

/** @brief Emits an AArch64 `STR <Qt>, [Xn, #imm]` for a 128-bit store from a SIMD&FP register. */
void emit_arm64_str_q_imm(code_buffer * buf, arm64_vpr src, arm64_gpr base, int32_t offset);
