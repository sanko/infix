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
 * @file abi_x64_emitters.h
 * @brief Declares the internal helper functions for emitting x86-64 machine code.
 *
 * @details This is a non-public, internal-only header. It provides the function
 * prototypes for all low-level x86-64 instruction emitters.
 *
 * This module was created to cleanly separate platform-specific implementation
 * details from the generic trampoline engine. These functions are shared by both
 * the Windows x64 (`abi_win_x64.c`) and System V x64 (`abi_sysv_x64.c`) ABI
 * implementations, providing a consistent, low-level interface for generating
 * machine code for the x86-64 architecture. Each function corresponds to a
 * specific machine instruction or a common addressing mode.
 */

#include <abi_x64_common.h>
#include <infix.h>

/** @brief Emits `mov r64, imm64` to load a 64-bit immediate value into a register. */
void emit_mov_reg_imm64(code_buffer * buf, x64_gpr reg, uint64_t value);

/** @brief Emits `mov [dest_base + offset], r64` (stores a 64-bit GPR to memory). */
void emit_mov_mem_reg(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src);

/** @brief Emits `mov [dest_base + offset], r32` (stores a 32-bit GPR to memory). */
void emit_mov_mem_reg32(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src);

/** @brief Emits `mov [dest_base + offset], r16` (stores a 16-bit GPR to memory). */
void emit_mov_mem_reg16(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src);

/** @brief Emits `mov [dest_base + offset], r8` (stores an 8-bit GPR to memory). */
void emit_mov_mem_reg8(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src);

/** @brief Emits `movss [dest_base + offset], xmm` (stores a 32-bit float to memory). */
void emit_movss_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src);

/** @brief Emits `movsd [dest_base + offset], xmm` (stores a 64-bit double to memory). */
void emit_movsd_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src);

/** @brief Emits `movups [dest_base + offset], xmm` (stores a 128-bit unaligned value to memory). */
void emit_movups_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src);

/** @brief Emits `mov r64, [src_base + offset]` (loads a 64-bit GPR from memory). */
void emit_mov_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `mov r32, [src_base + offset]` (loads a 32-bit value from memory, zero-extended to 64 bits). */
void emit_mov_reg32_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movss xmm, [src_base + offset]` (loads a 32-bit float from memory). */
void emit_movss_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movsd xmm, [src_base + offset]` (loads a 64-bit double from memory). */
void emit_movsd_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movsxd r64, [src_base + offset]` (loads a 32-bit value from memory and sign-extends it to 64 bits). */
void emit_movsxd_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movsx r64, r/m8` (loads a signed byte from memory and sign-extends to 64 bits). */
void emit_movsx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movsx r64, r/m16` (loads a signed word from memory and sign-extends to 64 bits). */
void emit_movsx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movq r64, xmm` (moves 64 bits from an XMM to a GPR). */
void emit_movq_gpr_xmm(code_buffer * buf, x64_gpr dest, x64_xmm src);

/** @brief Emits `movzx r64, r/m8` (loads an unsigned byte from memory and zero-extends to 64 bits). */
void emit_movzx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `movzx r64, r/m16` (loads an unsigned word from memory and zero-extends to 64 bits). */
void emit_movzx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `mov r64, r64` (register-to-register move). */
void emit_mov_reg_reg(code_buffer * buf, x64_gpr dest, x64_gpr src);

/** @brief Emits `pop r64` (pops a 64-bit value from the stack into a register). */
void emit_pop_reg(code_buffer * buf, x64_gpr reg);

/** @brief Emits `lea r64, [src_base + offset]` (loads the effective address of a memory location into a register). */
void emit_lea_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset);

/** @brief Emits `mov r64, imm32` (moves a 32-bit immediate, sign-extended to 64 bits, into a register). */
void emit_mov_reg_imm32(code_buffer * buf, x64_gpr reg, int32_t imm);

/** @brief Emits `add r64, imm8` (adds an 8-bit immediate, sign-extended, to a 64-bit register). */
void emit_add_reg_imm8(code_buffer * buf, x64_gpr reg, int8_t imm);

/** @brief Emits `dec r64` (decrements a 64-bit register by 1). */
void emit_dec_reg(code_buffer * buf, x64_gpr reg);

/** @brief Emits an x86-64 ModR/M byte, used to encode operands for many instructions. */
void emit_modrm(code_buffer * buf, uint8_t mod, uint8_t reg_opcode, uint8_t rm);

/** @brief Emits an x86-64 REX prefix byte, used to enable 64-bit operations and extended registers. */
void emit_rex_prefix(code_buffer * buf, bool w, bool r, bool x, bool b);

/** @brief Emits an x86-64 `fldt [r64 + offset]` instruction (loads an 80-bit `long double` onto the FPU stack). */
void emit_fldt_mem(code_buffer * buf, x64_gpr base, int32_t offset);

/** @brief Emits an x86-64 `fstpt [r64 + offset]` instruction (stores an 80-bit `long double` from the FPU stack and
 * pops). */
void emit_fstpt_mem(code_buffer * buf, x64_gpr base, int32_t offset);
