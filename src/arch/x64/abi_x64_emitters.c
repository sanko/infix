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
 * @file abi_x64_emitters.c
 * @brief Implements internal helper functions for emitting x86-64 machine code.
 * @ingroup internal_abi_x64
 *
 * @internal
 * This file provides the concrete implementations for the low-level x86-64
 * instruction emitters. These functions are the fundamental building blocks
 * used by both the Windows x64 and System V ABI implementations.
 *
 * By centralizing these functions, we encapsulate the complex details of x86-64
 * instruction encoding (opcodes, ModR/M bytes, REX prefixes). For a definitive
 * reference, see the Intel 64 and IA-32 Architectures Software Developer's Manuals.
 * @endinternal
 */

#include "arch/x64/abi_x64_emitters.h"
#include "common/utility.h"
#include <assert.h>
#include <string.h>

// Helper defines for REX prefix bits, making the code more readable.
#define REX_W (1 << 3)  // 64-bit operand size
#define REX_R (1 << 2)  // Extends ModR/M 'reg' field
#define REX_X (1 << 1)  // Extends SIB 'index' field
#define REX_B (1 << 0)  // Extends ModR/M 'r/m' or SIB 'base' field

// Instruction Encoding Helpers
/*
 * Implementation for emit_rex_prefix.
 * The REX prefix is a single byte (0x40-0x4F) used in 64-bit mode to:
 * - Set operand size to 64 bits (W bit).
 * - Extend the register fields to access R8-R15 (R, X, B bits).
 */
void emit_rex_prefix(code_buffer * buf, bool w, bool r, bool x, bool b) {
    uint8_t rex_byte = 0x40;
    if (w)
        rex_byte |= REX_W;
    if (r)
        rex_byte |= REX_R;
    if (x)
        rex_byte |= REX_X;
    if (b)
        rex_byte |= REX_B;
    emit_byte(buf, rex_byte);
}

/*
 * Implementation for emit_modrm.
 * The ModR/M byte is a crucial part of many instructions, specifying the addressing mode.
 * It encodes register operands and memory operands.
 */
void emit_modrm(code_buffer * buf, uint8_t mod, uint8_t reg_opcode, uint8_t rm) {
    uint8_t modrm_byte = (mod << 6) | (reg_opcode << 3) | rm;
    emit_byte(buf, modrm_byte);
}

// GPR <-> Immediate Value Emitters
/*
 * Implementation for emit_mov_reg_imm64.
 * Instruction Breakdown: MOV r64, imm64
 * Opcode format: REX.W + B8+rd imm64
 * - REX.W: (0x48) Mandatory prefix to promote the operation to 64 bits.
 *          REX.B is also set if `reg` is R8-R15.
 * - B8+rd: The base opcode is modified by the low 3 bits of the register index.
 * - imm64: The 8-byte immediate value.
 */
void emit_mov_reg_imm64(code_buffer * buf, x64_gpr reg, uint64_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0xB8 + (reg % 8));
    emit_int64(buf, imm);
}

/*
 * Implementation for emit_mov_reg_imm32.
 * Instruction Breakdown: MOV r/m64, imm32 (sign-extended)
 * Opcode format: REX.W + C7 /0 id
 * - REX.W: Mandatory for 64-bit operation.
 * - C7: Opcode for MOV with a 32-bit immediate.
 * - /0: The ModR/M `reg` field is used as an opcode extension (0 for MOV).
 * - id: The 4-byte immediate value.
 */
void emit_mov_reg_imm32(code_buffer * buf, x64_gpr reg, int32_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0xC7);
    emit_modrm(buf, 3, 0, reg % 8);  // mod=11 (register), reg=/0
    emit_int32(buf, imm);
}

// GPR <-> GPR Move Emitters
/*
 * Implementation for emit_mov_reg_reg.
 * Instruction Breakdown: MOV r/m64, r64
 * Opcode format: REX.W + 89 /r
 * - REX.W: Mandatory for 64-bit operation. REX.R extends `src`, REX.B extends `dest`.
 * - 89: Opcode for MOV where the destination is in the `r/m` field.
 * - /r: Indicates a ModR/M byte follows. (mod=11 for register-to-register).
 */
void emit_mov_reg_reg(code_buffer * buf, x64_gpr dest, x64_gpr src) {
    uint8_t rex = REX_W;
    if (dest >= R8_REG)
        rex |= REX_B;
    if (src >= R8_REG)
        rex |= REX_R;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);
    emit_modrm(buf, 3, src % 8, dest % 8);  // mod=11 (register-to-register)
}

// Memory -> GPR Load Emitters
/*
 * Implementation for emit_mov_reg_mem.
 * Instruction Breakdown: MOV r64, r/m64
 * Opcode format: REX.W + 8B /r
 * - REX.W: Mandatory. REX.R extends `dest`, REX.B extends `src_base`.
 * - 8B: Opcode for MOV where the destination is in the `reg` field.
 * - /r: Indicates a ModR/M byte and potential SIB/displacement follow.
 */
void emit_mov_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = REX_W;
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x8B);

    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;

    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);  // SIB byte required for RSP base

    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_mov_reg32_mem.
 * Instruction Breakdown: MOV r32, r/m32
 * Opcode format: 8B /r (without REX.W)
 * - This loads a 32-bit value and implicitly zero-extends it to 64 bits.
 */
void emit_mov_reg32_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = 0;
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);

    emit_byte(buf, 0x8B);

    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;

    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);

    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movsxd_reg_mem.
 * Instruction Breakdown: MOVSXD r64, r/m32
 * Opcode format: REX.W + 63 /r
 * - Loads a 32-bit value and sign-extends it to 64 bits.
 */
void emit_movsxd_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    emit_byte(buf, 0x63);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movsx_reg64_mem8.
 * Instruction Breakdown: MOVSX r64, r/m8
 * Opcode format: REX.W + 0F BE /r
 */
void emit_movsx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xBE);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movsx_reg64_mem16.
 * Instruction Breakdown: MOVSX r64, r/m16
 * Opcode format: REX.W + 0F BF /r
 */
void emit_movsx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xBF);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movzx_reg64_mem8.
 * Instruction Breakdown: MOVZX r64, r/m8
 * Opcode format: REX.W + 0F B6 /r
 */
void emit_movzx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xB6);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movzx_reg64_mem16.
 * Instruction Breakdown: MOVZX r64, r/m16
 * Opcode format: REX.W + 0F B7 /r
 */
void emit_movzx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xB7);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

// GPR -> Memory Store Emitters
/*
 * Implementation for emit_mov_mem_reg.
 * Instruction Breakdown: MOV r/m64, r64
 * Opcode format: REX.W + 89 /r
 * - 89: Opcode for MOV where the source is in the `reg` field.
 */
void emit_mov_mem_reg(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    emit_rex_prefix(buf, 1, src >= R8_REG, 0, dest_base >= R8_REG);
    emit_byte(buf, 0x89);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_mov_mem_reg32.
 * Instruction Breakdown: MOV r/m32, r32
 * Opcode format: 89 /r (without REX.W)
 */
void emit_mov_mem_reg32(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    uint8_t rex = 0;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_mov_mem_reg16.
 * Instruction Breakdown: MOV r/m16, r16
 * Opcode format: 66 + 89 /r
 * - 66: The operand-size override prefix, changing the operation to 16-bit.
 */
void emit_mov_mem_reg16(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    emit_byte(buf, 0x66);
    uint8_t rex = 0;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_mov_mem_reg8.
 * Instruction Breakdown: MOV r/m8, r8
 * Opcode format: 88 /r
 */
void emit_mov_mem_reg8(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    uint8_t rex = 0;
    // REX prefix is needed to access r8-r15, or the low bytes of RSI, RDI, etc.
    if (src >= R8_REG || dest_base >= R8_REG || src >= RSP_REG)
        rex = 0x40;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, rex);
    emit_byte(buf, 0x88);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

// Memory <-> XMM/YMM (SSE/AVX) Emitters
/*
 * Implementation for emit_movss_xmm_mem.
 * Instruction Breakdown: MOVSS xmm, m32
 * Opcode format: F3 0F 10 /r
 * - F3: Mandatory prefix for scalar single-precision (SS) operations.
 */
void emit_movss_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    emit_byte(buf, 0xF3);
    uint8_t rex = 0;
    if (dest >= XMM8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x10);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movss_mem_xmm.
 * Instruction Breakdown: MOVSS m32, xmm
 * Opcode format: F3 0F 11 /r
 */
void emit_movss_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    emit_byte(buf, 0xF3);
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x11);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movsd_xmm_mem.
 * Instruction Breakdown: MOVSD xmm, m64
 * Opcode format: F2 0F 10 /r
 * - F2: Mandatory prefix for scalar double-precision (SD) operations.
 */
void emit_movsd_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    emit_byte(buf, 0xF2);
    uint8_t rex = 0;
    if (dest >= XMM8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x10);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movsd_mem_xmm.
 * Instruction Breakdown: MOVSD m64, xmm
 * Opcode format: F2 0F 11 /r
 */
void emit_movsd_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    emit_byte(buf, 0xF2);
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x11);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movups_xmm_mem.
 * Instruction Breakdown: MOVUPS xmm, m128 (Move Unaligned Packed Single)
 * Opcode format: 0F 10 /r
 */
void emit_movups_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = 0;
    if (dest >= XMM8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x10);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_movups_mem_xmm.
 * Instruction Breakdown: MOVUPS m128, xmm
 * Opcode format: 0F 11 /r
 */
void emit_movups_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    EMIT_BYTES(buf, 0x0F, 0x11);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * @internal
 * Emits a VEX prefix for an AVX instruction. This helper centralizes the complex
 * logic of choosing between the 2-byte (C5) and 3-byte (C4) VEX encodings.
 */
static void emit_vex_prefix(
    code_buffer * buf, bool r, bool x, bool b, uint8_t m, bool w, uint8_t v, bool l, uint8_t p) {
    // The VEX encoding inverts the R, X, and B bits from the REX prefix.
    if (!b && !x && m == 1 && w == 0) {
        // Use the more compact 2-byte VEX prefix (C5) when possible.
        emit_byte(buf, 0xC5);
        uint8_t byte2 = ((!r) << 7) | ((~v & 0xF) << 3) | ((l & 1) << 2) | (p & 3);
        emit_byte(buf, byte2);
    }
    else {
        // Fall back to the 3-byte VEX prefix (C4).
        emit_byte(buf, 0xC4);
        uint8_t byte2 = ((!r) << 7) | ((!x) << 6) | ((!b) << 5) | (m & 7);
        emit_byte(buf, byte2);
        uint8_t byte3 = ((w & 1) << 7) | ((~v & 0xF) << 3) | ((l & 1) << 2) | (p & 3);
        emit_byte(buf, byte3);
    }
}

/*
 * Implementation for emit_vmovupd_ymm_mem (load 256-bit AVX vector).
 * Instruction format: VEX.256.66.0F.WIG 10 /r
 */
void emit_vmovupd_ymm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    // VEX prefix fields for vmovupd ymm, m256:
    // L=1 (256-bit), p=1 (from 66 prefix), m-mmmm=01 (from 0F map).
    emit_vex_prefix(buf, dest >= XMM8_REG, 0, src_base >= R8_REG, 1, false, 0, true, 1);
    emit_byte(buf, 0x10);  // Opcode for MOVUPD
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_vmovupd_mem_ymm (store 256-bit AVX vector).
 * Instruction format: VEX.256.66.0F.WIG 11 /r
 */
void emit_vmovupd_mem_ymm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    emit_vex_prefix(buf, src >= XMM8_REG, 0, dest_base >= R8_REG, 1, false, 0, true, 1);
    emit_byte(buf, 0x11);  // Opcode for MOVUPD (store)
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, src % 8, dest_base % 8);
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

// GPR <-> XMM Move Emitters
/*
 * Implementation for emit_movq_xmm_gpr.
 * Instruction Breakdown: MOVQ xmm, r/m64
 * Opcode format: 66 + REX.W + 0F 6E /r
 * - Copies 64 bits from GPR to the lower half of an XMM register, zeroing the upper half.
 */
void emit_movq_xmm_gpr(code_buffer * buf, x64_xmm dest, x64_gpr src) {
    emit_byte(buf, 0x66);
    emit_rex_prefix(buf, 1, dest >= XMM8_REG, 0, src >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0x6E);
    emit_modrm(buf, 3, dest % 8, src % 8);
}

/*
 * Implementation for emit_movq_gpr_xmm.
 * Instruction Breakdown: MOVQ r/m64, xmm
 * Opcode format: 66 + REX.W + 0F 7E /r
 * - Copies the lower 64 bits from an XMM register to a GPR.
 */
void emit_movq_gpr_xmm(code_buffer * buf, x64_gpr dest, x64_xmm src) {
    emit_byte(buf, 0x66);
    emit_rex_prefix(buf, 1, src >= XMM8_REG, 0, dest >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0x7E);
    emit_modrm(buf, 3, src % 8, dest % 8);
}

// Memory <-> x87 FPU Emitters
/*
 * Implementation for emit_fldt_mem.
 * Instruction Breakdown: FLDT m80fp (Load long double)
 * Opcode format: DB /5
 * - Loads an 80-bit value from memory onto the top of the x87 FPU stack (st0).
 */
void emit_fldt_mem(code_buffer * buf, x64_gpr base, int32_t offset) {
    uint8_t rex = 0;
    if (base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0xDB);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, 5, base % 8);  // reg field is 5 for this instruction
    if (base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_fstpt_mem.
 * Instruction Breakdown: FSTPT m80fp (Store long double and Pop)
 * Opcode format: DB /7
 * - Stores the 80-bit value from st(0) into memory and pops it from the FPU stack.
 */
void emit_fstpt_mem(code_buffer * buf, x64_gpr base, int32_t offset) {
    uint8_t rex = 0;
    if (base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0xDB);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, 7, base % 8);  // reg field is 7 for this instruction
    if (base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

// Arithmetic & Logic Emitters
/*
 * Implementation for emit_lea_reg_mem.
 * Instruction Breakdown: LEA r64, m
 * Opcode format: REX.W + 8D /r
 * - Loads the effective address `[base + offset]` into the destination register.
 */
void emit_lea_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    emit_byte(buf, 0x8D);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_modrm(buf, mod >> 6, dest % 8, src_base % 8);
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/*
 * Implementation for emit_add_reg_imm32.
 * Opcode format: REX.W + 81 /0 id
 */
void emit_add_reg_imm32(code_buffer * buf, x64_gpr reg, int32_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0x81);
    emit_modrm(buf, 3, 0, reg % 8);  // mod=11, reg=/0 for ADD
    emit_int32(buf, imm);
}

/*
 * Implementation for emit_sub_reg_imm32.
 * Opcode format: REX.W + 81 /5 id
 */
void emit_sub_reg_imm32(code_buffer * buf, x64_gpr reg, int32_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0x81);
    emit_modrm(buf, 3, 5, reg % 8);  // mod=11, reg=/5 for SUB
    emit_int32(buf, imm);
}

/*
 * Implementation for emit_add_reg_imm8.
 * Instruction Breakdown: ADD r/m64, imm8 (sign-extended)
 * Opcode format: REX.W + 83 /0 ib
 * - /0: ModR/M `reg` field is 0, acting as an opcode extension for ADD.
 * Currently unused
 */
void emit_add_reg_imm8(code_buffer * buf, x64_gpr reg, int8_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, (reg >= R8_REG));
    emit_byte(buf, 0x83);
    emit_modrm(buf, 3, 0, (reg & 0x7));
    emit_byte(buf, imm);
}

/*
 * Implementation for emit_dec_reg.
 * Instruction Breakdown: DEC r/m64
 * Opcode format: REX.W + FF /1
 * - /1: ModR/M `reg` field is 1, acting as an opcode extension for DEC.
 */
void emit_dec_reg(code_buffer * buf, x64_gpr reg) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0xFF);
    emit_modrm(buf, 3, 1, reg % 8);
}

// Stack & Control Flow Emitters
/*
 * Implementation for emit_push_reg.
 * Opcode format: [REX.B] 50+rd
 */
void emit_push_reg(code_buffer * buf, x64_gpr reg) {
    uint8_t rex = 0;
    if (reg >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x50 + (reg % 8));
}

/*
 * Implementation for emit_pop_reg.
 * Opcode format: [REX.B] 58+rd
 */
void emit_pop_reg(code_buffer * buf, x64_gpr reg) {
    uint8_t rex = 0;
    if (reg >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x58 + (reg % 8));
}

/*
 * Implementation for emit_call_reg.
 * Opcode format: [REX.W] [REX.B] FF /2
 */
void emit_call_reg(code_buffer * buf, x64_gpr reg) {
    uint8_t rex = REX_W;
    if (reg >= R8_REG)
        rex |= REX_B;
    if (rex != REX_W)
        emit_byte(buf, 0x40 | rex);  // REX is only needed for extended regs
    else if (rex == REX_W)
        emit_byte(buf, 0x48);

    emit_byte(buf, 0xFF);
    emit_modrm(buf, 3, 2, reg % 8);  // mod=11, reg=/2 for CALL
}

/*
 * Implementation for emit_ret.
 * Opcode: C3
 */
void emit_ret(code_buffer * buf) { emit_byte(buf, 0xC3); }

/*
 * Implementation for emit_test_reg_reg.
 * Opcode format: REX.W + 85 /r
 */
void emit_test_reg_reg(code_buffer * buf, x64_gpr reg1, x64_gpr reg2) {
    emit_rex_prefix(buf, 1, reg2 >= R8_REG, 0, reg1 >= R8_REG);
    emit_byte(buf, 0x85);
    emit_modrm(buf, 3, reg2 % 8, reg1 % 8);
}

/*
 * Implementation for emit_jnz_short.
 * Opcode format: 75 rel8
 */
void emit_jnz_short(code_buffer * buf, int8_t offset) { EMIT_BYTES(buf, 0x75, (uint8_t)offset); }

/**
 * Emits a `jmp r64` instruction.
 * This instruction performs an indirect jump to the address contained in the
 * specified 64-bit register.
 * Opcode format: [REX.B] FF /4
 */
void emit_jmp_reg(code_buffer * buf, x64_gpr reg) {
    uint8_t rex = 0;
    if (reg >= R8_REG)
        rex = 0x40 | REX_B;
    if (rex)
        emit_byte(buf, rex);
    emit_byte(buf, 0xFF);
    emit_modrm(buf, 3, 4, reg % 8);  // mod=11 (register), reg=/4 for JMP
}

/*
 * Implementation for emit_ud2.
 * Opcode format: 0F 0B
 */
void emit_ud2(code_buffer * buf) { EMIT_BYTES(buf, 0x0F, 0x0B); }
