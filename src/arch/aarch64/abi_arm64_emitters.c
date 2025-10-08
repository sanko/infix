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
 * @file abi_arm64_emitters.c
 * @brief Implements internal helper functions for emitting AArch64 machine code.
 * @ingroup internal_abi_aarch64
 *
 * @internal
 * This file provides the concrete implementations for the low-level AArch64
 * instruction emitters. Each function constructs a single, valid 32-bit AArch64
 * instruction word from its component parts (registers, immediates, etc.) and
 * appends it to a `code_buffer`.
 *
 * This module encapsulates the bitwise logic for encoding ARM64 instructions,
 * keeping the main `abi_arm64.c` file focused on the higher-level logic of
 * applying the AAPCS64 ABI rules.
 * @endinternal
 */

#include "abi_arm64_emitters.h"
#include "common/utility.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

//=================================================================================================
// GPR <-> Immediate Value Emitters
//=================================================================================================

/*
 * @internal
 * Emits a single AArch64 `MOVZ` or `MOVK` instruction. This is the fundamental
 * building block for loading large constants.
 * - `MOVZ` (Move Wide with Zero): Zeros the register and writes a 16-bit immediate.
 * - `MOVK` (Move Wide with Keep): Writes a 16-bit immediate, preserving other bits.
 *
 * Opcode format (MOVZ, 64-bit): 1 1 0 100101 hw imm16 Rd  (base 0xD2800000)
 * Opcode format (MOVK, 64-bit): 1 1 1 100101 hw imm16 Rd  (base 0xF2800000)
 */
static void emit_arm64_mov_imm_chunk(
    code_buffer * buf, bool is_movz, uint64_t dest_reg, uint16_t imm, uint8_t shift_count) {
    // Base encoding for MOVZ Xd, #imm, LSL #shift
    uint32_t instr = 0x52800000;
    instr |= (1u << 31);  // 'sf' bit for 64-bit register.
    if (!is_movz)
        // Change opcode from MOVZ to MOVK by setting the 'opc' field to '11'.
        instr |= (0b11u << 29);
    // 'hw' field encodes the shift: 00=LSL 0, 01=LSL 16, 10=LSL 32, 11=LSL 48.
    instr |= ((uint32_t)shift_count & 0x3) << 21;
    // 'imm16' field holds the 16-bit immediate.
    instr |= ((uint32_t)imm & 0xFFFF) << 5;
    // 'Rd' field holds the destination register.
    instr |= (dest_reg & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_load_u64_immediate.
 * This is the standard AArch64 pattern for materializing a 64-bit constant. It
 * emits a sequence of up to four "move wide" instructions: one MOVZ to zero the
 * register and load the first 16 bits, followed by up to three MOVK instructions
 * for the remaining 16-bit chunks if they are non-zero.
 */
void emit_arm64_load_u64_immediate(code_buffer * buf, arm64_gpr dest, uint64_t value) {
    // Load the lowest 16 bits with MOVZ (zeros the rest of the register).
    emit_arm64_mov_imm_chunk(buf, true, dest, (value >> 0) & 0xFFFF, 0);

    // For each subsequent 16-bit chunk, use MOVK (Move Wide with Keep) only if
    // the chunk is not zero to avoid emitting redundant instructions.
    if ((value >> 16) & 0xFFFF)
        emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 16) & 0xFFFF, 1);
    if ((value >> 32) & 0xFFFF)
        emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 32) & 0xFFFF, 2);
    if ((value >> 48) & 0xFFFF)
        emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 48) & 0xFFFF, 3);
}

//=================================================================================================
// GPR <-> GPR Move Emitters
//=================================================================================================

/*
 * Implementation for emit_arm64_mov_reg.
 * Encodes `MOV Xd, Xn` which is an alias for `ORR Xd, XZR, Xn`.
 * Opcode (64-bit): 10101010000111110000001111100000 (0xAA1F03E0) + dest
 * This requires a special case for moving the stack pointer.
 */
void emit_arm64_mov_reg(code_buffer * buf, bool is64, arm64_gpr dest, arm64_gpr src) {
    // Special case: MOV to/from SP is an alias for ADD Xd, SP, #0.
    // The generic ORR-based alias treats register 31 as XZR, not SP.
    if (dest == SP_REG || src == SP_REG) {
        uint32_t instr = 0x11000000;  // ADD Wd, Wn, #0
        if (is64)
            instr |= (1u << 31);
        instr |= (uint32_t)(src & 0x1F) << 5;  // Rn
        instr |= (uint32_t)(dest & 0x1F);      // Rd
        emit_int32(buf, instr);
        return;
    }

    // Standard case: MOV is an alias for ORR Xd, XZR, Xn
    uint32_t instr = 0x2A0003E0;  // ORR Wd, WZR, Wm
    if (is64)
        instr |= (1u << 31);
    instr |= (uint32_t)(src & 0x1F) << 16;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}


//=================================================================================================
// Memory <-> GPR Load/Store Emitters
//=================================================================================================

/*
 * Implementation for emit_arm64_ldr_imm.
 * Encodes `LDR <Wt|Xt>, [<Xn|SP>, #pimm]`.
 * Opcode (64-bit): 11_111_00_1_01_... (base 0xB9400000)
 * Opcode (32-bit): 10_111_00_1_01_... (base 0x79400000)
 */
void emit_arm64_ldr_imm(code_buffer * buf, bool is64, arm64_gpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && offset % scale == 0 && (offset / scale) <= 0xFFF);
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0xb9400000;
    if (is64)
        instr |= (1u << 30);
    instr |= ((uint32_t)(offset / scale) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_ldrsw_imm.
 * Encodes `LDRSW <Xt>, [<Xn|SP>, #pimm]` (Load Register Signed Word).
 * Opcode: 10_111_00_1_10_... (base 0xB9800000)
 */
void emit_arm64_ldrsw_imm(code_buffer * buf, arm64_gpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset % 4 == 0 && (offset / 4) <= 0xFFF);
    if (offset < 0 || offset % 4 != 0 || (offset / 4) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0xB9800000;
    instr |= ((uint32_t)(offset / 4) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_str_imm.
 * Encodes `STR <Wt|Xt>, [<Xn|SP>, #pimm]`.
 * Opcode (64-bit): 11_111_00_1_00_... (base 0xB9000000)
 * Opcode (32-bit): 10_111_00_1_00_... (base 0x79000000)
 */
void emit_arm64_str_imm(code_buffer * buf, bool is64, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && offset % scale == 0 && (offset / scale) <= 0xFFF);
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0xb9000000;
    if (is64)
        instr |= (1u << 30);
    instr |= ((uint32_t)(offset / scale) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_strb_imm.
 * Encodes `STRB <Wt>, [<Xn|SP>, #imm]`. Stores the low 8 bits of a register.
 * Opcode: 00_111_00_1_00_... (base 0x39000000)
 */
void emit_arm64_strb_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset <= 0xFFF);
    if (offset < 0 || offset > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x39000000;
    instr |= ((uint32_t)offset & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_strh_imm.
 * Encodes `STRH <Wt>, [<Xn|SP>, #imm]`. Stores the low 16 bits of a register.
 * Opcode: 01_111_00_1_00_... (base 0x79000000)
 */
void emit_arm64_strh_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset % 2 == 0 && (offset / 2) <= 0xFFF);
    if (offset < 0 || offset % 2 != 0 || (offset / 2) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x79000000;
    instr |= ((uint32_t)(offset / 2) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_stp_pre_index (Store Pair).
 * Encodes `STP <Xt1>, <Xt2>, [Xn|SP, #imm]!`.
 * Opcode (64-bit): 1010100110...
 */
void emit_arm64_stp_pre_index(
    code_buffer * buf, bool is64, arm64_gpr src1, arm64_gpr src2, arm64_gpr base, int32_t offset) {
    uint32_t instr = 0xA9800000;  // Base for STP pre-indexed
    if (is64)
        instr |= (1u << 31);
    int scale = is64 ? 8 : 4;
    assert(offset % scale == 0 && (offset / scale) >= -64 && (offset / scale) <= 63);
    instr |= ((uint32_t)(offset / scale) & 0x7F) << 15;
    instr |= (uint32_t)(src2 & 0x1F) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src1 & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_ldp_post_index (Load Pair).
 * Encodes `LDP <Xt1>, <Xt2>, [Xn|SP], #imm`.
 * Opcode (64-bit): 1010100011...
 */
void emit_arm64_ldp_post_index(
    code_buffer * buf, bool is64, arm64_gpr dest1, arm64_gpr dest2, arm64_gpr base, int32_t offset) {
    uint32_t instr = 0xA8C00000;  // Base for LDP post-indexed
    if (is64)
        instr |= (1u << 31);
    int scale = is64 ? 8 : 4;
    assert(offset % scale == 0 && (offset / scale) >= -64 && (offset / scale) <= 63);
    instr |= ((uint32_t)(offset / scale) & 0x7F) << 15;
    instr |= (uint32_t)(dest2 & 0x1F) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest1 & 0x1F);
    emit_int32(buf, instr);
}

//=================================================================================================
// Memory <-> VPR (SIMD/FP) Emitters
//=================================================================================================

/*
 * Implementation for emit_arm64_ldr_vpr.
 * Encodes `LDR <St|Dt>, [<Xn|SP>, #imm]`.
 * Opcode (64-bit, D reg): 11_111_10_1_01_... (base 0xBD400000)
 * Opcode (32-bit, S reg): 10_111_10_1_01_... (base 0x7D400000)
 */
void emit_arm64_ldr_vpr(code_buffer * buf, bool is64, arm64_vpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && offset % scale == 0 && (offset / scale) <= 0xFFF);
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x3d400000;
    uint32_t size_bits = is64 ? 0b11 : 0b10;
    instr |= (size_bits << 30);
    instr |= ((uint32_t)(offset / scale) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_str_vpr.
 * Encodes `STR <St|Dt>, [<Xn|SP>, #imm]`.
 * Opcode (64-bit, D reg): 11_111_10_1_00_... (base 0xBD000000)
 * Opcode (32-bit, S reg): 10_111_10_1_00_... (base 0x7D000000)
 */
void emit_arm64_str_vpr(code_buffer * buf, bool is64, arm64_vpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && offset % scale == 0 && (offset / scale) <= 0xFFF);
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x3d000000;
    uint32_t size_bits = is64 ? 0b11 : 0b10;
    instr |= (size_bits << 30);
    instr |= ((uint32_t)(offset / scale) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_ldr_q_imm.
 * Encodes `LDR <Qt>, [Xn, #imm]` for a 128-bit load into a full V-register.
 * Opcode: 00_111_10_1_01... (base 0x3DC00000)
 */
void emit_arm64_ldr_q_imm(code_buffer * buf, arm64_vpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset % 16 == 0 && (offset / 16) <= 0xFFF);
    if (offset < 0 || offset % 16 != 0 || (offset / 16) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x3DC00000;
    instr |= ((uint32_t)(offset / 16) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_str_q_imm.
 * Encodes `STR <Qt>, [Xn, #imm]` for a 128-bit store from a full V-register.
 * Opcode: 00_111_10_1_00... (base 0x3D800000)
 */
void emit_arm64_str_q_imm(code_buffer * buf, arm64_vpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset % 16 == 0 && (offset / 16) <= 0xFFF);
    if (offset < 0 || offset % 16 != 0 || (offset / 16) > 0xFFF) {
        buf->error = true;
        return;
    }
    uint32_t instr = 0x3D800000;
    instr |= ((uint32_t)(offset / 16) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

//=================================================================================================
// Arithmetic Emitters
//=================================================================================================

/*
 * @internal
 * Generic helper for emitting ARM64 `ADD` or `SUB` with an immediate.
 * It handles large immediates by falling back to a multi-instruction sequence that
 * uses a scratch register (X15), since single instructions have a limited immediate range.
 */
static void emit_arm64_arith_imm(
    code_buffer * buf, bool is_sub, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    uint32_t instr = is_sub ? 0x51000000 : 0x11000000;
    if (is64)
        instr |= (1u << 31);
    if (set_flags)
        instr |= (1u << 29);

    if (imm <= 0xFFF)  // Check for un-shifted 12-bit immediate.
        instr |= (imm & 0xFFF) << 10;
    else if ((imm & 0xFFF) == 0 && (imm >> 12) <= 0xFFF && (imm >> 12) > 0) {  // Check for shifted 12-bit immediate.
        instr |= (1u << 22);                                                   // 'sh' bit selects LSL #12 shift.
        instr |= ((imm >> 12) & 0xFFF) << 10;
    }
    else {
        // Immediate is too large. Load it into a scratch register (X15) and do a register-based operation.
        arm64_gpr scratch_reg = X15_REG;
        emit_arm64_load_u64_immediate(buf, scratch_reg, imm);

        uint32_t reg_instr = is_sub ? 0x4B000000 : 0x0B000000;
        if (is64)
            reg_instr |= (1u << 31);
        if (set_flags)
            reg_instr |= (1u << 29);

        reg_instr |= (uint32_t)(scratch_reg & 0x1F) << 16;
        reg_instr |= (uint32_t)(base & 0x1F) << 5;
        reg_instr |= (uint32_t)(dest & 0x1F);
        emit_int32(buf, reg_instr);
        return;
    }

    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_add_imm.
 * Opcode (64-bit): 10_0_10001_... (0x91...)
 * Opcode (32-bit): 00_0_10001_... (0x11...)
 */
void emit_arm64_add_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    emit_arm64_arith_imm(buf, false, is64, set_flags, dest, base, imm);
}

/*
 * Implementation for emit_arm64_sub_imm.
 * Opcode (64-bit): 11_0_10001_... (0xD1...)
 * Opcode (32-bit): 01_0_10001_... (0x51...)
 */
void emit_arm64_sub_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    emit_arm64_arith_imm(buf, true, is64, set_flags, dest, base, imm);
}

//=================================================================================================
// Control Flow Emitters
//=================================================================================================

/*
 * Implementation for emit_arm64_blr_reg (Branch with Link to Register).
 * Opcode: 1101011000111111000000... (0xD63F0000)
 */
void emit_arm64_blr_reg(code_buffer * buf, arm64_gpr reg) {
    uint32_t instr = 0xD63F0000;
    instr |= (uint32_t)(reg & 0x1F) << 5;
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_ret.
 * Opcode: 1101011001011111000000... (0xD65F0000)
 * Defaults to `RET X30` if X30_LR_REG is passed.
 */
void emit_arm64_ret(code_buffer * buf, arm64_gpr reg) {
    uint32_t instr = 0xD65F0000;
    instr |= (uint32_t)(reg & 0x1F) << 5;
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_cbnz (Compare and Branch on Non-Zero).
 * Opcode (64-bit): 10110101... (0xB5...)
 */
void emit_arm64_cbnz(code_buffer * buf, bool is64, arm64_gpr reg, int32_t offset) {
    uint32_t instr = 0x35000000;
    if (is64)
        instr |= (1u << 31);
    // Offset is encoded as a 19-bit immediate, scaled by 4 bytes.
    assert(offset % 4 == 0 && (offset / 4) >= -262144 && (offset / 4) <= 262143);
    instr |= ((uint32_t)(offset / 4) & 0x7FFFF) << 5;
    instr |= (uint32_t)(reg & 0x1F);
    emit_int32(buf, instr);
}

/*
 * Implementation for emit_arm64_brk (Breakpoint).
 * Opcode: 11010100001... (0xD42...)
 */
void emit_arm64_brk(code_buffer * buf, uint16_t imm) {
    uint32_t instr = 0xD4200000;
    instr |= (uint32_t)(imm & 0xFFFF) << 5;
    emit_int32(buf, instr);
}

/**
 * Emits `BR <Xn>` (Branch to Register).
 * This instruction performs an indirect, unconditional branch to the
 * address contained in the specified register. It is functionally similar to
 * `JMP` on x86.
 * Opcode: 1101011000011111000000... (0xD61F0000)
 */
void emit_arm64_b_reg(code_buffer * buf, arm64_gpr reg) {
    uint32_t instr = 0xD61F0000;
    instr |= (uint32_t)(reg & 0x1F) << 5;
    emit_int32(buf, instr);
}
