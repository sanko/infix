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
 * @brief Implements the internal helper functions for emitting AArch64 machine code.
 *
 * @details This file provides the concrete implementations for the low-level
 * AArch64 instruction emitters declared in `abi_arm64_emitters.h`. Each function
 * in this file is responsible for constructing a single, valid 32-bit AArch64
 * instruction word from its constituent parts (registers, immediates, etc.) and
 * appending it to a `code_buffer`.
 *
 * This module encapsulates all the bitwise logic for encoding ARM64 instructions,
 * keeping the main `abi_arm64.c` file focused on the higher-level logic of
 * argument classification and trampoline structure. This separation improves
 * code readability and maintainability by isolating the complexities of the
 * instruction set architecture.
 */

#include "abi_arm64_emitters.h"
#include "common/utility.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/**
 * @brief Emits an AArch64 `LDR` (immediate) instruction.
 * @details Encodes the `LDR <Wt|Xt>, [<Xn|SP>, #pimm]` instruction. This loads
 *          a 32-bit or 64-bit value from memory at the address `base + offset`
 *          into the destination register.
 *
 *          - Opcode (64-bit): `11_111_00_1_01_...` (base 0xB9400000)
 *          - Opcode (32-bit): `10_111_00_1_01_...` (base 0x79400000)
 *
 * @param buf The code buffer to write the instruction to.
 * @param is64 True for a 64-bit load (LDR Xt), false for 32-bit (LDR Wt).
 * @param dest The destination general-purpose register (X0-X30 or W0-W30).
 * @param base The base general-purpose register (Xn or SP) for the memory address.
 * @param offset The 12-bit scaled immediate offset. Must be positive and a multiple of the access size (4 or 8).
 */
void emit_arm64_ldr_imm(code_buffer * buf, bool is64, arm64_gpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    // The immediate-offset addressing mode for LDR requires a positive offset that is a multiple of the transfer size.
    assert(offset >= 0 && "ARM64 LDR immediate offset must be positive for this encoding.");
    assert(offset % scale == 0 && "ARM64 LDR offset must be a multiple of the access size.");
    assert((offset / scale) <= 0xFFF && "ARM64 LDR offset exceeds 12-bit scaled limit.");
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 LDR instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for LDR (immediate) with 32-bit size and '01' opc.
    uint32_t instr = 0xb9400000;
    if (is64)
        instr |= (1u << 30);  // Set the 'size' field to '11' for 64-bit.
    // Encode the scaled immediate offset into the 'imm12' field.
    instr |= ((uint32_t)(offset / (is64 ? 8 : 4)) & 0xFFF) << 10;
    // Encode the base register into the 'Rn' field.
    instr |= (uint32_t)(base & 0x1F) << 5;
    // Encode the destination register into the 'Rt' field.
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `LDRSW` (immediate) instruction.
 * @details Encodes the `LDRSW <Xt>, [<Xn|SP>, #pimm]` instruction. This loads
 *          a 32-bit word from memory, sign-extends it to 64 bits, and writes
 *          it to a 64-bit general-purpose register.
 *
 *          - Opcode: `10_111_00_1_10_...` (base 0xB9800000)
 *
 * @param buf The code buffer.
 * @param dest The 64-bit destination GPR (Xt).
 * @param base The base GPR for the memory address.
 * @param offset The 12-bit scaled immediate offset (must be a multiple of 4).
 */
void emit_arm64_ldrsw_imm(code_buffer * buf, arm64_gpr dest, arm64_gpr base, int32_t offset) {
    assert(offset >= 0 && "ARM64 LDRSW immediate offset must be positive for this encoding.");
    assert(offset % 4 == 0 && "ARM64 LDRSW offset must be a multiple of 4.");
    assert((offset / 4) <= 0xFFF && "ARM64 LDRSW offset exceeds 12-bit scaled limit.");
    if (buf->error)
        return;
    if (offset < 0 || offset % 4 != 0 || (offset / 4) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 LDRSW instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for LDRSW <Xt>, [<Xn|SP>, #pimm].
    uint32_t instr = 0xB9800000;
    // The immediate offset is scaled by 4 for this instruction.
    instr |= ((uint32_t)(offset / 4) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `STR` (immediate) instruction.
 * @details Encodes the `STR <Wt|Xt>, [<Xn|SP>, #pimm]` instruction. This stores
 *          a 32-bit or 64-bit value from a GPR to memory at `base + offset`.
 *
 *          - Opcode (64-bit): `11_111_00_1_00_...` (base 0xB9000000)
 *          - Opcode (32-bit): `10_111_00_1_00_...` (base 0x79000000)
 *
 * @param buf The code buffer.
 * @param is64 True for a 64-bit store (STR Xt), false for 32-bit (STR Wt).
 * @param src The source GPR.
 * @param base The base GPR for the memory address.
 * @param offset The 12-bit scaled immediate offset.
 */
void emit_arm64_str_imm(code_buffer * buf, bool is64, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && "ARM64 STR immediate offset must be positive for this encoding.");
    assert(offset % scale == 0 && "ARM64 STR offset must be a multiple of the access size.");
    assert((offset / scale) <= 0xFFF && "ARM64 STR offset exceeds 12-bit scaled limit.");
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 STR instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for STR (immediate) with 32-bit size and '00' opc.
    uint32_t instr = 0xb9000000;
    if (is64)
        instr |= (1u << 30);  // Set the 'size' field to '11' for 64-bit.
    instr |= ((uint32_t)(offset / (is64 ? 8 : 4)) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `STRB` (immediate) instruction.
 * @details Encodes `STRB <Wt>, [<Xn|SP>, #imm]`. This stores the low byte (8 bits)
 *          from a GPR to memory.
 *
 *          - Opcode: `00_111_00_1_00_...` (base 0x39000000)
 *
 * @param buf The code buffer.
 * @param src The source GPR (Wt). The low 8 bits are used.
 * @param base The base GPR for the memory address (Xn).
 * @param offset The 12-bit immediate offset (unscaled).
 */
void emit_arm64_strb_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset <= 0xFFF && "ARM64 STRB offset exceeds 12-bit limit.");
    if (offset < 0 || offset > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 STRB instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for STRB Wt, [Xn, #imm]. The size field is '00'.
    uint32_t instr = 0x39000000;
    instr |= ((uint32_t)offset & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `STRH` (immediate) instruction.
 * @details Encodes `STRH <Wt>, [<Xn|SP>, #imm]`. This stores a half-word (16 bits)
 *          from a GPR to memory.
 *
 *          - Opcode: `01_111_00_1_00_...` (base 0x79000000)
 *
 * @param buf The code buffer.
 * @param src The source GPR (Wt). The low 16 bits are used.
 * @param base The base GPR for the memory address (Xn).
 * @param offset The 12-bit scaled immediate offset (must be a multiple of 2).
 */
void emit_arm64_strh_imm(code_buffer * buf, arm64_gpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    assert(offset >= 0 && offset % 2 == 0 && "ARM64 STRH offset must be a multiple of 2.");
    assert((offset / 2) <= 0xFFF && "ARM64 STRH offset exceeds 12-bit scaled limit.");
    if (offset < 0 || offset % 2 != 0 || (offset / 2) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 STRH instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for STRH Wt, [Xn, #imm]. The size field is '01'.
    uint32_t instr = 0x79000000;
    instr |= ((uint32_t)(offset / 2) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}


/**
 * @brief Emits an AArch64 `LDR` (immediate) for SIMD & FP registers.
 * @details Encodes `LDR <St|Dt>, [<Xn|SP>, #imm]`. This loads a 32-bit (single-precision)
 *          or 64-bit (double-precision) value from memory into a V-register.
 *
 *          - Opcode (64-bit): `11_111_10_1_01_...` (base 0xBD400000)
 *          - Opcode (32-bit): `10_111_10_1_01_...` (base 0x7D400000)
 *
 * @param buf The code buffer.
 * @param is64 True for 64-bit (D register), false for 32-bit (S register).
 * @param dest The destination V-register (V0-V31).
 * @param base The base GPR for the memory address.
 * @param offset The 12-bit scaled immediate offset.
 */
void emit_arm64_ldr_vpr(code_buffer * buf, bool is64, arm64_vpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && "ARM64 LDR (FP) immediate offset must be positive for this encoding.");
    assert(offset % scale == 0 && "ARM64 LDR (FP) offset must be a multiple of the access size.");
    assert((offset / scale) <= 0xFFF && "ARM64 LDR (FP) offset exceeds 12-bit scaled limit.");
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 LDR (FP/SIMD) instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for LDR (SIMD&FP). The 'V' bit (bit 26) is 1.
    uint32_t instr = 0x3d400000;
    // Size bits: 10 for 32-bit (S), 11 for 64-bit (D). These are bits 31 and 30.
    uint32_t size_bits = is64 ? 0b11 : 0b10;
    instr |= (size_bits << 30);
    instr |= ((uint32_t)(offset / (is64 ? 8 : 4)) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `STR` (immediate) for SIMD & FP registers.
 * @details Encodes `STR <St|Dt>, [<Xn|SP>, #imm]`. This stores a 32-bit or
 *          64-bit value from a V-register to memory.
 *
 *          - Opcode (64-bit): `11_111_10_1_00_...` (base 0xBD000000)
 *          - Opcode (32-bit): `10_111_10_1_00_...` (base 0x7D000000)
 *
 * @param buf The code buffer.
 * @param is64 True for 64-bit (D register), false for 32-bit (S register).
 * @param src The source V-register.
 * @param base The base GPR for the memory address.
 * @param offset The 12-bit scaled immediate offset.
 */
void emit_arm64_str_vpr(code_buffer * buf, bool is64, arm64_vpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    const int scale = is64 ? 8 : 4;
    assert(offset >= 0 && "ARM64 STR (FP) immediate offset must be positive for this encoding.");
    assert(offset % scale == 0 && "ARM64 STR (FP) offset must be a multiple of the access size.");
    assert((offset / scale) <= 0xFFF && "ARM64 STR (FP) offset exceeds 12-bit scaled limit.");
    if (offset < 0 || offset % scale != 0 || (offset / scale) > 0xFFF) {
        fprintf(stderr, "Error: Invalid offset %d for ARM64 STR (FP/SIMD) instruction.\n", offset);
        buf->error = true;
        return;
    }
    // Base encoding for STR (SIMD&FP). 'V' is 1, L bit (load/store) is 0.
    uint32_t instr = 0x3d000000;
    // Size bits: 10 for 32-bit (S), 11 for 64-bit (D).
    uint32_t size_bits = is64 ? 0b11 : 0b10;
    instr |= (size_bits << 30);
    instr |= ((uint32_t)(offset / (is64 ? 8 : 4)) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief (Internal) A generic helper for emitting ARM64 `ADD` or `SUB` with an immediate.
 * @details This static helper function abstracts the logic for `add/sub` immediate instructions.
 *          It correctly handles the immediate value by choosing the best encoding:
 *          1. A single instruction if the immediate fits in 12 bits (un-shifted).
 *          2. A single instruction if the immediate is a multiple of 4096 (0x1000) and can be
 *             represented as a 12-bit value left-shifted by 12.
 *          3. A fallback sequence that loads the large immediate into a scratch register (X15)
 *             and then performs a register-to-register `add/sub`. This avoids polluting
 *             registers used for argument passing.
 *
 * @param buf The code buffer.
 * @param is_sub If true, emits `SUB`; otherwise, emits `ADD`.
 * @param is64 If true, performs a 64-bit operation (on X registers).
 * @param set_flags If true, emits the flag-setting variant (`ADDS` or `SUBS`).
 * @param dest The destination register.
 * @param base The source register.
 * @param imm The immediate value.
 */
static void emit_arm64_arith_imm(
    code_buffer * buf, bool is_sub, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    // Base opcodes for ADD/SUB (immediate)
    // ADD is 0x11... (32b) or 0x91... (64b)
    // SUB is 0x51... (32b) or 0xD1... (64b)
    uint32_t instr = is_sub ? 0x51000000 : 0x11000000;
    if (is64)
        instr |= (1u << 31);  // 'sf' bit for 64-bit operation.
    if (set_flags)
        instr |= (1u << 29);  // 'S' bit to update flags.
    if (imm <= 0xFFF) {       // Check if the immediate fits in the un-shifted 12-bit field.
        instr |= (imm & 0xFFF) << 10;
    }
    else if ((imm & 0xFFF) == 0 && (imm >> 12) <= 0xFFF && (imm >> 12) > 0) {
        // Check if the immediate can be represented as a 12-bit value shifted left by 12.
        instr |= (1u << 22);  // 'sh' bit selects LSL #12 shift.
        instr |= ((imm >> 12) & 0xFFF) << 10;
    }
    else {
        // Immediate is too large for a single instruction. Use a scratch register.
        // X15 is a caller-saved GPR not used for arguments, making it a safe scratch register.
        arm64_gpr scratch_reg = X15_REG;
        emit_arm64_load_u64_immediate(buf, scratch_reg, imm);

        // Emit the register-to-register version of ADD/SUB.
        // Base opcodes for ADD/SUB (register)
        // ADD reg: 0B (32b), 8B (64b)
        // SUB reg: 4B (32b), CB (64b)
        uint32_t reg_instr = is_sub ? 0x4B000000 : 0x0B000000;
        if (is64)
            reg_instr |= (1u << 31);
        if (set_flags)
            reg_instr |= (1u << 29);

        reg_instr |= (uint32_t)(scratch_reg & 0x1F) << 16;  // Rm = scratch register
        reg_instr |= (uint32_t)(base & 0x1F) << 5;          // Rn = base register
        reg_instr |= (uint32_t)(dest & 0x1F);               // Rd = destination register
        emit_int32(buf, reg_instr);
        return;
    }

    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `ADD` (immediate) instruction.
 * @details Encodes `ADD(S) <Wd|Xd>, <Wn|Xn>, #imm`. Adds an immediate value to a register.
 *          This function automatically handles large immediates by generating a
 *          multi-instruction sequence if necessary.
 *
 *          - Opcode (64-bit): `10_0_10001_...` (0x91...)
 *          - Opcode (32-bit): `00_0_10001_...` (0x11...)
 *
 * @param buf The code buffer.
 * @param is64 True for 64-bit operation (operands are X registers).
 * @param set_flags True to update condition flags (emits `ADDS`).
 * @param dest The destination GPR.
 * @param base The source GPR.
 * @param imm The immediate value. Can be larger than 12 bits.
 */
void emit_arm64_add_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    emit_arm64_arith_imm(buf, false, is64, set_flags, dest, base, imm);
}

/**
 * @brief Emits an AArch64 `SUB` (immediate) instruction.
 * @details Encodes `SUB(S) <Wd|Xd>, <Wn|Xn>, #imm`. Subtracts an immediate value from a register.
 *          This function automatically handles large immediates.
 *
 *          - Opcode (64-bit): `11_0_10001_...` (0xD1...)
 *          - Opcode (32-bit): `01_0_10001_...` (0x51...)
 *
 * @param buf The code buffer.
 * @param is64 True for 64-bit operation.
 * @param set_flags True to update condition flags (emits `SUBS`).
 * @param dest The destination GPR.
 * @param base The source GPR.
 * @param imm The immediate value.
 */
void emit_arm64_sub_imm(code_buffer * buf, bool is64, bool set_flags, arm64_gpr dest, arm64_gpr base, uint32_t imm) {
    emit_arm64_arith_imm(buf, true, is64, set_flags, dest, base, imm);
}

/**
 * @brief (Internal) Emits a single AArch64 `MOVZ` or `MOVK` instruction.
 * @details This static helper is the fundamental building block used by `emit_arm64_load_u64_immediate`.
 *          It constructs a "move wide" instruction, which places a 16-bit immediate into a
 *          register at a specified position (shifted by 0, 16, 32, or 48 bits).
 *
 *          - `MOVZ` (Move Wide with Zero): Zeros the entire register and then writes the immediate.
 *            Used for loading the first 16-bit chunk of a larger value.
 *            Opcode (64-bit): `1_1_0_100101_...` (base 0xD2800000)
 *
 *          - `MOVK` (Move Wide with Keep): Writes the immediate to the specified position while
 *            preserving all other bits in the register. Used for subsequent chunks.
 *            Opcode (64-bit): `1_1_1_100101_...` (base 0xF2800000)
 *
 * @param buf The code buffer.
 * @param is_movz If true, emits `MOVZ`; otherwise, emits `MOVK`.
 * @param dest_reg The destination register.
 * @param imm The 16-bit immediate chunk to write.
 * @param shift_count The chunk index, determining the left shift amount (0=LSL 0, 1=LSL 16, 2=LSL 32, 3=LSL 48).
 */
static void emit_arm64_mov_imm_chunk(
    code_buffer * buf, bool is_movz, uint64_t dest_reg, uint16_t imm, uint8_t shift_count) {
    // Base encoding for MOVZ Xd, #imm, LSL #shift
    uint32_t instr = 0x52800000;
    instr |= (1u << 31);  // 'sf' bit for 64-bit register.
    if (!is_movz) {
        // Change opcode from MOVZ to MOVK by setting the 'opc' field to '11'.
        instr |= (0b11u << 29);
    }
    // Encode the shift amount (00, 01, 10, 11 for LSL 0, 16, 32, 48) into the 'hw' field.
    instr |= ((uint32_t)shift_count & 0x3) << 21;
    // Encode the 16-bit immediate into the 'imm16' field.
    instr |= ((uint32_t)imm & 0xFFFF) << 5;
    // Encode the destination register into the 'Rd' field.
    instr |= (dest_reg & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits instructions to load an arbitrary 64-bit immediate into a GPR.
 * @details This is achieved by emitting a sequence of up to four "move wide" instructions:
 *          one `MOVZ` for the first 16-bit chunk (to zero the register) followed by
 *          up to three `MOVK` instructions for the remaining chunks. This is the
 *          standard AArch64 pattern for materializing a 64-bit constant.
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param value The 64-bit immediate value to load.
 */
void emit_arm64_load_u64_immediate(code_buffer * buf, arm64_gpr dest, uint64_t value) {
    // Load the lowest 16 bits with MOVZ (zeros the rest of the register).
    emit_arm64_mov_imm_chunk(buf, true, dest, (value >> 0) & 0xFFFF, 0);
    // Load the next 16 bits with MOVK (keeps the other bits).
    emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 16) & 0xFFFF, 1);
    // Load the third 16 bits.
    emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 32) & 0xFFFF, 2);
    // Load the highest 16 bits.
    emit_arm64_mov_imm_chunk(buf, false, dest, (value >> 48) & 0xFFFF, 3);
}

/**
 * @brief Emits an AArch64 `LDR <Qt>, [Xn, #imm]` for a 128-bit load.
 * @details This instruction is used for loading 128-bit values, such as the
 *          `long double` type on Linux AArch64, from memory into a full
 *          128-bit Q-register (which is the full width of a V-register).
 *
 *          - Opcode: `00_111_10_1_01...` (base 0x3DC00000)
 *
 * @param buf The code buffer.
 * @param dest The destination V-register (V0-V31).
 * @param base The base GPR for the memory address.
 * @param offset The byte offset from the base register. Must be a multiple of 16.
 */
void emit_arm64_ldr_q_imm(code_buffer * buf, arm64_vpr dest, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    // This is the "Load/store register (unsigned immediate)" encoding for a 128-bit vector.
    // opc<1>:size<1> = 00, V=1, opc<0>=1 -> 0b0011110101...
    assert(offset >= 0 && offset % 16 == 0 && "ARM64 LDR (128-bit) offset must be a multiple of 16.");
    assert((offset / 16) <= 0xFFF && "ARM64 LDR (128-bit) offset exceeds scaled limit.");

    // Base encoding for LDR Qt, [...]. opc=01, V=1, size=00.
    uint32_t instr = 0x3DC00000;
    instr |= ((uint32_t)(offset / 16) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(dest & 0x1F);
    emit_int32(buf, instr);
}

/**
 * @brief Emits an AArch64 `STR <Qt>, [Xn, #imm]` for a 128-bit store.
 * @details This instruction is used for storing 128-bit values from a Q-register
 *          to memory.
 *
 *          - Opcode: `00_111_10_1_00...` (base 0x3D800000)
 *
 * @param buf The code buffer.
 * @param src The source V-register (V0-V31).
 * @param base The base GPR for the memory address.
 * @param offset The byte offset. Must be a multiple of 16.
 */
void emit_arm64_str_q_imm(code_buffer * buf, arm64_vpr src, arm64_gpr base, int32_t offset) {
    if (buf->error)
        return;
    // This is the "Load/store register (unsigned immediate)" encoding for a 128-bit vector store.
    // opc<1>:size<1> = 00, V=1, opc<0>=0 -> 0b0011110100...
    assert(offset >= 0 && offset % 16 == 0 && "ARM64 STR (128-bit) offset must be a multiple of 16.");
    assert((offset / 16) <= 0xFFF && "ARM64 STR (128-bit) offset exceeds scaled limit.");

    // Base encoding for STR Qt, [...]. opc=00, V=1, size=00.
    uint32_t instr = 0x3D800000;
    instr |= ((uint32_t)(offset / 16) & 0xFFF) << 10;
    instr |= (uint32_t)(base & 0x1F) << 5;
    instr |= (uint32_t)(src & 0x1F);
    emit_int32(buf, instr);
}
