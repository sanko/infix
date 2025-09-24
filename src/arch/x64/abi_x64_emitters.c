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
 * @brief Implements the internal helper functions for emitting x86-64 machine code.
 *
 * @details This file provides the concrete implementations for the low-level
 * x86-64 instruction emitters. These functions are the fundamental building blocks
 * used by both the Windows x64 and System V ABI implementations to generate
 * trampoline machine code. All multi-byte values are emitted in little-endian format.
 *
 * By centralizing these functions, we encapsulate the complex details of x86-64
 * instruction encoding (opcodes, ModR/M bytes, REX prefixes) and hide them from
 * the higher-level ABI logic. For a definitive reference on instruction encoding,
 * see the Intel 64 and IA-32 Architectures Software Developer's Manuals.
 */

#include "abi_x64_emitters.h"
#include "common/utility.h"
#include <string.h>

/** @internal Helper defines for REX prefix bits. */
#define REX_W (1 << 3)  // 64-bit operand size
#define REX_R (1 << 2)  // Extends ModR/M 'reg' field
#define REX_X (1 << 1)  // Extends SIB 'index' field
#define REX_B (1 << 0)  // Extends ModR/M 'r/m' or SIB 'base' field

/**
 * @brief Emits an x86-64 `mov r64, imm64` instruction.
 * @details This is the most direct way to load a full 64-bit immediate value
 *          (like a pointer or a large constant) into a general-purpose register.
 *
 *          - **Instruction format:** `REX.W + B8+r imm64`
 *          - `REX.W`: A mandatory prefix (0x48) that promotes the operation to 64 bits.
 *          - `B8+r`: The base opcode for moving an immediate into a register, where `r` is the low 3 bits of the
 * register's index.
 *          - `imm64`: The 8-byte immediate value.
 *
 * @param buf The code buffer to write to.
 * @param reg The destination 64-bit register (GPR).
 * @param imm The 64-bit immediate value to load.
 */
void emit_mov_reg_imm64(code_buffer * buf, x64_gpr reg, uint64_t imm) {
    /*
     * Instruction Breakdown: MOV r64, imm64
     * --------------------------------------
     * This is the most direct way to load a full 64-bit immediate into a GPR.
     *
     * Opcode format: REX.W + B8+rd imm64
     * - REX.W: (0x48) A mandatory prefix that promotes the operation to 64 bits.
     *          The REX.B bit is also set if `reg` is R8-R15.
     * - B8+rd: The base opcode (0xB8) is modified by the low 3 bits of the
     *          destination register's index.
     * - imm64: The 8-byte immediate value.
     */

    // A REX prefix is needed for 64-bit operation (W=1) or to access R8-R15 (B=1).
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    // The opcode is 0xB8 plus the 3-bit index of the register.
    emit_byte(buf, 0xB8 + (reg % 8));
    // Append the 8-byte immediate value.
    emit_int64(buf, imm);
}

/**
 * @brief Emits an x86-64 `pop r64` instruction.
 * @details Pops a 64-bit value from the top of the stack into the specified register.
 *          This also increments the stack pointer (RSP) by 8.
 *
 *          - **Opcode:** `58+r` (where `r` is the register index).
 *          - A REX prefix is added if the register is R8 or higher.
 *
 * @param buf The code buffer.
 * @param reg The destination GPR.
 */
void emit_pop_reg(code_buffer * buf, x64_gpr reg) {
    /*
     * Instruction Breakdown: POP r64
     * ------------------------------
     * Opcode format: [REX.B] + 58+rd
     * - REX.B: An optional prefix (0x41) used only if the register is R8-R15.
     * - 58+rd: The base opcode (0x58) is modified by the low 3 bits of the
     *          register's index.
     */
    uint8_t rex = 0;
    // REX.B bit is needed to encode registers R8-R15.
    if (reg >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x58 + (reg % 8));
}

/**
 * @brief Emits an x86-64 `mov r64, r64` instruction.
 * @details Copies a 64-bit value from the source register to the destination register.
 *
 *          - **Opcode:** `REX.W + 89 /r`
 *          - `REX.W` is required for 64-bit operation.
 *          - The `/r` indicates that a ModR/M byte follows to specify the registers.
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src The source GPR.
 */
void emit_mov_reg_reg(code_buffer * buf, x64_gpr dest, x64_gpr src) {
    /*
     * Instruction Breakdown: MOV r/m64, r64
     * --------------------------------------
     * Opcode format: REX.W + 89 /r
     * - REX.W: Mandatory for 64-bit operation. REX.R extends the `src` register,
     *          and REX.B extends the `dest` register.
     * - 89: Opcode for MOV where the destination is the `r/m` field.
     * - /r: Indicates a ModR/M byte follows.
     *   - ModR/M byte: mod=11 (register-to-register), reg=src, rm=dest.
     */
    // REX.W is mandatory. REX.B extends `dest`. REX.R extends `src`.
    uint8_t rex = REX_W;
    if (dest >= R8_REG)
        rex |= REX_B;
    if (src >= R8_REG)
        rex |= REX_R;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);
    // ModR/M byte for register-to-register: mod=11, reg=src, rm=dest.
    emit_byte(buf, 0xC0 | ((src % 8) << 3) | (dest % 8));
}

/**
 * @brief Emits an x86-64 `mov r64, [r64 + offset]` instruction.
 * @details Loads a 64-bit value from a memory location into a register.
 *
 *          - **Opcode:** `REX.W + 8B /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 */
void emit_mov_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    /*
     * Instruction Breakdown: MOV r64, r/m64
     * --------------------------------------
     * Opcode format: REX.W + 8B /r
     * - REX.W: Mandatory for 64-bit operation. REX.R extends `dest` (reg field),
     *          REX.B extends `src_base` (r/m field).
     * - 8B: Opcode for MOV where the destination is the `reg` field.
     * - /r: Indicates a ModR/M byte and potential SIB/displacement follow.
     */
    // REX.W=1 (64-bit), REX.R extends 'dest', REX.B extends 'src_base'.
    uint8_t rex = REX_W;
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x8B);  // Opcode for MOV r, r/m
    // Determine the ModR/M 'mod' field based on the offset size.
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;  // mod=01 (8-bit offset) or mod=10 (32-bit offset)
    if (offset == 0 && (src_base % 8) != RBP_REG)                   // mod=00 (no offset) unless base is RBP/R13
        mod = 0x00;
    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));
    if (src_base % 8 == RSP_REG)  // If the base is RSP, a SIB byte is required.
        emit_byte(buf, 0x24);
    if (mod == 0x40)  // Append 8-bit offset
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)  // Append 32-bit offset
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `mov r32, [r/m32]` instruction.
 * @details Loads a 32-bit value from memory into a register. On x86-64, any operation
 *          on a 32-bit register automatically zero-extends the value to fill the full
 *          64-bit register. This is the correct way to perform a zero-extending load
 *          for `unsigned int`, `unsigned short`, and `unsigned char`.
 *
 *          - **Opcode:** `8B /r` (without a REX.W prefix)
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_mov_reg32_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    /*
     * Instruction Breakdown: MOV r/m64, r64
     * --------------------------------------
     * Opcode format: REX.W + 89 /r
     * - REX.W: Mandatory for 64-bit operation. REX.R extends `src` (reg field),
     *          REX.B extends `dest_base` (r/m field).
     * - 89: Opcode for MOV where the source is the `reg` field.
     * - /r: Indicates a ModR/M byte and potential SIB/displacement follow.
     */
    // REX prefix is only needed for extended registers, NOT for operand size.
    uint8_t rex = 0;
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);

    emit_byte(buf, 0x8B);  // Opcode for MOV r32, r/m32

    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;

    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));

    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);  // SIB byte required for RSP base

    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `mov [r64 + offset], r64` instruction.
 * @details Stores a 64-bit value from a register into a memory location.
 *
 *          - **Opcode:** `REX.W + 89 /r`
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 * @param src The source GPR.
 */
void emit_mov_mem_reg(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    /*
     * Instruction Breakdown: MOV r/m64, r64
     * --------------------------------------
     * Opcode format: REX.W + 89 /r
     * - REX.W: Mandatory for 64-bit operation. REX.R extends `src` (reg field),
     *          REX.B extends `dest_base` (r/m field).
     * - 89: Opcode for MOV where the source is the `reg` field.
     * - /r: Indicates a ModR/M byte and potential SIB/displacement follow.
     */
    // REX.W=1 (64-bit), REX.R extends 'src', REX.B extends 'dest_base'.
    uint8_t rex = REX_W;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);  // Opcode for MOV r/m, r
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `mov [r64 + offset], r32` instruction.
 * @details Stores the lower 32 bits of a register into a memory location.
 *
 *          - **Opcode:** `89 /r` (no REX.W prefix)
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 * @param src The source GPR.
 */
void emit_mov_mem_reg32(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    /*
     * Instruction Breakdown: MOV r/m32, r32
     * --------------------------------------
     * Same as 64-bit version, but WITHOUT the REX.W prefix.
     */
    uint8_t rex = 0;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x89);  // Note: No REX.W means 32-bit operation.
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `mov [r64 + offset], r16` instruction.
 * @details Stores the lower 16 bits of a register into a memory location.
 *
 *          - **Opcode:** `66 + 89 /r`
 *          - `66`: The operand-size override prefix, changing the default 32/64-bit operation to 16-bit.
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 * @param src The source GPR.
 */
void emit_mov_mem_reg16(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    /*
     * Instruction Breakdown: MOV r/m16, r16
     * --------------------------------------
     * Uses the 0x66 operand-size override prefix to specify a 16-bit operation.
     */
    emit_byte(buf, 0x66);  // Operand-size override prefix for 16-bit.
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
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `mov [r64 + offset], r8` instruction.
 * @details Stores the lower 8 bits of a register into a memory location.
 *
 *          - **Opcode:** `88 /r`
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 * @param src The source GPR.
 */
void emit_mov_mem_reg8(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_gpr src) {
    uint8_t rex = 0;
    // A REX prefix is needed for r8-r15, or to access the low bytes of RSI, RDI, etc. (SIL, DIL).
    if (src >= R8_REG || dest_base >= R8_REG || src >= RSP_REG)
        rex = 0x40;
    if (src >= R8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, rex);
    emit_byte(buf, 0x88);  // Opcode for 8-bit MOV r/m, r
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}


/**
 * @brief Emits an x86-64 `movss xmm, [r64 + offset]` instruction.
 * @details Loads a 32-bit single-precision float from memory into an XMM register.
 *
 *          - **Opcode:** `F3 0F 10 /r`
 *          - `F3`: Mandatory prefix for scalar single-precision operations (SS).
 *
 * @param buf The code buffer.
 * @param dest The destination XMM register.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movss_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = 0;
    if (dest >= XMM8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0xF3);  // Prefix for MOVSS
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x0F);
    emit_byte(buf, 0x10);  // Opcode for MOVAPS/MOVSS (prefix determines which)
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `movss [r64 + offset], xmm` instruction.
 * @details Stores a 32-bit single-precision float from an XMM register to memory.
 *
 *          - **Opcode:** `F3 0F 11 /r`
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 * @param src The source XMM register.
 */
void emit_movss_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0xF3);
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x0F);
    emit_byte(buf, 0x11);  // Opcode for MOVSS r/m, xmm
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `movsd xmm, [r64 + offset]` instruction.
 * @details Loads a 64-bit double-precision float from memory into an XMM register.
 *
 *          - **Opcode:** `F2 0F 10 /r`
 *          - `F2`: Mandatory prefix for scalar double-precision operations (SD).
 *
 * @param buf The code buffer.
 * @param dest The destination XMM register.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movsd_xmm_mem(code_buffer * buf, x64_xmm dest, x64_gpr src_base, int32_t offset) {
    /*
     * Instruction Breakdown: MOVSD xmm, m64
     * --------------------------------------
     * Opcode format: F2 + [REX] + 0F 10 /r
     * - F2: Mandatory prefix for scalar double-precision (SD) SSE instructions.
     * - REX: Optional, used to access XMM8-XMM15 or R8-R15.
     * - 0F 10: The two-byte opcode for MOVSD (load).
     * - /r: A ModR/M byte follows.
     */
    uint8_t rex = 0;
    if (dest >= XMM8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0xF2);  // Prefix for MOVSD
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x0F);
    emit_byte(buf, 0x10);
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `movsxd r64, [r/m32]` instruction.
 * @details Loads a 32-bit value from memory, sign-extends it to 64 bits,
 *          and places it in a GPR. This is essential for correctly passing
 *          signed 32-bit integers in both Windows and System V ABIs.
 *
 *          - **Opcode:** `REX.W + 63 /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 */
void emit_movsxd_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = REX_W;  // REX.W is required for this instruction.
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x63);  // Opcode for MOVSXD
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `movsx r64, r/m8` instruction.
 * @details Loads a signed 8-bit value from memory, sign-extends it to 64 bits,
 *          and places it in a GPR. This is used for promoting `signed char` and
 *          `char` in variadic calls.
 *
 *          - **Opcode:** `REX.W + 0F BE /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movsx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xBE);  // Opcode for MOVSX r, r/m8
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

/**
 * @brief Emits an x86-64 `movsx r64, r/m16` instruction.
 * @details Loads a signed 16-bit value from memory, sign-extends it to 64 bits,
 *          and places it in a GPR. This is used for promoting `signed short`
 *          in variadic calls.
 *
 *          - **Opcode:** `REX.W + 0F BF /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movsx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xBF);  // Opcode for MOVSX r, r/m16
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

/**
 * @brief Emits an x86-64 `movq xmm, r64` instruction.
 * @details This instruction copies 64 bits of data from a GPR to the lower
 *          64 bits of an XMM register. The upper 64 bits of the XMM are zeroed.
 *
 *          - **Opcode:** `66 + REX.W + 0F 6E /r`
 *
 * @param buf The code buffer.
 * @param dest The destination XMM register.
 * @param src The source GPR.
 */
void emit_movq_xmm_gpr(code_buffer * buf, x64_xmm dest, x64_gpr src) {
    emit_byte(buf, 0x66);  // Operand-size override prefix.

    // REX prefix: W=1 for 64-bit GPR, R extends dest, B extends src.
    emit_rex_prefix(buf, 1, dest >= XMM8_REG, 0, src >= R8_REG);

    EMIT_BYTES(buf, 0x0f, 0x6e);  // Opcode for MOVQ xmm, r/m64

    // ModR/M byte: mod=11 (register), reg=dest, rm=src
    emit_modrm(buf, 3, dest % 8, src % 8);
}

/**
 * @brief Emits an x86-64 `movsd [r64 + offset], xmm` instruction.
 * @details Stores a 64-bit double-precision float from an XMM register to memory.
 *
 *          - **Opcode:** `F2 0F 11 /r`
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 * @param src The source XMM register.
 */
void emit_movsd_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0xF2);  // Prefix for MOVSD
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x0F);
    emit_byte(buf, 0x11);  // Opcode for MOVSD r/m, xmm
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `movq r64, xmm` instruction.
 * @details This instruction copies the lower 64 bits of an XMM register
 *          into a general-purpose register.
 *
 *          - **Opcode:** `66 + REX.W + 0F 7E /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src The source XMM register.
 */
void emit_movq_gpr_xmm(code_buffer * buf, x64_gpr dest, x64_xmm src) {
    emit_byte(buf, 0x66);
    emit_rex_prefix(buf, 1, src >= XMM8_REG, 0, dest >= R8_REG);
    EMIT_BYTES(buf, 0x0f, 0x7e);
    emit_modrm(buf, 3, src % 8, dest % 8);
}

/**
 * @brief Emits an x86-64 `movzx r64, r/m8` instruction.
 * @details Loads an unsigned 8-bit value from memory, zero-extends it to 64 bits,
 *          and places it in a GPR. This is the correct way to promote `unsigned char`
 *          and `bool` arguments.
 *
 *          - **Opcode:** `REX.W + 0F B6 /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movzx_reg64_mem8(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xB6);  // Opcode for MOVZX r, r/m8
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

/**
 * @brief Emits an x86-64 `movzx r64, r/m16` instruction.
 * @details Loads an unsigned 16-bit value from memory, zero-extends it to 64 bits,
 *          and places it in a GPR. This is the correct way to promote `unsigned short`.
 *
 *          - **Opcode:** `REX.W + 0F B7 /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_movzx_reg64_mem16(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    emit_rex_prefix(buf, 1, dest >= R8_REG, 0, src_base >= R8_REG);
    EMIT_BYTES(buf, 0x0F, 0xB7);  // Opcode for MOVZX r, r/m16
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

/**
 * @brief Emits an x86-64 `movups [r64 + offset], xmm` instruction.
 * @details Stores a 128-bit unaligned packed single-precision value from an XMM register to memory.
 *          This is used to save the full state of an XMM register.
 *
 *          - **Opcode:** `0F 11 /r`
 *
 * @param buf The code buffer.
 * @param dest_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 * @param src The source XMM register.
 */
void emit_movups_mem_xmm(code_buffer * buf, x64_gpr dest_base, int32_t offset, x64_xmm src) {
    uint8_t rex = 0;
    if (src >= XMM8_REG)
        rex |= REX_R;
    if (dest_base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x0F);
    emit_byte(buf, 0x11);  // Opcode for MOVUPS r/m, xmm
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (dest_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((src % 8) << 3) | (dest_base % 8));
    if (dest_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `lea r64, [r64 + offset]` instruction.
 * @details Loads the effective address of a memory location into a register.
 *          This is equivalent to `dest = &src_base[offset]` in C, but is
 *          often used as a way to perform addition without modifying flags.
 *
 *          - **Opcode:** `REX.W + 8D /r`
 *
 * @param buf The code buffer.
 * @param dest The destination GPR.
 * @param src_base The base register for the memory address.
 * @param offset The 32-bit signed offset.
 */
void emit_lea_reg_mem(code_buffer * buf, x64_gpr dest, x64_gpr src_base, int32_t offset) {
    uint8_t rex = REX_W;
    if (dest >= R8_REG)
        rex |= REX_R;
    if (src_base >= R8_REG)
        rex |= REX_B;
    emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0x8D);  // Opcode for LEA
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (src_base % 8) != RBP_REG)
        mod = 0x00;
    emit_byte(buf, mod | ((dest % 8) << 3) | (src_base % 8));
    if (src_base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `add r64, imm8` instruction.
 * @details Adds an 8-bit immediate value (sign-extended to 64 bits) to a 64-bit register.
 *
 *          - **Opcode:** `REX.W + 83 /0 ib`
 *          - `/0` means the ModR/M `reg` field is used as an opcode extension (0 for ADD).
 *
 * @param buf The code buffer.
 * @param reg The destination register.
 * @param imm The 8-bit immediate value to add.
 */
void emit_add_reg_imm8(code_buffer * buf, x64_gpr reg, int8_t imm) {
    // REX.W=1 for 64-bit op, REX.B extends 'reg'.
    emit_rex_prefix(buf, 1, 0, 0, (reg >= R8_REG));
    // Opcode for immediate arithmetic operations (ADD, OR, ADC, etc.).
    emit_byte(buf, 0x83);
    // ModR/M: mod=11 (register), reg=0 (for ADD), rm=reg.
    emit_modrm(buf, 3, 0, (reg & 0x7));
    // Append the 1-byte immediate value.
    emit_byte(buf, imm);
}

/**
 * @brief Emits an x86-64 `dec r64` instruction.
 * @details Decrements the value in a 64-bit register by 1.
 *
 *          - **Opcode:** `REX.W + FF /1`
 *
 * @param buf The code buffer.
 * @param reg The register to decrement.
 */
void emit_dec_reg(code_buffer * buf, x64_gpr reg) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0xFF);
    emit_modrm(buf, 3, 1, reg % 8);  // ModR/M reg field is 1 for DEC.
}

/**
 * @brief Emits an x86-64 `mov r64, imm32` instruction.
 * @details Moves a 32-bit immediate value into a 64-bit register. The value is sign-extended to 64 bits.
 *
 *          - **Opcode:** `REX.W + C7 /0 id`
 *
 * @param buf The code buffer.
 * @param reg The destination register.
 * @param imm The 32-bit immediate value.
 */
void emit_mov_reg_imm32(code_buffer * buf, x64_gpr reg, int32_t imm) {
    emit_rex_prefix(buf, 1, 0, 0, reg >= R8_REG);
    emit_byte(buf, 0xC7);
    emit_modrm(buf, 3, 0, reg % 8);  // ModR/M for MOV r/m64, imm32. reg=/0.
    emit_int32(buf, imm);
}

/**
 * @brief Emits an x86-64 `fldt [r64 + offset]` (load long double) instruction.
 * @details Loads an 80-bit extended-precision float from memory onto the top
 *          of the x87 FPU stack (`st(0)`). This is used for `long double` on System V.
 *
 *          - **Opcode:** `DB /5`
 *
 * @param buf The code buffer.
 * @param base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
 */
void emit_fldt_mem(code_buffer * buf, x64_gpr base, int32_t offset) {
    uint8_t rex = 0;
    if (base >= R8_REG)
        rex |= REX_B;
    if (rex)
        emit_byte(buf, 0x40 | rex);
    emit_byte(buf, 0xDB);  // FPU instruction prefix
    uint8_t mod = (offset >= -128 && offset <= 127) ? 0x40 : 0x80;
    if (offset == 0 && (base % 8) != RBP_REG)
        mod = 0x00;
    // The reg field of the ModR/M byte is 5 for this instruction.
    emit_byte(buf, mod | (5 << 3) | (base % 8));
    if (base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 `fstpt [r64 + offset]` (store long double and pop) instruction.
 * @details Stores the 80-bit value from the top of the x87 FPU stack (`st(0)`)
 *          into memory and pops the value from the FPU stack.
 *
 *          - **Opcode:** `DB /7`
 *
 * @param buf The code buffer.
 * @param base The base register for the memory address.
 * @param offset The 32-bit signed offset from the base register.
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
    // The reg field of the ModR/M byte is 7 for this instruction.
    emit_byte(buf, mod | (7 << 3) | (base % 8));
    if (base % 8 == RSP_REG)
        emit_byte(buf, 0x24);
    if (mod == 0x40)
        emit_byte(buf, (uint8_t)offset);
    else if (mod == 0x80)
        emit_int32(buf, offset);
}

/**
 * @brief Emits an x86-64 ModR/M byte.
 * @details The ModR/M byte is a crucial part of many x86 instructions, specifying
 *          the addressing mode. It encodes register operands and memory operands.
 *
 * @param buf The code buffer.
 * @param mod The `mod` field (bits 7-6), specifying register/memory mode.
 *            (e.g., 11=register-direct, 10=reg+32bit_disp, 01=reg+8bit_disp, 00=reg_indirect).
 * @param reg_opcode The `reg/opcode` field (bits 5-3), specifying a register or extending the opcode.
 * @param rm The `r/m` field (bits 2-0), specifying a register or memory operand.
 */
void emit_modrm(code_buffer * buf, uint8_t mod, uint8_t reg_opcode, uint8_t rm) {
    // Construct the byte by shifting the fields into their correct positions
    // and combining them with a bitwise OR.
    uint8_t modrm_byte = (mod << 6) | (reg_opcode << 3) | rm;
    emit_byte(buf, modrm_byte);
}

/**
 * @brief Emits an x86-64 REX prefix byte.
 * @details The REX prefix is a single byte (in the range 0x40-0x4F) used in 64-bit
 *          mode to enable features not available in 32-bit mode.
 *
 * @param buf The code buffer.
 * @param w If true, sets the W bit (bit 3), promoting the operand size to 64 bits.
 * @param r If true, sets the R bit (bit 2), extending the ModR/M `reg` field to access registers R8-R15.
 * @param x If true, sets the X bit (bit 1), extending the SIB `index` field.
 * @param b If true, sets the B bit (bit 0), extending the ModR/M `r/m` field or SIB `base` field.
 */
void emit_rex_prefix(code_buffer * buf, bool w, bool r, bool x, bool b) {
    // The REX prefix base value is 0x40 (binary 01000000).
    uint8_t rex_byte = 0x40;
    if (w)
        rex_byte |= 0x8;
    if (r)
        rex_byte |= 0x4;
    if (x)
        rex_byte |= 0x2;
    if (b)
        rex_byte |= 0x1;
    emit_byte(buf, rex_byte);
}
