/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use the code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 */
/**
 * @file emit_math.c
 * @brief Math operations for JIT code generation (x86-64 and ARM64).
 */
#include "emit/emit_math.h"
#include "emit/emit.h"
#include "emit_internals.h"
#include <stdio.h>
#include <string.h>

#define EMIT_REG_NEEDS_REX(reg) ((reg) >= 8)

static void emit_x86_rex(emit_context_t * ctx, bool w, bool r, bool x, bool b) {
    (void)ctx;
    if (ctx->arch == EMIT_ARCH_X86_64 && (w || r || x || b)) {
        uint8_t rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
        (void)emit_emit_u8(ctx, rex);
    }
}

static infix_status _emit_emit_u8(emit_context_t * ctx, uint8_t byte) { return emit_emit_u8(ctx, byte); }

INFIX_API infix_status emit_math_mov_imm(emit_context_t * ctx, emit_register_t dest, uint64_t imm) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0xB8 | (dest & 0x07));
        (void)emit_emit_u64(ctx, imm);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_mov_reg(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) return INFIX_ERROR_INVALID_ARGUMENT;

    if (ctx->arch == EMIT_ARCH_X86_64) {
        /* mov r64, r64 -> Opcode 0x89 with ModRM bits 11 (register mode) */
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)emit_emit_u8(ctx, 0x89);
        (void)emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}
INFIX_API infix_status emit_math_add(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x01);
        (void)_emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_add_imm(emit_context_t * ctx, emit_register_t dest, int32_t imm) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x81);
        (void)_emit_emit_u8(ctx, 0xC0 | (dest & 0x07));
        (void)emit_emit_u32(ctx, (uint32_t)imm);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_sub(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x29);
        (void)_emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_sub_imm(emit_context_t * ctx, emit_register_t dest, int32_t imm) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x81);
        (void)_emit_emit_u8(ctx, 0xE8 | (dest & 0x07));
        (void)emit_emit_u32(ctx, (uint32_t)imm);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_mul(emit_context_t * ctx, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(src));
        (void)_emit_emit_u8(ctx, 0xF7);
        (void)_emit_emit_u8(ctx, 0xE0 | (src & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_imul_imm(emit_context_t * ctx, emit_register_t dest, int32_t imm) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(dest), false, EMIT_REG_NEEDS_REX(dest));
        if (imm >= -128 && imm <= 127) {
            (void)_emit_emit_u8(ctx, 0x6B);
            (void)_emit_emit_u8(ctx, 0xC0 | ((dest & 0x07) << 3) | (dest & 0x07));
            (void)_emit_emit_u8(ctx, (uint8_t)imm);
        } else {
            (void)_emit_emit_u8(ctx, 0x69);
            (void)_emit_emit_u8(ctx, 0xC0 | ((dest & 0x07) << 3) | (dest & 0x07));
            (void)emit_emit_u32(ctx, (uint32_t)imm);
        }
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_and(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x21);
        (void)_emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_or(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x09);
        (void)_emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_xor(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0x31);
        (void)_emit_emit_u8(ctx, 0xC0 | ((src & 0x07) << 3) | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_not(emit_context_t * ctx, emit_register_t reg) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
        (void)_emit_emit_u8(ctx, 0xF7);
        (void)_emit_emit_u8(ctx, 0xD0 | (reg & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_neg(emit_context_t * ctx, emit_register_t reg) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
        (void)_emit_emit_u8(ctx, 0xF7);
        (void)_emit_emit_u8(ctx, 0xD8 | (reg & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_shl(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        if (src != EMIT_REG_RCX) return INFIX_ERROR_INVALID_ARGUMENT;
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0xD3);
        (void)_emit_emit_u8(ctx, 0xE0 | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_shr(emit_context_t * ctx, emit_register_t dest, emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        if (src != EMIT_REG_RCX) return INFIX_ERROR_INVALID_ARGUMENT;
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(dest));
        (void)_emit_emit_u8(ctx, 0xD3);
        (void)_emit_emit_u8(ctx, 0xE8 | (dest & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_sal(emit_context_t * ctx, emit_register_t reg, uint8_t amount) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        if (amount == 1) {
            emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
            (void)_emit_emit_u8(ctx, 0xD1);
            (void)_emit_emit_u8(ctx, 0xE0 | (reg & 0x07));
        }
        else {
            emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
            (void)_emit_emit_u8(ctx, 0xC1);
            (void)_emit_emit_u8(ctx, 0xE0 | (reg & 0x07));
            (void)_emit_emit_u8(ctx, amount);
        }
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_sar(emit_context_t * ctx, emit_register_t reg, uint8_t amount) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        if (amount == 1) {
            emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
            (void)_emit_emit_u8(ctx, 0xD1);
            (void)_emit_emit_u8(ctx, 0xF8 | (reg & 0x07));
        }
        else {
            emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
            (void)_emit_emit_u8(ctx, 0xC1);
            (void)_emit_emit_u8(ctx, 0xF8 | (reg & 0x07));
            (void)_emit_emit_u8(ctx, amount);
        }
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_cmp(emit_context_t * ctx, emit_register_t a, emit_register_t b) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(b), false, EMIT_REG_NEEDS_REX(a));
        (void)_emit_emit_u8(ctx, 0x39);
        (void)_emit_emit_u8(ctx, 0xC0 | ((b & 0x07) << 3) | (a & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_cmp_imm(emit_context_t * ctx, emit_register_t reg, int32_t imm) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, false, false, EMIT_REG_NEEDS_REX(reg));
        (void)_emit_emit_u8(ctx, 0x81);
        (void)_emit_emit_u8(ctx, 0xF8 | (reg & 0x07));
        (void)emit_emit_u32(ctx, (uint32_t)imm);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_test(emit_context_t * ctx, emit_register_t a, emit_register_t b) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(b), false, EMIT_REG_NEEDS_REX(a));
        (void)_emit_emit_u8(ctx, 0x85);
        (void)_emit_emit_u8(ctx, 0xC0 | ((b & 0x07) << 3) | (a & 0x07));
    }
    return INFIX_SUCCESS;
}

static const uint8_t x86_jcc_opcodes[16] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F
};

INFIX_API infix_status emit_math_jmp(emit_context_t * ctx, const char * label) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint64_t jump_offset = ctx->current_section->size;
        (void)_emit_emit_u8(ctx, 0xE9);
        (void)emit_emit_u32(ctx, 0);
        (void)emit_add_relocation(ctx, label, jump_offset + 1, 4, 5);
    }
    return INFIX_SUCCESS;
}


INFIX_API infix_status emit_math_jmp_cc(emit_context_t * ctx, emit_cc_t cc, const char * label) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint64_t jump_offset = ctx->current_section->size;
        (void)_emit_emit_u8(ctx, 0x0F);
        (void)_emit_emit_u8(ctx, x86_jcc_opcodes[cc]);
        (void)emit_emit_u32(ctx, 0); /* Placeholder for 32-bit displacement */
        (void)emit_add_relocation(ctx, label, jump_offset + 2, 4, 6);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_call(emit_context_t * ctx, const char * name) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint64_t call_offset = ctx->current_section->size;
        (void)_emit_emit_u8(ctx, 0xE8);
        (void)emit_emit_u32(ctx, 0);
        (void)emit_add_relocation(ctx, name, call_offset + 1, 4, 5);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_prologue(emit_context_t * ctx) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        (void)_emit_emit_u8(ctx, 0x55);
        (void)_emit_emit_u8(ctx, 0x48);
        (void)_emit_emit_u8(ctx, 0x8B);
        (void)_emit_emit_u8(ctx, 0xEC);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_epilogue(emit_context_t * ctx) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        (void)_emit_emit_u8(ctx, 0xC9);
        (void)_emit_emit_u8(ctx, 0xC3);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_ret(emit_context_t * ctx) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64)
        (void)_emit_emit_u8(ctx, 0xC3);
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_push(emit_context_t * ctx, emit_register_t reg) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, false, false, false, EMIT_REG_NEEDS_REX(reg));
        (void)_emit_emit_u8(ctx, 0x50 | (reg & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_pop(emit_context_t * ctx, emit_register_t reg) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        emit_x86_rex(ctx, false, false, false, EMIT_REG_NEEDS_REX(reg));
        (void)_emit_emit_u8(ctx, 0x58 | (reg & 0x07));
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_load_reg(emit_context_t * ctx,
                                          emit_register_t dest,
                                          emit_register_t base,
                                          int32_t offset) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint8_t mod;
        if (offset == 0 && (base & 0x07) != 5) {
            mod = 0x00;
        } else if (offset >= -128 && offset <= 127) {
            mod = 0x40;
        } else {
            mod = 0x80;
        }

        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(dest), false, EMIT_REG_NEEDS_REX(base));
        (void)_emit_emit_u8(ctx, 0x8B);
        (void)_emit_emit_u8(ctx, mod | ((dest & 0x07) << 3) | (base & 0x07));
        if ((base & 0x07) == 4) {
            (void)_emit_emit_u8(ctx, 0x24);
        }

        if (mod == 0x40) {
            (void)_emit_emit_u8(ctx, (uint8_t)offset);
        } else if (mod == 0x80) {
            (void)emit_emit_u32(ctx, (uint32_t)offset);
        }
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_store_reg(emit_context_t * ctx,
                                           emit_register_t base,
                                           int32_t offset,
                                           emit_register_t src) {
    _infix_clear_error();
    if (!ctx) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint8_t mod;
        if (offset == 0 && (base & 0x07) != 5) {
            mod = 0x00;
        } else if (offset >= -128 && offset <= 127) {
            mod = 0x40;
        } else {
            mod = 0x80;
        }

        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, EMIT_REG_NEEDS_REX(base));
        (void)_emit_emit_u8(ctx, 0x89);
        (void)_emit_emit_u8(ctx, mod | ((src & 0x07) << 3) | (base & 0x07));
        if ((base & 0x07) == 4) {
            (void)_emit_emit_u8(ctx, 0x24);
        }

        if (mod == 0x40) {
            (void)_emit_emit_u8(ctx, (uint8_t)offset);
        } else if (mod == 0x80) {
            (void)emit_emit_u32(ctx, (uint32_t)offset);
        }
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_load_sym(emit_context_t * ctx, emit_register_t dest, const char * sym) {
    _infix_clear_error();
    if (!ctx || !sym) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint64_t load_offset = ctx->current_section->size;
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(dest), false, false);
        (void)_emit_emit_u8(ctx, 0x8B);
        (void)_emit_emit_u8(ctx, 0x05 | ((dest & 0x07) << 3));
        (void)emit_emit_u32(ctx, 0);
        (void)emit_add_relocation(ctx, sym, load_offset + 3, 4, 7);
    }
    return INFIX_SUCCESS;
}

INFIX_API infix_status emit_math_store_sym(emit_context_t * ctx, const char * sym, emit_register_t src) {
    _infix_clear_error();
    if (!ctx || !sym) {
        _infix_set_error(INFIX_CATEGORY_PARSER, INFIX_CODE_INVALID_KEYWORD, 0);
        return INFIX_ERROR_INVALID_ARGUMENT;
    }

    if (ctx->arch == EMIT_ARCH_X86_64) {
        uint64_t store_offset = ctx->current_section->size;
        emit_x86_rex(ctx, true, EMIT_REG_NEEDS_REX(src), false, false);
        (void)_emit_emit_u8(ctx, 0x89);
        (void)_emit_emit_u8(ctx, 0x05 | ((src & 0x07) << 3));
        (void)emit_emit_u32(ctx, 0);
        (void)emit_add_relocation(ctx, sym, store_offset + 3, 4, 7);
    }
    return INFIX_SUCCESS;
}
