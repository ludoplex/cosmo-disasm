/*
 * cosmo_disasm_x86.c - x86/x86-64 Disassembler Implementation
 * 
 * A lightweight x86/x86-64 disassembler adapted from e9studio.
 * Covers the most common instructions in typical binaries.
 * 
 * Based on e9studio's e9disasm_x86.c (GPLv3+), rewritten for cosmo-disasm.
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#include "cosmo_disasm_x86.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================================
 * Disassembler Context
 * ============================================================================ */

struct CosmoX86Disasm {
    int mode;  /* 16, 32, or 64 */
};

/* ============================================================================
 * Register Tables
 * ============================================================================ */

static const char *REG_NAMES[] = {
    [COSMO_X86_REG_NONE] = "",

    /* 64-bit */
    [COSMO_X86_REG_RAX] = "rax", [COSMO_X86_REG_RCX] = "rcx",
    [COSMO_X86_REG_RDX] = "rdx", [COSMO_X86_REG_RBX] = "rbx",
    [COSMO_X86_REG_RSP] = "rsp", [COSMO_X86_REG_RBP] = "rbp",
    [COSMO_X86_REG_RSI] = "rsi", [COSMO_X86_REG_RDI] = "rdi",
    [COSMO_X86_REG_R8]  = "r8",  [COSMO_X86_REG_R9]  = "r9",
    [COSMO_X86_REG_R10] = "r10", [COSMO_X86_REG_R11] = "r11",
    [COSMO_X86_REG_R12] = "r12", [COSMO_X86_REG_R13] = "r13",
    [COSMO_X86_REG_R14] = "r14", [COSMO_X86_REG_R15] = "r15",
    [COSMO_X86_REG_RIP] = "rip",

    /* 32-bit */
    [COSMO_X86_REG_EAX] = "eax", [COSMO_X86_REG_ECX] = "ecx",
    [COSMO_X86_REG_EDX] = "edx", [COSMO_X86_REG_EBX] = "ebx",
    [COSMO_X86_REG_ESP] = "esp", [COSMO_X86_REG_EBP] = "ebp",
    [COSMO_X86_REG_ESI] = "esi", [COSMO_X86_REG_EDI] = "edi",
    [COSMO_X86_REG_R8D] = "r8d", [COSMO_X86_REG_R9D] = "r9d",
    [COSMO_X86_REG_R10D] = "r10d", [COSMO_X86_REG_R11D] = "r11d",
    [COSMO_X86_REG_R12D] = "r12d", [COSMO_X86_REG_R13D] = "r13d",
    [COSMO_X86_REG_R14D] = "r14d", [COSMO_X86_REG_R15D] = "r15d",
    [COSMO_X86_REG_EIP] = "eip",

    /* 16-bit */
    [COSMO_X86_REG_AX] = "ax", [COSMO_X86_REG_CX] = "cx",
    [COSMO_X86_REG_DX] = "dx", [COSMO_X86_REG_BX] = "bx",
    [COSMO_X86_REG_SP] = "sp", [COSMO_X86_REG_BP] = "bp",
    [COSMO_X86_REG_SI] = "si", [COSMO_X86_REG_DI] = "di",

    /* 8-bit */
    [COSMO_X86_REG_AL] = "al", [COSMO_X86_REG_CL] = "cl",
    [COSMO_X86_REG_DL] = "dl", [COSMO_X86_REG_BL] = "bl",
    [COSMO_X86_REG_AH] = "ah", [COSMO_X86_REG_CH] = "ch",
    [COSMO_X86_REG_DH] = "dh", [COSMO_X86_REG_BH] = "bh",
    [COSMO_X86_REG_SPL] = "spl", [COSMO_X86_REG_BPL] = "bpl",
    [COSMO_X86_REG_SIL] = "sil", [COSMO_X86_REG_DIL] = "dil",

    /* Segment */
    [COSMO_X86_REG_CS] = "cs", [COSMO_X86_REG_DS] = "ds",
    [COSMO_X86_REG_ES] = "es", [COSMO_X86_REG_FS] = "fs",
    [COSMO_X86_REG_GS] = "gs", [COSMO_X86_REG_SS] = "ss",

    /* XMM */
    [COSMO_X86_REG_XMM0] = "xmm0", [COSMO_X86_REG_XMM1] = "xmm1",
    [COSMO_X86_REG_XMM2] = "xmm2", [COSMO_X86_REG_XMM3] = "xmm3",
    [COSMO_X86_REG_XMM4] = "xmm4", [COSMO_X86_REG_XMM5] = "xmm5",
    [COSMO_X86_REG_XMM6] = "xmm6", [COSMO_X86_REG_XMM7] = "xmm7",
    [COSMO_X86_REG_XMM8] = "xmm8", [COSMO_X86_REG_XMM9] = "xmm9",
    [COSMO_X86_REG_XMM10] = "xmm10", [COSMO_X86_REG_XMM11] = "xmm11",
    [COSMO_X86_REG_XMM12] = "xmm12", [COSMO_X86_REG_XMM13] = "xmm13",
    [COSMO_X86_REG_XMM14] = "xmm14", [COSMO_X86_REG_XMM15] = "xmm15",
};

/* Register tables for ModR/M decoding */
static const int REG64[] = {
    COSMO_X86_REG_RAX, COSMO_X86_REG_RCX, COSMO_X86_REG_RDX, COSMO_X86_REG_RBX,
    COSMO_X86_REG_RSP, COSMO_X86_REG_RBP, COSMO_X86_REG_RSI, COSMO_X86_REG_RDI,
    COSMO_X86_REG_R8,  COSMO_X86_REG_R9,  COSMO_X86_REG_R10, COSMO_X86_REG_R11,
    COSMO_X86_REG_R12, COSMO_X86_REG_R13, COSMO_X86_REG_R14, COSMO_X86_REG_R15,
};

static const int REG32[] = {
    COSMO_X86_REG_EAX, COSMO_X86_REG_ECX, COSMO_X86_REG_EDX, COSMO_X86_REG_EBX,
    COSMO_X86_REG_ESP, COSMO_X86_REG_EBP, COSMO_X86_REG_ESI, COSMO_X86_REG_EDI,
    COSMO_X86_REG_R8D, COSMO_X86_REG_R9D, COSMO_X86_REG_R10D, COSMO_X86_REG_R11D,
    COSMO_X86_REG_R12D, COSMO_X86_REG_R13D, COSMO_X86_REG_R14D, COSMO_X86_REG_R15D,
};

static const int REG8[] = {
    COSMO_X86_REG_AL, COSMO_X86_REG_CL, COSMO_X86_REG_DL, COSMO_X86_REG_BL,
    COSMO_X86_REG_AH, COSMO_X86_REG_CH, COSMO_X86_REG_DH, COSMO_X86_REG_BH,
};

static const int REG8_REX[] = {
    COSMO_X86_REG_AL, COSMO_X86_REG_CL, COSMO_X86_REG_DL, COSMO_X86_REG_BL,
    COSMO_X86_REG_SPL, COSMO_X86_REG_BPL, COSMO_X86_REG_SIL, COSMO_X86_REG_DIL,
};

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static inline int8_t read_i8(const uint8_t *p) { return (int8_t)p[0]; }

static inline int16_t read_i16(const uint8_t *p) {
    return (int16_t)(p[0] | (p[1] << 8));
}

static inline int32_t read_i32(const uint8_t *p) {
    return (int32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static inline int64_t read_i64(const uint8_t *p) {
    return (int64_t)read_i32(p) | ((int64_t)read_i32(p + 4) << 32);
}

/* Map category from old E9 enum to new CosmoInsnCategory */
static CosmoInsnCategory map_category(int old_cat)
{
    /* Direct mapping since we use similar values */
    return (CosmoInsnCategory)old_cat;
}

/* ============================================================================
 * ModR/M Decoding
 * ============================================================================ */

static int decode_modrm(CosmoX86Disasm *ctx, const uint8_t *code, size_t size,
                        int pos, uint8_t rex, int op_size,
                        CosmoOperand *reg_op, CosmoOperand *rm_op)
{
    if (pos >= (int)size) return -1;

    uint8_t modrm = code[pos++];
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;

    /* REX extensions */
    if (rex & 0x04) reg |= 8;  /* REX.R */
    if (rex & 0x01) rm |= 8;   /* REX.B */

    /* Register operand from reg field */
    if (reg_op) {
        reg_op->type = COSMO_OP_REG;
        reg_op->size = op_size;
        if (op_size == 8) {
            reg_op->reg.reg_id = REG64[reg];
        } else if (op_size == 4) {
            reg_op->reg.reg_id = REG32[reg];
        } else if (op_size == 1) {
            reg_op->reg.reg_id = (rex) ? REG8_REX[reg & 7] : REG8[reg & 7];
        }
        reg_op->reg.name = cosmo_x86_reg_name(reg_op->reg.reg_id);
    }

    /* R/M operand */
    if (!rm_op) return pos;

    if (mod == 3) {
        /* Register direct */
        rm_op->type = COSMO_OP_REG;
        rm_op->size = op_size;
        if (op_size == 8) {
            rm_op->reg.reg_id = REG64[rm];
        } else if (op_size == 4) {
            rm_op->reg.reg_id = REG32[rm];
        } else if (op_size == 1) {
            rm_op->reg.reg_id = (rex) ? REG8_REX[rm & 7] : REG8[rm & 7];
        }
        rm_op->reg.name = cosmo_x86_reg_name(rm_op->reg.reg_id);
    } else {
        /* Memory operand */
        rm_op->type = COSMO_OP_MEM;
        rm_op->size = op_size;
        rm_op->mem.base_reg = -1;
        rm_op->mem.index_reg = -1;
        rm_op->mem.scale = 1;
        rm_op->mem.disp = 0;
        rm_op->mem.segment = -1;

        bool has_sib = (ctx->mode >= 32) && (rm & 7) == 4;
        bool rip_rel = (ctx->mode == 64) && (mod == 0) && (rm & 7) == 5;

        if (has_sib && mod != 3) {
            if (pos >= (int)size) return -1;
            uint8_t sib = code[pos++];
            uint8_t scale = (sib >> 6) & 0x3;
            uint8_t index = (sib >> 3) & 0x7;
            uint8_t base = sib & 0x7;

            if (rex & 0x02) index |= 8;  /* REX.X */
            if (rex & 0x01) base |= 8;   /* REX.B */

            rm_op->mem.scale = 1 << scale;

            if (index != 4) {  /* RSP cannot be index */
                rm_op->mem.index_reg = REG64[index];
            }

            if (mod == 0 && (base & 7) == 5) {
                /* disp32 only */
                rm_op->mem.base_reg = -1;
            } else {
                rm_op->mem.base_reg = REG64[base];
            }

            if (mod == 0 && (base & 7) == 5) {
                if (pos + 4 > (int)size) return -1;
                rm_op->mem.disp = read_i32(&code[pos]);
                pos += 4;
            }
        } else if (rip_rel) {
            rm_op->mem.base_reg = COSMO_X86_REG_RIP;
        } else if (mod == 0 && (rm & 7) == 5) {
            /* 32-bit mode: disp32 */
            rm_op->mem.base_reg = -1;
        } else {
            rm_op->mem.base_reg = REG64[rm];
        }

        /* Displacement */
        if (mod == 1) {
            if (pos >= (int)size) return -1;
            rm_op->mem.disp = read_i8(&code[pos]);
            pos += 1;
        } else if (mod == 2 || (mod == 0 && ((rm & 7) == 5 || rip_rel))) {
            if (pos + 4 > (int)size) return -1;
            rm_op->mem.disp = read_i32(&code[pos]);
            pos += 4;
        }
    }

    return pos;
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

CosmoX86Disasm *cosmo_x86_disasm_create(int mode)
{
    if (mode != 16 && mode != 32 && mode != 64) {
        return NULL;
    }

    CosmoX86Disasm *ctx = calloc(1, sizeof(CosmoX86Disasm));
    if (!ctx) return NULL;

    ctx->mode = mode;
    return ctx;
}

void cosmo_x86_disasm_free(CosmoX86Disasm *ctx)
{
    free(ctx);
}

void cosmo_x86_disasm_set_mode(CosmoX86Disasm *ctx, int mode)
{
    if (ctx && (mode == 16 || mode == 32 || mode == 64)) {
        ctx->mode = mode;
    }
}

const char *cosmo_x86_reg_name(int reg_id)
{
    if (reg_id < 0 || reg_id >= (int)(sizeof(REG_NAMES) / sizeof(REG_NAMES[0]))) {
        return "???";
    }
    return REG_NAMES[reg_id];
}

int cosmo_x86_reg_size(int reg_id)
{
    if (reg_id >= COSMO_X86_REG_RAX && reg_id <= COSMO_X86_REG_RIP) return 8;
    if (reg_id >= COSMO_X86_REG_EAX && reg_id <= COSMO_X86_REG_EIP) return 4;
    if (reg_id >= COSMO_X86_REG_AX && reg_id <= COSMO_X86_REG_DI) return 2;
    if (reg_id >= COSMO_X86_REG_AL && reg_id <= COSMO_X86_REG_DIL) return 1;
    if (reg_id >= COSMO_X86_REG_XMM0 && reg_id <= COSMO_X86_REG_XMM15) return 16;
    return 0;
}

/* Format instruction text */
static void format_insn(CosmoInsn *insn)
{
    char *p = insn->text;
    char *end = insn->text + sizeof(insn->text) - 1;

    /* Prefixes */
    if (insn->has_lock) p += snprintf(p, end - p, "lock ");
    if (insn->has_rep) p += snprintf(p, end - p, "rep ");

    /* Mnemonic */
    p += snprintf(p, end - p, "%s", insn->mnemonic);

    /* Operands */
    for (int i = 0; i < insn->num_operands && p < end; i++) {
        p += snprintf(p, end - p, "%s", (i == 0) ? " " : ", ");

        const CosmoOperand *op = &insn->operands[i];
        switch (op->type) {
            case COSMO_OP_REG:
                p += snprintf(p, end - p, "%s", 
                              op->reg.name ? op->reg.name : cosmo_x86_reg_name(op->reg.reg_id));
                break;

            case COSMO_OP_IMM:
                if (op->imm.value < 0) {
                    p += snprintf(p, end - p, "-0x%llx", (unsigned long long)-op->imm.value);
                } else {
                    p += snprintf(p, end - p, "0x%llx", (unsigned long long)op->imm.value);
                }
                break;

            case COSMO_OP_LABEL:
                p += snprintf(p, end - p, "0x%llx", (unsigned long long)op->label.target);
                break;

            case COSMO_OP_MEM: {
                p += snprintf(p, end - p, "[");
                bool need_plus = false;

                if (op->mem.base_reg >= 0) {
                    p += snprintf(p, end - p, "%s", cosmo_x86_reg_name(op->mem.base_reg));
                    need_plus = true;
                }

                if (op->mem.index_reg >= 0) {
                    if (need_plus) p += snprintf(p, end - p, "+");
                    p += snprintf(p, end - p, "%s", cosmo_x86_reg_name(op->mem.index_reg));
                    if (op->mem.scale > 1) {
                        p += snprintf(p, end - p, "*%d", op->mem.scale);
                    }
                    need_plus = true;
                }

                if (op->mem.disp != 0 || !need_plus) {
                    if (op->mem.disp >= 0) {
                        if (need_plus) p += snprintf(p, end - p, "+");
                        p += snprintf(p, end - p, "0x%llx", (unsigned long long)op->mem.disp);
                    } else {
                        p += snprintf(p, end - p, "-0x%llx", (unsigned long long)-op->mem.disp);
                    }
                }

                p += snprintf(p, end - p, "]");
                break;
            }

            default:
                break;
        }
    }

    *p = '\0';
}

/* ============================================================================
 * Main Disassembly Function
 * ============================================================================ */

int cosmo_x86_disasm_one(CosmoX86Disasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address, CosmoInsn *insn)
{
    if (!ctx || !code || size == 0 || !insn) return 0;

    memset(insn, 0, sizeof(*insn));
    insn->address = address;
    insn->arch = (ctx->mode == 64) ? COSMO_ARCH_X86_64 : COSMO_ARCH_X86_32;

    int pos = 0;
    uint8_t rex = 0;
    bool has_66 = false;
    bool has_67 = false;
    int seg_override = -1;

    /* Parse prefixes */
    while (pos < (int)size) {
        uint8_t b = code[pos];

        if (b == 0xF0) { insn->has_lock = true; pos++; }
        else if (b == 0xF2) { pos++; }  /* REPNE */
        else if (b == 0xF3) { insn->has_rep = true; pos++; }
        else if (b == 0x2E) { seg_override = COSMO_X86_REG_CS; pos++; }
        else if (b == 0x36) { seg_override = COSMO_X86_REG_SS; pos++; }
        else if (b == 0x3E) { seg_override = COSMO_X86_REG_DS; pos++; }
        else if (b == 0x26) { seg_override = COSMO_X86_REG_ES; pos++; }
        else if (b == 0x64) { seg_override = COSMO_X86_REG_FS; pos++; }
        else if (b == 0x65) { seg_override = COSMO_X86_REG_GS; pos++; }
        else if (b == 0x66) { has_66 = true; pos++; }
        else if (b == 0x67) { has_67 = true; pos++; }
        else if (ctx->mode == 64 && (b >= 0x40 && b <= 0x4F)) {
            rex = b;
            insn->has_rex = true;
            insn->rex = rex;
            pos++;
        }
        else break;
    }

    if (pos >= (int)size) goto invalid;

    /* Determine operand size */
    int op_size = (ctx->mode == 64) ? 4 : ctx->mode / 8;
    if (rex & 0x08) op_size = 8;  /* REX.W */
    if (has_66) op_size = (op_size == 4) ? 2 : 4;

    (void)has_67;
    (void)seg_override;

    /* Decode opcode */
    uint8_t op = code[pos++];

    /* Single-byte opcodes */
    switch (op) {
        /* NOP */
        case 0x90:
            strcpy(insn->mnemonic, "nop");
            insn->category = COSMO_CAT_NOP;
            break;

        /* PUSH reg */
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
            strcpy(insn->mnemonic, "push");
            insn->category = COSMO_CAT_STACK;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].size = (ctx->mode == 64) ? 8 : 4;
            insn->operands[0].reg.reg_id = (ctx->mode == 64) ?
                REG64[(op - 0x50) | ((rex & 1) << 3)] :
                REG32[op - 0x50];
            insn->operands[0].reg.name = cosmo_x86_reg_name(insn->operands[0].reg.reg_id);
            break;

        /* POP reg */
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            strcpy(insn->mnemonic, "pop");
            insn->category = COSMO_CAT_STACK;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].size = (ctx->mode == 64) ? 8 : 4;
            insn->operands[0].reg.reg_id = (ctx->mode == 64) ?
                REG64[(op - 0x58) | ((rex & 1) << 3)] :
                REG32[op - 0x58];
            insn->operands[0].reg.name = cosmo_x86_reg_name(insn->operands[0].reg.reg_id);
            break;

        /* MOV r, imm (B8-BF) */
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            strcpy(insn->mnemonic, "mov");
            insn->category = COSMO_CAT_DATA_XFER;
            insn->num_operands = 2;
            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].size = op_size;
            if (op_size == 8) {
                insn->operands[0].reg.reg_id = REG64[(op - 0xB8) | ((rex & 1) << 3)];
                if (pos + 8 > (int)size) goto invalid;
                insn->operands[1].type = COSMO_OP_IMM;
                insn->operands[1].size = 8;
                insn->operands[1].imm.value = read_i64(&code[pos]);
                pos += 8;
            } else {
                insn->operands[0].reg.reg_id = REG32[(op - 0xB8) | ((rex & 1) << 3)];
                if (pos + 4 > (int)size) goto invalid;
                insn->operands[1].type = COSMO_OP_IMM;
                insn->operands[1].size = 4;
                insn->operands[1].imm.value = read_i32(&code[pos]);
                pos += 4;
            }
            insn->operands[0].reg.name = cosmo_x86_reg_name(insn->operands[0].reg.reg_id);
            break;

        /* RET */
        case 0xC3:
            strcpy(insn->mnemonic, "ret");
            insn->category = COSMO_CAT_RETURN;
            insn->is_return = true;
            insn->is_branch = true;
            break;

        /* LEAVE */
        case 0xC9:
            strcpy(insn->mnemonic, "leave");
            insn->category = COSMO_CAT_STACK;
            break;

        /* CALL rel32 */
        case 0xE8:
            strcpy(insn->mnemonic, "call");
            insn->category = COSMO_CAT_CALL;
            insn->is_call = true;
            insn->is_branch = true;
            if (pos + 4 > (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_LABEL;
            insn->operands[0].label.offset = read_i32(&code[pos]);
            pos += 4;
            insn->operands[0].label.target = address + pos + insn->operands[0].label.offset;
            insn->branch_target = insn->operands[0].label.target;
            break;

        /* JMP rel32 */
        case 0xE9:
            strcpy(insn->mnemonic, "jmp");
            insn->category = COSMO_CAT_BRANCH;
            insn->is_branch = true;
            if (pos + 4 > (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_LABEL;
            insn->operands[0].label.offset = read_i32(&code[pos]);
            pos += 4;
            insn->operands[0].label.target = address + pos + insn->operands[0].label.offset;
            insn->branch_target = insn->operands[0].label.target;
            break;

        /* JMP rel8 */
        case 0xEB:
            strcpy(insn->mnemonic, "jmp");
            insn->category = COSMO_CAT_BRANCH;
            insn->is_branch = true;
            if (pos >= (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_LABEL;
            insn->operands[0].label.offset = read_i8(&code[pos]);
            pos += 1;
            insn->operands[0].label.target = address + pos + insn->operands[0].label.offset;
            insn->branch_target = insn->operands[0].label.target;
            break;

        /* Jcc rel8 (70-7F) */
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            static const char *jcc_names[] = {
                "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            strcpy(insn->mnemonic, jcc_names[op - 0x70]);
            insn->category = COSMO_CAT_BRANCH;
            insn->is_branch = true;
            insn->is_conditional = true;
            if (pos >= (int)size) goto invalid;
            insn->num_operands = 1;
            insn->operands[0].type = COSMO_OP_LABEL;
            insn->operands[0].label.offset = read_i8(&code[pos]);
            pos += 1;
            insn->operands[0].label.target = address + pos + insn->operands[0].label.offset;
            insn->branch_target = insn->operands[0].label.target;
            break;
        }

        /* Two-byte opcodes (0F xx) */
        case 0x0F: {
            if (pos >= (int)size) goto invalid;
            uint8_t op2 = code[pos++];

            /* Jcc rel32 (0F 80 - 0F 8F) */
            if (op2 >= 0x80 && op2 <= 0x8F) {
                static const char *jcc_names[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                };
                strcpy(insn->mnemonic, jcc_names[op2 - 0x80]);
                insn->category = COSMO_CAT_BRANCH;
                insn->is_branch = true;
                insn->is_conditional = true;
                if (pos + 4 > (int)size) goto invalid;
                insn->num_operands = 1;
                insn->operands[0].type = COSMO_OP_LABEL;
                insn->operands[0].label.offset = read_i32(&code[pos]);
                pos += 4;
                insn->operands[0].label.target = address + pos + insn->operands[0].label.offset;
                insn->branch_target = insn->operands[0].label.target;
            }
            /* SYSCALL */
            else if (op2 == 0x05) {
                strcpy(insn->mnemonic, "syscall");
                insn->category = COSMO_CAT_SYSTEM;
            }
            /* SYSRET */
            else if (op2 == 0x07) {
                strcpy(insn->mnemonic, "sysret");
                insn->category = COSMO_CAT_SYSTEM;
            }
            /* CPUID */
            else if (op2 == 0xA2) {
                strcpy(insn->mnemonic, "cpuid");
                insn->category = COSMO_CAT_SYSTEM;
            }
            /* NOP (multi-byte) */
            else if (op2 == 0x1F) {
                strcpy(insn->mnemonic, "nop");
                insn->category = COSMO_CAT_NOP;
                pos = decode_modrm(ctx, code, size, pos, rex, op_size, NULL, NULL);
                if (pos < 0) goto invalid;
            }
            else {
                snprintf(insn->mnemonic, sizeof(insn->mnemonic), "0f %02x", op2);
                insn->category = COSMO_CAT_OTHER;
            }
            break;
        }

        /* MOV r/m, r (89) */
        case 0x89:
            strcpy(insn->mnemonic, "mov");
            insn->category = COSMO_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            if (insn->operands[0].type == COSMO_OP_MEM) {
                insn->writes_memory = true;
            }
            break;

        /* MOV r, r/m (8B) */
        case 0x8B:
            strcpy(insn->mnemonic, "mov");
            insn->category = COSMO_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[0], &insn->operands[1]);
            if (pos < 0) goto invalid;
            if (insn->operands[1].type == COSMO_OP_MEM) {
                insn->reads_memory = true;
            }
            break;

        /* LEA r, m (8D) */
        case 0x8D:
            strcpy(insn->mnemonic, "lea");
            insn->category = COSMO_CAT_DATA_XFER;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[0], &insn->operands[1]);
            if (pos < 0) goto invalid;
            break;

        /* XOR r/m, r (31) */
        case 0x31:
            strcpy(insn->mnemonic, "xor");
            insn->category = COSMO_CAT_LOGICAL;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm (83) */
        case 0x83: {
            if (pos >= (int)size) goto invalid;
            uint8_t modrm = code[pos];
            uint8_t op_ext = (modrm >> 3) & 7;
            static const char *grp1[] = {
                "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
            };
            strcpy(insn->mnemonic, grp1[op_ext]);
            insn->category = (op_ext == 7) ? COSMO_CAT_COMPARE :
                             (op_ext < 2 || op_ext == 4 || op_ext == 6) ?
                             COSMO_CAT_LOGICAL : COSMO_CAT_ARITHMETIC;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               NULL, &insn->operands[0]);
            if (pos < 0 || pos >= (int)size) goto invalid;
            insn->operands[1].type = COSMO_OP_IMM;
            insn->operands[1].size = 1;
            insn->operands[1].imm.value = read_i8(&code[pos]);
            insn->operands[1].imm.is_signed = true;
            pos += 1;
            break;
        }

        /* TEST r/m, r (85) */
        case 0x85:
            strcpy(insn->mnemonic, "test");
            insn->category = COSMO_CAT_COMPARE;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* CMP r/m, r (39) */
        case 0x39:
            strcpy(insn->mnemonic, "cmp");
            insn->category = COSMO_CAT_COMPARE;
            insn->num_operands = 2;
            pos = decode_modrm(ctx, code, size, pos, rex, op_size,
                               &insn->operands[1], &insn->operands[0]);
            if (pos < 0) goto invalid;
            break;

        /* INT 3 */
        case 0xCC:
            strcpy(insn->mnemonic, "int3");
            insn->category = COSMO_CAT_SYSTEM;
            break;

        /* HLT */
        case 0xF4:
            strcpy(insn->mnemonic, "hlt");
            insn->category = COSMO_CAT_SYSTEM;
            break;

        /* Default: unknown opcode */
        default:
            snprintf(insn->mnemonic, sizeof(insn->mnemonic), "db 0x%02x", op);
            insn->category = COSMO_CAT_OTHER;
            break;
    }

    /* Set length and copy bytes */
    insn->length = pos;
    memcpy(insn->bytes, code, (pos > COSMO_MAX_INSN_LEN) ? COSMO_MAX_INSN_LEN : pos);

    /* Format text */
    format_insn(insn);

    return pos;

invalid:
    insn->length = 1;
    insn->bytes[0] = code[0];
    strcpy(insn->mnemonic, "(bad)");
    insn->category = COSMO_CAT_INVALID;
    snprintf(insn->text, sizeof(insn->text), "(bad)");
    return 1;
}

/* ============================================================================
 * Pattern Recognition
 * ============================================================================ */

bool cosmo_x86_is_prologue(const uint8_t *code, size_t size)
{
    if (size < 1) return false;

    /* push rbp; mov rbp, rsp */
    if (size >= 4 && code[0] == 0x55 &&
        code[1] == 0x48 && code[2] == 0x89 && code[3] == 0xE5) {
        return true;
    }

    /* push rbp (might be followed by other setup) */
    if (code[0] == 0x55) return true;

    /* endbr64 (CET) followed by push */
    if (size >= 5 && code[0] == 0xF3 && code[1] == 0x0F &&
        code[2] == 0x1E && code[3] == 0xFA && code[4] == 0x55) {
        return true;
    }

    return false;
}

bool cosmo_x86_is_epilogue(const uint8_t *code, size_t size)
{
    if (size < 1) return false;

    /* ret */
    if (code[0] == 0xC3) return true;

    /* leave; ret */
    if (size >= 2 && code[0] == 0xC9 && code[1] == 0xC3) return true;

    /* pop rbp; ret */
    if (size >= 2 && code[0] == 0x5D && code[1] == 0xC3) return true;

    return false;
}

int cosmo_x86_insn_length(const uint8_t *code, size_t size, int mode)
{
    CosmoX86Disasm *ctx = cosmo_x86_disasm_create(mode);
    if (!ctx) return 0;

    CosmoInsn insn;
    int len = cosmo_x86_disasm_one(ctx, code, size, 0, &insn);

    cosmo_x86_disasm_free(ctx);
    return len;
}
