/*
 * cosmo_disasm_arm64.c - AArch64 Disassembler Implementation
 * 
 * A lightweight AArch64 disassembler adapted from e9studio.
 * Covers the most common instructions in typical binaries.
 * 
 * Based on e9studio's e9disasm_arm64.c (GPLv3+), rewritten for cosmo-disasm.
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#include "cosmo_disasm_arm64.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================================================
 * Disassembler Context
 * ============================================================================ */

struct CosmoA64Disasm {
    int dummy;  /* Placeholder for future state */
};

/* ============================================================================
 * Register Tables
 * ============================================================================ */

static const char *REG_NAMES_X[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "sp"
};

static const char *REG_NAMES_W[] = {
    "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
    "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
    "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
    "w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr", "wsp"
};

static const char *COND_NAMES[] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
};

static const char *SHIFT_NAMES[] = { "lsl", "lsr", "asr", "ror" };

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static inline uint32_t read_insn(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline int64_t sign_extend(uint64_t val, int bits)
{
    int64_t sign_bit = 1LL << (bits - 1);
    return (int64_t)((val ^ sign_bit) - sign_bit);
}

#define BITS(insn, hi, lo) (((insn) >> (lo)) & ((1 << ((hi) - (lo) + 1)) - 1))
#define BIT(insn, n) (((insn) >> (n)) & 1)

/* Decode register with size selection */
static int decode_reg(uint32_t num, bool is_64bit, bool is_sp)
{
    if (num == 31) {
        if (is_sp) {
            return is_64bit ? COSMO_A64_REG_SP : COSMO_A64_REG_WSP;
        }
        return is_64bit ? COSMO_A64_REG_XZR : COSMO_A64_REG_WZR;
    }
    return is_64bit ? (COSMO_A64_REG_X0 + num) : (COSMO_A64_REG_W0 + num);
}

/* ============================================================================
 * API Implementation
 * ============================================================================ */

CosmoA64Disasm *cosmo_a64_disasm_create(void)
{
    CosmoA64Disasm *ctx = calloc(1, sizeof(CosmoA64Disasm));
    return ctx;
}

void cosmo_a64_disasm_free(CosmoA64Disasm *ctx)
{
    free(ctx);
}

const char *cosmo_a64_reg_name(int reg_id)
{
    if (reg_id >= COSMO_A64_REG_X0 && reg_id <= COSMO_A64_REG_SP) {
        return REG_NAMES_X[reg_id - COSMO_A64_REG_X0];
    }
    if (reg_id >= COSMO_A64_REG_W0 && reg_id <= COSMO_A64_REG_WSP) {
        return REG_NAMES_W[reg_id - COSMO_A64_REG_W0];
    }
    return "???";
}

int cosmo_a64_reg_size(int reg_id)
{
    if (reg_id >= COSMO_A64_REG_X0 && reg_id <= COSMO_A64_REG_SP) return 8;
    if (reg_id >= COSMO_A64_REG_W0 && reg_id <= COSMO_A64_REG_WSP) return 4;
    return 0;
}

/* Format instruction text */
static void format_insn(CosmoInsn *insn)
{
    char *p = insn->text;
    char *end = insn->text + sizeof(insn->text) - 1;

    /* Mnemonic */
    p += snprintf(p, end - p, "%s", insn->mnemonic);

    /* Operands */
    for (int i = 0; i < insn->num_operands && p < end; i++) {
        p += snprintf(p, end - p, "%s", (i == 0) ? " " : ", ");

        const CosmoOperand *op = &insn->operands[i];
        switch (op->type) {
            case COSMO_OP_REG:
                p += snprintf(p, end - p, "%s",
                              op->reg.name ? op->reg.name : cosmo_a64_reg_name(op->reg.reg_id));
                break;

            case COSMO_OP_IMM:
                if (op->imm.value < 0) {
                    p += snprintf(p, end - p, "#-0x%llx",
                                  (unsigned long long)-op->imm.value);
                } else {
                    p += snprintf(p, end - p, "#0x%llx",
                                  (unsigned long long)op->imm.value);
                }
                break;

            case COSMO_OP_LABEL:
                p += snprintf(p, end - p, "0x%llx",
                              (unsigned long long)op->label.target);
                break;

            case COSMO_OP_MEM:
                p += snprintf(p, end - p, "[%s",
                              cosmo_a64_reg_name(op->mem.base_reg));
                if (op->mem.disp != 0) {
                    if (op->mem.disp > 0) {
                        p += snprintf(p, end - p, ", #0x%llx",
                                      (unsigned long long)op->mem.disp);
                    } else {
                        p += snprintf(p, end - p, ", #-0x%llx",
                                      (unsigned long long)-op->mem.disp);
                    }
                }
                p += snprintf(p, end - p, "]");
                break;

            default:
                break;
        }
    }

    *p = '\0';
}

/* ============================================================================
 * Main Disassembly Function
 * ============================================================================ */

int cosmo_a64_disasm_one(CosmoA64Disasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address, CosmoInsn *insn)
{
    (void)ctx;

    if (!code || size < 4 || !insn) return 0;

    memset(insn, 0, sizeof(*insn));
    insn->address = address;
    insn->arch = COSMO_ARCH_AARCH64;
    insn->encoding = read_insn(code);
    insn->length = 4;
    memcpy(insn->bytes, code, 4);

    uint32_t enc = insn->encoding;

    /* Extract top-level opcode fields */
    uint32_t op0 = BITS(enc, 31, 25);

    /* Data Processing -- Immediate */
    if ((op0 & 0x71) == 0x10) {
        /* PC-rel addressing (ADR/ADRP) */
        bool is_adrp = BIT(enc, 31);
        int64_t imm = (sign_extend(BITS(enc, 23, 5), 19) << 2) | BITS(enc, 30, 29);
        uint32_t rd = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_adrp ? "adrp" : "adr");
        insn->category = COSMO_CAT_DATA_XFER;
        insn->num_operands = 2;

        insn->operands[0].type = COSMO_OP_REG;
        insn->operands[0].reg.reg_id = decode_reg(rd, true, false);
        insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
        insn->operands[0].size = 8;

        insn->operands[1].type = COSMO_OP_LABEL;
        if (is_adrp) {
            insn->operands[1].label.target = (address & ~0xFFFULL) + (imm << 12);
        } else {
            insn->operands[1].label.target = address + imm;
        }
    }
    /* Add/Sub immediate */
    else if ((op0 & 0x71) == 0x11) {
        bool is_64bit = BIT(enc, 31);
        bool is_sub = BIT(enc, 30);
        bool set_flags = BIT(enc, 29);
        uint32_t shift = BITS(enc, 23, 22);
        uint32_t imm12 = BITS(enc, 21, 10);
        uint32_t rn = BITS(enc, 9, 5);
        uint32_t rd = BITS(enc, 4, 0);

        if (is_sub && rd == 31 && set_flags) {
            strcpy(insn->mnemonic, "cmp");
            insn->category = COSMO_CAT_COMPARE;
            insn->num_operands = 2;

            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rn, is_64bit, true);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = COSMO_OP_IMM;
            insn->operands[1].imm.value = shift ? (imm12 << 12) : imm12;
        } else {
            snprintf(insn->mnemonic, sizeof(insn->mnemonic), "%s%s",
                     is_sub ? "sub" : "add", set_flags ? "s" : "");
            insn->category = COSMO_CAT_ARITHMETIC;
            insn->num_operands = 3;

            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rd, is_64bit, !set_flags);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = COSMO_OP_REG;
            insn->operands[1].reg.reg_id = decode_reg(rn, is_64bit, true);
            insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);
            insn->operands[1].size = is_64bit ? 8 : 4;

            insn->operands[2].type = COSMO_OP_IMM;
            insn->operands[2].imm.value = shift ? (imm12 << 12) : imm12;
        }
    }
    /* Move wide immediate (MOVN/MOVZ/MOVK) */
    else if ((op0 & 0x3F) == 0x25) {
        bool is_64bit = BIT(enc, 31);
        uint32_t opc = BITS(enc, 30, 29);
        uint32_t hw = BITS(enc, 22, 21);
        uint32_t imm16 = BITS(enc, 20, 5);
        uint32_t rd = BITS(enc, 4, 0);

        static const char *mov_ops[] = { "movn", "???", "movz", "movk" };
        strcpy(insn->mnemonic, mov_ops[opc]);
        insn->category = COSMO_CAT_DATA_XFER;
        insn->num_operands = 2;

        insn->operands[0].type = COSMO_OP_REG;
        insn->operands[0].reg.reg_id = decode_reg(rd, is_64bit, false);
        insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
        insn->operands[0].size = is_64bit ? 8 : 4;

        insn->operands[1].type = COSMO_OP_IMM;
        insn->operands[1].imm.value = (uint64_t)imm16 << (hw * 16);
    }
    /* Branches */
    else if ((op0 & 0x7C) == 0x14) {
        /* Unconditional branch (B, BL) */
        bool is_bl = BIT(enc, 31);
        int64_t imm26 = sign_extend(BITS(enc, 25, 0), 26) << 2;

        strcpy(insn->mnemonic, is_bl ? "bl" : "b");
        insn->category = is_bl ? COSMO_CAT_CALL : COSMO_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_call = is_bl;
        insn->branch_target = address + imm26;
        insn->num_operands = 1;

        insn->operands[0].type = COSMO_OP_LABEL;
        insn->operands[0].label.target = insn->branch_target;
    }
    /* Compare and branch */
    else if ((op0 & 0x7E) == 0x34) {
        bool is_64bit = BIT(enc, 31);
        bool is_nz = BIT(enc, 24);
        int64_t imm19 = sign_extend(BITS(enc, 23, 5), 19) << 2;
        uint32_t rt = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_nz ? "cbnz" : "cbz");
        insn->category = COSMO_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm19;
        insn->num_operands = 2;

        insn->operands[0].type = COSMO_OP_REG;
        insn->operands[0].reg.reg_id = decode_reg(rt, is_64bit, false);
        insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
        insn->operands[0].size = is_64bit ? 8 : 4;

        insn->operands[1].type = COSMO_OP_LABEL;
        insn->operands[1].label.target = insn->branch_target;
    }
    /* Conditional branch */
    else if ((op0 & 0x7E) == 0x54) {
        int64_t imm19 = sign_extend(BITS(enc, 23, 5), 19) << 2;
        uint32_t cond = BITS(enc, 3, 0);

        snprintf(insn->mnemonic, sizeof(insn->mnemonic), "b.%s",
                 COND_NAMES[cond]);
        insn->category = COSMO_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm19;
        insn->num_operands = 1;

        insn->operands[0].type = COSMO_OP_LABEL;
        insn->operands[0].label.target = insn->branch_target;
    }
    /* Test and branch */
    else if ((op0 & 0x7E) == 0x36) {
        bool is_64bit = BIT(enc, 31);
        bool is_nz = BIT(enc, 24);
        uint32_t b5 = BIT(enc, 31);
        uint32_t b40 = BITS(enc, 23, 19);
        int64_t imm14 = sign_extend(BITS(enc, 18, 5), 14) << 2;
        uint32_t rt = BITS(enc, 4, 0);

        strcpy(insn->mnemonic, is_nz ? "tbnz" : "tbz");
        insn->category = COSMO_CAT_BRANCH;
        insn->is_branch = true;
        insn->is_conditional = true;
        insn->branch_target = address + imm14;
        insn->num_operands = 3;

        insn->operands[0].type = COSMO_OP_REG;
        insn->operands[0].reg.reg_id = decode_reg(rt, is_64bit, false);
        insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);

        insn->operands[1].type = COSMO_OP_IMM;
        insn->operands[1].imm.value = (b5 << 5) | b40;

        insn->operands[2].type = COSMO_OP_LABEL;
        insn->operands[2].label.target = insn->branch_target;
    }
    /* Unconditional branch (register) */
    else if ((op0 & 0x7E) == 0x6A) {
        uint32_t opc = BITS(enc, 24, 21);
        uint32_t rn = BITS(enc, 9, 5);

        if (opc == 0) {
            strcpy(insn->mnemonic, "br");
            insn->is_branch = true;
            insn->category = COSMO_CAT_BRANCH;
        } else if (opc == 1) {
            strcpy(insn->mnemonic, "blr");
            insn->is_branch = true;
            insn->is_call = true;
            insn->category = COSMO_CAT_CALL;
        } else if (opc == 2) {
            strcpy(insn->mnemonic, "ret");
            insn->is_branch = true;
            insn->is_return = true;
            insn->category = COSMO_CAT_RETURN;
        } else {
            strcpy(insn->mnemonic, "br_reg");
            insn->category = COSMO_CAT_BRANCH;
        }

        insn->num_operands = (opc == 2 && rn == 30) ? 0 : 1;

        if (insn->num_operands > 0) {
            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rn, true, false);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
            insn->operands[0].size = 8;
        }
    }
    /* Load/Store */
    else if ((op0 & 0x0A) == 0x08) {
        uint32_t size = BITS(enc, 31, 30);
        bool is_vector = BIT(enc, 26);

        if (BITS(enc, 29, 28) == 3 && BITS(enc, 25, 24) == 1) {
            /* Load/store register (unsigned immediate) */
            uint32_t imm12 = BITS(enc, 21, 10);
            uint32_t rn = BITS(enc, 9, 5);
            uint32_t rt = BITS(enc, 4, 0);
            bool is_load = BIT(enc, 22);

            int scale = size;
            int64_t offset = imm12 << scale;

            strcpy(insn->mnemonic, is_load ? "ldr" : "str");
            insn->category = COSMO_CAT_DATA_XFER;
            insn->reads_memory = is_load;
            insn->writes_memory = !is_load;
            insn->num_operands = 2;

            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rt, size == 3, false);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
            insn->operands[0].size = 1 << size;

            insn->operands[1].type = COSMO_OP_MEM;
            insn->operands[1].mem.base_reg = decode_reg(rn, true, true);
            insn->operands[1].mem.disp = offset;
            insn->operands[1].size = 1 << size;
        }
        /* Load/store register pair (LDP/STP) */
        else if (BITS(enc, 29, 27) == 5) {
            bool is_load = BIT(enc, 22);
            int64_t imm7 = sign_extend(BITS(enc, 21, 15), 7);
            uint32_t rt2 = BITS(enc, 14, 10);
            uint32_t rn = BITS(enc, 9, 5);
            uint32_t rt = BITS(enc, 4, 0);
            bool is_64bit = BIT(enc, 31);

            int scale = 2 + (is_64bit ? 1 : 0);
            int64_t offset = imm7 << scale;

            strcpy(insn->mnemonic, is_load ? "ldp" : "stp");
            insn->category = is_load ? COSMO_CAT_DATA_XFER : COSMO_CAT_STACK;
            insn->reads_memory = is_load;
            insn->writes_memory = !is_load;
            insn->num_operands = 3;

            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rt, is_64bit, false);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
            insn->operands[0].size = is_64bit ? 8 : 4;

            insn->operands[1].type = COSMO_OP_REG;
            insn->operands[1].reg.reg_id = decode_reg(rt2, is_64bit, false);
            insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);
            insn->operands[1].size = is_64bit ? 8 : 4;

            insn->operands[2].type = COSMO_OP_MEM;
            insn->operands[2].mem.base_reg = decode_reg(rn, true, true);
            insn->operands[2].mem.disp = offset;
        }
        else {
            strcpy(insn->mnemonic, "ldst");
            insn->category = COSMO_CAT_DATA_XFER;
        }

        (void)is_vector;
    }
    /* Data Processing -- Register */
    else if ((op0 & 0x0F) == 0x0A || (op0 & 0x0F) == 0x0B) {
        bool is_64bit = BIT(enc, 31);
        uint32_t opc = BITS(enc, 30, 29);
        bool set_flags = BIT(enc, 29);
        uint32_t shift = BITS(enc, 23, 22);
        bool is_neg = BIT(enc, 21);
        uint32_t rm = BITS(enc, 20, 16);
        uint32_t imm6 = BITS(enc, 15, 10);
        uint32_t rn = BITS(enc, 9, 5);
        uint32_t rd = BITS(enc, 4, 0);

        /* Logical shifted register */
        if ((BITS(enc, 28, 24) & 0x1E) == 0x0A) {
            static const char *log_ops[] = { "and", "orr", "eor", "ands" };
            static const char *log_neg[] = { "bic", "orn", "eon", "bics" };
            strcpy(insn->mnemonic, is_neg ? log_neg[opc] : log_ops[opc]);

            /* MOV alias */
            if (opc == 1 && !is_neg && rn == 31 && imm6 == 0 && shift == 0) {
                strcpy(insn->mnemonic, "mov");
                insn->category = COSMO_CAT_DATA_XFER;
                insn->num_operands = 2;

                insn->operands[0].type = COSMO_OP_REG;
                insn->operands[0].reg.reg_id = decode_reg(rd, is_64bit, false);
                insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
                insn->operands[0].size = is_64bit ? 8 : 4;

                insn->operands[1].type = COSMO_OP_REG;
                insn->operands[1].reg.reg_id = decode_reg(rm, is_64bit, false);
                insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);
                insn->operands[1].size = is_64bit ? 8 : 4;
            } else {
                insn->category = COSMO_CAT_LOGICAL;
                insn->num_operands = 3;

                insn->operands[0].type = COSMO_OP_REG;
                insn->operands[0].reg.reg_id = decode_reg(rd, is_64bit, false);
                insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);

                insn->operands[1].type = COSMO_OP_REG;
                insn->operands[1].reg.reg_id = decode_reg(rn, is_64bit, false);
                insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);

                insn->operands[2].type = COSMO_OP_REG;
                insn->operands[2].reg.reg_id = decode_reg(rm, is_64bit, false);
                insn->operands[2].reg.name = cosmo_a64_reg_name(insn->operands[2].reg.reg_id);
            }
        }
        /* Add/sub shifted register */
        else if ((BITS(enc, 28, 24) & 0x1F) == 0x0B) {
            bool is_sub = BIT(enc, 30);

            /* CMP alias */
            if (is_sub && rd == 31 && set_flags) {
                strcpy(insn->mnemonic, "cmp");
                insn->category = COSMO_CAT_COMPARE;
                insn->num_operands = 2;

                insn->operands[0].type = COSMO_OP_REG;
                insn->operands[0].reg.reg_id = decode_reg(rn, is_64bit, true);
                insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);

                insn->operands[1].type = COSMO_OP_REG;
                insn->operands[1].reg.reg_id = decode_reg(rm, is_64bit, false);
                insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);
            } else {
                snprintf(insn->mnemonic, sizeof(insn->mnemonic), "%s%s",
                         is_sub ? "sub" : "add", set_flags ? "s" : "");
                insn->category = COSMO_CAT_ARITHMETIC;
                insn->num_operands = 3;

                insn->operands[0].type = COSMO_OP_REG;
                insn->operands[0].reg.reg_id = decode_reg(rd, is_64bit, !set_flags);
                insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);

                insn->operands[1].type = COSMO_OP_REG;
                insn->operands[1].reg.reg_id = decode_reg(rn, is_64bit, true);
                insn->operands[1].reg.name = cosmo_a64_reg_name(insn->operands[1].reg.reg_id);

                insn->operands[2].type = COSMO_OP_REG;
                insn->operands[2].reg.reg_id = decode_reg(rm, is_64bit, false);
                insn->operands[2].reg.name = cosmo_a64_reg_name(insn->operands[2].reg.reg_id);
            }
        }
        else {
            strcpy(insn->mnemonic, "data_reg");
            insn->category = COSMO_CAT_OTHER;
        }

        (void)shift;
        (void)imm6;
    }
    /* System instructions */
    else if ((enc & 0xFFC00000) == 0xD5000000) {
        uint32_t l = BIT(enc, 21);
        uint32_t op0_sys = BITS(enc, 20, 19);
        uint32_t op1 = BITS(enc, 18, 16);
        uint32_t crn = BITS(enc, 15, 12);
        uint32_t crm = BITS(enc, 11, 8);
        uint32_t op2 = BITS(enc, 7, 5);
        uint32_t rt = BITS(enc, 4, 0);

        if (op0_sys == 1 && l == 0 && rt == 31) {
            /* Hint instructions */
            if (crn == 2 && op1 == 3) {
                switch ((crm << 3) | op2) {
                    case 0: strcpy(insn->mnemonic, "nop"); break;
                    case 1: strcpy(insn->mnemonic, "yield"); break;
                    case 2: strcpy(insn->mnemonic, "wfe"); break;
                    case 3: strcpy(insn->mnemonic, "wfi"); break;
                    case 4: strcpy(insn->mnemonic, "sev"); break;
                    case 5: strcpy(insn->mnemonic, "sevl"); break;
                    default: strcpy(insn->mnemonic, "hint"); break;
                }
                insn->category = (crm == 0 && op2 == 0) ? COSMO_CAT_NOP : COSMO_CAT_SYSTEM;
            }
            /* Barriers */
            else if (crn == 3) {
                switch (op2) {
                    case 2: strcpy(insn->mnemonic, "clrex"); break;
                    case 4: strcpy(insn->mnemonic, "dsb"); break;
                    case 5: strcpy(insn->mnemonic, "dmb"); break;
                    case 6: strcpy(insn->mnemonic, "isb"); break;
                    default: strcpy(insn->mnemonic, "barrier"); break;
                }
                insn->category = COSMO_CAT_SYSTEM;
            }
            else {
                strcpy(insn->mnemonic, "sys");
                insn->category = COSMO_CAT_SYSTEM;
            }
        }
        /* MSR/MRS */
        else if (op0_sys >= 2) {
            strcpy(insn->mnemonic, l ? "mrs" : "msr");
            insn->category = COSMO_CAT_SYSTEM;
            insn->num_operands = 1;

            insn->operands[0].type = COSMO_OP_REG;
            insn->operands[0].reg.reg_id = decode_reg(rt, true, false);
            insn->operands[0].reg.name = cosmo_a64_reg_name(insn->operands[0].reg.reg_id);
        }
        else {
            strcpy(insn->mnemonic, "sys");
            insn->category = COSMO_CAT_SYSTEM;
        }
    }
    /* Exception generation */
    else if ((enc & 0xFF000000) == 0xD4000000) {
        uint32_t opc = BITS(enc, 23, 21);
        uint32_t imm16 = BITS(enc, 20, 5);
        uint32_t ll = BITS(enc, 1, 0);

        switch ((opc << 2) | ll) {
            case 0x01: strcpy(insn->mnemonic, "svc"); break;
            case 0x02: strcpy(insn->mnemonic, "hvc"); break;
            case 0x03: strcpy(insn->mnemonic, "smc"); break;
            case 0x04: strcpy(insn->mnemonic, "brk"); break;
            case 0x08: strcpy(insn->mnemonic, "hlt"); break;
            default: strcpy(insn->mnemonic, "exc"); break;
        }
        insn->category = COSMO_CAT_SYSTEM;
        insn->num_operands = 1;
        insn->operands[0].type = COSMO_OP_IMM;
        insn->operands[0].imm.value = imm16;
    }
    /* Default: unknown */
    else {
        snprintf(insn->mnemonic, sizeof(insn->mnemonic), ".inst 0x%08x", enc);
        insn->category = COSMO_CAT_OTHER;
    }

    /* Format text output */
    format_insn(insn);

    return 4;
}

/* ============================================================================
 * Pattern Recognition
 * ============================================================================ */

bool cosmo_a64_is_prologue(const uint8_t *code, size_t size)
{
    if (size < 4) return false;

    uint32_t insn = read_insn(code);

    /* STP x29, x30, [sp, #offset]! - common prologue pattern */
    if ((insn & 0xFFC07FFF) == 0xA9007BFD) {
        return true;
    }

    /* SUB sp, sp, #... - stack allocation */
    if ((insn & 0xFF0003FF) == 0xD10003FF) {
        return true;
    }

    /* PACIASP / PACIBSP (PAC prologue) */
    if (insn == 0xD503233F || insn == 0xD503237F) {
        return true;
    }

    return false;
}

bool cosmo_a64_is_epilogue(const uint8_t *code, size_t size)
{
    if (size < 4) return false;

    uint32_t insn = read_insn(code);

    /* RET */
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        return true;
    }

    /* RET with PAC (RETAA/RETAB) */
    if (insn == 0xD65F0BFF || insn == 0xD65F0FFF) {
        return true;
    }

    return false;
}
