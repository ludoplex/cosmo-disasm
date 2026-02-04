/*
 * cosmo_disasm_arm64.h - AArch64 Disassembler Backend
 * 
 * Internal header for the ARM64 disassembler implementation.
 * Based on e9studio's e9disasm_arm64.c.
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#ifndef COSMO_DISASM_ARM64_H
#define COSMO_DISASM_ARM64_H

#include "cosmo_disasm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ARM64 Register IDs
 * ============================================================================ */

typedef enum {
    /* 64-bit general purpose */
    COSMO_A64_REG_X0 = 0, COSMO_A64_REG_X1, COSMO_A64_REG_X2, COSMO_A64_REG_X3,
    COSMO_A64_REG_X4, COSMO_A64_REG_X5, COSMO_A64_REG_X6, COSMO_A64_REG_X7,
    COSMO_A64_REG_X8, COSMO_A64_REG_X9, COSMO_A64_REG_X10, COSMO_A64_REG_X11,
    COSMO_A64_REG_X12, COSMO_A64_REG_X13, COSMO_A64_REG_X14, COSMO_A64_REG_X15,
    COSMO_A64_REG_X16, COSMO_A64_REG_X17, COSMO_A64_REG_X18, COSMO_A64_REG_X19,
    COSMO_A64_REG_X20, COSMO_A64_REG_X21, COSMO_A64_REG_X22, COSMO_A64_REG_X23,
    COSMO_A64_REG_X24, COSMO_A64_REG_X25, COSMO_A64_REG_X26, COSMO_A64_REG_X27,
    COSMO_A64_REG_X28, COSMO_A64_REG_X29, COSMO_A64_REG_X30, COSMO_A64_REG_XZR,
    COSMO_A64_REG_SP,

    /* 32-bit aliases */
    COSMO_A64_REG_W0 = 64, COSMO_A64_REG_W1, COSMO_A64_REG_W2, COSMO_A64_REG_W3,
    COSMO_A64_REG_W4, COSMO_A64_REG_W5, COSMO_A64_REG_W6, COSMO_A64_REG_W7,
    COSMO_A64_REG_W8, COSMO_A64_REG_W9, COSMO_A64_REG_W10, COSMO_A64_REG_W11,
    COSMO_A64_REG_W12, COSMO_A64_REG_W13, COSMO_A64_REG_W14, COSMO_A64_REG_W15,
    COSMO_A64_REG_W16, COSMO_A64_REG_W17, COSMO_A64_REG_W18, COSMO_A64_REG_W19,
    COSMO_A64_REG_W20, COSMO_A64_REG_W21, COSMO_A64_REG_W22, COSMO_A64_REG_W23,
    COSMO_A64_REG_W24, COSMO_A64_REG_W25, COSMO_A64_REG_W26, COSMO_A64_REG_W27,
    COSMO_A64_REG_W28, COSMO_A64_REG_W29, COSMO_A64_REG_W30, COSMO_A64_REG_WZR,
    COSMO_A64_REG_WSP,

    /* Aliases */
    COSMO_A64_REG_LR = COSMO_A64_REG_X30,
    COSMO_A64_REG_FP = COSMO_A64_REG_X29,
} CosmoA64Reg;

/* ============================================================================
 * ARM64 Disassembler Context
 * ============================================================================ */

typedef struct CosmoA64Disasm CosmoA64Disasm;

/* Create/destroy */
CosmoA64Disasm *cosmo_a64_disasm_create(void);
void cosmo_a64_disasm_free(CosmoA64Disasm *ctx);

/* Disassemble single instruction (fills CosmoInsn) */
int cosmo_a64_disasm_one(CosmoA64Disasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address, CosmoInsn *insn);

/* Helper functions */
const char *cosmo_a64_reg_name(int reg_id);
int cosmo_a64_reg_size(int reg_id);
bool cosmo_a64_is_prologue(const uint8_t *code, size_t size);
bool cosmo_a64_is_epilogue(const uint8_t *code, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* COSMO_DISASM_ARM64_H */
