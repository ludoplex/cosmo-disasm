/*
 * cosmo_disasm_x86.h - x86/x86-64 Disassembler Backend
 * 
 * Internal header for the x86 disassembler implementation.
 * Based on e9studio's e9disasm_x86.c.
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#ifndef COSMO_DISASM_X86_H
#define COSMO_DISASM_X86_H

#include "cosmo_disasm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * x86 Register IDs
 * ============================================================================ */

typedef enum {
    COSMO_X86_REG_NONE = 0,

    /* 64-bit */
    COSMO_X86_REG_RAX, COSMO_X86_REG_RCX, COSMO_X86_REG_RDX, COSMO_X86_REG_RBX,
    COSMO_X86_REG_RSP, COSMO_X86_REG_RBP, COSMO_X86_REG_RSI, COSMO_X86_REG_RDI,
    COSMO_X86_REG_R8,  COSMO_X86_REG_R9,  COSMO_X86_REG_R10, COSMO_X86_REG_R11,
    COSMO_X86_REG_R12, COSMO_X86_REG_R13, COSMO_X86_REG_R14, COSMO_X86_REG_R15,
    COSMO_X86_REG_RIP,

    /* 32-bit */
    COSMO_X86_REG_EAX, COSMO_X86_REG_ECX, COSMO_X86_REG_EDX, COSMO_X86_REG_EBX,
    COSMO_X86_REG_ESP, COSMO_X86_REG_EBP, COSMO_X86_REG_ESI, COSMO_X86_REG_EDI,
    COSMO_X86_REG_R8D, COSMO_X86_REG_R9D, COSMO_X86_REG_R10D, COSMO_X86_REG_R11D,
    COSMO_X86_REG_R12D, COSMO_X86_REG_R13D, COSMO_X86_REG_R14D, COSMO_X86_REG_R15D,
    COSMO_X86_REG_EIP,

    /* 16-bit */
    COSMO_X86_REG_AX, COSMO_X86_REG_CX, COSMO_X86_REG_DX, COSMO_X86_REG_BX,
    COSMO_X86_REG_SP, COSMO_X86_REG_BP, COSMO_X86_REG_SI, COSMO_X86_REG_DI,

    /* 8-bit */
    COSMO_X86_REG_AL, COSMO_X86_REG_CL, COSMO_X86_REG_DL, COSMO_X86_REG_BL,
    COSMO_X86_REG_AH, COSMO_X86_REG_CH, COSMO_X86_REG_DH, COSMO_X86_REG_BH,
    COSMO_X86_REG_SPL, COSMO_X86_REG_BPL, COSMO_X86_REG_SIL, COSMO_X86_REG_DIL,

    /* Segment registers */
    COSMO_X86_REG_CS, COSMO_X86_REG_DS, COSMO_X86_REG_ES,
    COSMO_X86_REG_FS, COSMO_X86_REG_GS, COSMO_X86_REG_SS,

    /* XMM registers */
    COSMO_X86_REG_XMM0, COSMO_X86_REG_XMM1, COSMO_X86_REG_XMM2, COSMO_X86_REG_XMM3,
    COSMO_X86_REG_XMM4, COSMO_X86_REG_XMM5, COSMO_X86_REG_XMM6, COSMO_X86_REG_XMM7,
    COSMO_X86_REG_XMM8, COSMO_X86_REG_XMM9, COSMO_X86_REG_XMM10, COSMO_X86_REG_XMM11,
    COSMO_X86_REG_XMM12, COSMO_X86_REG_XMM13, COSMO_X86_REG_XMM14, COSMO_X86_REG_XMM15,

} CosmoX86Reg;

/* ============================================================================
 * x86 Disassembler Context
 * ============================================================================ */

typedef struct CosmoX86Disasm CosmoX86Disasm;

/* Create/destroy */
CosmoX86Disasm *cosmo_x86_disasm_create(int mode);
void cosmo_x86_disasm_free(CosmoX86Disasm *ctx);

/* Set mode (16, 32, 64) */
void cosmo_x86_disasm_set_mode(CosmoX86Disasm *ctx, int mode);

/* Disassemble single instruction (fills CosmoInsn) */
int cosmo_x86_disasm_one(CosmoX86Disasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address, CosmoInsn *insn);

/* Helper functions */
const char *cosmo_x86_reg_name(int reg_id);
int cosmo_x86_reg_size(int reg_id);
bool cosmo_x86_is_prologue(const uint8_t *code, size_t size);
bool cosmo_x86_is_epilogue(const uint8_t *code, size_t size);
int cosmo_x86_insn_length(const uint8_t *code, size_t size, int mode);

#ifdef __cplusplus
}
#endif

#endif /* COSMO_DISASM_X86_H */
