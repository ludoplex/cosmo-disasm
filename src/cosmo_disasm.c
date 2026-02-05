/*
 * cosmo_disasm.c - Unified Disassembler Implementation
 * 
 * This file provides the unified API that dispatches to architecture-specific
 * backends (x86-64 and AArch64).
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#include "cosmo_disasm.h"
#include "cosmo_disasm_x86.h"
#include "cosmo_disasm_arm64.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Disassembler Context
 * ============================================================================ */

struct CosmoDisasm {
    CosmoArch arch;
    
    /* Architecture-specific contexts (created on demand) */
    CosmoX86Disasm *x86;
    CosmoA64Disasm *a64;
};

/*
 * Create disassembler context
 */
CosmoDisasm *cosmo_disasm_create(CosmoArch arch)
{
    CosmoDisasm *ctx = calloc(1, sizeof(CosmoDisasm));
    if (!ctx) return NULL;
    
    ctx->arch = arch;
    
    /* Pre-create the appropriate backend */
    switch (arch) {
        case COSMO_ARCH_X86_64:
            ctx->x86 = cosmo_x86_disasm_create(64);
            break;
        case COSMO_ARCH_X86_32:
            ctx->x86 = cosmo_x86_disasm_create(32);
            break;
        case COSMO_ARCH_AARCH64:
            ctx->a64 = cosmo_a64_disasm_create();
            break;
        default:
            break;
    }
    
    return ctx;
}

/*
 * Free disassembler context
 */
void cosmo_disasm_free(CosmoDisasm *ctx)
{
    if (!ctx) return;
    
    if (ctx->x86) cosmo_x86_disasm_free(ctx->x86);
    if (ctx->a64) cosmo_a64_disasm_free(ctx->a64);
    
    free(ctx);
}

/*
 * Set architecture
 */
void cosmo_disasm_set_arch(CosmoDisasm *ctx, CosmoArch arch)
{
    if (!ctx || ctx->arch == arch) return;
    
    ctx->arch = arch;
    
    /* Create backend if needed */
    switch (arch) {
        case COSMO_ARCH_X86_64:
            if (!ctx->x86) ctx->x86 = cosmo_x86_disasm_create(64);
            else cosmo_x86_disasm_set_mode(ctx->x86, 64);
            break;
        case COSMO_ARCH_X86_32:
            if (!ctx->x86) ctx->x86 = cosmo_x86_disasm_create(32);
            else cosmo_x86_disasm_set_mode(ctx->x86, 32);
            break;
        case COSMO_ARCH_AARCH64:
            if (!ctx->a64) ctx->a64 = cosmo_a64_disasm_create();
            break;
        default:
            break;
    }
}

/*
 * Get architecture
 */
CosmoArch cosmo_disasm_get_arch(const CosmoDisasm *ctx)
{
    return ctx ? ctx->arch : COSMO_ARCH_UNKNOWN;
}

/* ============================================================================
 * Disassembly Functions
 * ============================================================================ */

/*
 * Disassemble single instruction
 */
int cosmo_disasm_one(CosmoDisasm *ctx,
                     const uint8_t *code, size_t size,
                     uint64_t address,
                     CosmoInsn *insn)
{
    if (!ctx || !code || size == 0 || !insn) return 0;
    
    memset(insn, 0, sizeof(*insn));
    insn->arch = ctx->arch;
    insn->address = address;
    
    switch (ctx->arch) {
        case COSMO_ARCH_X86_64:
        case COSMO_ARCH_X86_32:
            if (ctx->x86) {
                return cosmo_x86_disasm_one(ctx->x86, code, size, address, insn);
            }
            break;
            
        case COSMO_ARCH_AARCH64:
            if (ctx->a64) {
                return cosmo_a64_disasm_one(ctx->a64, code, size, address, insn);
            }
            break;
            
        default:
            break;
    }
    
    /* Fallback: invalid instruction */
    insn->length = 1;
    insn->bytes[0] = code[0];
    strcpy(insn->mnemonic, "(bad)");
    insn->category = COSMO_CAT_INVALID;
    snprintf(insn->text, sizeof(insn->text), "(bad)");
    return 1;
}

/*
 * Disassemble multiple instructions
 */
size_t cosmo_disasm_many(CosmoDisasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address,
                         size_t max_count,
                         CosmoInsn **insns)
{
    if (!ctx || !code || size == 0 || !insns || max_count == 0) return 0;
    
    *insns = calloc(max_count, sizeof(CosmoInsn));
    if (!*insns) return 0;
    
    size_t decoded = 0;
    size_t offset = 0;
    
    while (decoded < max_count && offset < size) {
        int len = cosmo_disasm_one(ctx, code + offset, size - offset,
                                   address + offset, &(*insns)[decoded]);
        if (len <= 0) break;
        
        offset += len;
        decoded++;
    }
    
    return decoded;
}

/*
 * Free instruction array
 */
void cosmo_disasm_free_insns(CosmoInsn *insns, size_t count)
{
    (void)count;
    free(insns);
}

/* ============================================================================
 * Analysis Helpers
 * ============================================================================ */

/*
 * Check for function prologue
 */
bool cosmo_is_prologue(CosmoArch arch, const uint8_t *code, size_t size)
{
    if (!code || size == 0) return false;
    
    switch (arch) {
        case COSMO_ARCH_X86_64:
        case COSMO_ARCH_X86_32:
            return cosmo_x86_is_prologue(code, size);
        case COSMO_ARCH_AARCH64:
            return cosmo_a64_is_prologue(code, size);
        default:
            return false;
    }
}

/*
 * Check for function epilogue
 */
bool cosmo_is_epilogue(CosmoArch arch, const uint8_t *code, size_t size)
{
    if (!code || size == 0) return false;
    
    switch (arch) {
        case COSMO_ARCH_X86_64:
        case COSMO_ARCH_X86_32:
            return cosmo_x86_is_epilogue(code, size);
        case COSMO_ARCH_AARCH64:
            return cosmo_a64_is_epilogue(code, size);
        default:
            return false;
    }
}

/*
 * Get instruction length without full decode
 */
int cosmo_insn_length(CosmoArch arch, const uint8_t *code, size_t size)
{
    if (!code || size == 0) return 0;
    
    switch (arch) {
        case COSMO_ARCH_X86_64:
            return cosmo_x86_insn_length(code, size, 64);
        case COSMO_ARCH_X86_32:
            return cosmo_x86_insn_length(code, size, 32);
        case COSMO_ARCH_AARCH64:
            return (size >= 4) ? 4 : 0;  /* ARM64 always 4 bytes */
        default:
            return 0;
    }
}

/*
 * Check if instruction writes register
 */
bool cosmo_insn_writes_reg(const CosmoInsn *insn, int reg_id)
{
    if (!insn || insn->num_operands == 0) return false;
    
    /* Most instructions write to first operand */
    if (insn->operands[0].type == COSMO_OP_REG &&
        insn->operands[0].reg.reg_id == reg_id) {
        return true;
    }
    
    return false;
}

/*
 * Check if instruction reads register
 */
bool cosmo_insn_reads_reg(const CosmoInsn *insn, int reg_id)
{
    if (!insn) return false;
    
    for (int i = 0; i < insn->num_operands; i++) {
        const CosmoOperand *op = &insn->operands[i];
        
        if (op->type == COSMO_OP_REG && op->reg.reg_id == reg_id) {
            /* Skip destination for most instructions */
            if (i == 0 && strcmp(insn->mnemonic, "cmp") != 0 &&
                strcmp(insn->mnemonic, "test") != 0) {
                continue;
            }
            return true;
        }
        
        if (op->type == COSMO_OP_MEM) {
            if (op->mem.base_reg == reg_id || op->mem.index_reg == reg_id) {
                return true;
            }
        }
    }
    
    return false;
}

/* ============================================================================
 * Register Helpers
 * ============================================================================ */

/*
 * Get register name
 */
const char *cosmo_reg_name(CosmoArch arch, int reg_id)
{
    switch (arch) {
        case COSMO_ARCH_X86_64:
        case COSMO_ARCH_X86_32:
            return cosmo_x86_reg_name(reg_id);
        case COSMO_ARCH_AARCH64:
            return cosmo_a64_reg_name(reg_id);
        default:
            return "???";
    }
}

/*
 * Get register size
 */
int cosmo_reg_size(CosmoArch arch, int reg_id)
{
    switch (arch) {
        case COSMO_ARCH_X86_64:
        case COSMO_ARCH_X86_32:
            return cosmo_x86_reg_size(reg_id);
        case COSMO_ARCH_AARCH64:
            return cosmo_a64_reg_size(reg_id);
        default:
            return 0;
    }
}

/*
 * Map unified register class to architecture-specific ID
 */
int cosmo_reg_to_arch(CosmoArch arch, CosmoRegClass reg_class)
{
    switch (arch) {
        case COSMO_ARCH_X86_64:
            switch (reg_class) {
                case COSMO_REG_GP0:  return COSMO_X86_REG_RAX;
                case COSMO_REG_GP1:  return COSMO_X86_REG_RCX;
                case COSMO_REG_GP2:  return COSMO_X86_REG_RDX;
                case COSMO_REG_GP3:  return COSMO_X86_REG_RBX;
                case COSMO_REG_GP4:  return COSMO_X86_REG_RSI;
                case COSMO_REG_GP5:  return COSMO_X86_REG_RDI;
                case COSMO_REG_GP6:  return COSMO_X86_REG_R8;
                case COSMO_REG_GP7:  return COSMO_X86_REG_R9;
                case COSMO_REG_GP8:  return COSMO_X86_REG_R10;
                case COSMO_REG_GP9:  return COSMO_X86_REG_R11;
                case COSMO_REG_GP10: return COSMO_X86_REG_R12;
                case COSMO_REG_GP11: return COSMO_X86_REG_R13;
                case COSMO_REG_GP12: return COSMO_X86_REG_R14;
                case COSMO_REG_GP13: return COSMO_X86_REG_R15;
                case COSMO_REG_SP:   return COSMO_X86_REG_RSP;
                case COSMO_REG_FP:   return COSMO_X86_REG_RBP;
                case COSMO_REG_IP:   return COSMO_X86_REG_RIP;
                default:             return -1;
            }
            
        case COSMO_ARCH_AARCH64:
            switch (reg_class) {
                case COSMO_REG_GP0:  return COSMO_A64_REG_X0;
                case COSMO_REG_GP1:  return COSMO_A64_REG_X1;
                case COSMO_REG_GP2:  return COSMO_A64_REG_X2;
                case COSMO_REG_GP3:  return COSMO_A64_REG_X3;
                case COSMO_REG_GP4:  return COSMO_A64_REG_X4;
                case COSMO_REG_GP5:  return COSMO_A64_REG_X5;
                case COSMO_REG_GP6:  return COSMO_A64_REG_X6;
                case COSMO_REG_GP7:  return COSMO_A64_REG_X7;
                case COSMO_REG_SP:   return COSMO_A64_REG_SP;
                case COSMO_REG_FP:   return COSMO_A64_REG_X29;
                case COSMO_REG_LR:   return COSMO_A64_REG_X30;
                default:             return -1;
            }
            
        default:
            return -1;
    }
}

/*
 * Map architecture-specific ID to unified register class
 */
CosmoRegClass cosmo_reg_from_arch(CosmoArch arch, int reg_id)
{
    switch (arch) {
        case COSMO_ARCH_X86_64:
            switch (reg_id) {
                case COSMO_X86_REG_RAX: return COSMO_REG_GP0;
                case COSMO_X86_REG_RCX: return COSMO_REG_GP1;
                case COSMO_X86_REG_RDX: return COSMO_REG_GP2;
                case COSMO_X86_REG_RBX: return COSMO_REG_GP3;
                case COSMO_X86_REG_RSP: return COSMO_REG_SP;
                case COSMO_X86_REG_RBP: return COSMO_REG_FP;
                case COSMO_X86_REG_RIP: return COSMO_REG_IP;
                default:                return COSMO_REG_NONE;
            }
            
        case COSMO_ARCH_AARCH64:
            switch (reg_id) {
                case COSMO_A64_REG_X0:  return COSMO_REG_GP0;
                case COSMO_A64_REG_X1:  return COSMO_REG_GP1;
                case COSMO_A64_REG_X2:  return COSMO_REG_GP2;
                case COSMO_A64_REG_X3:  return COSMO_REG_GP3;
                case COSMO_A64_REG_SP:  return COSMO_REG_SP;
                case COSMO_A64_REG_X29: return COSMO_REG_FP;
                case COSMO_A64_REG_X30: return COSMO_REG_LR;
                default:                return COSMO_REG_NONE;
            }
            
        default:
            return COSMO_REG_NONE;
    }
}

/* ============================================================================
 * Architecture Detection
 * ============================================================================ */

/*
 * Detect architecture from ELF headers
 */
CosmoArch cosmo_detect_arch_elf(const uint8_t *data, size_t size)
{
    if (!data || size < 20) return COSMO_ARCH_UNKNOWN;
    
    /* Check ELF magic */
    if (data[0] != 0x7F || data[1] != 'E' ||
        data[2] != 'L' || data[3] != 'F') {
        return COSMO_ARCH_UNKNOWN;
    }
    
    /* e_machine at offset 18 (16-bit) */
    uint16_t machine = data[18] | (data[19] << 8);
    
    switch (machine) {
        case 0x3E:   /* EM_X86_64 */
            return COSMO_ARCH_X86_64;
        case 0x03:   /* EM_386 */
            return COSMO_ARCH_X86_32;
        case 0xB7:   /* EM_AARCH64 */
            return COSMO_ARCH_AARCH64;
        default:
            return COSMO_ARCH_UNKNOWN;
    }
}

/*
 * Detect architecture from PE headers
 */
CosmoArch cosmo_detect_arch_pe(const uint8_t *data, size_t size)
{
    if (!data || size < 64) return COSMO_ARCH_UNKNOWN;
    
    /* Check MZ signature */
    if (data[0] != 'M' || data[1] != 'Z') {
        return COSMO_ARCH_UNKNOWN;
    }
    
    /* Get PE header offset from e_lfanew at offset 0x3C */
    uint32_t pe_offset = data[0x3C] | (data[0x3D] << 8) |
                         (data[0x3E] << 16) | (data[0x3F] << 24);
    
    if (pe_offset + 6 > size) return COSMO_ARCH_UNKNOWN;
    
    /* Check PE signature */
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' ||
        data[pe_offset + 2] != 0 || data[pe_offset + 3] != 0) {
        return COSMO_ARCH_UNKNOWN;
    }
    
    /* Machine type at PE+4 */
    uint16_t machine = data[pe_offset + 4] | (data[pe_offset + 5] << 8);
    
    switch (machine) {
        case 0x8664:  /* AMD64 */
            return COSMO_ARCH_X86_64;
        case 0x014C:  /* i386 */
            return COSMO_ARCH_X86_32;
        case 0xAA64:  /* ARM64 */
            return COSMO_ARCH_AARCH64;
        default:
            return COSMO_ARCH_UNKNOWN;
    }
}

/*
 * Detect architecture from APE binary
 * 
 * APE binaries are polyglot - they contain both ELF and PE headers.
 * We check both and prefer the architecture that matches the host.
 */
CosmoArch cosmo_detect_arch_ape(const uint8_t *data, size_t size)
{
    if (!data || size < 64) return COSMO_ARCH_UNKNOWN;
    
    /* APE binaries start with "MZqFpD" or similar DOS stub */
    if (data[0] != 'M' || data[1] != 'Z') {
        return COSMO_ARCH_UNKNOWN;
    }
    
    /* Try PE detection first */
    CosmoArch pe_arch = cosmo_detect_arch_pe(data, size);
    
    /* Also try finding embedded ELF */
    /* ELF header is typically at a fixed offset in APE binaries */
    for (size_t offset = 0; offset < size - 64 && offset < 4096; offset += 4) {
        if (data[offset] == 0x7F && data[offset + 1] == 'E' &&
            data[offset + 2] == 'L' && data[offset + 3] == 'F') {
            CosmoArch elf_arch = cosmo_detect_arch_elf(data + offset, size - offset);
            if (elf_arch != COSMO_ARCH_UNKNOWN) {
                return elf_arch;
            }
        }
    }
    
    return pe_arch;
}

/* ============================================================================
 * Version Information
 * ============================================================================ */

/* Helper for stringifying version numbers */
#define COSMO_DISASM_STR2(x) #x
#define COSMO_DISASM_STR(x) COSMO_DISASM_STR2(x)

const char *cosmo_disasm_version(void)
{
    return "cosmo-disasm " 
           COSMO_DISASM_STR(COSMO_DISASM_VERSION_MAJOR) "."
           COSMO_DISASM_STR(COSMO_DISASM_VERSION_MINOR) "."
           COSMO_DISASM_STR(COSMO_DISASM_VERSION_PATCH);
}
