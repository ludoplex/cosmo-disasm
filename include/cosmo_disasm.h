/*
 * cosmo-disasm: Unified Cross-Architecture Disassembler Library
 * 
 * A lightweight, self-contained disassembler supporting x86-64 and AArch64.
 * Built for Cosmopolitan Libc - produces Actually Portable Executables.
 * 
 * Extracted and unified from e9studio's disassembler implementation.
 * 
 * Usage:
 *   - tedit-cosmo: Binary file disassembly view
 *   - e9studio: Binary patching and analysis
 *   - llamafile-llm: JIT code introspection (future)
 *   - Any Cosmo project needing disassembly
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC (permissive, compatible with Cosmopolitan)
 */

#ifndef COSMO_DISASM_H
#define COSMO_DISASM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Architecture Selection
 * ============================================================================ */

typedef enum {
    COSMO_ARCH_UNKNOWN = 0,
    COSMO_ARCH_X86_64  = 1,    /* AMD64 / x86-64 / x64 */
    COSMO_ARCH_AARCH64 = 2,    /* ARM64 / AArch64 */
    COSMO_ARCH_X86_32  = 3,    /* i386 / x86 (32-bit) */
    COSMO_ARCH_ARM32   = 4,    /* ARM (32-bit) - future */
} CosmoArch;

/* ============================================================================
 * Register Definitions (Unified)
 * ============================================================================ */

/* Register categories for cross-architecture analysis */
typedef enum {
    COSMO_REG_NONE = 0,
    
    /* General purpose - mapped per architecture */
    COSMO_REG_GP0,  COSMO_REG_GP1,  COSMO_REG_GP2,  COSMO_REG_GP3,
    COSMO_REG_GP4,  COSMO_REG_GP5,  COSMO_REG_GP6,  COSMO_REG_GP7,
    COSMO_REG_GP8,  COSMO_REG_GP9,  COSMO_REG_GP10, COSMO_REG_GP11,
    COSMO_REG_GP12, COSMO_REG_GP13, COSMO_REG_GP14, COSMO_REG_GP15,
    
    /* Special purpose */
    COSMO_REG_SP,       /* Stack pointer */
    COSMO_REG_FP,       /* Frame pointer */
    COSMO_REG_IP,       /* Instruction pointer / PC */
    COSMO_REG_LR,       /* Link register (ARM) */
    COSMO_REG_FLAGS,    /* Flags / condition codes */
    
    /* SIMD - first 8 (common to both architectures) */
    COSMO_REG_VEC0, COSMO_REG_VEC1, COSMO_REG_VEC2, COSMO_REG_VEC3,
    COSMO_REG_VEC4, COSMO_REG_VEC5, COSMO_REG_VEC6, COSMO_REG_VEC7,
    
} CosmoRegClass;

/* ============================================================================
 * Operand Types
 * ============================================================================ */

typedef enum {
    COSMO_OP_NONE = 0,
    COSMO_OP_REG,       /* Register */
    COSMO_OP_IMM,       /* Immediate value */
    COSMO_OP_MEM,       /* Memory reference */
    COSMO_OP_LABEL,     /* PC-relative label/address */
} CosmoOpType;

typedef struct {
    CosmoOpType type;
    int size;           /* Operand size in bytes */
    
    union {
        /* COSMO_OP_REG */
        struct {
            int reg_id;         /* Architecture-specific register ID */
            const char *name;   /* Register name string */
        } reg;
        
        /* COSMO_OP_IMM */
        struct {
            int64_t value;
            bool is_signed;
        } imm;
        
        /* COSMO_OP_MEM */
        struct {
            int base_reg;       /* Base register (-1 if none) */
            int index_reg;      /* Index register (-1 if none) */
            int scale;          /* Scale factor (1, 2, 4, 8) */
            int64_t disp;       /* Displacement */
            int segment;        /* Segment override (x86 only, -1 if none) */
        } mem;
        
        /* COSMO_OP_LABEL */
        struct {
            uint64_t target;    /* Absolute target address */
            int64_t offset;     /* Relative offset from instruction end */
        } label;
    };
} CosmoOperand;

/* ============================================================================
 * Instruction Categories
 * ============================================================================ */

typedef enum {
    COSMO_CAT_INVALID = 0,
    COSMO_CAT_DATA_XFER,    /* MOV, LOAD, STORE */
    COSMO_CAT_ARITHMETIC,   /* ADD, SUB, MUL, DIV */
    COSMO_CAT_LOGICAL,      /* AND, OR, XOR, NOT */
    COSMO_CAT_COMPARE,      /* CMP, TEST */
    COSMO_CAT_BRANCH,       /* JMP, Jcc, B, B.cond */
    COSMO_CAT_CALL,         /* CALL, BL */
    COSMO_CAT_RETURN,       /* RET, BX LR */
    COSMO_CAT_STACK,        /* PUSH, POP, STP, LDP */
    COSMO_CAT_SIMD,         /* Vector/SIMD operations */
    COSMO_CAT_SYSTEM,       /* Syscall, privileged */
    COSMO_CAT_NOP,          /* NOP variants */
    COSMO_CAT_OTHER,        /* Miscellaneous */
} CosmoInsnCategory;

/* ============================================================================
 * Instruction Structure
 * ============================================================================ */

#define COSMO_MAX_OPERANDS 4
#define COSMO_MAX_INSN_LEN 15   /* x86-64 max is 15, ARM64 is always 4 */

typedef struct {
    /* Location */
    uint64_t address;
    uint8_t bytes[COSMO_MAX_INSN_LEN];
    int length;
    
    /* Disassembly */
    char mnemonic[32];
    char text[128];             /* Full formatted instruction */
    
    /* Classification */
    CosmoInsnCategory category;
    CosmoArch arch;
    
    /* Operands */
    int num_operands;
    CosmoOperand operands[COSMO_MAX_OPERANDS];
    
    /* Control flow */
    bool is_branch;
    bool is_call;
    bool is_return;
    bool is_conditional;
    uint64_t branch_target;     /* If known, else 0 */
    
    /* Memory access */
    bool reads_memory;
    bool writes_memory;
    
    /* x86-specific */
    bool has_lock;
    bool has_rep;
    bool has_rex;
    uint8_t rex;
    
    /* ARM-specific */
    uint32_t encoding;          /* Full 32-bit instruction word */
    
} CosmoInsn;

/* ============================================================================
 * Disassembler Context
 * ============================================================================ */

typedef struct CosmoDisasm CosmoDisasm;

/* Create/destroy context */
CosmoDisasm *cosmo_disasm_create(CosmoArch arch);
void cosmo_disasm_free(CosmoDisasm *ctx);

/* Set architecture (can change for multi-arch files) */
void cosmo_disasm_set_arch(CosmoDisasm *ctx, CosmoArch arch);
CosmoArch cosmo_disasm_get_arch(const CosmoDisasm *ctx);

/* ============================================================================
 * Disassembly Functions
 * ============================================================================ */

/* Disassemble single instruction
 * Returns: instruction length (>0) or 0 on failure */
int cosmo_disasm_one(CosmoDisasm *ctx,
                     const uint8_t *code, size_t size,
                     uint64_t address,
                     CosmoInsn *insn);

/* Disassemble multiple instructions
 * Returns: number of instructions decoded */
size_t cosmo_disasm_many(CosmoDisasm *ctx,
                         const uint8_t *code, size_t size,
                         uint64_t address,
                         size_t max_count,
                         CosmoInsn **insns);  /* Caller frees with cosmo_disasm_free_insns */

/* Free instruction array from cosmo_disasm_many */
void cosmo_disasm_free_insns(CosmoInsn *insns, size_t count);

/* ============================================================================
 * Analysis Helpers
 * ============================================================================ */

/* Check if bytes look like a function prologue */
bool cosmo_is_prologue(CosmoArch arch, const uint8_t *code, size_t size);

/* Check if bytes look like a function epilogue */
bool cosmo_is_epilogue(CosmoArch arch, const uint8_t *code, size_t size);

/* Get instruction length without full decode */
int cosmo_insn_length(CosmoArch arch, const uint8_t *code, size_t size);

/* Check if instruction modifies a register */
bool cosmo_insn_writes_reg(const CosmoInsn *insn, int reg_id);
bool cosmo_insn_reads_reg(const CosmoInsn *insn, int reg_id);

/* ============================================================================
 * Register Name Helpers
 * ============================================================================ */

/* Get register name for architecture-specific ID */
const char *cosmo_reg_name(CosmoArch arch, int reg_id);

/* Get register size in bytes */
int cosmo_reg_size(CosmoArch arch, int reg_id);

/* Map between unified CosmoRegClass and architecture-specific IDs */
int cosmo_reg_to_arch(CosmoArch arch, CosmoRegClass reg_class);
CosmoRegClass cosmo_reg_from_arch(CosmoArch arch, int reg_id);

/* ============================================================================
 * Architecture Detection
 * ============================================================================ */

/* Detect architecture from ELF/PE headers */
CosmoArch cosmo_detect_arch_elf(const uint8_t *data, size_t size);
CosmoArch cosmo_detect_arch_pe(const uint8_t *data, size_t size);

/* Detect architecture from APE binary (Cosmopolitan portable executable) */
CosmoArch cosmo_detect_arch_ape(const uint8_t *data, size_t size);

/* ============================================================================
 * Version Information
 * ============================================================================ */

#define COSMO_DISASM_VERSION_MAJOR 1
#define COSMO_DISASM_VERSION_MINOR 0
#define COSMO_DISASM_VERSION_PATCH 0

const char *cosmo_disasm_version(void);

#ifdef __cplusplus
}
#endif

#endif /* COSMO_DISASM_H */
