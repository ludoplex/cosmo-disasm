/*
 * test_disasm.c - Basic tests for cosmo-disasm library
 * 
 * Tests:
 *   1. x86-64 instruction decoding
 *   2. ARM64 instruction decoding
 *   3. Prologue/epilogue detection
 *   4. Architecture detection
 * 
 * Copyright (C) 2024-2026 Cosmopolitan Contributors
 * License: ISC
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../include/cosmo_disasm.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-40s", #name); \
    fflush(stdout); \
    test_##name(); \
    printf(" [OK]\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf(" [FAIL]\n    Assertion failed: %s\n    at %s:%d\n", \
               #cond, __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf(" [FAIL]\n    Expected: \"%s\"\n    Got: \"%s\"\n    at %s:%d\n", \
               (b), (a), __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* ============================================================================
 * x86-64 Tests
 * ============================================================================ */

TEST(x86_nop)
{
    uint8_t code[] = { 0x90 };  /* nop */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 1);
    ASSERT_STR_EQ(insn.mnemonic, "nop");
    ASSERT(insn.category == COSMO_CAT_NOP);
    
    cosmo_disasm_free(ctx);
}

TEST(x86_push_pop)
{
    uint8_t code[] = { 0x55, 0x5D };  /* push rbp; pop rbp */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    
    /* push rbp */
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    ASSERT(len == 1);
    ASSERT_STR_EQ(insn.mnemonic, "push");
    ASSERT(insn.category == COSMO_CAT_STACK);
    
    /* pop rbp */
    len = cosmo_disasm_one(ctx, code + 1, sizeof(code) - 1, 0x1001, &insn);
    ASSERT(len == 1);
    ASSERT_STR_EQ(insn.mnemonic, "pop");
    
    cosmo_disasm_free(ctx);
}

TEST(x86_ret)
{
    uint8_t code[] = { 0xC3 };  /* ret */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 1);
    ASSERT_STR_EQ(insn.mnemonic, "ret");
    ASSERT(insn.is_return == true);
    ASSERT(insn.is_branch == true);
    ASSERT(insn.category == COSMO_CAT_RETURN);
    
    cosmo_disasm_free(ctx);
}

TEST(x86_call)
{
    uint8_t code[] = { 0xE8, 0x10, 0x00, 0x00, 0x00 };  /* call +0x10 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 5);
    ASSERT_STR_EQ(insn.mnemonic, "call");
    ASSERT(insn.is_call == true);
    ASSERT(insn.is_branch == true);
    ASSERT(insn.branch_target == 0x1015);  /* 0x1000 + 5 + 0x10 */
    
    cosmo_disasm_free(ctx);
}

TEST(x86_jmp)
{
    uint8_t code[] = { 0xEB, 0x10 };  /* jmp short +0x10 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 2);
    ASSERT_STR_EQ(insn.mnemonic, "jmp");
    ASSERT(insn.is_branch == true);
    ASSERT(insn.branch_target == 0x1012);  /* 0x1000 + 2 + 0x10 */
    
    cosmo_disasm_free(ctx);
}

TEST(x86_jcc)
{
    uint8_t code[] = { 0x74, 0x10 };  /* jz +0x10 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 2);
    ASSERT_STR_EQ(insn.mnemonic, "jz");
    ASSERT(insn.is_branch == true);
    ASSERT(insn.is_conditional == true);
    
    cosmo_disasm_free(ctx);
}

TEST(x86_mov_reg_imm)
{
    uint8_t code[] = { 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00 };
    /* movabs rax, 0x12345678 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 10);
    ASSERT_STR_EQ(insn.mnemonic, "mov");
    ASSERT(insn.num_operands == 2);
    ASSERT(insn.operands[0].type == COSMO_OP_REG);
    ASSERT(insn.operands[1].type == COSMO_OP_IMM);
    ASSERT(insn.operands[1].imm.value == 0x12345678);
    
    cosmo_disasm_free(ctx);
}

TEST(x86_syscall)
{
    uint8_t code[] = { 0x0F, 0x05 };  /* syscall */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 2);
    ASSERT_STR_EQ(insn.mnemonic, "syscall");
    ASSERT(insn.category == COSMO_CAT_SYSTEM);
    
    cosmo_disasm_free(ctx);
}

TEST(x86_prologue_detection)
{
    /* Standard prologue: push rbp; mov rbp, rsp */
    uint8_t prologue1[] = { 0x55, 0x48, 0x89, 0xE5 };
    ASSERT(cosmo_is_prologue(COSMO_ARCH_X86_64, prologue1, sizeof(prologue1)) == true);
    
    /* CET prologue: endbr64; push rbp */
    uint8_t prologue2[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0x55 };
    ASSERT(cosmo_is_prologue(COSMO_ARCH_X86_64, prologue2, sizeof(prologue2)) == true);
    
    /* Not a prologue */
    uint8_t not_prologue[] = { 0xC3 };  /* ret */
    ASSERT(cosmo_is_prologue(COSMO_ARCH_X86_64, not_prologue, sizeof(not_prologue)) == false);
}

TEST(x86_epilogue_detection)
{
    /* ret */
    uint8_t epilogue1[] = { 0xC3 };
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_X86_64, epilogue1, sizeof(epilogue1)) == true);
    
    /* leave; ret */
    uint8_t epilogue2[] = { 0xC9, 0xC3 };
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_X86_64, epilogue2, sizeof(epilogue2)) == true);
    
    /* pop rbp; ret */
    uint8_t epilogue3[] = { 0x5D, 0xC3 };
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_X86_64, epilogue3, sizeof(epilogue3)) == true);
    
    /* Not an epilogue */
    uint8_t not_epilogue[] = { 0x55 };  /* push rbp */
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_X86_64, not_epilogue, sizeof(not_epilogue)) == false);
}

/* ============================================================================
 * ARM64 Tests
 * ============================================================================ */

TEST(arm64_nop)
{
    uint8_t code[] = { 0x1F, 0x20, 0x03, 0xD5 };  /* nop */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "nop");
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_ret)
{
    uint8_t code[] = { 0xC0, 0x03, 0x5F, 0xD6 };  /* ret */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "ret");
    ASSERT(insn.is_return == true);
    ASSERT(insn.is_branch == true);
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_bl)
{
    uint8_t code[] = { 0x04, 0x00, 0x00, 0x94 };  /* bl +0x10 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "bl");
    ASSERT(insn.is_call == true);
    ASSERT(insn.is_branch == true);
    ASSERT(insn.branch_target == 0x1010);  /* 0x1000 + 4*4 */
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_b)
{
    uint8_t code[] = { 0x04, 0x00, 0x00, 0x14 };  /* b +0x10 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "b");
    ASSERT(insn.is_branch == true);
    ASSERT(insn.is_call == false);
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_b_cond)
{
    uint8_t code[] = { 0x40, 0x00, 0x00, 0x54 };  /* b.eq +8 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "b.eq");
    ASSERT(insn.is_branch == true);
    ASSERT(insn.is_conditional == true);
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_svc)
{
    uint8_t code[] = { 0x01, 0x00, 0x00, 0xD4 };  /* svc #0 */
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_AARCH64);
    ASSERT(ctx != NULL);
    
    CosmoInsn insn;
    int len = cosmo_disasm_one(ctx, code, sizeof(code), 0x1000, &insn);
    
    ASSERT(len == 4);
    ASSERT_STR_EQ(insn.mnemonic, "svc");
    ASSERT(insn.category == COSMO_CAT_SYSTEM);
    
    cosmo_disasm_free(ctx);
}

TEST(arm64_prologue_detection)
{
    /* STP x29, x30, [sp, #-16]! - typical prologue */
    uint8_t prologue1[] = { 0xFD, 0x7B, 0xBF, 0xA9 };
    ASSERT(cosmo_is_prologue(COSMO_ARCH_AARCH64, prologue1, sizeof(prologue1)) == true);
    
    /* PACIASP (PAC prologue) */
    uint8_t prologue2[] = { 0x3F, 0x23, 0x03, 0xD5 };
    ASSERT(cosmo_is_prologue(COSMO_ARCH_AARCH64, prologue2, sizeof(prologue2)) == true);
    
    /* Not a prologue */
    uint8_t not_prologue[] = { 0xC0, 0x03, 0x5F, 0xD6 };  /* ret */
    ASSERT(cosmo_is_prologue(COSMO_ARCH_AARCH64, not_prologue, sizeof(not_prologue)) == false);
}

TEST(arm64_epilogue_detection)
{
    /* ret */
    uint8_t epilogue1[] = { 0xC0, 0x03, 0x5F, 0xD6 };
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_AARCH64, epilogue1, sizeof(epilogue1)) == true);
    
    /* retaa (PAC) */
    uint8_t epilogue2[] = { 0xFF, 0x0B, 0x5F, 0xD6 };
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_AARCH64, epilogue2, sizeof(epilogue2)) == true);
    
    /* Not an epilogue */
    uint8_t not_epilogue[] = { 0xFD, 0x7B, 0xBF, 0xA9 };  /* stp */
    ASSERT(cosmo_is_epilogue(COSMO_ARCH_AARCH64, not_epilogue, sizeof(not_epilogue)) == false);
}

/* ============================================================================
 * Multi-instruction Tests
 * ============================================================================ */

TEST(x86_disasm_many)
{
    /* push rbp; mov rbp, rsp; sub rsp, 0x20; ret */
    uint8_t code[] = { 
        0x55,                   /* push rbp */
        0x48, 0x89, 0xE5,       /* mov rbp, rsp */
        0x48, 0x83, 0xEC, 0x20, /* sub rsp, 0x20 */
        0xC3                    /* ret */
    };
    
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    ASSERT(ctx != NULL);
    
    CosmoInsn *insns;
    size_t count = cosmo_disasm_many(ctx, code, sizeof(code), 0x1000, 10, &insns);
    
    ASSERT(count == 4);
    ASSERT_STR_EQ(insns[0].mnemonic, "push");
    ASSERT_STR_EQ(insns[1].mnemonic, "mov");
    ASSERT_STR_EQ(insns[2].mnemonic, "sub");
    ASSERT_STR_EQ(insns[3].mnemonic, "ret");
    
    cosmo_disasm_free_insns(insns, count);
    cosmo_disasm_free(ctx);
}

/* ============================================================================
 * Architecture Detection Tests
 * ============================================================================ */

TEST(detect_arch_elf_x86_64)
{
    /* Minimal ELF header for x86-64 */
    uint8_t elf_x64[] = {
        0x7F, 'E', 'L', 'F',     /* ELF magic */
        0x02, 0x01, 0x01, 0x00,  /* Class, endian, version, OS/ABI */
        0x00, 0x00, 0x00, 0x00,  /* Padding */
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,              /* Type: ET_EXEC */
        0x3E, 0x00,              /* Machine: EM_X86_64 */
    };
    
    ASSERT(cosmo_detect_arch_elf(elf_x64, sizeof(elf_x64)) == COSMO_ARCH_X86_64);
}

TEST(detect_arch_elf_aarch64)
{
    /* Minimal ELF header for AArch64 */
    uint8_t elf_a64[] = {
        0x7F, 'E', 'L', 'F',     /* ELF magic */
        0x02, 0x01, 0x01, 0x00,  /* Class, endian, version, OS/ABI */
        0x00, 0x00, 0x00, 0x00,  /* Padding */
        0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,              /* Type: ET_EXEC */
        0xB7, 0x00,              /* Machine: EM_AARCH64 */
    };
    
    ASSERT(cosmo_detect_arch_elf(elf_a64, sizeof(elf_a64)) == COSMO_ARCH_AARCH64);
}

/* ============================================================================
 * Version Test
 * ============================================================================ */

TEST(version)
{
    const char *ver = cosmo_disasm_version();
    ASSERT(ver != NULL);
    ASSERT(strstr(ver, "cosmo-disasm") != NULL);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void)
{
    printf("=== cosmo-disasm Test Suite ===\n\n");
    
    printf("x86-64 Tests:\n");
    RUN_TEST(x86_nop);
    RUN_TEST(x86_push_pop);
    RUN_TEST(x86_ret);
    RUN_TEST(x86_call);
    RUN_TEST(x86_jmp);
    RUN_TEST(x86_jcc);
    RUN_TEST(x86_mov_reg_imm);
    RUN_TEST(x86_syscall);
    RUN_TEST(x86_prologue_detection);
    RUN_TEST(x86_epilogue_detection);
    
    printf("\nARM64 Tests:\n");
    RUN_TEST(arm64_nop);
    RUN_TEST(arm64_ret);
    RUN_TEST(arm64_bl);
    RUN_TEST(arm64_b);
    RUN_TEST(arm64_b_cond);
    RUN_TEST(arm64_svc);
    RUN_TEST(arm64_prologue_detection);
    RUN_TEST(arm64_epilogue_detection);
    
    printf("\nMulti-instruction Tests:\n");
    RUN_TEST(x86_disasm_many);
    
    printf("\nArchitecture Detection Tests:\n");
    RUN_TEST(detect_arch_elf_x86_64);
    RUN_TEST(detect_arch_elf_aarch64);
    
    printf("\nMisc Tests:\n");
    RUN_TEST(version);
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
