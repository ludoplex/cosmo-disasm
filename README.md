# cosmo-disasm

A lightweight, cross-platform disassembler library for x86-64 and AArch64, built with Cosmopolitan Libc.

## Features

- **Multi-architecture support**: x86-64 and ARM64 (AArch64)
- **Unified API**: Same interface for all architectures
- **Zero dependencies**: Self-contained, no external libraries needed
- **Actually Portable**: Builds to APE format, runs on Linux, macOS, Windows, FreeBSD, and more
- **Lightweight**: Minimal footprint, suitable for embedding
- **Function detection**: Prologue/epilogue recognition for x86-64 and ARM64

## Building

Requires `cosmocc` (Cosmopolitan C Compiler) in your PATH.

```bash
# Build library and tests
make

# Run tests
make test

# Install to /opt/cosmo
make install PREFIX=/opt/cosmo

# Clean build artifacts
make clean
```

## Quick Start

```c
#include "cosmo_disasm.h"

int main(void) {
    // Create disassembler for x86-64
    CosmoDisasm *ctx = cosmo_disasm_create(COSMO_ARCH_X86_64);
    
    // Sample code: push rbp; mov rbp, rsp; ret
    uint8_t code[] = { 0x55, 0x48, 0x89, 0xE5, 0xC3 };
    
    // Disassemble
    CosmoInsn insn;
    size_t offset = 0;
    
    while (offset < sizeof(code)) {
        int len = cosmo_disasm_one(ctx, code + offset, sizeof(code) - offset,
                                   0x1000 + offset, &insn);
        if (len <= 0) break;
        
        printf("%016llx  %s\n", insn.address, insn.text);
        offset += len;
    }
    
    cosmo_disasm_free(ctx);
    return 0;
}
```

Output:
```
0000000000001000  push rbp
0000000000001001  mov rbp, rsp
0000000000001004  ret
```

## API Overview

### Context Management

```c
// Create/destroy
CosmoDisasm *cosmo_disasm_create(CosmoArch arch);
void cosmo_disasm_free(CosmoDisasm *ctx);

// Change architecture
void cosmo_disasm_set_arch(CosmoDisasm *ctx, CosmoArch arch);
```

### Disassembly

```c
// Single instruction
int cosmo_disasm_one(CosmoDisasm *ctx, const uint8_t *code, size_t size,
                     uint64_t address, CosmoInsn *insn);

// Multiple instructions
size_t cosmo_disasm_many(CosmoDisasm *ctx, const uint8_t *code, size_t size,
                         uint64_t address, size_t max_count, CosmoInsn **insns);

void cosmo_disasm_free_insns(CosmoInsn *insns, size_t count);
```

### Analysis Helpers

```c
// Function boundary detection
bool cosmo_is_prologue(CosmoArch arch, const uint8_t *code, size_t size);
bool cosmo_is_epilogue(CosmoArch arch, const uint8_t *code, size_t size);

// Quick length check
int cosmo_insn_length(CosmoArch arch, const uint8_t *code, size_t size);

// Register analysis
bool cosmo_insn_writes_reg(const CosmoInsn *insn, int reg_id);
bool cosmo_insn_reads_reg(const CosmoInsn *insn, int reg_id);
```

### Architecture Detection

```c
CosmoArch cosmo_detect_arch_elf(const uint8_t *data, size_t size);
CosmoArch cosmo_detect_arch_pe(const uint8_t *data, size_t size);
CosmoArch cosmo_detect_arch_ape(const uint8_t *data, size_t size);
```

## Supported Architectures

| Architecture | Status | Notes |
|--------------|--------|-------|
| x86-64 | ✅ Full | Most common instructions |
| x86 (32-bit) | ✅ Partial | Basic support |
| AArch64 | ✅ Full | Most common instructions |
| ARM (32-bit) | 🚧 Future | Not yet implemented |

## Instruction Coverage

### x86-64
- Data transfer: MOV, PUSH, POP, LEA, XCHG
- Arithmetic: ADD, SUB, MUL, DIV, INC, DEC
- Logical: AND, OR, XOR, NOT, TEST
- Control flow: JMP, Jcc, CALL, RET
- System: SYSCALL, CPUID, INT3, HLT
- Multi-byte NOP (0F 1F)

### ARM64
- Data processing: ADD, SUB, AND, ORR, EOR, MOV
- Load/Store: LDR, STR, LDP, STP
- Branches: B, BL, BR, BLR, RET, B.cond, CBZ/CBNZ, TBZ/TBNZ
- PC-relative: ADR, ADRP
- System: SVC, HVC, SMC, NOP, barriers, MSR/MRS
- PAC: PACIASP, PACIBSP, RETAA, RETAB

## Integration

### With tedit-cosmo
```c
// Add disassembly view for binary files
if (is_binary_file(filename)) {
    CosmoArch arch = cosmo_detect_arch_elf(data, size);
    CosmoDisasm *ctx = cosmo_disasm_create(arch);
    // ... disassemble and display
}
```

### With e9studio
This library was extracted from e9studio's disassembler. Use it to share
disassembly logic across projects.

## License

ISC License (permissive, BSD-like).

Based on e9studio's disassembler (GPLv3+), rewritten for this library.

## Contributing

Part of the Cosmopolitan toolchain ecosystem. See also:
- [tedit-cosmo](https://github.com/user/tedit-cosmo) - Terminal text editor
- [e9studio](https://github.com/user/e9studio) - Binary patching toolkit
- [Cosmopolitan Libc](https://github.com/jart/cosmopolitan) - The underlying libc

## Version History

- **1.0.0** - Initial release
  - x86-64 and ARM64 support
  - Unified API
  - Prologue/epilogue detection
  - Architecture detection (ELF, PE, APE)
