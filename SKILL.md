---
name: assemble
description: Comprehensive assembly programming toolkit and knowledge graph for AI agents covering x86_64, ARM64, and RISC-V with absolute safety guardrails, automated error corrections, execution tracing, ABI verification, and micro-optimization idioms.
---

# Assemble: AI Agent Assembly Programming Skill

When writing, reviewing, repairing, optimizing, or debugging assembly language code across **x86_64**, **ARM64 (AArch64)**, and **RISC-V**, use the `assemble` engine to guarantee absolute safety, ABI compliance, and self-healing error correction.

---

## 1. Safety Guardrails & Absolute Host Protections

1. **Privileged Instruction Guard**: Ring 0 instructions (`cli`, `sti`, `hlt`, `in`, `out`, `wrmsr`, `rdmsr`, `invd`, `swapgs`, `sysenter`, `sysexit`) are detected and blocked from execution to prevent General Protection Faults (#GP) or host tampering.
2. **Exploit & Shellcode Heuristics**: Detects NOP sleds (4+ consecutive NOPs) and GetPC stubs (`call $+5 ; pop reg`).
3. **Large Stack Frame Probe Guard**: Flags allocations exceeding 4096 bytes without `__chkstk` to prevent OS guard page bypass.
4. **Division Safety Guard**: Detects unchecked divisors before `div`/`idiv`.
5. **Execution Sandboxing**: Emulation is executed in memory-isolated structures with maximum step limits (default 1000) to prevent denial-of-service / infinite loops.

---

## 2. Automated Self-Healing & Error Corrections (`assemble fix`)

Whenever the linter flags issues, run `assemble fix <file>` (or MCP tool `asm_fix`) to automatically repair the source code:
- **Stack Alignment & Shadow Space**: Automatically inserts `sub rsp, 40` (or `sub rsp, 32`) in prologue and `add rsp, 40` before `ret` to guarantee 16-byte alignment and Windows home space.
- **Callee-Saved Register Preservation**: Automatically inserts `push <reg>` in prologue and `pop <reg>` in epilogue for all modified non-volatile registers (`rbx, rbp, rdi, rsi, r12-r15`).
- **AVX-to-SSE Transitions**: Automatically inserts `vzeroupper` before `ret`.
- **Zero-Latency Register Clearing**: Automatically converts `mov reg, 0` into `xor reg32, reg32`.
- **64-bit Direct Memory Write Split**: Splits `mov [mem], imm64` into a register load intermediate.

---

## 3. Toolkit Tools Reference

| Command | MCP Tool | Purpose |
|---|---|---|
| `assemble lint <file>` | `asm_lint` | Statically checks ABI compliance, stack alignment, shadow space, and CQO clobbers |
| `assemble fix <file>` | `asm_fix` | **Self-healing auto-repair**: rewrites broken asm into clean, compliant code |
| `assemble audit <file>` | `asm_audit_safety` | Audits safety guardrails, privileged instructions, exploit patterns |
| `assemble trace <file>` | `asm_trace` | Simulates step-by-step execution, outputs register diffs & flag changes |
| `assemble query <term>` | `asm_query` | Queries knowledge graph for instructions, flags, ABIs, and syscalls |
| `assemble idiom <cat>` | `asm_idiom` | Retrieves branchless, bitwise, SIMD, and atomic optimizations |
| `assemble update` | `asm_update_kg` | Synchronizes knowledge base with latest CPU specs and latencies |
| `assemble mcp` | N/A | Starts the stdio JSON-RPC 2.0 MCP server for AI agents |
