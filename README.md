# Assemble

A high-performance, memory-safe, zero-compromise assembly engineering engine, automated self-healing fixer, and generalized knowledge graph built in **Rust** for AI agents and systems engineers.

> **Language**: `Rust 1.93+` &nbsp;|&nbsp; **License**: `MIT` &nbsp;|&nbsp; **Interface**: `MCP (JSON-RPC 2.0)` &nbsp;|&nbsp; **Architectures**: `x86_64` · `ARM64` · `RISC-V`

---

## 🚀 Core Capabilities

1. **Strict Static ABI & Trap Linter** (`assemble lint`):
   - **x86_64 (Windows x64 & System V AMD64)**: Stack alignment (16-byte RSP boundary), 32-byte shadow space allocation, callee-saved register clobbers (`rbx, rbp, rdi, rsi, r12-r15`), vector register preservation (`xmm6-xmm15`), destructive `cqo`/`cdq` divisor clobbering, unchecked arithmetic overflow on `imul`, and unchecked division (`idiv`) hardware `#DE` crashes.
   - **ARM64 (AAPCS64)**: Frame pointer (`x29`) and link register (`x30`) preservation across `bl` calls, callee-saved registers (`x19-x28`, `d8-d15`), and silent division-by-zero detection (`sdiv`/`udiv` returns 0 without faulting).
   - **RISC-V (LP64 / RV64G)**: Return address (`ra`/`x1`) preservation across `call`/`jal`, callee-saved registers (`s0-s11`, `fs0-fs11`), and silent zero-division detection (`div` returns -1, `rem` returns dividend).

2. **Automated Self-Healing & Error Correction** (`assemble fix` / MCP `asm_fix`):
   - Automatically repairs stack misalignment (`sub rsp, N` / `add rsp, N`).
   - Automatically allocates Windows 32-byte shadow space with 16-byte alignment.
   - Automatically injects `push` in prologue and `pop` before `ret` for all clobbered callee-saved registers.
   - Automatically inserts `vzeroupper` before `ret` to eliminate AVX-to-SSE transition stalls.
   - Automatically replaces `mov reg, 0` with zero-latency `xor reg32, reg32`.
   - Automatically splits invalid 64-bit direct memory writes into intermediate register loads.

3. **Absolute Safety Guardrails & Host Protection** (`assemble audit` / MCP `asm_audit_safety`):
   - **Privileged Instruction Guard**: Blocks Ring 0 instructions (`cli`, `sti`, `hlt`, `in`, `out`, `wrmsr`, `invd`, `swapgs`, `sysenter`).
   - **Exploit Pattern Guard**: Detects NOP sleds (4+ consecutive NOPs) and GetPC shellcode stubs (`call $+5; pop reg`).
   - **Unprobed Stack Frame Guard**: Flags allocations > 4096 bytes without `__chkstk` to prevent OS guard page bypasses.
   - **Division Safety Guard**: Detects unchecked divisors before `div`/`idiv`.
   - **Execution Sandboxing**: Emulation runs inside memory-isolated structures with hard step limits (1000 steps max) to prevent infinite loops.

4. **Generalized, Auto-Updating Knowledge Graph** (`assemble query` & `assemble update`):
   - Relational graph connecting instructions, CPU flags (`CF, ZF, SF, OF, AF, PF`), registers, ABIs, and syscalls.
   - Live synchronization fetching updated latency and throughput measurements across Intel and AMD microarchitectures.
   - Local persistent caching in `%LOCALAPPDATA%\assemble\knowledge_cache.json`.

5. **Step-by-Step Symbolic & Concrete Tracer** (`assemble trace`):
   - Simulates instruction execution without OS crashes or risk of kernel panic.
   - Displays instruction-by-instruction register mutation diffs (`RAX: 0x00 -> 0x2A`), CPU flag transitions (`ZF: false -> true`), and stack memory writes.

6. **Model Context Protocol (MCP) Server** (`assemble mcp`):
   - Native JSON-RPC 2.0 stdio server ready for direct plug-in to Google Antigravity, Claude Code, Cursor, and custom agent pipelines.

---

## 🛠️ Installation

```bash
# Clone and build from source
git clone https://github.com/shiva2321/Assemble.git
cd Assemble
cargo build --release

# Or install directly with Cargo
cargo install --git https://github.com/shiva2321/Assemble.git
```

---

## 📦 Quick Start

### Self-Healing Broken Assembly
```bash
# Preview automated repairs
assemble fix broken.asm --abi windows

# Automatically overwrite broken file with repaired, compliant code
assemble fix broken.asm --abi windows --write
```

### Auditing Safety Guardrails
```bash
assemble audit code.asm
```

### Running the Multi-Architecture Static Linter
```bash
# x86_64 Windows ABI
assemble lint routine.asm --arch x86_64 --abi windows

# ARM64 AAPCS64
assemble lint routine.s --arch arm64

# RISC-V LP64
assemble lint routine.s --arch riscv
```

### Knowledge Graph Query
```bash
assemble query xor
assemble query windows
assemble query idiv
```

### Optimization Catalog & Idioms
```bash
assemble idiom
assemble idiom branchless
assemble idiom arithmetic
assemble idiom atomic
```

### Step-by-Step Execution Trace
```bash
assemble trace routine.asm --reg rax=10 --reg rbx=32
```

### Connecting to AI Agents via MCP
Add to your agent's MCP configuration:
```json
{
  "mcpServers": {
    "assemble": {
      "command": "assemble",
      "args": ["mcp"]
    }
  }
}
```

---

## 🧮 Real-World Showcase: 64-Bit Windows Assembly Calculator

Included in [`calculator/`](calculator/) is a fully functional, zero-CRT, 4 KB 64-bit Windows console calculator written in pure x86_64 assembly (NASM + MSVC Linker).

It demonstrates Assemble's zero-compromise engineering:
- **Checked signed 64-bit arithmetic** (`+`, `-`, `*`) with overflow trap detection.
- **Precision decimal fraction expansion** (`1/3` $\rightarrow$ `0.333333`, `9/7` $\rightarrow$ `1.285714`, `1215646581523853/2` $\rightarrow$ `607823290761926.5`).
- **Zero-runtime division guards** preventing hardware `#DE` crashes on zero division and `INT64_MIN / -1`.
- **Branchless absolute value** (`|-99|` $\rightarrow$ `99`) using the Assemble optimization catalog.

Build and verify with:
```powershell
powershell -ExecutionPolicy Bypass -File .\calculator\run_tests.ps1
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
