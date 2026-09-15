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
   - **Context-Aware Execution Modes** (`--mode user`, `--mode kernel`, `--mode baremetal`): Permits Ring 0 instructions (`cli`, `sti`, `in`, `out`, `wrmsr`, `iretq`) when building drivers and kernel components, while blocking them in user applications.
   - **Driver-Specific Hazard Auditing**: Detects interrupt leaks (`cli` without matching `sti` before `ret`), and spinlock pipeline stalls (busy-wait loops lacking hardware `pause` backoff).
   - **Host & Exploit Protection**: Blocks NOP sleds (4+ consecutive NOPs) and GetPC shellcode stubs (`call $+5; pop reg`).
   - **Unprobed Stack Frame Guard**: Flags allocations > 4096 bytes without `__chkstk` to prevent OS guard page bypasses.
   - **Division Safety Guard**: Detects unchecked divisors before `div`/`idiv`.
   - **Execution Sandboxing**: Emulation runs inside memory-isolated structures with hard step limits to prevent infinite loops.

4. **Production Scaffolding & Driver Templates** (`assemble template` / MCP `asm_template`):
   - **`baremetal-uart`**: Complete 16550A UART serial driver with baud rate divisor, 8-N-1 configuration, and TX/RX FIFO routines.
   - **`kernel-isr`**: Production x86_64 Interrupt Service Routine frame with full general-purpose register preservation, 16-byte stack realignment, and `iretq`.
   - **`spinlock`**: Multi-core atomic ticket spinlock with `pause` pipeline backoff and `mfence`/`sfence` memory barriers.
   - **`bignum-math`**: 128-bit multi-precision integer addition, subtraction, and multiplication kernel using chained `adc` and `sbb`.
   - **`standalone-cli`**: Zero-CRT standalone Windows x64 console application with direct Win32 API calls (`GetStdHandle`, `WriteFile`, `ExitProcess`).

5. **Integrated Machine Code Assembler & Disassembler** (`assemble asm`, `assemble disasm` / MCP `asm_assemble`, `asm_disassemble`):
   - Directly compiles assembly text into raw machine code bytes and formatted hex without external file management.
   - Disassembles machine code byte streams into Intel, AT&T, NASM, or MASM syntax with control flow analysis.

6. **Generalized, Auto-Updating Knowledge Graph** (`assemble query` & `assemble update`):
   - Relational graph connecting instructions, CPU flags (`CF, ZF, SF, OF, AF, PF`), registers, ABIs, and syscalls.
   - Live synchronization fetching updated latency and throughput measurements across Intel and AMD microarchitectures.
   - Includes Windows Kernel (`x64-kernel`) and Linux Kernel (`linux-kernel`) calling conventions.

7. **Step-by-Step Symbolic & Concrete Tracer** (`assemble trace` / MCP `asm_trace`):
   - Simulates instruction execution without OS crashes or risk of kernel panic.
   - Fully supports arithmetic (`add`, `sub`, `mul`, `imul`, `adc`, `sbb`), bitwise operations (`and`, `or`, `xor`, `not`, `shl`, `shr`, `bswap`), memory swaps (`xchg`), effective address computation (`lea`), flag operations (`clc`, `stc`, `cmc`, `cld`, `std`), and pipeline hints (`pause`).
   - Displays instruction-by-instruction register mutation diffs, flag transitions, and memory writes.

8. **Model Context Protocol (MCP) Server** (`assemble mcp`):
   - Native JSON-RPC 2.0 stdio server providing 9 specialized tools directly into AI agents (Google Antigravity, Claude Code, Cursor).

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

### Auditing Safety Guardrails (User vs. Kernel Mode)
```bash
# Audit user-space assembly (flags Ring 0 instructions as dangerous)
assemble audit code.asm

# Audit driver/kernel assembly (permits Ring 0, audits interrupt leaks & spinlock stalls)
assemble audit driver.asm --mode kernel
```

### Production Scaffolding & Driver Templates
```bash
# List all production templates
assemble template list

# Inspect or output a bare-metal 16550A UART driver
assemble template baremetal-uart -o uart_driver.asm

# Generate an x86_64 Interrupt Service Routine (ISR) frame
assemble template kernel-isr -o isr.asm

# Generate an atomic multi-core ticket spinlock
assemble template spinlock -o spinlock.asm
```

### Direct Machine Code Assembly & Disassembly
```bash
# Assemble code directly to machine bytes and hex
assemble asm "mov rax, 42\nret"

# Disassemble hex bytes
assemble disasm "48 31 c0 c3" --syntax intel
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
