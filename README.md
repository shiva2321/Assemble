# Assemble

<p align="center">
  <strong>The Complete AI Agent Assembly Engineering Toolkit</strong><br/>
  <em>Compiler-grade static linter, automated self-healing fixer, dual-mode safety sandbox, production driver scaffolding, and generalized knowledge graph built in Rust.</em>
</p>

<p align="center">
  <a href="https://github.com/shiva2321/Assemble"><img src="https://img.shields.io/badge/tests-26%2F26%20passing-success?style=flat-square" alt="Tests"/></a>
  <a href="https://crates.io/"><img src="https://img.shields.io/badge/rust-1.93%2B-orange?style=flat-square&logo=rust" alt="Rust 1.93+"/></a>
  <a href="https://github.com/shiva2321/Assemble/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License MIT"/></a>
  <a href="https://modelcontextprotocol.io/"><img src="https://img.shields.io/badge/interface-MCP%20JSON--RPC%202.0-purple?style=flat-square" alt="MCP Compatible"/></a>
  <a href="#-architectures-supported"><img src="https://img.shields.io/badge/architectures-x86__64%20%7C%20ARM64%20%7C%20RISC--V-lightgrey?style=flat-square" alt="Architectures"/></a>
</p>

---

## 📖 Overview

Assembly language is unforgiving. A single missing 8-byte stack realignment crashes vectorized libc functions with General Protection Faults (`#GP`). Omitting the Windows 32-byte shadow space corrupts stack parameters upon calling Win32 APIs. Executing `imul` without checking the overflow flag silently corrupts 64-bit cryptographic calculations. In driver code, omitting a `pause` hint in spinloops causes severe pipeline memory-order violations, while returning with disabled interrupts (`cli` without `sti`) freezes entire CPU cores.

For AI agents generating, auditing, or refactoring low-level systems code, these minute hazards are catastrophic.

**Assemble** solves this problem by providing a compiler-grade toolkit tailored for both autonomous AI agents and systems engineers:
- **Strict Static ABI & Trap Linter**: Catches stack misalignment, missing shadow space, callee-saved clobbers, destructive sign extensions, unchecked `idiv` crashes, and silent RISC-V/ARM64 zero-division.
- **Automated Self-Healing (`assemble fix`)**: Parses broken assembly and rewrites it in-place with correct prologues, epilogues, shadow reservations, callee-saved preservation, and `vzeroupper` transition guards.
- **Context-Aware Safety Auditing (`assemble audit`)**: Supports **User**, **Kernel**, and **BareMetal** execution modes. Blocks hostile shellcode stubs and user-mode Ring 0 instructions while actively auditing driver-specific hazards (interrupt leakage, spinlock pipeline stalls).
- **Production Scaffolding & Driver Templates (`assemble template`)**: Battle-tested templates for bare-metal 16550A UART drivers, kernel Interrupt Service Routines (ISRs), atomic multi-core ticket spinlocks, 128-bit bignum arithmetic kernels, and zero-CRT standalone Windows binaries.
- **Direct Machine Code Assembler & Disassembler (`assemble asm` / `assemble disasm`)**: Compiles assembly into machine code bytes and hex or disassembles byte sequences with control flow annotations.
- **Step-by-Step Symbolic Tracer (`assemble trace`)**: Safely simulates instruction execution, tracking register mutations, CPU flag transitions (`ZF`, `CF`, `SF`, `OF`), effective address calculation (`lea`), chained `adc`/`sbb` carry propagation, and memory writes without triggering OS faults.
- **Auto-Updating Knowledge Graph (`assemble query` / `assemble update`)**: Relational graph linking instructions, cycle latencies, throughputs, CPU flags, ABIs, syscalls, and branchless optimization idioms.
- **Model Context Protocol (MCP) Server**: Exposes 9 specialized JSON-RPC tools over stdio for plug-and-play integration into Google Antigravity, Claude Code, Cursor, and autonomous agent loops.

---

## 🏛️ Architecture

```
                                 ┌────────────────────────┐
                                 │   AI Agent / Client    │
                                 │ (Claude / Antigravity) │
                                 └───────────┬────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │ CLI (clap v4)     │                       │ MCP Server (stdio)│
             └─────────┬─────────┘                       └─────────┬─────────┘
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                     ┌───────────────────────────────────────────────┐
                     │              Assemble Core Engine             │
                     ├───────────────────────┬───────────────────────┤
                     │ Static ABI Linter     │ Auto-Fixer & Healer   │
                     │ Dual-Mode Guardrails  │ Step-by-Step Tracer   │
                     │ Assembler / Disasm    │ Production Templates  │
                     │ Knowledge Graph Engine│ Microarchitecture DB  │
                     └───────────────────────┬───────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │    iced-x86 /     │                       │   Local Storage   │
             │   NASM Backend    │                       │  & Graph Cache    │
             └───────────────────┘                       └───────────────────┘
```

---

## 🚀 Key Capabilities & Modules

### 1. Multi-Architecture Static Linter (`assemble lint`)

Assemble statically verifies assembly files against architectural specifications and system ABIs, preventing crashes before machine code is ever emitted.

| Rule ID | Arch | Severity | Description & Hazard |
|---|---|---|---|
| `STACK_ALIGNMENT_VIOLATION` | x86_64 | **ERROR** | RSP is not 16-byte aligned immediately before a `call`. Causes `#GP` crashes in libc and SIMD instructions (`movaps`). |
| `WINDOWS_SHADOW_SPACE_MISSING` | x86_64 | **ERROR** | Function calls another routine without allocating at least 32 bytes (0x20) of home space on Windows x64. Corrupts caller frame. |
| `CALLEE_SAVED_REGISTER_CLOBBERED` | All | **ERROR** | Modifies non-volatile registers (`rbx, rbp, rdi, rsi, r12-r15` on x64; `x19-x28` on ARM64; `s0-s11` on RISC-V) without preservation. |
| `CALLEE_SAVED_XMM_CLOBBERED` | x86_64 | **WARN** | Modifies non-volatile vector registers (`xmm6-xmm15` on Windows) without saving them to stack. |
| `UNCHECKED_ARITHMETIC_OVERFLOW` | x86_64 | **WARN** | Performs signed multiplication (`imul`) without a subsequent `jo`/`jno` overflow check. |
| `UNCHECKED_IDIV_OVERFLOW` | x86_64 | **ERROR** | Executes `idiv` without verifying divisor $\neq 0$ and dividend $\neq \text{INT64\_MIN} / -1$. Causes immediate `#DE` hardware fault. |
| `DESTRUCTIVE_SIGN_EXTENSION` | x86_64 | **WARN** | Emits `cdq`/`cqo` which silently clobbers `rdx`/`edx`, destroying function arguments or pointers. |
| `AVX_SSE_TRANSITION_PENALTY` | x86_64 | **WARN** | Uses 256-bit AVX/AVX2 instructions without emitting `vzeroupper` before returning or calling legacy SSE code. |
| `ARM64_MISSING_FRAME_PAIR` | ARM64 | **ERROR** | Non-leaf routine calls `bl` without saving Frame Pointer (`x29`) and Link Register (`x30`) via `stp x29, x30, [sp, -16]!`. |
| `ARM64_SILENT_DIVISION_BY_ZERO` | ARM64 | **WARN** | `sdiv`/`udiv` on AArch64 returns 0 upon division by zero without raising an exception. Flags missing guards. |
| `RISCV_MISSING_RA_SAVE` | RISC-V | **ERROR** | Routine executes `call`/`jal` without saving return address `ra` (`x1`), causing an infinite loop or crash on `ret`. |
| `RISCV_SILENT_DIVISION_BY_ZERO` | RISC-V | **WARN** | RISC-V `div` returns -1 and `rem` returns the dividend on division by zero without faulting. Flags missing guards. |

---

### 2. Automated Self-Healing Engine (`assemble fix`)

Assemble automatically repairs broken assembly source files in-place:

```bash
assemble fix broken.asm --abi windows --write
```

#### What It Heals Automatically:
1. **Stack Misalignment**: Calculates net stack displacement across all `push`, `pop`, and `sub rsp` instructions, adjusting allocations to enforce strict `RSP % 16 == 0` alignment before every `call`.
2. **Windows Shadow Space**: Automatically inserts 32-byte shadow space in prologues and restores it in epilogues.
3. **Callee-Saved Register Spills**: Injects `push` in the prologue and corresponding `pop` in reverse order before every `ret` for all clobbered non-volatile registers.
4. **AVX Clean-up**: Inserts `vzeroupper` prior to function exit.
5. **Zero-Latency Zeroing**: Replaces power-inefficient `mov reg, 0` with zero-latency `xor reg32, reg32`.

```diff
  my_routine:
+     push rbx
+     push rsi
+     sub rsp, 40               ; 32-byte shadow space + 8-byte alignment
-     mov rbx, 100
+     mov rbx, 100
      vmovdqu ymm0, [rsi]
      call printf
+     vzeroupper
+     add rsp, 40
+     pop rsi
+     pop rbx
      ret
```

### 3. Context-Aware Safety & Driver Guardrails (`assemble audit`)

Assemble provides multi-tier safety sandboxing depending on the target execution context:

```bash
# Audit user-space code (Ring 0 instructions blocked to prevent crashes)
assemble audit user_app.asm --mode user

# Audit kernel / driver code (Ring 0 permitted, driver hazards audited)
assemble audit serial_driver.asm --mode kernel
```

#### User Mode vs. Kernel / Driver Mode:
| Check | User Mode (`--mode user`) | Kernel / Driver Mode (`--mode kernel`) |
|---|---|---|
| **Ring 0 Instructions** (`cli`, `sti`, `in`, `out`, `wrmsr`, `iretq`) | **BLOCKED (Dangerous)**: Prevents `#GP` crashes in user-space applications. | **PERMITTED (Safe)**: Valid driver and OS operations. |
| **Interrupt Leak Hazard** (`CLI_WITHOUT_STI`) | N/A | **BLOCKED (High Risk)**: Detects functions that disable interrupts with `cli` and exit via `ret` without re-enabling them via `sti` or `popfq`. |
| **Spinlock Pipeline Stalls** (`SPINLOCK_WITHOUT_PAUSE`) | N/A | **CAUTION**: Flags busy-wait loops lacking the `pause` instruction, preventing pipeline thrashing and memory-order violations on multi-core CPUs. |
| **Exploit Shellcode Patterns** | **BLOCKED**: Detects NOP sleds (4+ consecutive NOPs) and GetPC stubs (`call $+5; pop reg`). | **BLOCKED**: Same host protection. |
| **Unprobed Stack Allocations** | **BLOCKED**: Flags allocations > 4096 bytes lacking `__chkstk` stack probe calls. | **BLOCKED**: Prevents OS guard page bypasses. |
| **Host Sandboxing** | Emulation executes inside bounded memory structures with hard step limits (1000 steps). | Same execution sandboxing. |

---

### 4. Production Scaffolding & Driver Templates (`assemble template`)

Assemble provides battle-tested templates so AI agents and engineers can instantly scaffold drivers, kernel handlers, and mathematical kernels:

```bash
# List all available production templates
assemble template list

# Inspect or output a bare-metal 16550A UART driver
assemble template baremetal-uart -o uart.asm
```

| Template Name | Target ISA | Category | Description |
|---|---|---|---|
| **`baremetal-uart`** | x86_64 | Driver / Embedded | Complete 16550A serial UART driver with baud rate divisor calculation, line control setup (8-N-1), FIFO buffer enabling, and polled `uart_putc`, `uart_puts`, and `uart_getc` routines. |
| **`kernel-isr`** | x86_64 | Kernel / OS | Production x86_64 Interrupt Service Routine entry/exit frame with complete general-purpose register preservation, 16-byte stack realignment, and `iretq` dispatch. |
| **`spinlock`** | x86_64 | Concurrency / Sync | Hardware-optimized multi-core ticket spinlock featuring `pause` pipeline backoff, `lock bts` acquisition, and `sfence`/`mfence` memory synchronization barriers. |
| **`bignum-math`** | x86_64 | Cryptography / Math | 128-bit multi-precision integer addition, subtraction, and multiplication kernel utilizing chained `adc` and `sbb` carry propagation. |
| **`standalone-cli`** | x86_64 | User Applications | Zero-CRT standalone Windows x64 console application demonstrating raw Win32 system interaction (`GetStdHandle`, `WriteFile`, `ExitProcess`). |

---

### 5. Direct Machine Code Assembler & Disassembler (`assemble asm` / `assemble disasm`)

Assemble integrates compilation and disassembly directly into the CLI and MCP tools:

```bash
# Direct machine code compilation
assemble asm "mov rax, 42\nret"
# Output:
#   Generated 6 machine code bytes:
#   Hex:       b8 2a 00 00 00 c3
#   Formatted: 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3

# Multi-syntax disassembly with control flow annotations
assemble disasm "48 31 c0 c3" --syntax intel
# Output:
#   0x00400000:  xor rax, rax
#   0x00400003:  ret                      ; [RET]
```

---

### 6. Step-by-Step Symbolic & Concrete Tracer (`assemble trace`)

Assemble includes a lightweight, isolated emulator and tracer capable of stepping through machine code without risk of crashing the host process:

```bash
assemble trace routine.asm --reg rax=10 --reg rbx=0x20
```

- **Supported Instructions**: Arithmetic (`add`, `sub`, `mul`, `imul`, `adc`, `sbb`), bitwise (`and`, `or`, `xor`, `not`, `shl`, `shr`, `bswap`), data movement (`mov`, `xchg`, `lea`), flag modifiers (`clc`, `stc`, `cmc`, `cld`, `std`), and CPU hints (`pause`).
- **Detailed Diff Output**: Instruction-by-instruction register changes (`rax: 0x10 -> 0x20`), CPU flag transitions (`CF: false -> true`, `ZF: false -> true`), and memory stack writes.
- **Safety Limits**: Bounded execution (1000 step threshold) prevents infinite loops.

---

### 7. Generalized, Auto-Updating Knowledge Graph (`assemble query` / `assemble update`)

Assemble maintains a local relational knowledge graph connecting instructions, CPU flags (`CF, ZF, SF, OF, AF, PF`), registers, ABIs, and syscalls:

```bash
# Query instruction timings, operand rules, and hardware pitfalls
assemble query idiv
assemble query windows
assemble query spinlock

# Sync knowledge graph with upstream microarchitecture measurements
assemble update
```

- **Upstream Synchronization**: Fetches live microarchitecture measurements (Intel Alder Lake/Raptor Lake, AMD Zen 4/Zen 5) for instruction latency and reciprocal throughput.
- **Local Persistence**: Caches data locally in `%LOCALAPPDATA%\assemble\knowledge_cache.json` for instant offline query performance.

---

## 🤖 AI Agent Integration (Model Context Protocol)

Assemble implements a native JSON-RPC 2.0 stdio server conforming to the **Model Context Protocol (MCP)** specification, allowing AI agents to directly lint, fix, audit, assemble, disassemble, and trace assembly code.

### Adding Assemble to Your Agent Configuration

#### Claude Desktop (`claude_desktop_config.json`) / Google Antigravity
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

#### Cursor (`.cursor/mcp.json`)
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

### Complete MCP Tool Matrix (9 Tools)

| Tool Name | Parameters | Purpose & Output |
|---|---|---|
| `asm_lint` | `code: string`, `arch?: string`, `abi?: string` | Audits assembly for ABI violations, stack alignment, shadow space, and traps across x86_64, ARM64, and RISC-V. |
| `asm_fix` | `code: string`, `abi?: string` | Automatically repairs broken assembly, aligning stack frames, adding shadow space, and saving registers. |
| `asm_audit_safety` | `code: string`, `mode?: "user" \| "kernel" \| "baremetal"` | Audits code for safety hazards, privileged instructions, interrupt leaks, and spinlock stalls. |
| `asm_template` | `name: string` | Retrieves production scaffolding for UART drivers, ISR handlers, spinlocks, bignum arithmetic, or CLI apps. |
| `asm_assemble` | `code: string` | Compiles assembly text into machine code bytes and hex representation. |
| `asm_disassemble` | `hex_bytes: string`, `syntax?: string` | Disassembles raw machine code hex into formatted assembly with control flow markings. |
| `asm_trace` | `code: string`, `initial_registers?: object` | Executes assembly in a sandboxed emulator, returning register, flag, and memory mutations. |
| `asm_query` | `query: string` | Queries the assembly knowledge graph for instruction semantics, operand rules, CPU flags, and ABIs. |
| `asm_idiom` | `category: string` | Browses high-performance assembly idioms (branchless min/max, bit twiddling, SIMD, lockless sync). |

---

## 🧮 Real-World Showcases

### Showcase 1: Zero-CRT 64-Bit Assembly Calculator
Included in [`calculator/`](calculator/) is a fully functional, zero-CRT, 4 KB 64-bit Windows console calculator written in pure x86_64 assembly (NASM + MSVC Linker).

- **Checked Signed Arithmetic**: Addition, subtraction, and multiplication with automatic `jo` overflow detection.
- **Precision Fractional Division**: Expands remainders into exact decimal fractions (`1/3` $\rightarrow$ `0.333333`, `9/7` $\rightarrow$ `1.285714`, `1215646581523853/2` $\rightarrow$ `607823290761926.5`).
- **Hardware Fault Guards**: Zero-runtime guards preventing `#DE` hardware crashes on division/modulo by zero and `INT64_MIN / -1`.
- **Branchless Operations**: Uses branchless absolute value (`|-99|` $\rightarrow$ `99`).
- **Automated Test Suite**: 15/15 tests passing via:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\calculator\run_tests.ps1
  ```

### Showcase 2: Self-Healing Console Text Editor
Included in [`editor/`](editor/) is a standalone x64 console text editor written in MASM assembly (`editor.asm`).
- Demonstrates build-time self-healing: [editor/build.bat](editor/build.bat) invokes `assemble lint` and `assemble fix` automatically before invoking `ml64.exe` and `link.exe`, ensuring zero stack alignment crashes.

---

## 📦 Installation & Setup

### Prerequisites
- **Rust Toolchain**: `rustc` and `cargo` (version 1.93+)
- **Assembler Backend (Optional for live compilation)**: NASM (in system `PATH`) or MSVC `ml64.exe`

### Building from Source
```bash
# Clone repository
git clone https://github.com/shiva2321/Assemble.git
cd Assemble

# Compile optimized release binary
cargo build --release

# Run all 26 unit and integration tests
cargo test
```

### Adding to PATH
The compiled binary will be located at `target/release/assemble` (or `target\release\assemble.exe` on Windows). Add this directory to your system `PATH` or install globally:
```bash
cargo install --path .
```

---

## 📋 Complete CLI Cheatsheet

```bash
# 1. Lint an assembly file for Windows ABI violations
assemble lint routine.asm --arch x86_64 --abi windows

# 2. Lint ARM64 assembly (AAPCS64)
assemble lint kernel.s --arch arm64

# 3. Automatically fix stack and register bugs in-place
assemble fix broken.asm --abi windows --write

# 4. Audit driver code for kernel safety (permits Ring 0, audits hazards)
assemble audit driver.asm --mode kernel

# 5. Compile assembly directly to machine code hex
assemble asm "mov rax, 42\nret"

# 6. Disassemble raw machine code hex
assemble disasm "48 89 d8 c3" --syntax intel

# 7. Fetch a production UART driver template
assemble template baremetal-uart -o uart.asm

# 8. Step-by-step trace execution with initial registers
assemble trace algorithm.asm --reg rax=10 --reg rbx=0x40

# 9. Query CPU microarchitecture timing and flags
assemble query xor
assemble query idiv

# 10. Browse branchless and SIMD idioms
assemble idiom branchless

# 11. Launch MCP server for AI agents
assemble mcp
```

---

## 🧪 Test Suite Verification Status

Assemble maintains a strict 100% test pass rate across all suites:

```text
running 26 tests across 4 test suites:
- test_assembler_tracer: 6 passed (ADC/SBB carry chaining, LEA, XCHG, BSWAP, flags, roundtrip)
- test_knowledge:        3 passed (Instruction, ABI, and Idiom relational queries)
- test_linter:          10 passed (x86_64, ARM64, and RISC-V ABI and trap verifications)
- test_safety_fixer:     7 passed (Kernel Ring 0 audit, driver CLI/STI hazards, spinlock PAUSE, templates)

Total: 26 passed; 0 failed; 0 ignored (100% pass rate).
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
Contributions, issue reports, and feature requests are welcome at [https://github.com/shiva2321/Assemble](https://github.com/shiva2321/Assemble).
