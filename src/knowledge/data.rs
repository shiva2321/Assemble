use crate::knowledge::graph::*;
use crate::types::{Arch, CallingConvention};

pub fn populate_baseline_knowledge(kg: &mut KnowledgeGraph) {
    populate_flags(kg);
    populate_calling_conventions(kg);
    populate_instructions(kg);
    populate_idioms(kg);
    populate_syscalls(kg);
}

fn populate_flags(kg: &mut KnowledgeGraph) {
    kg.add_flag(FlagNode {
        name: "CF".into(),
        full_name: "Carry Flag".into(),
        description: "Set on unsigned overflow/carry out or borrow during subtraction.".into(),
        condition_codes_testing: vec!["jb".into(), "jbe".into(), "jae".into(), "ja".into(), "cmovb".into()],
    });
    kg.add_flag(FlagNode {
        name: "ZF".into(),
        full_name: "Zero Flag".into(),
        description: "Set when result of arithmetic/logical operation is exactly zero.".into(),
        condition_codes_testing: vec!["je".into(), "jne".into(), "jz".into(), "jnz".into(), "cmove".into()],
    });
    kg.add_flag(FlagNode {
        name: "SF".into(),
        full_name: "Sign Flag".into(),
        description: "Set equal to most significant bit of the result (negative in two's complement).".into(),
        condition_codes_testing: vec!["js".into(), "jns".into(), "jl".into(), "jge".into()],
    });
    kg.add_flag(FlagNode {
        name: "OF".into(),
        full_name: "Overflow Flag".into(),
        description: "Set when signed two's complement result exceeds destination capacity.".into(),
        condition_codes_testing: vec!["jo".into(), "jno".into(), "jl".into(), "jg".into()],
    });
    kg.add_flag(FlagNode {
        name: "DF".into(),
        full_name: "Direction Flag".into(),
        description: "Controls string instruction auto-increment (0, cld) or auto-decrement (1, std).".into(),
        condition_codes_testing: vec!["cld".into(), "std".into()],
    });
    kg.add_flag(FlagNode {
        name: "PF".into(),
        full_name: "Parity Flag".into(),
        description: "Set if least significant byte contains an even number of 1 bits.".into(),
        condition_codes_testing: vec!["jp".into(), "jnp".into()],
    });
}

fn populate_calling_conventions(kg: &mut KnowledgeGraph) {
    kg.add_calling_convention(CallingConventionNode {
        id: CallingConvention::SystemV_AMD64,
        name: "System V AMD64 ABI (Linux, macOS, BSD)".into(),
        arch: Arch::X86_64,
        arg_registers: vec!["rdi".into(), "rsi".into(), "rdx".into(), "rcx".into(), "r8".into(), "r9".into()],
        float_arg_registers: vec!["xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into(), "xmm4".into(), "xmm5".into(), "xmm6".into(), "xmm7".into()],
        return_registers: vec!["rax".into(), "rdx".into()],
        callee_saved_registers: vec!["rbx".into(), "rsp".into(), "rbp".into(), "r12".into(), "r13".into(), "r14".into(), "r15".into()],
        caller_saved_registers: vec!["rax".into(), "rcx".into(), "rdx".into(), "rsi".into(), "rdi".into(), "r8".into(), "r9".into(), "r10".into(), "r11".into()],
        stack_alignment_bytes: 16,
        shadow_space_bytes: 0,
        red_zone_bytes: 128,
        rules_and_traps: vec![
            "Stack MUST be aligned to 16 bytes before the CALL instruction.".into(),
            "The 128-byte red zone below RSP can be used by leaf functions without moving RSP.".into(),
            "Syscall clobbers RCX (saved RIP) and R11 (saved RFLAGS).".into(),
            "Writing to 32-bit registers (e.g. eax) automatically zero-extends into 64-bit parent (rax).".into(),
        ],
    });

    kg.add_calling_convention(CallingConventionNode {
        id: CallingConvention::Windows_X64,
        name: "Microsoft x64 Calling Convention (Windows)".into(),
        arch: Arch::X86_64,
        arg_registers: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
        float_arg_registers: vec!["xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into()],
        return_registers: vec!["rax".into()],
        callee_saved_registers: vec!["rbx".into(), "rbp".into(), "rdi".into(), "rsi".into(), "rsp".into(), "r12".into(), "r13".into(), "r14".into(), "r15".into(), "xmm6".into(), "xmm7".into()],
        caller_saved_registers: vec!["rax".into(), "rcx".into(), "rdx".into(), "r8".into(), "r9".into(), "r10".into(), "r11".into()],
        stack_alignment_bytes: 16,
        shadow_space_bytes: 32,
        red_zone_bytes: 0,
        rules_and_traps: vec![
            "CALLER MUST allocate 32 bytes of 'shadow space' (home space) on stack before every CALL, even for 0-parameter functions!".into(),
            "Stack MUST be 16-byte aligned before CALL.".into(),
            "RSI and RDI are CALLEE-SAVED on Windows, unlike System V where they are caller-saved!".into(),
            "No Red Zone exists on Windows. Accessing memory below RSP will cause corruption if interrupts or APCs fire.".into(),
        ],
    });

    kg.add_calling_convention(CallingConventionNode {
        id: CallingConvention::Arm64_AAPCS,
        name: "ARM64 AAPCS (AArch64)".into(),
        arch: Arch::Arm64,
        arg_registers: vec!["x0".into(), "x1".into(), "x2".into(), "x3".into(), "x4".into(), "x5".into(), "x6".into(), "x7".into()],
        float_arg_registers: vec!["v0".into(), "v1".into(), "v2".into(), "v3".into(), "v4".into(), "v5".into(), "v6".into(), "v7".into()],
        return_registers: vec!["x0".into(), "x1".into()],
        callee_saved_registers: vec!["x19".into(), "x20".into(), "x21".into(), "x22".into(), "x23".into(), "x24".into(), "x25".into(), "x26".into(), "x27".into(), "x28".into(), "x29".into(), "x30".into()],
        caller_saved_registers: vec!["x9".into(), "x10".into(), "x11".into(), "x12".into(), "x13".into(), "x14".into(), "x15".into()],
        stack_alignment_bytes: 16,
        shadow_space_bytes: 0,
        red_zone_bytes: 0,
        rules_and_traps: vec![
            "Stack pointer SP MUST be 16-byte aligned whenever used as a memory base.".into(),
            "x29 is Frame Pointer (FP); x30 is Link Register (LR).".into(),
        ],
    });

    kg.add_calling_convention(CallingConventionNode {
        id: CallingConvention::Riscv_LP64,
        name: "RISC-V Standard Calling Convention (LP64/LP64D)".into(),
        arch: Arch::Riscv64,
        arg_registers: vec!["a0".into(), "a1".into(), "a2".into(), "a3".into(), "a4".into(), "a5".into(), "a6".into(), "a7".into()],
        float_arg_registers: vec!["fa0".into(), "fa1".into(), "fa2".into(), "fa3".into(), "fa4".into(), "fa5".into(), "fa6".into(), "fa7".into()],
        return_registers: vec!["a0".into(), "a1".into()],
        callee_saved_registers: vec!["s0".into(), "s1".into(), "s2".into(), "s3".into(), "s4".into(), "s5".into(), "s6".into(), "s7".into(), "s8".into(), "s9".into(), "s10".into(), "s11".into(), "sp".into()],
        caller_saved_registers: vec!["t0".into(), "t1".into(), "t2".into(), "t3".into(), "t4".into(), "t5".into(), "t6".into(), "ra".into()],
        stack_alignment_bytes: 16,
        shadow_space_bytes: 0,
        red_zone_bytes: 0,
        rules_and_traps: vec![
            "Stack pointer SP MUST remain 16-byte aligned at all times.".into(),
            "Non-leaf functions MUST save return address 'ra' (x1) before calling 'jal'/'call'.".into(),
            "Division by zero does NOT cause an exception in RISC-V: 'div' returns -1, 'rem' returns dividend.".into(),
        ],
    });
}

fn populate_instructions(kg: &mut KnowledgeGraph) {
    kg.add_instruction(InstructionNode {
        mnemonic: "add".into(),
        arch: Arch::X86_64,
        summary: "Integer addition. Adds source to destination with carry/overflow update.".into(),
        syntax_forms: vec!["add reg, reg".into(), "add reg, imm".into(), "add reg, [mem]".into()],
        flags_read: vec![],
        flags_written: vec!["OF".into(), "SF".into(), "ZF".into(), "AF".into(), "CF".into(), "PF".into()],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.25),
        extension: "Base".into(),
        traps_and_pitfalls: vec!["Sets CF on unsigned overflow, OF on signed overflow.".into()],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "sub".into(),
        arch: Arch::X86_64,
        summary: "Integer subtraction. Subtracts source from destination.".into(),
        syntax_forms: vec!["sub reg, reg".into(), "sub reg, imm".into(), "sub reg, [mem]".into()],
        flags_read: vec![],
        flags_written: vec!["OF".into(), "SF".into(), "ZF".into(), "AF".into(), "CF".into(), "PF".into()],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.25),
        extension: "Base".into(),
        traps_and_pitfalls: vec!["Sets CF if borrow occurred (dest < src unsigned).".into()],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "imul".into(),
        arch: Arch::X86_64,
        summary: "Signed integer multiplication. Available in 1-operand, 2-operand (imul r, r), and 3-operand (imul r, r, imm) forms.".into(),
        syntax_forms: vec!["imul reg".into(), "imul reg, reg/mem".into(), "imul reg, reg/mem, imm".into()],
        flags_read: vec![],
        flags_written: vec!["CF".into(), "OF".into()],
        flags_undefined: vec!["SF".into(), "ZF".into(), "AF".into(), "PF".into()],
        implicit_registers_read: vec!["rax".into()],
        implicit_registers_written: vec!["rdx".into(), "rax".into()],
        latency_cycles: Some(3.0),
        throughput_cycles: Some(1.0),
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "In 2-operand and 3-operand forms, destination MUST be a register!".into(),
            "CF and OF are set if the significant bits of the result exceed destination register width.".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "idiv".into(),
        arch: Arch::X86_64,
        summary: "Signed integer divide. Divides RDX:RAX by operand. Quotient returned in RAX, Remainder in RDX.".into(),
        syntax_forms: vec!["idiv reg/mem".into()],
        flags_read: vec![],
        flags_written: vec![],
        flags_undefined: vec!["CF".into(), "OF".into(), "SF".into(), "ZF".into(), "AF".into(), "PF".into()],
        implicit_registers_read: vec!["rdx".into(), "rax".into()],
        implicit_registers_written: vec!["rax (quotient)".into(), "rdx (remainder)".into()],
        latency_cycles: Some(18.0),
        throughput_cycles: Some(6.0),
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "MANDATORY: Must execute 'cqo' (or 'cdq') prior to IDIV to sign-extend RAX into RDX:RAX!".into(),
            "CRITICAL TRAP: Triggers #DE (Divide Error Exception) if divisor is 0 or if quotient overflows (e.g. INT64_MIN / -1).".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "cqo".into(),
        arch: Arch::X86_64,
        summary: "Convert Quadword to Octaword. Sign-extends RAX into RDX:RAX for 64-bit IDIV.".into(),
        syntax_forms: vec!["cqo".into()],
        flags_read: vec![],
        flags_written: vec![],
        flags_undefined: vec![],
        implicit_registers_read: vec!["rax".into()],
        implicit_registers_written: vec!["rdx".into()],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.5),
        extension: "Base".into(),
        traps_and_pitfalls: vec!["Clobbers RDX completely with the sign bit of RAX.".into()],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "neg".into(),
        arch: Arch::X86_64,
        summary: "Two's complement negation (dest = 0 - dest).".into(),
        syntax_forms: vec!["neg reg".into(), "neg [mem]".into()],
        flags_read: vec![],
        flags_written: vec!["CF".into(), "OF".into(), "SF".into(), "ZF".into(), "AF".into(), "PF".into()],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.5),
        extension: "Base".into(),
        traps_and_pitfalls: vec!["CF is set to 0 if operand is 0, and 1 if non-zero.".into()],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "xor".into(),
        arch: Arch::X86_64,
        summary: "Bitwise logical Exclusive OR. 'xor reg, reg' is the canonical zero-latency register zeroing idiom.".into(),
        syntax_forms: vec!["xor reg, reg".into(), "xor reg, imm".into(), "xor reg, [mem]".into()],
        flags_read: vec![],
        flags_written: vec!["CF".into(), "OF".into(), "SF".into(), "ZF".into(), "PF".into()],
        flags_undefined: vec!["AF".into()],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(0.25),
        throughput_cycles: Some(0.25),
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "Clears CF and OF unconditionally.".into(),
            "Writing to 32-bit register e.g. 'xor eax, eax' automatically clears upper 32 bits of RAX and breaks dependency chains.".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "lea".into(),
        arch: Arch::X86_64,
        summary: "Load Effective Address. Calculates memory address without accessing memory. Ideal for fast math (base + index*scale + disp).".into(),
        syntax_forms: vec!["lea reg, [base + index*scale + disp]".into()],
        flags_read: vec![],
        flags_written: vec![],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.5),
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "Does NOT modify any CPU flags! Ideal for arithmetic where flags must be preserved.".into(),
            "Use RIP-relative addressing 'lea rax, [rip + symbol]' for position-independent code (PIC).".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "inc".into(),
        arch: Arch::X86_64,
        summary: "Increment register or memory by 1.".into(),
        syntax_forms: vec!["inc reg".into(), "inc byte/dword/qword [mem]".into()],
        flags_read: vec![],
        flags_written: vec!["OF".into(), "SF".into(), "ZF".into(), "AF".into(), "PF".into()],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec![],
        latency_cycles: Some(1.0),
        throughput_cycles: Some(0.5),
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "CRITICAL: INC does NOT modify CF (Carry Flag)! Prefer 'add reg, 1' if flags are needed.".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "syscall".into(),
        arch: Arch::X86_64,
        summary: "Fast system call into the OS kernel.".into(),
        syntax_forms: vec!["syscall".into()],
        flags_read: vec![],
        flags_written: vec![],
        flags_undefined: vec![],
        implicit_registers_read: vec!["rax".into(), "rdi".into(), "rsi".into(), "rdx".into(), "r10".into(), "r8".into(), "r9".into()],
        implicit_registers_written: vec!["rcx".into(), "r11".into(), "rax".into()],
        latency_cycles: None,
        throughput_cycles: None,
        extension: "Base".into(),
        traps_and_pitfalls: vec![
            "DESTRUCTIVE: Hardware SYSCALL always clobbers RCX (stores RIP) and R11 (stores RFLAGS).".into(),
            "In Linux x86_64, the 4th argument is in R10, NOT RCX.".into(),
        ],
    });

    kg.add_instruction(InstructionNode {
        mnemonic: "vzeroupper".into(),
        arch: Arch::X86_64,
        summary: "Zero upper 128-bits of all YMM/ZMM registers. Avoids AVX-to-SSE transition penalties.".into(),
        syntax_forms: vec!["vzeroupper".into()],
        flags_read: vec![],
        flags_written: vec![],
        flags_undefined: vec![],
        implicit_registers_read: vec![],
        implicit_registers_written: vec!["ymm0-ymm15".into()],
        latency_cycles: Some(4.0),
        throughput_cycles: Some(4.0),
        extension: "AVX".into(),
        traps_and_pitfalls: vec![
            "MANDATORY: Must be executed before leaving any AVX function (before RET) or calling legacy SSE functions.".into(),
        ],
    });
}

fn populate_idioms(kg: &mut KnowledgeGraph) {
    kg.add_idiom(IdiomNode {
        id: "branchless_abs_x86_64".into(),
        name: "Branchless Absolute Value (x86_64)".into(),
        category: "branchless".into(),
        arch: Arch::X86_64,
        description: "Computes |x| for signed 64-bit integer in RAX without conditional jumps.".into(),
        assembly_intel: "mov rdx, rax\nsar rdx, 63\nxor rax, rdx\nsub rax, rdx".into(),
        assembly_att: Some("movq %rax, %rdx\nsarq $63, %rdx\nxorq %rdx, %rax\nsubq %rdx, %rax".into()),
        assembly_arm64: Some("cmp x0, #0\ncsneg x0, x0, x0, mi".into()),
        why_it_matters: "Completely eliminates branch misprediction penalties (15-20 cycles on modern CPUs).".into(),
        latency_cycles: "3 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "branchless_min_max_x86_64".into(),
        name: "Branchless Min / Max using CMOVcc".into(),
        category: "branchless".into(),
        arch: Arch::X86_64,
        description: "Selects min or max of RAX and RBX without branching.".into(),
        assembly_intel: "cmp rax, rbx\ncmovg rax, rbx ; for min (signed)\n; or cmovl rax, rbx ; for max".into(),
        assembly_att: Some("cmpq %rbx, %rax\ncmovg %rbx, %rax".into()),
        assembly_arm64: Some("cmp x0, x1\ncsel x0, x0, x1, le ; min".into()),
        why_it_matters: "Single CMP followed by single CMOVcc eliminates branch predictor thrashing.".into(),
        latency_cycles: "2 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "zero_latency_register_clear".into(),
        name: "Zero-Latency Register Clearing".into(),
        category: "zeroing".into(),
        arch: Arch::X86_64,
        description: "Clears a register to 0 with zero execution port latency on modern x86 cores.".into(),
        assembly_intel: "xor eax, eax ; Note: 32-bit register clears 64-bit RAX!".into(),
        assembly_att: Some("xorl %eax, %eax".into()),
        assembly_arm64: Some("mov x0, xzr".into()),
        why_it_matters: "Recognized by CPU register renaming unit as a zero-latency idiom.".into(),
        latency_cycles: "0 cycles (handled at rename stage)".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "checked_imul_overflow".into(),
        name: "Checked Signed Multiplication with Overflow Detection".into(),
        category: "checked_arithmetic".into(),
        arch: Arch::X86_64,
        description: "Detects 64-bit integer overflow immediately upon multiplication using the CPU Overflow Flag (OF).".into(),
        assembly_intel: "imul rax, rdx\njo .overflow_handler ; Jump if product does not fit in 64 bits".into(),
        assembly_att: Some("imulq %rdx, %rax\njo .overflow_handler".into()),
        assembly_arm64: Some("smull x2, w0, w1\n// Or test high half in ARM64".into()),
        why_it_matters: "Prevents silent integer wraparound corruptions that produce wild mathematical errors.".into(),
        latency_cycles: "3 cycles + 1 branch cycle".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "full_128bit_multiplication".into(),
        name: "Full 128-Bit Integer Multiplication (No Truncation)".into(),
        category: "multi_precision".into(),
        arch: Arch::X86_64,
        description: "Multiplies two 64-bit integers and captures the entire 128-bit product in RDX:RAX without any truncation.".into(),
        assembly_intel: "mov rax, rcx\nmul rdx       ; RDX:RAX = RCX * RDX (RDX = upper 64 bits, RAX = lower 64 bits)".into(),
        assembly_att: Some("movq %rcx, %rax\nmulq %rdx".into()),
        assembly_arm64: Some("mul x2, x0, x1\numulh x3, x0, x1 ; x3 = high 64 bits, x2 = low 64 bits".into()),
        why_it_matters: "Permits arbitrary-precision bignum arithmetic and eliminates overflow completely for 64-bit inputs.".into(),
        latency_cycles: "4 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "decimal_fraction_expansion".into(),
        name: "Decimal Fraction Expansion from Division Remainder".into(),
        category: "formatting".into(),
        arch: Arch::X86_64,
        description: "Expands integer division remainder into exact decimal digits (e.g. 1/3 -> 0.333333, 9/7 -> 1.285714).".into(),
        assembly_intel: "; After idiv r10 (RAX = quotient, RDX = remainder):\n; Loop to extract decimal digits:\n.digit_loop:\nmov rax, rdx\nimul rax, 10\ncqo\nidiv r10       ; RAX = next decimal digit, RDX = new remainder\n// append RAX + '0' to output buffer\ntest rdx, rdx\njnz .digit_loop".into(),
        assembly_att: None,
        assembly_arm64: None,
        why_it_matters: "Turns basic integer truncation (like 1/3 = 0) into precise decimal output without floating point errors.".into(),
        latency_cycles: "~18 cycles per decimal digit".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "sse2_double_precision_division".into(),
        name: "IEEE 754 Double-Precision Float Division (SSE2)".into(),
        category: "floating_point".into(),
        arch: Arch::X86_64,
        description: "Performs true 64-bit floating-point division using hardware vector registers XMM0/XMM1.".into(),
        assembly_intel: "cvtsi2sd xmm0, rcx ; Convert int64 dividend to double\ncvtsi2sd xmm1, rdx ; Convert int64 divisor to double\ndivsd xmm0, xmm1   ; XMM0 = dividend / divisor".into(),
        assembly_att: Some("cvtsi2sdq %rcx, %xmm0\ncvtsi2sdq %rdx, %xmm1\ndivsd %xmm1, %xmm0".into()),
        assembly_arm64: Some("scvtf d0, x0\nscvtf d1, x1\nfdiv d0, d0, d1".into()),
        why_it_matters: "Delivers IEEE-754 compliant double-precision floats with zero truncation.".into(),
        latency_cycles: "~14 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "arm64_checked_division_remainder".into(),
        name: "ARM64 Safe Division with Remainder Computation".into(),
        category: "arithmetic".into(),
        arch: Arch::Arm64,
        description: "Guards against division by zero (which returns 0 silently in AArch64) and computes the remainder using MSUB.".into(),
        assembly_intel: "; x86 equivalent: test rdx, rdx; jz .err; idiv rdx".into(),
        assembly_att: None,
        assembly_arm64: Some("cbz x1, .div_zero_error  // Guard division by zero\nsdiv x2, x0, x1           // x2 = quotient (x0 / x1)\nmsub x3, x2, x1, x0       // x3 = remainder: x0 - (x2 * x1)".into()),
        why_it_matters: "Prevents silent division-by-zero logic errors and recovers the remainder without needing extra division steps.".into(),
        latency_cycles: "4 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "riscv_checked_division_remainder".into(),
        name: "RISC-V Safe Division and Remainder".into(),
        category: "arithmetic".into(),
        arch: Arch::Riscv64,
        description: "Guards against division by zero (which returns -1 silently in RISC-V) and executes div and rem.".into(),
        assembly_intel: "; x86 equivalent: idiv".into(),
        assembly_att: None,
        assembly_arm64: None,
        why_it_matters: "RISC-V hardware specifies no hardware exception on divide-by-zero, requiring an explicit branch to prevent silent corrupted state.".into(),
        latency_cycles: "5-32 cycles (M extension)".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "safe_signed_negation".into(),
        name: "Safe Signed Negation Handling INT_MIN".into(),
        category: "checked_arithmetic".into(),
        arch: Arch::X86_64,
        description: "Safely negates a signed integer and branches on overflow if the value is INT64_MIN (-2^63).".into(),
        assembly_intel: "neg rax\njo .overflow_handler ; Triggered if RAX was 0x8000000000000000".into(),
        assembly_att: Some("negq %rax\njo .overflow_handler".into()),
        assembly_arm64: Some("negs x0, x0\nb.vs .overflow_handler".into()),
        why_it_matters: "In two's complement, -INT_MIN cannot be represented as a positive signed number and wraps back to INT_MIN.".into(),
        latency_cycles: "1 cycle".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "multi_precision_adc_chain".into(),
        name: "Multi-Precision 128-Bit Addition (ADC Chain)".into(),
        category: "multi_precision".into(),
        arch: Arch::X86_64,
        description: "Chains ADD and ADC to add 128-bit integers across two 64-bit register pairs.".into(),
        assembly_intel: "add rax, rcx ; add low 64 bits (sets CF)\nadc rdx, r8  ; add high 64 bits with CF carry".into(),
        assembly_att: Some("addq %rcx, %rax\nadcq %r8, %rdx".into()),
        assembly_arm64: Some("adds x0, x0, x2\nadc x1, x1, x3".into()),
        why_it_matters: "Forms the fundamental building block of arbitrary-precision bignum arithmetic and cryptographic primitives.".into(),
        latency_cycles: "2 cycles".into(),
    });

    kg.add_idiom(IdiomNode {
        id: "windows_x64_callee_saved_prologue".into(),
        name: "Standard Windows x64 ABI Non-Volatile Prologue & Epilogue".into(),
        category: "calling_convention".into(),
        arch: Arch::X86_64,
        description: "Preserves all required callee-saved registers (RBX, RSI, RDI, R12-R15) and allocates shadow space with 16-byte alignment.".into(),
        assembly_intel: "push rbx\npush rsi\npush rdi\npush r12\npush r13\npush r14\npush r15\nsub rsp, 48 ; 7 pushes (56) + 8 ret = 64 (0 mod 16). 64 + 48 = 112 (multiple of 16)\n; ... body ...\nadd rsp, 48\npop r15\npop r14\npop r13\npop r12\npop rdi\npop rsi\npop rbx\nret".into(),
        assembly_att: None,
        assembly_arm64: None,
        why_it_matters: "Failing to preserve RSI/RDI on Windows x64 corrupts the caller's state, leading to intermittent and catastrophic crashes.".into(),
        latency_cycles: "Minimal push/pop overhead".into(),
    });
}

fn populate_syscalls(kg: &mut KnowledgeGraph) {
    kg.add_syscall(SyscallNode {
        id: 0,
        name: "sys_read".into(),
        arch: Arch::X86_64,
        os: "linux".into(),
        signature: "ssize_t read(int fd, void *buf, size_t count)".into(),
        arg_registers: vec!["rdi (fd)".into(), "rsi (buf)".into(), "rdx (count)".into()],
        return_register: "rax (bytes read or negative error code)".into(),
        clobbered_registers: vec!["rcx".into(), "r11".into()],
    });

    kg.add_syscall(SyscallNode {
        id: 1,
        name: "sys_write".into(),
        arch: Arch::X86_64,
        os: "linux".into(),
        signature: "ssize_t write(int fd, const void *buf, size_t count)".into(),
        arg_registers: vec!["rdi (fd)".into(), "rsi (buf)".into(), "rdx (count)".into()],
        return_register: "rax (bytes written or negative error code)".into(),
        clobbered_registers: vec!["rcx".into(), "r11".into()],
    });

    kg.add_syscall(SyscallNode {
        id: 60,
        name: "sys_exit".into(),
        arch: Arch::X86_64,
        os: "linux".into(),
        signature: "void exit(int status)".into(),
        arg_registers: vec!["rdi (status)".into()],
        return_register: "Does not return".into(),
        clobbered_registers: vec!["rcx".into(), "r11".into()],
    });
}
