use crate::types::{CallingConvention, LintDiagnostic, Severity};
use regex::Regex;
use std::collections::HashSet;

pub struct X86_64Linter {
    abi: CallingConvention,
}

impl X86_64Linter {
    pub fn new(abi: CallingConvention) -> Self {
        Self { abi }
    }

    pub fn lint(&self, assembly_code: &str) -> Vec<LintDiagnostic> {
        let mut diagnostics = Vec::new();
        let lines: Vec<&str> = assembly_code.lines().collect();

        let mut stack_offset: i64 = 8;
        let mut shadow_space_allocated: i64 = 0;
        let mut pushed_registers = HashSet::new();
        let mut popped_registers = HashSet::new();
        let mut modified_registers = HashSet::new();
        let mut used_avx = false;
        let mut has_vzeroupper = false;

        let re_push = Regex::new(r"(?i)^\s*push\s+([a-z0-9]+)").unwrap();
        let re_pop = Regex::new(r"(?i)^\s*pop\s+([a-z0-9]+)").unwrap();
        let re_sub_rsp = Regex::new(r"(?i)^\s*sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)").unwrap();
        let re_add_rsp = Regex::new(r"(?i)^\s*add\s+(rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)").unwrap();
        let re_call = Regex::new(r"(?i)^\s*call\s+").unwrap();
        let _re_ret = Regex::new(r"(?i)^\s*ret\b").unwrap();
        let re_syscall = Regex::new(r"(?i)^\s*syscall\b").unwrap();
        let re_mov_zero = Regex::new(r"(?i)^\s*mov\s+(rax|rbx|rcx|rdx|rsi|rdi|r[8-9]|r1[0-5]),\s*0\b").unwrap();
        let re_mem_imm64 = Regex::new(r"(?i)^\s*mov\s+(qword\s*)?\[.+?\],\s*(0x[0-9a-fA-F]{9,16})").unwrap();
        let re_dst_reg = Regex::new(r"(?i)^\s*(mov|add|sub|xor|and|or|imul|shl|shr|sar|lea|inc|dec|neg|not)\s+([a-z0-9]+)\b").unwrap();
        let re_string_insn = Regex::new(r"(?i)^\s*(stos[bwdq]?|lods[bwdq]?|movs[bwdq]?)").unwrap();
        let re_idiv_div_rdx = Regex::new(r"(?i)^\s*(idiv|div)\s+(rdx|edx)\b").unwrap();
        let re_idiv_any = Regex::new(r"(?i)^\s*idiv\s+([a-z0-9]+)\b").unwrap();
        let re_write_rdx = Regex::new(r"(?i)^\s*(mov|xor|lea|add|sub|pop)\s+(rdx|edx)\b").unwrap();
        let re_imul = Regex::new(r"(?i)^\s*imul\b").unwrap();
        let re_check_overflow = Regex::new(r"(?i)^\s*(jo|jno|into|seto)\b").unwrap();
        let re_cmp_zero = Regex::new(r"(?i)^\s*(test|cmp)\b.*,\s*(0|0x0)\b").unwrap();
        let re_test_self = Regex::new(r"(?i)^\s*test\s+([a-z0-9]+),\s*([a-z0-9]+)\b").unwrap();
        let re_movaps_movdqa = Regex::new(r"(?i)^\s*(movaps|movdqa)\s+").unwrap();
        let re_dst_xmm = Regex::new(r"(?i)^\s*(mov[au]?[psd]|add[psd]|sub[psd]|mul[psd]|div[psd])\s+(xmm[6-9]|xmm1[0-5])\b").unwrap();

        let mut last_cqo_line: Option<usize> = None;
        let mut last_cdq_line: Option<usize> = None;
        let mut had_imul = false;
        let mut checked_overflow = false;
        let mut imul_line = 0;
        let mut had_idiv = false;
        let mut idiv_line = 0;
        let mut had_div_guard = false;
        let mut modified_xmm: HashSet<String> = HashSet::new();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let mut trimmed = line.trim();
            if let Some(pos) = trimmed.find(';') {
                trimmed = trimmed[..pos].trim();
            }
            if let Some(pos) = trimmed.find("//") {
                trimmed = trimmed[..pos].trim();
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.ends_with(':') {
                continue;
            }

            if trimmed.to_lowercase().starts_with('v') && !trimmed.to_lowercase().starts_with("var") {
                used_avx = true;
                if trimmed.to_lowercase().starts_with("vzeroupper") {
                    has_vzeroupper = true;
                }
            }

            if let Some(caps) = re_push.captures(trimmed) {
                let reg = caps[1].to_lowercase();
                stack_offset = (stack_offset + 8) % 16;
                pushed_registers.insert(reg);
            }

            if let Some(caps) = re_pop.captures(trimmed) {
                let reg = caps[1].to_lowercase();
                stack_offset = (stack_offset - 8 + 16) % 16;
                popped_registers.insert(reg);
            }

            if let Some(caps) = re_sub_rsp.captures(trimmed) {
                let val_str = &caps[2];
                let val = parse_imm(val_str);
                stack_offset = (stack_offset + val) % 16;
                shadow_space_allocated += val;
            }

            if let Some(caps) = re_add_rsp.captures(trimmed) {
                let val_str = &caps[2];
                let val = parse_imm(val_str);
                stack_offset = (stack_offset - val % 16 + 16) % 16;
                shadow_space_allocated -= val;
            }

            if let Some(caps) = re_dst_reg.captures(trimmed) {
                let reg = caps[2].to_lowercase();
                let parent = canonical_reg(&reg);
                modified_registers.insert(parent);
            }

            if let Some(caps) = re_string_insn.captures(trimmed) {
                let prefix = &caps[1].to_lowercase();
                if prefix.starts_with("stos") {
                    modified_registers.insert("rdi".into());
                } else if prefix.starts_with("lods") {
                    modified_registers.insert("rsi".into());
                } else if prefix.starts_with("movs") {
                    modified_registers.insert("rdi".into());
                    modified_registers.insert("rsi".into());
                }
            }

            if re_cmp_zero.is_match(trimmed) {
                had_div_guard = true;
            } else if let Some(caps) = re_test_self.captures(trimmed) {
                if caps[1].eq_ignore_ascii_case(&caps[2]) {
                    had_div_guard = true;
                }
            }

            if let Some(caps) = re_movaps_movdqa.captures(trimmed) {
                if trimmed.contains('[') {
                    diagnostics.push(LintDiagnostic {
                        rule: "VECTOR_ALIGNMENT_FAULT_RISK".into(),
                        severity: Severity::Hint,
                        line: line_num,
                        col: 1,
                        message: format!("'{}' memory operand requires strict 16-byte alignment. Misalignment triggers #GP fault.", &caps[1]),
                        explanation: "Aligned vector memory operations ('movaps', 'movdqa') fault with #GP(0) if the address is not a multiple of 16. If working with arbitrary or unaligned pointers, prefer unaligned variants 'movups' / 'movdqu'.".into(),
                        fix_suggestion: Some(format!("Replace '{}' with '{}' if 16-byte alignment is not guaranteed.", &caps[1], if caps[1].to_lowercase().ends_with("ps") { "movups" } else { "movdqu" })),
                    });
                }
            }

            if re_call.is_match(trimmed) {
                if stack_offset % 16 != 0 {
                    diagnostics.push(LintDiagnostic {
                        rule: "STACK_ALIGNMENT_VIOLATION".into(),
                        severity: Severity::Error,
                        line: line_num,
                        col: 1,
                        message: format!("Stack pointer (RSP) is not 16-byte aligned before 'call' (current offset mod 16 = {}).", stack_offset),
                        explanation: "The x86-64 ABI strictly requires RSP to be a multiple of 16 immediately before executing a 'call'. Misalignment will cause crashes in libc, SSE/AVX vector instructions, or Windows API functions.".into(),
                        fix_suggestion: Some("Adjust your stack allocation: e.g. change 'sub rsp, 8' to 'sub rsp, 16' or push an extra register/dummy value to align RSP.".into()),
                    });
                }

                if self.abi == CallingConvention::Windows_X64 && shadow_space_allocated < 32 {
                    diagnostics.push(LintDiagnostic {
                        rule: "WINDOWS_SHADOW_SPACE_MISSING".into(),
                        severity: Severity::Error,
                        line: line_num,
                        col: 1,
                        message: format!("Calling a function in Windows x64 ABI without allocating 32-byte shadow space (currently allocated: {} bytes).", shadow_space_allocated.max(0)),
                        explanation: "Microsoft x64 ABI mandates that the caller allocate at least 32 bytes (0x20) of 'shadow space' (home space) on the stack directly above the return address for the callee to spill RCX, RDX, R8, R9.".into(),
                        fix_suggestion: Some("Add 'sub rsp, 32' (or 'sub rsp, 40' with 8-byte alignment) in function prologue and restore with 'add rsp, 32'/'add rsp, 40' before ret.".into()),
                    });
                }
            }

            if re_syscall.is_match(trimmed) {
                diagnostics.push(LintDiagnostic {
                    rule: "SYSCALL_REGISTER_CLOBBER_NOTICE".into(),
                    severity: Severity::Info,
                    line: line_num,
                    col: 1,
                    message: "Hardware 'syscall' instruction clobbers RCX (saves RIP) and R11 (saves RFLAGS).".into(),
                    explanation: "If you are using RCX or R11 to hold data across a syscall, it will be destroyed. Also note that in Linux x86-64, the 4th syscall argument is passed in R10, NOT RCX.".into(),
                    fix_suggestion: Some("Pass the 4th argument in R10 instead of RCX, and do not expect RCX/R11 values to be preserved after syscall.".into()),
                });
            }

            if let Some(caps) = re_mem_imm64.captures(trimmed) {
                diagnostics.push(LintDiagnostic {
                    rule: "INVALID_64BIT_IMM_MEM_WRITE".into(),
                    severity: Severity::Error,
                    line: line_num,
                    col: 1,
                    message: format!("Invalid x86-64 instruction: Cannot write 64-bit immediate '{}' directly to memory.", &caps[2]),
                    explanation: "x86-64 has no opcode to move a 64-bit immediate directly into memory (only 32-bit sign-extended immediates are valid with memory destinations).".into(),
                    fix_suggestion: Some(format!("Load immediate into a register first: 'mov rax, {}' followed by 'mov [dest], rax'.", &caps[2])),
                });
            }

            if let Some(caps) = re_mov_zero.captures(trimmed) {
                let reg = &caps[1];
                let sub_32 = to_32bit_subreg(reg);
                diagnostics.push(LintDiagnostic {
                    rule: "ZERO_LATENCY_IDIOM_SUGGESTION".into(),
                    severity: Severity::Hint,
                    line: line_num,
                    col: 1,
                    message: format!("'mov {}, 0' is inefficient. Prefer 'xor {}, {}' instead.", reg, sub_32, sub_32),
                    explanation: "The CPU recognizes 'xor reg32, reg32' at register rename time as a zero-latency idiom with no execution port stalls and smaller encoded byte length.".into(),
                    fix_suggestion: Some(format!("xor {}, {}", sub_32, sub_32)),
                });
            }

            let lower = trimmed.to_lowercase();
            if lower == "cqo" {
                last_cqo_line = Some(line_num);
            } else if lower == "cdq" {
                last_cdq_line = Some(line_num);
            } else if re_write_rdx.is_match(trimmed) {
                last_cqo_line = None;
                last_cdq_line = None;
            }

            if let Some(caps) = re_idiv_div_rdx.captures(trimmed) {
                let op = caps[1].to_uppercase();
                let reg = caps[2].to_lowercase();
                if (reg == "rdx" && last_cqo_line.is_some()) || (reg == "edx" && last_cdq_line.is_some()) {
                    let prev_line = if reg == "rdx" { last_cqo_line.unwrap() } else { last_cdq_line.unwrap() };
                    let helper = if reg == "rdx" { "CQO" } else { "CDQ" };
                    diagnostics.push(LintDiagnostic {
                        rule: "CQO_CLOBBERS_DIVISOR_ERROR".into(),
                        severity: Severity::Error,
                        line: line_num,
                        col: 1,
                        message: format!("'{} {}' divides by register '{}' which was clobbered by '{}' on line {}.", op, reg, reg.to_uppercase(), helper, prev_line),
                        explanation: format!("'{}' sign-extends the dividend into {} (overwriting it with the sign bit, usually 0). Executing '{} {}' immediately afterward will trigger a fatal Hardware Divide Error (#DE).", helper, reg.to_uppercase(), op, reg),
                        fix_suggestion: Some(format!("Move the divisor to another register (e.g. 'mov r8, {}') before '{}', then execute '{} r8'.", reg, helper, op)),
                    });
                }
            }

            if re_imul.is_match(trimmed) {
                had_imul = true;
                imul_line = line_num;
            }
            if let Some(_caps) = re_idiv_any.captures(trimmed) {
                had_idiv = true;
                idiv_line = line_num;
            }
            if re_check_overflow.is_match(trimmed) {
                checked_overflow = true;
            }
            if let Some(caps) = re_dst_xmm.captures(trimmed) {
                modified_xmm.insert(caps[2].to_lowercase());
            }
        }

        if had_imul && !checked_overflow {
            diagnostics.push(LintDiagnostic {
                rule: "UNCHECKED_ARITHMETIC_OVERFLOW".into(),
                severity: Severity::Hint,
                line: imul_line,
                col: 1,
                message: "'imul' sets Overflow Flag (OF) on 64-bit integer overflow. No 'jo' check detected.".into(),
                explanation: "When multiplying inputs that may exceed 64-bit integers (~9.22e18), 'imul' silently wraps around and truncates high bits. Check the overflow flag using 'jo .overflow_handler' or use 128-bit 'mul'.".into(),
                fix_suggestion: Some("Add 'jo .overflow_error' immediately following the multiplication to handle large numbers safely.".into()),
            });
        }

        if had_idiv && !had_div_guard {
            diagnostics.push(LintDiagnostic {
                rule: "UNCHECKED_IDIV_OVERFLOW".into(),
                severity: Severity::Warning,
                line: idiv_line,
                col: 1,
                message: "Signed integer division ('idiv') detected without divisor zero-check or overflow guard.".into(),
                explanation: "Dividing by 0 or dividing INT64_MIN (-9223372036854775808) by -1 triggers a fatal CPU Hardware Divide Error (#DE) exception. Always check divisor (e.g. 'test r10, r10; jz .zero_err') before 'idiv'.".into(),
                fix_suggestion: Some("Test divisor register for zero and handle division-by-zero prior to executing 'idiv'.".into()),
            });
        }

        if self.abi == CallingConvention::Windows_X64 {
            for xmm in &modified_xmm {
                diagnostics.push(LintDiagnostic {
                    rule: "CALLEE_SAVED_XMM_CLOBBERED".into(),
                    severity: Severity::Error,
                    line: lines.len(),
                    col: 1,
                    message: format!("Vector register '{}' is callee-saved on Windows x64 and was modified without being saved.", xmm.to_uppercase()),
                    explanation: "On Windows x64, XMM6 through XMM15 are non-volatile (callee-saved). Functions modifying them must save their 128-bit contents to stack and restore them before returning.".into(),
                    fix_suggestion: Some(format!("Save to stack with 'movaps [rsp + offset], {}' in prologue and restore before ret.", xmm)),
                });
            }
        }

        let callee_saved = match self.abi {
            CallingConvention::Windows_X64 => vec!["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            _ => vec!["rbx", "rbp", "r12", "r13", "r14", "r15"],
        };

        for reg in callee_saved {
            if modified_registers.contains(reg) {
                let is_saved = pushed_registers.contains(reg);
                let is_restored = popped_registers.contains(reg);

                if !is_saved || !is_restored {
                    diagnostics.push(LintDiagnostic {
                        rule: "CALLEE_SAVED_REGISTER_CLOBBERED".into(),
                        severity: Severity::Error,
                        line: lines.len(),
                        col: 1,
                        message: format!("Callee-saved register '{}' was modified but not properly preserved (saved={}, restored={}).", reg, is_saved, is_restored),
                        explanation: format!("According to {:?}, the caller expects '{}' to remain unchanged across function calls. Clobbering it will corrupt the caller's state.", self.abi, reg),
                        fix_suggestion: Some(format!("Add 'push {}' in function prologue and 'pop {}' before ret.", reg, reg)),
                    });
                }
            }
        }

        if used_avx && !has_vzeroupper {
            diagnostics.push(LintDiagnostic {
                rule: "AVX_MISSING_VZEROUPPER".into(),
                severity: Severity::Warning,
                line: lines.len(),
                col: 1,
                message: "AVX instructions were used, but no 'vzeroupper' was detected before exit/calls.".into(),
                explanation: "Failing to execute 'vzeroupper' when transitioning between 256/512-bit AVX code and legacy SSE or function returns causes severe microarchitectural state transition penalties (up to 70 clock cycles per subsequent SSE instruction).".into(),
                fix_suggestion: Some("Insert 'vzeroupper' before 'ret' or before calling non-AVX functions.".into()),
            });
        }

        diagnostics
    }
}

fn parse_imm(s: &str) -> i64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<i64>().unwrap_or(0)
    }
}

fn canonical_reg(r: &str) -> String {
    match r {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax".into(),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx".into(),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx".into(),
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx".into(),
        "rsi" | "esi" | "si" | "sil" => "rsi".into(),
        "rdi" | "edi" | "di" | "dil" => "rdi".into(),
        "rbp" | "ebp" | "bp" | "bpl" => "rbp".into(),
        "rsp" | "esp" | "sp" | "spl" => "rsp".into(),
        "r8" | "r8d" | "r8w" | "r8b" => "r8".into(),
        "r9" | "r9d" | "r9w" | "r9b" => "r9".into(),
        "r10" | "r10d" | "r10w" | "r10b" => "r10".into(),
        "r11" | "r11d" | "r11w" | "r11b" => "r11".into(),
        "r12" | "r12d" | "r12w" | "r12b" => "r12".into(),
        "r13" | "r13d" | "r13w" | "r13b" => "r13".into(),
        "r14" | "r14d" | "r14w" | "r14b" => "r14".into(),
        "r15" | "r15d" | "r15w" | "r15b" => "r15".into(),
        other => other.to_string(),
    }
}

fn to_32bit_subreg(r: &str) -> &str {
    match r {
        "rax" => "eax",
        "rbx" => "ebx",
        "rcx" => "ecx",
        "rdx" => "edx",
        "rsi" => "esi",
        "rdi" => "edi",
        "rbp" => "ebp",
        "rsp" => "esp",
        "r8" => "r8d",
        "r9" => "r9d",
        "r10" => "r10d",
        "r11" => "r11d",
        "r12" => "r12d",
        "r13" => "r13d",
        "r14" => "r14d",
        "r15" => "r15d",
        _ => r,
    }
}
