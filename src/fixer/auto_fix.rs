use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::types::CallingConvention;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFixEdit {
    pub rule: String,
    pub description: String,
    pub original_line: String,
    pub fixed_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFixReport {
    pub original_code: String,
    pub fixed_code: String,
    pub changes_made: Vec<AutoFixEdit>,
    pub fixes_applied: usize,
}

pub struct AssemblyAutoFixer {
    abi: CallingConvention,
}

impl AssemblyAutoFixer {
    pub fn new(abi: CallingConvention) -> Self {
        Self { abi }
    }

    pub fn fix(&self, code: &str) -> AutoFixReport {
        let mut changes = Vec::new();
        let lines: Vec<&str> = code.lines().collect();
        let mut new_lines = Vec::new();

        let re_mov_zero = Regex::new(r"(?i)^(\s*)mov\s+(rax|rbx|rcx|rdx|rsi|rdi|r[8-9]|r1[0-5]),\s*0\b(.*)$").unwrap();
        let re_mem_imm64 = Regex::new(r"(?i)^(\s*)mov\s+((?:qword\s*)?\[.+?\]),\s*(0x[0-9a-fA-F]{9,16})(.*)$").unwrap();
        let re_call = Regex::new(r"(?i)^\s*call\s+").unwrap();
        let re_sub_rsp = Regex::new(r"(?i)^(\s*)sub\s+rsp,\s*(\d+|0x[0-9a-fA-F]+)(.*)$").unwrap();
        let re_add_rsp = Regex::new(r"(?i)^(\s*)add\s+rsp,\s*(\d+|0x[0-9a-fA-F]+)(.*)$").unwrap();
        let re_push = Regex::new(r"(?i)^\s*push\s+([a-z0-9]+)").unwrap();
        let re_pop = Regex::new(r"(?i)^\s*pop\s+([a-z0-9]+)").unwrap();
        let re_dst_reg = Regex::new(r"(?i)^\s*(mov|add|sub|xor|and|or|imul|shl|shr|sar|lea)\s+([a-z0-9]+)\s*,").unwrap();
        let re_ret = Regex::new(r"(?i)^\s*ret\b").unwrap();

        let mut used_avx = false;
        let mut has_vzeroupper = false;
        let mut pushed = HashSet::new();
        let mut popped = HashSet::new();
        let mut modified = HashSet::new();
        let mut has_call = false;

        // First pass: scan properties
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.to_lowercase().starts_with('v') && !trimmed.to_lowercase().starts_with("var") {
                used_avx = true;
                if trimmed.to_lowercase().starts_with("vzeroupper") {
                    has_vzeroupper = true;
                }
            }
            if let Some(caps) = re_push.captures(trimmed) {
                pushed.insert(caps[1].to_lowercase());
            }
            if let Some(caps) = re_pop.captures(trimmed) {
                popped.insert(caps[1].to_lowercase());
            }
            if let Some(caps) = re_dst_reg.captures(trimmed) {
                modified.insert(canonical_reg(&caps[2].to_lowercase()));
            }
            if re_call.is_match(trimmed) {
                has_call = true;
            }
        }

        // Determine which callee-saved registers need preservation
        let callee_saved = match self.abi {
            CallingConvention::Windows_X64 => vec!["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            _ => vec!["rbx", "rbp", "r12", "r13", "r14", "r15"],
        };

        let mut regs_to_preserve = Vec::new();
        for reg in callee_saved {
            if modified.contains(reg) && (!pushed.contains(reg) || !popped.contains(reg)) {
                regs_to_preserve.push(reg);
            }
        }

        // Calculate needed stack adjustment for alignment & shadow space
        // Base entry has offset = 8. Each push adds 8.
        let pushes_count = pushed.len() + regs_to_preserve.len();
        let offset_after_pushes = (8 + pushes_count * 8) % 16;
        let needed_sub_rsp = match self.abi {
            CallingConvention::Windows_X64 if has_call => {
                // Must be at least 32, and total offset must be 0 mod 16
                if offset_after_pushes == 0 {
                    32 // 0 + 32 = 32 (aligned)
                } else {
                    40 // 8 + 40 = 48 (aligned)
                }
            }
            _ if has_call => {
                if offset_after_pushes == 8 {
                    8 // 8 + 8 = 16 (aligned)
                } else {
                    0
                }
            }
            _ => 0,
        };

        let mut inserted_pushes = false;

        for line in &lines {
            let trimmed = line.trim();

            // Insert callee-saved pushes right after label or at entry
            if !inserted_pushes && (trimmed.ends_with(':') || (!trimmed.is_empty() && !trimmed.starts_with(';'))) {
                if trimmed.ends_with(':') {
                    new_lines.push(line.to_string());
                }

                for reg in &regs_to_preserve {
                    let fix = format!("    push {}", reg);
                    changes.push(AutoFixEdit {
                        rule: "CALLEE_SAVED_AUTO_PRESERVE".into(),
                        description: format!("Automatically added prologue 'push {}' to preserve callee-saved register.", reg),
                        original_line: line.to_string(),
                        fixed_line: fix.clone(),
                    });
                    new_lines.push(fix);
                }

                if needed_sub_rsp > 0 && !lines.iter().any(|l| re_sub_rsp.is_match(l)) {
                    let fix = format!("    sub rsp, {}", needed_sub_rsp);
                    changes.push(AutoFixEdit {
                        rule: "STACK_ALIGNMENT_AUTO_ALLOCATE".into(),
                        description: format!("Automatically allocated {} bytes for 16-byte stack alignment & shadow space.", needed_sub_rsp),
                        original_line: line.to_string(),
                        fixed_line: fix.clone(),
                    });
                    new_lines.push(fix);
                }

                inserted_pushes = true;
                if trimmed.ends_with(':') {
                    continue;
                }
            }

            // Fix 1: Replace 'mov rax, 0' with 'xor eax, eax'
            if let Some(caps) = re_mov_zero.captures(line) {
                let indent = &caps[1];
                let reg = &caps[2];
                let comment = &caps[3];
                let sub_32 = to_32bit_subreg(reg);
                let fixed = format!("{}xor {}, {}{}", indent, sub_32, sub_32, comment);
                changes.push(AutoFixEdit {
                    rule: "ZERO_LATENCY_IDIOM".into(),
                    description: format!("Replaced inefficient 'mov {}, 0' with zero-latency 'xor {}, {}'.", reg, sub_32, sub_32),
                    original_line: line.to_string(),
                    fixed_line: fixed.clone(),
                });
                new_lines.push(fixed);
                continue;
            }

            // Fix 2: Split direct 64-bit immediate write to memory into register load
            if let Some(caps) = re_mem_imm64.captures(line) {
                let indent = &caps[1];
                let mem = &caps[2];
                let imm = &caps[3];
                let comment = &caps[4];
                let load_line = format!("{}mov r11, {}{}", indent, imm, comment);
                let store_line = format!("{}mov {}, r11", indent, mem);
                changes.push(AutoFixEdit {
                    rule: "SPLIT_64BIT_IMM_MEM_WRITE".into(),
                    description: "Split invalid 64-bit immediate-to-memory write into temporary register intermediate.".into(),
                    original_line: line.to_string(),
                    fixed_line: format!("{}\n{}", load_line, store_line),
                });
                new_lines.push(load_line);
                new_lines.push(store_line);
                continue;
            }

            // Fix 3: Adjust existing sub rsp if misaligned
            if let Some(caps) = re_sub_rsp.captures(line) {
                if needed_sub_rsp > 0 {
                    let indent = &caps[1];
                    let comment = &caps[3];
                    let fixed = format!("{}sub rsp, {}{}", indent, needed_sub_rsp, comment);
                    if fixed.trim() != line.trim() {
                        changes.push(AutoFixEdit {
                            rule: "ADJUST_STACK_SUB_RSP".into(),
                            description: format!("Adjusted stack allocation to {} bytes to satisfy 16-byte alignment and ABI requirements.", needed_sub_rsp),
                            original_line: line.to_string(),
                            fixed_line: fixed.clone(),
                        });
                        new_lines.push(fixed);
                        continue;
                    }
                }
            }

            // Fix 4: Adjust existing add rsp if matching
            if let Some(caps) = re_add_rsp.captures(line) {
                if needed_sub_rsp > 0 {
                    let indent = &caps[1];
                    let comment = &caps[3];
                    let fixed = format!("{}add rsp, {}{}", indent, needed_sub_rsp, comment);
                    if fixed.trim() != line.trim() {
                        changes.push(AutoFixEdit {
                            rule: "ADJUST_STACK_ADD_RSP".into(),
                            description: format!("Adjusted stack cleanup to {} bytes.", needed_sub_rsp),
                            original_line: line.to_string(),
                            fixed_line: fixed.clone(),
                        });
                        new_lines.push(fixed);
                        continue;
                    }
                }
            }

            // Fix 5: Before RET, insert stack cleanup, callee-saved pops, and vzeroupper
            if re_ret.is_match(trimmed) {
                // If sub rsp was auto-inserted, insert matching add rsp before ret
                if needed_sub_rsp > 0 && !lines.iter().any(|l| re_add_rsp.is_match(l)) {
                    let fix = format!("    add rsp, {}", needed_sub_rsp);
                    changes.push(AutoFixEdit {
                        rule: "STACK_CLEANUP_AUTO_ADD".into(),
                        description: format!("Automatically inserted 'add rsp, {}' stack cleanup before ret.", needed_sub_rsp),
                        original_line: line.to_string(),
                        fixed_line: fix.clone(),
                    });
                    new_lines.push(fix);
                }

                // Restore preserved registers in reverse order
                for reg in regs_to_preserve.iter().rev() {
                    let fix = format!("    pop {}", reg);
                    changes.push(AutoFixEdit {
                        rule: "CALLEE_SAVED_AUTO_RESTORE".into(),
                        description: format!("Automatically inserted 'pop {}' before ret to restore callee-saved state.", reg),
                        original_line: line.to_string(),
                        fixed_line: fix.clone(),
                    });
                    new_lines.push(fix);
                }

                // Insert vzeroupper if AVX was used
                if used_avx && !has_vzeroupper {
                    let fix = "    vzeroupper".to_string();
                    changes.push(AutoFixEdit {
                        rule: "INSERT_VZEROUPPER".into(),
                        description: "Automatically inserted 'vzeroupper' before ret to eliminate AVX-to-SSE transition penalties.".into(),
                        original_line: line.to_string(),
                        fixed_line: fix.clone(),
                    });
                    new_lines.push(fix);
                }
            }

            new_lines.push(line.to_string());
        }

        let fixed_code = new_lines.join("\n");
        let fixes_applied = changes.len();

        AutoFixReport {
            original_code: code.to_string(),
            fixed_code,
            changes_made: changes,
            fixes_applied,
        }
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
