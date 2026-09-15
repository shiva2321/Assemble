use crate::types::{CallingConvention, LintDiagnostic, Severity};
use regex::Regex;
use std::collections::HashSet;

pub struct Arm64Linter {
    _abi: CallingConvention,
}

impl Arm64Linter {
    pub fn new(abi: CallingConvention) -> Self {
        Self { _abi: abi }
    }

    pub fn lint(&self, assembly_code: &str) -> Vec<LintDiagnostic> {
        let mut diagnostics = Vec::new();
        let lines: Vec<&str> = assembly_code.lines().collect();

        let mut has_frame_saved = false;
        let mut has_branch_link = false;
        let mut branch_link_line = 0;
        let mut had_div = false;
        let mut had_zero_guard = false;
        let mut div_line = 0;

        let mut saved_registers = HashSet::new();
        let mut restored_registers = HashSet::new();
        let mut modified_registers = HashSet::new();

        let re_stp = Regex::new(r"(?i)^\s*stp\s+([a-z0-9]+),\s*([a-z0-9]+)").unwrap();
        let re_ldp = Regex::new(r"(?i)^\s*ldp\s+([a-z0-9]+),\s*([a-z0-9]+)").unwrap();
        let re_str = Regex::new(r"(?i)^\s*str\s+([a-z0-9]+)").unwrap();
        let re_ldr = Regex::new(r"(?i)^\s*ldr\s+([a-z0-9]+)").unwrap();
        let re_bl = Regex::new(r"(?i)^\s*bl\s+").unwrap();
        let re_div = Regex::new(r"(?i)^\s*(sdiv|udiv)\s+([a-z0-9]+),\s*([a-z0-9]+),\s*([a-z0-9]+)").unwrap();
        let re_zero_check = Regex::new(r"(?i)^\s*(cbz|cbnz|cmp)\b.*#0").unwrap();
        let re_dst_reg = Regex::new(r"(?i)^\s*(mov|add|sub|eor|and|orr|lsl|lsr|asr|mul|smull|msub)\s+([a-z0-9]+)\b").unwrap();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let mut trimmed = line.trim();
            if let Some(pos) = trimmed.find("//") {
                trimmed = trimmed[..pos].trim();
            }
            if let Some(pos) = trimmed.find(';') {
                trimmed = trimmed[..pos].trim();
            }
            if trimmed.is_empty() || trimmed.ends_with(':') {
                continue;
            }

            if let Some(caps) = re_stp.captures(trimmed) {
                let r1 = canonical_arm_reg(&caps[1]);
                let r2 = canonical_arm_reg(&caps[2]);
                saved_registers.insert(r1.clone());
                saved_registers.insert(r2.clone());
                if (r1 == "x29" && r2 == "x30") || (r1 == "x30" && r2 == "x29") {
                    has_frame_saved = true;
                }
            }

            if let Some(caps) = re_ldp.captures(trimmed) {
                let r1 = canonical_arm_reg(&caps[1]);
                let r2 = canonical_arm_reg(&caps[2]);
                restored_registers.insert(r1);
                restored_registers.insert(r2);
            }

            if let Some(caps) = re_str.captures(trimmed) {
                saved_registers.insert(canonical_arm_reg(&caps[1]));
            }

            if let Some(caps) = re_ldr.captures(trimmed) {
                restored_registers.insert(canonical_arm_reg(&caps[1]));
            }

            if let Some(caps) = re_dst_reg.captures(trimmed) {
                let r = canonical_arm_reg(&caps[2]);
                modified_registers.insert(r);
            }

            if re_zero_check.is_match(trimmed) {
                had_zero_guard = true;
            }

            if let Some(_caps) = re_div.captures(trimmed) {
                had_div = true;
                div_line = line_num;
            }

            if re_bl.is_match(trimmed) {
                has_branch_link = true;
                branch_link_line = line_num;
            }
        }

        if has_branch_link && !has_frame_saved {
            diagnostics.push(LintDiagnostic {
                rule: "ARM64_MISSING_FRAME_PAIR".into(),
                severity: Severity::Error,
                line: branch_link_line,
                col: 1,
                message: "Non-leaf ARM64 function calls 'bl' without saving FP (x29) and LR (x30).".into(),
                explanation: "Branch with Link ('bl') overwrites the Link Register (x30). Without saving x29 and x30, returning via 'ret' crashes or returns to wrong location.".into(),
                fix_suggestion: Some("Add 'stp x29, x30, [sp, #-16]!' in prologue and 'ldp x29, x30, [sp], #16' before ret.".into()),
            });
        }

        if had_div && !had_zero_guard {
            diagnostics.push(LintDiagnostic {
                rule: "ARM64_SILENT_DIVISION_BY_ZERO".into(),
                severity: Severity::Warning,
                line: div_line,
                col: 1,
                message: "ARM64 'sdiv'/'udiv' without divisor zero-check. Division by zero silently yields 0 without trapping.".into(),
                explanation: "Unlike x86 which triggers a hardware exception, ARM64 hardware division returns 0 when dividing by zero. This causes silent logic errors.".into(),
                fix_suggestion: Some("Check divisor before division using 'cbz x_denom, .div_by_zero_handler'.".into()),
            });
        }

        let callee_saved_arm = vec![
            "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
            "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
        ];

        for reg in callee_saved_arm {
            if modified_registers.contains(reg) {
                let is_saved = saved_registers.contains(reg);
                let is_restored = restored_registers.contains(reg);

                if !is_saved || !is_restored {
                    diagnostics.push(LintDiagnostic {
                        rule: "CALLEE_SAVED_REGISTER_CLOBBERED".into(),
                        severity: Severity::Error,
                        line: lines.len(),
                        col: 1,
                        message: format!("ARM64 callee-saved register '{}' was modified but not preserved (saved={}, restored={}).", reg, is_saved, is_restored),
                        explanation: "AAPCS64 requires x19-x28 and d8-d15 to be preserved across calls.".into(),
                        fix_suggestion: Some(format!("Save '{}' in function prologue using 'stp' and restore with 'ldp' before return.", reg)),
                    });
                }
            }
        }

        diagnostics
    }
}

fn canonical_arm_reg(r: &str) -> String {
    let lower = r.to_lowercase();
    if lower.starts_with('w') {
        format!("x{}", &lower[1..])
    } else if lower.starts_with('s') {
        format!("d{}", &lower[1..])
    } else {
        lower
    }
}
