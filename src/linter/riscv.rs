use crate::types::{CallingConvention, LintDiagnostic, Severity};
use regex::Regex;
use std::collections::HashSet;

pub struct RiscvLinter {
    _abi: CallingConvention,
}

impl RiscvLinter {
    pub fn new(abi: CallingConvention) -> Self {
        Self { _abi: abi }
    }

    pub fn lint(&self, assembly_code: &str) -> Vec<LintDiagnostic> {
        let mut diagnostics = Vec::new();
        let lines: Vec<&str> = assembly_code.lines().collect();

        let mut has_ra_saved = false;
        let mut has_call = false;
        let mut call_line = 0;
        let mut had_div = false;
        let mut had_zero_guard = false;
        let mut div_line = 0;

        let mut saved_registers = HashSet::new();
        let mut restored_registers = HashSet::new();
        let mut modified_registers = HashSet::new();

        let re_sd_sw = Regex::new(r"(?i)^\s*(sd|sw|fsd|fsw)\s+([a-z0-9]+),\s*(-?\d+)\(sp\)").unwrap();
        let re_ld_lw = Regex::new(r"(?i)^\s*(ld|lw|fld|flw)\s+([a-z0-9]+),\s*(-?\d+)\(sp\)").unwrap();
        let re_call = Regex::new(r"(?i)^\s*(call|jal|jalr)\b").unwrap();
        let re_div = Regex::new(r"(?i)^\s*(div[uw]?|rem[uw]?)\s+([a-z0-9]+),\s*([a-z0-9]+),\s*([a-z0-9]+)").unwrap();
        let re_zero_check = Regex::new(r"(?i)^\s*(beqz|bnez)\b").unwrap();
        let re_dst_reg = Regex::new(r"(?i)^\s*(mv|li|add[iw]?|sub[iw]?|mul[iw]?|div[iw]?|rem[iw]?|xor|and|or|sll[iw]?|srl[iw]?|sra[iw]?)\s+([a-z0-9]+)\b").unwrap();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let mut trimmed = line.trim();
            if let Some(pos) = trimmed.find('#') {
                trimmed = trimmed[..pos].trim();
            }
            if let Some(pos) = trimmed.find("//") {
                trimmed = trimmed[..pos].trim();
            }
            if trimmed.is_empty() || trimmed.ends_with(':') {
                continue;
            }

            if let Some(caps) = re_sd_sw.captures(trimmed) {
                let r = canonical_riscv_reg(&caps[2]);
                saved_registers.insert(r.clone());
                if r == "ra" || r == "x1" {
                    has_ra_saved = true;
                }
            }

            if let Some(caps) = re_ld_lw.captures(trimmed) {
                let r = canonical_riscv_reg(&caps[2]);
                restored_registers.insert(r);
            }

            if let Some(caps) = re_dst_reg.captures(trimmed) {
                let r = canonical_riscv_reg(&caps[2]);
                modified_registers.insert(r);
            }

            if re_zero_check.is_match(trimmed) {
                had_zero_guard = true;
            }

            if let Some(_caps) = re_div.captures(trimmed) {
                had_div = true;
                div_line = line_num;
            }

            if re_call.is_match(trimmed) {
                has_call = true;
                call_line = line_num;
            }
        }

        if has_call && !has_ra_saved {
            diagnostics.push(LintDiagnostic {
                rule: "RISCV_MISSING_RA_SAVE".into(),
                severity: Severity::Error,
                line: call_line,
                col: 1,
                message: "Non-leaf RISC-V function calls external function without saving return address 'ra' (x1).".into(),
                explanation: "'call' / 'jal' overwrites the 'ra' register with the return address. Without saving 'ra' on the stack, 'ret' (jalr x0, x1, 0) cannot return to caller.".into(),
                fix_suggestion: Some("Save 'ra' in prologue with 'sd ra, 8(sp)' and restore with 'ld ra, 8(sp)' before ret.".into()),
            });
        }

        if had_div && !had_zero_guard {
            diagnostics.push(LintDiagnostic {
                rule: "RISCV_SILENT_DIVISION_BY_ZERO".into(),
                severity: Severity::Warning,
                line: div_line,
                col: 1,
                message: "RISC-V 'div'/'rem' without zero-check. Division by zero does NOT trap in RISC-V: 'div' returns -1 and 'rem' returns dividend.".into(),
                explanation: "RISC-V architecture intentionally avoids hardware divide-by-zero exceptions. Unchecked division by zero silently returns all 1s (-1), causing subtle arithmetic bugs.".into(),
                fix_suggestion: Some("Check divisor with 'beqz reg, .zero_handler' before division.".into()),
            });
        }

        let callee_saved_riscv = vec![
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
        ];

        for reg in callee_saved_riscv {
            if modified_registers.contains(reg) {
                let is_saved = saved_registers.contains(reg);
                let is_restored = restored_registers.contains(reg);

                if !is_saved || !is_restored {
                    diagnostics.push(LintDiagnostic {
                        rule: "CALLEE_SAVED_REGISTER_CLOBBERED".into(),
                        severity: Severity::Error,
                        line: lines.len(),
                        col: 1,
                        message: format!("RISC-V callee-saved register '{}' was modified but not preserved (saved={}, restored={}).", reg, is_saved, is_restored),
                        explanation: "RISC-V ABI requires s0-s11 and fs0-fs11 to be preserved across calls.".into(),
                        fix_suggestion: Some(format!("Save '{}' to stack in prologue with 'sd {}, offset(sp)' and restore before ret.", reg, reg)),
                    });
                }
            }
        }

        diagnostics
    }
}

fn canonical_riscv_reg(r: &str) -> String {
    let lower = r.to_lowercase();
    match lower.as_str() {
        "x1" => "ra".into(),
        "x2" => "sp".into(),
        "x8" => "s0".into(),
        "x9" => "s1".into(),
        "x18" => "s2".into(),
        "x19" => "s3".into(),
        "x20" => "s4".into(),
        "x21" => "s5".into(),
        "x22" => "s6".into(),
        "x23" => "s7".into(),
        "x24" => "s8".into(),
        "x25" => "s9".into(),
        "x26" => "s10".into(),
        "x27" => "s11".into(),
        other => other.to_string(),
    }
}
