use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyRiskLevel {
    Safe,
    Caution,
    HighRisk,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyFinding {
    pub category: String,
    pub risk_level: SafetyRiskLevel,
    pub line: usize,
    pub instruction: String,
    pub description: String,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyReport {
    pub overall_risk: SafetyRiskLevel,
    pub is_executable_safely: bool,
    pub findings: Vec<SafetyFinding>,
    pub summary: String,
}

pub struct SafetyGuardrails;

impl Default for SafetyGuardrails {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGuardrails {
    pub fn new() -> Self {
        Self
    }

    pub fn audit(&self, assembly_code: &str) -> SafetyReport {
        let mut findings = Vec::new();
        let lines: Vec<&str> = assembly_code.lines().collect();

        let re_privileged = Regex::new(
            r"(?i)^\s*(cli|sti|hlt|in\b|out\b|ins\b|outs\b|wrmsr|rdmsr|invd|wbinvd|invlpg|lidt|lgdt|ltr|swapgs|sysenter|sysexit)\b"
        ).unwrap();

        let re_getpc = Regex::new(r"(?i)^\s*call\s+(\$\+5|\.+5|[0-9a-fA-FxX]+)\s*$").unwrap();
        let re_pop = Regex::new(r"(?i)^\s*pop\s+([a-z0-9]+)").unwrap();
        let re_large_stack = Regex::new(r"(?i)^\s*sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+|\d+)").unwrap();
        let re_div = Regex::new(r"(?i)^\s*(div|idiv)\s+([a-z0-9]+)").unwrap();

        let mut nop_streak = 0;
        let mut prev_was_getpc = false;

        for (i, line) in lines.iter().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // 1. Privileged Instruction Guard
            if let Some(caps) = re_privileged.captures(trimmed) {
                let instr = caps[1].to_uppercase();
                findings.push(SafetyFinding {
                    category: "PRIVILEGED_INSTRUCTION".into(),
                    risk_level: SafetyRiskLevel::Dangerous,
                    line: line_num,
                    instruction: trimmed.to_string(),
                    description: format!("'{}' is a privileged Ring 0 instruction. Executing this in user-space will immediately trigger a General Protection Fault (#GP).", instr),
                    mitigation: "Remove privileged instruction or implement via OS kernel driver API.".into(),
                });
            }

            // 2. NOP Sled Heuristic (Buffer overflow / shellcode pattern)
            if trimmed.eq_ignore_ascii_case("nop") {
                nop_streak += 1;
                if nop_streak == 4 {
                    findings.push(SafetyFinding {
                        category: "NOP_SLED_DETECTED".into(),
                        risk_level: SafetyRiskLevel::HighRisk,
                        line: line_num,
                        instruction: trimmed.to_string(),
                        description: "Detected consecutive NOP instructions typical of exploit NOP sleds or padding.".into(),
                        mitigation: "Replace multi-NOP padding with architectural multi-byte NOPs (e.g. 'nop dword [rax]') or optimize alignment with assembler '.align' directives.".into(),
                    });
                }
            } else {
                nop_streak = 0;
            }

            // 3. GetPC Shellcode Stub Detection (call $+5 ; pop reg)
            if re_getpc.is_match(trimmed) {
                prev_was_getpc = true;
            } else if prev_was_getpc {
                if let Some(caps) = re_pop.captures(trimmed) {
                    findings.push(SafetyFinding {
                        category: "POSITION_INDEPENDENT_GETPC_STUB".into(),
                        risk_level: SafetyRiskLevel::Caution,
                        line: line_num,
                        instruction: trimmed.to_string(),
                        description: format!("Detected classic GetPC stub ('call $+5; pop {}'). While common in PIC shellcode, in modern 64-bit assembly, RIP-relative addressing is faster and hardware-accelerated.", &caps[1]),
                        mitigation: format!("Replace with RIP-relative address loading: 'lea {}, [rip + target_label]'.", &caps[1]),
                    });
                }
                prev_was_getpc = false;
            }

            // 4. Large Stack Allocation without Probe (Stack Overflow / Chkstk Guard)
            if let Some(caps) = re_large_stack.captures(trimmed) {
                let val_str = &caps[2];
                let val = if let Some(hex) = val_str.strip_prefix("0x").or_else(|| val_str.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    val_str.parse::<u64>().unwrap_or(0)
                };

                // In Windows, allocating > 4096 bytes (1 page) on stack without __chkstk will miss guard pages and crash!
                if val >= 4096 {
                    findings.push(SafetyFinding {
                        category: "UNPROBED_LARGE_STACK_ALLOCATION".into(),
                        risk_level: SafetyRiskLevel::HighRisk,
                        line: line_num,
                        instruction: trimmed.to_string(),
                        description: format!("Stack allocation of {} bytes exceeds page size (4096 bytes). Without stack probing, this can bypass the OS guard page and cause immediate stack corruption or memory faults.", val),
                        mitigation: "Call '__chkstk' (Windows) or allocate in increments of 4096 bytes touching each page, or allocate large buffers on heap instead.".into(),
                    });
                }
            }

            // 5. Division Safety Guard
            if let Some(caps) = re_div.captures(trimmed) {
                let divisor = caps[2].to_lowercase();
                // Inspect preceding code lines in the function (up to 25 instructions back)
                let mut is_guarded = false;
                let test_sub = format!("test {}, {}", divisor, divisor);
                let test_sub_nospace = format!("test {},{}", divisor, divisor);
                let cmp_sub = format!("cmp {}, 0", divisor);
                let cmp_sub_nospace = format!("cmp {},0", divisor);

                let mut code_lines_checked = 0;
                for prev_idx in (0..i).rev() {
                    let prev_line = lines[prev_idx].trim();
                    if prev_line.is_empty() || prev_line.starts_with(';') || prev_line.starts_with('#') || prev_line.starts_with("//") {
                        continue;
                    }
                    let prev_lower = prev_line.to_lowercase();
                    if prev_lower.contains(&test_sub) || prev_lower.contains(&test_sub_nospace) ||
                       prev_lower.contains(&cmp_sub) || prev_lower.contains(&cmp_sub_nospace) {
                        is_guarded = true;
                        break;
                    }

                    // Check if divisor was loaded with a non-zero immediate (e.g. mov r10, 10)
                    let mov_prefix = format!("mov {},", divisor);
                    let mov_prefix_space = format!("mov {}, ", divisor);
                    if prev_lower.starts_with(&mov_prefix) || prev_lower.starts_with(&mov_prefix_space) {
                        let parts: Vec<&str> = prev_lower.split(',').collect();
                        if parts.len() == 2 {
                            let val_str = parts[1].trim();
                            let val = if let Some(hex) = val_str.strip_prefix("0x") {
                                u64::from_str_radix(hex, 16).unwrap_or(0)
                            } else {
                                val_str.parse::<u64>().unwrap_or(0)
                            };
                            if val > 0 {
                                is_guarded = true;
                                break;
                            }
                        }
                    }

                    code_lines_checked += 1;
                    if code_lines_checked >= 25 {
                        break;
                    }
                }

                if !is_guarded {
                    findings.push(SafetyFinding {
                        category: "UNCHECKED_DIVISION_HAZARD".into(),
                        risk_level: SafetyRiskLevel::Caution,
                        line: line_num,
                        instruction: trimmed.to_string(),
                        description: format!("'{}' will trigger an immediate Divide Error Exception (#DE) if divisor '{}' is 0 or if quotient overflows RAX/RDX.", trimmed, divisor),
                        mitigation: format!("Validate divisor: 'test {0}, {0}; jz handle_zero_error' before executing division.", divisor),
                    });
                }
            }
        }

        let overall_risk = if findings.iter().any(|f| f.risk_level == SafetyRiskLevel::Dangerous) {
            SafetyRiskLevel::Dangerous
        } else if findings.iter().any(|f| f.risk_level == SafetyRiskLevel::HighRisk) {
            SafetyRiskLevel::HighRisk
        } else if findings.iter().any(|f| f.risk_level == SafetyRiskLevel::Caution) {
            SafetyRiskLevel::Caution
        } else {
            SafetyRiskLevel::Safe
        };

        let is_executable_safely = overall_risk != SafetyRiskLevel::Dangerous;
        let summary = match overall_risk {
            SafetyRiskLevel::Dangerous => "CRITICAL: Assembly contains privileged or crash-inducing instructions. Blocked from execution.".into(),
            SafetyRiskLevel::HighRisk => "HIGH RISK: Potential stack overflow or memory hazards detected. Review mitigations before execution.".into(),
            SafetyRiskLevel::Caution => "CAUTION: Minor safety or portability concerns detected (e.g. unchecked division or legacy idioms).".into(),
            SafetyRiskLevel::Safe => "SAFE: Code conforms to safety guardrails. No hostile or privileged instructions found.".into(),
        };

        SafetyReport {
            overall_risk,
            is_executable_safely,
            findings,
            summary,
        }
    }
}
