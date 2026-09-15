use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use crate::knowledge::KnowledgeUpdater;
use crate::linter::lint_assembly;
use crate::assembler::{assemble, disassemble};
use crate::emulator::StepTracer;
use crate::fixer::AssemblyAutoFixer;
use crate::safety::SafetyGuardrails;
use crate::templates;
use crate::types::{Arch, CallingConvention, ExecutionMode, Severity, Syntax};
use crate::util::read_input_or_file;

#[derive(Parser, Debug)]
#[command(name = "assemble")]
#[command(author = "Assemble Team")]
#[command(version = "0.1.0")]
#[command(about = "Assemble: The Ultimate AI Agent Assembly Toolkit - Linter, Knowledge Graph, Emulator, Debugger, and Idioms", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Lint assembly code for ABI violations, stack misalignment, and instruction traps
    Lint {
        /// Assembly file path, inline string, or '-' for stdin
        input: String,
        /// Target architecture: x86_64, arm64 (default: x86_64)
        #[arg(short, long, default_value = "x86_64")]
        arch: String,
        /// Calling convention: sysv, windows (default: sysv)
        #[arg(long, default_value = "sysv")]
        abi: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Automatically repair assembly bugs (stack alignment, shadow space, vzeroupper, callee-saved)
    Fix {
        /// Assembly file path, inline code string, or '-' for stdin
        input: String,
        /// Calling convention: sysv, windows (default: windows)
        #[arg(long, default_value = "windows")]
        abi: String,
        /// Overwrite the source file with fixed code
        #[arg(short, long)]
        write: bool,
        /// Output report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Audit safety guardrails for privileged instructions, NOP sleds, stack overflows, and traps
    Audit {
        /// Assembly file path, inline string, or '-' for stdin
        input: String,
        /// Execution context mode: user, kernel, baremetal (default: user)
        #[arg(short, long, default_value = "user")]
        mode: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Assemble assembly code into raw machine code bytes and hex
    Asm {
        /// Assembly file path, inline string, or '-' for stdin
        input: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate production assembly scaffolding (drivers, ISRs, spinlocks, bignum, standalone apps)
    Template {
        /// Template name (baremetal-uart, kernel-isr, spinlock, bignum-math, standalone-cli) or 'list'
        #[arg(default_value = "list")]
        name: String,
        /// Output file path to write template code into
        #[arg(short, long)]
        out: Option<String>,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Query the Assembly Knowledge Graph for instructions, flags, registers, or ABIs
    Query {
        /// Search query (e.g. 'xor', 'CF', 'Windows_X64', 'syscall')
        query: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Browse ultra-optimized assembly tricks, branchless idioms, and SIMD patterns
    Idiom {
        /// Category: branchless, bitwise, simd, zeroing, atomic, or all
        #[arg(default_value = "all")]
        category: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Simulate step-by-step execution and display register/flag mutations
    Trace {
        /// Assembly file, inline code string, or '-' for stdin
        input: String,
        /// Initial register values formatted as REG=VAL (e.g. rax=42 rbx=0x10)
        #[arg(long, value_parser = parse_reg_kv)]
        reg: Vec<(String, u64)>,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Disassemble raw machine code hex bytes into formatted assembly
    Disasm {
        /// Hexadecimal byte sequence (e.g. "48 31 c0 c3")
        hex: String,
        /// Syntax style: intel, att, nasm, masm (default: intel)
        #[arg(short, long, default_value = "intel")]
        syntax: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Fetch and update the Knowledge Graph with the latest CPU specs and idioms
    Update {
        /// Optional upstream spec URL
        #[arg(long)]
        source: Option<String>,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Launch the Model Context Protocol (MCP) server over stdio for AI agents
    Mcp,
}

fn parse_reg_kv(s: &str) -> Result<(String, u64), String> {
    let parts: Vec<&str> = s.split('=').collect();
    if parts.len() != 2 {
        return Err("Expected REG=VAL format (e.g. rax=42)".into());
    }
    let reg = parts[0].trim().to_lowercase();
    let val_str = parts[1].trim();
    let val = if let Some(hex) = val_str.strip_prefix("0x").or_else(|| val_str.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?
    } else {
        val_str.parse::<u64>().map_err(|e| e.to_string())?
    };
    Ok((reg, val))
}

pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let updater = KnowledgeUpdater::new();

    match cli.command {
        Commands::Lint { input, arch, abi, json } => {
            let code = read_input_or_file(&input);
            let target_arch = Arch::from_str(&arch).unwrap_or(Arch::X86_64);
            let target_abi = CallingConvention::from_str(&abi).ok();

            let diags = lint_assembly(&code, target_arch, target_abi);

            if json {
                println!("{}", serde_json::to_string_pretty(&diags)?);
            } else {
                println!("\n{}", "=== Assemble Static Linter & ABI Verifier ===".bold().cyan());
                if diags.is_empty() {
                    println!("{}", "✓ No ABI violations or traps detected. Code appears clean!".bold().green());
                } else {
                    println!("Found {} issues:\n", diags.len());
                    for d in &diags {
                        let sev_badge = match d.severity {
                            Severity::Error => " ERROR ".on_red().white().bold(),
                            Severity::Warning => " WARN  ".on_yellow().black().bold(),
                            Severity::Info => " INFO  ".on_blue().white().bold(),
                            Severity::Hint => " HINT  ".on_green().black().bold(),
                        };
                        println!("{} {} [Line {}] - {}", sev_badge, d.rule.bold(), d.line, d.message);
                        println!("   {}", d.explanation.dimmed());
                        if let Some(ref fix) = d.fix_suggestion {
                            println!("   {} {}", "Fix suggestion:".bold().yellow(), fix.green());
                        }
                        println!();
                    }
                }
            }
        }

        Commands::Fix { input, abi, write, json } => {
            let code = read_input_or_file(&input);
            let target_abi = CallingConvention::from_str(&abi).unwrap_or(CallingConvention::Windows_X64);
            let fixer = AssemblyAutoFixer::new(target_abi);
            let report = fixer.fix(&code);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("\n{}", "=== Assemble Automated Assembly Self-Healing ===".bold().cyan());
                println!("Applied {} automated corrections:\n", report.fixes_applied);
                for edit in &report.changes_made {
                    println!("{} {}", "✓".bold().green(), edit.description);
                    println!("   Original: {}", edit.original_line.red());
                    println!("   Repaired: {}", edit.fixed_line.green());
                    println!();
                }

                println!("{}", "--- Repaired Assembly Code ---".bold().yellow());
                println!("{}", report.fixed_code.cyan());

                if write && Path::new(&input).exists() {
                    fs::write(&input, &report.fixed_code)?;
                    println!("\n{}", format!("✓ Overwrote '{}' with repaired code.", input).bold().green());
                }
            }
        }

        Commands::Audit { input, mode, json } => {
            let code = read_input_or_file(&input);
            let exec_mode = ExecutionMode::from_str(&mode).unwrap_or(ExecutionMode::User);
            let guard = SafetyGuardrails::new();
            let report = guard.audit_with_mode(&code, exec_mode);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("\n{}", format!("=== Assemble Absolute Safety Guardrail Audit [{:?}] ===", exec_mode).bold().cyan());
                let status_badge = match report.overall_risk {
                    crate::safety::SafetyRiskLevel::Safe => " VERIFIED SAFE ".on_green().black().bold(),
                    crate::safety::SafetyRiskLevel::Caution => " CAUTION ".on_yellow().black().bold(),
                    crate::safety::SafetyRiskLevel::HighRisk => " HIGH RISK ".on_red().white().bold(),
                    crate::safety::SafetyRiskLevel::Dangerous => " DANGEROUS / MALICIOUS ".on_red().white().bold(),
                };
                println!("Risk Status:  {}", status_badge);
                println!("Summary:     {}\n", report.summary);

                if !report.findings.is_empty() {
                    println!("Specific Findings ({}):", report.findings.len());
                    for f in &report.findings {
                        println!("[Line {}] Category: {} | Instruction: '{}'", f.line, f.category.bold(), f.instruction);
                        println!("   Hazard:     {}", f.description);
                        println!("   Mitigation: {}\n", f.mitigation.green());
                    }
                }
            }
        }

        Commands::Asm { input, json } => {
            let code = read_input_or_file(&input);
            match assemble(&code) {
                Ok(bytes) => {
                    let hex_str = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    if json {
                        let obj = serde_json::json!({
                            "byte_count": bytes.len(),
                            "hex": hex_str,
                            "bytes": bytes
                        });
                        println!("{}", serde_json::to_string_pretty(&obj)?);
                    } else {
                        println!("\n{}", "=== Assemble Machine Code Generation ===".bold().cyan());
                        println!("Generated {} machine code bytes:", bytes.len().to_string().bold().green());
                        println!("  Hex:       {}", hex_str.yellow());
                        println!("  Formatted: {}", bytes.iter().map(|b| format!("0x{:02X}", b)).collect::<Vec<_>>().join(", ").cyan());
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Assembly Error:".bold().red(), e);
                }
            }
        }

        Commands::Template { name, out, json } => {
            if name == "list" {
                let list = templates::list_templates();
                if json {
                    println!("{}", serde_json::to_string_pretty(&list)?);
                } else {
                    println!("\n{}", "=== Assemble Production Template Scaffolding ===".bold().cyan());
                    for t in list {
                        println!("\n{} [{}]", t.name.bold().green(), t.arch.cyan());
                        println!("  {}", t.description);
                        println!("  Category: {}", t.category.yellow());
                    }
                    println!("\nUsage: assemble template <name> [-o output.asm]");
                }
            } else {
                match templates::get_template(&name) {
                    Some(tpl) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&tpl)?);
                        } else {
                            if let Some(ref out_path) = out {
                                fs::write(out_path, &tpl.code)?;
                                println!("\n{}", format!("✓ Successfully wrote template '{}' to {}", tpl.name, out_path).bold().green());
                            } else {
                                println!("\n{} [{}] - {}", tpl.name.bold().green(), format!("{:?}", tpl.arch).cyan(), tpl.description);
                                println!("{}", "--- Source Code ---".dimmed());
                                println!("{}", tpl.code);
                            }
                        }
                    }
                    None => {
                        eprintln!("Unknown template '{}'. Run 'assemble template list' to see available templates.", name);
                    }
                }
            }
        }

        Commands::Query { query, json } => {
            let kg = updater.load_or_init_graph();
            let matches = kg.query(&query);

            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else {
                println!("\n{} '{}' ({} found):", "Assemble Knowledge Query:".bold().cyan(), query.yellow(), matches.len());
                for m in &matches {
                    match m {
                        crate::knowledge::KnowledgeNode::Instruction(i) => {
                            println!("\n{} [{}] - {}", i.mnemonic.to_uppercase().bold().green(), i.extension.dimmed(), i.summary);
                            println!("  Syntax: {}", i.syntax_forms.join(", ").cyan());
                            if !i.flags_written.is_empty() {
                                println!("  Modifies Flags: {}", i.flags_written.join(", ").yellow());
                            }
                            if let Some(lat) = i.latency_cycles {
                                println!("  Latency: ~{} cycles | Throughput: ~{} cycles", lat, i.throughput_cycles.unwrap_or(0.0));
                            }
                            for trap in &i.traps_and_pitfalls {
                                println!("  {} {}", "⚠ Traps:".bold().red(), trap);
                            }
                        }
                        crate::knowledge::KnowledgeNode::Flag(f) => {
                            println!("\n{} ({}) - {}", f.name.bold().magenta(), f.full_name, f.description);
                            println!("  Tested by: {}", f.condition_codes_testing.join(", ").cyan());
                        }
                        crate::knowledge::KnowledgeNode::CallingConvention(c) => {
                            println!("\n{} [{}]", c.name.bold().blue(), format!("{:?}", c.id).dimmed());
                            println!("  Arg Regs: {}", c.arg_registers.join(", ").green());
                            println!("  Return: {}", c.return_registers.join(", ").yellow());
                            println!("  Callee-saved: {}", c.callee_saved_registers.join(", ").magenta());
                            println!("  Stack alignment: {} bytes | Shadow space: {} bytes", c.stack_alignment_bytes, c.shadow_space_bytes);
                            for rule in &c.rules_and_traps {
                                println!("  • {}", rule.dimmed());
                            }
                        }
                        crate::knowledge::KnowledgeNode::Idiom(id) => {
                            println!("\n{} [{}] - {}", id.name.bold().yellow(), id.category.dimmed(), id.description);
                            println!("  Why it matters: {}", id.why_it_matters.dimmed());
                            println!("  Intel Assembly:\n{}", id.assembly_intel.cyan());
                        }
                        crate::knowledge::KnowledgeNode::Syscall(s) => {
                            println!("\nSyscall #{} [{}] {} - {}", s.id, s.os.to_uppercase(), s.name.bold().green(), s.signature);
                            println!("  Args: {}", s.arg_registers.join(", ").cyan());
                            println!("  Return: {}", s.return_register.yellow());
                            println!("  Clobbers: {}", s.clobbered_registers.join(", ").red());
                        }
                        _ => {}
                    }
                }
            }
        }

        Commands::Idiom { category, json } => {
            let kg = updater.load_or_init_graph();
            let idioms = if category == "all" {
                kg.get_idioms_by_category("")
            } else {
                kg.get_idioms_by_category(&category)
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&idioms)?);
            } else {
                println!("\n{} Category '{}' ({} idioms):", "=== Assemble Optimization Catalog ===".bold().cyan(), category.yellow(), idioms.len());
                for id in idioms {
                    println!("\n{} [{}]", id.name.bold().green(), id.category.cyan());
                    println!("  {}", id.description);
                    println!("  Performance: {}", id.latency_cycles.yellow());
                    println!("  Why it matters: {}", id.why_it_matters.dimmed());
                    println!("  Intel Asm:\n{}", id.assembly_intel.cyan());
                    if let Some(ref arm) = id.assembly_arm64 {
                        println!("  ARM64 Equivalent:\n{}", arm.magenta());
                    }
                }
            }
        }

        Commands::Trace { input, reg, json } => {
            let code = read_input_or_file(&input);
            match assemble(&code) {
                Ok(bytes) => {
                    let mut tracer = StepTracer::new();
                    for (r, v) in reg {
                        tracer.set_initial_register(&r, v);
                    }
                    let steps = tracer.trace(&bytes, 0x400000)?;

                    if json {
                        println!("{}", serde_json::to_string_pretty(&steps)?);
                    } else {
                        println!("\n{} ({} instructions executed):", "=== Assemble Step-by-Step Execution Trace ===".bold().cyan(), steps.len());
                        for s in &steps {
                            println!("\nStep {:02} @ 0x{:08x}:  {}  ({})", s.step, s.address, s.instruction.bold().green(), s.bytes.dimmed());
                            for rd in &s.reg_diffs {
                                let before_str = format!("0x{:016x}", rd.before);
                                let after_str = format!("0x{:016x}", rd.after);
                                println!("   Register Mutation: {:<5} {} -> {}", rd.reg.to_uppercase().yellow(), before_str, after_str.cyan());
                            }
                            for fd in &s.flag_diffs {
                                println!("   Flag Change:       {:<5} {} -> {}", fd.flag.magenta(), fd.before, fd.after);
                            }
                            for mw in &s.memory_writes {
                                println!("   Memory Access:     {}", mw.blue());
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Assembly Error:".bold().red(), e);
                }
            }
        }

        Commands::Disasm { hex, syntax, json } => {
            let clean_hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            let mut bytes = Vec::new();
            for i in (0..clean_hex.len()).step_by(2) {
                if i + 2 <= clean_hex.len() {
                    if let Ok(b) = u8::from_str_radix(&clean_hex[i..i+2], 16) {
                        bytes.push(b);
                    }
                }
            }

            let syn = Syntax::from_str(&syntax).unwrap_or(Syntax::Intel);
            let instrs = disassemble(&bytes, 0x400000, syn);

            if json {
                let serialized: Vec<_> = instrs.iter().map(|i| {
                    serde_json::json!({
                        "ip": format!("0x{:x}", i.ip),
                        "text": i.text,
                        "mnemonic": i.mnemonic,
                        "is_branch": i.is_branch,
                        "is_call": i.is_call,
                        "is_ret": i.is_ret
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&serialized)?);
            } else {
                println!("\nDisassembly ({} instructions):", instrs.len());
                for i in &instrs {
                    let mut flags = Vec::new();
                    if i.is_call { flags.push("CALL"); }
                    if i.is_ret { flags.push("RET"); }
                    if i.is_branch { flags.push("BRANCH"); }
                    let flag_str = if flags.is_empty() { String::new() } else { format!("; [{}]", flags.join(", ")) };
                    println!("  0x{:08x}:  {:<24} {}", i.ip, i.text.green(), flag_str.dimmed());
                }
            }
        }

        Commands::Update { source, json } => {
            println!("{}", "Syncing Assemble Knowledge Graph from upstream sources...".cyan());
            match updater.update_from_upstream(source.as_deref()).await {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        println!("{} Status: {}", "✓ Update Complete.".bold().green(), report.status.green());
                        println!("  Timestamp: {}", report.timestamp);
                        println!("  Extra Instructions Indexed: {}", report.instructions_count);
                        println!("  Idioms & Tricks Indexed: {}", report.idioms_count);
                        for note in report.notes {
                            println!("  • {}", note.dimmed());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Update failed:".bold().red(), e);
                }
            }
        }

        Commands::Mcp => {
            crate::mcp::run_mcp_server().await?;
        }
    }

    Ok(())
}
