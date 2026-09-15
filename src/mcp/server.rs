use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use crate::knowledge::KnowledgeUpdater;
use crate::linter::lint_assembly;
use crate::assembler::{assemble, disassemble};
use crate::emulator::StepTracer;
use crate::fixer::AssemblyAutoFixer;
use crate::safety::SafetyGuardrails;
use crate::types::{Arch, CallingConvention, Syntax};
use std::str::FromStr;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let updater = KnowledgeUpdater::new();
    let kg = updater.load_or_init_graph();
    let safety_guard = SafetyGuardrails::new();

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(trimmed) {
            let id = req.id.clone().unwrap_or(Value::Null);

            match req.method.as_str() {
                "initialize" => {
                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": {
                                "tools": {}
                            },
                            "serverInfo": {
                                "name": "assemble-mcp",
                                "version": env!("CARGO_PKG_VERSION"),
                            }
                        })),
                        error: None,
                    };
                    send_response(&mut stdout, &resp).await?;
                }
                "notifications/initialized" => {
                    // Notification, no response needed
                }
                "tools/list" => {
                    let tools = json!({
                        "tools": [
                            {
                                "name": "asm_lint",
                                "description": "Lints assembly code for ABI violations, stack alignment bugs, shadow space issues, and callee-saved register clobbers.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "code": { "type": "string", "description": "The assembly code to lint" },
                                        "arch": { "type": "string", "description": "Architecture: x86_64, arm64 (default: x86_64)" },
                                        "abi": { "type": "string", "description": "Calling convention: sysv, windows (default: sysv)" }
                                    },
                                    "required": ["code"]
                                }
                            },
                            {
                                "name": "asm_fix",
                                "description": "Automatically repairs assembly errors (aligns stack to 16-bytes, adds Windows shadow space, inserts vzeroupper, preserves callee-saved registers).",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "code": { "type": "string", "description": "The broken assembly code to repair" },
                                        "abi": { "type": "string", "description": "Target calling convention: sysv, windows (default: windows)" }
                                    },
                                    "required": ["code"]
                                }
                            },
                            {
                                "name": "asm_audit_safety",
                                "description": "Scans assembly code for safety guardrails: privileged Ring 0 instructions (cli, hlt, wrmsr), NOP sleds, large unprobed stack frames, and div/0 hazards.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "code": { "type": "string", "description": "The assembly code to audit for safety" }
                                    },
                                    "required": ["code"]
                                }
                            },
                            {
                                "name": "asm_query",
                                "description": "Queries the Assembly Knowledge Graph for instruction semantics, operand rules, CPU flags, ABI constraints, or syscalls.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "query": { "type": "string", "description": "Instruction mnemonic, flag, or concept to look up (e.g. 'xor', 'CF', 'Windows_X64')" }
                                    },
                                    "required": ["query"]
                                }
                            },
                            {
                                "name": "asm_idiom",
                                "description": "Retrieves ultra-optimized assembly tricks and idioms (branchless min/max/abs, bit twiddling, SIMD strlen, lockless spinlocks).",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "category": { "type": "string", "description": "Category: branchless, bitwise, simd, zeroing, atomic, or all" }
                                    },
                                    "required": ["category"]
                                }
                            },
                            {
                                "name": "asm_trace",
                                "description": "Simulates step-by-step assembly execution and returns instruction-by-instruction register mutations, flag diffs, and memory writes.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "code": { "type": "string", "description": "The assembly code to execute" },
                                        "initial_registers": {
                                            "type": "object",
                                            "description": "Optional dictionary of initial register values (e.g. {'rax': 42, 'rbx': 10})"
                                        }
                                    },
                                    "required": ["code"]
                                }
                            },
                            {
                                "name": "asm_disassemble",
                                "description": "Disassembles raw hex machine code bytes into formatted assembly with control flow markings.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "hex_bytes": { "type": "string", "description": "Hexadecimal byte string (e.g. '48 31 c0 c3' or '4831c0c3')" },
                                        "syntax": { "type": "string", "description": "intel, att, nasm, masm (default: intel)" }
                                    },
                                    "required": ["hex_bytes"]
                                }
                            },
                            {
                                "name": "asm_update_kg",
                                "description": "Fetches and updates the local assembly knowledge graph with the latest CPU microarchitecture timings and ISA definitions.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "source_url": { "type": "string", "description": "Optional upstream JSON spec URL" }
                                    }
                                }
                            }
                        ]
                    });

                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(tools),
                        error: None,
                    };
                    send_response(&mut stdout, &resp).await?;
                }
                "tools/call" => {
                    let params = req.params.unwrap_or(Value::Null);
                    let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

                    let tool_result = match tool_name {
                        "asm_lint" => {
                            let code = arguments.get("code").and_then(|v| v.as_str()).unwrap_or("");
                            let arch_str = arguments.get("arch").and_then(|v| v.as_str()).unwrap_or("x86_64");
                            let abi_str = arguments.get("abi").and_then(|v| v.as_str());

                            let arch = Arch::from_str(arch_str).unwrap_or(Arch::X86_64);
                            let abi = abi_str.and_then(|s| CallingConvention::from_str(s).ok());
                            let diags = lint_assembly(code, arch, abi);

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&diags).unwrap_or_default()
                                }]
                            })
                        }
                        "asm_fix" => {
                            let code = arguments.get("code").and_then(|v| v.as_str()).unwrap_or("");
                            let abi_str = arguments.get("abi").and_then(|v| v.as_str()).unwrap_or("windows");
                            let abi = CallingConvention::from_str(abi_str).unwrap_or(CallingConvention::Windows_X64);

                            let fixer = AssemblyAutoFixer::new(abi);
                            let report = fixer.fix(code);

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&report).unwrap_or_default()
                                }]
                            })
                        }
                        "asm_audit_safety" => {
                            let code = arguments.get("code").and_then(|v| v.as_str()).unwrap_or("");
                            let report = safety_guard.audit(code);

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&report).unwrap_or_default()
                                }]
                            })
                        }
                        "asm_query" => {
                            let query = arguments.get("query").and_then(|v| v.as_str()).unwrap_or("");
                            let matches = kg.query(query);

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&matches).unwrap_or_default()
                                }]
                            })
                        }
                        "asm_idiom" => {
                            let cat = arguments.get("category").and_then(|v| v.as_str()).unwrap_or("all");
                            let idioms = if cat == "all" {
                                kg.get_idioms_by_category("")
                            } else {
                                kg.get_idioms_by_category(cat)
                            };

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&idioms).unwrap_or_default()
                                }]
                            })
                        }
                        "asm_trace" => {
                            let code = arguments.get("code").and_then(|v| v.as_str()).unwrap_or("");
                            let init_regs = arguments.get("initial_registers");

                            // Guardrail check before tracing
                            let safety_report = safety_guard.audit(code);
                            if !safety_report.is_executable_safely {
                                json!({
                                    "isError": true,
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Execution blocked by Safety Guardrail: {}", safety_report.summary)
                                    }]
                                })
                            } else {
                                match assemble(code) {
                                    Ok(bytes) => {
                                        let mut tracer = StepTracer::new();
                                        if let Some(map) = init_regs.and_then(|r| r.as_object()) {
                                            for (reg, val) in map {
                                                if let Some(v) = val.as_u64() {
                                                    tracer.set_initial_register(reg, v);
                                                }
                                            }
                                        }
                                        match tracer.trace(&bytes, 0x400000) {
                                            Ok(steps) => json!({
                                                "content": [{
                                                    "type": "text",
                                                    "text": serde_json::to_string_pretty(&steps).unwrap_or_default()
                                                }]
                                            }),
                                            Err(e) => json!({
                                                "isError": true,
                                                "content": [{ "type": "text", "text": format!("Trace error: {}", e) }]
                                            }),
                                        }
                                    }
                                    Err(e) => json!({
                                        "isError": true,
                                        "content": [{ "type": "text", "text": format!("Assembly error: {}", e) }]
                                    }),
                                }
                            }
                        }
                        "asm_disassemble" => {
                            let hex_str = arguments.get("hex_bytes").and_then(|v| v.as_str()).unwrap_or("");
                            let syntax_str = arguments.get("syntax").and_then(|v| v.as_str()).unwrap_or("intel");
                            let syntax = Syntax::from_str(syntax_str).unwrap_or(Syntax::Intel);

                            let clean_hex: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                            let mut bytes = Vec::new();
                            for i in (0..clean_hex.len()).step_by(2) {
                                if i + 2 <= clean_hex.len() {
                                    if let Ok(b) = u8::from_str_radix(&clean_hex[i..i+2], 16) {
                                        bytes.push(b);
                                    }
                                }
                            }

                            let disasm = disassemble(&bytes, 0x400000, syntax);
                            let formatted: Vec<_> = disasm.iter().map(|d| format!("0x{:x}:  {:20} ; mnemonic: {}", d.ip, d.text, d.mnemonic)).collect();

                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": formatted.join("\n")
                                }]
                            })
                        }
                        "asm_update_kg" => {
                            let source = arguments.get("source_url").and_then(|v| v.as_str());
                            match updater.update_from_upstream(source).await {
                                Ok(report) => json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&report).unwrap_or_default()
                                    }]
                                }),
                                Err(e) => json!({
                                    "isError": true,
                                    "content": [{ "type": "text", "text": format!("Update failed: {}", e) }]
                                }),
                            }
                        }
                        _ => json!({
                            "isError": true,
                            "content": [{ "type": "text", "text": format!("Unknown tool: {}", tool_name) }]
                        }),
                    };

                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(tool_result),
                        error: None,
                    };
                    send_response(&mut stdout, &resp).await?;
                }
                _ => {
                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: None,
                        error: Some(json!({
                            "code": -32601,
                            "message": "Method not found"
                        })),
                    };
                    send_response(&mut stdout, &resp).await?;
                }
            }
        }

        line.clear();
    }

    Ok(())
}

async fn send_response<W: AsyncWriteExt + Unpin>(out: &mut W, resp: &JsonRpcResponse) -> Result<(), std::io::Error> {
    let s = serde_json::to_string(resp).unwrap_or_default();
    out.write_all(s.as_bytes()).await?;
    out.write_all(b"\n").await?;
    out.flush().await?;
    Ok(())
}
