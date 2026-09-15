use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Arch {
    X86_64,
    X86_32,
    Arm64,
    Arm32,
    Riscv64,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::X86_32 => write!(f, "x86_32"),
            Arch::Arm64 => write!(f, "arm64"),
            Arch::Arm32 => write!(f, "arm32"),
            Arch::Riscv64 => write!(f, "riscv64"),
        }
    }
}

impl std::str::FromStr for Arch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64" | "x86-64" | "x64" | "amd64" => Ok(Arch::X86_64),
            "x86" | "x86_32" | "i386" | "i686" => Ok(Arch::X86_32),
            "arm64" | "aarch64" => Ok(Arch::Arm64),
            "arm" | "arm32" | "armv7" => Ok(Arch::Arm32),
            "riscv64" | "riscv" | "rv64" => Ok(Arch::Riscv64),
            other => Err(format!("Unsupported architecture: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Syntax {
    Intel,
    Att,
    Nasm,
    Masm,
}

impl std::str::FromStr for Syntax {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "intel" => Ok(Syntax::Intel),
            "att" | "at&t" => Ok(Syntax::Att),
            "nasm" => Ok(Syntax::Nasm),
            "masm" => Ok(Syntax::Masm),
            other => Err(format!("Unsupported syntax: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionMode {
    User,
    Kernel,
    BareMetal,
}

impl Default for ExecutionMode {
    fn default() -> Self {
        Self::User
    }
}

impl std::str::FromStr for ExecutionMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" | "app" | "userspace" => Ok(ExecutionMode::User),
            "kernel" | "driver" | "kmd" | "sys" => Ok(ExecutionMode::Kernel),
            "baremetal" | "embedded" | "firmware" | "freestanding" => Ok(ExecutionMode::BareMetal),
            other => Err(format!("Unknown execution mode: {}. Expected 'user', 'kernel', or 'baremetal'", other)),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    SystemV_AMD64,
    Windows_X64,
    Windows_Kernel,
    Linux_Kernel,
    Arm64_AAPCS,
    Riscv_LP64,
}

impl std::str::FromStr for CallingConvention {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sysv" | "systemv" | "linux" | "elf" | "sysv_amd64" => Ok(CallingConvention::SystemV_AMD64),
            "win64" | "windows" | "ms64" | "windows_x64" | "win_x64" | "msvc" => Ok(CallingConvention::Windows_X64),
            "win_kernel" | "windows_kernel" | "ntoskrnl" | "wdm" | "kmdf" => Ok(CallingConvention::Windows_Kernel),
            "linux_kernel" | "kmod" => Ok(CallingConvention::Linux_Kernel),
            "arm64" | "aapcs" | "aapcs64" | "arm64_aapcs" => Ok(CallingConvention::Arm64_AAPCS),
            "riscv" | "lp64" | "riscv_lp64" | "rv64" => Ok(CallingConvention::Riscv_LP64),
            other => Err(format!("Unknown calling convention: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Hint,
    Info,
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Hint => write!(f, "HINT"),
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintDiagnostic {
    pub rule: String,
    pub severity: Severity,
    pub line: usize,
    pub col: usize,
    pub message: String,
    pub explanation: String,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuFlags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
    pub df: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuRegisters {
    pub gprs: HashMap<String, u64>,
    pub flags: CpuFlags,
}

impl CpuRegisters {
    pub fn new_x86_64() -> Self {
        let mut gprs = HashMap::new();
        let regs = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"
        ];
        for r in regs {
            gprs.insert(r.to_string(), 0);
        }
        gprs.insert("rsp".to_string(), 0x7fffffff0000);
        gprs.insert("rbp".to_string(), 0x7fffffff0000);
        Self {
            gprs,
            flags: CpuFlags::default(),
        }
    }

    pub fn get(&self, reg: &str) -> u64 {
        let r = reg.to_lowercase();
        *self.gprs.get(&r).unwrap_or(&0)
    }

    pub fn set(&mut self, reg: &str, val: u64) {
        let r = reg.to_lowercase();
        match r.as_str() {
            "eax" => { self.gprs.insert("rax".into(), val & 0xFFFFFFFF); },
            "ebx" => { self.gprs.insert("rbx".into(), val & 0xFFFFFFFF); },
            "ecx" => { self.gprs.insert("rcx".into(), val & 0xFFFFFFFF); },
            "edx" => { self.gprs.insert("rdx".into(), val & 0xFFFFFFFF); },
            "esi" => { self.gprs.insert("rsi".into(), val & 0xFFFFFFFF); },
            "edi" => { self.gprs.insert("rdi".into(), val & 0xFFFFFFFF); },
            "esp" => { self.gprs.insert("rsp".into(), val & 0xFFFFFFFF); },
            "ebp" => { self.gprs.insert("rbp".into(), val & 0xFFFFFFFF); },
            "r8d" => { self.gprs.insert("r8".into(), val & 0xFFFFFFFF); },
            "r9d" => { self.gprs.insert("r9".into(), val & 0xFFFFFFFF); },
            "r10d" => { self.gprs.insert("r10".into(), val & 0xFFFFFFFF); },
            "r11d" => { self.gprs.insert("r11".into(), val & 0xFFFFFFFF); },
            "r12d" => { self.gprs.insert("r12".into(), val & 0xFFFFFFFF); },
            "r13d" => { self.gprs.insert("r13".into(), val & 0xFFFFFFFF); },
            "r14d" => { self.gprs.insert("r14".into(), val & 0xFFFFFFFF); },
            "r15d" => { self.gprs.insert("r15".into(), val & 0xFFFFFFFF); },
            _ => { self.gprs.insert(r, val); }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDiff {
    pub reg: String,
    pub before: u64,
    pub after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagDiff {
    pub flag: String,
    pub before: bool,
    pub after: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: usize,
    pub address: u64,
    pub instruction: String,
    pub bytes: String,
    pub reg_diffs: Vec<RegisterDiff>,
    pub flag_diffs: Vec<FlagDiff>,
    pub memory_writes: Vec<String>,
}
