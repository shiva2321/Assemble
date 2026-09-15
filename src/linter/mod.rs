pub mod arm64;
pub mod riscv;
pub mod x86_64;

use crate::types::{Arch, CallingConvention, LintDiagnostic};
use arm64::Arm64Linter;
use riscv::RiscvLinter;
use x86_64::X86_64Linter;

pub fn lint_assembly(code: &str, arch: Arch, abi: Option<CallingConvention>) -> Vec<LintDiagnostic> {
    match arch {
        Arch::X86_64 => {
            let selected_abi = abi.unwrap_or(CallingConvention::SystemV_AMD64);
            let linter = X86_64Linter::new(selected_abi);
            linter.lint(code)
        }
        Arch::Arm64 => {
            let selected_abi = abi.unwrap_or(CallingConvention::Arm64_AAPCS);
            let linter = Arm64Linter::new(selected_abi);
            linter.lint(code)
        }
        Arch::Riscv64 => {
            let selected_abi = abi.unwrap_or(CallingConvention::Riscv_LP64);
            let linter = RiscvLinter::new(selected_abi);
            linter.lint(code)
        }
        _ => Vec::new(),
    }
}
