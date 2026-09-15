use assemble::fixer::AssemblyAutoFixer;
use assemble::linter::lint_assembly;
use assemble::safety::{SafetyGuardrails, SafetyRiskLevel};
use assemble::types::{Arch, CallingConvention, Severity};

#[test]
fn test_auto_fix_produces_clean_code() {
    let buggy_code = r#"
my_func:
    mov rbx, 100
    mov rax, 0
    vmovdqu ymm0, [rsi]
    call printf
    ret
    "#;

    let fixer = AssemblyAutoFixer::new(CallingConvention::Windows_X64);
    let report = fixer.fix(buggy_code);

    assert!(report.fixes_applied >= 4);

    // Verify fixed code passes linter with 0 errors
    let diags = lint_assembly(&report.fixed_code, Arch::X86_64, Some(CallingConvention::Windows_X64));
    let errors: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Error).collect();
    assert!(errors.is_empty(), "Repaired code should have 0 errors, got: {:?}", errors);
}

#[test]
fn test_safety_audit_detects_privileged_instruction() {
    let code = "cli\nhlt\nret";
    let guard = SafetyGuardrails::new();
    let report = guard.audit(code);

    assert_eq!(report.overall_risk, SafetyRiskLevel::Dangerous);
    assert!(!report.is_executable_safely);
    assert!(report.findings.iter().any(|f| f.category == "PRIVILEGED_INSTRUCTION"));
}

#[test]
fn test_safety_audit_clean_code_is_safe() {
    let code = "mov rax, 42\nxor rbx, rbx\nret";
    let guard = SafetyGuardrails::new();
    let report = guard.audit(code);

    assert_eq!(report.overall_risk, SafetyRiskLevel::Safe);
    assert!(report.is_executable_safely);
}
