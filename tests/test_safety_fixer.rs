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

#[test]
fn test_safety_audit_kernel_mode_permits_ring0() {
    use assemble::types::ExecutionMode;
    let code = "cli\nin al, 0x64\nout 0x20, al\nsti\nret";
    let guard = SafetyGuardrails::new();
    
    // In User mode: dangerous
    let user_report = guard.audit_with_mode(code, ExecutionMode::User);
    assert_eq!(user_report.overall_risk, SafetyRiskLevel::Dangerous);
    assert!(user_report.findings.iter().any(|f| f.category == "PRIVILEGED_INSTRUCTION"));

    // In Kernel mode: privileged instructions are valid Ring 0 operations
    let kernel_report = guard.audit_with_mode(code, ExecutionMode::Kernel);
    assert_eq!(kernel_report.overall_risk, SafetyRiskLevel::Safe);
    assert!(kernel_report.findings.is_empty());
}

#[test]
fn test_safety_audit_driver_cli_without_sti() {
    use assemble::types::ExecutionMode;
    let code = "cli\nin al, 0x60\nret";
    let guard = SafetyGuardrails::new();
    let report = guard.audit_with_mode(code, ExecutionMode::Kernel);

    assert!(report.findings.iter().any(|f| f.category == "CLI_WITHOUT_STI"));
}

#[test]
fn test_safety_audit_driver_spinlock_without_pause() {
    use assemble::types::ExecutionMode;
    let code = r#"
.spin:
    test byte [lock], 1
    jnz .spin
    ret
    "#;
    let guard = SafetyGuardrails::new();
    let report = guard.audit_with_mode(code, ExecutionMode::Kernel);

    assert!(report.findings.iter().any(|f| f.category == "SPINLOCK_WITHOUT_PAUSE"));
}

#[test]
fn test_templates_retrieval_and_listing() {
    use assemble::templates;
    let templates_list = templates::list_templates();
    assert!(templates_list.len() >= 5);

    let uart = templates::get_template("baremetal-uart");
    assert!(uart.is_some());
    let u = uart.unwrap();
    assert!(u.code.contains("16550A UART"));
    assert!(u.code.contains("uart_init"));

    let isr = templates::get_template("kernel-isr");
    assert!(isr.is_some());
    assert!(isr.unwrap().code.contains("iretq"));

    let spinlock = templates::get_template("spinlock");
    assert!(spinlock.is_some());
    assert!(spinlock.unwrap().code.contains("pause"));
}
