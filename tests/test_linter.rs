use assemble::linter::lint_assembly;
use assemble::types::{Arch, CallingConvention, Severity};

#[test]
fn test_stack_misalignment_detected() {
    let code = r#"
    push rbp
    ; now stack is 16-byte aligned
    push rbx
    ; now stack is 8-byte misaligned
    call some_func
    pop rbx
    pop rbp
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::SystemV_AMD64));
    let has_align_err = diags.iter().any(|d| d.rule == "STACK_ALIGNMENT_VIOLATION" && d.severity == Severity::Error);
    assert!(has_align_err, "Expected STACK_ALIGNMENT_VIOLATION error");
}

#[test]
fn test_windows_shadow_space_missing() {
    let code = r#"
    sub rsp, 8
    call some_func
    add rsp, 8
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::Windows_X64));
    let has_shadow_err = diags.iter().any(|d| d.rule == "WINDOWS_SHADOW_SPACE_MISSING");
    assert!(has_shadow_err, "Expected WINDOWS_SHADOW_SPACE_MISSING error");
}

#[test]
fn test_callee_saved_register_clobber() {
    let code = r#"
    mov r12, 99
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::SystemV_AMD64));
    let has_clobber_err = diags.iter().any(|d| d.rule == "CALLEE_SAVED_REGISTER_CLOBBERED");
    assert!(has_clobber_err, "Expected CALLEE_SAVED_REGISTER_CLOBBERED error");
}

#[test]
fn test_clean_code_passes() {
    let code = r#"
    push rbp
    push rbx
    sub rsp, 40
    call some_func
    add rsp, 40
    pop rbx
    pop rbp
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::Windows_X64));
    let errors: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Error).collect();
    assert!(errors.is_empty(), "Expected clean code to have 0 errors, got: {:?}", errors);
}

#[test]
fn test_zero_latency_suggestion() {
    let code = r#"
    mov rax, 0
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::SystemV_AMD64));
    let has_hint = diags.iter().any(|d| d.rule == "ZERO_LATENCY_IDIOM_SUGGESTION");
    assert!(has_hint, "Expected ZERO_LATENCY_IDIOM_SUGGESTION hint");
}

#[test]
fn test_unchecked_idiv_overflow_detected() {
    let code = r#"
    mov rax, 100
    cqo
    idiv rcx
    ret
    "#;

    let diags = lint_assembly(code, Arch::X86_64, Some(CallingConvention::SystemV_AMD64));
    let has_warn = diags.iter().any(|d| d.rule == "UNCHECKED_IDIV_OVERFLOW");
    assert!(has_warn, "Expected UNCHECKED_IDIV_OVERFLOW warning");
}

#[test]
fn test_arm64_missing_frame_pair() {
    let code = r#"
    bl some_function
    ret
    "#;

    let diags = lint_assembly(code, Arch::Arm64, Some(CallingConvention::Arm64_AAPCS));
    let has_frame_err = diags.iter().any(|d| d.rule == "ARM64_MISSING_FRAME_PAIR");
    assert!(has_frame_err, "Expected ARM64_MISSING_FRAME_PAIR error");
}

#[test]
fn test_arm64_silent_division_by_zero() {
    let code = r#"
    sdiv x2, x0, x1
    ret
    "#;

    let diags = lint_assembly(code, Arch::Arm64, Some(CallingConvention::Arm64_AAPCS));
    let has_div_warn = diags.iter().any(|d| d.rule == "ARM64_SILENT_DIVISION_BY_ZERO");
    assert!(has_div_warn, "Expected ARM64_SILENT_DIVISION_BY_ZERO warning");
}

#[test]
fn test_riscv_missing_ra_save() {
    let code = r#"
    call external_func
    ret
    "#;

    let diags = lint_assembly(code, Arch::Riscv64, Some(CallingConvention::Riscv_LP64));
    let has_ra_err = diags.iter().any(|d| d.rule == "RISCV_MISSING_RA_SAVE");
    assert!(has_ra_err, "Expected RISCV_MISSING_RA_SAVE error");
}

#[test]
fn test_riscv_silent_division_by_zero() {
    let code = r#"
    div a2, a0, a1
    ret
    "#;

    let diags = lint_assembly(code, Arch::Riscv64, Some(CallingConvention::Riscv_LP64));
    let has_div_warn = diags.iter().any(|d| d.rule == "RISCV_SILENT_DIVISION_BY_ZERO");
    assert!(has_div_warn, "Expected RISCV_SILENT_DIVISION_BY_ZERO warning");
}

