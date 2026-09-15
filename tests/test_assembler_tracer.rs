use assemble::assembler::{assemble, disassemble};
use assemble::emulator::StepTracer;
use assemble::types::Syntax;

#[test]
fn test_assemble_and_disassemble_roundtrip() {
    let code = "mov rax, 0x2a\nret";
    let bytes = assemble(code).expect("Assembly failed");
    assert!(!bytes.is_empty());

    let instrs = disassemble(&bytes, 0x400000, Syntax::Intel);
    assert_eq!(instrs.len(), 2);
    assert_eq!(instrs[0].mnemonic, "mov");
    assert_eq!(instrs[1].mnemonic, "ret");
    assert!(instrs[1].is_ret);
}

#[test]
fn test_tracer_arithmetic_execution() {
    let code = r#"
    mov rax, 10
    add rax, 20
    sub rax, 5
    ret
    "#;

    let bytes = assemble(code).expect("Assembly failed");
    let mut tracer = StepTracer::new();
    let steps = tracer.trace(&bytes, 0x400000).expect("Trace failed");

    assert!(!steps.is_empty());
    // After step 1: rax = 10
    assert_eq!(steps[0].reg_diffs[0].after, 10);
    // After step 2: rax = 30
    assert_eq!(steps[1].reg_diffs[0].after, 30);
    // After step 3: rax = 25
    assert_eq!(steps[2].reg_diffs[0].after, 25);
}

#[test]
fn test_tracer_flags_mutation() {
    let code = r#"
    xor rax, rax
    ret
    "#;

    let bytes = assemble(code).expect("Assembly failed");
    let mut tracer = StepTracer::new();
    let steps = tracer.trace(&bytes, 0x400000).expect("Trace failed");

    let zf_diff = steps[0].flag_diffs.iter().find(|f| f.flag == "ZF");
    assert!(zf_diff.is_some());
    assert_eq!(zf_diff.unwrap().after, true);
}
