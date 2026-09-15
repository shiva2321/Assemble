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

#[test]
fn test_tracer_adc_sbb_carry_chain() {
    let code = r#"
    stc
    mov rax, 10
    adc rax, 5
    clc
    mov rbx, 20
    sbb rbx, 5
    ret
    "#;

    let bytes = assemble(code).expect("Assembly failed");
    let mut tracer = StepTracer::new();
    let steps = tracer.trace(&bytes, 0x400000).expect("Trace failed");

    // After step 2 (adc rax, 5 with CF=1): rax = 10 + 5 + 1 = 16
    let adc_step = steps.iter().find(|s| s.instruction.starts_with("adc")).expect("adc step found");
    assert_eq!(adc_step.reg_diffs[0].after, 16);

    // After sbb rbx, 5 with CF=0: rbx = 20 - 5 - 0 = 15
    let sbb_step = steps.iter().find(|s| s.instruction.starts_with("sbb")).expect("sbb step found");
    assert_eq!(sbb_step.reg_diffs[0].after, 15);
}

#[test]
fn test_tracer_lea_and_xchg() {
    let code = r#"
    mov rax, 0x10
    mov rbx, 0x20
    xchg rax, rbx
    lea rdx, [rax + 0x8]
    ret
    "#;

    let bytes = assemble(code).expect("Assembly failed");
    let mut tracer = StepTracer::new();
    let steps = tracer.trace(&bytes, 0x400000).expect("Trace failed");

    // After xchg rax, rbx: rax = 0x20, rbx = 0x10
    let xchg_step = steps.iter().find(|s| s.instruction.starts_with("xchg")).expect("xchg step found");
    let rax_diff = xchg_step.reg_diffs.iter().find(|d| d.reg == "rax").unwrap();
    let rbx_diff = xchg_step.reg_diffs.iter().find(|d| d.reg == "rbx").unwrap();
    assert_eq!(rax_diff.after, 0x20);
    assert_eq!(rbx_diff.after, 0x10);

    // After lea rdx, [rax + 8]: rdx = 0x20 + 8 = 0x28
    let lea_step = steps.iter().find(|s| s.instruction.starts_with("lea")).expect("lea step found");
    assert_eq!(lea_step.reg_diffs[0].after, 0x28);
}

#[test]
fn test_tracer_bswap_and_flags() {
    let code = r#"
    mov rax, 0x1122334455667788
    bswap rax
    stc
    cmc
    ret
    "#;

    let bytes = assemble(code).expect("Assembly failed");
    let mut tracer = StepTracer::new();
    let steps = tracer.trace(&bytes, 0x400000).expect("Trace failed");

    // After bswap rax: 0x8877665544332211
    let bswap_step = steps.iter().find(|s| s.instruction.starts_with("bswap")).expect("bswap step found");
    assert_eq!(bswap_step.reg_diffs[0].after, 0x8877665544332211);

    // After stc: CF = true
    let stc_step = steps.iter().find(|s| s.instruction.starts_with("stc")).expect("stc step found");
    assert_eq!(stc_step.flag_diffs.iter().find(|f| f.flag == "CF").unwrap().after, true);

    // After cmc: CF = false
    let cmc_step = steps.iter().find(|s| s.instruction.starts_with("cmc")).expect("cmc step found");
    assert_eq!(cmc_step.flag_diffs.iter().find(|f| f.flag == "CF").unwrap().after, false);
}
