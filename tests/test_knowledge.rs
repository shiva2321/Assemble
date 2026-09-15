use assemble::knowledge::KnowledgeUpdater;
use assemble::types::CallingConvention;

#[test]
fn test_knowledge_graph_instruction_lookup() {
    let updater = KnowledgeUpdater::new();
    let kg = updater.load_or_init_graph();

    let xor_matches = kg.query("xor");
    assert!(!xor_matches.is_empty(), "Should find XOR instruction");
}

#[test]
fn test_knowledge_graph_calling_convention_lookup() {
    let updater = KnowledgeUpdater::new();
    let kg = updater.load_or_init_graph();

    let sysv = kg.get_calling_convention(CallingConvention::SystemV_AMD64);
    assert!(sysv.is_some());
    let sysv = sysv.unwrap();
    assert_eq!(sysv.arg_registers, vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    assert_eq!(sysv.stack_alignment_bytes, 16);

    let win64 = kg.get_calling_convention(CallingConvention::Windows_X64);
    assert!(win64.is_some());
    let win64 = win64.unwrap();
    assert_eq!(win64.shadow_space_bytes, 32);
}

#[test]
fn test_knowledge_graph_idioms_lookup() {
    let updater = KnowledgeUpdater::new();
    let kg = updater.load_or_init_graph();

    let branchless = kg.get_idioms_by_category("branchless");
    assert!(!branchless.is_empty(), "Should find branchless idioms");
    let has_abs = branchless.iter().any(|i| i.id.contains("abs"));
    assert!(has_abs, "Should have branchless abs idiom");
}
