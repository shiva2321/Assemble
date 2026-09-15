use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::{Arch, CallingConvention};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionNode {
    pub mnemonic: String,
    pub arch: Arch,
    pub summary: String,
    pub syntax_forms: Vec<String>,
    pub flags_read: Vec<String>,
    pub flags_written: Vec<String>,
    pub flags_undefined: Vec<String>,
    pub implicit_registers_read: Vec<String>,
    pub implicit_registers_written: Vec<String>,
    pub latency_cycles: Option<f32>,
    pub throughput_cycles: Option<f32>,
    pub extension: String,
    pub traps_and_pitfalls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNode {
    pub name: String,
    pub arch: Arch,
    pub width_bits: usize,
    pub parent_register: Option<String>,
    pub sub_registers: Vec<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagNode {
    pub name: String,
    pub full_name: String,
    pub description: String,
    pub condition_codes_testing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingConventionNode {
    pub id: CallingConvention,
    pub name: String,
    pub arch: Arch,
    pub arg_registers: Vec<String>,
    pub float_arg_registers: Vec<String>,
    pub return_registers: Vec<String>,
    pub callee_saved_registers: Vec<String>,
    pub caller_saved_registers: Vec<String>,
    pub stack_alignment_bytes: usize,
    pub shadow_space_bytes: usize,
    pub red_zone_bytes: usize,
    pub rules_and_traps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdiomNode {
    pub id: String,
    pub name: String,
    pub category: String,
    pub arch: Arch,
    pub description: String,
    pub assembly_intel: String,
    pub assembly_att: Option<String>,
    pub assembly_arm64: Option<String>,
    pub why_it_matters: String,
    pub latency_cycles: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallNode {
    pub id: u32,
    pub name: String,
    pub arch: Arch,
    pub os: String,
    pub signature: String,
    pub arg_registers: Vec<String>,
    pub return_register: String,
    pub clobbered_registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KnowledgeNode {
    Instruction(InstructionNode),
    Register(RegisterNode),
    Flag(FlagNode),
    CallingConvention(CallingConventionNode),
    Idiom(IdiomNode),
    Syscall(SyscallNode),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KnowledgeEdge {
    ModifiesFlag,
    TestsFlag,
    ClobbersRegister,
    ImplicitRead,
    BelongsToConvention,
    OptimizedBy,
    HasSubRegister,
}

#[derive(Debug, Clone)]
pub struct KnowledgeGraph {
    pub graph: DiGraph<KnowledgeNode, KnowledgeEdge>,
    pub name_index: HashMap<String, NodeIndex>,
    pub mnemonic_index: HashMap<String, Vec<NodeIndex>>,
    pub idiom_category_index: HashMap<String, Vec<NodeIndex>>,
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            name_index: HashMap::new(),
            mnemonic_index: HashMap::new(),
            idiom_category_index: HashMap::new(),
        }
    }

    pub fn add_instruction(&mut self, instr: InstructionNode) -> NodeIndex {
        let mnemonic_key = instr.mnemonic.to_lowercase();
        let full_key = format!("instr:{}:{}", instr.arch, mnemonic_key);
        let idx = self.graph.add_node(KnowledgeNode::Instruction(instr));
        self.name_index.insert(full_key, idx);
        self.mnemonic_index
            .entry(mnemonic_key)
            .or_default()
            .push(idx);
        idx
    }

    pub fn add_register(&mut self, reg: RegisterNode) -> NodeIndex {
        let key = format!("reg:{}:{}", reg.arch, reg.name.to_lowercase());
        let idx = self.graph.add_node(KnowledgeNode::Register(reg));
        self.name_index.insert(key, idx);
        idx
    }

    pub fn add_flag(&mut self, flag: FlagNode) -> NodeIndex {
        let key = format!("flag:{}", flag.name.to_lowercase());
        let idx = self.graph.add_node(KnowledgeNode::Flag(flag));
        self.name_index.insert(key, idx);
        idx
    }

    pub fn add_calling_convention(&mut self, conv: CallingConventionNode) -> NodeIndex {
        let key = format!("abi:{:?}", conv.id);
        let idx = self.graph.add_node(KnowledgeNode::CallingConvention(conv));
        self.name_index.insert(key, idx);
        idx
    }

    pub fn add_idiom(&mut self, idiom: IdiomNode) -> NodeIndex {
        let key = format!("idiom:{}", idiom.id.to_lowercase());
        let cat_key = idiom.category.to_lowercase();
        let idx = self.graph.add_node(KnowledgeNode::Idiom(idiom));
        self.name_index.insert(key, idx);
        self.idiom_category_index
            .entry(cat_key)
            .or_default()
            .push(idx);
        idx
    }

    pub fn add_syscall(&mut self, sc: SyscallNode) -> NodeIndex {
        let key = format!("syscall:{}:{}:{}", sc.os, sc.arch, sc.name.to_lowercase());
        let idx = self.graph.add_node(KnowledgeNode::Syscall(sc));
        self.name_index.insert(key, idx);
        idx
    }

    pub fn add_relation(&mut self, from: NodeIndex, to: NodeIndex, edge: KnowledgeEdge) {
        self.graph.add_edge(from, to, edge);
    }

    pub fn query(&self, term: &str) -> Vec<&KnowledgeNode> {
        let query = term.to_lowercase();
        let mut matches = Vec::new();

        // 1. Direct mnemonic lookup
        if let Some(indices) = self.mnemonic_index.get(&query) {
            for &idx in indices {
                matches.push(&self.graph[idx]);
            }
        }

        // 2. Comprehensive fuzzy semantic matching
        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let hit = match node {
                KnowledgeNode::Instruction(i) => {
                    i.mnemonic.to_lowercase().contains(&query)
                        || i.summary.to_lowercase().contains(&query)
                        || i.extension.to_lowercase().contains(&query)
                        || i.syntax_forms.iter().any(|s| s.to_lowercase().contains(&query))
                }
                KnowledgeNode::Register(r) => {
                    r.name.to_lowercase() == query || r.role.to_lowercase().contains(&query)
                }
                KnowledgeNode::Flag(f) => {
                    f.name.to_lowercase() == query
                        || f.full_name.to_lowercase().contains(&query)
                        || f.description.to_lowercase().contains(&query)
                }
                KnowledgeNode::CallingConvention(c) => {
                    let conv_id_str = format!("{:?}", c.id).to_lowercase();
                    c.name.to_lowercase().contains(&query)
                        || conv_id_str.contains(&query)
                        || (query == "windows" && conv_id_str.contains("windows"))
                        || (query == "linux" && conv_id_str.contains("systemv"))
                        || (query == "abi" || query == "convention")
                        || c.arg_registers.iter().any(|r| r.to_lowercase() == query)
                }
                KnowledgeNode::Idiom(i) => {
                    i.name.to_lowercase().contains(&query)
                        || i.category.to_lowercase().contains(&query)
                        || i.description.to_lowercase().contains(&query)
                        || i.why_it_matters.to_lowercase().contains(&query)
                }
                KnowledgeNode::Syscall(s) => {
                    s.name.to_lowercase().contains(&query) || s.id.to_string() == query || (query == "syscall")
                }
            };
            if hit && !matches.iter().any(|&m| std::ptr::eq(m, node)) {
                matches.push(node);
            }
        }

        matches
    }

    pub fn get_instruction(&self, mnemonic: &str, arch: Arch) -> Option<&InstructionNode> {
        let m = mnemonic.to_lowercase();
        if let Some(indices) = self.mnemonic_index.get(&m) {
            for &idx in indices {
                if let KnowledgeNode::Instruction(ref i) = self.graph[idx] {
                    if i.arch == arch {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn get_calling_convention(&self, conv: CallingConvention) -> Option<&CallingConventionNode> {
        let key = format!("abi:{:?}", conv);
        if let Some(&idx) = self.name_index.get(&key) {
            if let KnowledgeNode::CallingConvention(ref c) = self.graph[idx] {
                return Some(c);
            }
        }
        None
    }

    pub fn get_idioms_by_category(&self, cat: &str) -> Vec<&IdiomNode> {
        let mut res = Vec::new();
        let cat_lower = cat.to_lowercase();
        for (category, indices) in &self.idiom_category_index {
            if category.contains(&cat_lower) {
                for &idx in indices {
                    if let KnowledgeNode::Idiom(ref id) = self.graph[idx] {
                        res.push(id);
                    }
                }
            }
        }
        res
    }
}
