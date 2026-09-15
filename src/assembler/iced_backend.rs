use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, GasFormatter, Instruction, IntelFormatter,
    MasmFormatter, NasmFormatter,
};
use crate::types::Syntax;

#[derive(Debug, Clone)]
pub struct DisassembledInstruction {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub mnemonic: String,
    pub op_count: usize,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

pub fn disassemble_x86_64(bytes: &[u8], base_ip: u64, syntax: Syntax) -> Vec<DisassembledInstruction> {
    let mut decoder = Decoder::with_ip(64, bytes, base_ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();

    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        let mut output = String::new();
        match syntax {
            Syntax::Intel => {
                let mut formatter = IntelFormatter::new();
                formatter.format(&instruction, &mut output);
            }
            Syntax::Att => {
                let mut formatter = GasFormatter::new();
                formatter.format(&instruction, &mut output);
            }
            Syntax::Nasm => {
                let mut formatter = NasmFormatter::new();
                formatter.format(&instruction, &mut output);
            }
            Syntax::Masm => {
                let mut formatter = MasmFormatter::new();
                formatter.format(&instruction, &mut output);
            }
        }

        let start_index = (instruction.ip() - base_ip) as usize;
        let instr_bytes = if start_index + instruction.len() <= bytes.len() {
            bytes[start_index..start_index + instruction.len()].to_vec()
        } else {
            Vec::new()
        };

        let flow = instruction.flow_control();
        let is_branch = matches!(flow, FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch);
        let is_call = matches!(flow, FlowControl::Call);
        let is_ret = matches!(flow, FlowControl::Return);

        instructions.push(DisassembledInstruction {
            ip: instruction.ip(),
            bytes: instr_bytes,
            text: output,
            mnemonic: format!("{:?}", instruction.mnemonic()).to_lowercase(),
            op_count: instruction.op_count() as usize,
            is_branch,
            is_call,
            is_ret,
        });
    }

    instructions
}
