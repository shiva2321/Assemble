pub mod iced_backend;
pub mod nasm_backend;

pub use iced_backend::*;
pub use nasm_backend::*;
use crate::types::Syntax;

pub fn assemble(assembly_code: &str) -> Result<Vec<u8>, String> {
    let nasm = NasmAssembler::new();
    if nasm.is_available() {
        nasm.assemble_bin(assembly_code)
    } else {
        Err("NASM is not available on this system. Install NASM or configure backend.".into())
    }
}

pub fn disassemble(bytes: &[u8], base_ip: u64, syntax: Syntax) -> Vec<DisassembledInstruction> {
    disassemble_x86_64(bytes, base_ip, syntax)
}
