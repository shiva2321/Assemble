use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use crate::types::{CpuRegisters, FlagDiff, RegisterDiff, Syntax, TraceStep};
use crate::assembler::iced_backend::disassemble_x86_64;
use std::collections::HashMap;

pub struct StepTracer {
    registers: CpuRegisters,
    memory: HashMap<u64, u8>,
    max_steps: usize,
}

impl Default for StepTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl StepTracer {
    pub fn new() -> Self {
        Self {
            registers: CpuRegisters::new_x86_64(),
            memory: HashMap::new(),
            max_steps: 1000,
        }
    }

    pub fn set_initial_register(&mut self, reg: &str, val: u64) {
        self.registers.set(reg, val);
    }

    pub fn trace(&mut self, bytes: &[u8], base_ip: u64) -> Result<Vec<TraceStep>, String> {
        let mut steps = Vec::new();
        self.registers.set("rip", base_ip);

        let mut ip = base_ip;
        let mut step_count = 0;

        while step_count < self.max_steps {
            let offset = (ip.wrapping_sub(base_ip)) as usize;
            if offset >= bytes.len() {
                break;
            }

            let slice = &bytes[offset..];
            let mut decoder = Decoder::with_ip(64, slice, ip, DecoderOptions::NONE);
            if !decoder.can_decode() {
                break;
            }

            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);

            let reg_snapshot_before = self.registers.clone();
            let mut mem_writes = Vec::new();

            // Execute single instruction
            let next_ip = self.execute_instruction(&instr, &mut mem_writes)?;

            // Compute register diffs
            let mut reg_diffs = Vec::new();
            for (reg, &after_val) in &self.registers.gprs {
                let before_val = reg_snapshot_before.get(reg);
                if before_val != after_val {
                    reg_diffs.push(RegisterDiff {
                        reg: reg.clone(),
                        before: before_val,
                        after: after_val,
                    });
                }
            }
            reg_diffs.sort_by(|a, b| a.reg.cmp(&b.reg));

            // Compute flag diffs
            let mut flag_diffs = Vec::new();
            check_flag_diff("CF", reg_snapshot_before.flags.cf, self.registers.flags.cf, &mut flag_diffs);
            check_flag_diff("ZF", reg_snapshot_before.flags.zf, self.registers.flags.zf, &mut flag_diffs);
            check_flag_diff("SF", reg_snapshot_before.flags.sf, self.registers.flags.sf, &mut flag_diffs);
            check_flag_diff("OF", reg_snapshot_before.flags.of, self.registers.flags.of, &mut flag_diffs);

            let disasm = disassemble_x86_64(&bytes[offset..offset + instr.len()], ip, Syntax::Intel);
            let text = disasm.first().map(|d| d.text.clone()).unwrap_or_else(|| format!("{:?}", instr.mnemonic()));
            let hex_bytes = bytes[offset..offset + instr.len()]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            steps.push(TraceStep {
                step: step_count + 1,
                address: ip,
                instruction: text,
                bytes: hex_bytes,
                reg_diffs,
                flag_diffs,
                memory_writes: mem_writes,
            });

            if instr.flow_control() == FlowControl::Return {
                break;
            }

            ip = next_ip;
            self.registers.set("rip", ip);
            step_count += 1;
        }

        Ok(steps)
    }

    fn execute_instruction(&mut self, instr: &Instruction, mem_writes: &mut Vec<String>) -> Result<u64, String> {
        let ip = instr.ip();
        let next_ip = ip + instr.len() as u64;

        match instr.mnemonic() {
            Mnemonic::Mov => {
                let val = self.get_op_val(instr, 1)?;
                self.set_op_val(instr, 0, val, mem_writes)?;
            }
            Mnemonic::Lea => {
                let ea = self.calculate_ea(instr, 1)?;
                self.set_op_val(instr, 0, ea, mem_writes)?;
            }
            Mnemonic::Xor => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let res = op0 ^ op1;
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.cf = false;
                self.registers.flags.of = false;
            }
            Mnemonic::Adc => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let carry_in = if self.registers.flags.cf { 1u64 } else { 0u64 };
                let (res1, c1) = op0.overflowing_add(op1);
                let (res, c2) = res1.overflowing_add(carry_in);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.cf = c1 || c2;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = ((op0 ^ res) & (op1 ^ res) & 0x8000000000000000) != 0;
            }
            Mnemonic::Sbb => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let borrow_in = if self.registers.flags.cf { 1u64 } else { 0u64 };
                let (res1, b1) = op0.overflowing_sub(op1);
                let (res, b2) = res1.overflowing_sub(borrow_in);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.cf = b1 || b2;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = ((op0 ^ op1) & (op0 ^ res) & 0x8000000000000000) != 0;
            }
            Mnemonic::Xchg => {
                let v0 = self.get_op_val(instr, 0)?;
                let v1 = self.get_op_val(instr, 1)?;
                self.set_op_val(instr, 0, v1, mem_writes)?;
                self.set_op_val(instr, 1, v0, mem_writes)?;
            }
            Mnemonic::Bswap => {
                let val = self.get_op_val(instr, 0)?;
                self.set_op_val(instr, 0, val.swap_bytes(), mem_writes)?;
            }
            Mnemonic::Clc => {
                self.registers.flags.cf = false;
            }
            Mnemonic::Stc => {
                self.registers.flags.cf = true;
            }
            Mnemonic::Cmc => {
                self.registers.flags.cf = !self.registers.flags.cf;
            }
            Mnemonic::Cld => {
                self.registers.flags.df = false;
            }
            Mnemonic::Std => {
                self.registers.flags.df = true;
            }
            Mnemonic::Pause => {}
            Mnemonic::Add => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let (res, carry) = op0.overflowing_add(op1);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.cf = carry;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = ((op0 ^ res) & (op1 ^ res) & 0x8000000000000000) != 0;
            }
            Mnemonic::Sub => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let (res, borrow) = op0.overflowing_sub(op1);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.cf = borrow;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = ((op0 ^ op1) & (op0 ^ res) & 0x8000000000000000) != 0;
            }
            Mnemonic::Imul => {
                match instr.op_count() {
                    2 => {
                        let op0 = self.get_op_val(instr, 0)? as i64;
                        let op1 = self.get_op_val(instr, 1)? as i64;
                        let (res, overflow) = op0.overflowing_mul(op1);
                        self.set_op_val(instr, 0, res as u64, mem_writes)?;
                        self.registers.flags.of = overflow;
                        self.registers.flags.cf = overflow;
                    }
                    3 => {
                        let op1 = self.get_op_val(instr, 1)? as i64;
                        let op2 = self.get_op_val(instr, 2)? as i64;
                        let (res, overflow) = op1.overflowing_mul(op2);
                        self.set_op_val(instr, 0, res as u64, mem_writes)?;
                        self.registers.flags.of = overflow;
                        self.registers.flags.cf = overflow;
                    }
                    _ => {
                        // 1-operand form: RDX:RAX = RAX * op0
                        let rax = self.registers.get("rax") as i64 as i128;
                        let src = self.get_op_val(instr, 0)? as i64 as i128;
                        let res = rax * src;
                        self.registers.set("rax", res as u64);
                        self.registers.set("rdx", (res >> 64) as u64);
                    }
                }
            }
            Mnemonic::Mul => {
                // 1-operand unsigned multiply: RDX:RAX = RAX * op0
                let rax = self.registers.get("rax") as u128;
                let src = self.get_op_val(instr, 0)? as u128;
                let res = rax * src;
                self.registers.set("rax", res as u64);
                self.registers.set("rdx", (res >> 64) as u64);
                let overflow = (res >> 64) != 0;
                self.registers.flags.cf = overflow;
                self.registers.flags.of = overflow;
            }
            Mnemonic::Idiv => {
                let divisor = self.get_op_val(instr, 0)? as i64;
                if divisor == 0 {
                    return Err("Divide by Zero Exception (#DE) in IDIV".into());
                }
                let rdx = self.registers.get("rdx") as i64 as i128;
                let rax = self.registers.get("rax") as u64 as i128;
                let dividend = (rdx << 64) | (rax & 0xFFFFFFFFFFFFFFFF);
                let quotient = dividend / (divisor as i128);
                let remainder = dividend % (divisor as i128);

                self.registers.set("rax", quotient as u64);
                self.registers.set("rdx", remainder as u64);
            }
            Mnemonic::Div => {
                let divisor = self.get_op_val(instr, 0)?;
                if divisor == 0 {
                    return Err("Divide by Zero Exception (#DE) in DIV".into());
                }
                let rdx = (self.registers.get("rdx") as u128) << 64;
                let rax = self.registers.get("rax") as u128;
                let dividend = rdx | rax;
                let quotient = dividend / (divisor as u128);
                let remainder = dividend % (divisor as u128);

                self.registers.set("rax", quotient as u64);
                self.registers.set("rdx", remainder as u64);
            }
            Mnemonic::Cqo => {
                // Sign extend RAX into RDX:RAX
                let rax = self.registers.get("rax") as i64;
                let rdx = if rax < 0 { 0xFFFFFFFFFFFFFFFF } else { 0 };
                self.registers.set("rdx", rdx);
            }
            Mnemonic::Cdq => {
                // Sign extend EAX into EDX:EAX
                let eax = (self.registers.get("rax") & 0xFFFFFFFF) as i32;
                let edx = if eax < 0 { 0xFFFFFFFF } else { 0 };
                self.registers.set("rdx", edx);
            }
            Mnemonic::Neg => {
                let op0 = self.get_op_val(instr, 0)?;
                let res = (0u64).wrapping_sub(op0);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.cf = op0 != 0;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = op0 == 0x8000000000000000;
            }
            Mnemonic::Inc => {
                let op0 = self.get_op_val(instr, 0)?;
                let res = op0.wrapping_add(1);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = op0 == 0x7FFFFFFFFFFFFFFF;
            }
            Mnemonic::Dec => {
                let op0 = self.get_op_val(instr, 0)?;
                let res = op0.wrapping_sub(1);
                self.set_op_val(instr, 0, res, mem_writes)?;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = op0 == 0x8000000000000000;
            }
            Mnemonic::Cmp => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let (res, borrow) = op0.overflowing_sub(op1);
                self.registers.flags.cf = borrow;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
                self.registers.flags.of = ((op0 ^ op1) & (op0 ^ res) & 0x8000000000000000) != 0;
            }
            Mnemonic::Test => {
                let op0 = self.get_op_val(instr, 0)?;
                let op1 = self.get_op_val(instr, 1)?;
                let res = op0 & op1;
                self.registers.flags.cf = false;
                self.registers.flags.of = false;
                self.registers.flags.zf = res == 0;
                self.registers.flags.sf = (res as i64) < 0;
            }
            Mnemonic::Push => {
                let val = self.get_op_val(instr, 0)?;
                let rsp = self.registers.get("rsp").wrapping_sub(8);
                self.registers.set("rsp", rsp);
                self.write_u64(rsp, val);
                mem_writes.push(format!("Stack [0x{:x}] = 0x{:x}", rsp, val));
            }
            Mnemonic::Pop => {
                let rsp = self.registers.get("rsp");
                let val = self.read_u64(rsp);
                self.registers.set("rsp", rsp.wrapping_add(8));
                self.set_op_val(instr, 0, val, mem_writes)?;
            }
            Mnemonic::Jmp => {
                if instr.op0_kind() == OpKind::NearBranch64 {
                    return Ok(instr.near_branch64());
                }
            }
            Mnemonic::Je => {
                if self.registers.flags.zf && instr.op0_kind() == OpKind::NearBranch64 {
                    return Ok(instr.near_branch64());
                }
            }
            Mnemonic::Jne => {
                if !self.registers.flags.zf && instr.op0_kind() == OpKind::NearBranch64 {
                    return Ok(instr.near_branch64());
                }
            }
            Mnemonic::Ret => {
                return Ok(next_ip);
            }
            Mnemonic::Nop => {}
            _ => {}
        }

        Ok(next_ip)
    }

    fn get_op_val(&self, instr: &Instruction, op_idx: u32) -> Result<u64, String> {
        match instr.op_kind(op_idx) {
            OpKind::Register => {
                let reg_name = format!("{:?}", instr.op_register(op_idx)).to_lowercase();
                Ok(self.registers.get(&reg_name))
            }
            OpKind::Immediate8 | OpKind::Immediate8_2nd => Ok(instr.immediate8() as u64),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                Ok((instr.immediate8() as i8 as i64) as u64)
            }
            OpKind::Immediate16 => Ok(instr.immediate16() as u64),
            OpKind::Immediate32 => Ok(instr.immediate32() as u64),
            OpKind::Immediate32to64 => Ok((instr.immediate32() as i32 as i64) as u64),
            OpKind::Immediate64 => Ok(instr.immediate64()),
            OpKind::Memory => {
                let ea = self.calculate_ea(instr, op_idx)?;
                Ok(self.read_u64(ea))
            }
            _ => Ok(0),
        }
    }

    fn set_op_val(&mut self, instr: &Instruction, op_idx: u32, val: u64, mem_writes: &mut Vec<String>) -> Result<(), String> {
        match instr.op_kind(op_idx) {
            OpKind::Register => {
                let reg_name = format!("{:?}", instr.op_register(op_idx)).to_lowercase();
                self.registers.set(&reg_name, val);
                Ok(())
            }
            OpKind::Memory => {
                let ea = self.calculate_ea(instr, op_idx)?;
                self.write_u64(ea, val);
                mem_writes.push(format!("Memory [0x{:x}] = 0x{:x}", ea, val));
                Ok(())
            }
            _ => Err("Invalid destination operand".into()),
        }
    }

    fn calculate_ea(&self, instr: &Instruction, _op_idx: u32) -> Result<u64, String> {
        let base_reg = instr.memory_base();
        let index_reg = instr.memory_index();
        let scale = instr.memory_index_scale();
        let disp = instr.memory_displacement64();

        let mut addr: u64 = disp;
        if base_reg != Register::None {
            let base_name = format!("{:?}", base_reg).to_lowercase();
            addr = addr.wrapping_add(self.registers.get(&base_name));
        }
        if index_reg != Register::None {
            let index_name = format!("{:?}", index_reg).to_lowercase();
            let idx_val = self.registers.get(&index_name);
            addr = addr.wrapping_add(idx_val.wrapping_mul(scale as u64));
        }
        Ok(addr)
    }

    fn write_u64(&mut self, addr: u64, val: u64) {
        let bytes = val.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            self.memory.insert(addr + i as u64, *b);
        }
    }

    fn read_u64(&self, addr: u64) -> u64 {
        let mut bytes = [0u8; 8];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.memory.get(&(addr + i as u64)).unwrap_or(&0);
        }
        u64::from_le_bytes(bytes)
    }
}

fn check_flag_diff(name: &str, before: bool, after: bool, diffs: &mut Vec<FlagDiff>) {
    if before != after {
        diffs.push(FlagDiff {
            flag: name.into(),
            before,
            after,
        });
    }
}
