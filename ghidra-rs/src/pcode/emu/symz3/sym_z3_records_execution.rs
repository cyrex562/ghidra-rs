//! Port of `ghidra.pcode.emu.symz3.SymZ3RecordsExecution`.

use crate::pcode::seam_stubs::SymZ3PcodeThread;
use crate::program::model::address::Address;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::PcodeOp;
use crate::trace::model::target::path::key_path::KeyPath;

/// Port of the nested `record RecInstruction(int index, SymZ3PcodeThread thread, Instruction
/// instruction)`. Rust has no nested/inner-class equivalent, so this is a flat, free-standing
/// struct alongside the trait, per this crate's established convention (see
/// e.g. `Z3InfixPrinter::RegisterPlusConstant`).
#[derive(Clone)]
pub struct RecInstruction {
    pub index: i32,
    pub thread: SymZ3PcodeThread,
    pub instruction: std::sync::Arc<dyn Instruction>,
}

impl RecInstruction {
    pub fn new(index: i32, thread: SymZ3PcodeThread, instruction: std::sync::Arc<dyn Instruction>) -> Self {
        Self { index, thread, instruction }
    }

    /// Java: `"[%s]: %s".formatted(thread.getName(), instruction)`, where the `instruction`
    /// conversion is Java's default `Instruction.toString()` (mnemonic followed by its operand
    /// representations, comma-separated). This crate has no ported `Display` for `dyn
    /// Instruction`, so it is rebuilt here from `CodeUnit::get_mnemonic_string` and
    /// `Instruction::get_default_operand_representation`.
    pub fn to_display_string(&self) -> String {
        format!("[{}]: {}", self.thread.get_name(), self.instruction_display())
    }

    fn instruction_display(&self) -> String {
        let mnemonic = self.instruction.get_mnemonic_string();
        let n = self.instruction.get_num_operands();
        if n <= 0 {
            return mnemonic;
        }
        let operands: Vec<String> = (0..n)
            .map(|i| self.instruction.get_default_operand_representation(i))
            .collect();
        format!("{} {}", mnemonic, operands.join(","))
    }

    /// Java: `KeyPath.parse(thread.getName()).index()`.
    pub fn get_thread_name(&self) -> Option<String> {
        thread_index(&self.thread)
    }

    /// Java: `instruction.getAddress()`.
    pub fn get_address(&self) -> Address {
        self.instruction.get_min_address()
    }
}

/// Port of the nested `record RecOp(int index, SymZ3PcodeThread thread, PcodeOp op)`.
#[derive(Clone)]
pub struct RecOp {
    pub index: i32,
    pub thread: SymZ3PcodeThread,
    pub op: PcodeOp,
}

impl RecOp {
    pub fn new(index: i32, thread: SymZ3PcodeThread, op: PcodeOp) -> Self {
        Self { index, thread, op }
    }

    /// Java: `KeyPath.parse(thread.getName()).index()`.
    pub fn get_thread_name(&self) -> Option<String> {
        thread_index(&self.thread)
    }

    /// Java: `op.getSeqnum().getTarget()`.
    pub fn get_address(&self) -> Address {
        self.op.get_seqnum().get_target().clone()
    }
}

/// Shared helper for `RecInstruction::getThreadName`/`RecOp::getThreadName`, both of which are
/// Java's `KeyPath.parse(thread.getName()).index()`.
fn thread_index(thread: &SymZ3PcodeThread) -> Option<String> {
    KeyPath::parse(&thread.get_name())
        .ok()
        .and_then(|kp| kp.last_index().ok().flatten().map(|s| s.to_string()))
}

/// Port of `ghidra.pcode.emu.symz3.SymZ3RecordsExecution`.
///
/// A genuine open extension point (per `scripts/shape_rules.py`): [`InternalSymZ3RecordsExecution`]
/// and [`crate::pcode::emu::symz3::sym_z3_pcode_emulator_trait::SymZ3PcodeEmulatorTrait`] both
/// extend it in-repo.
pub trait SymZ3RecordsExecution {
    fn get_instructions(&self) -> Vec<RecInstruction>;
    fn get_ops(&self) -> Vec<RecOp>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber};
    use std::sync::Arc;

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(Arc::clone(space), offset)
    }

    #[test]
    fn rec_op_derives_thread_name_and_address_like_java() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let a = addr(&space, 0x1000);
        let seq = SequenceNumber::new(a.clone(), 0);
        let op = PcodeOp::with_address_no_inputs(a.clone(), 0, OpCode::Copy);
        let thread = SymZ3PcodeThread::named("[Threads][1]");
        let rec = RecOp::new(0, thread, op);

        // Java: KeyPath.parse("[Threads][1]").index() == "1"
        assert_eq!(rec.get_thread_name().as_deref(), Some("1"));
        assert_eq!(rec.get_address(), *seq.get_target());
    }
}
