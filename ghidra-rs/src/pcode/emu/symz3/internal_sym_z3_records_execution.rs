//! Port of `ghidra.pcode.emu.symz3.InternalSymZ3RecordsExecution`.

use crate::pcode::emu::symz3::sym_z3_pcode_thread::SymZ3ThreadId;
use crate::pcode::emu::symz3::sym_z3_records_execution::SymZ3RecordsExecution;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::pcode::PcodeOp;
use std::sync::Arc;

/// Port of `ghidra.pcode.emu.symz3.InternalSymZ3RecordsExecution`.
///
/// A genuine open extension point (per `scripts/shape_rules.py`): the one in-repo implementor is
/// `SymZ3PcodeExecutorStatePiece` (now ported).
pub trait InternalSymZ3RecordsExecution: SymZ3RecordsExecution {
    fn add_instruction(&mut self, thread: &SymZ3ThreadId, inst: Arc<dyn Instruction>);
    fn add_op(&mut self, thread: &SymZ3ThreadId, op: PcodeOp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::symz3::sym_z3_records_execution::{RecInstruction, RecOp};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::OpCode;

    /// A minimal in-memory recorder satisfying [`InternalSymZ3RecordsExecution`], modeling the
    /// bookkeeping half of `SymZ3PcodeExecutorStatePiece.addInstruction`/`addOp` faithfully
    /// enough to prove the trait's contract without pulling in the full (unported) state piece.
    #[derive(Default)]
    struct Recorder {
        instructions: Vec<RecInstruction>,
        ops: Vec<RecOp>,
    }

    impl SymZ3RecordsExecution for Recorder {
        fn get_instructions(&self) -> Vec<RecInstruction> {
            self.instructions.clone()
        }
        fn get_ops(&self) -> Vec<RecOp> {
            self.ops.clone()
        }
    }

    impl InternalSymZ3RecordsExecution for Recorder {
        fn add_instruction(&mut self, thread: &SymZ3ThreadId, inst: Arc<dyn Instruction>) {
            let index = self.instructions.len() as i32;
            self.instructions.push(RecInstruction::new(index, thread.clone(), inst));
        }
        fn add_op(&mut self, thread: &SymZ3ThreadId, op: PcodeOp) {
            let index = self.ops.len() as i32;
            self.ops.push(RecOp::new(index, thread.clone(), op));
        }
    }

    #[test]
    fn recorder_accumulates_ops_in_order() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x400);
        let thread = SymZ3ThreadId::new("[Threads][0]");
        let mut recorder = Recorder::default();

        let op0 = PcodeOp::with_address_no_inputs(addr.clone(), 0, OpCode::Copy);
        let op1 = PcodeOp::with_address_no_inputs(addr.clone(), 1, OpCode::Copy);
        recorder.add_op(&thread, op0);
        recorder.add_op(&thread, op1);

        let ops = recorder.get_ops();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].index, 0);
        assert_eq!(ops[1].index, 1);
        assert_eq!(ops[1].get_thread_name().as_deref(), Some("0"));
    }
}
