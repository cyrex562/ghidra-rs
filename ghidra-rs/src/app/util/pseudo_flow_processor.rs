//! Port of `ghidra.app.util.PseudoFlowProcessor`.
//!
//! Defines methods for flow as if the code were actually being disassembled. This is a plain
//! Java interface with no state, so it maps directly to an object-safe Rust trait. Its
//! `PseudoInstruction` parameter is the instruction type `PseudoDisassembler` produces, the
//! disassembler's [`DisassembledInstruction`].

use crate::program::disassemble::disassembler::DisassembledInstruction;

/// Defines methods for flow as if the code were actually being disassembled.
///
/// Port of `ghidra.app.util.PseudoFlowProcessor`.
pub trait PseudoFlowProcessor {
    /// Process this instruction; return false if instr terminates.
    ///
    /// Port of `PseudoFlowProcessor.process(PseudoInstruction)`.
    fn process(&mut self, instr: &DisassembledInstruction) -> bool;

    /// Return true if the flows should be followed from this instruction.
    ///
    /// Port of `PseudoFlowProcessor.followFlows(PseudoInstruction)`.
    fn follow_flows(&self, instr: &DisassembledInstruction) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::app::util::pseudo_instruction::PseudoInstruction;
    use crate::program::disassemble::disassembler::DisassemblerInstructionContext;
    use crate::program::model::address::Address;
    use crate::program::model::lang::language::Language;
    use crate::program::model::mem::ByteMemBufferImpl;

    /// `mov r1,#0x2a` of the toy sleigh language, as the disassembler would produce it.
    fn instruction() -> DisassembledInstruction {
        let lang = decode_tests::language();
        let addr = Address::new(lang.get_default_space(), 0x1000);
        let bytes = vec![0x11, 0x2a];
        let proto = lang
            .parse_prototype(Arc::new(ByteMemBufferImpl::new(addr.clone(), bytes.clone(), true)), Vec::new(), false)
            .unwrap();
        let mem = ByteMemBufferImpl::new(addr.clone(), bytes, true);
        PseudoInstruction::new(addr, Arc::new(proto), &mem, DisassemblerInstructionContext::new(lang, None)).unwrap()
    }

    struct StopAtThirdProcessor {
        calls: usize,
    }

    impl PseudoFlowProcessor for StopAtThirdProcessor {
        fn process(&mut self, _instr: &DisassembledInstruction) -> bool {
            self.calls += 1;
            self.calls < 3
        }

        fn follow_flows(&self, _instr: &DisassembledInstruction) -> bool {
            true
        }
    }

    #[test]
    fn process_stops_after_third_call() {
        let mut processor = StopAtThirdProcessor { calls: 0 };
        let dyn_processor: &mut dyn PseudoFlowProcessor = &mut processor;
        let instr = instruction();

        assert!(dyn_processor.process(&instr));
        assert!(dyn_processor.process(&instr));
        assert!(!dyn_processor.process(&instr));
    }

    #[test]
    fn follow_flows_is_object_safe_and_stateless() {
        let processor = StopAtThirdProcessor { calls: 0 };
        let dyn_processor: &dyn PseudoFlowProcessor = &processor;
        let instr = instruction();

        assert!(dyn_processor.follow_flows(&instr));
    }
}
