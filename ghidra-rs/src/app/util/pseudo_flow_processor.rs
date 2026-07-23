//! Port of `ghidra.app.util.PseudoFlowProcessor`.
//!
//! Defines methods for flow as if the code were actually being disassembled. This is a plain
//! Java interface with no state, so it maps directly to an object-safe Rust trait. Its
//! `PseudoInstruction` parameter is not yet ported, so it is modeled with the
//! [`PseudoInstructionLike`](crate::app::seam_stubs::PseudoInstructionLike) placeholder trait.

use crate::app::seam_stubs::PseudoInstructionLike;

/// Defines methods for flow as if the code were actually being disassembled.
///
/// Port of `ghidra.app.util.PseudoFlowProcessor`.
pub trait PseudoFlowProcessor {
    /// Process this instruction; return false if instr terminates.
    ///
    /// Port of `PseudoFlowProcessor.process(PseudoInstruction)`.
    fn process(&mut self, instr: &dyn PseudoInstructionLike) -> bool;

    /// Return true if the flows should be followed from this instruction.
    ///
    /// Port of `PseudoFlowProcessor.followFlows(PseudoInstruction)`.
    fn follow_flows(&self, instr: &dyn PseudoInstructionLike) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInstruction;
    impl PseudoInstructionLike for MockInstruction {}

    struct StopAtThirdProcessor {
        calls: usize,
    }

    impl PseudoFlowProcessor for StopAtThirdProcessor {
        fn process(&mut self, _instr: &dyn PseudoInstructionLike) -> bool {
            self.calls += 1;
            self.calls < 3
        }

        fn follow_flows(&self, _instr: &dyn PseudoInstructionLike) -> bool {
            true
        }
    }

    #[test]
    fn process_stops_after_third_call() {
        let mut processor = StopAtThirdProcessor { calls: 0 };
        let dyn_processor: &mut dyn PseudoFlowProcessor = &mut processor;
        let instr = MockInstruction;

        assert!(dyn_processor.process(&instr));
        assert!(dyn_processor.process(&instr));
        assert!(!dyn_processor.process(&instr));
    }

    #[test]
    fn follow_flows_is_object_safe_and_stateless() {
        let processor = StopAtThirdProcessor { calls: 0 };
        let dyn_processor: &dyn PseudoFlowProcessor = &processor;
        let instr = MockInstruction;

        assert!(dyn_processor.follow_flows(&instr));
    }
}
