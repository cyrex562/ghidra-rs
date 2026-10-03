//! The two kinds of emulator step Ghidra's trace schedule language can express.
//!
//! Port of `ghidra.trace.model.time.schedule.StepKind`.

use super::stepper::Stepper;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;

/// Mirrors `public enum StepKind implements Stepper`.
///
/// Java's two enum constants, `INSTRUCTION` and `PCODE`, each supply an anonymous-class override
/// of `tick`/`skip`; this enum keeps that behavior in [`Stepper::tick`]/[`Stepper::skip`], matched
/// on the variant, since Rust enum variants cannot carry their own method bodies the way Java enum
/// constants can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepKind {
    /// Steps or skips a whole instruction. Mirrors `StepKind.INSTRUCTION`.
    Instruction,
    /// Steps or skips a single p-code operation. Mirrors `StepKind.PCODE`.
    Pcode,
}

impl Stepper for StepKind {
    /// Mirrors `StepKind.INSTRUCTION.tick`/`StepKind.PCODE.tick`, which call
    /// `thread.stepInstruction()`/`thread.stepPcodeOp()` respectively.
    fn tick(&self, thread: &mut dyn ErasedPcodeThread) {
        match self {
            StepKind::Instruction => thread.erased_step_instruction(),
            StepKind::Pcode => thread.erased_step_pcode_op(),
        }
    }

    /// Mirrors `StepKind.INSTRUCTION.skip`/`StepKind.PCODE.skip`, which call
    /// `thread.skipInstruction()`/`thread.skipPcodeOp()` respectively.
    fn skip(&self, thread: &mut dyn ErasedPcodeThread) {
        match self {
            StepKind::Instruction => thread.erased_skip_instruction(),
            StepKind::Pcode => thread.erased_skip_pcode_op(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records which of the four erased stepping calls landed, so `tick`/`skip` on each variant
    /// can be checked to route to the correct one -- Java's `INSTRUCTION` and `PCODE` constants
    /// call four different `PcodeThread` methods between them
    /// (`stepInstruction`/`skipInstruction`/`stepPcodeOp`/`skipPcodeOp`), and it would be a real
    /// bug for `Instruction` to end up calling a `*_pcode_op` method or vice versa.
    #[derive(Default)]
    struct RecordingThread {
        calls: Mutex<Vec<&'static str>>,
    }

    impl ErasedPcodeThread for RecordingThread {
        fn erased_step_instruction(&mut self) {
            self.calls.lock().unwrap().push("step_instruction");
        }
        fn erased_skip_instruction(&mut self) {
            self.calls.lock().unwrap().push("skip_instruction");
        }
        fn erased_step_pcode_op(&mut self) {
            self.calls.lock().unwrap().push("step_pcode_op");
        }
        fn erased_skip_pcode_op(&mut self) {
            self.calls.lock().unwrap().push("skip_pcode_op");
        }
    }

    #[test]
    fn instruction_tick_steps_a_whole_instruction() {
        let mut thread = RecordingThread::default();
        StepKind::Instruction.tick(&mut thread);
        assert_eq!(*thread.calls.lock().unwrap(), vec!["step_instruction"]);
    }

    #[test]
    fn instruction_skip_skips_a_whole_instruction() {
        let mut thread = RecordingThread::default();
        StepKind::Instruction.skip(&mut thread);
        assert_eq!(*thread.calls.lock().unwrap(), vec!["skip_instruction"]);
    }

    #[test]
    fn pcode_tick_steps_a_single_pcode_op() {
        let mut thread = RecordingThread::default();
        StepKind::Pcode.tick(&mut thread);
        assert_eq!(*thread.calls.lock().unwrap(), vec!["step_pcode_op"]);
    }

    #[test]
    fn pcode_skip_skips_a_single_pcode_op() {
        let mut thread = RecordingThread::default();
        StepKind::Pcode.skip(&mut thread);
        assert_eq!(*thread.calls.lock().unwrap(), vec!["skip_pcode_op"]);
    }

    #[test]
    fn tick_dispatches_as_a_stepper_trait_object() {
        // Confirms `StepKind` actually satisfies `Stepper` (`implements Stepper` in Java) and can
        // be used polymorphically, not just via its own inherent methods.
        let mut thread = RecordingThread::default();
        let stepper: &dyn Stepper = &StepKind::Pcode;
        stepper.tick(&mut thread);
        assert_eq!(*thread.calls.lock().unwrap(), vec!["step_pcode_op"]);
    }

    #[test]
    fn variants_are_distinct_and_copy() {
        let a = StepKind::Instruction;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(StepKind::Instruction, StepKind::Pcode);
    }
}
