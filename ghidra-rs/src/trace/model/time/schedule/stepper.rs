use crate::pcode::emu::pcode_thread::ErasedPcodeThread;

/// A strategy for stepping a PcodeThread.
///
/// Mirrors Java interface `ghidra.trace.model.time.schedule.Stepper`. Java's `tick`/`skip` accept
/// a mutable `PcodeThread<?>` reference (calling `thread.stepInstruction()` etc. really does
/// mutate the thread), so the erased thread parameter here is `&mut dyn ErasedPcodeThread` rather
/// than a shared reference.
///
/// The concrete implementor of this trait is
/// [`StepKind`](crate::trace::model::time::schedule::step_kind::StepKind) (port of
/// `ghidra.trace.model.time.schedule.StepKind`, `public enum StepKind implements Stepper`).
///
/// Java's `Stepper` interface also declares two static factory methods, `instruction()` and
/// `pcode()`, that just return `StepKind.INSTRUCTION`/`StepKind.PCODE`. Those live on `StepKind`
/// itself in this port (`StepKind::INSTRUCTION`/`StepKind::PCODE` construction is simply
/// `StepKind::Instruction`/`StepKind::Pcode`) rather than on this trait, since Rust traits have no
/// namespaced-static equivalent that reads naturally as `Stepper::instruction()`.
pub trait Stepper: Send + Sync {
    /// Perform the step operation on the given thread.
    fn tick(&self, thread: &mut dyn ErasedPcodeThread);

    /// Skip the step operation on the given thread.
    fn skip(&self, thread: &mut dyn ErasedPcodeThread);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A minimal mock [`Stepper`], independent of [`StepKind`](super::super::step_kind::StepKind),
    /// verifying only that the trait itself can be implemented and invoked as a trait object
    /// through a `&mut dyn ErasedPcodeThread`. [`super::super::step_kind`] carries the real,
    /// end-to-end behavioral tests for the actual `StepKind` variants.
    struct MockStepper {
        tick_count: Mutex<i32>,
        skip_count: Mutex<i32>,
    }

    impl MockStepper {
        fn new() -> Self {
            MockStepper {
                tick_count: Mutex::new(0),
                skip_count: Mutex::new(0),
            }
        }
    }

    impl Stepper for MockStepper {
        fn tick(&self, _thread: &mut dyn ErasedPcodeThread) {
            *self.tick_count.lock().unwrap() += 1;
        }

        fn skip(&self, _thread: &mut dyn ErasedPcodeThread) {
            *self.skip_count.lock().unwrap() += 1;
        }
    }

    /// A thread mock that never needs any real stepping behavior; it just needs to exist so a
    /// `&mut dyn ErasedPcodeThread` can be formed.
    struct InertThread;
    impl ErasedPcodeThread for InertThread {}

    #[test]
    fn tick_and_skip_are_dispatched_through_the_trait_object() {
        let mock = MockStepper::new();
        let stepper: &dyn Stepper = &mock;
        let mut thread = InertThread;

        stepper.tick(&mut thread);
        stepper.tick(&mut thread);
        stepper.skip(&mut thread);

        assert_eq!(*mock.tick_count.lock().unwrap(), 2);
        assert_eq!(*mock.skip_count.lock().unwrap(), 1);
    }
}
