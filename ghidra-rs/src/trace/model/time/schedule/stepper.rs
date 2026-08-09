use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::trace::seam_stubs::StepKind;

/// A strategy for stepping a PcodeThread.
///
/// Mirrors Java interface `ghidra.trace.model.time.schedule.Stepper`.
pub trait Stepper: Send + Sync {
    /// Perform the step operation on the given thread.
    fn tick(&self, thread: &dyn ErasedPcodeThread);

    /// Skip the step operation on the given thread.
    fn skip(&self, thread: &dyn ErasedPcodeThread);
}

/// Blanket implementation: any StepKind can be used as a Stepper.
impl<T: StepKind + ?Sized> Stepper for T {
    fn tick(&self, thread: &dyn ErasedPcodeThread) {
        StepKind::tick(self, thread)
    }

    fn skip(&self, thread: &dyn ErasedPcodeThread) {
        StepKind::skip(self, thread)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock implementation of StepKind for testing.
    struct MockStepKind {
        tick_count: Mutex<i32>,
        skip_count: Mutex<i32>,
    }

    impl MockStepKind {
        fn new() -> Self {
            MockStepKind {
                tick_count: Mutex::new(0),
                skip_count: Mutex::new(0),
            }
        }
    }

    impl StepKind for MockStepKind {
        fn tick(&self, _thread: &dyn ErasedPcodeThread) {
            *self.tick_count.lock().unwrap() += 1;
        }

        fn skip(&self, _thread: &dyn ErasedPcodeThread) {
            *self.skip_count.lock().unwrap() += 1;
        }
    }

    #[test]
    fn test_stepper_trait_implementation() {
        let mock = MockStepKind::new();
        let stepper: &dyn Stepper = &mock;

        assert_eq!(*mock.tick_count.lock().unwrap(), 0);
        assert_eq!(*mock.skip_count.lock().unwrap(), 0);
    }
}
