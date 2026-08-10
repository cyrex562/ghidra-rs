//! A data-access shim for a trace's registers.
//!
//! Port of `ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess`.

use crate::pcode::emu::ErasedPcodeThread;
use crate::pcode::seam_stubs::PcodeTraceDataAccess;

/// A data-access shim for a trace's registers.
///
/// See [`PcodeTraceDataAccess`].
pub trait PcodeTraceRegistersAccess: PcodeTraceDataAccess {
    /// Initialize the given p-code thread's context register using register context from the trace
    /// at the thread's program counter.
    ///
    /// This is called during thread construction, after the program counter is initialized from the
    /// same trace thread. This will ensure that the instruction decoder starts in the same mode as
    /// the disassembler was for the trace.
    fn initialize_thread_context(&self, thread: &mut dyn ErasedPcodeThread);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal fake implementation to test the trait bounds.
    struct FakeRegistersAccess;

    impl PcodeTraceDataAccess for FakeRegistersAccess {}

    impl PcodeTraceRegistersAccess for FakeRegistersAccess {
        fn initialize_thread_context(&self, _thread: &mut dyn ErasedPcodeThread) {
            // Fake implementation: do nothing
        }
    }

    #[test]
    fn test_trait_bounds() {
        let fake = FakeRegistersAccess;
        // Verify that the trait object can be created and is Send + Sync compatible
        let _: &dyn PcodeTraceRegistersAccess = &fake;
    }
}
