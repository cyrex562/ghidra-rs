//! A data-access shim for a trace's registers.
//!
//! Port of `ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess`.

use crate::pcode::emu::ErasedPcodeThread;
use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;

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
    use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
    use crate::program::model::address::{Address, AddressRange, AddressSetView};
    use crate::program::model::lang::language::Language;
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;

    /// A minimal fake implementation to test the trait bounds.
    struct FakeRegistersAccess;

    impl PcodeTraceDataAccess for FakeRegistersAccess {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn set_state(&mut self, _range: &AddressRange, _state: TraceMemoryState) {
            unimplemented!("not exercised by these tests")
        }
        fn get_viewport_state(&self, _range: &AddressRange) -> TraceMemoryState {
            unimplemented!("not exercised by these tests")
        }
        fn intersect_view_known(
            &self,
            _view: &dyn AddressSetView,
            _use_full_spans: bool,
        ) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by these tests")
        }
        fn put_bytes(&mut self, _start: &Address, _buf: &[u8]) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _start: &Address, _buf: &mut [u8]) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn translate(&self, _address: &Address) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_property_access<T>(&self, _name: &str) -> Box<dyn PcodeTracePropertyAccess<T>>
        where
            T: 'static,
        {
            unimplemented!("not exercised by these tests")
        }
    }

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
