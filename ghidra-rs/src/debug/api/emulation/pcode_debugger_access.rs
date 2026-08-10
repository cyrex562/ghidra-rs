//! A trace-and-debugger access shim.
//!
//! Port of `ghidra.debug.api.emulation.PcodeDebuggerAccess`.

use crate::debug::api::emulation::pcode_debugger_memory_access::PcodeDebuggerMemoryAccess;
use crate::debug::api::emulation::pcode_debugger_registers_access::PcodeDebuggerRegistersAccess;
use crate::pcode::emu::ErasedPcodeThread;
use crate::pcode::exec::trace::data::pcode_trace_access::PcodeTraceAccess;
use crate::trace::seam_stubs::TraceThread;

/// A trace-and-debugger access shim.
///
/// In addition to the trace "coordinates" encapsulated by [`PcodeTraceAccess`], this
/// encapsulates the tool controlling a session and the session's target. This permits p-code
/// executor/emulator states to access target data and to access session data, e.g., data from
/// mapped static images. It supports the same method chain pattern as [`PcodeTraceAccess`].
pub trait PcodeDebuggerAccess: PcodeTraceAccess {
    /// Get the data-access shim for use in an emulator's shared state.
    ///
    /// This returns a debugger-specific memory access that can access both trace and target data.
    fn get_data_for_shared_state(&self) -> Box<dyn PcodeDebuggerMemoryAccess>;

    /// Get the data-access shim for use in an emulator thread's local state.
    ///
    /// `thread` is the emulator's thread, and `frame` is the frame, usually 0.
    /// This returns a debugger-specific registers access that can access both trace and target data.
    fn get_data_for_local_state(
        &self,
        thread: &dyn ErasedPcodeThread,
        frame: i32,
    ) -> Box<dyn PcodeDebuggerRegistersAccess>;

    /// Get the data-access shim for use in an emulator thread's local state.
    ///
    /// `thread` is the trace thread associated with the emulator's thread, and `frame` is the
    /// frame, usually 0.
    /// This returns a debugger-specific registers access that can access both trace and target data.
    fn get_data_for_local_state_for_trace_thread(
        &self,
        thread: &dyn TraceThread,
        frame: i32,
    ) -> Box<dyn PcodeDebuggerRegistersAccess>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::emulation::pcode_debugger_data_access::PcodeDebuggerDataAccess;
    use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
    use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
    use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
    use crate::pcode::exec::trace::data::pcode_trace_registers_access::PcodeTraceRegistersAccess;
    use crate::pcode::seam_stubs::PcodeTraceMemoryAccess;
    use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    struct FakeDebuggerAccess {
        space: Arc<AddressSpace>,
        is_live: bool,
    }

    impl FakeDebuggerAccess {
        fn new(space: Arc<AddressSpace>, is_live: bool) -> Self {
            FakeDebuggerAccess { space, is_live }
        }
    }

    impl PcodeTraceDataAccess for FakeDebuggerAccess {
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

    impl PcodeTraceMemoryAccess for FakeDebuggerAccess {}

    impl PcodeDebuggerDataAccess for FakeDebuggerAccess {
        fn is_live(&self) -> bool {
            self.is_live
        }
    }

    impl PcodeDebuggerMemoryAccess for FakeDebuggerAccess {
        fn read_from_target_memory(
            &self,
            _unknown: &dyn AddressSetView,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let is_live = self.is_live;
            Box::pin(async move { is_live })
        }

        fn read_from_static_images(
            &self,
            _piece: &dyn PcodeExecutorStatePiece<[u8], [u8]>,
            _unknown: &dyn AddressSetView,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn write_target_memory(
            &self,
            _address: &Address,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let is_live = self.is_live;
            Box::pin(async move { is_live })
        }
    }

    impl PcodeTraceRegistersAccess for FakeDebuggerAccess {
        fn initialize_thread_context(&self, _thread: &mut dyn ErasedPcodeThread) {}
    }

    impl PcodeDebuggerRegistersAccess for FakeDebuggerAccess {
        fn read_from_target_registers(
            &self,
            _unknown: &dyn AddressSetView,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let is_live = self.is_live;
            Box::pin(async move { is_live })
        }

        fn write_target_register(
            &self,
            _address: &Address,
            _data: &[u8],
        ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let is_live = self.is_live;
            Box::pin(async move { is_live })
        }
    }

    impl PcodeTraceAccess for FakeDebuggerAccess {
        fn derive_for_write(&self, _snap: i64) -> Box<dyn PcodeTraceAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn get_data_for_shared_state(&self) -> Box<dyn PcodeTraceMemoryAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }

        fn get_data_for_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
            _frame: i32,
        ) -> Box<dyn PcodeTraceRegistersAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }

        fn get_data_for_local_state_for_trace_thread(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
        ) -> Box<dyn PcodeTraceRegistersAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }
    }

    impl PcodeDebuggerAccess for FakeDebuggerAccess {
        fn get_data_for_shared_state(&self) -> Box<dyn PcodeDebuggerMemoryAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }

        fn get_data_for_local_state(
            &self,
            _thread: &dyn ErasedPcodeThread,
            _frame: i32,
        ) -> Box<dyn PcodeDebuggerRegistersAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }

        fn get_data_for_local_state_for_trace_thread(
            &self,
            _thread: &dyn TraceThread,
            _frame: i32,
        ) -> Box<dyn PcodeDebuggerRegistersAccess> {
            Box::new(FakeDebuggerAccess {
                space: self.space.clone(),
                is_live: self.is_live,
            })
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn test_pcode_debugger_access_get_data_for_shared_state_is_live() {
        let space = ram_space();
        let access = FakeDebuggerAccess::new(space, true);
        let shared = PcodeDebuggerAccess::get_data_for_shared_state(&access);
        assert!(shared.is_live());
    }

    #[test]
    fn test_pcode_debugger_access_get_data_for_shared_state_not_live() {
        let space = ram_space();
        let access = FakeDebuggerAccess::new(space, false);
        let shared = PcodeDebuggerAccess::get_data_for_shared_state(&access);
        assert!(!shared.is_live());
    }

    #[test]
    fn test_pcode_debugger_access_extends_trace_access() {
        let space = ram_space();
        let access = FakeDebuggerAccess::new(space.clone(), true);
        // Verify it can be used as a PcodeTraceAccess
        let _derived: Box<dyn PcodeTraceAccess> = Box::new(FakeDebuggerAccess::new(space, true));
    }
}
