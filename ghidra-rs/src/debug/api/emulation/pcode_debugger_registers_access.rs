//! A data-access shim for a trace's registers and the debugger.
//!
//! Port of `ghidra.debug.api.emulation.PcodeDebuggerRegistersAccess`.

use std::future::Future;
use std::pin::Pin;

use crate::debug::api::emulation::pcode_debugger_data_access::PcodeDebuggerDataAccess;
use crate::pcode::exec::trace::data::pcode_trace_registers_access::PcodeTraceRegistersAccess;
use crate::program::model::address::{Address, AddressSetView};

/// A data-access shim for a trace's registers and the debugger.
///
/// This shim, in addition to the trace and its associated target, can also facilitate reading
/// from and writing to target registers.
pub trait PcodeDebuggerRegistersAccess: PcodeTraceRegistersAccess + PcodeDebuggerDataAccess {
    /// Instruct the associated recorder to read registers from the target.
    ///
    /// # Arguments
    /// * `unknown` - the address set (in the platform's `register` space) of registers to read
    ///
    /// # Returns
    /// A future which completes when the read is complete and its results recorded to the trace.
    /// It completes with `true` when any part of target state was successfully read.
    /// It completes with `false` if there is no target, or if the target was not read.
    fn read_from_target_registers(
        &self,
        unknown: &dyn AddressSetView,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;

    /// Instruct the associated recorder to write target registers.
    ///
    /// In normal operation, this will also cause the recorder, upon a successful write, to record
    /// the same values into the destination trace. If this shim is not associated with a live
    /// session, the returned future completes immediately with `false`.
    ///
    /// # Arguments
    /// * `address` - the address of the first byte to write (in the platform's `register` space)
    /// * `data` - the bytes to write
    ///
    /// # Returns
    /// A future which completes when the write is complete and its results recorded to the trace.
    /// It completes with `true` when the target was written.
    /// It completes with `false` if there is no target, or if the target is not effected.
    fn write_target_register(
        &self,
        address: &Address,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::ErasedPcodeThread;
    use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
    use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
    use crate::program::model::address::{AddressRange, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct FakeDebuggerRegistersAccess {
        space: Arc<AddressSpace>,
        bytes: HashMap<i64, u8>,
        states: HashMap<i64, TraceMemoryState>,
        is_live: bool,
    }

    impl FakeDebuggerRegistersAccess {
        fn new(space: Arc<AddressSpace>, is_live: bool) -> Self {
            FakeDebuggerRegistersAccess {
                space,
                bytes: HashMap::new(),
                states: HashMap::new(),
                is_live,
            }
        }
    }

    impl PcodeTraceDataAccess for FakeDebuggerRegistersAccess {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn set_state(&mut self, range: &AddressRange, state: TraceMemoryState) {
            for addr in range.addresses() {
                self.states.insert(addr.offset(), state);
            }
        }

        fn get_viewport_state(&self, range: &AddressRange) -> TraceMemoryState {
            let all_known = range
                .addresses()
                .all(|addr| self.states.get(&addr.offset()) == Some(&TraceMemoryState::Known));
            if all_known {
                TraceMemoryState::Known
            } else {
                TraceMemoryState::Unknown
            }
        }

        fn intersect_view_known(
            &self,
            view: &dyn AddressSetView,
            _use_full_spans: bool,
        ) -> Box<dyn AddressSetView> {
            let mut result = AddressSet::new();
            for addr in view.addresses(true) {
                if self.states.get(&addr.offset()) == Some(&TraceMemoryState::Known) {
                    result.add_address(&addr);
                }
            }
            Box::new(result)
        }

        fn put_bytes(&mut self, start: &Address, buf: &[u8]) -> usize {
            for (i, b) in buf.iter().enumerate() {
                self.bytes.insert(start.offset() + i as i64, *b);
            }
            buf.len()
        }

        fn get_bytes(&self, start: &Address, buf: &mut [u8]) -> usize {
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                if let Some(b) = self.bytes.get(&(start.offset() + i as i64)) {
                    *slot = *b;
                    n += 1;
                }
            }
            n
        }

        fn translate(&self, address: &Address) -> Address {
            address.clone()
        }

        fn get_property_access<T>(&self, _name: &str) -> Box<dyn PcodeTracePropertyAccess<T>>
        where
            T: 'static,
        {
            unimplemented!("not exercised by these tests")
        }
    }

    impl PcodeTraceRegistersAccess for FakeDebuggerRegistersAccess {
        fn initialize_thread_context(&self, _thread: &mut dyn ErasedPcodeThread) {
            // Fake implementation: do nothing
        }
    }

    impl PcodeDebuggerDataAccess for FakeDebuggerRegistersAccess {
        fn is_live(&self) -> bool {
            self.is_live
        }
    }

    impl PcodeDebuggerRegistersAccess for FakeDebuggerRegistersAccess {
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

    fn reg_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    #[tokio::test]
    async fn test_read_from_target_registers_returns_false_when_not_live() {
        let space = reg_space();
        let access = FakeDebuggerRegistersAccess::new(space, false);
        let set = AddressSet::new();
        let result = access.read_from_target_registers(&set).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_read_from_target_registers_returns_true_when_live() {
        let space = reg_space();
        let access = FakeDebuggerRegistersAccess::new(space, true);
        let set = AddressSet::new();
        let result = access.read_from_target_registers(&set).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_write_target_register_returns_false_when_not_live() {
        let space = reg_space();
        let access = FakeDebuggerRegistersAccess::new(space.clone(), false);
        let addr = space.address(0x0);
        let data = [1, 2, 3, 4];
        let result = access.write_target_register(&addr, &data).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_write_target_register_returns_true_when_live() {
        let space = reg_space();
        let access = FakeDebuggerRegistersAccess::new(space.clone(), true);
        let addr = space.address(0x0);
        let data = [1, 2, 3, 4];
        let result = access.write_target_register(&addr, &data).await;
        assert!(result);
    }

    #[test]
    fn test_debugger_registers_access_extends_debugger_data_access() {
        let space = reg_space();
        let access = FakeDebuggerRegistersAccess::new(space, true);
        assert!(access.is_live());
    }
}
