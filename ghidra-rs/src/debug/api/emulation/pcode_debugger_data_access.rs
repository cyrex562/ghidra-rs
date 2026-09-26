//! A data-access shim for a trace and the debugger.
//!
//! Port of `ghidra.debug.api.emulation.PcodeDebuggerDataAccess`.

use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;

/// A data-access shim for a trace and the debugger.
///
/// This shim, in addition to the trace, can also access its associated target, as well as session
/// information maintained by the Debugger tool.
pub trait PcodeDebuggerDataAccess: PcodeTraceDataAccess {
    /// Check if the associated trace represents a live session.
    ///
    /// The session is live if its trace has a recorder and the source snapshot matches the
    /// recorder's destination snapshot.
    ///
    /// # Returns
    /// `true` if live, `false` otherwise
    fn is_live(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess;
    use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct FakeDebuggerDataAccess {
        space: Arc<AddressSpace>,
        bytes: HashMap<i64, u8>,
        states: HashMap<i64, TraceMemoryState>,
        is_live: bool,
    }

    impl FakeDebuggerDataAccess {
        fn new(space: Arc<AddressSpace>, is_live: bool) -> Self {
            FakeDebuggerDataAccess {
                space,
                bytes: HashMap::new(),
                states: HashMap::new(),
                is_live,
            }
        }
    }

    impl PcodeTraceDataAccess for FakeDebuggerDataAccess {
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
            view: &dyn crate::program::model::address::AddressSetView,
            _use_full_spans: bool,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
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

    impl PcodeDebuggerDataAccess for FakeDebuggerDataAccess {
        fn is_live(&self) -> bool {
            self.is_live
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn test_is_live_returns_false_when_not_live() {
        let space = ram_space();
        let access = FakeDebuggerDataAccess::new(space, false);
        assert!(!access.is_live());
    }

    #[test]
    fn test_is_live_returns_true_when_live() {
        let space = ram_space();
        let access = FakeDebuggerDataAccess::new(space, true);
        assert!(access.is_live());
    }

    #[test]
    fn test_debugger_data_access_is_pcode_trace_data_access() {
        let space = ram_space();
        let mut access: Box<dyn PcodeDebuggerDataAccess> =
            Box::new(FakeDebuggerDataAccess::new(space.clone(), true));
        let start = space.address(0x1000);

        access.put_bytes(&start, &[1, 2, 3, 4]);
        let mut out = [0u8; 4];
        let read = access.get_bytes(&start, &mut out);

        assert_eq!(read, 4);
        assert_eq!(out, [1, 2, 3, 4]);
        assert!(access.is_live());
    }
}
