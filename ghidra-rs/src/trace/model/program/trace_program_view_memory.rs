//! Memory as seen through a trace program view.
//!
//! Java source: `ghidra.trace.model.program.TraceProgramViewMemory`.
use crate::program::model::mem::memory::Memory;
use crate::trace::model::program::snap_specific_trace_view::SnapSpecificTraceView;
use crate::trace::seam_stubs::TraceProgramView;

/// The memory of a [`TraceProgramView`], as visible at a particular snapshot.
///
/// Port of `ghidra.trace.model.program.TraceProgramViewMemory`.
///
/// The Java interface overrides `Memory::getProgram()` to covariantly narrow its return type to
/// `TraceProgramView`. Rust does not support covariant trait-method overrides, so that override
/// is exposed here under a distinct name, [`TraceProgramViewMemory::get_trace_program_view`],
/// rather than redeclaring [`Memory::get_program`]. Implementors should still implement
/// [`Memory::get_program`] (delegating to `get_trace_program_view`), mirroring the Java override.
pub trait TraceProgramViewMemory: Memory + SnapSpecificTraceView {
    /// Returns the trace program view that owns this memory.
    ///
    /// This is the covariant override of `Memory::getProgram()` in the Java source; see the
    /// trait-level documentation for why it is exposed under a distinct name here.
    fn get_trace_program_view(&self) -> Box<dyn TraceProgramView>;

    /// Sets whether this view forces a full view of memory, i.e., ignores the current snapshot
    /// and shows the union of memory regions/blocks present across all snapshots.
    fn set_force_full_view(&mut self, force_full_view: bool);

    /// Returns whether this view is forcing a full view of memory.
    fn is_force_full_view(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;
    use crate::trace::model::trace::Trace;

    struct MockTraceProgramView;
    impl TraceProgramView for MockTraceProgramView {}

    struct MockTraceProgramViewMemory {
        force_full_view: bool,
        snap: i64,
    }

    impl Memory for MockTraceProgramViewMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }

        fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
            dest.len()
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    impl SnapSpecificTraceView for MockTraceProgramViewMemory {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    impl TraceProgramViewMemory for MockTraceProgramViewMemory {
        fn get_trace_program_view(&self) -> Box<dyn TraceProgramView> {
            Box::new(MockTraceProgramView)
        }

        fn set_force_full_view(&mut self, force_full_view: bool) {
            self.force_full_view = force_full_view;
        }

        fn is_force_full_view(&self) -> bool {
            self.force_full_view
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn force_full_view_toggles() {
        let mut mem = MockTraceProgramViewMemory {
            force_full_view: false,
            snap: 3,
        };
        assert!(!mem.is_force_full_view());
        mem.set_force_full_view(true);
        assert!(mem.is_force_full_view());
    }

    #[test]
    fn snap_specific_view_reports_snap() {
        let mem = MockTraceProgramViewMemory {
            force_full_view: false,
            snap: 7,
        };
        assert_eq!(mem.get_snap(), 7);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut mem: Box<dyn TraceProgramViewMemory> = Box::new(MockTraceProgramViewMemory {
            force_full_view: false,
            snap: 1,
        });
        assert!(mem.get_byte(&test_address(0x1000)).is_ok());
        let _ = mem.get_trace_program_view();
        mem.set_force_full_view(true);
        assert!(mem.is_force_full_view());
    }
}
