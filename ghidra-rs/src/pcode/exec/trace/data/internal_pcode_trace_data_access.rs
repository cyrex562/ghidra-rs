//! Internal extension of PcodeTraceDataAccess for trace-specific functionality.
//!
//! Port of `ghidra.pcode.exec.trace.data.InternalPcodeTraceDataAccess`.

use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::property::trace_property_map_operations::TracePropertyMapOperations;
use crate::trace::model::trace_time_viewport::TraceTimeViewport;

/// Internal extension of [`PcodeTraceDataAccess`] that provides access to trace-level metadata
/// and properties.
///
/// This trait extends `PcodeTraceDataAccess` with methods for accessing the trace platform,
/// snapshot information, property operations, and the time viewport.
pub trait InternalPcodeTraceDataAccess: PcodeTraceDataAccess {
    /// Get the guest platform associated with this trace.
    fn get_platform(&self) -> &dyn TracePlatform;

    /// Get the current snapshot number.
    fn get_snap(&self) -> i64;

    /// Get property operations for the named property with the given type.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the property
    /// * `create_if_absent` - Whether to create the property if it doesn't exist
    ///
    /// # Type parameters
    ///
    /// * `T` - The type of values stored in the property. This method requires `Self: Sized`
    ///   so it cannot be called through `dyn InternalPcodeTraceDataAccess`.
    fn get_property_ops<T>(
        &self,
        name: &str,
        create_if_absent: bool,
    ) -> Box<dyn TracePropertyMapOperations<T>>
    where
        T: 'static,
        Self: Sized;

    /// Get the time viewport for this trace.
    fn get_viewport(&self) -> &dyn TraceTimeViewport;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
    use crate::program::model::address::{Address, AddressRange, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
    use crate::trace::model::property::trace_property_map_operations::TracePropertyMapOperations;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use std::sync::Arc;
    use std::collections::HashMap;

    /// Minimal fake implementation for testing.
    struct FakeInternalAccess {
        platform: Arc<FakePlatform>,
        snap: i64,
        viewport: Arc<FakeViewport>,
    }

    struct FakePlatform;
    impl TracePlatform for FakePlatform {}

    struct FakeViewport;
    impl TraceTimeViewport for FakeViewport {
        fn set_snap(&mut self, _snap: i64) {}
        fn add_change_listener(&mut self, _l: crate::util::function::Runnable) {}
        fn remove_change_listener(&mut self, _l: &crate::util::function::Runnable) {}
        fn is_forked(&self) -> bool { false }
        fn contains_any_upper(&self, _lifespan: crate::trace::model::lifespan::Lifespan) -> bool { false }
        fn is_completely_visible(
            &self,
            _range: &AddressRange,
            _lifespan: crate::trace::model::lifespan::Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> bool {
            false
        }
        fn compute_visible_parts(
            &self,
            _set: &dyn AddressSetView,
            _lifespan: crate::trace::model::lifespan::Lifespan,
            _object: &dyn std::any::Any,
            _occlusion: &dyn crate::trace::model::trace_time_viewport::Occlusion,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn get_ordered_spans(&self) -> Vec<crate::trace::model::lifespan::Lifespan> { Vec::new() }
        fn get_reversed_spans(&self) -> Vec<crate::trace::model::lifespan::Lifespan> { Vec::new() }
        fn get_ordered_snaps(&self) -> Vec<i64> { Vec::new() }
        fn get_reversed_snaps(&self) -> Vec<i64> { Vec::new() }
        fn get_top(&self, _func: &dyn Fn(i64) -> Option<Box<dyn std::any::Any>>) -> Option<Box<dyn std::any::Any>> { None }
        fn merged_iterator(
            &self,
            _iter_func: &dyn Fn(i64) -> Box<dyn Iterator<Item = Box<dyn std::any::Any>>>,
            _comparator: &dyn Fn(&dyn std::any::Any, &dyn std::any::Any) -> std::cmp::Ordering,
        ) -> Box<dyn Iterator<Item = Box<dyn std::any::Any>>> {
            Box::new(std::iter::empty())
        }
        fn unioned_addresses(
            &self,
            _set_func: &dyn Fn(i64) -> Box<dyn AddressSetView>,
        ) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
    }

    impl PcodeTraceDataAccess for FakeInternalAccess {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }

        fn set_state(&mut self, _range: &AddressRange, _state: TraceMemoryState) {}

        fn get_viewport_state(&self, _range: &AddressRange) -> TraceMemoryState {
            TraceMemoryState::Unknown
        }

        fn intersect_view_known(&self, view: &dyn AddressSetView, _use_full_spans: bool) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn put_bytes(&mut self, _start: &Address, buf: &[u8]) -> usize {
            buf.len()
        }

        fn get_bytes(&self, _start: &Address, buf: &mut [u8]) -> usize {
            0
        }

        fn translate(&self, address: &Address) -> Address {
            address.clone()
        }

        fn get_property_access<T>(&self, _name: &str) -> Box<dyn crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess<T>>
        where
            T: 'static,
        {
            unimplemented!("not exercised by these tests")
        }
    }

    impl InternalPcodeTraceDataAccess for FakeInternalAccess {
        fn get_platform(&self) -> &dyn TracePlatform {
            &*self.platform
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }

        fn get_property_ops<T>(
            &self,
            _name: &str,
            _create_if_absent: bool,
        ) -> Box<dyn TracePropertyMapOperations<T>>
        where
            T: 'static,
        {
            unimplemented!("not exercised by these tests")
        }

        fn get_viewport(&self) -> &dyn TraceTimeViewport {
            &*self.viewport
        }
    }

    #[test]
    fn test_get_snap() {
        let access = FakeInternalAccess {
            platform: Arc::new(FakePlatform),
            snap: 42,
            viewport: Arc::new(FakeViewport),
        };
        assert_eq!(access.get_snap(), 42);
    }

    #[test]
    fn test_get_platform() {
        let access = FakeInternalAccess {
            platform: Arc::new(FakePlatform),
            snap: 1,
            viewport: Arc::new(FakeViewport),
        };
        let platform = access.get_platform();
        // Verify platform is retrievable (polymorphic access works)
        let _: &dyn TracePlatform = platform;
    }

    #[test]
    fn test_get_viewport() {
        let access = FakeInternalAccess {
            platform: Arc::new(FakePlatform),
            snap: 1,
            viewport: Arc::new(FakeViewport),
        };
        let viewport = access.get_viewport();
        // Verify viewport is retrievable (polymorphic access works)
        let _: &dyn TraceTimeViewport = viewport;
    }
}
