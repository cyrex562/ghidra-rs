//! Port of `ghidra.trace.database.listing.InternalTraceBaseDefinedUnitsView`.

use crate::program::model::lang::Register;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;
use crate::trace::model::listing::internal_base_code_units_view::InternalBaseCodeUnitsView;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Adds [`TracePlatform`]-aware defaults for [`TraceBaseDefinedUnitsView`]'s register-clearing
/// overloads, expressed in terms of [`InternalBaseCodeUnitsView::get_space`].
///
/// Port of `ghidra.trace.database.listing.InternalTraceBaseDefinedUnitsView`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface's two default methods override abstract methods it inherits (via
/// `TraceBaseDefinedUnitsView`): `clear(TracePlatform, Lifespan, Register, TaskMonitor)` and
/// `clear(Lifespan, Register, TaskMonitor)`, ported there (since Rust has no overloading) as
/// [`TraceBaseDefinedUnitsView::clear_platform_register`] and
/// [`TraceBaseDefinedUnitsView::clear_register`]. This trait redeclares those same names with
/// default bodies, mirroring the override relationship -- exactly as
/// [`InternalTracePlatform`](crate::trace::database::guest::internal_trace_platform::InternalTracePlatform)
/// does for `get_conventional_register_range` over
/// [`TracePlatform::get_conventional_register_range`]. As there, a type implementing both
/// `TraceBaseDefinedUnitsView` and this trait must disambiguate calls to these methods with UFCS
/// (`InternalTraceBaseDefinedUnitsView::clear_register(&mut x, ..)`), where Java would otherwise
/// resolve to the more specific override automatically; a `TraceBaseDefinedUnitsView` impl should
/// simply delegate its `clear_register`/`clear_platform_register` bodies to these defaults.
pub trait InternalTraceBaseDefinedUnitsView: TraceBaseDefinedUnitsView + InternalBaseCodeUnitsView {
    /// Clear the units contained within the given span and platform register. Mirrors
    /// `InternalTraceBaseDefinedUnitsView.clear(TracePlatform, Lifespan, Register, TaskMonitor)`,
    /// which overrides `TraceBaseDefinedUnitsView`'s abstract `clear(TracePlatform, ...)`.
    fn clear_platform_register(
        &mut self,
        platform: &dyn TracePlatform,
        span: Lifespan,
        register: &Register,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let range = platform.get_conventional_register_range(&self.get_space(), register);
        self.clear(span, &range, true, monitor)
    }

    /// Clear the units contained within the given span and register, using the trace's host
    /// platform. Mirrors `InternalTraceBaseDefinedUnitsView.clear(Lifespan, Register,
    /// TaskMonitor)`, which overrides `TraceBaseDefinedUnitsView`'s abstract `clear(Lifespan,
    /// ...)`.
    fn clear_register(
        &mut self,
        span: Lifespan,
        register: &Register,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        InternalTraceBaseDefinedUnitsView::clear_platform_register(
            self,
            platform.as_ref(),
            span,
            register,
            monitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use std::sync::Arc;

    /// A minimal in-memory view, only realistic enough to prove that
    /// [`InternalTraceBaseDefinedUnitsView::clear_platform_register`]'s default correctly
    /// computes the conventional register range and delegates the actual clearing to
    /// [`TraceBaseDefinedUnitsView::clear`], and that the trait is object-safe.
    struct MockView {
        space: Arc<AddressSpace>,
        units: Vec<(Address, i64, i64)>, // (address, start_snap, end_snap)
    }

    impl TraceBaseCodeUnitsView for MockView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            self.units.len() as i32
        }

        fn get_before(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_containing(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_at(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_after(&self, _snap: i64, _address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_between(
            &self,
            _snap: i64,
            _min: &Address,
            _max: &Address,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_set(
            &self,
            _snap: i64,
            _set: &dyn AddressSetView,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_in_range(
            &self,
            _snap: i64,
            _range: &AddressRange,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_from(&self, _snap: i64, _start: &Address, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_all(&self, _snap: i64, _forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }

        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn get_address_set_view_within(
            &self,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }

        fn contains_address(&self, _snap: i64, _address: &Address) -> bool {
            false
        }

        fn covers_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn intersects_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn get_for_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            None
        }

        fn get_by_platform_register(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            Vec::new()
        }
    }

    impl InternalBaseCodeUnitsView for MockView {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    impl TraceBaseDefinedUnitsView for MockView {
        fn clear(
            &mut self,
            _span: Lifespan,
            range: &AddressRange,
            _clear_context: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.units.retain(|(addr, _start, _end)| !range.contains(addr));
            Ok(())
        }

        fn clear_register(
            &mut self,
            _span: Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn clear_platform_register(
            &mut self,
            platform: &dyn TracePlatform,
            span: Lifespan,
            register: &Register,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            InternalTraceBaseDefinedUnitsView::clear_platform_register(
                self, platform, span, register, monitor,
            )
        }
    }

    impl InternalTraceBaseDefinedUnitsView for MockView {}

    /// The trace's (marker) host platform: all defaults, including
    /// [`TracePlatform::get_conventional_register_range`]'s identity-mapping rebasing formula.
    struct HostPlatform;
    impl TracePlatform for HostPlatform {}

    struct NeverCancelled;
    impl TaskMonitor for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }
        fn clear_cancelled(&self) {}
    }

    struct AlwaysCancelled;
    impl TaskMonitor for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException::default())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }
        fn clear_cancelled(&self) {}
    }


    fn make_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn clear_platform_register_computes_conventional_range_and_clears_only_that_register() {
        let space = make_space();
        let reg = Register::new("r0", "", space.address(0x100), 4, false, 0);

        let mut view = MockView {
            space: space.clone(),
            units: vec![
                (space.address(0x100), 0, 10), // inside the register's 4-byte range
                (space.address(0x200), 0, 10), // outside it
            ],
        };

        InternalTraceBaseDefinedUnitsView::clear_platform_register(
            &mut view,
            &HostPlatform,
            Lifespan::span(0, 10),
            &reg.borrow(),
            &NeverCancelled,
        )
        .expect("clear should succeed when not cancelled");

        assert_eq!(view.units.len(), 1);
        assert_eq!(view.units[0].0, space.address(0x200));
    }

    #[test]
    fn clear_platform_register_propagates_cancellation() {
        let space = make_space();
        let reg = Register::new("r1", "", space.address(0x100), 4, false, 0);

        let mut view = MockView {
            space: space.clone(),
            units: vec![(space.address(0x100), 0, 10)],
        };

        let result = InternalTraceBaseDefinedUnitsView::clear_platform_register(
            &mut view,
            &HostPlatform,
            Lifespan::span(0, 10),
            &reg.borrow(),
            &AlwaysCancelled,
        );

        assert!(result.is_err(), "clear should propagate a cancelled monitor as an error");
        assert_eq!(view.units.len(), 1, "cancelled clear must not have mutated the view");
    }

    #[test]
    fn is_object_safe_and_reachable_through_trace_base_defined_units_view() {
        fn assert_object_safe(_: &dyn InternalTraceBaseDefinedUnitsView) {}

        let space = make_space();
        let view = MockView { space: space.clone(), units: Vec::new() };
        assert_object_safe(&view);

        // Also usable as a plain `TraceBaseDefinedUnitsView` trait object (the interface it
        // overrides defaults for), exercising the `clear_platform_register` delegation this
        // trait's docs describe.
        let reg = Register::new("r2", "", space.address(0x100), 4, false, 0);
        let mut boxed: Box<dyn TraceBaseDefinedUnitsView> = Box::new(MockView {
            space: space.clone(),
            units: vec![(space.address(0x100), 0, 10)],
        });
        boxed
            .clear_platform_register(&HostPlatform, Lifespan::span(0, 10), &reg.borrow(), &NeverCancelled)
            .expect("clear should succeed when not cancelled");
        assert_eq!(boxed.size(), 0);
    }
}
