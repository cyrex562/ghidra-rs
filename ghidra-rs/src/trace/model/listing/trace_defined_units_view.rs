use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;

/// A view of defined units.
///
/// Port of `ghidra.trace.model.listing.TraceDefinedUnitsView`.
///
/// This view excludes default / undefined data units.
///
/// The Java interface is `TraceBaseDefinedUnitsView<TraceCodeUnit>`, i.e. it just fixes the base
/// interface's generic parameter to `TraceCodeUnit` without adding any members of its own. Since
/// [`TraceBaseDefinedUnitsView`] already represents that parameter as `Box<dyn TraceCodeUnit>`
/// (see its doc comment), this trait adds nothing beyond the supertrait bound; it exists purely
/// to mirror the Java type and preserve a distinct name for callers/impls to depend on.
pub trait TraceDefinedUnitsView: TraceBaseDefinedUnitsView {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::Register;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::guest::trace_platform::TracePlatform;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    /// A minimal in-memory view backing store, only realistic enough to prove that
    /// `TraceDefinedUnitsView` is object-safe and that its (inherited) `clear` behavior works
    /// through the narrower trait object.
    struct MockView {
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

    impl TraceBaseDefinedUnitsView for MockView {
        fn clear(
            &mut self,
            _span: Lifespan,
            range: &AddressRange,
            _clear_context: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.units.retain(|(addr, _, _)| !range.contains(addr));
            Ok(())
        }

        fn clear_register(
            &mut self,
            _span: Lifespan,
            _register: &Register,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.units.clear();
            Ok(())
        }

        fn clear_platform_register(
            &mut self,
            _platform: &dyn TracePlatform,
            span: Lifespan,
            register: &Register,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            self.clear_register(span, register, monitor)
        }
    }

    impl TraceDefinedUnitsView for MockView {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

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


    #[test]
    fn usable_as_trait_object_and_inherits_defined_units_behavior() {
        let mut view: Box<dyn TraceDefinedUnitsView> = Box::new(MockView {
            units: vec![(addr(0x400), 0, 10), (addr(0x500), 0, 10)],
        });

        assert_eq!(view.size(), 2);

        let full_range = AddressRange::new(addr(0x0), addr(0x1000));
        view.clear(Lifespan::span(0, 10), &full_range, false, &NeverCancelled)
            .expect("clear should succeed when not cancelled");
        assert_eq!(view.size(), 0);
    }
}
