//! Port of `ghidra.trace.database.listing.DBTraceDefinedUnitsView`.

use crate::program::model::address::AddressRange;
use crate::trace::database::listing::internal_trace_base_defined_units_view::InternalTraceBaseDefinedUnitsView;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_defined_units_view::TraceDefinedUnitsView;
use crate::trace::seam_stubs::AbstractBaseDBTraceDefinedUnitsView;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The implementation of `TraceCodeSpace::defined_units()`: a composed view over a trace's
/// instructions and defined-data views.
///
/// Port of `ghidra.trace.database.listing.DBTraceDefinedUnitsView`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java class extends `AbstractComposedDBTraceCodeUnitsView` (constructed, in its
/// constructor, from `List.of(space.instructions, space.definedData)`) and implements
/// `TraceDefinedUnitsView`/`InternalTraceBaseDefinedUnitsView<TraceCodeUnit>`. Neither the
/// composed superclass nor the constructor's `DBTraceCodeSpace` parameter are part of this
/// trait's object-safe surface (Rust traits have no constructors, and the composed superclass
/// contributes no public API beyond what `TraceDefinedUnitsView` already requires); what remains
/// is the inherited-trait bound plus the three methods the Java class actually overrides, each
/// implemented by delegating to [`Self::parts`] -- the same `parts` field the Java overrides
/// iterate.
///
/// `coversRange`/`intersectsRange` are declared abstract (no default) on
/// [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView)
/// and `clear` on
/// [`TraceBaseDefinedUnitsView`](crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView)
/// (both supertraits, via [`TraceDefinedUnitsView`]); this trait redeclares those same names with
/// default bodies, mirroring the override relationship -- exactly as
/// [`InternalTraceBaseDefinedUnitsView`] does for `clear_register`/`clear_platform_register` over
/// `TraceBaseDefinedUnitsView`. As there, a type implementing both `TraceBaseDefinedUnitsView` and
/// this trait must disambiguate calls to these methods with UFCS
/// (`DBTraceDefinedUnitsView::clear(&mut x, ..)`), where Java would otherwise resolve to the more
/// specific override automatically; a `TraceBaseDefinedUnitsView` impl should simply delegate its
/// `covers_range`/`intersects_range`/`clear` bodies to these defaults.
///
/// `coversRange`'s real algorithm (`AbstractBaseDBTraceDefinedUnitsView.subtractFrom`) computes
/// whether the *union* of all parts' coverage fills the queried box, via iterative geometric
/// subtraction of each part's intersecting ranges from a working set. That machinery isn't ported
/// (it isn't otherwise referenced by any currently-ported type), so this default instead checks
/// whether any single part covers the range alone -- a conservative under-approximation of true
/// union coverage, sufficient while `instructions`/`defined_data` remain the only two (mutually
/// exclusive) parts, but replace this default once the real subtraction is ported.
pub trait DBTraceDefinedUnitsView: TraceDefinedUnitsView + InternalTraceBaseDefinedUnitsView {
    /// Returns the component per-kind views (the trace's instructions and defined-data views)
    /// this composed view aggregates over. Mirrors the `parts` field inherited from
    /// `AbstractComposedDBTraceCodeUnitsView`, constructed in the Java constructor from
    /// `List.of(space.instructions, space.definedData)`.
    fn parts(&self) -> Vec<Box<dyn AbstractBaseDBTraceDefinedUnitsView>>;

    /// Checks whether every address in `range`, throughout `span`, is covered by some part.
    /// Mirrors `DBTraceDefinedUnitsView.coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool {
        self.parts().iter().any(|part| part.covers_range(span, range))
    }

    /// Checks whether any address in `range`, at some snap in `span`, is covered by some part.
    /// Mirrors `DBTraceDefinedUnitsView.intersectsRange(Lifespan, AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool {
        self.parts().iter().any(|part| part.intersects_range(span, range))
    }

    /// Clears every part's units within `span` and `range`. Mirrors
    /// `DBTraceDefinedUnitsView.clear(Lifespan, AddressRange, boolean, TaskMonitor)`.
    fn clear(
        &mut self,
        span: Lifespan,
        range: &AddressRange,
        clear_context: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        for mut part in self.parts() {
            part.clear(span, range, clear_context, monitor)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Register;
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::trace::model::listing::trace_base_defined_units_view::TraceBaseDefinedUnitsView;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::model::listing::internal_base_code_units_view::InternalBaseCodeUnitsView;
    use crate::trace::model::guest::trace_platform::TracePlatform;
    use std::sync::{Arc, Mutex};

    /// One "part" (e.g. instructions, or defined data): a plain in-memory set of addresses,
    /// shared (via `Arc<Mutex<..>>`) with the owning [`ComposedView`] so that `clear` calls
    /// through freshly-boxed [`AbstractBaseDBTraceDefinedUnitsView`] handles still mutate the
    /// same underlying storage -- standing in for the real port's shared backing database.
    #[derive(Clone)]
    struct PartView {
        addresses: Arc<Mutex<Vec<Address>>>,
    }

    impl AbstractBaseDBTraceDefinedUnitsView for PartView {
        fn covers_range(&self, _span: Lifespan, range: &AddressRange) -> bool {
            let addresses = self.addresses.lock().unwrap();
            range.addresses().all(|a| addresses.contains(&a))
        }

        fn intersects_range(&self, _span: Lifespan, range: &AddressRange) -> bool {
            self.addresses.lock().unwrap().iter().any(|a| range.contains(a))
        }

        fn clear(
            &mut self,
            _span: Lifespan,
            range: &AddressRange,
            _clear_context: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()?;
            self.addresses.lock().unwrap().retain(|a| !range.contains(a));
            Ok(())
        }
    }

    /// The composed view under test, mirroring `DBTraceDefinedUnitsView` over two parts
    /// (standing in for `instructions`/`definedData`).
    struct ComposedView {
        instructions: PartView,
        defined_data: PartView,
    }

    impl TraceBaseCodeUnitsView for ComposedView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn size(&self) -> i32 {
            (self.instructions.addresses.lock().unwrap().len()
                + self.defined_data.addresses.lock().unwrap().len()) as i32
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
        fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool {
            DBTraceDefinedUnitsView::covers_range(self, span, range)
        }
        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }
        fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool {
            DBTraceDefinedUnitsView::intersects_range(self, span, range)
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

    impl TraceBaseDefinedUnitsView for ComposedView {
        fn clear(
            &mut self,
            span: Lifespan,
            range: &AddressRange,
            clear_context: bool,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            DBTraceDefinedUnitsView::clear(self, span, range, clear_context, monitor)
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
            _platform: &dyn TracePlatform,
            _span: Lifespan,
            _register: &Register,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl crate::trace::model::listing::trace_defined_units_view::TraceDefinedUnitsView for ComposedView {}

    impl InternalBaseCodeUnitsView for ComposedView {
        fn get_space(&self) -> Arc<AddressSpace> {
            addr(0).space().clone()
        }
    }

    impl InternalTraceBaseDefinedUnitsView for ComposedView {}

    impl DBTraceDefinedUnitsView for ComposedView {
        fn parts(&self) -> Vec<Box<dyn AbstractBaseDBTraceDefinedUnitsView>> {
            vec![Box::new(self.instructions.clone()), Box::new(self.defined_data.clone())]
        }
    }

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


    fn make_view() -> ComposedView {
        ComposedView {
            instructions: PartView { addresses: Arc::new(Mutex::new(vec![addr(0x400)])) },
            defined_data: PartView { addresses: Arc::new(Mutex::new(vec![addr(0x500)])) },
        }
    }

    #[test]
    fn intersects_range_is_true_when_any_part_intersects() {
        let view = make_view();
        let range = AddressRange::new(addr(0x500), addr(0x500));
        assert!(DBTraceDefinedUnitsView::intersects_range(&view, Lifespan::span(0, 10), &range));

        let miss = AddressRange::new(addr(0x600), addr(0x600));
        assert!(!DBTraceDefinedUnitsView::intersects_range(&view, Lifespan::span(0, 10), &miss));
    }

    #[test]
    fn covers_range_is_true_when_a_single_part_alone_spans_the_range() {
        let view = make_view();

        // The instructions part alone covers this singleton range.
        let single = AddressRange::new(addr(0x400), addr(0x400));
        assert!(DBTraceDefinedUnitsView::covers_range(&view, Lifespan::span(0, 10), &single));

        // Neither part alone covers a range spanning both.
        let both = AddressRange::new(addr(0x400), addr(0x500));
        assert!(!DBTraceDefinedUnitsView::covers_range(&view, Lifespan::span(0, 10), &both));
    }

    #[test]
    fn clear_removes_matching_units_from_every_part() {
        let mut view = make_view();
        assert_eq!(view.size(), 2);

        let range = AddressRange::new(addr(0x0), addr(0x1000));
        DBTraceDefinedUnitsView::clear(&mut view, Lifespan::span(0, 10), &range, false, &NeverCancelled)
            .expect("clear should succeed when not cancelled");

        assert_eq!(view.size(), 0);
    }

    #[test]
    fn is_object_safe_and_reachable_through_trace_defined_units_view() {
        fn assert_object_safe(_: &dyn DBTraceDefinedUnitsView) {}
        let view = make_view();
        assert_object_safe(&view);

        // Also usable as a plain `TraceDefinedUnitsView`/`TraceBaseDefinedUnitsView` trait
        // object (the interfaces it implements), exercising the `clear` delegation this trait's
        // docs describe.
        let mut boxed: Box<dyn TraceBaseDefinedUnitsView> = Box::new(make_view());
        let range = AddressRange::new(addr(0x0), addr(0x1000));
        boxed
            .clear(Lifespan::span(0, 10), &range, false, &NeverCancelled)
            .expect("clear should succeed when not cancelled");
        assert_eq!(boxed.size(), 0);
    }
}
