use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;

/// A view of all code units.
///
/// Port of `ghidra.trace.model.listing.TraceCodeUnitsView`.
///
/// In particular, this includes default / undefined units. If an address is valid, this view
/// will show there is a code unit containing it.
///
/// The Java interface merely finalizes the type parameter of
/// [`TraceBaseCodeUnitsView`]`<TraceCodeUnit>`, adding no members of its own. Since
/// [`TraceBaseCodeUnitsView`] is already expressed in terms of `Box<dyn TraceCodeUnit>` rather
/// than a type parameter, this trait is likewise just a marker supertrait bound.
pub trait TraceCodeUnitsView: TraceBaseCodeUnitsView {}

impl<T: TraceBaseCodeUnitsView + ?Sized> TraceCodeUnitsView for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Register;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TracePlatform;

    /// A trivial view with no units, only realistic enough to prove that a
    /// `TraceBaseCodeUnitsView` impl is automatically usable as a `TraceCodeUnitsView` trait
    /// object (the blanket impl above), not merely as its narrower supertrait.
    struct EmptyView;

    impl TraceBaseCodeUnitsView for EmptyView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            0
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
            Box::new(AddressSet::new())
        }

        fn get_address_set_view_within(
            &self,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
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

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trace_code_units_view_trait_object() {
        let view: Box<dyn TraceCodeUnitsView> = Box::new(EmptyView);

        assert_eq!(view.size(), 0);
        assert!(view.get_at(0, &addr(0x400)).is_none());
        assert!(!view.contains_address(0, &addr(0x400)));
        assert!(view.get_all(0, true).is_empty());
    }
}
