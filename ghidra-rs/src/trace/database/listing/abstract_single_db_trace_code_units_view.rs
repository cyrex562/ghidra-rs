//! Port of `ghidra.trace.database.listing.AbstractSingleDBTraceCodeUnitsView`.

use crate::trace::seam_stubs::AbstractBaseDBTraceCodeUnitsView;

/// An abstract implementation of a single-type view.
///
/// Port of `ghidra.trace.database.listing.AbstractSingleDBTraceCodeUnitsView`.
///
/// The Java class declares no members beyond forwarding its constructor to
/// [`AbstractBaseDBTraceCodeUnitsView`] (its superclass); it exists purely as a marker/upper
/// bound so that composed views (`AbstractComposedDBTraceCodeUnitsView`) can hold several
/// distinct single-type views polymorphically. Mirrored here as a marker supertrait for the same
/// reason. `T` mirrors the superclass's own `T extends DBTraceCodeUnitAdapter` type parameter.
pub trait AbstractSingleDBTraceCodeUnitsView<T>: AbstractBaseDBTraceCodeUnitsView<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::program::model::address::Address;
    use std::sync::Arc;

    struct MockSingleView {
        space: Arc<AddressSpace>,
    }

    impl AbstractBaseDBTraceCodeUnitsView<()> for MockSingleView {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn size(&self) -> i32 {
            0
        }

        fn get_floor(&self, _snap: i64, _address: &Address) -> Option<()> {
            None
        }

        fn get_containing(&self, _snap: i64, _address: &Address) -> Option<()> {
            None
        }

        fn get_at(&self, _snap: i64, _address: &Address) -> Option<()> {
            None
        }

        fn get_ceiling(&self, _snap: i64, _address: &Address) -> Option<()> {
            None
        }

        fn get_in_range(&self, _snap: i64, _range: &AddressRange, _forward: bool) -> Vec<()> {
            Vec::new()
        }

        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<()> {
            Vec::new()
        }

        fn get_address_set_view_within(
            &self,
            _snap: i64,
            _within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn get_address_set_view(&self, _snap: i64) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }

        fn contains_address(&self, _snap: i64, _address: &Address) -> bool {
            false
        }

        fn covers_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }

        fn intersects_range(&self, _span: &dyn Lifespan, _range: &AddressRange) -> bool {
            false
        }

        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            false
        }
    }

    impl AbstractSingleDBTraceCodeUnitsView<()> for MockSingleView {}

    #[test]
    fn heterogeneous_single_views_are_usable_through_the_common_upper_bound() {
        let instructions_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let data_space = AddressSpace::new("data", 32, 1, AddressSpaceType::Ram, 1);

        // Two distinct "single" views (e.g. an instructions view and a data view in the real
        // hierarchy), stored through the common upper bound, as `AbstractComposedDBTraceCodeUnitsView`
        // would.
        let views: Vec<Box<dyn AbstractSingleDBTraceCodeUnitsView<()>>> = vec![
            Box::new(MockSingleView { space: instructions_space.clone() }),
            Box::new(MockSingleView { space: data_space.clone() }),
        ];

        assert_eq!(views[0].get_space().name(), "ram");
        assert_eq!(views[1].get_space().name(), "data");
        assert!(!Arc::ptr_eq(&views[0].get_space(), &views[1].get_space()));
    }
}
