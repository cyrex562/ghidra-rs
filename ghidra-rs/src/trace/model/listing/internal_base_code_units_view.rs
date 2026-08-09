use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;

/// A base view of code units within an address space.
///
/// Port of `ghidra.trace.database.listing.InternalBaseCodeUnitsView<T>`.
///
/// This interface extends [`TraceBaseCodeUnitsView`] and adds an abstract method to get the
/// address space the view is bound to. The three Java default implementations for
/// platform-taking register query methods (which use `getSpace()` to obtain the overlay
/// register space) are left to be implemented by concrete subtypes, as they require access to
/// `TraceRegisterUtils` and type-unsafe downcasting from `TraceCodeUnit` to `TraceData` which
/// are not easily expressed in Rust's trait-object system.
pub trait InternalBaseCodeUnitsView: TraceBaseCodeUnitsView {
    /// The address space this view is bound to. Mirrors
    /// `InternalBaseCodeUnitsView.getSpace()`.
    fn get_space(&self) -> Arc<AddressSpace>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView;
    use crate::program::model::address::{Address, AddressRange, AddressSet, AddressSetView};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
    use crate::trace::seam_stubs::TracePlatform;
    use crate::program::model::lang::Register;
    use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;

    struct MockView {
        space: Arc<AddressSpace>,
    }

    impl TraceBaseCodeUnitsView for MockView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
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

        fn get_from(
            &self,
            _snap: i64,
            _start: &Address,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
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

    impl InternalBaseCodeUnitsView for MockView {
        fn get_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }
    }

    #[test]
    fn internal_view_has_address_space() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let view = MockView {
            space: space.clone(),
        };

        assert_eq!(view.get_space().name(), "ram");
    }

    #[test]
    fn internal_view_implements_base_view_trait() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let view = MockView {
            space,
        };

        let base_view: &dyn TraceBaseCodeUnitsView = &view;
        assert_eq!(base_view.size(), 0);
    }
}
