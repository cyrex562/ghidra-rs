//! Base interface class for the view providers and view manager service.
//!
//! Mirrors `ghidra.app.services.ViewService`.

use crate::program::model::address::address_set::AddressSetView;
use crate::program::util::program_location::ProgramLocation;

/// Base interface class for the view providers and view manager service.
pub trait ViewService {
    /// Add the view that corresponds to the given program location.
    ///
    /// # Arguments
    ///
    /// * `loc` - program location to be added to the view
    ///
    /// # Returns
    ///
    /// New address set for the added view
    fn add_to_view(&self, loc: &dyn ProgramLocation) -> Box<dyn AddressSetView>;

    /// Get the current view.
    fn get_current_view(&self) -> Box<dyn AddressSetView>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAddressSet;
    impl AddressSetView for MockAddressSet {
        fn contains(&self, _address: &crate::program::model::address::Address) -> bool {
            false
        }

        fn contains_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }

        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }

        fn num_address_ranges(&self) -> usize {
            0
        }

        fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!()
        }

        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!()
        }

        fn address_ranges_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!()
        }

        fn num_addresses(&self) -> u64 {
            0
        }

        fn addresses(
            &self,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!()
        }

        fn addresses_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!()
        }

        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn intersects_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }

        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!()
        }

        fn intersect_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!()
        }

        fn union(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!()
        }

        fn subtract(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!()
        }

        fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!()
        }

        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            false
        }

        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn range_containing(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            None
        }

        fn find_first_address_in_common(
            &self,
            _set: &dyn AddressSetView,
        ) -> Option<crate::program::model::address::Address> {
            None
        }
    }

    struct MockProgramLocation;
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_address(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_byte_address(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }
    }

    struct MockViewService;
    impl ViewService for MockViewService {
        fn add_to_view(&self, _loc: &dyn ProgramLocation) -> Box<dyn AddressSetView> {
            Box::new(MockAddressSet)
        }

        fn get_current_view(&self) -> Box<dyn AddressSetView> {
            Box::new(MockAddressSet)
        }
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn ViewService> = Box::new(MockViewService);
        let location = MockProgramLocation;

        let _added_view = service.add_to_view(&location);
        let _current_view = service.get_current_view();
    }
}
