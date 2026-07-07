use crate::framework::model::DomainObject;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::{Function, Program};
use crate::util::datastruct::duo::Side;
use std::sync::Arc;

use super::ListingAddressCorrelation;

/// A dummy implementation of [`ListingAddressCorrelation`] that represents no correlation.
/// All methods return empty/null values: `get_function()` and `get_address()` return `None`,
/// while `get_program()` and `get_addresses()` return minimal no-op implementations.
#[derive(Debug, Clone)]
pub struct DummyListingAddressCorrelation;

struct DummyProgram;

impl DomainObject for DummyProgram {}

impl Program for DummyProgram {
    fn get_name(&self) -> String {
        "dummy".to_string()
    }

    fn get_language_id(&self) -> String {
        "unknown".to_string()
    }
}

struct DummyAddressSetView;

impl AddressSetView for DummyAddressSetView {
    fn contains(&self, _address: &Address) -> bool {
        false
    }

    fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
        false
    }

    fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
        false
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn min_address(&self) -> Option<Address> {
        None
    }

    fn max_address(&self) -> Option<Address> {
        None
    }

    fn num_address_ranges(&self) -> usize {
        0
    }

    fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(crate::program::model::address::EmptyAddressRangeIterator)
    }

    fn address_ranges_ordered(
        &self,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(crate::program::model::address::EmptyAddressRangeIterator)
    }

    fn address_ranges_from(
        &self,
        _start: &Address,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(crate::program::model::address::EmptyAddressRangeIterator)
    }

    fn num_addresses(&self) -> u64 {
        0
    }

    fn addresses(&self, _forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
        Box::new(crate::program::model::address::EmptyAddressIterator)
    }

    fn addresses_from(
        &self,
        _start: &Address,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        Box::new(crate::program::model::address::EmptyAddressIterator)
    }

    fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
        false
    }

    fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
        false
    }

    fn intersect(&self, _set: &dyn AddressSetView) -> AddressSet {
        AddressSet::new()
    }

    fn intersect_range(&self, _start: &Address, _end: &Address) -> AddressSet {
        AddressSet::new()
    }

    fn union(&self, _set: &dyn AddressSetView) -> AddressSet {
        AddressSet::new()
    }

    fn subtract(&self, _set: &dyn AddressSetView) -> AddressSet {
        AddressSet::new()
    }

    fn xor(&self, _set: &dyn AddressSetView) -> AddressSet {
        AddressSet::new()
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        set.is_empty()
    }

    fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
        None
    }

    fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
        None
    }

    fn range_containing(&self, _address: &Address) -> Option<crate::program::model::address::AddressRange> {
        None
    }

    fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
        None
    }
}

impl ListingAddressCorrelation for DummyListingAddressCorrelation {
    fn get_program(&self, _side: Side) -> Arc<dyn Program> {
        Arc::new(DummyProgram)
    }

    fn get_function(&self, _side: Side) -> Option<Arc<dyn Function>> {
        None
    }

    fn get_addresses(&self, _side: Side) -> Arc<dyn AddressSetView> {
        Arc::new(DummyAddressSetView)
    }

    fn get_address(&self, _side: Side, _other_side_address: &Address) -> Option<Address> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_program_returns_dummy() {
        let corr = DummyListingAddressCorrelation;
        let prog_left = corr.get_program(Side::Left);
        let prog_right = corr.get_program(Side::Right);
        assert_eq!(prog_left.get_name(), "dummy".to_string());
        assert_eq!(prog_right.get_name(), "dummy".to_string());
    }

    #[test]
    fn get_function_returns_none() {
        let corr = DummyListingAddressCorrelation;
        assert_eq!(corr.get_function(Side::Left), None);
        assert_eq!(corr.get_function(Side::Right), None);
    }

    #[test]
    fn get_addresses_returns_empty() {
        let corr = DummyListingAddressCorrelation;
        let addrs_left = corr.get_addresses(Side::Left);
        let addrs_right = corr.get_addresses(Side::Right);
        assert!(addrs_left.is_empty());
        assert!(addrs_right.is_empty());
        assert_eq!(addrs_left.num_addresses(), 0);
        assert_eq!(addrs_right.num_addresses(), 0);
    }

    #[test]
    fn get_address_returns_none() {
        let corr = DummyListingAddressCorrelation;
        let space =
            crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        assert_eq!(corr.get_address(Side::Left, &addr), None);
        assert_eq!(corr.get_address(Side::Right, &addr), None);
    }

    #[test]
    fn trait_object_creation() {
        let corr = DummyListingAddressCorrelation;
        let _: Arc<dyn ListingAddressCorrelation> = Arc::new(corr);
    }
}
