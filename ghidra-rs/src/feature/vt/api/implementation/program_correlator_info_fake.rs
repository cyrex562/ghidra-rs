use crate::framework::options::Options;
use crate::program::model::address::{
    AddressSetView, EmptyAddressIterator, EmptyAddressRangeIterator,
};

use super::VtProgramCorrelatorInfo;

struct EmptyOptions;

impl Options for EmptyOptions {}

struct EmptyAddressSet;

impl AddressSetView for EmptyAddressSet {
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

    fn address_ranges(
        &self,
    ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(EmptyAddressRangeIterator)
    }

    fn address_ranges_ordered(
        &self,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(EmptyAddressRangeIterator)
    }

    fn address_ranges_from(
        &self,
        _start: &crate::program::model::address::Address,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
        Box::new(EmptyAddressRangeIterator)
    }

    fn num_addresses(&self) -> u64 {
        0
    }

    fn addresses(
        &self,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        Box::new(EmptyAddressIterator)
    }

    fn addresses_from(
        &self,
        _start: &crate::program::model::address::Address,
        _forward: bool,
    ) -> Box<dyn crate::program::model::address::AddressIterator> {
        Box::new(EmptyAddressIterator)
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

    fn intersect(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
        crate::program::model::address::AddressSet::new()
    }

    fn intersect_range(
        &self,
        _start: &crate::program::model::address::Address,
        _end: &crate::program::model::address::Address,
    ) -> crate::program::model::address::AddressSet {
        crate::program::model::address::AddressSet::new()
    }

    fn union(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
        crate::program::model::address::AddressSet::new()
    }

    fn subtract(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
        crate::program::model::address::AddressSet::new()
    }

    fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
        crate::program::model::address::AddressSet::new()
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

/// A fake implementation of [`VtProgramCorrelatorInfo`] that only stores a name.
///
/// This implementation is useful for testing or for creating placeholder correlator information
/// without a full correlator implementation. All methods except [`get_name`] return empty or null-like values.
///
/// [`get_name`]: VtProgramCorrelatorInfo::get_name
pub struct ProgramCorrelatorInfoFake {
    name: String,
}

impl ProgramCorrelatorInfoFake {
    /// Creates a new fake correlator info with the given name.
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }
}

impl VtProgramCorrelatorInfo for ProgramCorrelatorInfoFake {
    fn get_name(&self) -> &str {
        &self.name
    }

    fn get_correlator_class_name(&self) -> &str {
        ""
    }

    fn get_options(&self) -> &dyn Options {
        &EmptyOptions
    }

    fn get_destination_address_set(&self) -> &dyn AddressSetView {
        &EmptyAddressSet
    }

    fn get_source_address_set(&self) -> &dyn AddressSetView {
        &EmptyAddressSet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_name() {
        let fake = ProgramCorrelatorInfoFake::new("Test Correlator".to_string());
        assert_eq!(fake.get_name(), "Test Correlator");
    }

    #[test]
    fn test_get_name() {
        let fake = ProgramCorrelatorInfoFake::new("My Correlator".to_string());
        assert_eq!(fake.get_name(), "My Correlator");
    }

    #[test]
    fn test_get_correlator_class_name_is_empty() {
        let fake = ProgramCorrelatorInfoFake::new("Test".to_string());
        assert_eq!(fake.get_correlator_class_name(), "");
    }

    #[test]
    fn test_get_options() {
        let fake = ProgramCorrelatorInfoFake::new("Test".to_string());
        let _opts = fake.get_options();
    }

    #[test]
    fn test_destination_address_set_is_empty() {
        let fake = ProgramCorrelatorInfoFake::new("Test".to_string());
        let addr_set = fake.get_destination_address_set();
        assert!(addr_set.is_empty());
    }

    #[test]
    fn test_source_address_set_is_empty() {
        let fake = ProgramCorrelatorInfoFake::new("Test".to_string());
        let addr_set = fake.get_source_address_set();
        assert!(addr_set.is_empty());
    }

    #[test]
    fn test_trait_object() {
        let fake = ProgramCorrelatorInfoFake::new("Trait Object Test".to_string());
        let correlator: &dyn VtProgramCorrelatorInfo = &fake;
        assert_eq!(correlator.get_name(), "Trait Object Test");
        assert_eq!(correlator.get_correlator_class_name(), "");
    }

    #[test]
    fn test_multiple_instances() {
        let fake1 = ProgramCorrelatorInfoFake::new("First".to_string());
        let fake2 = ProgramCorrelatorInfoFake::new("Second".to_string());

        assert_eq!(fake1.get_name(), "First");
        assert_eq!(fake2.get_name(), "Second");
        assert_ne!(fake1.get_name(), fake2.get_name());
    }
}
