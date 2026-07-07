use crate::program::model::data::isf::IsfObject;
use crate::program::model::listing::program_fragment::ProgramFragment;

use super::ext_fragment_range::ExtFragmentRange;

/// Represents an extended fragment for SARIF export.
///
/// Mirrors `ExtFragment` from Ghidra's `sarif.export.trees` package. Stores the name
/// of a [`ProgramFragment`] along with a vector of its address ranges.
pub struct ExtFragment {
    pub name: String,
    pub ranges: Vec<ExtFragmentRange>,
}

impl ExtFragment {
    /// Creates a new `ExtFragment` from a [`ProgramFragment`].
    ///
    /// Extracts the fragment's name and creates an [`ExtFragmentRange`] for each
    /// address range within the fragment. The fragment is added to the provided
    /// `visited` vector to track processing.
    ///
    /// # Arguments
    ///
    /// * `fragment` - The program fragment to extract data from.
    /// * `visited` - A mutable vector tracking visited fragments (for reference tracking).
    pub fn new(fragment: &dyn ProgramFragment, visited: &mut Vec<String>) -> Self {
        let name = fragment.get_name();
        visited.push(name.clone());

        let mut ranges = Vec::new();
        let mut iter = fragment.address_ranges();

        while let Some(range) = iter.next_range() {
            ranges.push(ExtFragmentRange::new(&range));
        }

        Self { name, ranges }
    }
}

impl IsfObject for ExtFragment {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressSpace, AddressSpaceType};
    use crate::program::model::address::AddressSet;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
    use crate::program::model::listing::group::Group;
    use crate::util::exception::{DuplicateNameException, NotFoundException};

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockProgramFragment {
        name: String,
        addresses: AddressSet,
    }

    impl MockProgramFragment {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                addresses: AddressSet::new(),
            }
        }

        fn with_ranges(name: &str, ranges: Vec<(i64, i64)>) -> Self {
            let mut addresses = AddressSet::new();
            for (start, end) in ranges {
                let start_addr = test_address(start);
                let end_addr = test_address(end);
                let range = AddressRange::new(start_addr, end_addr);
                addresses.add_range(&range);
            }
            Self {
                name: name.to_string(),
                addresses,
            }
        }
    }

    impl Group for MockProgramFragment {
        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }

        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }

        fn get_num_parents(&self) -> i32 {
            0
        }

        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }

        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }

        fn is_deleted(&self) -> bool {
            false
        }

        fn get_min_address(&self) -> Option<Address> {
            self.addresses.min_address()
        }

        fn get_max_address(&self) -> Option<Address> {
            self.addresses.max_address()
        }
    }

    impl crate::program::model::address::AddressSetView for MockProgramFragment {
        fn contains(&self, address: &Address) -> bool {
            self.addresses.contains(address)
        }

        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.contains_range(start, end)
        }

        fn contains_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.contains_set(set)
        }

        fn is_empty(&self) -> bool {
            self.addresses.is_empty()
        }

        fn min_address(&self) -> Option<Address> {
            self.addresses.min_address()
        }

        fn max_address(&self) -> Option<Address> {
            self.addresses.max_address()
        }

        fn num_address_ranges(&self) -> usize {
            self.addresses.num_address_ranges()
        }

        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges()
        }

        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges_ordered(forward)
        }

        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges_from(start, forward)
        }

        fn num_addresses(&self) -> u64 {
            self.addresses.num_addresses()
        }

        fn addresses(&self, forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            crate::program::model::address::AddressSetView::addresses(&self.addresses, forward)
        }

        fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.addresses.addresses_from(start, forward)
        }

        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.intersects_set(set)
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.intersects_range(start, end)
        }

        fn intersect(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.intersect(set)
        }

        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.addresses.intersect_range(start, end)
        }

        fn union(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.union(set)
        }

        fn subtract(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.subtract(set)
        }

        fn xor(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.xor(set)
        }

        fn has_same_addresses(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.has_same_addresses(set)
        }

        fn first_range(&self) -> Option<AddressRange> {
            self.addresses.first_range()
        }

        fn last_range(&self) -> Option<AddressRange> {
            self.addresses.last_range()
        }

        fn range_containing(&self, address: &Address) -> Option<AddressRange> {
            self.addresses.range_containing(address)
        }

        fn find_first_address_in_common(&self, set: &dyn crate::program::model::address::AddressSetView) -> Option<Address> {
            self.addresses.find_first_address_in_common(set)
        }
    }

    impl ProgramFragment for MockProgramFragment {
        fn get_code_units(&self) -> Box<dyn CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn move_code_units(&mut self, _min: &Address, _max: &Address) -> Result<(), NotFoundException> {
            Ok(())
        }
    }

    #[test]
    fn creates_fragment_with_name() {
        let fragment = MockProgramFragment::new("TestFragment");
        let mut visited = Vec::new();

        let ext = ExtFragment::new(&fragment, &mut visited);

        assert_eq!(ext.name, "TestFragment");
    }

    #[test]
    fn adds_fragment_to_visited() {
        let fragment = MockProgramFragment::new("MyFragment");
        let mut visited = Vec::new();

        ExtFragment::new(&fragment, &mut visited);

        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0], "MyFragment");
    }

    #[test]
    fn creates_ranges_for_address_ranges() {
        let fragment = MockProgramFragment::with_ranges("RangeFragment", vec![(0x1000, 0x2000), (0x3000, 0x4000)]);
        let mut visited = Vec::new();

        let ext = ExtFragment::new(&fragment, &mut visited);

        assert_eq!(ext.ranges.len(), 2);
        assert_eq!(ext.ranges[0].start, "RAM:0x1000");
        assert_eq!(ext.ranges[0].end, "RAM:0x2000");
        assert_eq!(ext.ranges[1].start, "RAM:0x3000");
        assert_eq!(ext.ranges[1].end, "RAM:0x4000");
    }

    #[test]
    fn handles_fragment_with_no_ranges() {
        let fragment = MockProgramFragment::new("EmptyFragment");
        let mut visited = Vec::new();

        let ext = ExtFragment::new(&fragment, &mut visited);

        assert_eq!(ext.ranges.is_empty(), true);
        assert_eq!(ext.name, "EmptyFragment");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let fragment = MockProgramFragment::new("TestFragment");
        let mut visited = Vec::new();
        let ext = ExtFragment::new(&fragment, &mut visited);

        accepts_isf_object(&ext);
    }

    #[test]
    fn multiple_fragments_tracked_in_visited() {
        let frag1 = MockProgramFragment::new("Fragment1");
        let frag2 = MockProgramFragment::new("Fragment2");
        let mut visited = Vec::new();

        ExtFragment::new(&frag1, &mut visited);
        ExtFragment::new(&frag2, &mut visited);

        assert_eq!(visited.len(), 2);
        assert_eq!(visited[0], "Fragment1");
        assert_eq!(visited[1], "Fragment2");
    }

    #[test]
    fn preserves_fragment_name_exactly() {
        let names = vec!["a", "Fragment_With_Underscore", "123", "MixedCASE"];
        for name in names {
            let fragment = MockProgramFragment::new(name);
            let mut visited = Vec::new();

            let ext = ExtFragment::new(&fragment, &mut visited);

            assert_eq!(ext.name, name);
        }
    }
}
