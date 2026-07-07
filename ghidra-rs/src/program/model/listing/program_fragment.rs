use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::group::Group;
use crate::util::exception::NotFoundException;

/// A `ProgramFragment` is a set of [`CodeUnit`]s that have been bundled together with some
/// additional information such as a name, comment, alias, etc. Every code unit in the program is
/// in one and only one fragment so the fragments form a partition of the program. Fragments in
/// turn are the building blocks of
/// [`ProgramModule`](crate::program::model::listing::program_module::ProgramModule)s. Program
/// fragments and modules allow the user to overlay a hierarchical structure upon the program
/// which can then be used to control viewing and navigating the program.
///
/// Port of `ghidra.program.model.listing.ProgramFragment`.
///
/// The Java interface extends `Group` and `AddressSetView`, carried here as supertraits. The
/// Java `@Override` of `Group.contains(CodeUnit)` is inherited unchanged from
/// [`Group::contains`], since `AddressSetView::contains` takes an `Address` and so does not
/// collide with it.
pub trait ProgramFragment: Group + AddressSetView {
    /// Returns a forward iterator over the code units making up this fragment.
    fn get_code_units(&self) -> Box<dyn CodeUnitIterator>;

    /// Moves all of the code units in a given range into this fragment.
    ///
    /// Note that `min` must be the starting address of a code unit and `max` must be the ending
    /// address of a code unit. Furthermore every address in the given range must exist in
    /// program memory.
    ///
    /// # Errors
    /// Returns `Err` if any address between `min` and `max` (inclusive) does not belong to
    /// program memory.
    fn move_code_units(&mut self, min: &Address, max: &Address) -> Result<(), NotFoundException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressRange, AddressRangeIterator, AddressIterator};
    use crate::program::model::address::AddressSet;
    use crate::util::exception::DuplicateNameException;

    struct MockFragment {
        name: String,
        addresses: AddressSet,
    }

    impl Group for MockFragment {
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

    impl AddressSetView for MockFragment {
        fn contains(&self, address: &Address) -> bool {
            AddressSetView::contains(&self.addresses, address)
        }

        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.contains_range(start, end)
        }

        fn contains_set(&self, set: &dyn AddressSetView) -> bool {
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

        fn addresses(&self, forward: bool) -> Box<dyn AddressIterator> {
            AddressSetView::addresses(&self.addresses, forward)
        }

        fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn AddressIterator> {
            self.addresses.addresses_from(start, forward)
        }

        fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
            self.addresses.intersects_set(set)
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.intersects_range(start, end)
        }

        fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.intersect(set)
        }

        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.addresses.intersect_range(start, end)
        }

        fn union(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.union(set)
        }

        fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.subtract(set)
        }

        fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
            self.addresses.xor(set)
        }

        fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
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

        fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
            self.addresses.find_first_address_in_common(set)
        }
    }

    impl ProgramFragment for MockFragment {
        fn get_code_units(&self) -> Box<dyn CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn move_code_units(&mut self, _min: &Address, _max: &Address) -> Result<(), NotFoundException> {
            Ok(())
        }
    }

    #[test]
    fn object_safe_and_usable_via_trait_object() {
        let fragment = MockFragment { name: "frag".to_string(), addresses: AddressSet::new() };
        let mut fragment: Box<dyn ProgramFragment> = Box::new(fragment);

        assert_eq!(fragment.get_name(), "frag");
        assert!(fragment.is_empty());
        assert!(fragment.get_code_units().next_code_unit().is_none());
        assert!(fragment.move_code_units(&fragment_addr(0), &fragment_addr(0)).is_ok());
    }

    fn fragment_addr(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
