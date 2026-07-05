use crate::framework::model::ChangeSet;
use crate::program::model::address::{Address, AddressSetView};

/// Tracks change information on a set of addresses where the program has changed.
///
/// Objects implementing this trait track various change information on a set of addresses,
/// allowing clients to identify which addresses within a program have been modified.
pub trait AddressChangeSet: ChangeSet {
    /// Returns the address set of all addresses where the listing has changed.
    fn get_address_set(&self) -> &dyn AddressSetView;

    /// Adds the address set to the set of addresses where changes occurred.
    fn add(&mut self, addr_set: &dyn AddressSetView);

    /// Adds the range of addresses to the set of addresses where changes occurred.
    ///
    /// # Arguments
    /// * `addr1` - The first address in the range.
    /// * `addr2` - The last address in the range (inclusive).
    fn add_range(&mut self, addr1: &Address, addr2: &Address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct SimpleAddressChangeSet {
        address_set: AddressSet,
    }

    impl SimpleAddressChangeSet {
        fn new() -> Self {
            Self {
                address_set: AddressSet::new(),
            }
        }
    }

    impl ChangeSet for SimpleAddressChangeSet {}

    impl AddressChangeSet for SimpleAddressChangeSet {
        fn get_address_set(&self) -> &dyn AddressSetView {
            &self.address_set
        }

        fn add(&mut self, addr_set: &dyn AddressSetView) {
            self.address_set.add_set(addr_set);
        }

        fn add_range(&mut self, addr1: &Address, addr2: &Address) {
            self.address_set.add_range(addr1, addr2);
        }
    }

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_change_set_is_empty() {
        let cs = SimpleAddressChangeSet::new();
        assert!(cs.get_address_set().is_empty());
    }

    #[test]
    fn add_range_single() {
        let space = create_test_address_space();
        let mut cs = SimpleAddressChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        cs.add_range(&addr1, &addr2);
        let addr_set = cs.get_address_set();
        assert!(!addr_set.is_empty());
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
    }

    #[test]
    fn add_range_multiple_ranges() {
        let space = create_test_address_space();
        let mut cs = SimpleAddressChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        let addr3 = space.address(0x2000);
        let addr4 = space.address(0x2010);
        cs.add_range(&addr1, &addr2);
        cs.add_range(&addr3, &addr4);
        let addr_set = cs.get_address_set();
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
        assert!(addr_set.contains(&addr3));
        assert!(addr_set.contains(&addr4));
    }

    #[test]
    fn add_set() {
        let space = create_test_address_space();
        let mut cs = SimpleAddressChangeSet::new();
        let mut other_set = AddressSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        other_set.add_range(&addr1, &addr2);
        cs.add(&other_set);
        let addr_set = cs.get_address_set();
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
    }

    #[test]
    fn add_set_multiple_times() {
        let space = create_test_address_space();
        let mut cs = SimpleAddressChangeSet::new();
        let mut set1 = AddressSet::new();
        let mut set2 = AddressSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        let addr3 = space.address(0x2000);
        let addr4 = space.address(0x2010);
        set1.add_range(&addr1, &addr2);
        set2.add_range(&addr3, &addr4);
        cs.add(&set1);
        cs.add(&set2);
        let addr_set = cs.get_address_set();
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
        assert!(addr_set.contains(&addr3));
        assert!(addr_set.contains(&addr4));
    }

    #[test]
    fn trait_object_dispatch() {
        let space = create_test_address_space();
        let mut cs: Box<dyn AddressChangeSet> = Box::new(SimpleAddressChangeSet::new());
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        cs.add_range(&addr1, &addr2);
        assert!(cs.get_address_set().contains(&addr1));
    }

    #[test]
    fn add_single_address() {
        let space = create_test_address_space();
        let mut cs = SimpleAddressChangeSet::new();
        let addr = space.address(0x1000);
        cs.add_range(&addr, &addr);
        let addr_set = cs.get_address_set();
        assert!(addr_set.contains(&addr));
    }
}
