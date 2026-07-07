use crate::framework::model::ChangeSet;
use crate::program::model::address::{Address, AddressSetView};

/// Tracks change information on a set of addresses where the program register values have changed.
///
/// Objects implementing this trait track various change information on a set of addresses,
/// allowing clients to identify which registers within a program have been modified.
pub trait RegisterChangeSet: ChangeSet {
    /// Adds the ranges of addresses that have register changes.
    ///
    /// # Arguments
    /// * `addr1` - The first address in the range.
    /// * `addr2` - The last address in the range (inclusive).
    fn add_register_range(&mut self, addr1: &Address, addr2: &Address);

    /// Returns the set of addresses containing register changes.
    fn get_register_address_set(&self) -> &dyn AddressSetView;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct SimpleRegisterChangeSet {
        address_set: AddressSet,
    }

    impl SimpleRegisterChangeSet {
        fn new() -> Self {
            Self {
                address_set: AddressSet::new(),
            }
        }
    }

    impl ChangeSet for SimpleRegisterChangeSet {}

    impl RegisterChangeSet for SimpleRegisterChangeSet {
        fn add_register_range(&mut self, addr1: &Address, addr2: &Address) {
            self.address_set.add_range(addr1, addr2);
        }

        fn get_register_address_set(&self) -> &dyn AddressSetView {
            &self.address_set
        }
    }

    fn create_test_address_space() -> Arc<AddressSpace> {
        AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_change_set_is_empty() {
        let cs = SimpleRegisterChangeSet::new();
        assert!(cs.get_register_address_set().is_empty());
    }

    #[test]
    fn add_register_range_single() {
        let space = create_test_address_space();
        let mut cs = SimpleRegisterChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        cs.add_register_range(&addr1, &addr2);
        let addr_set = cs.get_register_address_set();
        assert!(!addr_set.is_empty());
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
    }

    #[test]
    fn add_register_range_multiple_ranges() {
        let space = create_test_address_space();
        let mut cs = SimpleRegisterChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        let addr3 = space.address(0x2000);
        let addr4 = space.address(0x2010);
        cs.add_register_range(&addr1, &addr2);
        cs.add_register_range(&addr3, &addr4);
        let addr_set = cs.get_register_address_set();
        assert!(addr_set.contains(&addr1));
        assert!(addr_set.contains(&addr2));
        assert!(addr_set.contains(&addr3));
        assert!(addr_set.contains(&addr4));
    }

    #[test]
    fn get_register_address_set_returns_combined_ranges() {
        let space = create_test_address_space();
        let mut cs = SimpleRegisterChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1005);
        let addr3 = space.address(0x1006);
        let addr4 = space.address(0x1010);
        cs.add_register_range(&addr1, &addr2);
        cs.add_register_range(&addr3, &addr4);
        let addr_set = cs.get_register_address_set();
        assert_eq!(addr_set.num_ranges(), 2);
    }
}
