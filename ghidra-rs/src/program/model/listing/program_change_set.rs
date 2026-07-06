use crate::program::model::address::AddressSetCollection;
use super::{
    AddressChangeSet, DataTypeChangeSet, DomainObjectChangeSet, FunctionTagChangeSet,
    ProgramTreeChangeSet, RegisterChangeSet, SymbolChangeSet,
};

/// Interface for a Program Change set. Objects that implement this trait track
/// various change information on a program.
pub trait ProgramChangeSet:
    DomainObjectChangeSet
    + AddressChangeSet
    + RegisterChangeSet
    + DataTypeChangeSet
    + ProgramTreeChangeSet
    + SymbolChangeSet
    + FunctionTagChangeSet
{
    /// Gets an AddressSetCollection which contains the addressSets that track all the addresses
    /// where changes have occurred since the last save.
    fn get_address_set_collection_since_last_save(&self) -> Box<dyn AddressSetCollection>;

    /// Gets an AddressSetCollection which contains the addressSets that track all the addresses
    /// where changes have occurred since the file was checked out. If the file is not versioned,
    /// this AddressSetCollection will be empty.
    fn get_address_set_collection_since_checkout(&self) -> Box<dyn AddressSetCollection>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct SimpleProgramChangeSet {
        address_set_since_save: AddressSet,
        address_set_since_checkout: AddressSet,
    }

    impl SimpleProgramChangeSet {
        fn new() -> Self {
            Self {
                address_set_since_save: AddressSet::new(),
                address_set_since_checkout: AddressSet::new(),
            }
        }
    }

    impl DomainObjectChangeSet for SimpleProgramChangeSet {
        fn has_changes(&self) -> bool {
            !self.address_set_since_save.is_empty() || !self.address_set_since_checkout.is_empty()
        }
    }

    impl crate::framework::model::ChangeSet for SimpleProgramChangeSet {}

    impl AddressChangeSet for SimpleProgramChangeSet {
        fn get_address_set(&self) -> &dyn crate::program::model::address::AddressSetView {
            &self.address_set_since_save
        }

        fn add(&mut self, addr_set: &dyn crate::program::model::address::AddressSetView) {
            self.address_set_since_save.add_set(addr_set);
        }

        fn add_range(
            &mut self,
            addr1: &Address,
            addr2: &Address,
        ) {
            self.address_set_since_save.add_range(addr1, addr2);
        }
    }

    impl RegisterChangeSet for SimpleProgramChangeSet {
        fn add_register_range(&mut self, _addr1: &Address, _addr2: &Address) {}

        fn get_register_address_set(&self) -> &dyn crate::program::model::address::AddressSetView {
            &self.address_set_since_checkout
        }
    }

    impl DataTypeChangeSet for SimpleProgramChangeSet {
        fn data_type_changed(&mut self, _id: i64) {}

        fn data_type_added(&mut self, _id: i64) {}

        fn get_data_type_changes(&self) -> &[i64] {
            &[]
        }

        fn get_data_type_additions(&self) -> &[i64] {
            &[]
        }

        fn category_changed(&mut self, _id: i64) {}

        fn category_added(&mut self, _id: i64) {}

        fn get_category_changes(&self) -> &[i64] {
            &[]
        }

        fn get_category_additions(&self) -> &[i64] {
            &[]
        }

        fn source_archive_changed(&mut self, _id: i64) {}

        fn source_archive_added(&mut self, _id: i64) {}

        fn get_source_archive_changes(&self) -> &[i64] {
            &[]
        }

        fn get_source_archive_additions(&self) -> &[i64] {
            &[]
        }
    }

    impl ProgramTreeChangeSet for SimpleProgramChangeSet {
        fn program_tree_changed(&mut self, _id: i64) {}

        fn program_tree_added(&mut self, _id: i64) {}

        fn get_program_tree_changes(&self) -> &[i64] {
            &[]
        }

        fn get_program_tree_additions(&self) -> &[i64] {
            &[]
        }
    }

    impl SymbolChangeSet for SimpleProgramChangeSet {
        fn symbol_changed(&mut self, _id: i64) {}

        fn symbol_added(&mut self, _id: i64) {}

        fn get_symbol_changes(&self) -> &[i64] {
            &[]
        }

        fn get_symbol_additions(&self) -> &[i64] {
            &[]
        }
    }

    impl FunctionTagChangeSet for SimpleProgramChangeSet {
        fn tag_changed(&mut self, _id: i64) {}

        fn tag_created(&mut self, _id: i64) {}

        fn get_tag_changes(&self) -> &[i64] {
            &[]
        }

        fn get_tag_creations(&self) -> &[i64] {
            &[]
        }
    }

    impl ProgramChangeSet for SimpleProgramChangeSet {
        fn get_address_set_collection_since_last_save(&self) -> Box<dyn AddressSetCollection> {
            Box::new(crate::program::model::address::SingleAddressSetCollection::new(
                Some(&self.address_set_since_save),
            ))
        }

        fn get_address_set_collection_since_checkout(&self) -> Box<dyn AddressSetCollection> {
            Box::new(crate::program::model::address::SingleAddressSetCollection::new(
                Some(&self.address_set_since_checkout),
            ))
        }
    }

    #[test]
    fn new_change_set_has_no_changes() {
        let cs = SimpleProgramChangeSet::new();
        assert!(!cs.has_changes());
    }

    #[test]
    fn change_set_has_changes_when_address_added() {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        let mut cs = SimpleProgramChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        cs.add_range(&addr1, &addr2);
        assert!(cs.has_changes());
    }

    #[test]
    fn get_address_set_collection_since_last_save_returns_collection() {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        let mut cs = SimpleProgramChangeSet::new();
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);
        cs.add_range(&addr1, &addr2);

        let collection = cs.get_address_set_collection_since_last_save();
        assert!(collection.contains(&addr1));
        assert!(collection.contains(&addr2));
    }

    #[test]
    fn get_address_set_collection_since_checkout_returns_collection() {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        let mut cs = SimpleProgramChangeSet::new();
        let addr = space.address(0x2000);
        cs.address_set_since_checkout.add_range(&addr, &addr);

        let collection = cs.get_address_set_collection_since_checkout();
        assert!(collection.contains(&addr));
    }

    #[test]
    fn trait_object_dispatch() {
        let space = AddressSpace::new("test", 32, 1, AddressSpaceType::Ram, 0);
        let mut cs: Box<dyn ProgramChangeSet> = Box::new(SimpleProgramChangeSet::new());
        let addr1 = space.address(0x1000);
        let addr2 = space.address(0x1010);

        cs.add_range(&addr1, &addr2);
        assert!(cs.has_changes());

        let collection = cs.get_address_set_collection_since_last_save();
        assert!(collection.contains(&addr1));
    }
}
