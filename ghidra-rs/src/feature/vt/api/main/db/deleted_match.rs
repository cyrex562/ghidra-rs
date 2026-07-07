use crate::program::model::address::Address;

/// A simple object that holds information about a match that has been deleted from the database.
#[derive(Clone, Debug)]
pub struct DeletedMatch {
    source_address: Address,
    destination_address: Address,
}

impl DeletedMatch {
    /// Creates a new DeletedMatch with the given source and destination addresses.
    pub(crate) fn new(source_address: Address, destination_address: Address) -> Self {
        Self {
            source_address,
            destination_address,
        }
    }

    /// Returns the source address of this deleted match.
    pub fn source_address(&self) -> &Address {
        &self.source_address
    }

    /// Returns the destination address of this deleted match.
    pub fn destination_address(&self) -> &Address {
        &self.destination_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn create_test_address(space_name: &str, offset: i64) -> Address {
        let space = AddressSpace::new(space_name, 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn new_stores_addresses() {
        let source = create_test_address("ram", 0x1000);
        let dest = create_test_address("ram", 0x2000);
        let source_clone = source.clone();
        let dest_clone = dest.clone();

        let deleted_match = DeletedMatch::new(source, dest);

        assert_eq!(*deleted_match.source_address(), source_clone);
        assert_eq!(*deleted_match.destination_address(), dest_clone);
    }

    #[test]
    fn getters_return_correct_addresses() {
        let source = create_test_address("ram", 0x1000);
        let dest = create_test_address("ram", 0x2000);
        let source_clone = source.clone();
        let dest_clone = dest.clone();

        let deleted_match = DeletedMatch::new(source, dest);

        assert_eq!(*deleted_match.source_address(), source_clone);
        assert_eq!(*deleted_match.destination_address(), dest_clone);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let source = create_test_address("ram", 0x1000);
        let dest = create_test_address("ram", 0x2000);

        let deleted_match1 = DeletedMatch::new(source.clone(), dest.clone());
        let deleted_match2 = deleted_match1.clone();

        assert_eq!(*deleted_match1.source_address(), *deleted_match2.source_address());
        assert_eq!(
            *deleted_match1.destination_address(),
            *deleted_match2.destination_address()
        );
    }

    #[test]
    fn debug_format_works() {
        let source = create_test_address("ram", 0x1000);
        let dest = create_test_address("ram", 0x2000);
        let deleted_match = DeletedMatch::new(source, dest);

        let debug_str = format!("{:?}", deleted_match);
        assert!(debug_str.contains("DeletedMatch"));
    }
}
