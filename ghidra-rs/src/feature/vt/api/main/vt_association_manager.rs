use std::collections::HashMap;

use crate::feature::seam_stubs::VtAssociation;
use crate::program::model::address::Address;

/// Manages version tracking associations between source and destination addresses.
/// This trait provides query methods for retrieving associations within a session.
pub trait VtAssociationManager: Send + Sync {
    /// Returns the total number of associations that have been defined regardless of whether or
    /// not they have been accepted.
    fn get_association_count(&self) -> usize;

    /// Returns a list of all defined associations regardless of whether or not they have been accepted.
    fn get_associations(&self) -> Vec<Box<dyn VtAssociation>>;

    /// Returns an association for the given source and destination addresses if one has been defined or
    /// `None` if no such association has been defined.
    fn get_association(&self, source_address: &Address, destination_address: &Address) -> Option<Box<dyn VtAssociation>>;

    /// Returns a collection of all defined associations that have the given source address.
    fn get_related_associations_by_source_address(&self, source_address: &Address) -> Vec<Box<dyn VtAssociation>>;

    /// Returns a collection of all defined associations that have the given destination address.
    fn get_related_associations_by_destination_address(&self, destination_address: &Address) -> Vec<Box<dyn VtAssociation>>;

    /// Returns a collection of all defined associations that have either the given source
    /// address or the given destination address.
    fn get_related_associations_by_source_and_destination_address(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Vec<Box<dyn VtAssociation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVtAssociationManager {
        associations: HashMap<(String, String), bool>,
    }

    impl MockVtAssociationManager {
        fn new() -> Self {
            Self {
                associations: HashMap::new(),
            }
        }
    }

    impl VtAssociationManager for MockVtAssociationManager {
        fn get_association_count(&self) -> usize {
            self.associations.len()
        }

        fn get_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_association(&self, _source_address: &Address, _destination_address: &Address) -> Option<Box<dyn VtAssociation>> {
            None
        }

        fn get_related_associations_by_source_address(&self, _source_address: &Address) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_related_associations_by_destination_address(&self, _destination_address: &Address) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_related_associations_by_source_and_destination_address(
            &self,
            _source_address: &Address,
            _destination_address: &Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
    }

    #[test]
    fn mock_manager_has_zero_associations() {
        let manager = MockVtAssociationManager::new();
        assert_eq!(manager.get_association_count(), 0);
    }

    #[test]
    fn mock_manager_returns_empty_list() {
        let manager = MockVtAssociationManager::new();
        assert_eq!(manager.get_associations().len(), 0);
    }

    #[test]
    fn mock_manager_returns_none_for_nonexistent_association() {
        use crate::program::model::address::AddressSpaceType;

        let space = crate::program::model::address::AddressSpace::new("test", 64, 8, AddressSpaceType::Ram, 0);
        let addr1 = Address::new(space.clone(), 0);
        let addr2 = Address::new(space.clone(), 4);

        let manager = MockVtAssociationManager::new();
        assert!(manager.get_association(&addr1, &addr2).is_none());
    }
}
