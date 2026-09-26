//! Port of `ghidra.program.database.symbol.VariableStorageManager`.
//!
//! The Java type is a single-method interface for mapping a
//! [`VariableStorage`](crate::program::model::listing::variable_storage::VariableStorage) specification to (and
//! optionally allocating) the [`Address`] that represents it in the variable storage address
//! space. This trait was selected as a dependency-cycle cut-point.

use std::io;

use crate::program::model::address::Address;
use crate::program::model::listing::variable_storage::VariableStorage;

/// Maps variable storage specifications to variable addresses.
///
/// Port of `ghidra.program.database.symbol.VariableStorageManager`.
pub trait VariableStorageManager {
    /// Get a variable address for the given storage specification.
    ///
    /// Stands in for `VariableStorageManager.getVariableStorageAddress(VariableStorage, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_variable_storage_address(
        &self,
        storage: &dyn VariableStorage,
        create: bool,
    ) -> io::Result<Option<Address>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct MockStorage;

    impl VariableStorage for MockStorage {}

    /// Mock backed by a single storage slot: the [`VariableStorage`] trait's object-safe surface
    /// doesn't expose a hashable identity, so this mirrors the Java adapter's hash-keyed lookup
    /// with the simplest key space that still proves the create/find round trip.
    struct MockVariableStorageManager {
        slot: Mutex<Option<Address>>,
    }

    impl MockVariableStorageManager {
        fn new() -> Self {
            MockVariableStorageManager {
                slot: Mutex::new(None),
            }
        }
    }

    impl VariableStorageManager for MockVariableStorageManager {
        fn get_variable_storage_address(
            &self,
            _storage: &dyn VariableStorage,
            create: bool,
        ) -> io::Result<Option<Address>> {
            let mut slot = self.slot.lock().unwrap();
            if let Some(addr) = slot.clone() {
                return Ok(Some(addr));
            }
            if !create {
                return Ok(None);
            }
            let space = crate::program::model::address::AddressSpace::new(
                "const",
                32,
                1,
                crate::program::model::address::AddressSpaceType::Constant,
                0,
            );
            let addr = Address::new(space, 0);
            *slot = Some(addr.clone());
            Ok(Some(addr))
        }
    }

    #[test]
    fn object_safety_via_trait_object() {
        let manager: Box<dyn VariableStorageManager> = Box::new(MockVariableStorageManager::new());
        let storage = MockStorage;

        assert!(manager
            .get_variable_storage_address(&storage, false)
            .unwrap()
            .is_none());

        let allocated = manager
            .get_variable_storage_address(&storage, true)
            .unwrap()
            .expect("address allocated on create");

        let again = manager
            .get_variable_storage_address(&storage, false)
            .unwrap()
            .expect("previously allocated address is found without create");

        assert_eq!(allocated, again);
    }
}
