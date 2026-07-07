use crate::sarif::export::ExtLogicalLocation;
use crate::program::model::address::Address;

/// Represents a wrapped logical location for SARIF export.
///
/// Mirrors `WrappedLogicalLocation` from Ghidra's `sarif.export` package.
/// Combines an extended logical location with an address and an index,
/// typically used during SARIF export processing.
#[derive(Debug, Clone)]
pub struct WrappedLogicalLocation {
    logical_location: ExtLogicalLocation,
    address: Address,
    index: i32,
}

impl WrappedLogicalLocation {
    /// Creates a new `WrappedLogicalLocation` with the given logical location and address.
    ///
    /// # Arguments
    ///
    /// * `logical_location` - The extended logical location.
    /// * `address` - The associated address.
    ///
    /// The index is initialized to 0.
    pub fn new(logical_location: ExtLogicalLocation, address: Address) -> Self {
        Self {
            logical_location,
            address,
            index: 0,
        }
    }

    /// Get the logical location.
    pub fn get_logical_location(&self) -> &ExtLogicalLocation {
        &self.logical_location
    }

    /// Get the address.
    pub fn get_address(&self) -> &Address {
        &self.address
    }

    /// Get the index.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Set the index.
    pub fn set_index(&mut self, index: i32) {
        self.index = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::address::AddressSpace;

    #[test]
    fn creates_new_wrapped_logical_location() {
        let space = AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let address = Address::new(space, 0x1000);
        let lloc = ExtLogicalLocation {
            name: "test_func".to_string(),
            kind: "function".to_string(),
            decorated_name: "test_func()".to_string(),
            fully_qualified_name: "mymodule:test_func".to_string(),
            uri: "test.bin".to_string(),
        };

        let wrapped = WrappedLogicalLocation::new(lloc.clone(), address.clone());

        assert_eq!(wrapped.get_logical_location().get_name(), "test_func");
        assert_eq!(wrapped.get_address().offset(), 0x1000);
        assert_eq!(wrapped.get_index(), 0);
    }

    #[test]
    fn sets_and_gets_index() {
        let space = AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let address = Address::new(space, 0x2000);
        let lloc = ExtLogicalLocation {
            name: "func2".to_string(),
            kind: "function".to_string(),
            decorated_name: "func2()".to_string(),
            fully_qualified_name: "mymodule:func2".to_string(),
            uri: "test.bin".to_string(),
        };

        let mut wrapped = WrappedLogicalLocation::new(lloc, address);

        wrapped.set_index(42);
        assert_eq!(wrapped.get_index(), 42);
    }

    #[test]
    fn initial_index_is_zero() {
        let space = AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let address = Address::new(space, 0x3000);
        let lloc = ExtLogicalLocation {
            name: "func3".to_string(),
            kind: "function".to_string(),
            decorated_name: "func3()".to_string(),
            fully_qualified_name: "mymodule:func3".to_string(),
            uri: "test.bin".to_string(),
        };

        let wrapped = WrappedLogicalLocation::new(lloc, address);
        assert_eq!(wrapped.get_index(), 0);
    }

    #[test]
    fn preserves_address_value() {
        let space = AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let address = Address::new(space, 0xDEADBEEF);
        let lloc = ExtLogicalLocation {
            name: "func".to_string(),
            kind: "function".to_string(),
            decorated_name: "func()".to_string(),
            fully_qualified_name: "pkg:func".to_string(),
            uri: "binary".to_string(),
        };

        let wrapped = WrappedLogicalLocation::new(lloc, address);
        assert_eq!(wrapped.get_address().offset(), 0xDEADBEEF);
    }
}
