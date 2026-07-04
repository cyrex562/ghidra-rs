use crate::program::model::address::Address;

/// Represents an object that can be identified by an address.
///
/// Implementations of this trait provide a mechanism to retrieve the address
/// associated with a row object in a table or listing.
pub trait AddressableRowObject {
    /// Returns the address associated with this row object.
    ///
    /// # Returns
    /// The address of this row object.
    fn get_address(&self) -> &Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct TestRowObject {
        address: Address,
    }

    impl AddressableRowObject for TestRowObject {
        fn get_address(&self) -> &Address {
            &self.address
        }
    }

    #[test]
    fn test_get_address_returns_correct_address() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x1000);
        let obj = TestRowObject {
            address: addr.clone(),
        };

        assert_eq!(obj.get_address(), &addr);
    }

    #[test]
    fn test_get_address_with_different_addresses() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr1 = Address::new(space.clone(), 0x1000);
        let addr2 = Address::new(space, 0x2000);

        let obj1 = TestRowObject {
            address: addr1.clone(),
        };
        let obj2 = TestRowObject {
            address: addr2.clone(),
        };

        assert_eq!(obj1.get_address(), &addr1);
        assert_eq!(obj2.get_address(), &addr2);
        assert_ne!(obj1.get_address(), obj2.get_address());
    }

    #[test]
    fn test_get_address_with_multiple_spaces() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let stack = AddressSpace::new("Stack", 32, 1, AddressSpaceType::Stack, 2);

        let addr1 = Address::new(ram, 0x1000);
        let addr2 = Address::new(stack, -0x10);

        let obj1 = TestRowObject {
            address: addr1.clone(),
        };
        let obj2 = TestRowObject {
            address: addr2.clone(),
        };

        assert_eq!(obj1.get_address(), &addr1);
        assert_eq!(obj2.get_address(), &addr2);
    }

    #[test]
    fn test_get_address_reference_stability() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(space, 0x5678);
        let obj = TestRowObject {
            address: addr.clone(),
        };

        let ref1 = obj.get_address();
        let ref2 = obj.get_address();

        assert_eq!(ref1, ref2);
        assert_eq!(ref1.offset(), 0x5678);
    }
}
