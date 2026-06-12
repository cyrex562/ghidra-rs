use crate::program::model::address::Address;

/// Reference to an equate at an address and operand index.
///
/// This mirrors Ghidra's `EquateReference` interface.
pub trait EquateReference {
    /// Returns the address associated with this reference.
    fn address(&self) -> &Address;

    /// Returns the operand index for the instruction at this reference address.
    fn op_index(&self) -> i16;

    /// Returns the dynamic hash value associated with the referenced constant varnode.
    ///
    /// A value of zero indicates that no dynamic hash applies.
    fn dynamic_hash_value(&self) -> i64;
}

/// Simple immutable equate reference value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleEquateReference {
    address: Address,
    op_index: i16,
    dynamic_hash_value: i64,
}

impl SimpleEquateReference {
    /// Creates an equate reference.
    pub fn new(address: Address, op_index: i16, dynamic_hash_value: i64) -> Self {
        Self {
            address,
            op_index,
            dynamic_hash_value,
        }
    }
}

impl EquateReference for SimpleEquateReference {
    fn address(&self) -> &Address {
        &self.address
    }

    fn op_index(&self) -> i16 {
        self.op_index
    }

    fn dynamic_hash_value(&self) -> i64 {
        self.dynamic_hash_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x401000)
    }

    #[test]
    fn stores_equate_reference_fields() {
        let address = test_address();
        let reference = SimpleEquateReference::new(address.clone(), 2, 0x1234);

        assert_eq!(reference.address(), &address);
        assert_eq!(reference.op_index(), 2);
        assert_eq!(reference.dynamic_hash_value(), 0x1234);
    }

    #[test]
    fn zero_dynamic_hash_means_not_applicable() {
        let reference = SimpleEquateReference::new(test_address(), -1, 0);

        assert_eq!(reference.op_index(), -1);
        assert_eq!(reference.dynamic_hash_value(), 0);
    }

    #[test]
    fn trait_object_exposes_reference_values() {
        let address = test_address();
        let reference = SimpleEquateReference::new(address.clone(), 1, 99);
        let reference: &dyn EquateReference = &reference;

        assert_eq!(reference.address(), &address);
        assert_eq!(reference.op_index(), 1);
        assert_eq!(reference.dynamic_hash_value(), 99);
    }
}
