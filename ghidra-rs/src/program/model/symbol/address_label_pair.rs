use crate::program::model::address::Address;

/// Container for an address and label.
///
/// This mirrors Ghidra's `AddressLabelPair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressLabelPair {
    address: Address,
    label: String,
}

impl AddressLabelPair {
    /// Creates an address-label pair.
    pub fn new(address: Address, label: impl Into<String>) -> Self {
        Self {
            address,
            label: label.into(),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn stores_address_and_label() {
        let address = test_address(0x1000);
        let pair = AddressLabelPair::new(address.clone(), "entry");

        assert_eq!(pair.address(), &address);
        assert_eq!(pair.label(), "entry");
    }

    #[test]
    fn equality_requires_matching_address_and_label() {
        let address = test_address(0x1000);

        assert_eq!(
            AddressLabelPair::new(address.clone(), "label"),
            AddressLabelPair::new(address.clone(), "label")
        );
        assert_ne!(
            AddressLabelPair::new(address.clone(), "label"),
            AddressLabelPair::new(address.clone(), "other")
        );
        assert_ne!(
            AddressLabelPair::new(address, "label"),
            AddressLabelPair::new(test_address(0x1001), "label")
        );
    }
}
