use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

/// Address object used for Ghidra sentinel addresses.
///
/// This mirrors Java's `SpecialAddress` behavior: the address prints as its
/// symbolic space name regardless of prefix or address-space formatting flags.
pub struct SpecialAddress;

impl SpecialAddress {
    pub fn new(name: &str) -> Address {
        Address::new(AddressSpace::new(name, 0, 1, AddressSpaceType::None, -1), 0)
    }

    pub fn no_address() -> Address {
        Self::new("NO ADDRESS")
    }

    pub fn ext_from_address() -> Address {
        Self::new("Entry Point")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_address_formats_as_name() {
        let address = SpecialAddress::no_address();

        assert_eq!(address.to_string(), "NO ADDRESS");
        assert_eq!(address.to_string_with_prefix("0x"), "NO ADDRESS");
        assert_eq!(address.format(true, 16), "NO ADDRESS");
    }

    #[test]
    fn external_entry_address_formats_as_entry_point() {
        assert_eq!(
            SpecialAddress::ext_from_address().to_string(),
            "Entry Point"
        );
    }
}
