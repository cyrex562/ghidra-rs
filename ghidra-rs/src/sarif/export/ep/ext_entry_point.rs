use crate::program::model::address::Address;
use crate::program::model::data::isf::IsfObject;

/// Represents an extended entry point for SARIF export.
///
/// Mirrors `ExtEntryPoint` from Ghidra's `sarif.export.ep` package.
pub struct ExtEntryPoint {
    pub address: Address,
}

impl ExtEntryPoint {
    /// Creates a new `ExtEntryPoint` with the given address.
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}

impl IsfObject for ExtEntryPoint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn create_test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn creates_entry_point_with_address() {
        let addr = create_test_address(0x1000);
        let ep = ExtEntryPoint::new(addr.clone());

        assert_eq!(ep.address.offset(), addr.offset());
        assert_eq!(ep.address.space().name(), addr.space().name());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let addr = create_test_address(0x2000);
        let ep = ExtEntryPoint::new(addr);
        accepts_isf_object(&ep);
    }

    #[test]
    fn new_constructor_preserves_address_properties() {
        let addr = create_test_address(0x500);
        let ep = ExtEntryPoint::new(addr.clone());

        assert_eq!(ep.address.offset(), addr.offset());
        assert_eq!(ep.address.unsigned_offset(), addr.unsigned_offset());
    }

    #[test]
    fn address_space_properties_match() {
        let addr = create_test_address(0x100);
        let ep = ExtEntryPoint::new(addr.clone());

        assert_eq!(ep.address.space().size(), addr.space().size());
        assert_eq!(ep.address.space().unit_size(), addr.space().unit_size());
        assert_eq!(ep.address.space().space_type(), addr.space().space_type());
    }
}
