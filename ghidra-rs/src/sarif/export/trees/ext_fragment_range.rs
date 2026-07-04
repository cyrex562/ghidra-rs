use crate::program::model::address::AddressRange;
use crate::program::model::data::isf::IsfObject;

/// Represents an extended fragment range for SARIF export.
///
/// Mirrors `ExtFragmentRange` from Ghidra's `sarif.export.trees` package. Stores the string
/// representations of the minimum and maximum addresses from an [`AddressRange`].
pub struct ExtFragmentRange {
    pub start: String,
    pub end: String,
}

impl ExtFragmentRange {
    /// Creates a new `ExtFragmentRange` from an [`AddressRange`].
    pub fn new(range: &AddressRange) -> Self {
        let start = range.min_address().to_string();
        let end = range.max_address().to_string();
        Self { start, end }
    }
}

impl IsfObject for ExtFragmentRange {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn test_address(space_name: &str, offset: i64) -> Address {
        let space = AddressSpace::new(space_name, 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn creates_fragment_range_from_address_range() {
        let start = test_address("RAM", 0x1000);
        let end = test_address("RAM", 0x2000);
        let range = AddressRange::new(start.clone(), end.clone());

        let fragment = ExtFragmentRange::new(&range);

        assert_eq!(fragment.start, "RAM:0x1000");
        assert_eq!(fragment.end, "RAM:0x2000");
    }

    #[test]
    fn handles_reversed_address_range() {
        let start = test_address("RAM", 0x2000);
        let end = test_address("RAM", 0x1000);
        let range = AddressRange::new(start, end);

        let fragment = ExtFragmentRange::new(&range);

        assert_eq!(fragment.start, "RAM:0x1000");
        assert_eq!(fragment.end, "RAM:0x2000");
    }

    #[test]
    fn handles_zero_length_range() {
        let addr = test_address("RAM", 0x500);
        let range = AddressRange::new(addr.clone(), addr.clone());

        let fragment = ExtFragmentRange::new(&range);

        assert_eq!(fragment.start, "RAM:0x500");
        assert_eq!(fragment.end, "RAM:0x500");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let start = test_address("RAM", 0x1000);
        let end = test_address("RAM", 0x2000);
        let range = AddressRange::new(start, end);
        let fragment = ExtFragmentRange::new(&range);

        accepts_isf_object(&fragment);
    }

    #[test]
    fn address_strings_match_display_format() {
        let start = test_address("MEMORY", 0x4000);
        let end = test_address("MEMORY", 0x5000);
        let range = AddressRange::new(start.clone(), end.clone());

        let fragment = ExtFragmentRange::new(&range);

        assert_eq!(fragment.start, start.to_string());
        assert_eq!(fragment.end, end.to_string());
    }
}
