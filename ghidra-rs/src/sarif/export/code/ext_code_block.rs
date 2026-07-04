use crate::program::model::address::AddressRange;
use crate::program::model::data::isf::IsfObject;

/// Represents an extended code block for SARIF export.
///
/// Mirrors `ExtCodeBlock` from Ghidra's `sarif.export.code` package.
pub struct ExtCodeBlock {
    pub range: AddressRange,
}

impl ExtCodeBlock {
    /// Creates a new `ExtCodeBlock` with the given address range.
    pub fn new(range: AddressRange) -> Self {
        Self { range }
    }
}

impl IsfObject for ExtCodeBlock {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn create_test_range(start: i64, end: i64) -> AddressRange {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let start_addr = Address::new(space.clone(), start);
        let end_addr = Address::new(space, end);
        AddressRange::new(start_addr, end_addr)
    }

    #[test]
    fn creates_code_block_with_range() {
        let range = create_test_range(0x1000, 0x1100);
        let block = ExtCodeBlock::new(range.clone());

        assert_eq!(block.range, range);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let range = create_test_range(0x2000, 0x2100);
        let block = ExtCodeBlock::new(range);
        accepts_isf_object(&block);
    }

    #[test]
    fn new_constructor_preserves_range_properties() {
        let range = create_test_range(0x500, 0x1000);
        let block = ExtCodeBlock::new(range.clone());

        assert_eq!(block.range.min_address(), range.min_address());
        assert_eq!(block.range.max_address(), range.max_address());
        assert_eq!(block.range.length(), range.length());
    }
}
