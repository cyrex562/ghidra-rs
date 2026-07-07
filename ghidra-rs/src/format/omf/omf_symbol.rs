use crate::program::model::address::Address;

/// These names were taken from the OpenWatcom source code
/// <https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/fppatche.h>
const FLOATINGPOINT_SPECIALNAMES: &[&str] = &[
    "FIWRQQ", "FIDRQQ", "FIERQQ", "FICRQQ", "FJCRQQ", "FISRQQ", "FJSRQQ", "FIARQQ", "FJARQQ",
    "FIFRQQ", "FJFRQQ", "FIGRQQ", "FJGRQQ",
];

/// An OMF symbol record.
///
/// Mirrors Ghidra's `OmfSymbol` class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfSymbol {
    symbol_name: String,
    type_index: i32,
    data_type: i32,
    byte_length: i32,
    /// Symbol is really a reference to an extra segment.
    segment_ref: i32,
    offset: i64,
    address: Option<Address>,
}

impl OmfSymbol {
    pub fn new(name: impl Into<String>, type_index: i32, offset: i64, data_type: i32, byte_length: i32) -> Self {
        Self {
            symbol_name: name.into(),
            type_index,
            data_type,
            byte_length,
            segment_ref: 0,
            offset,
            address: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.symbol_name
    }

    pub fn type_index(&self) -> i32 {
        self.type_index
    }

    pub fn data_type(&self) -> i32 {
        self.data_type
    }

    pub fn byte_length(&self) -> i32 {
        self.byte_length
    }

    pub fn offset(&self) -> i64 {
        self.offset
    }

    pub fn segment_ref(&self) -> i32 {
        self.segment_ref
    }

    pub fn set_segment_ref(&mut self, val: i32) {
        self.segment_ref = val;
    }

    pub fn set_address(&mut self, addr: Address) {
        self.address = Some(addr);
    }

    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    /// This is currently unused.
    pub fn frame_datum(&self) -> i32 {
        0
    }

    pub fn is_floating_point_special(&self) -> bool {
        FLOATINGPOINT_SPECIALNAMES.contains(&self.symbol_name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn create_test_address(offset: i64) -> Address {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn new_stores_fields() {
        let sym = OmfSymbol::new("_main", 1, 0x100, 2, 4);
        assert_eq!(sym.name(), "_main");
        assert_eq!(sym.type_index(), 1);
        assert_eq!(sym.offset(), 0x100);
        assert_eq!(sym.data_type(), 2);
        assert_eq!(sym.byte_length(), 4);
        assert_eq!(sym.segment_ref(), 0);
        assert_eq!(sym.address(), None);
        assert_eq!(sym.frame_datum(), 0);
    }

    #[test]
    fn segment_ref_is_mutable() {
        let mut sym = OmfSymbol::new("sym", 0, 0, 0, 0);
        assert_eq!(sym.segment_ref(), 0);
        sym.set_segment_ref(5);
        assert_eq!(sym.segment_ref(), 5);
    }

    #[test]
    fn address_can_be_set() {
        let mut sym = OmfSymbol::new("sym", 0, 0, 0, 0);
        let addr = create_test_address(0x1000);
        sym.set_address(addr.clone());
        assert_eq!(sym.address(), Some(&addr));
    }

    #[test]
    fn floating_point_special_names_detected() {
        let sym = OmfSymbol::new("FIWRQQ", 0, 0, 0, 0);
        assert!(sym.is_floating_point_special());

        let other = OmfSymbol::new("FJGRQQ", 0, 0, 0, 0);
        assert!(other.is_floating_point_special());
    }

    #[test]
    fn non_special_name_is_not_floating_point_special() {
        let sym = OmfSymbol::new("_main", 0, 0, 0, 0);
        assert!(!sym.is_floating_point_special());
    }
}
