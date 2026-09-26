use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::data_type::DataType;

/// An OMF index that is either 1 or 2 bytes.
///
/// Mirrors Ghidra's `OmfIndex` class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfIndex {
    length: u32,
    value: u32,
}

impl OmfIndex {
    /// Creates a new [`OmfIndex`].
    ///
    /// # Arguments
    /// * `length` - 1 or 2
    /// * `value` - The 1 or 2 byte index value
    pub fn new(length: u32, value: u32) -> Self {
        Self { length, value }
    }

    /// Returns the length of the index (1 or 2).
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Returns the index value.
    pub fn value(&self) -> u32 {
        self.value
    }
}

impl StructConverter for OmfIndex {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        if self.length == 2 {
            Ok(Box::new(WordPlaceholderDataType))
        } else {
            Ok(Box::new(BytePlaceholderDataType))
        }
    }
}

/// Minimal stand-in for `ghidra.program.model.data.WordDataType.dataType`, used until
/// `WordDataType` is ported.
struct WordPlaceholderDataType;

impl DataType for WordPlaceholderDataType {
    fn get_length(&self) -> i32 {
        2
    }

    fn get_name(&self) -> String {
        "word".to_string()
    }
}

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used until
/// `ByteDataType` is ported.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }

    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let idx = OmfIndex::new(1, 0x42);
        assert_eq!(idx.length(), 1);
        assert_eq!(idx.value(), 0x42);
    }

    #[test]
    fn new_stores_word_index() {
        let idx = OmfIndex::new(2, 0x1234);
        assert_eq!(idx.length(), 2);
        assert_eq!(idx.value(), 0x1234);
    }

    #[test]
    fn to_data_type_returns_byte_for_length_one() {
        let idx = OmfIndex::new(1, 0x50);
        let dt = idx.to_data_type().unwrap();
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_name(), "byte");
    }

    #[test]
    fn to_data_type_returns_word_for_length_two() {
        let idx = OmfIndex::new(2, 0x100);
        let dt = idx.to_data_type().unwrap();
        assert_eq!(dt.get_length(), 2);
        assert_eq!(dt.get_name(), "word");
    }

    #[test]
    fn byte_placeholder_has_correct_length() {
        let byte_dt = BytePlaceholderDataType;
        assert_eq!(byte_dt.get_length(), 1);
    }

    #[test]
    fn word_placeholder_has_correct_length() {
        let word_dt = WordPlaceholderDataType;
        assert_eq!(word_dt.get_length(), 2);
    }

    #[test]
    fn omf_index_is_cloneable() {
        let idx1 = OmfIndex::new(2, 0x99);
        let idx2 = idx1.clone();
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn omf_index_equality() {
        let idx1 = OmfIndex::new(1, 0x50);
        let idx2 = OmfIndex::new(1, 0x50);
        let idx3 = OmfIndex::new(2, 0x50);
        assert_eq!(idx1, idx2);
        assert_ne!(idx1, idx3);
    }
}
