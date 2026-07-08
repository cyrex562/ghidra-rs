use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::data_type::DataType;

/// An OMF value that is either 2 or 4 bytes.
///
/// Mirrors Ghidra's `Omf2or4` class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omf2or4 {
    length: i32,
    value: i64,
}

impl Omf2or4 {
    /// Creates a new [`Omf2or4`].
    ///
    /// # Arguments
    /// * `length` - 2 or 4
    /// * `value` - The 2 or 4 byte value
    pub fn new(length: i32, value: i64) -> Self {
        Self { length, value }
    }

    /// Returns the length of the value (2 or 4).
    pub fn length(&self) -> i32 {
        self.length
    }

    /// Returns the value.
    pub fn value(&self) -> i64 {
        self.value
    }
}

impl StructConverter for Omf2or4 {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        if self.length == 2 {
            Ok(Box::new(WordPlaceholderDataType))
        } else {
            Ok(Box::new(DwordPlaceholderDataType))
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

/// Minimal stand-in for `ghidra.program.model.data.DwordDataType.dataType`, used until
/// `DwordDataType` is ported.
struct DwordPlaceholderDataType;

impl DataType for DwordPlaceholderDataType {
    fn get_length(&self) -> i32 {
        4
    }

    fn get_name(&self) -> String {
        "dword".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_fields() {
        let omf = Omf2or4::new(2, 0x1234);
        assert_eq!(omf.length(), 2);
        assert_eq!(omf.value(), 0x1234);
    }

    #[test]
    fn new_stores_4_byte_value() {
        let omf = Omf2or4::new(4, 0x12345678);
        assert_eq!(omf.length(), 4);
        assert_eq!(omf.value(), 0x12345678);
    }

    #[test]
    fn to_data_type_returns_word_for_length_2() {
        let omf = Omf2or4::new(2, 0x1234);
        let dt = omf.to_data_type().unwrap();
        assert_eq!(dt.get_length(), 2);
        assert_eq!(dt.get_name(), "word");
    }

    #[test]
    fn to_data_type_returns_dword_for_length_4() {
        let omf = Omf2or4::new(4, 0x12345678);
        let dt = omf.to_data_type().unwrap();
        assert_eq!(dt.get_length(), 4);
        assert_eq!(dt.get_name(), "dword");
    }

    #[test]
    fn word_placeholder_has_correct_length() {
        let word_dt = WordPlaceholderDataType;
        assert_eq!(word_dt.get_length(), 2);
    }

    #[test]
    fn dword_placeholder_has_correct_length() {
        let dword_dt = DwordPlaceholderDataType;
        assert_eq!(dword_dt.get_length(), 4);
    }

    #[test]
    fn omf2or4_is_cloneable() {
        let omf1 = Omf2or4::new(2, 0x5678);
        let omf2 = omf1.clone();
        assert_eq!(omf1, omf2);
    }

    #[test]
    fn omf2or4_equality() {
        let omf1 = Omf2or4::new(2, 0x1234);
        let omf2 = Omf2or4::new(2, 0x1234);
        let omf3 = Omf2or4::new(4, 0x1234);
        assert_eq!(omf1, omf2);
        assert_ne!(omf1, omf3);
    }

    #[test]
    fn omf2or4_with_large_value() {
        let omf = Omf2or4::new(4, 0xDEADBEEF);
        assert_eq!(omf.value(), 0xDEADBEEF);
    }
}
