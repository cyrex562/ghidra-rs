use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::dword_data_type::DWordDataType;
use crate::program::model::data::word_data_type::WordDataType;

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
            Ok(Box::new(WordDataType::new(None)))
        } else {
            Ok(Box::new(DWordDataType::new(None)))
        }
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
        let word_dt = WordDataType::new(None);
        assert_eq!(word_dt.get_length(), 2);
    }

    #[test]
    fn dword_placeholder_has_correct_length() {
        let dword_dt = DWordDataType::new(None);
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
