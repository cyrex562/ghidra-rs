use crate::app::util::bin::struct_converter::StructConverter;

/// Trait representing an OAT quick method header.
///
/// Port of `ghidra.file.formats.android.oat.quickmethod.OatQuickMethodHeader`.
pub trait OatQuickMethodHeader: StructConverter {
    /// Returns the code size.
    fn get_code_size(&self) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockMethodHeader {
        code_size: u32,
    }

    impl MockMethodHeader {
        fn new(code_size: u32) -> Self {
            Self { code_size }
        }
    }

    impl StructConverter for MockMethodHeader {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl OatQuickMethodHeader for MockMethodHeader {
        fn get_code_size(&self) -> u32 {
            self.code_size
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let mock = MockMethodHeader::new(1024);
        let boxed: Box<dyn OatQuickMethodHeader> = Box::new(mock);
        assert_eq!(boxed.get_code_size(), 1024);
    }

    #[test]
    fn get_code_size_returns_expected_value() {
        let mock = MockMethodHeader::new(512);
        assert_eq!(mock.get_code_size(), 512);
    }

    #[test]
    fn get_code_size_with_zero_value() {
        let mock = MockMethodHeader::new(0);
        assert_eq!(mock.get_code_size(), 0);
    }

    #[test]
    fn get_code_size_with_large_value() {
        let mock = MockMethodHeader::new(u32::MAX);
        assert_eq!(mock.get_code_size(), u32::MAX);
    }
}
