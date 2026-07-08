use crate::app::util::bin::struct_converter::StructConverter;

/// Represents a DMG (Apple Disk Image) header.
///
/// Port of `ghidra.file.formats.ios.dmg.DmgHeader`.
pub trait DmgHeader: StructConverter {
    /// Returns the signature bytes of the DMG header.
    fn get_signature(&self) -> Vec<u8>;

    /// Returns the version of the DMG header.
    fn get_version(&self) -> i32;

    /// Returns the size of the data in bytes.
    fn get_data_size(&self) -> i64;

    /// Returns the offset to the data in the file.
    fn get_data_offset(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockDmgHeader {
        signature: Vec<u8>,
        version: i32,
        data_size: i64,
        data_offset: i64,
    }

    impl MockDmgHeader {
        fn new(signature: Vec<u8>, version: i32, data_size: i64, data_offset: i64) -> Self {
            Self {
                signature,
                version,
                data_size,
                data_offset,
            }
        }
    }

    impl StructConverter for MockDmgHeader {
        fn to_data_type(
            &self,
        ) -> Result<
            Box<dyn crate::program::model::data::data_type::DataType>,
            crate::app::util::bin::struct_converter::ToDataTypeError,
        > {
            Ok(Box::new(MockDataType))
        }
    }

    impl DmgHeader for MockDmgHeader {
        fn get_signature(&self) -> Vec<u8> {
            self.signature.clone()
        }

        fn get_version(&self) -> i32 {
            self.version
        }

        fn get_data_size(&self) -> i64 {
            self.data_size
        }

        fn get_data_offset(&self) -> i64 {
            self.data_offset
        }
    }

    #[test]
    fn trait_can_be_implemented() {
        let _header: &dyn DmgHeader = &MockDmgHeader::new(vec![1, 2, 3, 4], 1, 1024, 512);
    }

    #[test]
    fn trait_is_object_safe() {
        fn _use_trait_object(_: &dyn DmgHeader) {}
        _use_trait_object(&MockDmgHeader::new(vec![1, 2, 3, 4], 1, 1024, 512));
    }

    #[test]
    fn get_signature_returns_correct_value() {
        let header = MockDmgHeader::new(vec![1, 2, 3, 4], 1, 1024, 512);
        assert_eq!(header.get_signature(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn get_version_returns_correct_value() {
        let header = MockDmgHeader::new(vec![1, 2, 3, 4], 42, 1024, 512);
        assert_eq!(header.get_version(), 42);
    }

    #[test]
    fn get_data_size_returns_correct_value() {
        let header = MockDmgHeader::new(vec![1, 2, 3, 4], 1, 2048, 512);
        assert_eq!(header.get_data_size(), 2048);
    }

    #[test]
    fn get_data_offset_returns_correct_value() {
        let header = MockDmgHeader::new(vec![1, 2, 3, 4], 1, 1024, 768);
        assert_eq!(header.get_data_offset(), 768);
    }

    #[test]
    fn multiple_headers_can_coexist() {
        let header1 = MockDmgHeader::new(vec![1, 2], 1, 100, 50);
        let header2 = MockDmgHeader::new(vec![3, 4, 5], 2, 200, 100);

        assert_eq!(header1.get_version(), 1);
        assert_eq!(header2.get_version(), 2);
        assert_eq!(header1.get_data_size(), 100);
        assert_eq!(header2.get_data_size(), 200);
    }
}
