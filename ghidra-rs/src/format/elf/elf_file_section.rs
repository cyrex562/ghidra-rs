use crate::app::util::bin::struct_converter::StructConverter;

/// Represents a section within an ELF file with location and size information.
///
/// Port of `ghidra.app.util.bin.format.elf.ElfFileSection`.
pub trait ElfFileSection: StructConverter {
    /// Preferred memory address offset where data should be loaded.
    ///
    /// The returned offset will already have the prelink adjustment applied,
    /// although will not reflect any change in the image base.
    ///
    /// # Returns
    /// Default memory address offset where data should be loaded
    fn get_address_offset(&self) -> i64;

    /// Offset within file where section bytes are specified.
    ///
    /// # Returns
    /// Offset within file where section bytes are specified
    fn get_file_offset(&self) -> i64;

    /// Length of file section in bytes.
    ///
    /// # Returns
    /// Length of file section in bytes
    fn get_length(&self) -> i64;

    /// Size of each structured entry in bytes.
    ///
    /// # Returns
    /// Entry size or -1 if variable
    fn get_entry_size(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;

    impl crate::program::model::data::data_type::DataType for MockDataType {}

    struct MockElfFileSection {
        address_offset: i64,
        file_offset: i64,
        length: i64,
        entry_size: i32,
    }

    impl MockElfFileSection {
        fn new(address_offset: i64, file_offset: i64, length: i64, entry_size: i32) -> Self {
            Self {
                address_offset,
                file_offset,
                length,
                entry_size,
            }
        }
    }

    impl StructConverter for MockElfFileSection {
        fn to_data_type(
            &self,
        ) -> Result<Box<dyn crate::program::model::data::data_type::DataType>, crate::app::util::bin::struct_converter::ToDataTypeError> {
            Ok(Box::new(MockDataType))
        }
    }

    impl ElfFileSection for MockElfFileSection {
        fn get_address_offset(&self) -> i64 {
            self.address_offset
        }

        fn get_file_offset(&self) -> i64 {
            self.file_offset
        }

        fn get_length(&self) -> i64 {
            self.length
        }

        fn get_entry_size(&self) -> i32 {
            self.entry_size
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable() {
        let section: Box<dyn ElfFileSection> =
            Box::new(MockElfFileSection::new(0x1000, 0x200, 0x400, 8));
        assert_eq!(section.get_address_offset(), 0x1000);
        assert_eq!(section.get_file_offset(), 0x200);
        assert_eq!(section.get_length(), 0x400);
        assert_eq!(section.get_entry_size(), 8);
    }

    #[test]
    fn get_address_offset_returns_prelink_adjusted_offset() {
        let section = MockElfFileSection::new(0x5000, 0x100, 0x200, 16);
        assert_eq!(section.get_address_offset(), 0x5000);
    }

    #[test]
    fn get_file_offset_returns_correct_position() {
        let section = MockElfFileSection::new(0x1000, 0x500, 0x300, 4);
        assert_eq!(section.get_file_offset(), 0x500);
    }

    #[test]
    fn get_length_returns_section_size() {
        let section = MockElfFileSection::new(0x2000, 0x300, 0x600, 8);
        assert_eq!(section.get_length(), 0x600);
    }

    #[test]
    fn get_entry_size_returns_fixed_size() {
        let section = MockElfFileSection::new(0x1000, 0x200, 0x400, 32);
        assert_eq!(section.get_entry_size(), 32);
    }

    #[test]
    fn get_entry_size_returns_variable_marker() {
        let section = MockElfFileSection::new(0x1000, 0x200, 0x400, -1);
        assert_eq!(section.get_entry_size(), -1);
    }

    #[test]
    fn zero_entry_size_is_valid() {
        let section = MockElfFileSection::new(0x1000, 0x200, 0x400, 0);
        assert_eq!(section.get_entry_size(), 0);
    }
}
