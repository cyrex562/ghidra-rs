use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::mem::Memory;

/// Provides a preview of data at a specific address.
///
/// Port of `ghidra.app.plugin.core.datapreview.Preview`.
///
/// This trait allows plugins and utilities to generate human-readable previews of program data
/// at specific memory addresses, using a particular data type interpretation.
pub trait Preview: Send + Sync {
    /// Returns the name of this preview provider.
    fn get_name(&self) -> String;

    /// Generates a preview string for the data at the given address in the provided memory.
    ///
    /// # Arguments
    /// * `memory` - The memory to read from
    /// * `addr` - The address to generate a preview for
    ///
    /// # Returns
    /// A string representation of the data, or an error message if preview generation fails
    fn get_preview(&self, memory: &dyn Memory, addr: &Address) -> String;

    /// Returns the data type used by this preview provider to interpret data.
    fn get_data_type(&self) -> &dyn DataType;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    struct MockMemory {
        big_endian: bool,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_byte(&self, _addr: &Address) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0x42)
        }

        fn get_bytes(&self, _addr: &Address, dest: &mut [u8]) -> usize {
            if !dest.is_empty() {
                dest[0] = 0x42;
            }
            1
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }
    }

    struct MockDataType;

    impl DataType for MockDataType {}

    struct TestPreview {
        name: String,
    }

    impl Preview for TestPreview {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_preview(&self, _memory: &dyn Memory, _addr: &Address) -> String {
            format!("{}: preview data", self.name)
        }

        fn get_data_type(&self) -> &dyn DataType {
            &MockDataType
        }
    }

    #[test]
    fn test_get_name_returns_configured_name() {
        let preview = TestPreview { name: "Hex".to_string() };
        assert_eq!(preview.get_name(), "Hex");
    }

    #[test]
    fn test_get_name_with_empty_string() {
        let preview = TestPreview { name: String::new() };
        assert_eq!(preview.get_name(), "");
    }

    #[test]
    fn test_get_name_with_multiword_string() {
        let preview = TestPreview { name: "ASCII Preview".to_string() };
        assert_eq!(preview.get_name(), "ASCII Preview");
    }

    #[test]
    fn test_get_preview_generates_preview_string() {
        let preview = TestPreview { name: "Test".to_string() };
        let mock_memory = MockMemory { big_endian: false };
        let addr = create_test_address();
        let result = preview.get_preview(&mock_memory, &addr);
        assert_eq!(result, "Test: preview data");
    }

    #[test]
    fn test_get_preview_with_different_name() {
        let preview = TestPreview { name: "Binary".to_string() };
        let mock_memory = MockMemory { big_endian: true };
        let addr = create_test_address();
        let result = preview.get_preview(&mock_memory, &addr);
        assert_eq!(result, "Binary: preview data");
    }

    #[test]
    fn test_get_data_type_returns_data_type() {
        let preview = TestPreview { name: "Test".to_string() };
        let data_type = preview.get_data_type();
        assert_eq!(data_type.type_id(), TypeId::of::<MockDataType>());
    }

    fn create_test_address() -> Address {
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, 0x1000)
    }
}
