use crate::format::coff::relocation::coff_relocation_context::CoffRelocationContext;
use crate::format::seam_stubs::{CoffFileHeader, CoffRelocation};
use crate::program::model::address::Address;
use crate::program::model::reloc::relocation_result::RelocationResult;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// An interface used to perform COFF relocations. Classes should implement this trait to
/// provide relocations in a machine/processor specific way.
pub trait CoffRelocationHandler: ExtensionPoint {
    /// Checks to see whether or not an instance of this COFF relocation handler can handle
    /// relocating the COFF defined by the provided file header.
    ///
    /// # Arguments
    /// * `file_header` - The file header associated with the COFF to relocate.
    ///
    /// # Returns
    /// `true` if this relocation handler can do the relocation; otherwise, `false`.
    fn can_relocate(&self, file_header: &dyn CoffFileHeader) -> bool;

    /// Performs a relocation at the specified address.
    ///
    /// # Arguments
    /// * `address` - The address at which to perform the relocation.
    /// * `relocation` - The relocation information to use to perform the relocation.
    /// * `relocation_context` - Relocation context data
    ///
    /// # Returns
    /// Applied relocation result (conveys status and applied byte-length)
    ///
    /// # Errors
    /// * `MemoryAccessException` if there is a problem accessing memory during the relocation.
    /// * `RelocationError` if supported relocation encountered an error during processing.
    fn relocate(
        &self,
        address: &Address,
        relocation: &dyn CoffRelocation,
        relocation_context: &mut CoffRelocationContext,
    ) -> Result<RelocationResult, Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCoffFileHeader;
    impl CoffFileHeader for MockCoffFileHeader {
        fn get_magic(&self) -> i16 { 0x014c }
        fn get_section_count(&self) -> i16 { 0 }
        fn get_timestamp(&self) -> i32 { 0 }
        fn get_symbol_table_pointer(&self) -> i32 { 0 }
        fn get_symbol_table_entries(&self) -> i32 { 0 }
        fn get_optional_header_size(&self) -> i16 { 0 }
        fn get_flags(&self) -> i16 { 0 }
        fn get_target_id(&self) -> std::io::Result<i16> { Ok(0) }
        fn get_image_base(&self, _: bool) -> i64 { 0 }
        fn get_machine_name(&self) -> String { String::new() }
        fn get_machine(&self) -> i16 { 0x014c }
        fn parse_section_headers(&self) -> std::io::Result<()> { Ok(()) }
        fn parse(&self, _: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> { Ok(()) }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::CoffSectionHeader>> { vec![] }
        fn get_symbols(&self) -> Vec<Box<dyn crate::format::seam_stubs::CoffSymbol>> { vec![] }
        fn get_symbol_at_index(&self, _: i64) -> Box<dyn crate::format::seam_stubs::CoffSymbol> {
            unimplemented!()
        }
        fn sizeof(&self) -> i32 { 0 }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::AoutHeader> {
            unimplemented!()
        }
        fn is_valid(&self) -> std::io::Result<bool> { Ok(true) }
        fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "unimplemented"))
        }
    }

    struct MockRelocationHandler;

    impl ExtensionPoint for MockRelocationHandler {}

    impl CoffRelocationHandler for MockRelocationHandler {
        fn can_relocate(&self, _file_header: &dyn CoffFileHeader) -> bool {
            true
        }

        fn relocate(
            &self,
            _address: &Address,
            _relocation: &dyn CoffRelocation,
            _relocation_context: &mut CoffRelocationContext,
        ) -> Result<RelocationResult, Box<dyn std::error::Error + Send + Sync>> {
            Ok(RelocationResult::UNSUPPORTED)
        }
    }

    #[test]
    fn can_implement_coff_relocation_handler() {
        let handler = MockRelocationHandler;
        let file_header = MockCoffFileHeader;
        assert!(handler.can_relocate(&file_header));
    }

    #[test]
    fn handler_is_extension_point() {
        let handler: Box<dyn ExtensionPoint> = Box::new(MockRelocationHandler);
        drop(handler);
    }
}
