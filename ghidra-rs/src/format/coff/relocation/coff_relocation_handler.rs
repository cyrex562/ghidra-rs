use crate::format::coff::coff_file_header::CoffFileHeader;
use crate::format::coff::relocation::coff_relocation_context::CoffRelocationContext;
use crate::format::seam_stubs::CoffRelocation;
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
    fn can_relocate(&self, file_header: &CoffFileHeader) -> bool;

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

    struct VecProvider(Vec<u8>);

    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for VecProvider {
        fn length(&mut self) -> std::io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }

    /// Builds a minimal valid (0 sections, 0 symbols, no optional header) little-endian COFF
    /// file header for tests that only need a `CoffFileHeader` to exist.
    fn mock_coff_file_header() -> CoffFileHeader {
        let mut data = Vec::new();
        data.extend_from_slice(&0x014ci16.to_le_bytes()); // f_magic: IMAGE_FILE_MACHINE_I386
        data.extend_from_slice(&0i16.to_le_bytes()); // f_nscns
        data.extend_from_slice(&0i32.to_le_bytes()); // f_timdat
        data.extend_from_slice(&0i32.to_le_bytes()); // f_symptr
        data.extend_from_slice(&0i32.to_le_bytes()); // f_nsyms
        data.extend_from_slice(&0i16.to_le_bytes()); // f_opthdr
        data.extend_from_slice(&0i16.to_le_bytes()); // f_flags
        // isValid()'s MIN_BYTE_LENGTH is 22 (see CoffFileHeader's own tests for details).
        data.resize(22, 0);
        let provider = std::rc::Rc::new(std::cell::RefCell::new(VecProvider(data)));
        CoffFileHeader::new(provider).expect("mock header should parse")
    }

    struct MockRelocationHandler;

    impl ExtensionPoint for MockRelocationHandler {}

    impl CoffRelocationHandler for MockRelocationHandler {
        fn can_relocate(&self, _file_header: &CoffFileHeader) -> bool {
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
        let file_header = mock_coff_file_header();
        assert!(handler.can_relocate(&file_header));
    }

    #[test]
    fn handler_is_extension_point() {
        let handler: Box<dyn ExtensionPoint> = Box::new(MockRelocationHandler);
        drop(handler);
    }
}
