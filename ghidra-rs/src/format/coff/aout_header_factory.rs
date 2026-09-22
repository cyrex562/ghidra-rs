use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::AoutHeader;

use super::coff_machine_type::IMAGE_FILE_MACHINE_R3000;

/// Creates an appropriate AoutHeader implementation based on the COFF file header's machine type.
///
/// Returns `None` if `optional_header_size` is 0, indicating no optional header is present.
/// For R3000 (MIPS) machines, this would create an AoutHeaderMIPS instance; otherwise, creates a
/// regular AoutHeader instance.
///
/// Port of `AoutHeaderFactory.createAoutHeader(BinaryReader, CoffFileHeader)`. Takes the two
/// `CoffFileHeader` accessors the Java method actually reads (`getOptionalHeaderSize()`,
/// `getMagic()`) directly rather than a `&CoffFileHeader`:
/// [`CoffFileHeader`](crate::format::coff::coff_file_header::CoffFileHeader) owns the very
/// `reader` passed in here, so a reference to the whole header would alias the mutable reader
/// borrow when [`CoffFileHeader::parse`](crate::format::coff::coff_file_header::CoffFileHeader::parse)
/// calls this factory.
///
/// Note: Since AoutHeaderMIPS and AoutHeader are not yet fully ported, this function returns
/// trait objects. When these types are ported, this may be refactored to return concrete types.
pub fn create_aout_header(
    reader: &mut dyn BinaryReader,
    optional_header_size: i16,
    magic: i16,
) -> io::Result<Option<Box<dyn AoutHeader>>> {
    if optional_header_size == 0 {
        return Ok(None);
    }

    let machine = magic as u16;
    if machine == IMAGE_FILE_MACHINE_R3000 {
        // Would create AoutHeaderMIPS(reader) in the real implementation
        let _ = reader;
        Err(io::Error::new(
            io::ErrorKind::Other,
            "AoutHeaderMIPS not yet ported",
        ))
    } else {
        // Would create AoutHeader(reader) in the real implementation
        Err(io::Error::new(
            io::ErrorKind::Other,
            "AoutHeader not yet ported",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new() -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(Vec::new()))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    #[test]
    fn returns_none_when_optional_header_size_is_zero() {
        let mut reader = MockReader::new();
        let result = create_aout_header(&mut reader, 0, 0x0000).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn errors_for_r3000_magic_with_nonzero_optional_header() {
        let mut reader = MockReader::new();
        let result = create_aout_header(&mut reader, 28, IMAGE_FILE_MACHINE_R3000 as i16);
        assert!(result.is_err());
    }

    #[test]
    fn errors_for_other_magic_with_nonzero_optional_header() {
        let mut reader = MockReader::new();
        let result = create_aout_header(&mut reader, 28, 0x014c /* IMAGE_FILE_MACHINE_I386 */);
        assert!(result.is_err());
    }
}
