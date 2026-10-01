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
    reader: &mut BinaryReader,
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


    #[test]
    fn returns_none_when_optional_header_size_is_zero() {
        let mut reader = BinaryReader::from_bytes(Vec::new(), true);
        let result = create_aout_header(&mut reader, 0, 0x0000).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn errors_for_r3000_magic_with_nonzero_optional_header() {
        let mut reader = BinaryReader::from_bytes(Vec::new(), true);
        let result = create_aout_header(&mut reader, 28, IMAGE_FILE_MACHINE_R3000 as i16);
        assert!(result.is_err());
    }

    #[test]
    fn errors_for_other_magic_with_nonzero_optional_header() {
        let mut reader = BinaryReader::from_bytes(Vec::new(), true);
        let result = create_aout_header(&mut reader, 28, 0x014c /* IMAGE_FILE_MACHINE_I386 */);
        assert!(result.is_err());
    }
}
