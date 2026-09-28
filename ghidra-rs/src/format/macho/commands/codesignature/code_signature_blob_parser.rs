use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::CodeSignatureGenericBlob;
use std::io;

use super::code_signature_constants::*;

/// Parses Code Signature blobs
///
/// This module provides functionality to parse Code Signature blob structures from binary data.
/// Based on the magic value, it determines the blob type and constructs the appropriate instance.
///
/// See <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>
pub fn parse(reader: &mut BinaryReader) -> io::Result<Box<dyn CodeSignatureGenericBlob>> {
    let magic = reader.peek_next_int()? as u32;
    match magic {
        CSMAGIC_EMBEDDED_SIGNATURE => {
            // When CodeSignatureSuperBlob is ported, return Box::new(CodeSignatureSuperBlob::new(reader)?)
            // For now, we return a generic blob placeholder
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CodeSignatureSuperBlob not yet ported",
            ))
        }
        CSMAGIC_CODEDIRECTORY => {
            // When CodeSignatureCodeDirectory is ported, return Box::new(CodeSignatureCodeDirectory::new(reader)?)
            // For now, we return a generic blob placeholder
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CodeSignatureCodeDirectory not yet ported",
            ))
        }
        _ => {
            // Default: return a generic blob placeholder
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "CodeSignatureGenericBlob not yet ported",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A big-endian reader (code signatures are big-endian) over `magic` plus padding.
    fn reader_with_magic(magic: u32) -> BinaryReader {
        let mut bytes = magic.to_be_bytes().to_vec();
        bytes.resize(1024, 0);
        BinaryReader::from_bytes(bytes, false)
    }

    #[test]
    fn test_parse_with_embedded_signature_magic() {
        let mut reader = reader_with_magic(CSMAGIC_EMBEDDED_SIGNATURE);
        let result = parse(&mut reader);
        // Will return Unsupported error until CodeSignatureSuperBlob is ported
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_codedirectory_magic() {
        let mut reader = reader_with_magic(CSMAGIC_CODEDIRECTORY);
        let result = parse(&mut reader);
        // Will return Unsupported error until CodeSignatureCodeDirectory is ported
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_unknown_magic() {
        let mut reader = reader_with_magic(0x12345678i32 as u32);
        let result = parse(&mut reader);
        // Will return Unsupported error until CodeSignatureGenericBlob is ported
        assert!(result.is_err());
    }

    #[test]
    fn test_magic_constants_used() {
        assert_eq!(CSMAGIC_EMBEDDED_SIGNATURE, 0xfade0cc0);
        assert_eq!(CSMAGIC_CODEDIRECTORY, 0xfade0c02);
    }
}
