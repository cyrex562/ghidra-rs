use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the Object Module Format (OMF) alignment symbol.
///
/// Mirrors the `OMFAlignSym` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfAlignSym {
    /// The alignment padding length.
    length: i16,
    /// The alignment padding bytes.
    pad: Vec<u8>,
}

impl OmfAlignSym {
    /// Creates a new `OmfAlignSym` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `index` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &BinaryReader, index: u64) -> io::Result<Self> {
        let length = reader.read_short(index)? as i16;
        let pad = reader.read_byte_array(index + 2, length as usize)?;

        Ok(OmfAlignSym { length, pad })
    }

    /// Returns the alignment padding bytes.
    pub fn pad(&self) -> &[u8] {
        &self.pad
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x03, 0x00, // length = 3 (little endian)
            0xAA, 0xBB, 0xCC, // pad = [0xAA, 0xBB, 0xCC]
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 3);
        assert_eq!(align_sym.pad(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x02, // length = 2 (big endian)
            0x11, 0x22, // pad = [0x11, 0x22]
        ];

        let reader = BinaryReader::from_bytes(data, false);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 2);
        assert_eq!(align_sym.pad(), &[0x11, 0x22]);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x02, 0x00,             // length = 2 at offset 4
            0x55, 0x66,             // pad at offset 6
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let align_sym = OmfAlignSym::new(&reader, 4).expect("failed to read");

        assert_eq!(align_sym.length, 2);
        assert_eq!(align_sym.pad(), &[0x55, 0x66]);
    }

    #[test]
    fn zero_length_padding() {
        let data = vec![
            0x00, 0x00, // length = 0
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let align_sym = OmfAlignSym::new(&reader, 0).expect("failed to read");

        assert_eq!(align_sym.length, 0);
        assert!(align_sym.pad().is_empty());
    }

    #[test]
    fn clone_equality() {
        let data = vec![
            0x02, 0x00,
            0xDE, 0xAD,
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let align_sym1 = OmfAlignSym::new(&reader, 0).expect("failed to read");
        let align_sym2 = align_sym1.clone();

        assert_eq!(align_sym1, align_sym2);
    }
}
