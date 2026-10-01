use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents an Object Module Format (OMF) directory entry.
///
/// Mirrors the `OMFDirEntry` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OmfDirEntry {
    /// Subsection type (sst...).
    subsection: i16,
    /// Module index.
    imod: i16,
    /// Large file offset of subsection.
    lfo: i32,
    /// Number of bytes in subsection.
    cb: i32,
}

impl OmfDirEntry {
    /// The size of an OMF directory entry structure in bytes.
    pub const SIZE: usize = 12;

    /// Creates a new `OmfDirEntry` by reading from the given binary reader at the
    /// specified index.
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
        let subsection = reader.read_short(index)?;
        let imod = reader.read_short(index + 2)?;
        let lfo = reader.read_int(index + 4)?;
        let cb = reader.read_int(index + 8)?;

        Ok(OmfDirEntry {
            subsection,
            imod,
            lfo,
            cb,
        })
    }

    /// Returns the subsection type.
    pub fn subsection_type(&self) -> i16 {
        self.subsection
    }

    /// Returns the module index.
    pub fn module_index(&self) -> i16 {
        self.imod
    }

    /// Returns the large file offset of the subsection.
    pub fn large_file_offset(&self) -> i32 {
        self.lfo
    }

    /// Returns the number of bytes in the subsection.
    pub fn number_of_bytes(&self) -> i32 {
        self.cb
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x02, 0x00,             // subsection = 2 (little endian)
            0x05, 0x00,             // imod = 5 (little endian)
            0x00, 0x10, 0x00, 0x00, // lfo = 0x1000 (little endian)
            0x20, 0x03, 0x00, 0x00, // cb = 0x320 (little endian)
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 2);
        assert_eq!(entry.module_index(), 5);
        assert_eq!(entry.large_file_offset(), 0x1000);
        assert_eq!(entry.number_of_bytes(), 0x320);
    }

    #[test]
    fn read_structure_big_endian() {
        let data = vec![
            0x00, 0x03,             // subsection = 3 (big endian)
            0x00, 0x07,             // imod = 7 (big endian)
            0x00, 0x00, 0x20, 0x00, // lfo = 0x2000 (big endian)
            0x00, 0x00, 0x04, 0x00, // cb = 0x400 (big endian)
        ];

        let reader = BinaryReader::from_bytes(data, false);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 3);
        assert_eq!(entry.module_index(), 7);
        assert_eq!(entry.large_file_offset(), 0x2000);
        assert_eq!(entry.number_of_bytes(), 0x400);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x01, 0x00,             // subsection = 1 at offset 4
            0x02, 0x00,             // imod = 2
            0x00, 0x08, 0x00, 0x00, // lfo = 0x800
            0x10, 0x01, 0x00, 0x00, // cb = 0x110
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry = OmfDirEntry::new(&reader, 4).expect("failed to read");

        assert_eq!(entry.subsection_type(), 1);
        assert_eq!(entry.module_index(), 2);
        assert_eq!(entry.large_file_offset(), 0x800);
        assert_eq!(entry.number_of_bytes(), 0x110);
    }

    #[test]
    fn zero_values() {
        let data = vec![
            0x00, 0x00, // subsection = 0
            0x00, 0x00, // imod = 0
            0x00, 0x00, 0x00, 0x00, // lfo = 0
            0x00, 0x00, 0x00, 0x00, // cb = 0
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), 0);
        assert_eq!(entry.module_index(), 0);
        assert_eq!(entry.large_file_offset(), 0);
        assert_eq!(entry.number_of_bytes(), 0);
    }

    #[test]
    fn max_values() {
        let data = vec![
            0xFF, 0x7F,             // subsection = 32767 (max i16)
            0xFF, 0x7F,             // imod = 32767
            0xFF, 0xFF, 0xFF, 0x7F, // lfo = 0x7FFFFFFF (max i32, little endian)
            0xFF, 0xFF, 0xFF, 0x7F, // cb = 0x7FFFFFFF (max i32, little endian)
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), i16::MAX);
        assert_eq!(entry.module_index(), i16::MAX);
        assert_eq!(entry.large_file_offset(), i32::MAX);
        assert_eq!(entry.number_of_bytes(), i32::MAX);
    }

    #[test]
    fn negative_values() {
        let data = vec![
            0xFF, 0xFF,             // subsection = -1 (little endian)
            0xFE, 0xFF,             // imod = -2 (little endian)
            0xFF, 0xFF, 0xFF, 0xFF, // lfo = -1 (little endian)
            0x00, 0xFF, 0xFF, 0xFF, // cb = -256 (little endian)
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry = OmfDirEntry::new(&reader, 0).expect("failed to read");

        assert_eq!(entry.subsection_type(), -1);
        assert_eq!(entry.module_index(), -2);
        assert_eq!(entry.large_file_offset(), -1);
        assert_eq!(entry.number_of_bytes(), -256);
    }

    #[test]
    fn clone_equality() {
        let data = vec![
            0x04, 0x00, // subsection = 4
            0x06, 0x00, // imod = 6
            0x00, 0x20, 0x00, 0x00, // lfo = 0x2000
            0x00, 0x02, 0x00, 0x00, // cb = 0x200
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let entry1 = OmfDirEntry::new(&reader, 0).expect("failed to read");
        let entry2 = entry1.clone();

        assert_eq!(entry1, entry2);
    }

    #[test]
    fn size_constant() {
        assert_eq!(OmfDirEntry::SIZE, 12);
    }
}
