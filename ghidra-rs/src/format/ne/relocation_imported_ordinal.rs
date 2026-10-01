use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

/// A relocation entry for an imported ordinal from an imported module.
///
/// Mirrors `RelocationImportedOrdinal` from the original Ghidra Java source.
/// Stores an index into the module reference table and the ordinal number
/// of a procedure in the imported module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationImportedOrdinal {
    index: i16,
    ordinal: i16,
}

impl RelocationImportedOrdinal {
    /// Constructs a new relocation imported ordinal by reading from the given binary reader.
    ///
    /// Reads two i16 values: the module index and the ordinal number.
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader) -> io::Result<Self> {
        let index = reader.read_next_short()?;
        let ordinal = reader.read_next_short()?;

        Ok(RelocationImportedOrdinal { index, ordinal })
    }

    /// Returns the index into the module reference table for the imported module.
    pub fn index(&self) -> i16 {
        self.index
    }

    /// Returns the ordinal number of the procedure in the imported module.
    pub fn ordinal(&self) -> i16 {
        self.ordinal
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn reads_simple_relocation() {
        let mut data = Vec::new();
        data.extend_from_slice(&(1i16).to_le_bytes());
        data.extend_from_slice(&(42i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationImportedOrdinal::new(&mut r).unwrap();

        assert_eq!(rel.index(), 1);
        assert_eq!(rel.ordinal(), 42);
    }

    #[test]
    fn reads_zero_indices() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0i16).to_le_bytes());
        data.extend_from_slice(&(0i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationImportedOrdinal::new(&mut r).unwrap();

        assert_eq!(rel.index(), 0);
        assert_eq!(rel.ordinal(), 0);
    }

    #[test]
    fn reads_negative_indices() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i16).to_le_bytes());
        data.extend_from_slice(&(-100i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        let rel = RelocationImportedOrdinal::new(&mut r).unwrap();

        assert_eq!(rel.index(), -1);
        assert_eq!(rel.ordinal(), -100);
    }

    #[test]
    fn updates_reader_position() {
        let mut data = Vec::new();
        data.extend_from_slice(&(5i16).to_le_bytes());
        data.extend_from_slice(&(10i16).to_le_bytes());
        data.push(99);

        let mut r = BinaryReader::from_bytes(data, true);
        let _ = RelocationImportedOrdinal::new(&mut r).unwrap();
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn reads_at_different_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&(7i16).to_le_bytes());
        data.extend_from_slice(&(77i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data, true);
        r.set_pointer_index(3);
        let rel = RelocationImportedOrdinal::new(&mut r).unwrap();

        assert_eq!(rel.index(), 7);
        assert_eq!(rel.ordinal(), 77);
    }

    #[test]
    fn copy_semantics() {
        let mut data = Vec::new();
        data.extend_from_slice(&(3i16).to_le_bytes());
        data.extend_from_slice(&(9i16).to_le_bytes());

        let mut r = BinaryReader::from_bytes(data.clone(), true);
        let rel1 = RelocationImportedOrdinal::new(&mut r).unwrap();
        let rel2 = rel1;

        assert_eq!(rel1, rel2);
        assert_eq!(rel1.index(), rel2.index());
        assert_eq!(rel1.ordinal(), rel2.ordinal());
    }

    #[test]
    fn equality_between_different_constructions() {
        let mut data1 = Vec::new();
        data1.extend_from_slice(&(15i16).to_le_bytes());
        data1.extend_from_slice(&(20i16).to_le_bytes());

        let mut r1 = BinaryReader::from_bytes(data1, true);
        let rel1 = RelocationImportedOrdinal::new(&mut r1).unwrap();

        let mut data2 = Vec::new();
        data2.extend_from_slice(&(15i16).to_le_bytes());
        data2.extend_from_slice(&(20i16).to_le_bytes());

        let mut r2 = BinaryReader::from_bytes(data2, true);
        let rel2 = RelocationImportedOrdinal::new(&mut r2).unwrap();

        assert_eq!(rel1, rel2);
    }
}
