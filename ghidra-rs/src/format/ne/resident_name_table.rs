use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_ordinal_set::LengthStringOrdinalSet;

/// Represents the resident name table in a new-executable (NE) format file.
///
/// The resident name table stores exported names and their ordinals. This struct
/// provides access to those names.
///
/// Mirrors `ResidentNameTable` from the original Ghidra Java source.
pub struct ResidentNameTable {
    names: Vec<LengthStringOrdinalSet>,
}

impl ResidentNameTable {
    /// Constructs a new resident name table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The byte offset where the resident name table begins
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader, index: u64) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut names = Vec::new();

        loop {
            let lsos = LengthStringOrdinalSet::new(reader)?;
            if lsos.length_string_set().length() == 0 {
                break;
            }
            names.push(lsos);
        }

        reader.set_pointer_index(old_index);

        Ok(ResidentNameTable { names })
    }

    /// Returns the array of names defined in the resident name table.
    pub fn names(&self) -> &[LengthStringOrdinalSet] {
        &self.names
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn creates_empty_table() {
        let data = vec![0];
        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(table.names().len(), 0);
    }

    #[test]
    fn reads_single_named_entry() {
        let mut data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        data.extend_from_slice(&42i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("hello"));
        assert_eq!(table.names()[0].ordinal(), Some(42));
    }

    #[test]
    fn reads_multiple_entries() {
        let mut data = Vec::new();
        data.push(4);
        data.extend_from_slice(b"foo1");
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo2");
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo3");
        data.extend_from_slice(&3i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(table.names().len(), 3);
        assert_eq!(table.names()[0].length_string_set().name(), Some("foo1"));
        assert_eq!(table.names()[0].ordinal(), Some(1));
        assert_eq!(table.names()[1].length_string_set().name(), Some("foo2"));
        assert_eq!(table.names()[1].ordinal(), Some(2));
        assert_eq!(table.names()[2].length_string_set().name(), Some("foo3"));
        assert_eq!(table.names()[2].ordinal(), Some(3));
    }

    #[test]
    fn restores_reader_position() {
        let mut data = vec![0, 0xFF, 0xFF];
        let mut reader = BinaryReader::from_bytes(data, true);
        reader.set_pointer_index(2);
        ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(reader.get_pointer_index(), 2);
    }

    #[test]
    fn handles_table_starting_at_nonzero_offset() {
        let mut data = vec![0xFF, 0xFF];
        data.push(3);
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&5i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 2).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("abc"));
        assert_eq!(table.names()[0].ordinal(), Some(5));
    }

    #[test]
    fn reads_zero_ordinal_entry() {
        let mut data = vec![4, b'z', b'e', b'r', b'o'];
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].ordinal(), Some(0));
    }

    #[test]
    fn reads_negative_ordinal() {
        let mut data = vec![2, b'n', b'g'];
        data.extend_from_slice(&(-10i16).to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = ResidentNameTable::new(&mut reader, 0).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].ordinal(), Some(-10));
    }
}
