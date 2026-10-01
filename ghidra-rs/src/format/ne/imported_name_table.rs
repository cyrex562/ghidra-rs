use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::length_string_set::LengthStringSet;
use std::io;

/// Represents the imported name table in a new-executable (NE) format file.
///
/// The imported name table stores names of functions/procedures imported from
/// DLLs. This struct provides access to names at specific offsets within the table.
///
/// Mirrors `ImportedNameTable` from the original Ghidra Java source.
pub struct ImportedNameTable {
    reader: BinaryReader,
    index: u64,
}

impl ImportedNameTable {
    /// Constructs a new imported name table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The absolute file offset where the table begins
    pub fn new(reader: BinaryReader, index: u64) -> Self {
        ImportedNameTable { reader, index }
    }

    /// Returns the length/string set at the given offset.
    ///
    /// # Arguments
    /// * `offset` - The offset from the beginning of the Imported Name Table
    ///              to the length/string set
    ///
    /// # Errors
    /// Returns an error if there is an IO-related error reading from the reader.
    pub fn get_name_at(&self, offset: i16) -> io::Result<LengthStringSet> {
        let new_index = self.index + (offset as u16) as u64;
        let mut reader = self.reader.clone_at(new_index);
        LengthStringSet::new(&mut reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn creates_table_with_index() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);
        assert_eq!(table.index, 0);
    }

    #[test]
    fn gets_name_at_zero_offset() {
        let data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 5);
        assert_eq!(name_set.name(), Some("hello"));
    }

    #[test]
    fn gets_name_at_positive_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 10]);
        data.push(3);
        data.extend_from_slice(b"abc");

        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(10).unwrap();
        assert_eq!(name_set.length(), 3);
        assert_eq!(name_set.name(), Some("abc"));
    }

    #[test]
    fn gets_name_at_different_table_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xffu8; 5]);
        data.push(4);
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0u8; 10]);

        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 5);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 4);
        assert_eq!(name_set.name(), Some("test"));
    }

    #[test]
    fn gets_zero_length_name() {
        let data = vec![0];
        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(0).unwrap();
        assert_eq!(name_set.length(), 0);
        assert_eq!(name_set.name(), None);
    }

    #[test]
    fn handles_offset_conversion_from_signed() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 50]);
        data.push(2);
        data.extend_from_slice(b"xy");

        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);

        let name_set = table.get_name_at(50).unwrap();
        assert_eq!(name_set.length(), 2);
        assert_eq!(name_set.name(), Some("xy"));
    }

    #[test]
    fn works_with_table_offset_and_name_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 100]);
        data.push(6);
        data.extend_from_slice(b"import");
        data.extend_from_slice(&[0u8; 50]);

        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 20);

        let name_set = table.get_name_at(80).unwrap();
        assert_eq!(name_set.length(), 6);
        assert_eq!(name_set.name(), Some("import"));
    }

    #[test]
    fn multiple_gets_independent() {
        let mut data = Vec::new();
        data.push(3);
        data.extend_from_slice(b"foo");
        data.push(3);
        data.extend_from_slice(b"bar");
        data.push(3);
        data.extend_from_slice(b"baz");

        let reader = BinaryReader::from_bytes(data, true);
        let table = ImportedNameTable::new(reader, 0);

        let first = table.get_name_at(0).unwrap();
        let second = table.get_name_at(4).unwrap();
        let third = table.get_name_at(8).unwrap();

        assert_eq!(first.name(), Some("foo"));
        assert_eq!(second.name(), Some("bar"));
        assert_eq!(third.name(), Some("baz"));
    }
}
