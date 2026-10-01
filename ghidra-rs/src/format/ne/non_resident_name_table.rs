use crate::app::util::bin::binary_reader::BinaryReader;
use std::io;

use super::length_string_ordinal_set::LengthStringOrdinalSet;

/// Represents the non-resident name table in a new-executable (NE) format file.
///
/// The non-resident name table stores exported names and their ordinals, along with
/// an optional module title. This struct provides access to those names and the title.
///
/// Mirrors `NonResidentNameTable` from the original Ghidra Java source.
pub struct NonResidentNameTable {
    title: String,
    names: Vec<LengthStringOrdinalSet>,
}

impl NonResidentNameTable {
    /// Constructs a new non-resident name table.
    ///
    /// # Arguments
    /// * `reader` - The binary reader used to read from the underlying data
    /// * `index` - The byte offset where the non-resident name table begins
    /// * `byte_count` - The number of bytes in the non-resident name table (unused,
    ///                  for compatibility with Java signature)
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(
        reader: &mut BinaryReader,
        index: u64,
        _byte_count: i16,
    ) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut names = Vec::new();
        let mut title = "<not set>".to_string();

        loop {
            let lsos = LengthStringOrdinalSet::new(reader)?;
            if lsos.length_string_set().length() == 0 {
                break;
            }
            if lsos.ordinal() == Some(0) {
                if let Some(name) = lsos.length_string_set().name() {
                    title = name.to_string();
                }
            }
            names.push(lsos);
        }

        reader.set_pointer_index(old_index);

        Ok(NonResidentNameTable { title, names })
    }

    /// Returns the non-resident name table title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the array of names defined in the non-resident name table.
    pub fn names(&self) -> &[LengthStringOrdinalSet] {
        &self.names
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn creates_table_with_default_title() {
        let data = vec![0];
        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 1).unwrap();
        assert_eq!(table.title(), "<not set>");
        assert_eq!(table.names().len(), 0);
    }

    #[test]
    fn reads_single_named_entry() {
        let mut data = vec![5, b'h', b'e', b'l', b'l', b'o'];
        data.extend_from_slice(&42i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.title(), "<not set>");
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("hello"));
        assert_eq!(table.names()[0].ordinal(), Some(42));
    }

    #[test]
    fn extracts_title_from_ordinal_zero() {
        let mut data = vec![5, b'T', b'i', b't', b'l', b'e'];
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.title(), "Title");
        assert_eq!(table.names().len(), 1);
    }

    #[test]
    fn reads_multiple_entries() {
        let mut data = Vec::new();
        data.push(5);
        data.extend_from_slice(b"title");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo1");
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(4);
        data.extend_from_slice(b"foo2");
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "title");
        assert_eq!(table.names().len(), 3);
        assert_eq!(table.names()[0].ordinal(), Some(0));
        assert_eq!(table.names()[1].ordinal(), Some(1));
        assert_eq!(table.names()[2].ordinal(), Some(2));
    }

    #[test]
    fn restores_reader_position() {
        let mut data = vec![0, 0xFF, 0xFF];
        let mut reader = BinaryReader::from_bytes(data, true);
        reader.set_pointer_index(2);
        NonResidentNameTable::new(&mut reader, 0, 1).unwrap();
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
        let table = NonResidentNameTable::new(&mut reader, 2, 16).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("abc"));
        assert_eq!(table.names()[0].ordinal(), Some(5));
    }

    #[test]
    fn skips_zero_length_ordinal() {
        let mut data = Vec::new();
        data.push(4);
        data.extend_from_slice(b"skip");
        data.extend_from_slice(&99i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 16).unwrap();
        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].length_string_set().name(), Some("skip"));
        assert_eq!(table.names()[0].ordinal(), Some(99));
    }

    #[test]
    fn title_from_first_ordinal_zero_entry() {
        let mut data = Vec::new();
        data.push(5);
        data.extend_from_slice(b"first");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(6);
        data.extend_from_slice(b"second");
        // Non-zero ordinal: only the first (ordinal-zero) entry supplies the title.
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "first");
        assert_eq!(table.names().len(), 2);
    }

    #[test]
    fn mixed_ordinals_with_title() {
        let mut data = Vec::new();
        data.push(3);
        data.extend_from_slice(b"app");
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(b"x1");
        data.extend_from_slice(&10i16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(b"x2");
        data.extend_from_slice(&20i16.to_le_bytes());
        data.push(0);

        let mut reader = BinaryReader::from_bytes(data, true);
        let table = NonResidentNameTable::new(&mut reader, 0, 32).unwrap();
        assert_eq!(table.title(), "app");
        assert_eq!(table.names().len(), 3);
        assert_eq!(
            table.names().iter().map(|n| n.ordinal()).collect::<Vec<_>>(),
            vec![Some(0), Some(10), Some(20)]
        );
    }
}
