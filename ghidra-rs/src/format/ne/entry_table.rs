use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::ne::entry_table_bundle::EntryTableBundle;
use std::io;

/// Represents a new-executable (NE) entry table.
///
/// Mirrors `EntryTable` from the original Ghidra Java source.
pub struct EntryTable {
    bundles: Vec<EntryTableBundle>,
}

impl EntryTable {
    /// Constructs a new entry table.
    ///
    /// # Arguments
    /// * `reader` - the binary reader
    /// * `index` - the index where the entry table begins
    /// * `byte_count` - the length in bytes of the entry table. Unused: mirrors the Java
    ///   constructor, whose `byteCount` parameter is likewise never read in the constructor body
    ///   (the bundle list is instead terminated by a zero-count bundle).
    ///
    /// # Errors
    /// Returns `Err` if there is an IO-related error reading from the reader.
    pub fn new(reader: &mut BinaryReader, index: u64, _byte_count: i16) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut bundles = Vec::new();
        loop {
            let etb = EntryTableBundle::new(reader)?;
            if etb.get_count() == 0 {
                break;
            }
            bundles.push(etb);
        }

        reader.set_pointer_index(old_index);

        Ok(EntryTable { bundles })
    }

    /// Returns the entry table bundles in this entry table.
    pub fn get_bundles(&self) -> &[EntryTableBundle] {
        &self.bundles
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn empty_table_stops_at_sentinel() {
        let data = vec![0x00u8]; // single sentinel bundle (count == 0)
        let mut reader = BinaryReader::from_bytes(data, true);

        let table = EntryTable::new(&mut reader, 0, 0).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
    }

    #[test]
    fn reads_multiple_bundles_until_sentinel() {
        let data = vec![
            // bundle 1: count=1, type=CONSTANT(0xfe), one non-moveable entry
            0x01, 0xfe, 0x03, 0x10, 0x00, // bundle 2: count=1, type=MOVEABLE(0xff), one
            // moveable entry
            0x01, 0xff, 0x04, 0xAA, 0xBB, 0x02, 0x20, 0x00, // sentinel
            0x00,
        ];
        let mut reader = BinaryReader::from_bytes(data, true);

        let table = EntryTable::new(&mut reader, 0, 0).unwrap();

        let bundles = table.get_bundles();
        assert_eq!(bundles.len(), 2);
        assert!(bundles[0].is_constant());
        assert!(bundles[1].is_moveable());
    }

    #[test]
    fn honors_starting_index_and_restores_pointer() {
        let mut data = vec![0xAA, 0xBB, 0xCC]; // filler before the table
        data.push(0x00); // sentinel at index 3
        let mut reader = BinaryReader::from_bytes(data, true);
        reader.set_pointer_index(1);

        let table = EntryTable::new(&mut reader, 3, 0).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
        assert_eq!(reader.get_pointer_index(), 1);
    }

    #[test]
    fn byte_count_argument_is_ignored() {
        // Mirrors the Java quirk where `byteCount` is accepted but never consulted; passing a
        // nonsensical value must not change parsing.
        let data = vec![0x00u8];
        let mut reader = BinaryReader::from_bytes(data, true);

        let table = EntryTable::new(&mut reader, 0, i16::MAX).unwrap();

        assert_eq!(table.get_bundles().len(), 0);
    }
}
