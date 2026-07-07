use std::io;

use crate::filesystem::btree::b_tree_header_record::BTreeHeaderRecord;
use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents a Map Record containing node allocation bitmap.
///
/// See: <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>
pub struct BTreeMapRecord {
    bitmap: Vec<u8>,
}

impl BTreeMapRecord {
    pub(crate) fn new(
        reader: &mut GBinaryReader,
        header_record: &BTreeHeaderRecord,
    ) -> io::Result<Self> {
        let node_size = header_record.get_node_size() as usize;
        let bitmap_size = if node_size > 256 {
            node_size - 256
        } else {
            0
        };

        Ok(BTreeMapRecord {
            bitmap: reader.read_next_byte_array(bitmap_size)?,
        })
    }

    /// Returns the map record node allocation bitmap.
    pub fn get_bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    /// Returns true if the specified node index is used.
    /// Returns false if the specified node index is free.
    pub fn is_node_used(&self, node_index: usize) -> bool {
        let byte_index = node_index / 8;
        if byte_index >= self.bitmap.len() {
            return false;
        }

        let block = self.bitmap[byte_index] as u32;
        let bit_position = 7 - (node_index % 8);
        (block & (1 << bit_position)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::BTreeMapRecord;
    use crate::filesystem::btree::b_tree_header_record::BTreeHeaderRecord;
    use crate::filesystem::ghidra::g_binary_reader::{ByteProvider, GBinaryReader};
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
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
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    fn reader(data: Vec<u8>) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecProvider(data))), false)
    }

    #[test]
    fn reads_bitmap_from_reader() {
        let node_size = 512i16;
        let bitmap_size = (node_size as usize) - 256;

        let mut header_data = vec![0u8; 114];
        // nodeSize lives at offset 18 in BTHeaderRec (after treeDepth i16 + four i32s).
        header_data[18..20].copy_from_slice(&node_size.to_be_bytes());

        let mut full_data = header_data.clone();
        full_data.extend(vec![0x80u8; bitmap_size]);

        let mut reader = reader(full_data);
        let mut header_reader = reader.clone_at(0);
        let header = BTreeHeaderRecord::new(&mut header_reader).unwrap();

        reader.set_pointer_index(114);
        let record = BTreeMapRecord::new(&mut reader, &header).unwrap();

        assert_eq!(record.get_bitmap().len(), bitmap_size);
        assert_eq!(record.get_bitmap()[0], 0x80);
    }

    #[test]
    fn is_node_used_checks_bitmap_correctly() {
        let node_size = 512i16;
        let bitmap_size = (node_size as usize) - 256;

        let mut bitmap = vec![0u8; bitmap_size];
        bitmap[0] = 0x80;

        let record = BTreeMapRecord {
            bitmap: bitmap.clone(),
        };

        assert!(record.is_node_used(0));
        assert!(!record.is_node_used(1));
        assert!(!record.is_node_used(2));
    }

    #[test]
    fn is_node_used_with_various_bit_positions() {
        let record = BTreeMapRecord {
            bitmap: vec![0b10101010],
        };

        assert!(record.is_node_used(0));
        assert!(!record.is_node_used(1));
        assert!(record.is_node_used(2));
        assert!(!record.is_node_used(3));
        assert!(record.is_node_used(4));
        assert!(!record.is_node_used(5));
        assert!(record.is_node_used(6));
        assert!(!record.is_node_used(7));
    }

    #[test]
    fn is_node_used_with_multiple_bytes() {
        let record = BTreeMapRecord {
            bitmap: vec![0x00, 0xFF],
        };

        assert!(!record.is_node_used(0));
        assert!(!record.is_node_used(7));

        assert!(record.is_node_used(8));
        assert!(record.is_node_used(15));
    }

    #[test]
    fn is_node_used_out_of_bounds_returns_false() {
        let record = BTreeMapRecord {
            bitmap: vec![0xFF; 10],
        };

        assert!(!record.is_node_used(1000));
    }

    #[test]
    fn handles_zero_sized_bitmap() {
        let node_size = 200i16;
        let mut header_data = vec![0u8; 114];
        header_data[12..14].copy_from_slice(&node_size.to_be_bytes());

        let mut reader = reader(header_data);
        let mut header_reader = reader.clone_at(0);
        let header = BTreeHeaderRecord::new(&mut header_reader).unwrap();

        reader.set_pointer_index(114);
        let record = BTreeMapRecord::new(&mut reader, &header).unwrap();

        assert_eq!(record.get_bitmap().len(), 0);
        assert!(!record.is_node_used(0));
    }

    #[test]
    fn errors_on_insufficient_bitmap_data() {
        let node_size = 512i16;
        let bitmap_size = (node_size as usize) - 256;

        let mut header_data = vec![0u8; 114];
        // nodeSize lives at offset 18 in BTHeaderRec (after treeDepth i16 + four i32s).
        header_data[18..20].copy_from_slice(&node_size.to_be_bytes());

        let mut full_data = header_data;
        full_data.extend(vec![0x80u8; bitmap_size / 2]);

        let mut reader = reader(full_data);
        let mut header_reader = reader.clone_at(0);
        let header = BTreeHeaderRecord::new(&mut header_reader).unwrap();

        reader.set_pointer_index(114);
        assert!(BTreeMapRecord::new(&mut reader, &header).is_err());
    }
}
