use std::io;

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents a `BTHeaderRec` structure.
///
/// See: <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>
pub struct BTreeHeaderRecord {
    tree_depth: i16,
    root_node: i32,
    leaf_records: i32,
    first_leaf_node: i32,
    last_leaf_node: i32,
    node_size: i16,
    max_key_length: i16,
    total_nodes: i32,
    free_nodes: i32,
    reserved1: i16,
    clump_size: i32,
    btree_type: u8,
    key_compare_type: u8,
    attributes: i32,
    reserved: Vec<i32>,
}

impl BTreeHeaderRecord {
    pub(crate) fn new(reader: &mut GBinaryReader) -> io::Result<Self> {
        Ok(BTreeHeaderRecord {
            tree_depth: reader.read_next_short()?,
            root_node: reader.read_next_int()?,
            leaf_records: reader.read_next_int()?,
            first_leaf_node: reader.read_next_int()?,
            last_leaf_node: reader.read_next_int()?,
            node_size: reader.read_next_short()?,
            max_key_length: reader.read_next_short()?,
            total_nodes: reader.read_next_int()?,
            free_nodes: reader.read_next_int()?,
            reserved1: reader.read_next_short()?,
            clump_size: reader.read_next_int()?,
            btree_type: reader.read_next_byte()?,
            key_compare_type: reader.read_next_byte()?,
            attributes: reader.read_next_int()?,
            reserved: reader.read_next_int_array(16)?,
        })
    }

    pub fn get_tree_depth(&self) -> i16 {
        self.tree_depth
    }

    pub fn get_root_node(&self) -> i32 {
        self.root_node
    }

    pub fn get_leaf_records(&self) -> i32 {
        self.leaf_records
    }

    pub fn get_first_leaf_node(&self) -> i32 {
        self.first_leaf_node
    }

    pub fn get_last_leaf_node(&self) -> i32 {
        self.last_leaf_node
    }

    pub fn get_node_size(&self) -> i16 {
        self.node_size
    }

    pub fn get_max_key_length(&self) -> i16 {
        self.max_key_length
    }

    pub fn get_total_nodes(&self) -> i32 {
        self.total_nodes
    }

    pub fn get_free_nodes(&self) -> i32 {
        self.free_nodes
    }

    pub fn get_reserved1(&self) -> i16 {
        self.reserved1
    }

    pub fn get_clump_size(&self) -> i32 {
        self.clump_size
    }

    pub fn get_btree_type(&self) -> u8 {
        self.btree_type
    }

    pub fn get_key_compare_type(&self) -> u8 {
        self.key_compare_type
    }

    pub fn get_attributes(&self) -> i32 {
        self.attributes
    }

    pub fn get_reserved(&self) -> &[i32] {
        &self.reserved
    }
}

#[cfg(test)]
mod tests {
    use super::BTreeHeaderRecord;
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

    fn build_header_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&3i16.to_be_bytes()); // treeDepth
        data.extend_from_slice(&4i32.to_be_bytes()); // rootNode
        data.extend_from_slice(&5i32.to_be_bytes()); // leafRecords
        data.extend_from_slice(&6i32.to_be_bytes()); // firstLeafNode
        data.extend_from_slice(&7i32.to_be_bytes()); // lastLeafNode
        data.extend_from_slice(&512i16.to_be_bytes()); // nodeSize
        data.extend_from_slice(&37i16.to_be_bytes()); // maxKeyLength
        data.extend_from_slice(&100i32.to_be_bytes()); // totalNodes
        data.extend_from_slice(&8i32.to_be_bytes()); // freeNodes
        data.extend_from_slice(&0i16.to_be_bytes()); // reserved1
        data.extend_from_slice(&1024i32.to_be_bytes()); // clumpSize
        data.push(0u8); // btreeType
        data.push(0xBCu8); // keyCompareType
        data.extend_from_slice(&2i32.to_be_bytes()); // attributes
        for i in 0..16i32 {
            data.extend_from_slice(&i.to_be_bytes()); // reserved[16]
        }
        data
    }

    fn reader(data: Vec<u8>) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecProvider(data))), false)
    }

    #[test]
    fn parses_fields_in_declared_order() {
        let mut r = reader(build_header_bytes());
        let record = BTreeHeaderRecord::new(&mut r).unwrap();

        assert_eq!(record.get_tree_depth(), 3);
        assert_eq!(record.get_root_node(), 4);
        assert_eq!(record.get_leaf_records(), 5);
        assert_eq!(record.get_first_leaf_node(), 6);
        assert_eq!(record.get_last_leaf_node(), 7);
        assert_eq!(record.get_node_size(), 512);
        assert_eq!(record.get_max_key_length(), 37);
        assert_eq!(record.get_total_nodes(), 100);
        assert_eq!(record.get_free_nodes(), 8);
        assert_eq!(record.get_reserved1(), 0);
        assert_eq!(record.get_clump_size(), 1024);
        assert_eq!(record.get_btree_type(), 0);
        assert_eq!(record.get_key_compare_type(), 0xBC);
        assert_eq!(record.get_attributes(), 2);
        assert_eq!(record.get_reserved(), &(0..16).collect::<Vec<i32>>()[..]);
    }

    #[test]
    fn errors_on_truncated_input() {
        let mut data = build_header_bytes();
        data.truncate(10);
        let mut r = reader(data);

        assert!(BTreeHeaderRecord::new(&mut r).is_err());
    }
}
