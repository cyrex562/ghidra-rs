use std::io;

use crate::filesystem::btree::b_tree_header_record::BTreeHeaderRecord;
use crate::filesystem::btree::b_tree_node_record::BTreeNodeRecord;
use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

/// Represents a `BTNodeDescriptor` structure (`mobiledevices.dmg.btree.BTreeNodeDescriptor`).
///
/// A node descriptor heads every node in an HFS+ B-tree. After the fixed descriptor fields
/// are read, the owning root descriptor walks the node's record-offset table (stored
/// backwards from the end of the node) with [`read_record_offsets`](Self::read_record_offsets)
/// and then materialises each record with [`read_records`](Self::read_records).
///
/// See: <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>
pub struct BTreeNodeDescriptor {
    f_link: i32,
    b_link: i32,
    kind: i8,
    height: i8,
    num_records: i16,
    reserved: i16,

    record_offsets: Vec<i16>,
    records: Vec<BTreeNodeRecord>,
}

impl BTreeNodeDescriptor {
    /// Reads the fixed 14-byte descriptor at the reader's current position.
    pub(crate) fn new(reader: &mut GBinaryReader) -> io::Result<Self> {
        Ok(BTreeNodeDescriptor {
            f_link: reader.read_next_int()?,
            b_link: reader.read_next_int()?,
            kind: reader.read_next_byte()? as i8,
            height: reader.read_next_byte()? as i8,
            num_records: reader.read_next_short()?,
            reserved: reader.read_next_short()?,
            record_offsets: Vec::new(),
            records: Vec::new(),
        })
    }

    /// Reads the record-offset table of the node starting at `node_start_index`.
    ///
    /// The table is stored as 16-bit offsets growing backwards from the last two bytes of the
    /// node (`node_start_index + header.node_size - 2`); reading stops at the first zero
    /// offset, as in Java. Offsets are appended to [`get_record_offsets`](Self::get_record_offsets).
    pub(crate) fn read_record_offsets(
        &mut self,
        reader: &GBinaryReader,
        node_start_index: u64,
        header: &BTreeHeaderRecord,
    ) -> io::Result<()> {
        let mut position = node_start_index as i64 + header.get_node_size() as i64 - 2;
        loop {
            if position < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("negative B-tree record offset position: {position}"),
                ));
            }
            let record_offset = reader.read_short(position as u64)?;
            if record_offset == 0 {
                break;
            }
            self.record_offsets.push(record_offset);
            position -= 2;
        }
        Ok(())
    }

    /// Reads [`get_num_records`](Self::get_num_records) records from the node starting at
    /// `node_start_index`, using the previously read record-offset table (each offset is
    /// treated as unsigned, relative to the node start).
    ///
    /// # Errors
    /// Fails if the offset table holds fewer entries than the record count (Java throws
    /// `IndexOutOfBoundsException` there) or if reading a record fails.
    pub(crate) fn read_records(
        &mut self,
        reader: &mut GBinaryReader,
        node_start_index: u64,
    ) -> io::Result<()> {
        for i in 0..self.num_records.max(0) as usize {
            let offset = *self.record_offsets.get(i).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "B-tree record index {i} out of bounds for {} record offsets",
                        self.record_offsets.len()
                    ),
                )
            })?;

            let record_index = (offset as u16 as u64) + node_start_index;
            reader.set_pointer_index(record_index);

            let record = BTreeNodeRecord::new(reader, self)?;
            self.records.push(record);
        }
        Ok(())
    }

    /// The record offsets read by [`read_record_offsets`](Self::read_record_offsets).
    pub fn get_record_offsets(&self) -> &[i16] {
        &self.record_offsets
    }

    /// The records read by [`read_records`](Self::read_records).
    pub fn get_records(&self) -> &[BTreeNodeRecord] {
        &self.records
    }

    /// The node number of the next node of this type, or zero if this is the last node.
    pub fn get_f_link(&self) -> i32 {
        self.f_link
    }

    /// The node number of the previous node of this type, or zero if this is the first node.
    pub fn get_b_link(&self) -> i32 {
        self.b_link
    }

    /// The kind of this node; see
    /// [`BTreeNodeKinds`](crate::filesystem::btree::b_tree_node_kinds::BTreeNodeKinds).
    pub fn get_kind(&self) -> i8 {
        self.kind
    }

    /// The level, or depth, of this node in the B-tree hierarchy.
    pub fn get_height(&self) -> i8 {
        self.height
    }

    /// The number of records in this node.
    pub fn get_num_records(&self) -> i16 {
        self.num_records
    }

    /// This field is reserved.
    pub fn get_reserved(&self) -> i16 {
        self.reserved
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::BTreeNodeDescriptor;
    use crate::filesystem::btree::b_tree_header_record::BTreeHeaderRecord;
    use crate::filesystem::btree::b_tree_node_kinds::BTreeNodeKinds;
    use crate::filesystem::ghidra::g_binary_reader::{GBinaryReader, GByteStore};
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    pub(crate) struct VecProvider(pub(crate) Vec<u8>);

    impl GByteStore for VecProvider {
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

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            *self
                .0
                .get_mut(index as usize)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))? = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            for (i, v) in values.iter().enumerate() {
                self.write_byte(index + i as u64, *v)?;
            }
            Ok(())
        }
    }

    pub(crate) fn reader(data: Vec<u8>) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecProvider(data))), false)
    }

    pub(crate) fn descriptor_bytes(kind: i8, num_records: i16) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&7i32.to_be_bytes()); // fLink
        d.extend_from_slice(&3i32.to_be_bytes()); // bLink
        d.push(kind as u8); // kind
        d.push(1u8); // height
        d.extend_from_slice(&num_records.to_be_bytes()); // numRecords
        d.extend_from_slice(&0x1234i16.to_be_bytes()); // reserved
        d
    }

    fn header_with_node_size(node_size: i16) -> BTreeHeaderRecord {
        let mut data = vec![0u8; 106];
        // nodeSize lives after treeDepth(2)+rootNode(4)+leafRecords(4)+first(4)+last(4) = 18
        data[18..20].copy_from_slice(&node_size.to_be_bytes());
        BTreeHeaderRecord::new(&mut reader(data)).unwrap()
    }

    #[test]
    fn parses_descriptor_fields() {
        let mut r = reader(descriptor_bytes(BTreeNodeKinds::K_BT_LEAF_NODE, 2));
        let d = BTreeNodeDescriptor::new(&mut r).unwrap();
        assert_eq!(d.get_f_link(), 7);
        assert_eq!(d.get_b_link(), 3);
        assert_eq!(d.get_kind(), -1);
        assert_eq!(d.get_height(), 1);
        assert_eq!(d.get_num_records(), 2);
        assert_eq!(d.get_reserved(), 0x1234);
        assert_eq!(r.get_pointer_index(), 14);
        assert!(d.get_record_offsets().is_empty());
        assert!(d.get_records().is_empty());
    }

    #[test]
    fn errors_on_truncated_descriptor() {
        let mut data = descriptor_bytes(0, 0);
        data.truncate(9);
        assert!(BTreeNodeDescriptor::new(&mut reader(data)).is_err());
    }

    #[test]
    fn reads_record_offsets_backwards_until_zero() {
        // A 32-byte node at index 0; offsets stored from the end backwards.
        let mut data = descriptor_bytes(BTreeNodeKinds::K_BT_INDEX_NODE, 2);
        data.resize(32, 0);
        data[30..32].copy_from_slice(&14i16.to_be_bytes()); // first offset
        data[28..30].copy_from_slice(&(-32768i16).to_be_bytes()); // 0x8000, non-zero
        data[26..28].copy_from_slice(&0i16.to_be_bytes()); // terminator

        let mut r = reader(data);
        let mut d = BTreeNodeDescriptor::new(&mut r).unwrap();
        d.read_record_offsets(&r, 0, &header_with_node_size(32)).unwrap();
        assert_eq!(d.get_record_offsets(), &[14, -32768]);
    }

    #[test]
    fn read_record_offsets_errors_when_running_off_the_start() {
        // No zero terminator anywhere: the walk reaches negative positions.
        let mut data = descriptor_bytes(0, 0);
        for b in data.iter_mut() {
            *b = 0xFF;
        }
        data.truncate(14);
        let mut r = reader(data);
        let mut d = BTreeNodeDescriptor::new(&mut r).unwrap();
        assert!(d.read_record_offsets(&r, 0, &header_with_node_size(14)).is_err());
    }

    #[test]
    fn read_records_errors_when_offsets_are_missing() {
        let mut r = reader(descriptor_bytes(BTreeNodeKinds::K_BT_INDEX_NODE, 1));
        let mut d = BTreeNodeDescriptor::new(&mut r).unwrap();
        let err = d.read_records(&mut r, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_records_parses_each_record_at_its_offset() {
        // Node layout: descriptor (14 bytes) + index record at 14 + offsets table at the end.
        let mut data = descriptor_bytes(BTreeNodeKinds::K_BT_INDEX_NODE, 1);
        data.extend_from_slice(&1i32.to_be_bytes()); // unknown0
        data.extend_from_slice(&42i32.to_be_bytes()); // fileID
        data.extend_from_slice(&2i32.to_be_bytes()); // unknown2
        data.extend_from_slice(&1i16.to_be_bytes()); // typeLength
        data.extend_from_slice(&[0, b'x']); // type "x"
        data.extend_from_slice(&3i32.to_be_bytes()); // unknown3
        data.resize(64, 0);
        data[62..64].copy_from_slice(&14i16.to_be_bytes());

        let mut r = reader(data);
        let mut d = BTreeNodeDescriptor::new(&mut r).unwrap();
        d.read_record_offsets(&r, 0, &header_with_node_size(64)).unwrap();
        d.read_records(&mut r, 0).unwrap();

        assert_eq!(d.get_records().len(), 1);
        let rec = &d.get_records()[0];
        assert_eq!(rec.get_record_offset(), 14);
        assert_eq!(rec.get_file_id(), 42);
        assert_eq!(rec.get_type(), "x");
        assert_eq!(rec.get_unknown3(), 3);
        assert_eq!(rec.get_descriptor_kind(), BTreeNodeKinds::K_BT_INDEX_NODE);
    }
}
