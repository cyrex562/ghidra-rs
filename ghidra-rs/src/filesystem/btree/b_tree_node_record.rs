use std::io;

use crate::filesystem::btree::b_tree_node_descriptor::BTreeNodeDescriptor;
use crate::filesystem::btree::b_tree_node_kinds::BTreeNodeKinds;
use crate::filesystem::decmpfs::decmpfs_header::DecmpfsHeader;
use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;
use crate::filesystem::xattr::xattr_constants::XattrConstants;

/// A record inside an HFS+ attributes B-tree node (`mobiledevices.dmg.btree.BTreeNodeRecord`).
///
/// The layout depends on the kind of the node that owns it: leaf records carry three extra
/// words (`unknown4`, `unknown5`, `recordLength`), and a leaf record whose type is the
/// `com.apple.decmpfs` extended attribute is followed by a [`DecmpfsHeader`].
///
/// Java keeps a back-reference to the owning `BTreeNodeDescriptor` (`getDescriptor()`, which
/// has no callers). In Rust the descriptor owns its records, so a record instead keeps the one
/// descriptor field its layout depends on, available via
/// [`get_descriptor_kind`](Self::get_descriptor_kind).
pub struct BTreeNodeRecord {
    unknown0: i32,
    file_id: i32,
    unknown2: i32,
    record_type: String,
    unknown3: i32,
    unknown4: i32,
    unknown5: i32,
    record_length: i32,

    type_length: i16,
    descriptor_kind: i8,
    decmpfs_header: Option<DecmpfsHeader>,
    offset: u64,
}

impl BTreeNodeRecord {
    /// Reads a record at the reader's current position, laid out according to the kind of
    /// `descriptor` (the node that contains it).
    ///
    /// # Errors
    /// Fails if the underlying read fails, or if a `decmpfs` leaf record declares a negative
    /// record length.
    pub(crate) fn new(
        reader: &mut GBinaryReader,
        descriptor: &BTreeNodeDescriptor,
    ) -> io::Result<Self> {
        let offset = reader.get_pointer_index();

        let unknown0 = reader.read_next_int()?;
        let file_id = reader.read_next_int()?;
        let unknown2 = reader.read_next_int()?;

        let type_length = reader.read_next_short()?;

        let record_type = Self::read_type(reader, type_length)?;
        let unknown3 = reader.read_next_int()?;

        let kind = descriptor.get_kind();
        let (mut unknown4, mut unknown5, mut record_length) = (0, 0, 0);
        if kind == BTreeNodeKinds::K_BT_LEAF_NODE {
            unknown4 = reader.read_next_int()?;
            unknown5 = reader.read_next_int()?;
            record_length = reader.read_next_int()?;
        }

        let mut decmpfs_header = None;
        if kind == BTreeNodeKinds::K_BT_LEAF_NODE
            && record_type == XattrConstants::DECMPFS_XATTR_NAME
        {
            let size = usize::try_from(record_length).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("negative decmpfs record length: {record_length}"),
                )
            })?;
            decmpfs_header = Some(DecmpfsHeader::new(reader, size)?);
        }
        // Java leaves KAUTH_FILESEC leaf records and decmpfs index records unparsed as well.

        Ok(BTreeNodeRecord {
            unknown0,
            file_id,
            unknown2,
            record_type,
            unknown3,
            unknown4,
            unknown5,
            record_length,
            type_length,
            descriptor_kind: kind,
            decmpfs_header,
            offset,
        })
    }

    /// Reads `type_length` UTF-16BE code units, keeping only the low byte of each as Java's
    /// `(char) reader.readNextByte()` does (the high byte is skipped; the low byte is
    /// sign-extended into a `char`).
    fn read_type(reader: &mut GBinaryReader, type_length: i16) -> io::Result<String> {
        let mut buffer = String::new();
        for _ in 0..type_length.max(0) {
            reader.read_next_byte()?; // skip it...
            let b = reader.read_next_byte()? as i8;
            let code = (b as i32 as u32) & 0xFFFF;
            buffer.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
        }
        Ok(buffer)
    }

    /// The attribute name (type) of this record, e.g. `com.apple.decmpfs`.
    pub fn get_type(&self) -> &str {
        &self.record_type
    }

    /// The record length (only read for leaf records; zero otherwise).
    pub fn get_record_length(&self) -> i32 {
        self.record_length
    }

    /// The kind of the node descriptor this record was read from; see
    /// [`BTreeNodeKinds`].
    pub fn get_descriptor_kind(&self) -> i8 {
        self.descriptor_kind
    }

    /// The number of UTF-16 code units in the record type.
    pub fn get_type_length(&self) -> i16 {
        self.type_length
    }

    pub fn get_unknown0(&self) -> i32 {
        self.unknown0
    }

    pub fn get_unknown2(&self) -> i32 {
        self.unknown2
    }

    pub fn get_unknown3(&self) -> i32 {
        self.unknown3
    }

    pub fn get_unknown4(&self) -> i32 {
        self.unknown4
    }

    pub fn get_unknown5(&self) -> i32 {
        self.unknown5
    }

    /// The file ID (catalog node ID) this attribute belongs to.
    pub fn get_file_id(&self) -> i32 {
        self.file_id
    }

    /// The `decmpfs` header following a `com.apple.decmpfs` leaf record, if any.
    pub fn get_decmpfs_header(&self) -> Option<&DecmpfsHeader> {
        self.decmpfs_header.as_ref()
    }

    /// The absolute reader index at which this record starts.
    pub fn get_record_offset(&self) -> u64 {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::BTreeNodeRecord;
    use crate::filesystem::btree::b_tree_node_descriptor::tests::{descriptor_bytes, reader};
    use crate::filesystem::btree::b_tree_node_descriptor::BTreeNodeDescriptor;
    use crate::filesystem::btree::b_tree_node_kinds::BTreeNodeKinds;

    fn descriptor(kind: i8) -> BTreeNodeDescriptor {
        BTreeNodeDescriptor::new(&mut reader(descriptor_bytes(kind, 1))).unwrap()
    }

    fn record_prefix(type_name: &str) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&0x11i32.to_be_bytes()); // unknown0
        d.extend_from_slice(&0x22i32.to_be_bytes()); // fileID
        d.extend_from_slice(&0x33i32.to_be_bytes()); // unknown2
        d.extend_from_slice(&(type_name.len() as i16).to_be_bytes());
        for b in type_name.bytes() {
            d.extend_from_slice(&[0, b]);
        }
        d.extend_from_slice(&0x44i32.to_be_bytes()); // unknown3
        d
    }

    #[test]
    fn index_record_skips_leaf_fields() {
        let mut data = vec![0xAA; 4];
        data.extend(record_prefix("com.apple.decmpfs"));
        let mut r = reader(data);
        r.set_pointer_index(4);
        let rec = BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_INDEX_NODE))
            .unwrap();
        assert_eq!(rec.get_record_offset(), 4);
        assert_eq!(rec.get_unknown0(), 0x11);
        assert_eq!(rec.get_file_id(), 0x22);
        assert_eq!(rec.get_unknown2(), 0x33);
        assert_eq!(rec.get_type_length(), 17);
        assert_eq!(rec.get_type(), "com.apple.decmpfs");
        assert_eq!(rec.get_unknown3(), 0x44);
        assert_eq!(rec.get_unknown4(), 0);
        assert_eq!(rec.get_unknown5(), 0);
        assert_eq!(rec.get_record_length(), 0);
        assert!(rec.get_decmpfs_header().is_none());
        assert_eq!(rec.get_descriptor_kind(), BTreeNodeKinds::K_BT_INDEX_NODE);
    }

    #[test]
    fn leaf_record_reads_extra_words() {
        let mut data = record_prefix("com.apple.ResourceFork");
        data.extend_from_slice(&5i32.to_be_bytes());
        data.extend_from_slice(&6i32.to_be_bytes());
        data.extend_from_slice(&7i32.to_be_bytes());
        let mut r = reader(data);
        let rec = BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_LEAF_NODE))
            .unwrap();
        assert_eq!(rec.get_unknown4(), 5);
        assert_eq!(rec.get_unknown5(), 6);
        assert_eq!(rec.get_record_length(), 7);
        assert!(rec.get_decmpfs_header().is_none());
    }

    #[test]
    fn decmpfs_leaf_record_reads_header() {
        let mut data = record_prefix("com.apple.decmpfs");
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&16i32.to_be_bytes()); // recordLength
        data.extend_from_slice(b"fpmc"); // compression magic (big endian)
        data.extend_from_slice(&3i32.to_le_bytes()); // compression type (little endian)
        data.extend_from_slice(&0x1000i64.to_le_bytes()); // uncompressed size
        data.extend_from_slice(&[0u8; 8]);
        let mut r = reader(data);
        let rec = BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_LEAF_NODE))
            .unwrap();
        let h = rec.get_decmpfs_header().expect("decmpfs header");
        assert_eq!(h.get_compression_magic(), "fpmc");
        assert_eq!(h.get_compression_type(), 3);
        assert_eq!(h.get_uncompressed_size(), 0x1000);
    }

    #[test]
    fn decmpfs_leaf_record_with_negative_length_errors() {
        let mut data = record_prefix("com.apple.decmpfs");
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&(-1i32).to_be_bytes());
        let mut r = reader(data);
        assert!(
            BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_LEAF_NODE)).is_err()
        );
    }

    #[test]
    fn type_low_byte_is_sign_extended_like_java_char_cast() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&1i16.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x80]);
        data.extend_from_slice(&[0u8; 4]);
        let mut r = reader(data);
        let rec = BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_MAP_NODE))
            .unwrap();
        assert_eq!(rec.get_type(), "\u{FF80}");
    }

    #[test]
    fn truncated_record_errors() {
        let mut r = reader(vec![0u8; 10]);
        assert!(
            BTreeNodeRecord::new(&mut r, &descriptor(BTreeNodeKinds::K_BT_INDEX_NODE)).is_err()
        );
    }
}
