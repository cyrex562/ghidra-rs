use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

use super::squash_constants::{
    INODE_TYPE_BASIC_DIRECTORY, INODE_TYPE_BASIC_FILE, INODE_TYPE_BASIC_SYMLINK,
    INODE_TYPE_EXTENDED_DIRECTORY, INODE_TYPE_EXTENDED_FILE, INODE_TYPE_EXTENDED_SYMLINK,
};
use super::squash_directory_table_entry::SquashDirectoryTableEntry;
use super::squash_super_block::SquashSuperBlock;

/// The common header shared by every SquashFS inode, plus the tree links assigned after the
/// inode table has been read.
///
/// Port of the state and concrete methods of `ghidra.file.formats.squashfs.SquashInode`. Java's
/// `SquashInode` is the base class of the basic/extended file, directory, symlink and "other"
/// inodes; per the shape rules its fields live here and the hierarchy is expressed through the
/// [`SquashInode`] trait, which each concrete inode implements by exposing its embedded base.
///
/// Java links each inode to its parent by object reference. Inodes are owned by the inode table
/// (an array indexed by inode number), so here the parent is recorded as that inode number -- an
/// ID resolved against the table -- rather than as a shared pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashInodeBase {
    /// The type of inode as an integer.
    inode_type: i16,
    /// Unix file permissions bitmask.
    permissions: i16,
    /// Index into the ID table where the user ID of the owner resides.
    user_id: i32,
    /// Index into the ID table where the group ID of the owner resides.
    group_id: i32,
    /// Unix timestamp of the last time the inode was modified (not counting leap seconds).
    mod_time: i64,
    /// A unique number for this inode. Must be at least 1 and less than the total number of
    /// inodes.
    inode_number: i32,
    /// The parent of this inode, as its inode number, and whether that parent is a directory.
    parent: Option<(i32, bool)>,
    /// The directory table entry that refers to this inode.
    directory_table_entry: Option<SquashDirectoryTableEntry>,
}

impl SquashInodeBase {
    /// Reads the common inode header.
    ///
    /// * `reader` - A binary reader with pointer index at the start of the inode data.
    /// * `super_block` - The super block for the current archive (unused by the common header;
    ///   kept for parity with the Java constructor that every subclass calls).
    ///
    /// # Errors
    /// Returns `Err` on any read failure, or with [`io::ErrorKind::InvalidData`] if the inode
    /// number does not fit in a positive 32-bit Java `int` (Java's `readNextUnsignedIntExact`).
    pub fn new(reader: &mut GBinaryReader, _super_block: &SquashSuperBlock) -> io::Result<Self> {
        // Assign common inode header values
        let inode_type = reader.read_next_short()?;
        let permissions = reader.read_next_short()?;
        let user_id = reader.read_next_short()? as u16 as i32;
        let group_id = reader.read_next_short()? as u16 as i32;
        let mod_time = reader.read_next_int()? as u32 as i64;
        let raw_number = reader.read_next_int()? as u32;
        let inode_number = i32::try_from(raw_number).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Value out of range for positive java 32 bit unsigned int: {raw_number}"),
            )
        })?;

        Ok(SquashInodeBase {
            inode_type,
            permissions,
            user_id,
            group_id,
            mod_time,
            inode_number,
            parent: None,
            directory_table_entry: None,
        })
    }

    /// Returns the Unix permissions bitmask.
    pub fn permissions(&self) -> i16 {
        self.permissions
    }

    /// Returns the inode type.
    pub fn inode_type(&self) -> i16 {
        self.inode_type
    }

    /// Returns the index into the ID table of the owner's user ID.
    pub fn user_id(&self) -> i32 {
        self.user_id
    }

    /// Returns the index into the ID table of the owner's group ID.
    pub fn group_id(&self) -> i32 {
        self.group_id
    }

    /// Returns the modification time, in seconds since the Unix epoch.
    pub fn mod_time(&self) -> i64 {
        self.mod_time
    }

    /// Returns the modification time as a [`SystemTime`] (Java: `new Date(modTime * 1000)`).
    pub fn mod_time_as_date(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.mod_time as u64)
    }

    /// Returns this inode's number.
    pub fn number(&self) -> i32 {
        self.inode_number
    }

    /// Records `parent_inode` as this inode's parent.
    pub fn set_parent(&mut self, parent_inode: &SquashInodeBase) {
        self.parent = Some((parent_inode.inode_number, parent_inode.is_dir()));
    }

    /// Returns the inode number of this inode's parent directory, or `None` if the parent is not
    /// a directory (Java returns `null`) or no parent has been assigned.
    ///
    /// Java returns the parent `SquashBasicDirectoryInode` itself; callers resolve the number
    /// against the inode table that owns the inodes.
    pub fn parent(&self) -> Option<i32> {
        match self.parent {
            Some((number, true)) => Some(number),
            _ => None,
        }
    }

    /// Records the directory table entry that refers to this inode.
    pub fn set_directory_table_entry(&mut self, entry: SquashDirectoryTableEntry) {
        self.directory_table_entry = Some(entry);
    }

    /// Returns the directory table entry that refers to this inode, if one has been assigned.
    pub fn directory_table_entry(&self) -> Option<&SquashDirectoryTableEntry> {
        self.directory_table_entry.as_ref()
    }

    /// Returns true if this is a basic or extended directory inode.
    pub fn is_dir(&self) -> bool {
        self.type_is(INODE_TYPE_BASIC_DIRECTORY) || self.type_is(INODE_TYPE_EXTENDED_DIRECTORY)
    }

    /// Returns true if this is a basic or extended file inode.
    pub fn is_file(&self) -> bool {
        self.type_is(INODE_TYPE_BASIC_FILE) || self.type_is(INODE_TYPE_EXTENDED_FILE)
    }

    /// Returns true if this is a basic or extended symlink inode.
    pub fn is_sym_link(&self) -> bool {
        self.type_is(INODE_TYPE_BASIC_SYMLINK) || self.type_is(INODE_TYPE_EXTENDED_SYMLINK)
    }

    /// Java compares the `short` type against an `int` constant, sign-extending the short.
    fn type_is(&self, constant: u32) -> bool {
        self.inode_type as i32 == constant as i32
    }
}

/// A SquashFS inode.
///
/// Port of the `ghidra.file.formats.squashfs.SquashInode` hierarchy: every concrete inode (basic
/// and extended file/directory, symlink, other) embeds a [`SquashInodeBase`] holding the common
/// header, and exposes it through this trait. Java's base class declares no abstract methods, so
/// the trait carries only the accessors to that shared state.
pub trait SquashInode {
    /// Returns the common inode header.
    fn base(&self) -> &SquashInodeBase;

    /// Returns the common inode header, mutably.
    fn base_mut(&mut self) -> &mut SquashInodeBase;
}

/// Java's `SquashInode` is itself instantiable; the bare header is a valid inode.
impl SquashInode for SquashInodeBase {
    fn base(&self) -> &SquashInodeBase {
        self
    }

    fn base_mut(&mut self) -> &mut SquashInodeBase {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::GByteStore;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct VecStore(Vec<u8>);

    impl GByteStore for VecStore {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.0.len()
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Ok(())
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    fn reader(bytes: Vec<u8>) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecStore(bytes))), true)
    }

    /// A minimal 96-byte little-endian SquashFS 4.0 super block.
    fn super_block() -> SquashSuperBlock {
        let mut sb = vec![0u8; 96];
        sb[0..4].copy_from_slice(&0x7371_7368u32.to_le_bytes()); // "hsqs"
        sb[12..16].copy_from_slice(&0x2_0000u32.to_le_bytes()); // block size
        sb[20..22].copy_from_slice(&1u16.to_le_bytes()); // compression: gzip
        sb[22..24].copy_from_slice(&17u16.to_le_bytes()); // block log
        sb[28..30].copy_from_slice(&4u16.to_le_bytes()); // major version
        SquashSuperBlock::read(&mut reader(sb)).expect("valid super block")
    }

    fn header(inode_type: u16, perms: u16, uid: u16, gid: u16, mtime: u32, number: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(inode_type.to_le_bytes());
        v.extend(perms.to_le_bytes());
        v.extend(uid.to_le_bytes());
        v.extend(gid.to_le_bytes());
        v.extend(mtime.to_le_bytes());
        v.extend(number.to_le_bytes());
        v
    }

    fn read(bytes: Vec<u8>) -> io::Result<SquashInodeBase> {
        let sb = super_block();
        let mut r = reader(bytes);
        let inode = SquashInodeBase::new(&mut r, &sb);
        if inode.is_ok() {
            assert_eq!(r.get_pointer_index(), 16);
        }
        inode
    }

    #[test]
    fn reads_common_header() {
        let inode = read(header(2, 0o644, 0xfffe, 3, 0xffff_fff0, 42)).unwrap();
        assert_eq!(inode.inode_type(), 2);
        assert_eq!(inode.permissions(), 0o644);
        // uid/gid and mtime are unsigned.
        assert_eq!(inode.user_id(), 0xfffe);
        assert_eq!(inode.group_id(), 3);
        assert_eq!(inode.mod_time(), 0xffff_fff0);
        assert_eq!(inode.mod_time_as_date(), UNIX_EPOCH + Duration::from_secs(0xffff_fff0));
        assert_eq!(inode.number(), 42);
        assert!(inode.is_file());
        assert!(!inode.is_dir());
        assert!(!inode.is_sym_link());
        assert_eq!(inode.parent(), None);
        assert!(inode.directory_table_entry().is_none());
    }

    #[test]
    fn permissions_are_a_signed_short() {
        let inode = read(header(1, 0xffff, 0, 0, 0, 1)).unwrap();
        assert_eq!(inode.permissions(), -1);
    }

    #[test]
    fn inode_number_above_int_max_is_rejected() {
        let err = read(header(1, 0, 0, 0, 0, 0x8000_0000)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("2147483648"));
        assert_eq!(read(header(1, 0, 0, 0, 0, 0x7fff_ffff)).unwrap().number(), i32::MAX);
    }

    #[test]
    fn type_predicates_cover_basic_and_extended_kinds() {
        let kind = |t: u16| read(header(t, 0, 0, 0, 0, 1)).unwrap();
        assert!(kind(1).is_dir() && kind(8).is_dir());
        assert!(kind(2).is_file() && kind(9).is_file());
        assert!(kind(3).is_sym_link() && kind(10).is_sym_link());
        for other in [4u16, 5, 6, 7, 11, 12, 13, 14] {
            let i = kind(other);
            assert!(!i.is_dir() && !i.is_file() && !i.is_sym_link(), "type {other}");
        }
    }

    #[test]
    fn parent_is_only_reported_when_it_is_a_directory() {
        let dir = read(header(8, 0, 0, 0, 0, 1)).unwrap();
        let file = read(header(2, 0, 0, 0, 0, 2)).unwrap();
        let mut child = read(header(2, 0, 0, 0, 0, 3)).unwrap();

        child.set_parent(&dir);
        assert_eq!(child.parent(), Some(1));

        child.set_parent(&file);
        assert_eq!(child.parent(), None);
    }

    #[test]
    fn directory_table_entry_round_trips_through_trait() {
        let mut entry_bytes = Vec::new();
        entry_bytes.extend(0u16.to_le_bytes()); // offset
        entry_bytes.extend(2i16.to_le_bytes()); // inode offset
        entry_bytes.extend(2u16.to_le_bytes()); // type
        entry_bytes.extend(2u16.to_le_bytes()); // name size - 1
        entry_bytes.extend(b"foo");
        let entry = SquashDirectoryTableEntry::read(&mut reader(entry_bytes), 5).unwrap();

        let mut inode: Box<dyn SquashInode> = Box::new(read(header(2, 0, 0, 0, 0, 7)).unwrap());
        inode.base_mut().set_directory_table_entry(entry.clone());
        assert_eq!(inode.base().directory_table_entry(), Some(&entry));
        assert_eq!(inode.base().directory_table_entry().unwrap().get_inode_number(), 7);
    }
}
