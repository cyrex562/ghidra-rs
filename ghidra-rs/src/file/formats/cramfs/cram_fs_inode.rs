use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

use super::cram_fs_constants::{CRAMFS_NAMELEN_WIDTH, CRAMFS_SIZE_WIDTH, CRAMFS_UID_WIDTH};

/// Stand-in for `StructConverter.DWORD` (`DWordDataType.dataType`), whose concrete singleton this
/// crate has not ported yet (see `struct_converter.rs`). Mirrors the identical local stand-ins in
/// `dex_header.rs`/`cdex_header.rs`; only its name and 4-byte length are observable here.
struct DWordDt;

impl DataType for DWordDt {
    fn get_name(&self) -> String {
        "dword".to_string()
    }

    fn get_length(&self) -> i32 {
        4
    }
}

/// Stand-in for `StructConverter.STRING` (`StringDataType.dataType`); see [`DWordDt`]. The
/// component length is supplied explicitly at the `add` call, matching Java's
/// `add(DataType, length, name, comment)` overload.
struct StringDt;

impl DataType for StringDt {
    fn get_name(&self) -> String {
        "string".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }
}

/// A cramfs inode (`struct cramfs_inode`).
///
/// Port of `ghidra.file.formats.cramfs.CramFsInode`.
///
/// On disk the inode is three packed little-endian 32-bit words:
/// `mode:16, uid:16`, `size:24, gid:8` and `namelen:6, offset:26`, followed by the name
/// (`namelen * 4` bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CramFsInode {
    mode: i32,
    uid: i32,
    /// 24-bit size.
    size: i32,
    /// 8-bit group id.
    gid: i32,
    namelen: i32,
    offset: i32,
    /// Not explicitly in `cramfs_inode`.
    name: String,
    /// Absolute address in the file, used for directory traversal.
    address: i64,
}

impl CramFsInode {
    /// Reads an inode at the reader's current position, advancing past it.
    ///
    /// The packed words are always decoded as little-endian regardless of the reader's
    /// endianness, as in Java.
    ///
    /// # Errors
    /// Returns `Err` if any read fails.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        // Before reader reads anything and progresses, get addr for start of inode.
        let address = reader.get_pointer_index() as i64;
        let mut mode_uid = reader.read_next_int()?;
        let mut size_gid = reader.read_next_int()?;
        let mut namelen_offset = reader.read_next_int()?;

        if reader.is_big_endian() {
            mode_uid = mode_uid.swap_bytes();
            size_gid = size_gid.swap_bytes();
            namelen_offset = namelen_offset.swap_bytes();
        }

        // Always read value as little endian. Java's `>>` is arithmetic on `int`; the trailing
        // masks discard the sign-extended bits, so the same expressions are used here.
        let uid = ((mode_uid & 0xffff0000u32 as i32) >> CRAMFS_UID_WIDTH) & 0x0000ffff;
        let mode = mode_uid & 0x0000ffff;

        let gid = ((size_gid & 0xff000000u32 as i32) >> CRAMFS_SIZE_WIDTH) & 0x000000ff;
        let size = size_gid & 0x00ffffff;

        let offset =
            ((namelen_offset & 0xffffffc0u32 as i32) >> CRAMFS_NAMELEN_WIDTH) & 0x0cffffff;
        let namelen = namelen_offset & 0x0000003f;

        let name = reader.read_next_ascii_string_fixed((namelen * 4) as usize)?;

        Ok(CramFsInode { mode, uid, size, gid, namelen, offset, name, address })
    }

    /// Builds the `cramfs_inode_<len>` structure returned by [`StructConverter::to_data_type`].
    fn build_structure(&self) -> Result<StructureDataTypeImpl, String> {
        let length = self.namelen * 4;

        let mut strukt = StructureDataTypeImpl::new(format!("cramfs_inode_{length}"), 0);
        strukt.add_with_name(Box::new(DWordDt), Some("modeUID".to_string()), None)?;
        strukt.add_with_name(Box::new(DWordDt), Some("sizeGID".to_string()), None)?;
        strukt.add_with_name(Box::new(DWordDt), Some("namelenOffset".to_string()), None)?;

        if self.namelen > 0 {
            strukt.add_with_length_and_name(
                Box::new(StringDt),
                length,
                Some("name".to_string()),
                None,
            )?;
        }
        Ok(strukt)
    }

    /// Returns the mode of the inode.
    pub fn mode(&self) -> i32 {
        self.mode
    }

    /// Returns the user identifier of the inode.
    pub fn uid(&self) -> i32 {
        self.uid
    }

    /// Returns the size of the inode.
    pub fn size(&self) -> i32 {
        self.size
    }

    /// Returns the group identifier of the inode.
    pub fn gid(&self) -> i32 {
        self.gid
    }

    /// Returns the name length of the inode, in 4-byte units.
    pub fn namelen(&self) -> i32 {
        self.namelen
    }

    /// Returns the offset of the inode, in 4-byte units.
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Returns the name of the inode.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the adjusted (byte) offset of the inode: `offset * 4`.
    pub fn offset_adjusted(&self) -> i32 {
        self.offset.wrapping_mul(4)
    }

    /// Returns true if the inode is a file.
    pub fn is_file(&self) -> bool {
        (self.mode & 0x8000) != 0
    }

    /// Returns true if the inode is a directory.
    pub fn is_directory(&self) -> bool {
        (self.mode & 0x4000) != 0
    }

    /// Returns the absolute address of the inode in the file.
    pub fn address(&self) -> i64 {
        self.address
    }
}

impl StructConverter for CramFsInode {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let strukt = self
            .build_structure()
            .map_err(|e| ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        Ok(Box::new(strukt))
    }
}

impl fmt::Display for CramFsInode {
    /// Mirrors `CramFsInode.toString()`; `Integer.toHexString` renders as unsigned hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "mode = 0x{:x} 16 MSB, UID = 0x{:x} 16 LSB", self.mode as u32, self.uid as u32)?;
        writeln!(f, "size = 0x{:x} 24 MSB,  GID = 0x{:x} 8 LSB", self.size as u32, self.gid as u32)?;
        writeln!(
            f,
            "namelen = 0x{:x} 6 MSB, offset = 0x{:x} 26 LSB",
            self.namelen as u32, self.offset as u32
        )?;

        if self.is_file() {
            writeln!(f, "Pointer to data = 0x{:x}", self.offset_adjusted() as u32)?;
        }

        if self.is_directory() {
            if self.offset == 0 {
                writeln!(f, "EMPTY DIRECTORY")?;
            } else {
                writeln!(f, "Pointer to next inode = 0x{:x}", self.offset_adjusted() as u32)?;
            }
        }
        Ok(())
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

    struct SimpleReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        pointer: u64,
        little_endian: bool,
    }

    impl BinaryReader for SimpleReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, little_endian: bool) {
            self.little_endian = little_endian;
        }
        fn get_pointer_index(&self) -> u64 {
            self.pointer
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pointer;
            self.pointer = index;
            old
        }
        fn read_byte_array(&self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, length)
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            self.provider.clone()
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(SimpleReader {
                provider: self.provider.clone(),
                pointer: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    fn reader(bytes: Vec<u8>, little_endian: bool, start: u64) -> SimpleReader {
        SimpleReader { provider: Rc::new(RefCell::new(VecStore(bytes))), pointer: start, little_endian }
    }

    /// Packs an inode the way `mkcramfs` writes it (little-endian words).
    fn inode_bytes(mode: u32, uid: u32, size: u32, gid: u32, offset: u32, name: &str) -> Vec<u8> {
        let namelen = (name.len() as u32).div_ceil(4);
        let mut v = Vec::new();
        v.extend(((uid << 16) | mode).to_le_bytes());
        v.extend(((gid << 24) | size).to_le_bytes());
        v.extend(((offset << 6) | namelen).to_le_bytes());
        let mut n = name.as_bytes().to_vec();
        n.resize((namelen * 4) as usize, 0);
        v.extend(n);
        v
    }

    #[test]
    fn decodes_packed_file_inode() {
        let mut bytes = vec![0xAA; 8];
        bytes.extend(inode_bytes(0x81a4, 0x03e8, 0x012345, 0x64, 0x1f0, "hello.txt"));
        let mut r = reader(bytes, true, 8);

        let inode = CramFsInode::new(&mut r).unwrap();
        assert_eq!(inode.address(), 8);
        assert_eq!(inode.mode(), 0x81a4);
        assert_eq!(inode.uid(), 0x03e8);
        assert_eq!(inode.size(), 0x012345);
        assert_eq!(inode.gid(), 0x64);
        assert_eq!(inode.namelen(), 3);
        assert_eq!(inode.offset(), 0x1f0);
        assert_eq!(inode.offset_adjusted(), 0x7c0);
        assert_eq!(inode.name(), "hello.txt");
        assert!(inode.is_file());
        assert!(!inode.is_directory());
        assert_eq!(r.get_pointer_index(), 8 + 12 + 12);
    }

    #[test]
    fn big_endian_reader_still_decodes_little_endian_words() {
        let bytes = inode_bytes(0x41ed, 0, 0x40, 0, 0x10, "dir");
        let mut le = reader(bytes.clone(), true, 0);
        let mut be = reader(bytes, false, 0);
        assert_eq!(CramFsInode::new(&mut le).unwrap(), CramFsInode::new(&mut be).unwrap());
    }

    #[test]
    fn high_bits_do_not_sign_extend() {
        // uid 0xffff, gid 0xff and the widest offset set the sign bit of each packed word.
        let bytes = inode_bytes(0x4000, 0xffff, 0xffffff, 0xff, 0x03ffffff, "");
        let inode = CramFsInode::new(&mut reader(bytes, true, 0)).unwrap();
        assert_eq!(inode.uid(), 0xffff);
        assert_eq!(inode.gid(), 0xff);
        assert_eq!(inode.size(), 0xffffff);
        // Java's arithmetic `>>` sign-extends the word 0xffffffc0 to 0xffffffff, and the
        // (odd) 0x0cffffff mask then keeps bits 26/27 -- the result is not the raw 26-bit field.
        assert_eq!(inode.offset(), 0x0cffffff);
        assert_eq!(inode.namelen(), 0);
        assert_eq!(inode.name(), "");
    }

    #[test]
    fn to_string_matches_java_for_file() {
        let bytes = inode_bytes(0x81a4, 0x03e8, 0x10, 0x64, 0x20, "a");
        let inode = CramFsInode::new(&mut reader(bytes, true, 0)).unwrap();
        assert_eq!(
            inode.to_string(),
            "mode = 0x81a4 16 MSB, UID = 0x3e8 16 LSB\n\
             size = 0x10 24 MSB,  GID = 0x64 8 LSB\n\
             namelen = 0x1 6 MSB, offset = 0x20 26 LSB\n\
             Pointer to data = 0x80\n"
        );
    }

    #[test]
    fn to_string_reports_empty_and_non_empty_directories() {
        let empty = CramFsInode::new(&mut reader(inode_bytes(0x41ed, 0, 0, 0, 0, ""), true, 0))
            .unwrap();
        assert!(empty.to_string().ends_with("EMPTY DIRECTORY\n"));

        let dir = CramFsInode::new(&mut reader(inode_bytes(0x41ed, 0, 0x40, 0, 0x10, "d"), true, 0))
            .unwrap();
        assert!(dir.to_string().ends_with("Pointer to next inode = 0x40\n"));
    }

    #[test]
    fn structure_has_three_dwords_and_optional_name() {
        let named = CramFsInode::new(&mut reader(inode_bytes(0x81a4, 0, 0, 0, 0, "abcdef"), true, 0))
            .unwrap();
        let s = named.build_structure().unwrap();
        assert_eq!(s.get_name(), "cramfs_inode_8");
        assert_eq!(s.get_num_components(), 4);
        assert_eq!(s.get_length(), 12 + 8);
        let names: Vec<_> = (0..4)
            .map(|i| s.get_component(i).unwrap().get_field_name().unwrap())
            .collect();
        assert_eq!(names, ["modeUID", "sizeGID", "namelenOffset", "name"]);

        let unnamed = CramFsInode::new(&mut reader(inode_bytes(0x41ed, 0, 0, 0, 0, ""), true, 0))
            .unwrap();
        let s = unnamed.build_structure().unwrap();
        assert_eq!(s.get_name(), "cramfs_inode_0");
        assert_eq!(s.get_num_components(), 3);
        assert_eq!(s.get_length(), 12);

        assert_eq!(named.to_data_type().unwrap().get_name(), "cramfs_inode_8");
    }
}
