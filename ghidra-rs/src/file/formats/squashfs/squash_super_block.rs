use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;

use super::squash_constants::{
    ALWAYS_FRAGMENT, COMPRESSION_OPTIONS_EXIST, COMPRESSION_TYPE_GZIP, COMPRESSION_TYPE_LZ4,
    COMPRESSION_TYPE_LZMA, COMPRESSION_TYPE_LZO, COMPRESSION_TYPE_XZ, COMPRESSION_TYPE_ZSTD,
    EXPORT_TABLE_EXISTS, NO_DUPLICATE_DATE, NO_FRAGMENTS, NO_XATTRS, SECTION_OMITTED,
    UNCOMPRESSED_DATA_BLOCKS, UNCOMPRESSED_FRAGMENTS, UNCOMPRESSED_IDS, UNCOMPRESSED_INODES,
    UNCOMPRESSED_XATTRS, UNUSED_FLAG,
};

/// Represents the SuperBlock (archive processing information) within a SquashFS archive.
///
/// Mirrors `ghidra.file.formats.squashfs.SquashSuperBlock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SquashSuperBlock {
    // ===== 32 bit integer values =====
    /// The magic for a Squash file. "HSQS" for little endian, "SQSH" for big endian.
    magic: i32,
    /// The number of inodes in the archive.
    inode_count: u32,
    /// Unix timestamp of the last time the archive was modified (not counting leap seconds).
    mod_time: u64,
    /// The size of a data block in bytes (must be a power of 2 between 4KB and 1 MiB).
    block_size: u32,
    /// The number of entries in the fragment table.
    total_fragments: u64,

    // ===== 16 bit short values =====
    /// The type of compression used.
    compression_type: u32,
    /// This should equal log2(block_size). If that's not the case, the archive is considered
    /// corrupt.
    block_log: u32,
    /// Flags with additional information about the archive.
    flags: u32,
    /// The number of entries in the ID lookup table.
    total_ids: u32,
    /// The major SquashFS version (should always be 4).
    major_version: u32,
    /// The minor SquashFS version (should always be 0).
    minor_version: u32,

    // ===== 64 bit long values =====
    /// A reference to the inode of the root directory. The upper 48 bits are the location
    /// where the metadata block resides; the lower 16 bits are the offset into the
    /// uncompressed metadata block where the inode starts.
    root_inode: i64,
    /// The number of bytes used by the archive. This may be less than the file size due to
    /// the total file size needing to be padded to be a multiple of the block size.
    bytes_used: i64,
    /// The byte offset to the start of the ID table.
    id_table_start: i64,
    /// The byte offset to the start of the XATTR ID table.
    xattr_id_table_start: i64,
    /// The byte offset to the start of the inode table.
    inode_table_start: i64,
    /// The byte offset to the start of the directory table.
    directory_table_start: i64,
    /// The byte offset to the start of the fragment table.
    fragment_table_start: i64,
    /// The byte offset to the start of the export table.
    export_table_start: i64,
}

impl SquashSuperBlock {
    /// Reads the SuperBlock (archive processing information) from the given binary reader.
    ///
    /// # Arguments
    /// * `reader` - A binary reader for the entire SquashFS archive.
    ///
    /// # Errors
    /// Returns `io::Error` if any read operation fails.
    pub fn read(reader: &mut GBinaryReader) -> io::Result<Self> {
        // Fetch the 32 bit integer fields.
        let magic = reader.read_next_int()?;
        // Java's readNextUnsignedIntExact only exists to fit an unsigned 32 bit value into a
        // signed Java int; a plain u32 already covers the full range, so no extra check is
        // needed here.
        let inode_count = reader.read_next_int()? as u32;
        let mod_time = reader.read_next_int()? as u32 as u64;
        let block_size = reader.read_next_int()? as u32;
        let total_fragments = reader.read_next_int()? as u32 as u64;

        // Fetch the 16 bit short fields.
        let compression_type = reader.read_next_short()? as u16 as u32;
        let block_log = reader.read_next_short()? as u16 as u32;
        let flags = reader.read_next_short()? as u16 as u32;
        let total_ids = reader.read_next_short()? as u16 as u32;
        let major_version = reader.read_next_short()? as u16 as u32;
        let minor_version = reader.read_next_short()? as u16 as u32;

        // Fetch the 64 bit long fields.
        let root_inode = reader.read_next_long()?;
        let bytes_used = reader.read_next_long()?;
        let id_table_start = reader.read_next_long()?;
        let xattr_id_table_start = reader.read_next_long()?;
        let inode_table_start = reader.read_next_long()?;
        let directory_table_start = reader.read_next_long()?;
        let fragment_table_start = reader.read_next_long()?;
        let export_table_start = reader.read_next_long()?;

        let super_block = SquashSuperBlock {
            magic,
            inode_count,
            mod_time,
            block_size,
            total_fragments,
            compression_type,
            block_log,
            flags,
            total_ids,
            major_version,
            minor_version,
            root_inode,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            export_table_start,
        };

        // Check that the SuperBlock values are what is expected by this FileSystem.
        super_block.check_compatibility();

        Ok(super_block)
    }

    pub fn get_magic(&self) -> i32 {
        self.magic
    }

    pub fn get_inode_count(&self) -> u32 {
        self.inode_count
    }

    pub fn get_mod_time(&self) -> u64 {
        self.mod_time
    }

    pub fn get_mod_time_as_date(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.mod_time)
    }

    pub fn get_block_size(&self) -> u64 {
        self.block_size as u64
    }

    pub fn get_total_fragments(&self) -> u64 {
        self.total_fragments
    }

    pub fn get_compression_type(&self) -> u32 {
        self.compression_type
    }

    pub fn get_block_log(&self) -> u32 {
        self.block_log
    }

    pub fn get_raw_flags(&self) -> u32 {
        self.flags
    }

    pub fn get_total_ids(&self) -> u32 {
        self.total_ids
    }

    pub fn get_major_version(&self) -> u32 {
        self.major_version
    }

    pub fn get_minor_version(&self) -> u32 {
        self.minor_version
    }

    pub fn get_root_inode(&self) -> i64 {
        self.root_inode
    }

    pub fn get_root_inode_block_location(&self) -> i64 {
        self.root_inode >> 16
    }

    pub fn get_root_inode_offset(&self) -> i64 {
        self.root_inode & 0xFFFF
    }

    pub fn get_bytes_used(&self) -> i64 {
        self.bytes_used
    }

    pub fn get_id_table_start(&self) -> i64 {
        self.id_table_start
    }

    pub fn get_xattr_id_table_start(&self) -> i64 {
        self.xattr_id_table_start
    }

    pub fn get_inode_table_start(&self) -> i64 {
        self.inode_table_start
    }

    pub fn get_directory_table_start(&self) -> i64 {
        self.directory_table_start
    }

    pub fn get_fragment_table_start(&self) -> i64 {
        self.fragment_table_start
    }

    pub fn get_export_table_start(&self) -> i64 {
        self.export_table_start
    }

    pub fn is_inodes_uncompressed(&self) -> bool {
        (self.flags & UNCOMPRESSED_INODES) != 0
    }

    pub fn is_data_uncompressed(&self) -> bool {
        (self.flags & UNCOMPRESSED_DATA_BLOCKS) != 0
    }

    pub fn is_used_flag_set(&self) -> bool {
        (self.flags & UNUSED_FLAG) != 0
    }

    pub fn is_fragments_uncompressed(&self) -> bool {
        (self.flags & UNCOMPRESSED_FRAGMENTS) != 0
    }

    pub fn is_fragments_unused(&self) -> bool {
        (self.flags & NO_FRAGMENTS) != 0
    }

    pub fn is_always_fragment(&self) -> bool {
        (self.flags & ALWAYS_FRAGMENT) != 0
    }

    pub fn allow_duplicates(&self) -> bool {
        (self.flags & NO_DUPLICATE_DATE) != 0
    }

    pub fn is_exportable(&self) -> bool {
        (self.flags & EXPORT_TABLE_EXISTS) != 0
    }

    pub fn is_xattrs_uncompressed(&self) -> bool {
        (self.flags & UNCOMPRESSED_XATTRS) != 0
    }

    pub fn has_xattrs(&self) -> bool {
        (self.flags & NO_XATTRS) != 0
    }

    pub fn is_compression_options_present(&self) -> bool {
        (self.flags & COMPRESSION_OPTIONS_EXIST) != 0
    }

    pub fn is_ids_uncompressed(&self) -> bool {
        (self.flags & UNCOMPRESSED_IDS) != 0
    }

    pub fn get_version_string(&self) -> String {
        format!("{}.{}", self.major_version, self.minor_version)
    }

    /// Validates the SuperBlock against expected values and warns of any possible issues.
    pub fn check_compatibility(&self) {
        // Verify the SquashFS version and warn if it isn't 4.0.
        if (self.major_version != 4) || (self.minor_version != 0) {
            tracing::warn!(
                "SquashFS archive is version {}.{} but Ghidra has only been tested with version 4.0",
                self.major_version,
                self.minor_version
            );
        }

        // Let the user know if the Xattr table is missing.
        if self.xattr_id_table_start == SECTION_OMITTED as i32 as i64 {
            tracing::info!("In SquashFS archive, the optional Xattr table is missing");
        }

        // Let the user know if the fragment table is missing.
        if self.fragment_table_start == SECTION_OMITTED as i32 as i64 {
            tracing::info!("In SquashFS archive, the optional fragment table is missing");
        }

        // Let the user know if the export table is missing.
        if self.export_table_start == SECTION_OMITTED as i32 as i64 {
            tracing::info!("In SquashFS archive, the optional export table is missing");
        }

        // Check if the unused flag is set and warn if it is.
        if self.is_used_flag_set() && (self.major_version >= 4) {
            tracing::warn!(
                "In SquashFS archive super block, the unused flag is set when it should \
                 be cleared. Per standard, the archive is invalid. Continue with caution!"
            );
        }

        // Check if block_log is correct and warn if not.
        if 1u32.wrapping_shl(self.block_log) != self.block_size {
            tracing::warn!(
                "In SquashFS archive super block, the blocksize does not match the blockLog value. \
                 Per standard, the archive is invalid. Continue with caution!"
            );
        }

        // Check if the flags for compressed inodes and compressed IDs match and warn if not.
        if (self.is_inodes_uncompressed() != self.is_ids_uncompressed()) && (self.major_version >= 4)
        {
            tracing::warn!(
                "In SquashFS archive super block, the flags for whether inodes and IDs \
                 are compressed should match. This is to maintain backwards compantability, \
                 but they differ in your archive. Continue with caution!"
            );
        }
    }

    pub fn get_compression_type_string(&self) -> String {
        match self.compression_type {
            COMPRESSION_TYPE_GZIP => "gzip",
            COMPRESSION_TYPE_LZMA => "lzma",
            COMPRESSION_TYPE_LZO => "lzo",
            COMPRESSION_TYPE_XZ => "xz",
            COMPRESSION_TYPE_LZ4 => "lz4-block",
            COMPRESSION_TYPE_ZSTD => "zstd",
            _ => "Unknown",
        }
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct TestProvider(Vec<u8>);

    impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for TestProvider {
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
            }
            Ok(self.0[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[idx] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "write past end"));
            }
            self.0[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    fn test_reader(data: Vec<u8>, little_endian: bool) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(TestProvider(data))), little_endian)
    }

    /// Builds a minimal, otherwise-valid little endian SuperBlock byte layout so tests can
    /// tweak individual fields.
    fn valid_super_block_bytes() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x73717368i32.to_le_bytes()); // magic ("hsqs")
        data.extend_from_slice(&10u32.to_le_bytes()); // inode_count
        data.extend_from_slice(&1_600_000_000u32.to_le_bytes()); // mod_time
        data.extend_from_slice(&131072u32.to_le_bytes()); // block_size = 2^17
        data.extend_from_slice(&2u32.to_le_bytes()); // total_fragments

        data.extend_from_slice(&1u16.to_le_bytes()); // compression_type = gzip
        data.extend_from_slice(&17u16.to_le_bytes()); // block_log = log2(131072)
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.extend_from_slice(&0u16.to_le_bytes()); // total_ids
        data.extend_from_slice(&4u16.to_le_bytes()); // major_version
        data.extend_from_slice(&0u16.to_le_bytes()); // minor_version

        data.extend_from_slice(&0x1234i64.to_le_bytes()); // root_inode
        data.extend_from_slice(&999i64.to_le_bytes()); // bytes_used
        data.extend_from_slice(&100i64.to_le_bytes()); // id_table_start
        data.extend_from_slice(&(-1i64).to_le_bytes()); // xattr_id_table_start (omitted)
        data.extend_from_slice(&200i64.to_le_bytes()); // inode_table_start
        data.extend_from_slice(&300i64.to_le_bytes()); // directory_table_start
        data.extend_from_slice(&(-1i64).to_le_bytes()); // fragment_table_start (omitted)
        data.extend_from_slice(&(-1i64).to_le_bytes()); // export_table_start (omitted)
        data
    }

    #[test]
    fn reads_all_fields() {
        let mut reader = test_reader(valid_super_block_bytes(), true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();

        assert_eq!(sb.get_magic(), 0x73717368);
        assert_eq!(sb.get_inode_count(), 10);
        assert_eq!(sb.get_mod_time(), 1_600_000_000);
        assert_eq!(sb.get_block_size(), 131072);
        assert_eq!(sb.get_total_fragments(), 2);
        assert_eq!(sb.get_compression_type(), 1);
        assert_eq!(sb.get_block_log(), 17);
        assert_eq!(sb.get_raw_flags(), 0);
        assert_eq!(sb.get_total_ids(), 0);
        assert_eq!(sb.get_major_version(), 4);
        assert_eq!(sb.get_minor_version(), 0);
        assert_eq!(sb.get_root_inode(), 0x1234);
        assert_eq!(sb.get_bytes_used(), 999);
        assert_eq!(sb.get_id_table_start(), 100);
        assert_eq!(sb.get_xattr_id_table_start(), -1);
        assert_eq!(sb.get_inode_table_start(), 200);
        assert_eq!(sb.get_directory_table_start(), 300);
        assert_eq!(sb.get_fragment_table_start(), -1);
        assert_eq!(sb.get_export_table_start(), -1);
    }

    #[test]
    fn root_inode_block_location_and_offset() {
        let mut data = valid_super_block_bytes();
        // root_inode is the 12th field group; overwrite its 8 bytes directly.
        let root_inode: i64 = (0xABCDi64 << 16) | 0x0F0F;
        let offset = 5 * 4 + 6 * 2; // 5 i32/u32 fields + 6 i16/u16 fields precede root_inode
        data[offset..offset + 8].copy_from_slice(&root_inode.to_le_bytes());
        let mut reader = test_reader(data, true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();

        assert_eq!(sb.get_root_inode_block_location(), 0xABCD);
        assert_eq!(sb.get_root_inode_offset(), 0x0F0F);
    }

    #[test]
    fn version_string_formats_major_and_minor() {
        let mut reader = test_reader(valid_super_block_bytes(), true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();
        assert_eq!(sb.get_version_string(), "4.0");
    }

    #[test]
    fn mod_time_as_date_converts_seconds_to_system_time() {
        let mut reader = test_reader(valid_super_block_bytes(), true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();
        assert_eq!(
            sb.get_mod_time_as_date(),
            UNIX_EPOCH + Duration::from_secs(1_600_000_000)
        );
    }

    #[test]
    fn compression_type_strings() {
        let cases = [
            (1u16, "gzip"),
            (2, "lzma"),
            (3, "lzo"),
            (4, "xz"),
            (5, "lz4-block"),
            (6, "zstd"),
            (99, "Unknown"),
        ];
        for (code, expected) in cases {
            let mut data = valid_super_block_bytes();
            data[20..22].copy_from_slice(&code.to_le_bytes()); // compression_type offset
            let mut reader = test_reader(data, true);
            let sb = SquashSuperBlock::read(&mut reader).unwrap();
            assert_eq!(sb.get_compression_type_string(), expected);
        }
    }

    #[test]
    fn flag_accessors_reflect_individual_bits() {
        let mut data = valid_super_block_bytes();
        let flags: u16 =
            (UNCOMPRESSED_INODES | EXPORT_TABLE_EXISTS | NO_XATTRS) as u16;
        data[24..26].copy_from_slice(&flags.to_le_bytes()); // flags offset
        let mut reader = test_reader(data, true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();

        assert!(sb.is_inodes_uncompressed());
        assert!(sb.is_exportable());
        assert!(sb.has_xattrs());
        assert!(!sb.is_data_uncompressed());
        assert!(!sb.is_fragments_uncompressed());
        assert!(!sb.is_always_fragment());
    }

    #[test]
    fn xattr_and_fragment_and_export_tables_report_omitted() {
        let mut reader = test_reader(valid_super_block_bytes(), true);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();
        // The fixture sets these three offsets to all-bits-set, matching SECTION_OMITTED
        // sign-extended to 64 bits (mirrors the Java int-to-long widening).
        assert_eq!(sb.get_xattr_id_table_start(), -1);
        assert_eq!(sb.get_fragment_table_start(), -1);
        assert_eq!(sb.get_export_table_start(), -1);
    }

    #[test]
    fn big_endian_round_trip() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x68737173i32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&4096u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&12u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        for _ in 0..8 {
            data.extend_from_slice(&(-1i64).to_be_bytes());
        }
        let mut reader = test_reader(data, false);
        let sb = SquashSuperBlock::read(&mut reader).unwrap();
        assert_eq!(sb.get_magic(), 0x68737173);
        assert_eq!(sb.get_block_size(), 4096);
        assert_eq!(sb.get_block_log(), 12);
    }

    #[test]
    fn struct_is_copy() {
        let mut reader = test_reader(valid_super_block_bytes(), true);
        let sb1 = SquashSuperBlock::read(&mut reader).unwrap();
        let sb2 = sb1;
        assert_eq!(sb1, sb2);
    }
}
