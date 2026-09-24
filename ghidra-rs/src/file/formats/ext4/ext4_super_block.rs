//! Port of `ghidra.file.formats.ext4.Ext4SuperBlock`.
//!
//! The Java class is a concrete `class Ext4SuperBlock implements StructConverter` that nothing
//! extends, so it ports to a `struct` + `impl`. Its 91 `s_*` members are plain on-disk values
//! with one trivial `getS_*()` getter each; here they are public read-only fields instead of a
//! getter per field. The derived accessors (`getS_blocks_count`, `getBlockSize`, `getNumGroups`,
//! `getVolumeName`, `getLastMountedString`, `isValid`, `is64Bit`, `isInlineData`,
//! `isDirEntry2`) are methods.
//!
//! Field signedness follows the Java declarations (`int` -> `i32`, `short` -> `i16`,
//! `byte` -> `i8`, `long` -> `i64`); the fixed-length `byte[]`/`int[]` members become fixed-size
//! arrays of the lengths the constructor reads.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::ext4::ext4_constants;
use crate::format::macos::data_type_stand_ins::PrimitiveDt;
use crate::program::model::data::array_data_type::ArrayDataType;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;

/// Maximum number of blocks per block group accepted by [`Ext4SuperBlock::get_num_groups`].
///
/// Port of the private `Ext4SuperBlock.MAX_BLOCKS_PER_GROUP` constant.
const MAX_BLOCKS_PER_GROUP: i32 = 1 << 19;

/// The ext4 on-disk superblock (`struct ext4_super_block`, 1024 bytes, little-endian).
///
/// Port of `ghidra.file.formats.ext4.Ext4SuperBlock`. Fields are named exactly as the Java
/// members (which mirror the Linux kernel's `ext4_super_block`) and appear in on-disk order.
///
/// Notes carried over from the Java source:
/// - `s_first_ino` through `s_feature_ro_compat` are only meaningful for `EXT4_DYNAMIC_REV`
///   superblocks (`s_rev_level == 1`).
/// - Directory preallocation (`s_prealloc_blocks`, `s_prealloc_dir_blocks`) applies only if
///   `EXT4_FEATURE_COMPAT_DIR_PREALLOC` is set (`s_feature_compat & 0x1 != 0`).
/// - The journaling members (`s_journal_uuid` ..) are valid if `EXT4_FEATURE_COMPAT_HAS_JOURNAL`
///   is set (`s_feature_compat & 0x4 != 0`).
/// - The `*_hi` 64-bit members are valid if `EXT4_FEATURE_INCOMPAT_64BIT` is set
///   (`s_feature_incompat & 0x80 != 0`).
/// - `s_inodes_count`, `s_log_block_size` and `s_blocks_per_group` are read as unsigned 32-bit
///   values and rejected if they exceed `i32::MAX` (Java's `readNextUnsignedIntExact`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4SuperBlock {
pub s_inodes_count: i32,
    pub s_blocks_count_lo: i32,
    pub s_r_blocks_count_lo: i32,
    pub s_free_blocks_count_lo: i32,
    pub s_free_inodes_count: i32,
    pub s_first_data_block: i32,
    pub s_log_block_size: i32,
    pub s_log_cluster_size: i32,
    pub s_blocks_per_group: i32,
    pub s_clusters_per_group: i32,
    pub s_inodes_per_group: i32,
    pub s_mtime: i32,
    pub s_wtime: i32,
    pub s_mnt_count: i16,
    pub s_max_mnt_count: i16,
    pub s_magic: i16,
    pub s_state: i16,
    pub s_errors: i16,
    pub s_minor_rev_level: i16,
    pub s_lastcheck: i32,
    pub s_checkinterval: i32,
    pub s_creator_os: i32,
    pub s_rev_level: i32,
    pub s_def_resuid: i16,
    pub s_def_resgid: i16,
    pub s_first_ino: i32,
    pub s_inode_size: i16,
    pub s_block_group_nr: i16,
    pub s_feature_compat: i32,
    pub s_feature_incompat: i32,
    pub s_feature_ro_compat: i32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: i32,
    pub s_prealloc_blocks: i8,
    pub s_prealloc_dir_blocks: i8,
    pub s_reserved_gdt_blocks: i16,
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: i32,
    pub s_journal_dev: i32,
    pub s_last_orphan: i32,
    pub s_hash_seed: [i32; 4],
    pub s_def_hash_version: i8,
    pub s_jnl_backup_type: i8,
    pub s_desc_size: i16,
    pub s_default_mount_opts: i32,
    pub s_first_meta_bg: i32,
    pub s_mkfs_time: i32,
    pub s_jnl_blocks: [i32; 17],
    pub s_blocks_count_hi: i32,
    pub s_r_blocks_count_hi: i32,
    pub s_free_blocks_count_hi: i32,
    pub s_min_extra_isize: i16,
    pub s_want_extra_isize: i16,
    pub s_flags: i32,
    pub s_raid_stride: i16,
    pub s_mmp_interval: i16,
    pub s_mmp_block: i64,
    pub s_raid_stripe_width: i32,
    pub s_log_groups_per_flex: i8,
    pub s_checksum_type: i8,
    pub s_reserved_pad: i16,
    pub s_kbytes_written: i64,
    pub s_snapshot_inum: i32,
    pub s_snapshot_id: i32,
    pub s_snapshot_r_blocks_count: i64,
    pub s_snapshot_list: i32,
    pub s_error_count: i32,
    pub s_first_error_time: i32,
    pub s_first_error_ino: i32,
    pub s_first_error_block: i64,
    pub s_first_error_func: [u8; 32],
    pub s_first_error_line: i32,
    pub s_last_error_time: i32,
    pub s_last_error_ino: i32,
    pub s_last_error_line: i32,
    pub s_last_error_block: i64,
    pub s_last_error_func: [u8; 32],
    pub s_mount_opts: [u8; 64],
    pub s_usr_quora_inum: i32,
    pub s_grp_quota_inum: i32,
    pub s_overhead_blocks: i32,
    pub s_backup_blocks: [i32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: i32,
    pub s_prj_quota_inum: i32,
    pub s_checksum_seed: i32,
    pub s_reserved: [i32; 98],
    pub s_checksum: i32,
}

/// How a superblock member is laid out in the structure built by
/// [`Ext4SuperBlock::to_data_type`].
#[derive(Debug, Clone, Copy)]
enum FieldKind {
    Byte,
    Word,
    Dword,
    Qword,
    /// `ArrayDataType(BYTE, n, 1)`.
    Bytes(i32),
    /// `ArrayDataType(DWORD, n, 4)`.
    Dwords(i32),
}

/// The superblock's members in on-disk order, as added by Java's `toDataType()`.
const FIELDS: &[(&str, FieldKind)] = &[
    ("s_inodes_count", FieldKind::Dword),
    ("s_blocks_count_lo", FieldKind::Dword),
    ("s_r_blocks_count_lo", FieldKind::Dword),
    ("s_free_blocks_count_lo", FieldKind::Dword),
    ("s_free_inodes_count", FieldKind::Dword),
    ("s_first_data_block", FieldKind::Dword),
    ("s_log_block_size", FieldKind::Dword),
    ("s_log_cluster_size", FieldKind::Dword),
    ("s_blocks_per_group", FieldKind::Dword),
    ("s_clusters_per_group", FieldKind::Dword),
    ("s_inodes_per_group", FieldKind::Dword),
    ("s_mtime", FieldKind::Dword),
    ("s_wtime", FieldKind::Dword),
    ("s_mnt_count", FieldKind::Word),
    ("s_max_mnt_count", FieldKind::Word),
    ("s_magic", FieldKind::Word),
    ("s_state", FieldKind::Word),
    ("s_errors", FieldKind::Word),
    ("s_minor_rev_level", FieldKind::Word),
    ("s_lastcheck", FieldKind::Dword),
    ("s_checkinterval", FieldKind::Dword),
    ("s_creator_os", FieldKind::Dword),
    ("s_rev_level", FieldKind::Dword),
    ("s_def_resuid", FieldKind::Word),
    ("s_def_resgid", FieldKind::Word),
    ("s_first_ino", FieldKind::Dword),
    ("s_inode_size", FieldKind::Word),
    ("s_block_group_nr", FieldKind::Word),
    ("s_feature_compat", FieldKind::Dword),
    ("s_feature_incompat", FieldKind::Dword),
    ("s_feature_ro_compat", FieldKind::Dword),
    ("s_uuid", FieldKind::Bytes(16)),
    ("s_volume_name", FieldKind::Bytes(16)),
    ("s_last_mounted", FieldKind::Bytes(64)),
    ("s_algorithm_usage_bitmap", FieldKind::Dword),
    ("s_prealloc_blocks", FieldKind::Byte),
    ("s_prealloc_dir_blocks", FieldKind::Byte),
    ("s_reserved_gdt_blocks", FieldKind::Word),
    ("s_journal_uuid", FieldKind::Bytes(16)),
    ("s_journal_inum", FieldKind::Dword),
    ("s_journal_dev", FieldKind::Dword),
    ("s_last_orphan", FieldKind::Dword),
    ("s_hash_seed", FieldKind::Dwords(4)),
    ("s_def_hash_version", FieldKind::Byte),
    ("s_jnl_backup_type", FieldKind::Byte),
    ("s_desc_size", FieldKind::Word),
    ("s_default_mount_opts", FieldKind::Dword),
    ("s_first_meta_bg", FieldKind::Dword),
    ("s_mkfs_time", FieldKind::Dword),
    ("s_jnl_blocks", FieldKind::Dwords(17)),
    ("s_blocks_count_hi", FieldKind::Dword),
    ("s_r_blocks_count_hi", FieldKind::Dword),
    ("s_free_blocks_count_hi", FieldKind::Dword),
    ("s_min_extra_isize", FieldKind::Word),
    ("s_want_extra_isize", FieldKind::Word),
    ("s_flags", FieldKind::Dword),
    ("s_raid_stride", FieldKind::Word),
    ("s_mmp_interval", FieldKind::Word),
    ("s_mmp_block", FieldKind::Qword),
    ("s_raid_stripe_width", FieldKind::Dword),
    ("s_log_groups_per_flex", FieldKind::Byte),
    ("s_checksum_type", FieldKind::Byte),
    ("s_reserved_pad", FieldKind::Word),
    ("s_kbytes_written", FieldKind::Qword),
    ("s_snapshot_inum", FieldKind::Dword),
    ("s_snapshot_id", FieldKind::Dword),
    ("s_snapshot_r_blocks_count", FieldKind::Qword),
    ("s_snapshot_list", FieldKind::Dword),
    ("s_error_count", FieldKind::Dword),
    ("s_first_error_time", FieldKind::Dword),
    ("s_first_error_ino", FieldKind::Dword),
    ("s_first_error_block", FieldKind::Qword),
    ("s_first_error_func", FieldKind::Bytes(32)),
    ("s_first_error_line", FieldKind::Dword),
    ("s_last_error_time", FieldKind::Dword),
    ("s_last_error_ino", FieldKind::Dword),
    ("s_last_error_line", FieldKind::Dword),
    ("s_last_error_block", FieldKind::Qword),
    ("s_last_error_func", FieldKind::Bytes(32)),
    ("s_mount_opts", FieldKind::Bytes(64)),
    ("s_usr_quora_inum", FieldKind::Dword),
    ("s_grp_quota_inum", FieldKind::Dword),
    ("s_overhead_blocks", FieldKind::Dword),
    ("s_backup_blocks", FieldKind::Dwords(2)),
    ("s_encrypt_algos", FieldKind::Bytes(4)),
    ("s_encrypt_pw_salt", FieldKind::Bytes(16)),
    ("s_lpf_ino", FieldKind::Dword),
    ("s_prj_quota_inum", FieldKind::Dword),
    ("s_checksum_seed", FieldKind::Dword),
    ("s_reserved", FieldKind::Dwords(98)),
    ("s_checksum", FieldKind::Dword),
];

/// Reads an unsigned 32-bit value that must fit in an `i32`.
///
/// Mirrors Java's `readNextUnsignedIntExact()` including its `ensureInt32u` range check (the
/// crate's `BinaryReader::read_next_unsigned_int_exact` returns a `u32` and skips that check).
fn read_u32_exact(reader: &mut dyn BinaryReader) -> io::Result<i32> {
    let value = reader.read_next_unsigned_int()?;
    i32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Value out of range for positive java 32 bit unsigned int: {value}"),
        )
    })
}

fn read_bytes<const N: usize>(reader: &mut dyn BinaryReader) -> io::Result<[u8; N]> {
    let bytes = reader.read_next_byte_array(N)?;
    bytes.try_into().map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "short read"))
}

fn read_ints<const N: usize>(reader: &mut dyn BinaryReader) -> io::Result<[i32; N]> {
    let ints = reader.read_next_int_array(N)?;
    ints.try_into().map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "short read"))
}

impl Ext4SuperBlock {
    /// Reads a superblock from the start of a byte provider, in little-endian order.
    ///
    /// Port of `Ext4SuperBlock(ByteProvider)`, which wraps the provider in a fresh little-endian
    /// `BinaryReader`. Here the caller passes a reader over the provider; it is switched to
    /// little-endian and repositioned to index 0 to match.
    pub fn from_provider_reader(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        reader.set_little_endian(true);
        reader.set_pointer_index(0);
        Self::new(reader)
    }

    /// Reads a superblock at the reader's current position, leaving the reader just past it.
    ///
    /// Port of `Ext4SuperBlock(BinaryReader)`.
    ///
    /// # Errors
    /// Any read error, or `InvalidData` if `s_inodes_count`, `s_log_block_size` or
    /// `s_blocks_per_group` does not fit in an `i32`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(Self {
            s_inodes_count: read_u32_exact(reader)?,
            s_blocks_count_lo: reader.read_next_int()?,
            s_r_blocks_count_lo: reader.read_next_int()?,
            s_free_blocks_count_lo: reader.read_next_int()?,
            s_free_inodes_count: reader.read_next_int()?,
            s_first_data_block: reader.read_next_int()?,
            s_log_block_size: read_u32_exact(reader)?,
            s_log_cluster_size: reader.read_next_int()?,
            s_blocks_per_group: read_u32_exact(reader)?,
            s_clusters_per_group: reader.read_next_int()?,
            s_inodes_per_group: reader.read_next_int()?,
            s_mtime: reader.read_next_int()?,
            s_wtime: reader.read_next_int()?,
            s_mnt_count: reader.read_next_short()?,
            s_max_mnt_count: reader.read_next_short()?,
            s_magic: reader.read_next_short()?,
            s_state: reader.read_next_short()?,
            s_errors: reader.read_next_short()?,
            s_minor_rev_level: reader.read_next_short()?,
            s_lastcheck: reader.read_next_int()?,
            s_checkinterval: reader.read_next_int()?,
            s_creator_os: reader.read_next_int()?,
            s_rev_level: reader.read_next_int()?,
            s_def_resuid: reader.read_next_short()?,
            s_def_resgid: reader.read_next_short()?,
            s_first_ino: reader.read_next_int()?,
            s_inode_size: reader.read_next_short()?,
            s_block_group_nr: reader.read_next_short()?,
            s_feature_compat: reader.read_next_int()?,
            s_feature_incompat: reader.read_next_int()?,
            s_feature_ro_compat: reader.read_next_int()?,
            s_uuid: read_bytes::<16>(reader)?,
            s_volume_name: read_bytes::<16>(reader)?,
            s_last_mounted: read_bytes::<64>(reader)?,
            s_algorithm_usage_bitmap: reader.read_next_int()?,
            s_prealloc_blocks: reader.read_next_byte()? as i8,
            s_prealloc_dir_blocks: reader.read_next_byte()? as i8,
            s_reserved_gdt_blocks: reader.read_next_short()?,
            s_journal_uuid: read_bytes::<16>(reader)?,
            s_journal_inum: reader.read_next_int()?,
            s_journal_dev: reader.read_next_int()?,
            s_last_orphan: reader.read_next_int()?,
            s_hash_seed: read_ints::<4>(reader)?,
            s_def_hash_version: reader.read_next_byte()? as i8,
            s_jnl_backup_type: reader.read_next_byte()? as i8,
            s_desc_size: reader.read_next_short()?,
            s_default_mount_opts: reader.read_next_int()?,
            s_first_meta_bg: reader.read_next_int()?,
            s_mkfs_time: reader.read_next_int()?,
            s_jnl_blocks: read_ints::<17>(reader)?,
            s_blocks_count_hi: reader.read_next_int()?,
            s_r_blocks_count_hi: reader.read_next_int()?,
            s_free_blocks_count_hi: reader.read_next_int()?,
            s_min_extra_isize: reader.read_next_short()?,
            s_want_extra_isize: reader.read_next_short()?,
            s_flags: reader.read_next_int()?,
            s_raid_stride: reader.read_next_short()?,
            s_mmp_interval: reader.read_next_short()?,
            s_mmp_block: reader.read_next_long()?,
            s_raid_stripe_width: reader.read_next_int()?,
            s_log_groups_per_flex: reader.read_next_byte()? as i8,
            s_checksum_type: reader.read_next_byte()? as i8,
            s_reserved_pad: reader.read_next_short()?,
            s_kbytes_written: reader.read_next_long()?,
            s_snapshot_inum: reader.read_next_int()?,
            s_snapshot_id: reader.read_next_int()?,
            s_snapshot_r_blocks_count: reader.read_next_long()?,
            s_snapshot_list: reader.read_next_int()?,
            s_error_count: reader.read_next_int()?,
            s_first_error_time: reader.read_next_int()?,
            s_first_error_ino: reader.read_next_int()?,
            s_first_error_block: reader.read_next_long()?,
            s_first_error_func: read_bytes::<32>(reader)?,
            s_first_error_line: reader.read_next_int()?,
            s_last_error_time: reader.read_next_int()?,
            s_last_error_ino: reader.read_next_int()?,
            s_last_error_line: reader.read_next_int()?,
            s_last_error_block: reader.read_next_long()?,
            s_last_error_func: read_bytes::<32>(reader)?,
            s_mount_opts: read_bytes::<64>(reader)?,
            s_usr_quora_inum: reader.read_next_int()?,
            s_grp_quota_inum: reader.read_next_int()?,
            s_overhead_blocks: reader.read_next_int()?,
            s_backup_blocks: read_ints::<2>(reader)?,
            s_encrypt_algos: read_bytes::<4>(reader)?,
            s_encrypt_pw_salt: read_bytes::<16>(reader)?,
            s_lpf_ino: reader.read_next_int()?,
            s_prj_quota_inum: reader.read_next_int()?,
            s_checksum_seed: reader.read_next_int()?,
            s_reserved: read_ints::<98>(reader)?,
            s_checksum: reader.read_next_int()?,
        })
    }

    /// Returns the block count formed by combining `s_blocks_count_lo` (unsigned) with
    /// `s_blocks_count_hi`.
    ///
    /// Port of `getS_blocks_count()`.
    pub fn get_s_blocks_count(&self) -> i64 {
        (i64::from(self.s_blocks_count_hi) << 32) | i64::from(self.s_blocks_count_lo as u32)
    }

    /// Returns the filesystem block size, `1 << (10 + s_log_block_size)`.
    ///
    /// Port of `getBlockSize()`.
    ///
    /// # Errors
    /// `InvalidData` ("Blocksize out of range") if `s_log_block_size > 6`.
    pub fn get_block_size(&self) -> io::Result<i32> {
        if self.s_log_block_size > 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Blocksize out of range: {}", self.s_log_block_size),
            ));
        }
        Ok(1 << (10 + self.s_log_block_size))
    }

    /// Returns the number of block groups: the block count divided by `s_blocks_per_group`,
    /// rounded up.
    ///
    /// Port of `getNumGroups()`.
    ///
    /// # Errors
    /// Propagates [`get_block_size`](Self::get_block_size)'s error, and `InvalidData`
    /// ("Bad blocks per group") if `s_blocks_per_group` is below the block size or above
    /// `1 << 19`.
    pub fn get_num_groups(&self) -> io::Result<i64> {
        let bs = self.get_block_size()?;
        if self.s_blocks_per_group < bs || self.s_blocks_per_group > MAX_BLOCKS_PER_GROUP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Bad blocks per group: {}", self.s_blocks_per_group),
            ));
        }
        let block_count = self.get_s_blocks_count();
        let per_group = i64::from(self.s_blocks_per_group);
        let mut num_groups = block_count / per_group;
        if block_count % per_group != 0 {
            num_groups += 1;
        }
        Ok(num_groups)
    }

    /// Returns `s_volume_name` decoded as a string.
    ///
    /// Port of `getVolumeName()`.
    pub fn get_volume_name(&self) -> String {
        sb_string(&self.s_volume_name)
    }

    /// Returns `s_last_mounted` decoded as a string.
    ///
    /// Port of `getLastMountedString()`.
    pub fn get_last_mounted_string(&self) -> String {
        sb_string(&self.s_last_mounted)
    }

    /// Returns true if `s_magic` is the ext4 superblock magic (`0xEF53`).
    ///
    /// Port of `isValid()`.
    pub fn is_valid(&self) -> bool {
        i32::from(self.s_magic as u16) == ext4_constants::SUPER_BLOCK_MAGIC
    }

    /// Returns true if group descriptors are 64-bit: `s_desc_size > 32` and the
    /// `INCOMPAT_64BIT` feature is set.
    ///
    /// Port of `is64Bit()`.
    pub fn is_64_bit(&self) -> bool {
        self.s_desc_size > 32 && (self.s_feature_incompat & ext4_constants::INCOMPAT_64BIT) != 0
    }

    /// Returns true if the `INCOMPAT_INLINE_DATA` feature is set.
    ///
    /// Port of `isInlineData()`.
    pub fn is_inline_data(&self) -> bool {
        (self.s_feature_incompat & ext4_constants::INCOMPAT_INLINE_DATA) != 0
    }

    /// Returns true if directory entries carry a file type (`INCOMPAT_FILETYPE`), i.e. use the
    /// `ext4_dir_entry_2` layout.
    ///
    /// Port of `isDirEntry2()`.
    pub fn is_dir_entry2(&self) -> bool {
        (self.s_feature_incompat & ext4_constants::INCOMPAT_FILETYPE) != 0
    }
}

/// Decodes a fixed-length superblock string field.
///
/// Port of the private `getSBString(byte[])`, which reads the whole field with
/// `readNextString(length, Ext4FileSystem.EXT4_DEFAULT_CHARSET /* UTF-8 */, 1)`: trailing NUL
/// bytes are dropped (interior NULs are kept) and malformed UTF-8 is replaced, as Java's decoder
/// does. The Java `IOException` fallback to `""` cannot occur for an in-memory array.
fn sb_string(bytes: &[u8]) -> String {
    let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

impl StructConverter for Ext4SuperBlock {
    /// Port of `toDataType()`: an `ext4_super_block` structure with one component per member,
    /// in on-disk order (1024 bytes in total).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut structure = StructureDataTypeImpl::new("ext4_super_block", 0);
        for &(name, kind) in FIELDS {
            let dt: Box<dyn DataType> = match kind {
                FieldKind::Byte => PrimitiveDt::BYTE.boxed(),
                FieldKind::Word => PrimitiveDt::WORD.boxed(),
                FieldKind::Dword => PrimitiveDt::DWORD.boxed(),
                FieldKind::Qword => PrimitiveDt::QWORD.boxed(),
                FieldKind::Bytes(n) => Box::new(array_of(PrimitiveDt::BYTE, n)?),
                FieldKind::Dwords(n) => Box::new(array_of(PrimitiveDt::DWORD, n)?),
            };
            structure.add_with_name(dt, Some(name.to_string()), None)?;
        }
        Ok(Box::new(structure))
    }
}

/// `new ArrayDataType(element, n, element.getLength())`.
fn array_of(element: PrimitiveDt, n: i32) -> Result<ArrayDataType, ToDataTypeError> {
    let element_length = element.get_length();
    ArrayDataType::with_element_length(element.boxed(), n, element_length)
        .map_err(|e| ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;

    /// Standard `ext4_super_block` offsets (Linux `fs/ext4/ext4.h`).
    const OFF_INODES_COUNT: usize = 0x00;
    const OFF_BLOCKS_COUNT_LO: usize = 0x04;
    const OFF_LOG_BLOCK_SIZE: usize = 0x18;
    const OFF_BLOCKS_PER_GROUP: usize = 0x20;
    const OFF_MAGIC: usize = 0x38;
    const OFF_FEATURE_INCOMPAT: usize = 0x60;
    const OFF_VOLUME_NAME: usize = 0x78;
    const OFF_LAST_MOUNTED: usize = 0x88;
    const OFF_DESC_SIZE: usize = 0xFE;
    const OFF_BLOCKS_COUNT_HI: usize = 0x150;
    const OFF_CHECKSUM: usize = 0x3FC;

    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// A 64-bit, 4 KiB-block filesystem with 0x1_0000_8001 blocks.
    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        put_u32(&mut b, OFF_INODES_COUNT, 65536);
        put_u32(&mut b, OFF_BLOCKS_COUNT_LO, 0x8001);
        put_u32(&mut b, OFF_LOG_BLOCK_SIZE, 2);
        put_u32(&mut b, OFF_BLOCKS_PER_GROUP, 32768);
        put_u16(&mut b, OFF_MAGIC, 0xEF53);
        put_u32(&mut b, OFF_FEATURE_INCOMPAT, 0x80 | 0x2);
        b[OFF_VOLUME_NAME..OFF_VOLUME_NAME + 6].copy_from_slice(b"rootfs");
        b[OFF_LAST_MOUNTED..OFF_LAST_MOUNTED + 4].copy_from_slice(b"/mnt");
        put_u16(&mut b, OFF_DESC_SIZE, 64);
        put_u32(&mut b, OFF_BLOCKS_COUNT_HI, 1);
        put_u32(&mut b, OFF_CHECKSUM, 0xDEAD_BEEF);
        b
    }

    fn parse(bytes: Vec<u8>) -> io::Result<Ext4SuperBlock> {
        let mut reader = VecReader::new(bytes);
        Ext4SuperBlock::from_provider_reader(&mut reader)
    }

    #[test]
    fn reads_members_at_their_on_disk_offsets() {
        let mut reader = VecReader::little_endian(sample());
        let sb = Ext4SuperBlock::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 1024);
        assert_eq!(sb.s_inodes_count, 65536);
        assert_eq!(sb.s_log_block_size, 2);
        assert_eq!(sb.s_blocks_per_group, 32768);
        assert_eq!(sb.s_magic as u16, 0xEF53);
        assert_eq!(sb.s_desc_size, 64);
        assert_eq!(sb.s_checksum as u32, 0xDEAD_BEEF);
        assert_eq!(sb.s_reserved, [0; 98]);
    }

    #[test]
    fn provider_constructor_forces_little_endian_from_index_zero() {
        let sb = parse(sample()).unwrap();
        assert!(sb.is_valid());
        assert_eq!(sb.s_blocks_count_lo, 0x8001);
    }

    #[test]
    fn derived_values_match_java() {
        let sb = parse(sample()).unwrap();
        assert_eq!(sb.get_s_blocks_count(), 0x1_0000_8001);
        assert_eq!(sb.get_block_size().unwrap(), 4096);
        // ceil(0x1_0000_8001 / 32768) = 131073 + 1
        assert_eq!(sb.get_num_groups().unwrap(), 131074);
        assert!(sb.is_64_bit());
        assert!(sb.is_dir_entry2());
        assert!(!sb.is_inline_data());
        assert_eq!(sb.get_volume_name(), "rootfs");
        assert_eq!(sb.get_last_mounted_string(), "/mnt");
    }

    #[test]
    fn blocks_count_lo_is_treated_as_unsigned() {
        let mut b = sample();
        put_u32(&mut b, OFF_BLOCKS_COUNT_LO, 0xFFFF_FFFF);
        put_u32(&mut b, OFF_BLOCKS_COUNT_HI, 0);
        let sb = parse(b).unwrap();
        assert_eq!(sb.get_s_blocks_count(), 0xFFFF_FFFF);
    }

    #[test]
    fn sixty_four_bit_needs_large_descriptors() {
        let mut b = sample();
        put_u16(&mut b, OFF_DESC_SIZE, 32);
        assert!(!parse(b).unwrap().is_64_bit());
    }

    #[test]
    fn invalid_magic_is_not_valid() {
        let mut b = sample();
        put_u16(&mut b, OFF_MAGIC, 0x1234);
        assert!(!parse(b).unwrap().is_valid());
    }

    #[test]
    fn block_size_out_of_range_errors() {
        let mut b = sample();
        put_u32(&mut b, OFF_LOG_BLOCK_SIZE, 7);
        let sb = parse(b).unwrap();
        let err = sb.get_block_size().unwrap_err();
        assert_eq!(err.to_string(), "Blocksize out of range: 7");
        assert!(sb.get_num_groups().is_err());
    }

    #[test]
    fn bad_blocks_per_group_errors() {
        let mut b = sample();
        put_u32(&mut b, OFF_BLOCKS_PER_GROUP, 1024); // below the 4096 block size
        let err = parse(b).unwrap().get_num_groups().unwrap_err();
        assert_eq!(err.to_string(), "Bad blocks per group: 1024");

        let mut b = sample();
        put_u32(&mut b, OFF_BLOCKS_PER_GROUP, (1 << 19) + 1);
        assert!(parse(b).unwrap().get_num_groups().is_err());
    }

    #[test]
    fn exact_block_multiple_does_not_round_up() {
        let mut b = sample();
        put_u32(&mut b, OFF_BLOCKS_COUNT_LO, 65536);
        put_u32(&mut b, OFF_BLOCKS_COUNT_HI, 0);
        assert_eq!(parse(b).unwrap().get_num_groups().unwrap(), 2);
    }

    #[test]
    fn unsigned_exact_fields_reject_values_above_i32_max() {
        let mut b = sample();
        put_u32(&mut b, OFF_INODES_COUNT, 0x8000_0000);
        let err = parse(b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "Value out of range for positive java 32 bit unsigned int: 2147483648"
        );
    }

    #[test]
    fn truncated_input_errors() {
        let mut b = sample();
        b.truncate(1020);
        assert!(parse(b).is_err());
    }

    #[test]
    fn sb_string_drops_only_trailing_nuls() {
        assert_eq!(sb_string(b"a\0b\0\0"), "a\0b");
        assert_eq!(sb_string(&[0; 16]), "");
    }

    #[test]
    fn data_type_is_the_1024_byte_ext4_super_block() {
        let sb = parse(sample()).unwrap();
        let dt = sb.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ext4_super_block");
        assert_eq!(dt.get_length(), 1024);
        assert_eq!(FIELDS.len(), 91);
    }
}
