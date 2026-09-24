//! Constants describing the cramfs on-disk format.
//!
//! Port of `ghidra.file.formats.cramfs.CramFsConstants`, a statics-only Java class, ported as a
//! module of `const` items.
//!
//! See <https://github.com/torvalds/linux/tree/master/fs/cramfs>.

/// Length of the cramfs signature string in the super block.
pub const HEADER_STRING_LENGTH: i32 = 16;
/// The cramfs magic number.
pub const MAGIC: i32 = 0x28cd3d45;

/// Constant size of an inode in bytes in memory.
pub const INODE_SIZE: i32 = 12;

/// Flag as described in `cramfs_fs.h`.
pub const CRAMFS_FLAG_EXT_BLOCK_POINTERS: i32 = 0x00000800;

/// Documentation points to this being the default size; provide option for user if they know
/// the block size.
pub const DEFAULT_BLOCK_SIZE: i32 = 4096;
/// Size in bytes of a block pointer.
pub const BLOCK_POINTER_SIZE: i32 = 4;
/// Size in bytes of the zlib magic header.
pub const ZLIB_MAGIC_SIZE: i32 = 2;

/// Width of the `mode` bitfield in struct
/// [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_MODE_WIDTH: i32 = 16;
/// Width of the `uid` bitfield in struct [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_UID_WIDTH: i32 = 16;
/// Width of the `size` bitfield in struct [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_SIZE_WIDTH: i32 = 24;
/// Width of the `gid` bitfield in struct [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_GID_WIDTH: i32 = 8;
/// Width of the `namelen` bitfield in struct
/// [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_NAMELEN_WIDTH: i32 = 6;
/// Width of the `offset` bitfield in struct
/// [`CramFsInode`](super::cram_fs_inode::CramFsInode).
pub const CRAMFS_OFFSET_WIDTH: i32 = 26;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java() {
        assert_eq!(HEADER_STRING_LENGTH, 16);
        assert_eq!(MAGIC, 0x28cd3d45);
        assert_eq!(INODE_SIZE, 12);
        assert_eq!(CRAMFS_FLAG_EXT_BLOCK_POINTERS, 0x800);
        assert_eq!(DEFAULT_BLOCK_SIZE, 4096);
        assert_eq!(BLOCK_POINTER_SIZE, 4);
        assert_eq!(ZLIB_MAGIC_SIZE, 2);
    }

    #[test]
    fn inode_bitfield_widths_pack_into_three_words() {
        assert_eq!(CRAMFS_MODE_WIDTH + CRAMFS_UID_WIDTH, 32);
        assert_eq!(CRAMFS_SIZE_WIDTH + CRAMFS_GID_WIDTH, 32);
        assert_eq!(CRAMFS_NAMELEN_WIDTH + CRAMFS_OFFSET_WIDTH, 32);
        assert_eq!(INODE_SIZE, 3 * 4);
    }
}
