/// SquashFS magic bytes ("hsqs").
pub const MAGIC: [u8; 4] = [0x68, 0x73, 0x71, 0x73];

/// Compression type: gzip.
pub const COMPRESSION_TYPE_GZIP: u32 = 1;
/// Compression type: LZMA.
pub const COMPRESSION_TYPE_LZMA: u32 = 2;
/// Compression type: LZO.
pub const COMPRESSION_TYPE_LZO: u32 = 3;
/// Compression type: XZ.
pub const COMPRESSION_TYPE_XZ: u32 = 4;
/// Compression type: LZ4.
pub const COMPRESSION_TYPE_LZ4: u32 = 5;
/// Compression type: Zstandard.
pub const COMPRESSION_TYPE_ZSTD: u32 = 6;

/// Superblock flag: inodes are stored uncompressed.
pub const UNCOMPRESSED_INODES: u32 = 0x0001;
/// Superblock flag: data blocks are stored uncompressed.
pub const UNCOMPRESSED_DATA_BLOCKS: u32 = 0x0002;
/// Superblock flag: unused / reserved.
pub const UNUSED_FLAG: u32 = 0x0004;
/// Superblock flag: fragments are stored uncompressed.
pub const UNCOMPRESSED_FRAGMENTS: u32 = 0x0008;
/// Superblock flag: no fragment table present.
pub const NO_FRAGMENTS: u32 = 0x0010;
/// Superblock flag: always use fragments for the last block of a file.
pub const ALWAYS_FRAGMENT: u32 = 0x0020;
/// Superblock flag: do not deduplicate files.
pub const NO_DUPLICATE_DATE: u32 = 0x0040;
/// Superblock flag: an export table is present.
pub const EXPORT_TABLE_EXISTS: u32 = 0x0080;
/// Superblock flag: xattrs are stored uncompressed.
pub const UNCOMPRESSED_XATTRS: u32 = 0x0100;
/// Superblock flag: no xattr table present.
pub const NO_XATTRS: u32 = 0x0200;
/// Superblock flag: compression options metadata block is present.
pub const COMPRESSION_OPTIONS_EXIST: u32 = 0x0400;
/// Superblock flag: ID table is stored uncompressed.
pub const UNCOMPRESSED_IDS: u32 = 0x0800;

/// Inode type: basic directory.
pub const INODE_TYPE_BASIC_DIRECTORY: u32 = 0x01;
/// Inode type: basic regular file.
pub const INODE_TYPE_BASIC_FILE: u32 = 0x02;
/// Inode type: basic symbolic link.
pub const INODE_TYPE_BASIC_SYMLINK: u32 = 0x03;
/// Inode type: basic block device.
pub const INODE_TYPE_BASIC_BLOCK_DEVICE: u32 = 0x04;
/// Inode type: basic character device.
pub const INODE_TYPE_BASIC_CHAR_DEVICE: u32 = 0x05;
/// Inode type: basic FIFO.
pub const INODE_TYPE_BASIC_FIFO: u32 = 0x06;
/// Inode type: basic socket.
pub const INODE_TYPE_BASIC_SOCKET: u32 = 0x07;
/// Inode type: extended directory.
pub const INODE_TYPE_EXTENDED_DIRECTORY: u32 = 0x08;
/// Inode type: extended regular file.
pub const INODE_TYPE_EXTENDED_FILE: u32 = 0x09;
/// Inode type: extended symbolic link.
pub const INODE_TYPE_EXTENDED_SYMLINK: u32 = 0x0A;
/// Inode type: extended block device.
pub const INODE_TYPE_EXTENDED_BLOCK_DEVICE: u32 = 0x0B;
/// Inode type: extended character device.
pub const INODE_TYPE_EXTENDED_CHAR_DEVICE: u32 = 0x0C;
/// Inode type: extended FIFO.
pub const INODE_TYPE_EXTENDED_FIFO: u32 = 0x0D;
/// Inode type: extended socket.
pub const INODE_TYPE_EXTENDED_SOCKET: u32 = 0x0E;

/// Maximum metadata block size in bytes (8 KiB).
pub const MAX_UNIT_BLOCK_SIZE: u32 = 0x2000;
/// Length in bytes of a single fragment table entry.
pub const FRAGMENT_ENTRY_LENGTH: u32 = 16;
/// Maximum depth when resolving symbolic links.
pub const MAX_SYMLINK_DEPTH: u32 = 100;

/// Sentinel value indicating a section is omitted (all bits set in a 32-bit field).
pub const SECTION_OMITTED: u32 = 0xFFFF_FFFF;
/// Sentinel value in an inode's fragment index indicating no associated fragments.
pub const INODE_NO_FRAGMENTS: u32 = 0xFFFF_FFFF;

/// Bit 24 mask used to test whether a fragment block is compressed.
/// Invert this mask to extract the size field.
pub const FRAGMENT_COMPRESSED_MASK: u32 = 1 << 24;
/// Bit 24 mask used to test whether a data block is compressed.
/// Invert this mask to extract the size field.
pub const DATABLOCK_COMPRESSED_MASK: u32 = 1 << 24;
/// Bit 15 mask used to test whether a metadata block is uncompressed.
/// Invert this mask to extract the size field.
pub const METABLOCK_UNCOMPRESSED_MASK: u32 = 1 << 15;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes() {
        assert_eq!(MAGIC, [0x68, 0x73, 0x71, 0x73]);
    }

    #[test]
    fn compression_types_sequential() {
        assert_eq!(COMPRESSION_TYPE_GZIP, 1);
        assert_eq!(COMPRESSION_TYPE_LZMA, 2);
        assert_eq!(COMPRESSION_TYPE_LZO, 3);
        assert_eq!(COMPRESSION_TYPE_XZ, 4);
        assert_eq!(COMPRESSION_TYPE_LZ4, 5);
        assert_eq!(COMPRESSION_TYPE_ZSTD, 6);
    }

    #[test]
    fn superblock_flags_are_distinct_bits() {
        let flags = [
            UNCOMPRESSED_INODES,
            UNCOMPRESSED_DATA_BLOCKS,
            UNUSED_FLAG,
            UNCOMPRESSED_FRAGMENTS,
            NO_FRAGMENTS,
            ALWAYS_FRAGMENT,
            NO_DUPLICATE_DATE,
            EXPORT_TABLE_EXISTS,
            UNCOMPRESSED_XATTRS,
            NO_XATTRS,
            COMPRESSION_OPTIONS_EXIST,
            UNCOMPRESSED_IDS,
        ];
        for i in 0..flags.len() {
            for j in (i + 1)..flags.len() {
                assert_eq!(flags[i] & flags[j], 0, "flags[{i}] and flags[{j}] share bits");
            }
        }
    }

    #[test]
    fn inode_types_range() {
        assert_eq!(INODE_TYPE_BASIC_DIRECTORY, 0x01);
        assert_eq!(INODE_TYPE_EXTENDED_SOCKET, 0x0E);
    }

    #[test]
    fn sentinel_values_all_bits_set() {
        assert_eq!(SECTION_OMITTED, u32::MAX);
        assert_eq!(INODE_NO_FRAGMENTS, u32::MAX);
    }

    #[test]
    fn compressed_masks_bit_position() {
        assert_eq!(FRAGMENT_COMPRESSED_MASK, 0x0100_0000);
        assert_eq!(DATABLOCK_COMPRESSED_MASK, 0x0100_0000);
        assert_eq!(METABLOCK_UNCOMPRESSED_MASK, 0x0000_8000);
    }

    #[test]
    fn max_unit_block_size_is_8kib() {
        assert_eq!(MAX_UNIT_BLOCK_SIZE, 8192);
    }
}
