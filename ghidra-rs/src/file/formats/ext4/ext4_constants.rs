//! Port of `ghidra.file.formats.ext4.Ext4Constants`.
//!
//! Java uses a `final class` of `public final static` fields purely to namespace constants;
//! Rust has no instance state or methods to hang off a type here, so these are emitted as
//! plain module-level `pub const`s (see `scripts/shape_rules.py`: "plain module" rule).

pub const SUPER_BLOCK_START: i32 = 0x400;
pub const SUPER_BLOCK_MAGIC: i32 = 0xEF53; // LE

// Super Block Compatible Feature Flags
pub const COMPAT_DIR_PREALLOC: i32 = 0x1;
pub const COMPAT_IMAGIC_INODES: i32 = 0x2;
pub const COMPAT_HAS_JOURNAL: i32 = 0x4;
pub const COMPAT_EXT_ATTR: i32 = 0x8;
pub const COMPAT_RESIZE_INODE: i32 = 0x10;
pub const COMPAT_DIR_INDEX: i32 = 0x20;
pub const COMPAT_LAZY_BG: i32 = 0x40;
pub const COMPAT_EXCLUDE_INODE: i32 = 0x80;
pub const COMPAT_EXCLUDE_BITMAP: i32 = 0x100;
pub const COMPAT_SPARSE_SUPER2: i32 = 0x200;

// Super Block Incompatible Feature Flags
pub const INCOMPAT_COMPRESSION: i32 = 0x1;
pub const INCOMPAT_FILETYPE: i32 = 0x2;
pub const INCOMPAT_RECOVER: i32 = 0x4;
pub const INCOMPAT_JOURNAL_DEV: i32 = 0x8;
pub const INCOMPAT_META_BG: i32 = 0x10;
pub const INCOMPAT_EXTENTS: i32 = 0x40;
pub const INCOMPAT_64BIT: i32 = 0x80;
pub const INCOMPAT_MMP: i32 = 0x100;
pub const INCOMPAT_FLEX_BG: i32 = 0x200;
pub const INCOMPAT_EA_INODE: i32 = 0x400;
pub const INCOMPAT_DIRDATA: i32 = 0x1000;
pub const INCOMPAT_CSUM_SEED: i32 = 0x2000;
pub const INCOMPAT_LARGEDIR: i32 = 0x4000;
pub const INCOMPAT_INLINE_DATA: i32 = 0x8000;
pub const INCOMPAT_ENCRYPT: i32 = 0x10000;

// Super Block Read-only Compatible Feature Flags
pub const RO_COMPAT_SPARSE_SUPER: i32 = 0x1;
pub const RO_COMPAT_LARGE_FILE: i32 = 0x2;
pub const RO_COMPAT_BTREE_DIR: i32 = 0x4;
pub const RO_COMPAT_HUGE_FILE: i32 = 0x8;
pub const RO_COMPAT_GDT_CSUM: i32 = 0x10;
pub const RO_COMPAT_DIR_NLINK: i32 = 0x20;
pub const RO_COMPAT_EXTRA_ISIZE: i32 = 0x40;
pub const RO_COMPAT_HAS_SNAPSHOT: i32 = 0x80;
pub const RO_COMPAT_QUOTA: i32 = 0x100;
pub const RO_COMPAT_BIGALLOC: i32 = 0x200;
pub const RO_COMPAT_METADATA_CSUM: i32 = 0x400;
pub const RO_COMPAT_REPLICA: i32 = 0x800;
pub const RO_COMPAT_READONLY: i32 = 0x1000;
pub const RO_COMPAT_PROJECT: i32 = 0x2000;

// Inode File Mode
pub const S_IXOTH: i32 = 0x1;
pub const S_IWOTH: i32 = 0x2;
pub const S_IROTH: i32 = 0x4;
pub const S_IXGRP: i32 = 0x8;
pub const S_IWGRP: i32 = 0x10;
pub const S_IRGRP: i32 = 0x20;
pub const S_IXUSR: i32 = 0x40;
pub const S_IWUSR: i32 = 0x80;
pub const S_IRUSR: i32 = 0x100;
pub const S_ISVTX: i32 = 0x200;
pub const S_ISGID: i32 = 0x400;
pub const S_ISUID: i32 = 0x800;
// These are mutually-exclusive file types
pub const S_IFIFO: i32 = 0x1000;
pub const S_IFCHR: i32 = 0x2000;
pub const S_IFDIR: i32 = 0x4000;
pub const S_IFBLK: i32 = 0x6000;
pub const S_IFREG: i32 = 0x8000;
pub const S_IFLNK: i32 = 0xA000;
pub const S_IFSOCK: i32 = 0xC000_u32 as i32;

pub const I_MODE_MASK: i32 = 0xF000_u32 as i32;

// Inode Flags
pub const EXT4_SECRM_FL: i32 = 0x1;
pub const EXT4_UNRM_FL: i32 = 0x2;
pub const EXT4_COMPR_FL: i32 = 0x4;
pub const EXT4_SYNC_FL: i32 = 0x8;
pub const EXT4_IMMUTABLE_FL: i32 = 0x10;
pub const EXT4_APPEND_FL: i32 = 0x20;
pub const EXT4_NODUMP_FL: i32 = 0x40;
pub const EXT4_NOATIME_FL: i32 = 0x80;
pub const EXT4_DIRTY_FL: i32 = 0x100;
pub const EXT4_COMPRBLK_FL: i32 = 0x200;
pub const EXT4_NOCOMPR_FL: i32 = 0x400;
pub const EXT4_ENCRYPT_FL: i32 = 0x800;
pub const EXT4_INDEX_FL: i32 = 0x1000;
pub const EXT4_IMAGIC_FL: i32 = 0x2000;
pub const EXT4_JOURNAL_DATA_FL: i32 = 0x4000;
pub const EXT4_NOTAIL_FL: i32 = 0x8000;
pub const EXT4_DIRSYNC_FL: i32 = 0x10000;
pub const EXT4_TOPDIR_FL: i32 = 0x20000;
pub const EXT4_HUGE_FILE_FL: i32 = 0x40000;
pub const EXT4_EXTENTS_FL: i32 = 0x80000;
pub const EXT4_EA_INODE_FL: i32 = 0x200000;
pub const EXT4_EOFBLOCKS_FL: i32 = 0x400000;
pub const EXT4_SNAPFILE_FL: i32 = 0x01000000;
pub const EXT4_SNAPFILE_DELETED_FL: i32 = 0x04000000;
pub const EXT4_SNAPFILE_SHRUNK_FL: i32 = 0x08000000;
pub const EXT4_INLINE_DATA_FL: i32 = 0x10000000;
pub const EXT4_PROJINHERIT_FL: i32 = 0x20000000;
pub const EXT4_RESERVED_FL: i32 = 0x80000000_u32 as i32;

pub const EXTENT_HEADER_MAGIC: i32 = 0xF30A;

// ------------------------------------------------------
// ext4_dir_entry_2 File Types

pub const FILE_TYPE_UNKNOWN: i8 = 0x0;
pub const FILE_TYPE_REGULAR_FILE: i8 = 0x1;
pub const FILE_TYPE_DIRECTORY: i8 = 0x2;
pub const FILE_TYPE_CHARACTER_DEVICE_FILE: i8 = 0x3;
pub const FILE_TYPE_BLOCK_DEVICE_FILE: i8 = 0x4;
pub const FILE_TYPE_FIFO: i8 = 0x5;
pub const FILE_TYPE_SOCKET: i8 = 0x6;
pub const FILE_TYPE_SYMBOLIC_LINK: i8 = 0x7;

// ------------------------------------------------------

/// See <https://github.com/torvalds/linux/blob/master/fs/ext4/ext4.h>
///
/// Ext4 directory file types. Only the low 3 bits are used. The other bits are
/// reserved for now.
pub const EXT4_FT_UNKNOWN: i8 = 0;
pub const EXT4_FT_REG_FILE: i8 = 1;
pub const EXT4_FT_DIR: i8 = 2;
pub const EXT4_FT_CHRDEV: i8 = 3;
pub const EXT4_FT_BLKDEV: i8 = 4;
pub const EXT4_FT_FIFO: i8 = 5;
pub const EXT4_FT_SOCK: i8 = 6;
pub const EXT4_FT_SYMLINK: i8 = 7;

pub const EXT4_FT_MAX: i8 = 8;

pub const EXT4_FT_DIR_CSUM: i8 = 0xDEu8 as i8;

// ---------------------------------------------------------
// index of special inodes that are statically assigned by convention

pub const EXT4_INODE_INDEX_NULL: i32 = 0;
/// This file holds info about bad blocks.
pub const EXT4_INODE_INDEX_BADBLOCKS: i32 = 1;
/// The root directory.
pub const EXT4_INODE_INDEX_ROOTDIR: i32 = 2;
pub const EXT4_INODE_INDEX_USERQUOTA: i32 = 3;
pub const EXT4_INODE_INDEX_GROUPQUOTA: i32 = 4;
pub const EXT4_INODE_INDEX_BOOTLOADER: i32 = 5;
pub const EXT4_INODE_INDEX_UNDELETEDIR: i32 = 6;
pub const EXT4_INODE_INDEX_RESERVED_GROUPDESCRIPTORS: i32 = 7;
pub const EXT4_INODE_INDEX_JOURNALINODE: i32 = 8;
pub const EXT4_INODE_INDEX_EXCLUDEINODE: i32 = 9;
pub const EXT4_INODE_INDEX_REPLICAINODE: i32 = 10;
/// Typically the first non-reserved inode, "lost+found" dir.
pub const EXT4_INODE_INDEX_NORMAL_FIRSTUSED: i32 = 11;

// ---------------------------------------------------------

pub const EXT4_XATTR_MAGIC: i32 = 0xEA020000_u32 as i32;

/// Prefixes inserted before the `Ext4XattrEntry` name value, looked up by
/// `Ext4XattrEntry.e_name_index`.
pub const EXT4_XATTR_NAMEINDEX_STRINGS: [&str; 9] = [
    "",
    "user.",
    "system.posix_acl_access.",
    "system.posix_acl_default",
    "trusted.",
    "lustre.", // guessing about this string
    "security.",
    "system.",
    "system.richacl",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn super_block_constants_match_java() {
        assert_eq!(SUPER_BLOCK_START, 0x400);
        assert_eq!(SUPER_BLOCK_MAGIC, 0xEF53);
    }

    #[test]
    fn inode_file_mode_constants_match_java() {
        assert_eq!(S_IFDIR, 0x4000);
        assert_eq!(S_IFREG, 0x8000);
        assert_eq!(S_IFLNK, 0xA000_u32 as i32);
        assert_eq!(I_MODE_MASK, 0xF000_u32 as i32);
    }

    #[test]
    fn ext4_ft_constants_match_java() {
        assert_eq!(EXT4_FT_UNKNOWN, 0);
        assert_eq!(EXT4_FT_SYMLINK, 7);
        assert_eq!(EXT4_FT_MAX, 8);
        assert_eq!(EXT4_FT_DIR_CSUM, 0xDEu8 as i8);
    }

    #[test]
    fn xattr_nameindex_strings_match_java_order() {
        assert_eq!(EXT4_XATTR_NAMEINDEX_STRINGS.len(), 9);
        assert_eq!(EXT4_XATTR_NAMEINDEX_STRINGS[0], "");
        assert_eq!(EXT4_XATTR_NAMEINDEX_STRINGS[1], "user.");
        assert_eq!(EXT4_XATTR_NAMEINDEX_STRINGS[8], "system.richacl");
    }

    #[test]
    fn xattr_magic_matches_java() {
        assert_eq!(EXT4_XATTR_MAGIC, 0xEA020000_u32 as i32);
    }
}
