/// Constants for the DECMPFS (Apple compressed data) xattr.
///
/// Mirrors `ghidra.file.formats.ios.decmpfs.DecmpfsConstants`.

/// Maximum size in bytes of a DECMPFS xattr.
pub const MAX_DECMPFS_XATTR_SIZE: i32 = 3802;

/// Magic bytes identifying a DECMPFS header (`fpmc`).
pub const DECMPFS_MAGIC_BYTES: [u8; 4] = *b"fpmc";

/// Magic string identifying a DECMPFS header.
pub const DECMPFS_MAGIC: &str = "fpmc";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(MAX_DECMPFS_XATTR_SIZE, 3802);
        assert_eq!(DECMPFS_MAGIC_BYTES, [b'f', b'p', b'm', b'c']);
        assert_eq!(DECMPFS_MAGIC, "fpmc");
    }

    #[test]
    fn magic_bytes_match_magic_string() {
        assert_eq!(DECMPFS_MAGIC.as_bytes(), &DECMPFS_MAGIC_BYTES);
    }

    #[test]
    fn max_xattr_size_is_positive() {
        assert!(MAX_DECMPFS_XATTR_SIZE > 0);
    }
}
