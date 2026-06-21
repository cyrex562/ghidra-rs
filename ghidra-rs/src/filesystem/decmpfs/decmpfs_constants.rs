/// Constants for the `decmpfs` extended attribute.
pub struct DecmpfsConstants;

impl DecmpfsConstants {
    /// Maximum size in bytes of the `decmpfs` extended attribute.
    pub const MAX_DECMPFS_XATTR_SIZE: u32 = 3802;

    /// Magic bytes identifying a `decmpfs` header (`fpmc`).
    pub const DECMPFS_MAGIC_BYTES: [u8; 4] = [b'f', b'p', b'm', b'c'];

    /// Magic string identifying a `decmpfs` header (`"fpmc"`).
    pub const DECMPFS_MAGIC: &'static str = "fpmc";
}

#[cfg(test)]
mod tests {
    use super::DecmpfsConstants;

    #[test]
    fn max_xattr_size_matches_java_source() {
        assert_eq!(DecmpfsConstants::MAX_DECMPFS_XATTR_SIZE, 3802_u32);
    }

    #[test]
    fn magic_bytes_match_java_source() {
        assert_eq!(
            DecmpfsConstants::DECMPFS_MAGIC_BYTES,
            [b'f', b'p', b'm', b'c']
        );
    }

    #[test]
    fn magic_string_matches_java_source() {
        assert_eq!(DecmpfsConstants::DECMPFS_MAGIC, "fpmc");
    }

    #[test]
    fn magic_string_matches_magic_bytes() {
        assert_eq!(
            DecmpfsConstants::DECMPFS_MAGIC.as_bytes(),
            DecmpfsConstants::DECMPFS_MAGIC_BYTES
        );
    }
}
