/// Constants for Apple Disk Image (DMG) files.
///
/// Mirrors `ghidra.file.formats.ios.dmg.DmgConstants`.

/// Magic bytes for DMG v1 (`cdsaencr`).
pub const DMG_MAGIC_BYTES_V1: [u8; 8] = *b"cdsaencr";

/// Magic bytes for DMG v2 (`encrcdsa`).
pub const DMG_MAGIC_BYTES_V2: [u8; 8] = *b"encrcdsa";

/// Length of the DMG magic byte sequences.
pub const DMG_MAGIC_LENGTH: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_magic_matches_java_source() {
        assert_eq!(
            DMG_MAGIC_BYTES_V1,
            [b'c', b'd', b's', b'a', b'e', b'n', b'c', b'r']
        );
    }

    #[test]
    fn v2_magic_matches_java_source() {
        assert_eq!(
            DMG_MAGIC_BYTES_V2,
            [b'e', b'n', b'c', b'r', b'c', b'd', b's', b'a']
        );
    }

    #[test]
    fn magic_length_is_eight() {
        assert_eq!(DMG_MAGIC_LENGTH, 8);
        assert_eq!(DMG_MAGIC_BYTES_V1.len(), DMG_MAGIC_LENGTH);
        assert_eq!(DMG_MAGIC_BYTES_V2.len(), DMG_MAGIC_LENGTH);
    }

    #[test]
    fn v1_and_v2_are_distinct() {
        assert_ne!(DMG_MAGIC_BYTES_V1, DMG_MAGIC_BYTES_V2);
    }
}
