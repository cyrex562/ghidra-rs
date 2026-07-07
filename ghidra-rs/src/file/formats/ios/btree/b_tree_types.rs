/// B-tree type constants for the HFS B-tree format.
///
/// Mirrors `ghidra.file.formats.ios.btree.BTreeTypes`.
///
/// See <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>

/// Control file B-tree (HFS-internal use).
pub const HFS_BTREE_TYPE: i8 = 0;

/// First value reserved for user B-trees; user types occupy 128–254.
pub const USER_BTREE_TYPE: i8 = -128;

/// Reserved B-tree type sentinel (wraps Java's `(byte)255`).
pub const RESERVED_BTREE_TYPE: i8 = -1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(HFS_BTREE_TYPE, 0i8);
        // Java: (byte)128 wraps to -128 in signed byte
        assert_eq!(USER_BTREE_TYPE, -128i8);
        // Java: (byte)255 wraps to -1 in signed byte
        assert_eq!(RESERVED_BTREE_TYPE, -1i8);
    }

    #[test]
    fn all_values_are_distinct() {
        let types = [HFS_BTREE_TYPE, USER_BTREE_TYPE, RESERVED_BTREE_TYPE];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }
}
