/// Compression type constants for the DECMPFS (Apple compressed data) xattr.
///
/// Mirrors `ghidra.file.formats.ios.decmpfs.DecmpfsCompressionTypes`.

/// Uncompressed data in xattr.
pub const CMP_TYPE1: i32 = 1;

/// Data stored in-line.
pub const CMP_TYPE3: i32 = 3;

/// Resource fork contains compressed data.
pub const CMP_TYPE4: i32 = 4;

/// Unknown compression type.
pub const CMP_TYPE10: i32 = 10;

/// Maximum compression type value.
pub const CMP_MAX: i32 = 255;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(CMP_TYPE1, 1);
        assert_eq!(CMP_TYPE3, 3);
        assert_eq!(CMP_TYPE4, 4);
        assert_eq!(CMP_TYPE10, 10);
        assert_eq!(CMP_MAX, 255);
    }

    #[test]
    fn all_values_are_distinct() {
        let types = [CMP_TYPE1, CMP_TYPE3, CMP_TYPE4, CMP_TYPE10, CMP_MAX];
        for i in 0..types.len() {
            for j in (i + 1)..types.len() {
                assert_ne!(types[i], types[j]);
            }
        }
    }

    #[test]
    fn all_known_types_within_max() {
        assert!(CMP_TYPE1 <= CMP_MAX);
        assert!(CMP_TYPE3 <= CMP_MAX);
        assert!(CMP_TYPE4 <= CMP_MAX);
        assert!(CMP_TYPE10 <= CMP_MAX);
    }
}
