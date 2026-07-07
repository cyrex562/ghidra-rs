/// File state constants for the DECMPFS (Apple compressed data) xattr.
///
/// Mirrors `ghidra.file.formats.ios.decmpfs.DecmpfsStates`.

/// File compression state is unknown.
pub const FILE_TYPE_UNKNOWN: i32 = 0;

/// File is not compressed.
pub const FILE_IS_NOT_COMPRESSED: i32 = 1;

/// File is compressed.
pub const FILE_IS_COMPRESSED: i32 = 2;

/// File is converting from compressed to decompressed.
pub const FILE_IS_CONVERTING: i32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(FILE_TYPE_UNKNOWN, 0);
        assert_eq!(FILE_IS_NOT_COMPRESSED, 1);
        assert_eq!(FILE_IS_COMPRESSED, 2);
        assert_eq!(FILE_IS_CONVERTING, 3);
    }

    #[test]
    fn all_values_are_distinct() {
        let states = [
            FILE_TYPE_UNKNOWN,
            FILE_IS_NOT_COMPRESSED,
            FILE_IS_COMPRESSED,
            FILE_IS_CONVERTING,
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }
}
