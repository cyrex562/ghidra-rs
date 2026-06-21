/// File compression state constants for the `decmpfs` extended attribute.
pub struct DecmpfsStates;

impl DecmpfsStates {
    /// File type could not be determined.
    pub const FILE_TYPE_UNKNOWN: u32 = 0;
    /// File is not compressed.
    pub const FILE_IS_NOT_COMPRESSED: u32 = 1;
    /// File is compressed.
    pub const FILE_IS_COMPRESSED: u32 = 2;
    /// File is in the process of being decompressed.
    pub const FILE_IS_CONVERTING: u32 = 3;
}

#[cfg(test)]
mod tests {
    use super::DecmpfsStates;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(DecmpfsStates::FILE_TYPE_UNKNOWN, 0_u32);
        assert_eq!(DecmpfsStates::FILE_IS_NOT_COMPRESSED, 1_u32);
        assert_eq!(DecmpfsStates::FILE_IS_COMPRESSED, 2_u32);
        assert_eq!(DecmpfsStates::FILE_IS_CONVERTING, 3_u32);
    }

    #[test]
    fn constants_are_distinct() {
        let states = [
            DecmpfsStates::FILE_TYPE_UNKNOWN,
            DecmpfsStates::FILE_IS_NOT_COMPRESSED,
            DecmpfsStates::FILE_IS_COMPRESSED,
            DecmpfsStates::FILE_IS_CONVERTING,
        ];
        for (i, &a) in states.iter().enumerate() {
            for &b in states[..i].iter() {
                assert_ne!(a, b, "state values must be unique");
            }
        }
    }

    #[test]
    fn states_are_sequential_from_zero() {
        assert_eq!(DecmpfsStates::FILE_TYPE_UNKNOWN + 1, DecmpfsStates::FILE_IS_NOT_COMPRESSED);
        assert_eq!(DecmpfsStates::FILE_IS_NOT_COMPRESSED + 1, DecmpfsStates::FILE_IS_COMPRESSED);
        assert_eq!(DecmpfsStates::FILE_IS_COMPRESSED + 1, DecmpfsStates::FILE_IS_CONVERTING);
    }
}
