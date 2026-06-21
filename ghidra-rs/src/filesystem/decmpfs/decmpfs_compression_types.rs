/// Compression type constants for the `decmpfs` extended attribute.
pub struct DecmpfsCompressionTypes;

impl DecmpfsCompressionTypes {
    /// Uncompressed data stored in the xattr.
    pub const CMP_TYPE1: u8 = 1;
    /// Data stored in-line (compressed, in-xattr).
    pub const CMP_TYPE3: u8 = 3;
    /// Compressed data stored in the resource fork.
    pub const CMP_TYPE4: u8 = 4;
    /// Unknown compression type 10.
    pub const CMP_TYPE10: u8 = 10;
    /// Maximum valid compression type value.
    pub const CMP_MAX: u8 = 255;
}

#[cfg(test)]
mod tests {
    use super::DecmpfsCompressionTypes;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(DecmpfsCompressionTypes::CMP_TYPE1, 1_u8);
        assert_eq!(DecmpfsCompressionTypes::CMP_TYPE3, 3_u8);
        assert_eq!(DecmpfsCompressionTypes::CMP_TYPE4, 4_u8);
        assert_eq!(DecmpfsCompressionTypes::CMP_TYPE10, 10_u8);
        assert_eq!(DecmpfsCompressionTypes::CMP_MAX, 255_u8);
    }

    #[test]
    fn constants_are_distinct() {
        let types = [
            DecmpfsCompressionTypes::CMP_TYPE1,
            DecmpfsCompressionTypes::CMP_TYPE3,
            DecmpfsCompressionTypes::CMP_TYPE4,
            DecmpfsCompressionTypes::CMP_TYPE10,
        ];
        for (i, &a) in types.iter().enumerate() {
            for &b in types[..i].iter() {
                assert_ne!(a, b, "compression type values must be unique");
            }
        }
    }

    #[test]
    fn all_types_within_max() {
        let types = [
            DecmpfsCompressionTypes::CMP_TYPE1,
            DecmpfsCompressionTypes::CMP_TYPE3,
            DecmpfsCompressionTypes::CMP_TYPE4,
            DecmpfsCompressionTypes::CMP_TYPE10,
        ];
        for &t in &types {
            assert!(t <= DecmpfsCompressionTypes::CMP_MAX);
        }
    }
}
