use std::fmt;

use super::fid_hash_quad::FidHashQuad;

/// Implementation container class for [`FidHashQuad`].
pub struct FidHashQuadImpl {
    code_unit_size: i16,
    full_hash: i64,
    specific_hash_additional_size: i8,
    specific_hash: i64,
}

impl FidHashQuadImpl {
    /// Constructs a `FidHashQuadImpl` with the given values.
    pub fn new(
        code_unit_size: i16,
        full_hash: i64,
        specific_hash_additional_size: i8,
        specific_hash: i64,
    ) -> Self {
        Self {
            code_unit_size,
            full_hash,
            specific_hash_additional_size,
            specific_hash,
        }
    }
}

impl FidHashQuad for FidHashQuadImpl {
    fn code_unit_size(&self) -> i16 {
        self.code_unit_size
    }

    fn full_hash(&self) -> i64 {
        self.full_hash
    }

    fn specific_hash_additional_size(&self) -> i8 {
        self.specific_hash_additional_size
    }

    fn specific_hash(&self) -> i64 {
        self.specific_hash
    }
}

impl fmt::Display for FidHashQuadImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            " FH: {:x} ({}) +{} XH: {:x}",
            self.full_hash, self.code_unit_size, self.specific_hash_additional_size, self.specific_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accessors() {
        let q = FidHashQuadImpl::new(10, 0x1234_5678_9ABC_DEF0_u64 as i64, 3, 0xDEAD_BEEF_CAFE_1234_u64 as i64);
        assert_eq!(q.code_unit_size(), 10);
        assert_eq!(q.full_hash(), 0x1234_5678_9ABC_DEF0_u64 as i64);
        assert_eq!(q.specific_hash_additional_size(), 3);
        assert_eq!(q.specific_hash(), 0xDEAD_BEEF_CAFE_1234_u64 as i64);
    }

    #[test]
    fn test_zero_values() {
        let q = FidHashQuadImpl::new(0, 0, 0, 0);
        assert_eq!(q.code_unit_size(), 0);
        assert_eq!(q.full_hash(), 0);
        assert_eq!(q.specific_hash_additional_size(), 0);
        assert_eq!(q.specific_hash(), 0);
    }

    #[test]
    fn test_boundary_values() {
        let q = FidHashQuadImpl::new(i16::MAX, i64::MIN, i8::MIN, i64::MAX);
        assert_eq!(q.code_unit_size(), i16::MAX);
        assert_eq!(q.full_hash(), i64::MIN);
        assert_eq!(q.specific_hash_additional_size(), i8::MIN);
        assert_eq!(q.specific_hash(), i64::MAX);
    }

    #[test]
    fn test_display_matches_java_format() {
        let q = FidHashQuadImpl::new(10, 0x1234_5678_9ABC_DEF0_u64 as i64, 3, 0xDEAD_BEEF_CAFE_1234_u64 as i64);
        assert_eq!(
            q.to_string(),
            " FH: 123456789abcdef0 (10) +3 XH: deadbeefcafe1234"
        );
    }

    #[test]
    fn test_display_negative_hash_uses_twos_complement_hex() {
        // Java's Long.toHexString prints the unsigned two's-complement hex form.
        let q = FidHashQuadImpl::new(-1, -1, -1, -1);
        assert_eq!(q.to_string(), " FH: ffffffffffffffff (-1) +-1 XH: ffffffffffffffff");
    }
}
