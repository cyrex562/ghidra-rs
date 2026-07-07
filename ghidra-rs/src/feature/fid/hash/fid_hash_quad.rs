/// Container to hold all three hashes for a function (medium, full, and specific).
pub trait FidHashQuad {
    /// Returns the actual number of code units used to compute the full hash value.
    fn code_unit_size(&self) -> i16;

    /// Returns the full hash value.
    fn full_hash(&self) -> i64;

    /// Returns the ADDITIONAL number of code units, past the number used for the full hash,
    /// used to compute the specific hash value.
    fn specific_hash_additional_size(&self) -> i8;

    /// Returns the specific hash value.
    fn specific_hash(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestQuad {
        code_unit_size: i16,
        full_hash: i64,
        specific_hash_additional_size: i8,
        specific_hash: i64,
    }

    impl FidHashQuad for TestQuad {
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

    #[test]
    fn test_accessors() {
        let q = TestQuad {
            code_unit_size: 10,
            full_hash: 0x1234_5678_9ABC_DEF0_u64 as i64,
            specific_hash_additional_size: 3,
            specific_hash: 0xDEAD_BEEF_CAFE_1234_u64 as i64,
        };
        assert_eq!(q.code_unit_size(), 10);
        assert_eq!(q.full_hash(), 0x1234_5678_9ABC_DEF0_u64 as i64);
        assert_eq!(q.specific_hash_additional_size(), 3);
        assert_eq!(q.specific_hash(), 0xDEAD_BEEF_CAFE_1234_u64 as i64);
    }

    #[test]
    fn test_zero_values() {
        let q = TestQuad {
            code_unit_size: 0,
            full_hash: 0,
            specific_hash_additional_size: 0,
            specific_hash: 0,
        };
        assert_eq!(q.code_unit_size(), 0);
        assert_eq!(q.full_hash(), 0);
        assert_eq!(q.specific_hash_additional_size(), 0);
        assert_eq!(q.specific_hash(), 0);
    }

    #[test]
    fn test_boundary_values() {
        let q = TestQuad {
            code_unit_size: i16::MAX,
            full_hash: i64::MIN,
            specific_hash_additional_size: i8::MIN,
            specific_hash: i64::MAX,
        };
        assert_eq!(q.code_unit_size(), i16::MAX);
        assert_eq!(q.full_hash(), i64::MIN);
        assert_eq!(q.specific_hash_additional_size(), i8::MIN);
        assert_eq!(q.specific_hash(), i64::MAX);
    }
}
