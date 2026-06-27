/// Validates raw file pointers and relative virtual addresses (RVAs) within a PE image.
///
/// Implementors decide what range of pointer and RVA values are considered valid
/// for their particular PE image, allowing callers to reject obviously-bad offsets
/// before attempting to read data at those locations.
pub trait OffsetValidator {
    /// Returns `true` if `ptr` is a valid raw file pointer in this PE image.
    fn check_pointer(&self, ptr: u64) -> bool;

    /// Returns `true` if `rva` is a valid relative virtual address in this PE image.
    fn check_rva(&self, rva: u64) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysValid;
    impl OffsetValidator for AlwaysValid {
        fn check_pointer(&self, _ptr: u64) -> bool {
            true
        }
        fn check_rva(&self, _rva: u64) -> bool {
            true
        }
    }

    struct BoundedValidator {
        max_ptr: u64,
        max_rva: u64,
    }
    impl OffsetValidator for BoundedValidator {
        fn check_pointer(&self, ptr: u64) -> bool {
            ptr <= self.max_ptr
        }
        fn check_rva(&self, rva: u64) -> bool {
            rva <= self.max_rva
        }
    }

    #[test]
    fn always_valid_accepts_any_pointer() {
        let v = AlwaysValid;
        assert!(v.check_pointer(0));
        assert!(v.check_pointer(u64::MAX));
    }

    #[test]
    fn always_valid_accepts_any_rva() {
        let v = AlwaysValid;
        assert!(v.check_rva(0));
        assert!(v.check_rva(u64::MAX));
    }

    #[test]
    fn bounded_validator_rejects_out_of_range_pointer() {
        let v = BoundedValidator { max_ptr: 0x1000, max_rva: 0x2000 };
        assert!(v.check_pointer(0x1000));
        assert!(!v.check_pointer(0x1001));
    }

    #[test]
    fn bounded_validator_rejects_out_of_range_rva() {
        let v = BoundedValidator { max_ptr: 0x1000, max_rva: 0x2000 };
        assert!(v.check_rva(0x2000));
        assert!(!v.check_rva(0x2001));
    }

    #[test]
    fn bounded_validator_accepts_zero() {
        let v = BoundedValidator { max_ptr: 0x1000, max_rva: 0x2000 };
        assert!(v.check_pointer(0));
        assert!(v.check_rva(0));
    }
}
