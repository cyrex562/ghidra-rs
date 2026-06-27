/// Optional interface that allows a struct-mapped object to verify itself after
/// deserialization.
///
/// This is the Rust equivalent of the Java `StructureVerifier` interface in
/// Ghidra's struct-mapping framework.  Types that need post-deserialization
/// validation implement this trait; the framework calls
/// [`is_valid`](StructureVerifier::is_valid) and can reject malformed instances.
pub trait StructureVerifier {
    /// Returns `true` if this object is in a valid, well-formed state.
    fn is_valid(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::StructureVerifier;

    struct AlwaysValid;

    impl StructureVerifier for AlwaysValid {
        fn is_valid(&self) -> bool {
            true
        }
    }

    struct AlwaysInvalid;

    impl StructureVerifier for AlwaysInvalid {
        fn is_valid(&self) -> bool {
            false
        }
    }

    struct Conditional {
        value: u32,
    }

    impl StructureVerifier for Conditional {
        fn is_valid(&self) -> bool {
            self.value > 0
        }
    }

    #[test]
    fn always_valid_returns_true() {
        assert!(AlwaysValid.is_valid());
    }

    #[test]
    fn always_invalid_returns_false() {
        assert!(!AlwaysInvalid.is_valid());
    }

    #[test]
    fn conditional_valid_when_nonzero() {
        assert!(Conditional { value: 42 }.is_valid());
    }

    #[test]
    fn conditional_invalid_when_zero() {
        assert!(!Conditional { value: 0 }.is_valid());
    }
}
