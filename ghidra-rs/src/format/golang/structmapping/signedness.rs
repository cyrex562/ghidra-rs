/// Signedness attribute of a structure-mapped field.
///
/// Rust equivalent of the Java `Signedness` enum in the struct-mapping framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signedness {
    /// No signedness override — use the data type's natural signedness.
    #[default]
    Unspecified,
    /// Force signed interpretation of the underlying numeric value.
    Signed,
    /// Force unsigned interpretation of the underlying numeric value.
    Unsigned,
}

#[cfg(test)]
mod tests {
    use super::Signedness;

    #[test]
    fn default_is_unspecified() {
        assert_eq!(Signedness::default(), Signedness::Unspecified);
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(Signedness::Unspecified, Signedness::Signed);
        assert_ne!(Signedness::Signed, Signedness::Unsigned);
        assert_ne!(Signedness::Unspecified, Signedness::Unsigned);
    }

    #[test]
    fn clone_works() {
        let s = Signedness::Signed;
        assert_eq!(s, s.clone());
    }

    #[test]
    fn copy_works() {
        let s = Signedness::Unsigned;
        let t = s;
        assert_eq!(s, t);
    }

    #[test]
    fn debug_format_contains_variant_name() {
        assert!(format!("{:?}", Signedness::Unspecified).contains("Unspecified"));
        assert!(format!("{:?}", Signedness::Signed).contains("Signed"));
        assert!(format!("{:?}", Signedness::Unsigned).contains("Unsigned"));
    }
}
