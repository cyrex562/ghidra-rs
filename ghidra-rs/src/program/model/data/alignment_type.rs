/// Specifies the type of alignment which applies to a composite data type.
///
/// For packed composites, the length is padded to a multiple of the computed alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlignmentType {
    /// Alignment computed from the current pack setting and data organization rules.
    /// If packing is disabled the computed alignment will be 1.
    Default,
    /// Alignment forced to a multiple of the machine alignment specified by the data organization.
    Machine,
    /// Alignment forced to a multiple of the explicit alignment value specified for the datatype.
    Explicit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(AlignmentType::Default, AlignmentType::Machine);
        assert_ne!(AlignmentType::Default, AlignmentType::Explicit);
        assert_ne!(AlignmentType::Machine, AlignmentType::Explicit);
    }

    #[test]
    fn equality_reflexive() {
        assert_eq!(AlignmentType::Default, AlignmentType::Default);
        assert_eq!(AlignmentType::Machine, AlignmentType::Machine);
        assert_eq!(AlignmentType::Explicit, AlignmentType::Explicit);
    }

    #[test]
    fn clone_preserves_variant() {
        for variant in [
            AlignmentType::Default,
            AlignmentType::Machine,
            AlignmentType::Explicit,
        ] {
            assert_eq!(variant.clone(), variant);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", AlignmentType::Default).contains("Default"));
        assert!(format!("{:?}", AlignmentType::Machine).contains("Machine"));
        assert!(format!("{:?}", AlignmentType::Explicit).contains("Explicit"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AlignmentType::Default);
        assert!(set.contains(&AlignmentType::Default));
        assert!(!set.contains(&AlignmentType::Machine));
    }
}
