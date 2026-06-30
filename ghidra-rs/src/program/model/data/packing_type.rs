/// Specifies the pack setting which applies to a composite data type.
///
/// A composite can have packing `Disabled`, use the compiler `Default`, or
/// carry an `Explicit` pack value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackingType {
    /// Automatic component placement is not performed; components are placed at
    /// specified offsets and `undefined` components reflect padding/unused bytes.
    /// Commonly used when reverse-engineering a composite whose full definition
    /// is not yet known.
    Disabled,
    /// Components are placed automatically based on their alignment, mirroring
    /// the default compiler behavior when a complete composite definition is known.
    Default,
    /// An explicit pack value has been specified; components are placed
    /// automatically based on their alignment, not to exceed the pack value.
    Explicit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(PackingType::Disabled, PackingType::Default);
        assert_ne!(PackingType::Disabled, PackingType::Explicit);
        assert_ne!(PackingType::Default, PackingType::Explicit);
    }

    #[test]
    fn equality_reflexive() {
        assert_eq!(PackingType::Disabled, PackingType::Disabled);
        assert_eq!(PackingType::Default, PackingType::Default);
        assert_eq!(PackingType::Explicit, PackingType::Explicit);
    }

    #[test]
    fn clone_preserves_variant() {
        for variant in [
            PackingType::Disabled,
            PackingType::Default,
            PackingType::Explicit,
        ] {
            assert_eq!(variant.clone(), variant);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", PackingType::Disabled).contains("Disabled"));
        assert!(format!("{:?}", PackingType::Default).contains("Default"));
        assert!(format!("{:?}", PackingType::Explicit).contains("Explicit"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PackingType::Disabled);
        assert!(set.contains(&PackingType::Disabled));
        assert!(!set.contains(&PackingType::Default));
    }
}
