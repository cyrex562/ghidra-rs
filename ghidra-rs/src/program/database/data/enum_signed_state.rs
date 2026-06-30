/// Tracks the signed state of an enum datatype.
///
/// Enums are fundamentally either signed or unsigned, but the state may be indeterminate until
/// a sufficiently large or negative value is added. Once a negative value is added the enum is
/// locked as [`Signed`][EnumSignedState::Signed], preventing high unsigned values. Once a high
/// unsigned value is added it is locked as [`Unsigned`][EnumSignedState::Unsigned]. If neither
/// has occurred the state is [`None`][EnumSignedState::None]. [`Invalid`][EnumSignedState::Invalid]
/// occurs when both negative and high unsigned values are present (can happen with old types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnumSignedState {
    /// Contains at least one negative value; high unsigned values are not permitted.
    Signed,
    /// Contains at least one high unsigned value; negative values are not permitted.
    Unsigned,
    /// Contains neither a negative nor a high unsigned value; either direction is still possible.
    None,
    /// Contains both negative and high unsigned values; arises in old data types.
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(EnumSignedState::Signed, EnumSignedState::Unsigned);
        assert_ne!(EnumSignedState::Signed, EnumSignedState::None);
        assert_ne!(EnumSignedState::Signed, EnumSignedState::Invalid);
        assert_ne!(EnumSignedState::Unsigned, EnumSignedState::None);
        assert_ne!(EnumSignedState::Unsigned, EnumSignedState::Invalid);
        assert_ne!(EnumSignedState::None, EnumSignedState::Invalid);
    }

    #[test]
    fn equality_reflexive() {
        assert_eq!(EnumSignedState::Signed, EnumSignedState::Signed);
        assert_eq!(EnumSignedState::Unsigned, EnumSignedState::Unsigned);
        assert_eq!(EnumSignedState::None, EnumSignedState::None);
        assert_eq!(EnumSignedState::Invalid, EnumSignedState::Invalid);
    }

    #[test]
    fn clone_preserves_variant() {
        for state in [
            EnumSignedState::Signed,
            EnumSignedState::Unsigned,
            EnumSignedState::None,
            EnumSignedState::Invalid,
        ] {
            assert_eq!(state.clone(), state);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", EnumSignedState::Signed).contains("Signed"));
        assert!(format!("{:?}", EnumSignedState::Unsigned).contains("Unsigned"));
        assert!(format!("{:?}", EnumSignedState::None).contains("None"));
        assert!(format!("{:?}", EnumSignedState::Invalid).contains("Invalid"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EnumSignedState::Signed);
        assert!(set.contains(&EnumSignedState::Signed));
        assert!(!set.contains(&EnumSignedState::Unsigned));
    }
}
