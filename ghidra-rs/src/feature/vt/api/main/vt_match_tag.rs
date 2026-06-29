use std::cmp::Ordering;

/// A tag that can be attached to a version-tracking match.
///
/// Corresponds to the Java `VTMatchTag` interface. The `UNTAGGED` sentinel
/// maps to [`VtMatchTag::Untagged`]; user-defined tags map to
/// [`VtMatchTag::Named`]. Equality and ordering are determined by the tag
/// name, matching the Java `compareTo` / `equals` contracts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VtMatchTag {
    /// Represents an untagged match (Java: `VTMatchTag.UNTAGGED`).
    Untagged,
    /// A user-defined named tag.
    Named(String),
}

impl VtMatchTag {
    /// Returns the name of this tag, or an empty string for [`VtMatchTag::Untagged`].
    pub fn name(&self) -> &str {
        match self {
            Self::Untagged => "",
            Self::Named(n) => n,
        }
    }
}

impl std::fmt::Display for VtMatchTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Untagged => f.write_str("<Not Tagged>"),
            Self::Named(n) => f.write_str(n),
        }
    }
}

impl PartialOrd for VtMatchTag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VtMatchTag {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name().cmp(other.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_name_is_empty() {
        assert_eq!(VtMatchTag::Untagged.name(), "");
    }

    #[test]
    fn named_name_matches() {
        assert_eq!(VtMatchTag::Named("foo".into()).name(), "foo");
    }

    #[test]
    fn untagged_display_is_not_tagged() {
        assert_eq!(VtMatchTag::Untagged.to_string(), "<Not Tagged>");
    }

    #[test]
    fn named_display_is_name() {
        assert_eq!(VtMatchTag::Named("bar".into()).to_string(), "bar");
    }

    #[test]
    fn ordering_by_name_lexicographic() {
        let a = VtMatchTag::Named("alpha".into());
        let b = VtMatchTag::Named("beta".into());
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }

    #[test]
    fn untagged_sorts_before_named() {
        // UNTAGGED has name "" which is less than any non-empty name
        let untagged = VtMatchTag::Untagged;
        let named = VtMatchTag::Named("a".into());
        assert!(untagged < named);
    }

    #[test]
    fn equality_by_name() {
        let a = VtMatchTag::Named("tag".into());
        let b = VtMatchTag::Named("tag".into());
        assert_eq!(a, b);

        let c = VtMatchTag::Named("other".into());
        assert_ne!(a, c);
    }

    #[test]
    fn untagged_equals_untagged() {
        assert_eq!(VtMatchTag::Untagged, VtMatchTag::Untagged);
    }

    #[test]
    fn untagged_not_equal_to_named_empty() {
        assert_ne!(VtMatchTag::Untagged, VtMatchTag::Named(String::new()));
    }

    #[test]
    fn clone_preserves_value() {
        let tag = VtMatchTag::Named("x".into());
        assert_eq!(tag.clone(), tag);
    }
}
