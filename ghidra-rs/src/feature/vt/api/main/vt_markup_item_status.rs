/// Application state of a version-tracking markup item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtMarkupItemStatus {
    /// Item has not yet been applied to the destination program.
    Unapplied,
    /// Item was applied by adding a new value at the destination.
    Added,
    /// Item was applied by replacing an existing value at the destination.
    Replaced,
    /// An attempt to apply the item failed.
    FailedApply,
    /// The user has marked this item as one they do not care about.
    DontCare,
    /// The user has marked this item as one whose status they have not decided.
    DontKnow,
    /// The user has explicitly rejected this item.
    Rejected,
    /// The destination already has the same value; no action is needed.
    Same,
    /// A conflicting markup item is already applied at the destination.
    Conflict,
}

impl VtMarkupItemStatus {
    /// Returns the human-readable description for this status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Unapplied    => "Unapplied",
            Self::Added        => "Applied (Added)",
            Self::Replaced     => "Applied (Replaced)",
            Self::FailedApply  => "Apply Failed",
            Self::DontCare     => "Don't Care",
            Self::DontKnow     => "Don't Know",
            Self::Rejected     => "Rejected",
            Self::Same         => "Destination has same value",
            Self::Conflict     => "Conflicting item is applied",
        }
    }

    /// Returns `true` if this status permits applying the markup item.
    pub fn is_appliable(&self) -> bool {
        matches!(self, Self::Unapplied | Self::DontCare | Self::DontKnow)
    }

    /// Returns `true` if this status permits un-applying the markup item.
    pub fn is_unappliable(&self) -> bool {
        matches!(self, Self::Added | Self::Replaced)
    }

    /// Returns `true` for statuses that represent the item's default/initial
    /// state (same as Java's `isDefault`: `SAME`, `CONFLICT`, or `UNAPPLIED`).
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Same | Self::Conflict | Self::Unapplied)
    }
}

impl std::fmt::Display for VtMarkupItemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_match_java() {
        assert_eq!(VtMarkupItemStatus::Unapplied.description(),   "Unapplied");
        assert_eq!(VtMarkupItemStatus::Added.description(),       "Applied (Added)");
        assert_eq!(VtMarkupItemStatus::Replaced.description(),    "Applied (Replaced)");
        assert_eq!(VtMarkupItemStatus::FailedApply.description(), "Apply Failed");
        assert_eq!(VtMarkupItemStatus::DontCare.description(),    "Don't Care");
        assert_eq!(VtMarkupItemStatus::DontKnow.description(),    "Don't Know");
        assert_eq!(VtMarkupItemStatus::Rejected.description(),    "Rejected");
        assert_eq!(VtMarkupItemStatus::Same.description(),        "Destination has same value");
        assert_eq!(VtMarkupItemStatus::Conflict.description(),    "Conflicting item is applied");
    }

    #[test]
    fn is_appliable_matches_java() {
        assert!(VtMarkupItemStatus::Unapplied.is_appliable());
        assert!(VtMarkupItemStatus::DontCare.is_appliable());
        assert!(VtMarkupItemStatus::DontKnow.is_appliable());

        assert!(!VtMarkupItemStatus::Added.is_appliable());
        assert!(!VtMarkupItemStatus::Replaced.is_appliable());
        assert!(!VtMarkupItemStatus::FailedApply.is_appliable());
        assert!(!VtMarkupItemStatus::Rejected.is_appliable());
        assert!(!VtMarkupItemStatus::Same.is_appliable());
        assert!(!VtMarkupItemStatus::Conflict.is_appliable());
    }

    #[test]
    fn is_unappliable_matches_java() {
        assert!(VtMarkupItemStatus::Added.is_unappliable());
        assert!(VtMarkupItemStatus::Replaced.is_unappliable());

        assert!(!VtMarkupItemStatus::Unapplied.is_unappliable());
        assert!(!VtMarkupItemStatus::FailedApply.is_unappliable());
        assert!(!VtMarkupItemStatus::DontCare.is_unappliable());
        assert!(!VtMarkupItemStatus::DontKnow.is_unappliable());
        assert!(!VtMarkupItemStatus::Rejected.is_unappliable());
        assert!(!VtMarkupItemStatus::Same.is_unappliable());
        assert!(!VtMarkupItemStatus::Conflict.is_unappliable());
    }

    #[test]
    fn is_default_matches_java() {
        assert!(VtMarkupItemStatus::Same.is_default());
        assert!(VtMarkupItemStatus::Conflict.is_default());
        assert!(VtMarkupItemStatus::Unapplied.is_default());

        assert!(!VtMarkupItemStatus::Added.is_default());
        assert!(!VtMarkupItemStatus::Replaced.is_default());
        assert!(!VtMarkupItemStatus::FailedApply.is_default());
        assert!(!VtMarkupItemStatus::DontCare.is_default());
        assert!(!VtMarkupItemStatus::DontKnow.is_default());
        assert!(!VtMarkupItemStatus::Rejected.is_default());
    }

    #[test]
    fn appliable_and_unappliable_are_mutually_exclusive() {
        let all = [
            VtMarkupItemStatus::Unapplied,
            VtMarkupItemStatus::Added,
            VtMarkupItemStatus::Replaced,
            VtMarkupItemStatus::FailedApply,
            VtMarkupItemStatus::DontCare,
            VtMarkupItemStatus::DontKnow,
            VtMarkupItemStatus::Rejected,
            VtMarkupItemStatus::Same,
            VtMarkupItemStatus::Conflict,
        ];
        for s in all {
            assert!(!(s.is_appliable() && s.is_unappliable()), "{s:?} is both appliable and unappliable");
        }
    }

    #[test]
    fn display_uses_description() {
        assert_eq!(VtMarkupItemStatus::Unapplied.to_string(), "Unapplied");
        assert_eq!(VtMarkupItemStatus::Added.to_string(),     "Applied (Added)");
        assert_eq!(VtMarkupItemStatus::Same.to_string(),      "Destination has same value");
    }

    #[test]
    fn all_descriptions_non_empty() {
        let all = [
            VtMarkupItemStatus::Unapplied,
            VtMarkupItemStatus::Added,
            VtMarkupItemStatus::Replaced,
            VtMarkupItemStatus::FailedApply,
            VtMarkupItemStatus::DontCare,
            VtMarkupItemStatus::DontKnow,
            VtMarkupItemStatus::Rejected,
            VtMarkupItemStatus::Same,
            VtMarkupItemStatus::Conflict,
        ];
        for s in all {
            assert!(!s.description().is_empty());
        }
    }
}
