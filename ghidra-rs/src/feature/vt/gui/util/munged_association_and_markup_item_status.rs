/// Status combining an association's acceptance state and its markup items' application state.
/// This is used for UI rendering and sorting in the version-tracking match provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MungedAssociationAndMarkupItemStatus {
    /// This match is available to be applied.
    Available,
    /// One or more markup errors occurred during application.
    AcceptedHasErrors,
    /// One or more markup items have not been considered.
    AcceptedSomeUnexamined,
    /// All markup items have been applied or ignored.
    AcceptedNoUnexamined,
    /// All markup items applied.
    AcceptedFullyApplied,
    /// This match is blocked by an already accepted conflicting match.
    Blocked,
    /// Rejected.
    Rejected,
}

impl MungedAssociationAndMarkupItemStatus {
    /// Returns a human-readable description for this status.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Available => "This match is available to be applied",
            Self::AcceptedHasErrors => "One or more markup errors",
            Self::AcceptedSomeUnexamined => "One or more markup items have not been considered",
            Self::AcceptedNoUnexamined => "All markup items have been applied or ignored",
            Self::AcceptedFullyApplied => "All markup items applied",
            Self::Blocked => "This match is blocked by an already accepted conflicting match",
            Self::Rejected => "Rejected",
        }
    }
}

impl std::fmt::Display for MungedAssociationAndMarkupItemStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_match_java() {
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::Available.description(),
            "This match is available to be applied"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::AcceptedHasErrors.description(),
            "One or more markup errors"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::AcceptedSomeUnexamined.description(),
            "One or more markup items have not been considered"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::AcceptedNoUnexamined.description(),
            "All markup items have been applied or ignored"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::AcceptedFullyApplied.description(),
            "All markup items applied"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::Blocked.description(),
            "This match is blocked by an already accepted conflicting match"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::Rejected.description(),
            "Rejected"
        );
    }

    #[test]
    fn display_uses_description() {
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::Available.to_string(),
            "This match is available to be applied"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::AcceptedHasErrors.to_string(),
            "One or more markup errors"
        );
        assert_eq!(
            MungedAssociationAndMarkupItemStatus::Rejected.to_string(),
            "Rejected"
        );
    }

    #[test]
    fn all_descriptions_non_empty() {
        let all = [
            MungedAssociationAndMarkupItemStatus::Available,
            MungedAssociationAndMarkupItemStatus::AcceptedHasErrors,
            MungedAssociationAndMarkupItemStatus::AcceptedSomeUnexamined,
            MungedAssociationAndMarkupItemStatus::AcceptedNoUnexamined,
            MungedAssociationAndMarkupItemStatus::AcceptedFullyApplied,
            MungedAssociationAndMarkupItemStatus::Blocked,
            MungedAssociationAndMarkupItemStatus::Rejected,
        ];
        for status in all {
            assert!(!status.description().is_empty());
        }
    }

    #[test]
    fn copy_semantics() {
        let a = MungedAssociationAndMarkupItemStatus::Available;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MungedAssociationAndMarkupItemStatus::Available);
        set.insert(MungedAssociationAndMarkupItemStatus::Rejected);
        set.insert(MungedAssociationAndMarkupItemStatus::Blocked);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn all_variants_distinct() {
        let all = [
            MungedAssociationAndMarkupItemStatus::Available,
            MungedAssociationAndMarkupItemStatus::AcceptedHasErrors,
            MungedAssociationAndMarkupItemStatus::AcceptedSomeUnexamined,
            MungedAssociationAndMarkupItemStatus::AcceptedNoUnexamined,
            MungedAssociationAndMarkupItemStatus::AcceptedFullyApplied,
            MungedAssociationAndMarkupItemStatus::Blocked,
            MungedAssociationAndMarkupItemStatus::Rejected,
        ];
        for (i, &a) in all.iter().enumerate() {
            for (j, &b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }
}
