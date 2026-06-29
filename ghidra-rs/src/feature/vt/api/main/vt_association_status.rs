/// High-level acceptance state for a version-tracking association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtAssociationStatus {
    /// Available for accepting; no competing association is currently accepted.
    Available,
    /// Accepted — competing associations cannot apply markup items while this
    /// status holds and not all markup items have been applied yet.
    Accepted,
    /// A competing association has been accepted; this association cannot be accepted.
    Blocked,
    /// The user has explicitly rejected this association.
    Rejected,
}

impl VtAssociationStatus {
    /// Returns the human-readable label for this status.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Accepted  => "Accepted",
            Self::Blocked   => "Blocked",
            Self::Rejected  => "Rejected",
        }
    }

    /// Returns `true` if a match with this status can transition to the accepted state.
    pub fn can_apply(&self) -> bool {
        matches!(self, Self::Accepted | Self::Available)
    }

    /// Returns `true` if a match with this status cannot be transitioned to an accepted state.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }
}

impl std::fmt::Display for VtAssociationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_match_java() {
        assert_eq!(VtAssociationStatus::Available.display_name(), "Available");
        assert_eq!(VtAssociationStatus::Accepted.display_name(),  "Accepted");
        assert_eq!(VtAssociationStatus::Blocked.display_name(),   "Blocked");
        assert_eq!(VtAssociationStatus::Rejected.display_name(),  "Rejected");
    }

    #[test]
    fn can_apply_true_for_accepted_and_available() {
        assert!(VtAssociationStatus::Accepted.can_apply());
        assert!(VtAssociationStatus::Available.can_apply());
        assert!(!VtAssociationStatus::Blocked.can_apply());
        assert!(!VtAssociationStatus::Rejected.can_apply());
    }

    #[test]
    fn is_blocked_true_for_blocked_and_rejected() {
        assert!(VtAssociationStatus::Blocked.is_blocked());
        assert!(VtAssociationStatus::Rejected.is_blocked());
        assert!(!VtAssociationStatus::Available.is_blocked());
        assert!(!VtAssociationStatus::Accepted.is_blocked());
    }

    #[test]
    fn can_apply_and_is_blocked_are_mutually_exclusive() {
        for status in [
            VtAssociationStatus::Available,
            VtAssociationStatus::Accepted,
            VtAssociationStatus::Blocked,
            VtAssociationStatus::Rejected,
        ] {
            assert_ne!(status.can_apply(), status.is_blocked());
        }
    }

    #[test]
    fn display_uses_display_name() {
        assert_eq!(VtAssociationStatus::Available.to_string(), "Available");
        assert_eq!(VtAssociationStatus::Rejected.to_string(),  "Rejected");
    }
}
