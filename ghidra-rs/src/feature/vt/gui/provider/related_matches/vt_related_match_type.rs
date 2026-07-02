use crate::feature::vt::api::main::vt_association_status::VtAssociationStatus;
use crate::feature::vt::gui::provider::related_matches::vt_related_match_correlation_type::VtRelatedMatchCorrelationType;

/// Classifies a related match by how its source and destination correlate to the
/// primary match, its association status, and a "goodness" ranking used to sort
/// candidate related matches.
///
/// Mirrors `VTRelatedMatchType` from the Java source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtRelatedMatchType {
    TargetMatchesTargetAccepted,
    CallerMatchesCallerAccepted,
    CalleeMatchesCalleeAccepted,
    TargetMatchesTargetAvailable,
    CallerMatchesCallerAvailable,
    CalleeMatchesCalleeAvailable,
    CallerMatchesTargetLockedOut,
    CalleeMatchesTargetLockedOut,
    TargetMatchesCallerLockedOut,
    TargetMatchesCalleeLockedOut,
    TargetMatchesUnrelatedLockedOut,
    UnrelatedMatchesTargetLockedOut,
    CallerMatchesCalleeLockedOut,
    CalleeMatchesCallerLockedOut,
    CallerMatchesUnrelatedLockedOut,
    CalleeMatchesUnrelatedLockedOut,
    UnrelatedMatchesCallerLockedOut,
    UnrelatedMatchesCalleeLockedOut,
    CallerMatchesUnrelatedAvailable,
    CalleeMatchesUnrelatedAvailable,
    UnrelatedMatchesCallerAvailable,
    UnrelatedMatchesCalleeAvailable,
    TargetMatchesUnrelatedAvailable,
    UnrelatedMatchesTargetAvailable,
    CallerMatchesTargetAvailable,
    CalleeMatchesTargetAvailable,
    TargetMatchesCallerAvailable,
    TargetMatchesCalleeAvailable,
    CallerMatchesCalleeAvailable,
    CalleeMatchesCallerAvailable,
    CallerMatchesUnrelatedAccepted,
    CalleeMatchesUnrelatedAccepted,
    UnrelatedMatchesCallerAccepted,
    UnrelatedMatchesCalleeAccepted,
    CallerMatchesCallerLockedOut,
    CalleeMatchesCalleeLockedOut,
    CallerMatchesCalleeAccepted,
    CalleeMatchesCallerAccepted,
    TargetMatchesUnrelatedAccepted,
    UnrelatedMatchesTargetAccepted,
    CallerMatchesTargetAccepted,
    CalleeMatchesTargetAccepted,
    TargetMatchesCallerAccepted,
    TargetMatchesCalleeAccepted,
    TargetMatchesTargetLockedOut,
}

impl VtRelatedMatchType {
    /// All variants, in Java declaration order.
    pub const VALUES: &'static [VtRelatedMatchType] = &[
        Self::TargetMatchesTargetAccepted,
        Self::CallerMatchesCallerAccepted,
        Self::CalleeMatchesCalleeAccepted,
        Self::TargetMatchesTargetAvailable,
        Self::CallerMatchesCallerAvailable,
        Self::CalleeMatchesCalleeAvailable,
        Self::CallerMatchesTargetLockedOut,
        Self::CalleeMatchesTargetLockedOut,
        Self::TargetMatchesCallerLockedOut,
        Self::TargetMatchesCalleeLockedOut,
        Self::TargetMatchesUnrelatedLockedOut,
        Self::UnrelatedMatchesTargetLockedOut,
        Self::CallerMatchesCalleeLockedOut,
        Self::CalleeMatchesCallerLockedOut,
        Self::CallerMatchesUnrelatedLockedOut,
        Self::CalleeMatchesUnrelatedLockedOut,
        Self::UnrelatedMatchesCallerLockedOut,
        Self::UnrelatedMatchesCalleeLockedOut,
        Self::CallerMatchesUnrelatedAvailable,
        Self::CalleeMatchesUnrelatedAvailable,
        Self::UnrelatedMatchesCallerAvailable,
        Self::UnrelatedMatchesCalleeAvailable,
        Self::TargetMatchesUnrelatedAvailable,
        Self::UnrelatedMatchesTargetAvailable,
        Self::CallerMatchesTargetAvailable,
        Self::CalleeMatchesTargetAvailable,
        Self::TargetMatchesCallerAvailable,
        Self::TargetMatchesCalleeAvailable,
        Self::CallerMatchesCalleeAvailable,
        Self::CalleeMatchesCallerAvailable,
        Self::CallerMatchesUnrelatedAccepted,
        Self::CalleeMatchesUnrelatedAccepted,
        Self::UnrelatedMatchesCallerAccepted,
        Self::UnrelatedMatchesCalleeAccepted,
        Self::CallerMatchesCallerLockedOut,
        Self::CalleeMatchesCalleeLockedOut,
        Self::CallerMatchesCalleeAccepted,
        Self::CalleeMatchesCallerAccepted,
        Self::TargetMatchesUnrelatedAccepted,
        Self::UnrelatedMatchesTargetAccepted,
        Self::CallerMatchesTargetAccepted,
        Self::CalleeMatchesTargetAccepted,
        Self::TargetMatchesCallerAccepted,
        Self::TargetMatchesCalleeAccepted,
        Self::TargetMatchesTargetLockedOut,
    ];

    /// The correlation of the source match to the primary match.
    pub fn source_type(&self) -> VtRelatedMatchCorrelationType {
        use VtRelatedMatchCorrelationType::*;
        match self {
            Self::TargetMatchesTargetAccepted => Target,
            Self::CallerMatchesCallerAccepted => Caller,
            Self::CalleeMatchesCalleeAccepted => Callee,
            Self::TargetMatchesTargetAvailable => Target,
            Self::CallerMatchesCallerAvailable => Caller,
            Self::CalleeMatchesCalleeAvailable => Callee,
            Self::CallerMatchesTargetLockedOut => Caller,
            Self::CalleeMatchesTargetLockedOut => Callee,
            Self::TargetMatchesCallerLockedOut => Target,
            Self::TargetMatchesCalleeLockedOut => Target,
            Self::TargetMatchesUnrelatedLockedOut => Target,
            Self::UnrelatedMatchesTargetLockedOut => Unrelated,
            Self::CallerMatchesCalleeLockedOut => Caller,
            Self::CalleeMatchesCallerLockedOut => Callee,
            Self::CallerMatchesUnrelatedLockedOut => Caller,
            Self::CalleeMatchesUnrelatedLockedOut => Callee,
            Self::UnrelatedMatchesCallerLockedOut => Unrelated,
            Self::UnrelatedMatchesCalleeLockedOut => Unrelated,
            Self::CallerMatchesUnrelatedAvailable => Caller,
            Self::CalleeMatchesUnrelatedAvailable => Callee,
            Self::UnrelatedMatchesCallerAvailable => Unrelated,
            Self::UnrelatedMatchesCalleeAvailable => Unrelated,
            Self::TargetMatchesUnrelatedAvailable => Target,
            Self::UnrelatedMatchesTargetAvailable => Unrelated,
            Self::CallerMatchesTargetAvailable => Caller,
            Self::CalleeMatchesTargetAvailable => Callee,
            Self::TargetMatchesCallerAvailable => Target,
            Self::TargetMatchesCalleeAvailable => Target,
            Self::CallerMatchesCalleeAvailable => Caller,
            Self::CalleeMatchesCallerAvailable => Callee,
            Self::CallerMatchesUnrelatedAccepted => Caller,
            Self::CalleeMatchesUnrelatedAccepted => Callee,
            Self::UnrelatedMatchesCallerAccepted => Unrelated,
            Self::UnrelatedMatchesCalleeAccepted => Unrelated,
            Self::CallerMatchesCallerLockedOut => Caller,
            Self::CalleeMatchesCalleeLockedOut => Callee,
            Self::CallerMatchesCalleeAccepted => Caller,
            Self::CalleeMatchesCallerAccepted => Callee,
            Self::TargetMatchesUnrelatedAccepted => Target,
            Self::UnrelatedMatchesTargetAccepted => Unrelated,
            Self::CallerMatchesTargetAccepted => Caller,
            Self::CalleeMatchesTargetAccepted => Callee,
            Self::TargetMatchesCallerAccepted => Target,
            Self::TargetMatchesCalleeAccepted => Target,
            Self::TargetMatchesTargetLockedOut => Target,
        }
    }

    /// The correlation of the destination match to the primary match.
    pub fn destination_type(&self) -> VtRelatedMatchCorrelationType {
        use VtRelatedMatchCorrelationType::*;
        match self {
            Self::TargetMatchesTargetAccepted => Target,
            Self::CallerMatchesCallerAccepted => Caller,
            Self::CalleeMatchesCalleeAccepted => Callee,
            Self::TargetMatchesTargetAvailable => Target,
            Self::CallerMatchesCallerAvailable => Caller,
            Self::CalleeMatchesCalleeAvailable => Callee,
            Self::CallerMatchesTargetLockedOut => Target,
            Self::CalleeMatchesTargetLockedOut => Target,
            Self::TargetMatchesCallerLockedOut => Caller,
            Self::TargetMatchesCalleeLockedOut => Callee,
            Self::TargetMatchesUnrelatedLockedOut => Unrelated,
            Self::UnrelatedMatchesTargetLockedOut => Target,
            Self::CallerMatchesCalleeLockedOut => Callee,
            Self::CalleeMatchesCallerLockedOut => Caller,
            Self::CallerMatchesUnrelatedLockedOut => Unrelated,
            Self::CalleeMatchesUnrelatedLockedOut => Unrelated,
            Self::UnrelatedMatchesCallerLockedOut => Caller,
            Self::UnrelatedMatchesCalleeLockedOut => Callee,
            Self::CallerMatchesUnrelatedAvailable => Unrelated,
            Self::CalleeMatchesUnrelatedAvailable => Unrelated,
            Self::UnrelatedMatchesCallerAvailable => Caller,
            Self::UnrelatedMatchesCalleeAvailable => Callee,
            Self::TargetMatchesUnrelatedAvailable => Unrelated,
            Self::UnrelatedMatchesTargetAvailable => Target,
            Self::CallerMatchesTargetAvailable => Target,
            Self::CalleeMatchesTargetAvailable => Target,
            Self::TargetMatchesCallerAvailable => Caller,
            Self::TargetMatchesCalleeAvailable => Callee,
            Self::CallerMatchesCalleeAvailable => Callee,
            Self::CalleeMatchesCallerAvailable => Caller,
            Self::CallerMatchesUnrelatedAccepted => Unrelated,
            Self::CalleeMatchesUnrelatedAccepted => Unrelated,
            Self::UnrelatedMatchesCallerAccepted => Caller,
            Self::UnrelatedMatchesCalleeAccepted => Callee,
            Self::CallerMatchesCallerLockedOut => Caller,
            Self::CalleeMatchesCalleeLockedOut => Callee,
            Self::CallerMatchesCalleeAccepted => Callee,
            Self::CalleeMatchesCallerAccepted => Caller,
            Self::TargetMatchesUnrelatedAccepted => Unrelated,
            Self::UnrelatedMatchesTargetAccepted => Target,
            Self::CallerMatchesTargetAccepted => Target,
            Self::CalleeMatchesTargetAccepted => Target,
            Self::TargetMatchesCallerAccepted => Caller,
            Self::TargetMatchesCalleeAccepted => Callee,
            Self::TargetMatchesTargetLockedOut => Target,
        }
    }

    /// The association status this related match type applies to.
    pub fn association_status(&self) -> VtAssociationStatus {
        use VtAssociationStatus::*;
        match self {
            Self::TargetMatchesTargetAccepted => Accepted,
            Self::CallerMatchesCallerAccepted => Accepted,
            Self::CalleeMatchesCalleeAccepted => Accepted,
            Self::TargetMatchesTargetAvailable => Available,
            Self::CallerMatchesCallerAvailable => Available,
            Self::CalleeMatchesCalleeAvailable => Available,
            Self::CallerMatchesTargetLockedOut => Blocked,
            Self::CalleeMatchesTargetLockedOut => Blocked,
            Self::TargetMatchesCallerLockedOut => Blocked,
            Self::TargetMatchesCalleeLockedOut => Blocked,
            Self::TargetMatchesUnrelatedLockedOut => Blocked,
            Self::UnrelatedMatchesTargetLockedOut => Blocked,
            Self::CallerMatchesCalleeLockedOut => Blocked,
            Self::CalleeMatchesCallerLockedOut => Blocked,
            Self::CallerMatchesUnrelatedLockedOut => Blocked,
            Self::CalleeMatchesUnrelatedLockedOut => Blocked,
            Self::UnrelatedMatchesCallerLockedOut => Blocked,
            Self::UnrelatedMatchesCalleeLockedOut => Blocked,
            Self::CallerMatchesUnrelatedAvailable => Available,
            Self::CalleeMatchesUnrelatedAvailable => Available,
            Self::UnrelatedMatchesCallerAvailable => Available,
            Self::UnrelatedMatchesCalleeAvailable => Available,
            Self::TargetMatchesUnrelatedAvailable => Available,
            Self::UnrelatedMatchesTargetAvailable => Available,
            Self::CallerMatchesTargetAvailable => Available,
            Self::CalleeMatchesTargetAvailable => Available,
            Self::TargetMatchesCallerAvailable => Available,
            Self::TargetMatchesCalleeAvailable => Available,
            Self::CallerMatchesCalleeAvailable => Available,
            Self::CalleeMatchesCallerAvailable => Available,
            Self::CallerMatchesUnrelatedAccepted => Accepted,
            Self::CalleeMatchesUnrelatedAccepted => Accepted,
            Self::UnrelatedMatchesCallerAccepted => Accepted,
            Self::UnrelatedMatchesCalleeAccepted => Accepted,
            Self::CallerMatchesCallerLockedOut => Blocked,
            Self::CalleeMatchesCalleeLockedOut => Blocked,
            Self::CallerMatchesCalleeAccepted => Accepted,
            Self::CalleeMatchesCallerAccepted => Accepted,
            Self::TargetMatchesUnrelatedAccepted => Accepted,
            Self::UnrelatedMatchesTargetAccepted => Accepted,
            Self::CallerMatchesTargetAccepted => Accepted,
            Self::CalleeMatchesTargetAccepted => Accepted,
            Self::TargetMatchesCallerAccepted => Accepted,
            Self::TargetMatchesCalleeAccepted => Accepted,
            Self::TargetMatchesTargetLockedOut => Blocked,
        }
    }

    /// The relative ranking of this related match type; higher is better.
    pub fn goodness(&self) -> i32 {
        match self {
            Self::TargetMatchesTargetAccepted => 100,
            Self::CallerMatchesCallerAccepted => 90,
            Self::CalleeMatchesCalleeAccepted => 90,
            Self::TargetMatchesTargetAvailable => 80,
            Self::CallerMatchesCallerAvailable => 80,
            Self::CalleeMatchesCalleeAvailable => 80,
            Self::CallerMatchesTargetLockedOut => 70,
            Self::CalleeMatchesTargetLockedOut => 70,
            Self::TargetMatchesCallerLockedOut => 70,
            Self::TargetMatchesCalleeLockedOut => 70,
            Self::TargetMatchesUnrelatedLockedOut => 70,
            Self::UnrelatedMatchesTargetLockedOut => 70,
            Self::CallerMatchesCalleeLockedOut => 60,
            Self::CalleeMatchesCallerLockedOut => 60,
            Self::CallerMatchesUnrelatedLockedOut => 60,
            Self::CalleeMatchesUnrelatedLockedOut => 60,
            Self::UnrelatedMatchesCallerLockedOut => 60,
            Self::UnrelatedMatchesCalleeLockedOut => 60,
            Self::CallerMatchesUnrelatedAvailable => 50,
            Self::CalleeMatchesUnrelatedAvailable => 50,
            Self::UnrelatedMatchesCallerAvailable => 50,
            Self::UnrelatedMatchesCalleeAvailable => 50,
            Self::TargetMatchesUnrelatedAvailable => 50,
            Self::UnrelatedMatchesTargetAvailable => 50,
            Self::CallerMatchesTargetAvailable => 50,
            Self::CalleeMatchesTargetAvailable => 50,
            Self::TargetMatchesCallerAvailable => 50,
            Self::TargetMatchesCalleeAvailable => 50,
            Self::CallerMatchesCalleeAvailable => 50,
            Self::CalleeMatchesCallerAvailable => 50,
            Self::CallerMatchesUnrelatedAccepted => 40,
            Self::CalleeMatchesUnrelatedAccepted => 40,
            Self::UnrelatedMatchesCallerAccepted => 40,
            Self::UnrelatedMatchesCalleeAccepted => 40,
            Self::CallerMatchesCallerLockedOut => 30,
            Self::CalleeMatchesCalleeLockedOut => 30,
            Self::CallerMatchesCalleeAccepted => 20,
            Self::CalleeMatchesCallerAccepted => 20,
            Self::TargetMatchesUnrelatedAccepted => 10,
            Self::UnrelatedMatchesTargetAccepted => 10,
            Self::CallerMatchesTargetAccepted => 10,
            Self::CalleeMatchesTargetAccepted => 10,
            Self::TargetMatchesCallerAccepted => 10,
            Self::TargetMatchesCalleeAccepted => 10,
            Self::TargetMatchesTargetLockedOut => 0,
        }
    }

    /// Finds the related match type whose source type, destination type, and
    /// association status match the given values, if any.
    pub fn find_match_type(
        source_type: VtRelatedMatchCorrelationType,
        destination_type: VtRelatedMatchCorrelationType,
        association_status: VtAssociationStatus,
    ) -> Option<VtRelatedMatchType> {
        Self::VALUES
            .iter()
            .copied()
            .find(|related_match_type| {
                related_match_type.source_type() == source_type
                    && related_match_type.destination_type() == destination_type
                    && related_match_type.association_status() == association_status
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_present() {
        assert_eq!(VtRelatedMatchType::VALUES.len(), 45);
    }

    #[test]
    fn goodness_matches_java() {
        assert_eq!(VtRelatedMatchType::TargetMatchesTargetAccepted.goodness(), 100);
        assert_eq!(VtRelatedMatchType::CallerMatchesCallerAccepted.goodness(), 90);
        assert_eq!(VtRelatedMatchType::TargetMatchesTargetLockedOut.goodness(), 0);
    }

    #[test]
    fn source_and_destination_types_match_java() {
        let t = VtRelatedMatchType::CallerMatchesTargetLockedOut;
        assert_eq!(t.source_type(), VtRelatedMatchCorrelationType::Caller);
        assert_eq!(t.destination_type(), VtRelatedMatchCorrelationType::Target);
        assert_eq!(t.association_status(), VtAssociationStatus::Blocked);
    }

    #[test]
    fn find_match_type_returns_expected_variant() {
        let found = VtRelatedMatchType::find_match_type(
            VtRelatedMatchCorrelationType::Target,
            VtRelatedMatchCorrelationType::Target,
            VtAssociationStatus::Accepted,
        );
        assert_eq!(found, Some(VtRelatedMatchType::TargetMatchesTargetAccepted));
    }

    #[test]
    fn find_match_type_returns_none_for_unmatched_combination() {
        // No Java enum constant has both source and destination Unrelated.
        let found = VtRelatedMatchType::find_match_type(
            VtRelatedMatchCorrelationType::Unrelated,
            VtRelatedMatchCorrelationType::Unrelated,
            VtAssociationStatus::Rejected,
        );
        assert_eq!(found, None);
    }

    #[test]
    fn all_variants_have_unique_source_destination_status_triples() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for &variant in VtRelatedMatchType::VALUES {
            let key = (
                variant.source_type(),
                variant.destination_type(),
                variant.association_status(),
            );
            assert!(seen.insert(key), "duplicate triple for {variant:?}");
        }
    }
}
