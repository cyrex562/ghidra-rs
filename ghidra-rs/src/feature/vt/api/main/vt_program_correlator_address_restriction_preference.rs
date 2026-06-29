/// Controls how a program correlator handles address restrictions when scoring matches.
///
/// Corresponds to `VTProgramCorrelatorAddressRestrictionPreference` in the Java source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtProgramCorrelatorAddressRestrictionPreference {
    /// The correlator has no preference regarding address restrictions.
    NoPreference,
    /// The correlator does not allow address restrictions to be applied.
    RestrictionNotAllowed,
    /// The correlator prefers to restrict scoring to previously accepted matches.
    PreferRestrictingAcceptedMatches,
}

impl VtProgramCorrelatorAddressRestrictionPreference {
    /// Returns the human-readable label for this preference.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::NoPreference => "No Preference",
            Self::RestrictionNotAllowed => "Restriction Not Allowed",
            Self::PreferRestrictingAcceptedMatches => "Prefer Restricting Accepted Matches",
        }
    }
}

impl std::fmt::Display for VtProgramCorrelatorAddressRestrictionPreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_distinct_display_names() {
        let names = [
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference.display_name(),
            VtProgramCorrelatorAddressRestrictionPreference::RestrictionNotAllowed.display_name(),
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
                .display_name(),
        ];
        assert_eq!(names[0], "No Preference");
        assert_eq!(names[1], "Restriction Not Allowed");
        assert_eq!(names[2], "Prefer Restricting Accepted Matches");
    }

    #[test]
    fn display_uses_display_name() {
        assert_eq!(
            VtProgramCorrelatorAddressRestrictionPreference::NoPreference.to_string(),
            "No Preference"
        );
        assert_eq!(
            VtProgramCorrelatorAddressRestrictionPreference::RestrictionNotAllowed.to_string(),
            "Restriction Not Allowed"
        );
        assert_eq!(
            VtProgramCorrelatorAddressRestrictionPreference::PreferRestrictingAcceptedMatches
                .to_string(),
            "Prefer Restricting Accepted Matches"
        );
    }

    #[test]
    fn variants_are_distinct() {
        use VtProgramCorrelatorAddressRestrictionPreference::*;
        assert_ne!(NoPreference, RestrictionNotAllowed);
        assert_ne!(NoPreference, PreferRestrictingAcceptedMatches);
        assert_ne!(RestrictionNotAllowed, PreferRestrictingAcceptedMatches);
    }

    #[test]
    fn copy_and_clone() {
        let a = VtProgramCorrelatorAddressRestrictionPreference::NoPreference;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), b);
    }
}
