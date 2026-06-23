/// Enum of BSim results apply statuses for when users attempt to apply function names or signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BSimResultStatus {
    NotApplied,
    NameApplied,
    SignatureApplied,
    Matches,
    AppliedNoLongerMatches,
    Error,
    NoFunction,
    Ignored,
}

impl BSimResultStatus {
    pub fn description(&self) -> &'static str {
        match self {
            Self::NotApplied => "This result has not been applied.",
            Self::NameApplied => "The name and namespace have been applied.",
            Self::SignatureApplied => "The name, namespace and signature have been applied.",
            Self::Matches => "The name already matches.",
            Self::AppliedNoLongerMatches => {
                "This result has been applied, but no longer matches!"
            }
            Self::Error => "An error occurred while attempting to apply this result.",
            Self::NoFunction => "There is no longer a function at the result address!",
            Self::Ignored => "The result was not applied because it already matched.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptions_match_java_source() {
        assert_eq!(
            BSimResultStatus::NotApplied.description(),
            "This result has not been applied."
        );
        assert_eq!(
            BSimResultStatus::NameApplied.description(),
            "The name and namespace have been applied."
        );
        assert_eq!(
            BSimResultStatus::SignatureApplied.description(),
            "The name, namespace and signature have been applied."
        );
        assert_eq!(
            BSimResultStatus::Matches.description(),
            "The name already matches."
        );
        assert_eq!(
            BSimResultStatus::AppliedNoLongerMatches.description(),
            "This result has been applied, but no longer matches!"
        );
        assert_eq!(
            BSimResultStatus::Error.description(),
            "An error occurred while attempting to apply this result."
        );
        assert_eq!(
            BSimResultStatus::NoFunction.description(),
            "There is no longer a function at the result address!"
        );
        assert_eq!(
            BSimResultStatus::Ignored.description(),
            "The result was not applied because it already matched."
        );
    }

    #[test]
    fn test_all_variants_are_distinct() {
        use std::collections::HashSet;
        let variants = [
            BSimResultStatus::NotApplied,
            BSimResultStatus::NameApplied,
            BSimResultStatus::SignatureApplied,
            BSimResultStatus::Matches,
            BSimResultStatus::AppliedNoLongerMatches,
            BSimResultStatus::Error,
            BSimResultStatus::NoFunction,
            BSimResultStatus::Ignored,
        ];
        let descriptions: HashSet<&str> = variants.iter().map(|v| v.description()).collect();
        assert_eq!(descriptions.len(), variants.len());
    }

    #[test]
    fn test_clone_and_eq() {
        let s = BSimResultStatus::Matches;
        assert_eq!(s, s.clone());
        assert_ne!(BSimResultStatus::Matches, BSimResultStatus::Error);
    }
}
