/// Determines sort order for [`Loader`]s: sorted first by tier, then by tier priority to break ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoaderTier {
    SpecializedTargetLoader,
    GenericTargetLoader,
    AmbiguousTargetLoader,
    UntargetedLoader,
}

#[cfg(test)]
mod tests {
    use super::LoaderTier;

    #[test]
    fn tier_ordering_matches_java_enum_ordinals() {
        assert!(LoaderTier::SpecializedTargetLoader < LoaderTier::GenericTargetLoader);
        assert!(LoaderTier::GenericTargetLoader < LoaderTier::AmbiguousTargetLoader);
        assert!(LoaderTier::AmbiguousTargetLoader < LoaderTier::UntargetedLoader);
    }

    #[test]
    fn tier_equality() {
        assert_eq!(LoaderTier::SpecializedTargetLoader, LoaderTier::SpecializedTargetLoader);
        assert_ne!(LoaderTier::SpecializedTargetLoader, LoaderTier::UntargetedLoader);
    }

    #[test]
    fn tier_clone_and_copy() {
        let tier = LoaderTier::GenericTargetLoader;
        let cloned = tier;
        assert_eq!(tier, cloned);
    }

    #[test]
    fn all_variants_are_distinct() {
        let tiers = [
            LoaderTier::SpecializedTargetLoader,
            LoaderTier::GenericTargetLoader,
            LoaderTier::AmbiguousTargetLoader,
            LoaderTier::UntargetedLoader,
        ];
        for i in 0..tiers.len() {
            for j in 0..tiers.len() {
                if i == j {
                    assert_eq!(tiers[i], tiers[j]);
                } else {
                    assert_ne!(tiers[i], tiers[j]);
                }
            }
        }
    }
}
