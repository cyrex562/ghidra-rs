/// Memory model configuration for Locality-Sensitive Hashing (LSH).
///
/// Each variant encodes a trade-off between memory consumption and query
/// speed by controlling `k`, the number of hyperplanes per bin.
///
/// Mirrors `generic.lsh.LSHMemoryModel` from Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LshMemoryModel {
    /// Small memory footprint; slower query performance (`k = 10`).
    Small,
    /// Balanced memory and performance (`k = 13`).
    Medium,
    /// Large memory footprint; faster query performance (`k = 16`).
    Large,
}

impl LshMemoryModel {
    /// Returns the human-readable label for this memory model.
    pub fn label(self) -> &'static str {
        match self {
            LshMemoryModel::Small => "Small (slower)",
            LshMemoryModel::Medium => "Medium",
            LshMemoryModel::Large => "Large (faster)",
        }
    }

    /// Returns `k`, the number of hyperplanes comprising each bin.
    pub fn k(self) -> i32 {
        match self {
            LshMemoryModel::Small => 10,
            LshMemoryModel::Medium => 13,
            LshMemoryModel::Large => 16,
        }
    }

    /// Returns the probability threshold used in LSH scoring.
    pub fn probability_threshold(self) -> f64 {
        0.97
    }

    /// Returns the tau bound used in LSH scoring.
    pub fn tau_bound(self) -> f64 {
        0.75
    }
}

impl std::fmt::Display for LshMemoryModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_has_k_10() {
        assert_eq!(LshMemoryModel::Small.k(), 10);
    }

    #[test]
    fn medium_has_k_13() {
        assert_eq!(LshMemoryModel::Medium.k(), 13);
    }

    #[test]
    fn large_has_k_16() {
        assert_eq!(LshMemoryModel::Large.k(), 16);
    }

    #[test]
    fn labels_match_java_source() {
        assert_eq!(LshMemoryModel::Small.label(), "Small (slower)");
        assert_eq!(LshMemoryModel::Medium.label(), "Medium");
        assert_eq!(LshMemoryModel::Large.label(), "Large (faster)");
    }

    #[test]
    fn display_equals_label() {
        for model in [LshMemoryModel::Small, LshMemoryModel::Medium, LshMemoryModel::Large] {
            assert_eq!(model.to_string(), model.label());
        }
    }

    #[test]
    fn probability_threshold_is_consistent() {
        for model in [LshMemoryModel::Small, LshMemoryModel::Medium, LshMemoryModel::Large] {
            assert!((model.probability_threshold() - 0.97).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn tau_bound_is_consistent() {
        for model in [LshMemoryModel::Small, LshMemoryModel::Medium, LshMemoryModel::Large] {
            assert!((model.tau_bound() - 0.75).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn copy_and_eq() {
        let a = LshMemoryModel::Medium;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn hash_usable_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LshMemoryModel::Small);
        set.insert(LshMemoryModel::Large);
        assert!(set.contains(&LshMemoryModel::Small));
        assert!(!set.contains(&LshMemoryModel::Medium));
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(LshMemoryModel::Small, LshMemoryModel::Medium);
        assert_ne!(LshMemoryModel::Medium, LshMemoryModel::Large);
        assert_ne!(LshMemoryModel::Small, LshMemoryModel::Large);
    }
}
