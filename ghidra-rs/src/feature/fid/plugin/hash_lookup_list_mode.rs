/// Indicates whether a hash should be considered as the full or specific hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashLookupListMode {
    Full,
    Specific,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_distinct() {
        assert_ne!(HashLookupListMode::Full, HashLookupListMode::Specific);
    }

    #[test]
    fn test_clone_and_copy() {
        let m = HashLookupListMode::Full;
        let c = m;
        assert_eq!(m, c);
        assert_eq!(m.clone(), m);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", HashLookupListMode::Full), "Full");
        assert_eq!(format!("{:?}", HashLookupListMode::Specific), "Specific");
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(HashLookupListMode::Full);
        set.insert(HashLookupListMode::Specific);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&HashLookupListMode::Full));
        assert!(set.contains(&HashLookupListMode::Specific));
    }
}
