use std::collections::HashSet;

/// Holds the set of bookmark type names that pass a filter.
pub struct FilterState {
    bookmark_types: HashSet<String>,
}

impl FilterState {
    pub fn new(bookmark_types: HashSet<String>) -> Self {
        Self { bookmark_types }
    }

    pub fn bookmark_types(&self) -> &HashSet<String> {
        &self.bookmark_types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_getter() {
        let types: HashSet<String> = ["Note", "Error"].iter().map(|s| s.to_string()).collect();
        let state = FilterState::new(types.clone());
        assert_eq!(state.bookmark_types(), &types);
    }

    #[test]
    fn test_empty_set() {
        let state = FilterState::new(HashSet::new());
        assert!(state.bookmark_types().is_empty());
    }

    #[test]
    fn test_single_type() {
        let mut types = HashSet::new();
        types.insert("Warning".to_string());
        let state = FilterState::new(types);
        assert!(state.bookmark_types().contains("Warning"));
        assert_eq!(state.bookmark_types().len(), 1);
    }

    #[test]
    fn test_multiple_types() {
        let types: HashSet<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        let state = FilterState::new(types);
        assert_eq!(state.bookmark_types().len(), 3);
        assert!(state.bookmark_types().contains("A"));
        assert!(state.bookmark_types().contains("B"));
        assert!(state.bookmark_types().contains("C"));
    }
}
