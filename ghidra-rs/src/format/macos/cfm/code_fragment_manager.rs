/// Represents the Code Fragment Manager container format for classic Mac OS.
///
/// This is a marker type corresponding to the CFM binary format; it carries no
/// fields in the original Ghidra source and serves as a namespace anchor.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CodeFragmentManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructs() {
        let _ = CodeFragmentManager::default();
    }

    #[test]
    fn debug_repr_contains_name() {
        let s = format!("{:?}", CodeFragmentManager);
        assert!(s.contains("CodeFragmentManager"));
    }

    #[test]
    fn clone_equals_original() {
        let a = CodeFragmentManager;
        let b = a.clone();
        assert_eq!(a, b);
    }
}
