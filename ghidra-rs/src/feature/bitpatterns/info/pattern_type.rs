/// Different types of byte/instruction sequences relative to a function.
///
/// Mirrors `ghidra.bitpatterns.info.PatternType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternType {
    /// First instructions/bytes in a function.
    First,
    /// Instructions/bytes immediately before a function.
    Pre,
    /// Instructions/bytes before a function return.
    Return,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_variants_distinct() {
        let variants = [PatternType::First, PatternType::Pre, PatternType::Return];
        let set: HashSet<_> = variants.iter().collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn clone_and_copy() {
        let a = PatternType::First;
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", PatternType::First), "First");
        assert_eq!(format!("{:?}", PatternType::Pre), "Pre");
        assert_eq!(format!("{:?}", PatternType::Return), "Return");
    }
}
