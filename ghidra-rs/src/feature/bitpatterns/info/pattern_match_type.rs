/// Different types of matches for a pattern.
///
/// Mirrors `ghidra.bitpatterns.info.PatternMatchType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternMatchType {
    /// A match at the start of a known function.
    TruePositive,
    /// A match within defined code that could be a function start.
    PossibleStartCode,
    /// A match that can't be a function start due to the wrong incoming flow.
    FpWrongFlow,
    /// A match that can't be a function start because it occurs within a defined instruction.
    FpMisaligned,
    /// A match within undefined bytes that could be a function start.
    PossibleStartUndefined,
    /// A match within defined data.
    FpData,
    /// A match with a context register conflict.
    ContextConflict,
    /// A match of a pre-pattern without a post-pattern.
    PrePatternHit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            PatternMatchType::TruePositive,
            PatternMatchType::PossibleStartCode,
            PatternMatchType::FpWrongFlow,
            PatternMatchType::FpMisaligned,
            PatternMatchType::PossibleStartUndefined,
            PatternMatchType::FpData,
            PatternMatchType::ContextConflict,
            PatternMatchType::PrePatternHit,
        ];
        let set: HashSet<_> = variants.iter().collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn clone_and_copy() {
        let a = PatternMatchType::TruePositive;
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", PatternMatchType::FpData), "FpData");
        assert_eq!(
            format!("{:?}", PatternMatchType::PrePatternHit),
            "PrePatternHit"
        );
    }
}
