/// Defines the matching strategy used by a text filter.
///
/// Corresponds to `docking.widgets.filter.TextFilterStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextFilterStrategy {
    /// Matches items that contain the filter text as a substring.
    Contains,
    /// Matches items that begin with the filter text.
    StartsWith,
    /// Matches items that are exactly equal to the filter text.
    MatchesExactly,
    /// Matches items using the filter text as a regular expression.
    RegularExpression,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_are_distinct() {
        let variants = [
            TextFilterStrategy::Contains,
            TextFilterStrategy::StartsWith,
            TextFilterStrategy::MatchesExactly,
            TextFilterStrategy::RegularExpression,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn copy_and_clone() {
        let strategy = TextFilterStrategy::Contains;
        let copied = strategy;
        assert_eq!(strategy, copied);
        let cloned = strategy.clone();
        assert_eq!(strategy, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", TextFilterStrategy::Contains), "Contains");
        assert_eq!(format!("{:?}", TextFilterStrategy::StartsWith), "StartsWith");
        assert_eq!(format!("{:?}", TextFilterStrategy::MatchesExactly), "MatchesExactly");
        assert_eq!(format!("{:?}", TextFilterStrategy::RegularExpression), "RegularExpression");
    }
}
