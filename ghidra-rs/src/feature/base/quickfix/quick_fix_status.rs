/// Possible status values of a QuickFix item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuickFixStatus {
    /// The item is unapplied and is ready to be executed.
    None,
    /// The item is unapplied and has an associated warning.
    Warning,
    /// The item is unapplied, but has changed from its original value.
    Changed,
    /// The item's target program element no longer exists.
    Deleted,
    /// The item can't be applied. This may occur before or after it is applied.
    Error,
    /// The item has been applied.
    Done,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_variants_distinct() {
        let variants = [
            QuickFixStatus::None,
            QuickFixStatus::Warning,
            QuickFixStatus::Changed,
            QuickFixStatus::Deleted,
            QuickFixStatus::Error,
            QuickFixStatus::Done,
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
    fn test_clone_and_copy() {
        let s = QuickFixStatus::Warning;
        let c = s;
        assert_eq!(s, c);
        assert_eq!(s.clone(), s);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", QuickFixStatus::None), "None");
        assert_eq!(format!("{:?}", QuickFixStatus::Warning), "Warning");
        assert_eq!(format!("{:?}", QuickFixStatus::Changed), "Changed");
        assert_eq!(format!("{:?}", QuickFixStatus::Deleted), "Deleted");
        assert_eq!(format!("{:?}", QuickFixStatus::Error), "Error");
        assert_eq!(format!("{:?}", QuickFixStatus::Done), "Done");
    }

    #[test]
    fn test_applied_vs_unapplied() {
        let applied = [QuickFixStatus::Done];
        let unapplied = [
            QuickFixStatus::None,
            QuickFixStatus::Warning,
            QuickFixStatus::Changed,
            QuickFixStatus::Deleted,
            QuickFixStatus::Error,
        ];
        for v in &applied {
            assert!(!unapplied.contains(v));
        }
        for v in &unapplied {
            assert!(!applied.contains(v));
        }
    }
}
