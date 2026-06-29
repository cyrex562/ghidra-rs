/// Represents the outcome of a condition test.
///
/// Corresponds to `docking.widgets.conditiontestpanel.ConditionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionStatus {
    None,
    Passed,
    Warning,
    Error,
    Cancelled,
    Skipped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let all = [
            ConditionStatus::None,
            ConditionStatus::Passed,
            ConditionStatus::Warning,
            ConditionStatus::Error,
            ConditionStatus::Cancelled,
            ConditionStatus::Skipped,
        ];
        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let original = ConditionStatus::Passed;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ConditionStatus::None), "None");
        assert_eq!(format!("{:?}", ConditionStatus::Passed), "Passed");
        assert_eq!(format!("{:?}", ConditionStatus::Warning), "Warning");
        assert_eq!(format!("{:?}", ConditionStatus::Error), "Error");
        assert_eq!(format!("{:?}", ConditionStatus::Cancelled), "Cancelled");
        assert_eq!(format!("{:?}", ConditionStatus::Skipped), "Skipped");
    }
}
