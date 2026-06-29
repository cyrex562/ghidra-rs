/// Controls how multiple filter terms are combined.
///
/// Corresponds to `docking.widgets.filter.MultitermEvaluationMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultitermEvaluationMode {
    /// Object must match all filter terms.
    And,
    /// Object must match at least one filter term.
    Or,
}

impl MultitermEvaluationMode {
    /// Returns a human-readable description of this evaluation mode.
    pub fn description(self) -> &'static str {
        match self {
            Self::And => "Object must match all filter terms",
            Self::Or => "Object must match at least one filter term",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_description() {
        assert_eq!(
            MultitermEvaluationMode::And.description(),
            "Object must match all filter terms"
        );
    }

    #[test]
    fn or_description() {
        assert_eq!(
            MultitermEvaluationMode::Or.description(),
            "Object must match at least one filter term"
        );
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(MultitermEvaluationMode::And, MultitermEvaluationMode::Or);
    }

    #[test]
    fn copy_and_clone() {
        let mode = MultitermEvaluationMode::And;
        let copied = mode;
        assert_eq!(mode, copied);
    }
}
