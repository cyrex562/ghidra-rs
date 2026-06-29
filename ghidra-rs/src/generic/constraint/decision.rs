/// Result object from getting values that match the constraints for a given test object.
pub struct Decision {
    value: String,
    decision_path: Vec<String>,
    source: String,
}

impl Decision {
    pub fn new(value: String, decision_path: Vec<String>, source: String) -> Self {
        Self { value, decision_path, source }
    }

    /// Returns the value of the property for which this decision matched the constraints.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the constraint source file that added the value for this decision.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns a slice of strings where each string is a description of the constraint that
    /// passed to reach this decision.
    pub fn decision_path(&self) -> &[String] {
        &self.decision_path
    }

    /// Returns a newline-separated string describing the constraints that passed to reach
    /// this decision.
    pub fn decision_path_string(&self) -> String {
        let mut out = String::new();
        for s in &self.decision_path {
            out.push_str(s);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make() -> Decision {
        Decision::new(
            "my-value".to_string(),
            vec!["step one".to_string(), "step two".to_string()],
            "config.xml".to_string(),
        )
    }

    #[test]
    fn value_returns_constructor_value() {
        assert_eq!(make().value(), "my-value");
    }

    #[test]
    fn source_returns_constructor_source() {
        assert_eq!(make().source(), "config.xml");
    }

    #[test]
    fn decision_path_returns_all_steps() {
        let d = make();
        assert_eq!(d.decision_path(), &["step one", "step two"]);
    }

    #[test]
    fn decision_path_string_joins_with_newlines() {
        assert_eq!(make().decision_path_string(), "step one\nstep two\n");
    }

    #[test]
    fn decision_path_string_empty_when_no_steps() {
        let d = Decision::new("v".to_string(), vec![], "s".to_string());
        assert_eq!(d.decision_path_string(), "");
    }

    #[test]
    fn decision_path_string_single_step_ends_with_newline() {
        let d = Decision::new("v".to_string(), vec!["only".to_string()], "s".to_string());
        assert_eq!(d.decision_path_string(), "only\n");
    }
}
