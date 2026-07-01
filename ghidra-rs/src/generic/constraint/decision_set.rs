use super::decision::Decision;

/// Result object returned from a scan of a decision tree looking for property values that
/// match the constraints for some test object.
pub struct DecisionSet {
    decision_list: Vec<Decision>,
    property_name: String,
}

impl DecisionSet {
    pub fn new(property_name: String) -> Self {
        Self {
            decision_list: Vec::new(),
            property_name,
        }
    }

    /// Returns a slice of all the decisions whose decision path constraints matched the given
    /// test object.
    pub fn decisions(&self) -> &[Decision] {
        &self.decision_list
    }

    /// Returns a list of property values from decision paths that matched the constraints.
    pub fn values(&self) -> Vec<String> {
        self.decision_list
            .iter()
            .map(|d| d.value().to_string())
            .collect()
    }

    /// Returns the name of the property that was scanned for in the decision tree.
    pub fn decision_property_name(&self) -> &str {
        &self.property_name
    }

    /// Adds a decision to this decision set.
    pub(crate) fn add_decision(&mut self, decision: Decision) {
        self.decision_list.push(decision);
    }

    /// Returns true if this decision set has no results.
    pub fn is_empty(&self) -> bool {
        self.decision_list.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_empty_decision_set() {
        let ds = DecisionSet::new("test_property".to_string());
        assert!(ds.is_empty());
        assert_eq!(ds.decision_property_name(), "test_property");
    }

    #[test]
    fn decisions_returns_empty_initially() {
        let ds = DecisionSet::new("prop".to_string());
        assert_eq!(ds.decisions().len(), 0);
    }

    #[test]
    fn add_decision_adds_to_list() {
        let mut ds = DecisionSet::new("prop".to_string());
        let decision =
            Decision::new("value1".to_string(), vec!["step1".to_string()], "source1".to_string());
        ds.add_decision(decision);
        assert_eq!(ds.decisions().len(), 1);
        assert!(!ds.is_empty());
    }

    #[test]
    fn decisions_returns_all_added_decisions() {
        let mut ds = DecisionSet::new("prop".to_string());
        ds.add_decision(Decision::new(
            "value1".to_string(),
            vec!["step1".to_string()],
            "source1".to_string(),
        ));
        ds.add_decision(Decision::new(
            "value2".to_string(),
            vec!["step2".to_string()],
            "source2".to_string(),
        ));
        assert_eq!(ds.decisions().len(), 2);
        assert_eq!(ds.decisions()[0].value(), "value1");
        assert_eq!(ds.decisions()[1].value(), "value2");
    }

    #[test]
    fn values_collects_all_decision_values() {
        let mut ds = DecisionSet::new("prop".to_string());
        ds.add_decision(Decision::new(
            "val1".to_string(),
            vec![],
            "source1".to_string(),
        ));
        ds.add_decision(Decision::new(
            "val2".to_string(),
            vec![],
            "source2".to_string(),
        ));
        ds.add_decision(Decision::new(
            "val3".to_string(),
            vec![],
            "source3".to_string(),
        ));
        let values = ds.values();
        assert_eq!(values, vec!["val1", "val2", "val3"]);
    }

    #[test]
    fn values_returns_empty_list_when_no_decisions() {
        let ds = DecisionSet::new("prop".to_string());
        let values = ds.values();
        assert!(values.is_empty());
    }

    #[test]
    fn decision_property_name_returns_constructor_value() {
        let ds = DecisionSet::new("my_property".to_string());
        assert_eq!(ds.decision_property_name(), "my_property");
    }

    #[test]
    fn is_empty_true_initially() {
        let ds = DecisionSet::new("prop".to_string());
        assert!(ds.is_empty());
    }

    #[test]
    fn is_empty_false_after_adding_decision() {
        let mut ds = DecisionSet::new("prop".to_string());
        ds.add_decision(Decision::new(
            "val".to_string(),
            vec![],
            "source".to_string(),
        ));
        assert!(!ds.is_empty());
    }
}
