use std::fmt;

/// Represents a choice from a limited set of string options.
///
/// Corresponds to `docking.widgets.dialogs.StringChoices`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringChoices {
    values: Vec<String>,
    selected: usize,
}

impl StringChoices {
    /// Constructs a `StringChoices` from a non-empty list of strings.
    ///
    /// # Panics
    ///
    /// Panics if `values` is empty.
    pub fn new(values: Vec<String>) -> Self {
        assert!(!values.is_empty(), "Set of values must contain at least one value");
        Self { values, selected: 0 }
    }

    /// Returns a copy of all allowed string values.
    pub fn get_values(&self) -> Vec<String> {
        self.values.clone()
    }

    /// Returns the currently selected value.
    pub fn get_selected_value(&self) -> &str {
        &self.values[self.selected]
    }

    /// Returns the index of the currently selected value.
    pub fn get_selected_value_index(&self) -> usize {
        self.selected
    }

    /// Returns `true` if `value` is one of the allowed values.
    pub fn contains(&self, value: &str) -> bool {
        self.index_of(value).is_some()
    }

    /// Returns the index of `value` in the allowed values, or `None` if not present.
    pub fn index_of(&self, value: &str) -> Option<usize> {
        self.values.iter().position(|v| v == value)
    }

    /// Sets the currently selected value by name.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not one of the allowed values.
    pub fn set_selected_value(&mut self, value: &str) -> Result<(), String> {
        match self.index_of(value) {
            Some(i) => {
                self.selected = i;
                Ok(())
            }
            None => Err("No such value in Enum".to_owned()),
        }
    }

    /// Sets the currently selected value by index.
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is out of range.
    pub fn set_selected_index(&mut self, index: usize) -> Result<(), String> {
        if index >= self.values.len() {
            return Err("index out of range".to_owned());
        }
        self.selected = index;
        Ok(())
    }
}

impl fmt::Display for StringChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get_selected_value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices() -> StringChoices {
        StringChoices::new(vec![
            "alpha".to_owned(),
            "beta".to_owned(),
            "gamma".to_owned(),
        ])
    }

    #[test]
    fn new_selects_first_value() {
        let sc = choices();
        assert_eq!(sc.get_selected_value(), "alpha");
        assert_eq!(sc.get_selected_value_index(), 0);
    }

    #[test]
    #[should_panic(expected = "Set of values must contain at least one value")]
    fn new_panics_on_empty() {
        StringChoices::new(vec![]);
    }

    #[test]
    fn get_values_returns_a_copy() {
        let sc = choices();
        assert_eq!(sc.get_values(), vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn contains_known_value() {
        let sc = choices();
        assert!(sc.contains("beta"));
    }

    #[test]
    fn contains_unknown_value() {
        let sc = choices();
        assert!(!sc.contains("delta"));
    }

    #[test]
    fn index_of_returns_correct_position() {
        let sc = choices();
        assert_eq!(sc.index_of("alpha"), Some(0));
        assert_eq!(sc.index_of("beta"), Some(1));
        assert_eq!(sc.index_of("gamma"), Some(2));
    }

    #[test]
    fn index_of_missing_returns_none() {
        let sc = choices();
        assert_eq!(sc.index_of("delta"), None);
    }

    #[test]
    fn set_selected_value_by_name() {
        let mut sc = choices();
        sc.set_selected_value("gamma").unwrap();
        assert_eq!(sc.get_selected_value(), "gamma");
        assert_eq!(sc.get_selected_value_index(), 2);
    }

    #[test]
    fn set_selected_value_invalid_is_err() {
        let mut sc = choices();
        assert!(sc.set_selected_value("delta").is_err());
    }

    #[test]
    fn set_selected_index_valid() {
        let mut sc = choices();
        sc.set_selected_index(1).unwrap();
        assert_eq!(sc.get_selected_value(), "beta");
        assert_eq!(sc.get_selected_value_index(), 1);
    }

    #[test]
    fn set_selected_index_out_of_range_is_err() {
        let mut sc = choices();
        assert!(sc.set_selected_index(3).is_err());
    }

    #[test]
    fn clone_preserves_values_and_selection() {
        let mut sc = choices();
        sc.set_selected_index(2).unwrap();
        let cloned = sc.clone();
        assert_eq!(cloned.get_values(), sc.get_values());
        assert_eq!(cloned.get_selected_value_index(), 2);
    }

    #[test]
    fn equality_same_values_same_selection() {
        assert_eq!(choices(), choices());
    }

    #[test]
    fn inequality_different_selection() {
        let sc1 = choices();
        let mut sc2 = choices();
        sc2.set_selected_index(1).unwrap();
        assert_ne!(sc1, sc2);
    }

    #[test]
    fn inequality_different_values() {
        let sc1 = choices();
        let sc2 = StringChoices::new(vec!["x".to_owned(), "y".to_owned()]);
        assert_ne!(sc1, sc2);
    }

    #[test]
    fn display_shows_selected_value() {
        let mut sc = choices();
        sc.set_selected_index(1).unwrap();
        assert_eq!(sc.to_string(), "beta");
    }

    #[test]
    fn single_value_choices() {
        let sc = StringChoices::new(vec!["only".to_owned()]);
        assert_eq!(sc.get_selected_value(), "only");
        assert_eq!(sc.get_selected_value_index(), 0);
        assert!(sc.contains("only"));
    }
}
