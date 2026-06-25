use std::any::Any;
use std::cmp::Ordering;

/// Encapsulates a code completion.
///
/// Used by the code completion process, especially the CodeCompletionWindow.
/// Encapsulates:
/// - A description of the completion (what are you completing?)
/// - The actual string that will be inserted
/// - An optional component that will be in the completion list
/// - The number of characters to remove before the insertion of the completion
///
/// # Example
///
/// If one wants to autocomplete a string "Runscr" into "runScript", the fields may look as follows:
/// - description: "runScript (Method)"
/// - insertion: "runScript"
/// - component: None or Some custom UI component
/// - charsToRemove: 6 (i.e. the length of "Runscr")
#[derive(Debug)]
pub struct CodeCompletion {
    description: String,
    insertion: Option<String>,
    component: Option<Box<dyn Any>>,
    chars_to_remove: usize,
}

impl CodeCompletion {
    /// Returns true if the given CodeCompletion actually would insert something.
    pub fn is_valid(completion: Option<&CodeCompletion>) -> bool {
        completion.is_some_and(|c| c.insertion.is_some())
    }

    /// Creates a new CodeCompletion with default chars_to_remove of 0.
    ///
    /// # Arguments
    ///
    /// * `description` - Description of this completion
    /// * `insertion` - What will be inserted (or None)
    /// * `component` - Optional component to appear in completion list (or None)
    pub fn new(
        description: String,
        insertion: Option<String>,
        component: Option<Box<dyn Any>>,
    ) -> Self {
        Self {
            description,
            insertion,
            component,
            chars_to_remove: 0,
        }
    }

    /// Creates a new CodeCompletion with explicit chars_to_remove.
    ///
    /// # Arguments
    ///
    /// * `description` - Description of this completion
    /// * `insertion` - What will be inserted (or None)
    /// * `component` - Optional component to appear in completion list (or None)
    /// * `chars_to_remove` - The number of characters that should be removed before insertion
    pub fn with_chars_to_remove(
        description: String,
        insertion: Option<String>,
        component: Option<Box<dyn Any>>,
        chars_to_remove: usize,
    ) -> Self {
        Self {
            description,
            insertion,
            component,
            chars_to_remove,
        }
    }

    /// Returns the component to display in the completion list.
    pub fn component(&self) -> Option<&dyn Any> {
        self.component.as_ref().map(|b| b.as_ref())
    }

    /// Returns the description of this CodeCompletion.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the text to insert to complete the code.
    pub fn insertion(&self) -> Option<&str> {
        self.insertion.as_deref()
    }

    /// Returns the number of characters to remove from the input before the insertion
    /// of the code completion.
    pub fn chars_to_remove(&self) -> usize {
        self.chars_to_remove
    }
}

impl std::fmt::Display for CodeCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CodeCompletion: '{}' ({})",
            self.description,
            self.insertion.as_deref().unwrap_or("null")
        )
    }
}

impl PartialEq for CodeCompletion {
    fn eq(&self, other: &Self) -> bool {
        self.description == other.description
            && self.insertion == other.insertion
            && self.chars_to_remove == other.chars_to_remove
    }
}

impl Eq for CodeCompletion {}

impl PartialOrd for CodeCompletion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeCompletion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.description
            .to_lowercase()
            .cmp(&other.description.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_with_none() {
        assert!(!CodeCompletion::is_valid(None));
    }

    #[test]
    fn test_is_valid_with_some_and_no_insertion() {
        let completion = CodeCompletion::new("desc".to_string(), None, None);
        assert!(!CodeCompletion::is_valid(Some(&completion)));
    }

    #[test]
    fn test_is_valid_with_some_and_insertion() {
        let completion = CodeCompletion::new("desc".to_string(), Some("insert".to_string()), None);
        assert!(CodeCompletion::is_valid(Some(&completion)));
    }

    #[test]
    fn test_new_defaults_chars_to_remove() {
        let completion = CodeCompletion::new("desc".to_string(), Some("insert".to_string()), None);
        assert_eq!(completion.chars_to_remove(), 0);
    }

    #[test]
    fn test_with_chars_to_remove() {
        let completion = CodeCompletion::with_chars_to_remove(
            "desc".to_string(),
            Some("insert".to_string()),
            None,
            6,
        );
        assert_eq!(completion.chars_to_remove(), 6);
    }

    #[test]
    fn test_getters() {
        let completion = CodeCompletion::new(
            "runScript (Method)".to_string(),
            Some("runScript".to_string()),
            None,
        );

        assert_eq!(completion.description(), "runScript (Method)");
        assert_eq!(completion.insertion(), Some("runScript"));
        assert!(completion.component().is_none());
    }

    #[test]
    fn test_display() {
        let completion = CodeCompletion::new(
            "runScript (Method)".to_string(),
            Some("runScript".to_string()),
            None,
        );
        let expected = "CodeCompletion: 'runScript (Method)' (runScript)";
        assert_eq!(completion.to_string(), expected);
    }

    #[test]
    fn test_display_with_no_insertion() {
        let completion = CodeCompletion::new("desc".to_string(), None, None);
        let expected = "CodeCompletion: 'desc' (null)";
        assert_eq!(completion.to_string(), expected);
    }

    #[test]
    fn test_comparable_case_insensitive() {
        let completion1 = CodeCompletion::new("Alpha".to_string(), Some("a".to_string()), None);
        let completion2 = CodeCompletion::new("alpha".to_string(), Some("a".to_string()), None);
        assert_eq!(completion1, completion2);
    }

    #[test]
    fn test_comparable_ordering() {
        let completion1 = CodeCompletion::new("Alpha".to_string(), Some("a".to_string()), None);
        let completion2 = CodeCompletion::new("Beta".to_string(), Some("b".to_string()), None);
        let completion3 = CodeCompletion::new("alpha".to_string(), Some("a".to_string()), None);

        let mut completions = vec![completion2, completion1, completion3];
        completions.sort();

        assert_eq!(completions[0].description(), "Alpha");
        assert_eq!(completions[1].description(), "alpha");
        assert_eq!(completions[2].description(), "Beta");
    }

    #[test]
    fn test_example_runscr_to_runscript() {
        let completion = CodeCompletion::with_chars_to_remove(
            "runScript (Method)".to_string(),
            Some("runScript".to_string()),
            None,
            6,
        );

        assert_eq!(completion.description(), "runScript (Method)");
        assert_eq!(completion.insertion(), Some("runScript"));
        assert_eq!(completion.chars_to_remove(), 6);
        assert!(CodeCompletion::is_valid(Some(&completion)));
    }
}
