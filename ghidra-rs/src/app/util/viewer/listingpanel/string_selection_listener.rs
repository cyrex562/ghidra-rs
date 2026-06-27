//! Listener interface for string selection events in the listing panel.

/// Notified when a string is selected in the listing panel.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.StringSelectionListener`.
pub trait StringSelectionListener {
    /// Called when a string is selected.
    fn set_string_selection(&mut self, string: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        selections: Vec<String>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                selections: Vec::new(),
            }
        }
    }

    impl StringSelectionListener for RecordingListener {
        fn set_string_selection(&mut self, string: &str) {
            self.selections.push(string.to_owned());
        }
    }

    #[test]
    fn test_set_string_selection_called() {
        let mut listener = RecordingListener::new();
        listener.set_string_selection("hello");
        assert_eq!(listener.selections, vec!["hello"]);
    }

    #[test]
    fn test_set_string_selection_multiple_calls() {
        let mut listener = RecordingListener::new();
        listener.set_string_selection("foo");
        listener.set_string_selection("bar");
        assert_eq!(listener.selections, vec!["foo", "bar"]);
    }

    #[test]
    fn test_set_string_selection_empty_string() {
        let mut listener = RecordingListener::new();
        listener.set_string_selection("");
        assert_eq!(listener.selections, vec![""]);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn StringSelectionListener> = Box::new(RecordingListener::new());
        listener.set_string_selection("test");
    }
}
