/// Listener for composite viewer model status information changes.
///
/// This trait provides a notification method for status information changes
/// in the CompositeViewerModel, including an optional audible beep notification.
pub trait CompositeModelStatusListener {
    /// Called when the composite viewer model's status information has changed.
    ///
    /// # Arguments
    /// * `message` - The status information message to provide to the user
    /// * `beep` - Whether an audible beep is suggested to accompany the notification
    fn status_changed(&self, message: &str, beep: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockStatusListener {
        status_changes: RefCell<Vec<(String, bool)>>,
    }

    impl MockStatusListener {
        fn new() -> Self {
            Self {
                status_changes: RefCell::new(Vec::new()),
            }
        }

        fn get_status_changes(&self) -> Vec<(String, bool)> {
            self.status_changes.borrow().clone()
        }
    }

    impl CompositeModelStatusListener for MockStatusListener {
        fn status_changed(&self, message: &str, beep: bool) {
            self.status_changes
                .borrow_mut()
                .push((message.to_string(), beep));
        }
    }

    #[test]
    fn test_status_changed_with_beep() {
        let listener = MockStatusListener::new();
        listener.status_changed("Operation complete", true);
        assert_eq!(
            listener.get_status_changes(),
            vec![("Operation complete".to_string(), true)]
        );
    }

    #[test]
    fn test_status_changed_without_beep() {
        let listener = MockStatusListener::new();
        listener.status_changed("Status update", false);
        assert_eq!(
            listener.get_status_changes(),
            vec![("Status update".to_string(), false)]
        );
    }

    #[test]
    fn test_status_changed_empty_message() {
        let listener = MockStatusListener::new();
        listener.status_changed("", false);
        assert_eq!(
            listener.get_status_changes(),
            vec![("".to_string(), false)]
        );
    }

    #[test]
    fn test_status_changed_multiple_updates() {
        let listener = MockStatusListener::new();
        listener.status_changed("First status", true);
        listener.status_changed("Second status", false);
        listener.status_changed("Third status", true);
        assert_eq!(
            listener.get_status_changes(),
            vec![
                ("First status".to_string(), true),
                ("Second status".to_string(), false),
                ("Third status".to_string(), true),
            ]
        );
    }

    #[test]
    fn test_status_changed_unicode_message() {
        let listener = MockStatusListener::new();
        listener.status_changed("Status: ✓ Complete", true);
        assert_eq!(
            listener.get_status_changes(),
            vec![("Status: ✓ Complete".to_string(), true)]
        );
    }
}
