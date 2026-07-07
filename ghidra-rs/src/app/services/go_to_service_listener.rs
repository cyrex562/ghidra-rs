/// Listener that is notified when a GOTO operation completes or fails.
///
/// Implementations of this trait can register with a GoToService to receive
/// notifications about the completion or failure of GOTO queries.
pub trait GoToServiceListener {
    /// Called when a GOTO operation completes.
    ///
    /// # Arguments
    /// * `query_string` - The original query string that was used for the GOTO operation
    /// * `found_results` - True if at least one hit was found for the query, false otherwise
    fn goto_completed(&self, query_string: &str, found_results: bool);

    /// Called when a GOTO operation fails with an exception.
    ///
    /// # Arguments
    /// * `error` - The error message describing what went wrong
    fn goto_failed(&self, error: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockGoToListener {
        completed_events: Rc<RefCell<Vec<(String, bool)>>>,
        failed_events: Rc<RefCell<Vec<String>>>,
    }

    impl MockGoToListener {
        fn new() -> Self {
            MockGoToListener {
                completed_events: Rc::new(RefCell::new(Vec::new())),
                failed_events: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn completed_events(&self) -> Rc<RefCell<Vec<(String, bool)>>> {
            Rc::clone(&self.completed_events)
        }

        fn failed_events(&self) -> Rc<RefCell<Vec<String>>> {
            Rc::clone(&self.failed_events)
        }
    }

    impl GoToServiceListener for MockGoToListener {
        fn goto_completed(&self, query_string: &str, found_results: bool) {
            self.completed_events
                .borrow_mut()
                .push((query_string.to_string(), found_results));
        }

        fn goto_failed(&self, error: &str) {
            self.failed_events.borrow_mut().push(error.to_string());
        }
    }

    #[test]
    fn test_goto_completed_with_results() {
        let listener = MockGoToListener::new();
        listener.goto_completed("test_query", true);

        let events = listener.completed_events();
        assert_eq!(events.borrow().len(), 1);
        assert_eq!(events.borrow()[0].0, "test_query");
        assert_eq!(events.borrow()[0].1, true);
    }

    #[test]
    fn test_goto_completed_without_results() {
        let listener = MockGoToListener::new();
        listener.goto_completed("no_results_query", false);

        let events = listener.completed_events();
        assert_eq!(events.borrow().len(), 1);
        assert_eq!(events.borrow()[0].0, "no_results_query");
        assert_eq!(events.borrow()[0].1, false);
    }

    #[test]
    fn test_goto_failed() {
        let listener = MockGoToListener::new();
        listener.goto_failed("Connection timeout");

        let events = listener.failed_events();
        assert_eq!(events.borrow().len(), 1);
        assert_eq!(events.borrow()[0], "Connection timeout");
    }

    #[test]
    fn test_multiple_completed_notifications() {
        let listener = MockGoToListener::new();

        listener.goto_completed("query1", true);
        listener.goto_completed("query2", false);
        listener.goto_completed("query3", true);

        let events = listener.completed_events();
        assert_eq!(events.borrow().len(), 3);
        assert_eq!(events.borrow()[0], ("query1".to_string(), true));
        assert_eq!(events.borrow()[1], ("query2".to_string(), false));
        assert_eq!(events.borrow()[2], ("query3".to_string(), true));
    }

    #[test]
    fn test_multiple_failed_notifications() {
        let listener = MockGoToListener::new();

        listener.goto_failed("Error 1");
        listener.goto_failed("Error 2");
        listener.goto_failed("Error 3");

        let events = listener.failed_events();
        assert_eq!(events.borrow().len(), 3);
        assert_eq!(events.borrow()[0], "Error 1");
        assert_eq!(events.borrow()[1], "Error 2");
        assert_eq!(events.borrow()[2], "Error 3");
    }

    #[test]
    fn test_mixed_completed_and_failed_notifications() {
        let listener = MockGoToListener::new();

        listener.goto_completed("query1", true);
        listener.goto_failed("Error occurred");
        listener.goto_completed("query2", false);

        let completed = listener.completed_events();
        assert_eq!(completed.borrow().len(), 2);
        assert_eq!(completed.borrow()[0], ("query1".to_string(), true));
        assert_eq!(completed.borrow()[1], ("query2".to_string(), false));

        let failed = listener.failed_events();
        assert_eq!(failed.borrow().len(), 1);
        assert_eq!(failed.borrow()[0], "Error occurred");
    }

    #[test]
    fn test_query_string_preserved() {
        let listener = MockGoToListener::new();
        let query = "complex.query.name_123";

        listener.goto_completed(query, true);

        let events = listener.completed_events();
        assert_eq!(events.borrow()[0].0, query);
    }

    #[test]
    fn test_error_message_preserved() {
        let listener = MockGoToListener::new();
        let error_msg = "Failed to resolve: Invalid address format";

        listener.goto_failed(error_msg);

        let events = listener.failed_events();
        assert_eq!(events.borrow()[0], error_msg);
    }

    #[test]
    fn test_found_results_true() {
        let listener = MockGoToListener::new();
        listener.goto_completed("query", true);

        let events = listener.completed_events();
        assert!(events.borrow()[0].1);
    }

    #[test]
    fn test_found_results_false() {
        let listener = MockGoToListener::new();
        listener.goto_completed("query", false);

        let events = listener.completed_events();
        assert!(!events.borrow()[0].1);
    }
}
