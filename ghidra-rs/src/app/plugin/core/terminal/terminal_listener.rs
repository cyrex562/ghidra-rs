/// A listener for various events on a terminal panel.
pub trait TerminalListener {
    /// The terminal was resized by the user.
    ///
    /// If applicable and possible, this information should be communicated to the connection.
    ///
    /// # Arguments
    ///
    /// * `cols` - The number of columns
    /// * `rows` - The number of rows
    fn resized(&mut self, cols: i16, rows: i16) {}

    /// The application requested the window title changed.
    ///
    /// # Arguments
    ///
    /// * `title` - The requested title
    fn retitled(&mut self, title: &str) {}

    /// The terminal session was terminated.
    ///
    /// # Arguments
    ///
    /// * `exitcode` - The exit code of the session leader, or -1 if not applicable
    fn terminated(&mut self, exitcode: i32) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        resized_calls: Vec<(i16, i16)>,
        retitled_calls: Vec<String>,
        terminated_calls: Vec<i32>,
    }

    impl TestListener {
        fn new() -> Self {
            TestListener {
                resized_calls: Vec::new(),
                retitled_calls: Vec::new(),
                terminated_calls: Vec::new(),
            }
        }
    }

    impl TerminalListener for TestListener {
        fn resized(&mut self, cols: i16, rows: i16) {
            self.resized_calls.push((cols, rows));
        }

        fn retitled(&mut self, title: &str) {
            self.retitled_calls.push(title.to_string());
        }

        fn terminated(&mut self, exitcode: i32) {
            self.terminated_calls.push(exitcode);
        }
    }

    #[test]
    fn test_resized_event() {
        let mut listener = TestListener::new();
        listener.resized(80, 24);
        assert_eq!(listener.resized_calls.len(), 1);
        assert_eq!(listener.resized_calls[0], (80, 24));
    }

    #[test]
    fn test_multiple_resized_events() {
        let mut listener = TestListener::new();
        listener.resized(80, 24);
        listener.resized(100, 50);
        listener.resized(120, 30);
        assert_eq!(listener.resized_calls.len(), 3);
        assert_eq!(listener.resized_calls[0], (80, 24));
        assert_eq!(listener.resized_calls[1], (100, 50));
        assert_eq!(listener.resized_calls[2], (120, 30));
    }

    #[test]
    fn test_resized_edge_cases() {
        let mut listener = TestListener::new();
        listener.resized(0, 0);
        listener.resized(i16::MAX, i16::MAX);
        listener.resized(i16::MIN, i16::MIN);
        assert_eq!(listener.resized_calls[0], (0, 0));
        assert_eq!(listener.resized_calls[1], (i16::MAX, i16::MAX));
        assert_eq!(listener.resized_calls[2], (i16::MIN, i16::MIN));
    }

    #[test]
    fn test_retitled_event() {
        let mut listener = TestListener::new();
        listener.retitled("New Title");
        assert_eq!(listener.retitled_calls.len(), 1);
        assert_eq!(listener.retitled_calls[0], "New Title");
    }

    #[test]
    fn test_multiple_retitled_events() {
        let mut listener = TestListener::new();
        listener.retitled("Title 1");
        listener.retitled("Title 2");
        listener.retitled("Title 3");
        assert_eq!(listener.retitled_calls.len(), 3);
        assert_eq!(listener.retitled_calls[0], "Title 1");
        assert_eq!(listener.retitled_calls[1], "Title 2");
        assert_eq!(listener.retitled_calls[2], "Title 3");
    }

    #[test]
    fn test_retitled_empty_string() {
        let mut listener = TestListener::new();
        listener.retitled("");
        assert_eq!(listener.retitled_calls.len(), 1);
        assert_eq!(listener.retitled_calls[0], "");
    }

    #[test]
    fn test_terminated_event() {
        let mut listener = TestListener::new();
        listener.terminated(0);
        assert_eq!(listener.terminated_calls.len(), 1);
        assert_eq!(listener.terminated_calls[0], 0);
    }

    #[test]
    fn test_terminated_with_exit_code() {
        let mut listener = TestListener::new();
        listener.terminated(1);
        listener.terminated(42);
        listener.terminated(-1);
        assert_eq!(listener.terminated_calls.len(), 3);
        assert_eq!(listener.terminated_calls[0], 1);
        assert_eq!(listener.terminated_calls[1], 42);
        assert_eq!(listener.terminated_calls[2], -1);
    }

    #[test]
    fn test_all_events_together() {
        let mut listener = TestListener::new();
        listener.resized(80, 24);
        listener.retitled("My Terminal");
        listener.resized(100, 30);
        listener.terminated(0);

        assert_eq!(listener.resized_calls.len(), 2);
        assert_eq!(listener.retitled_calls.len(), 1);
        assert_eq!(listener.terminated_calls.len(), 1);

        assert_eq!(listener.resized_calls[0], (80, 24));
        assert_eq!(listener.resized_calls[1], (100, 30));
        assert_eq!(listener.retitled_calls[0], "My Terminal");
        assert_eq!(listener.terminated_calls[0], 0);
    }

    #[test]
    fn test_default_implementation() {
        struct DefaultListener;

        impl TerminalListener for DefaultListener {}

        let mut listener = DefaultListener;
        listener.resized(80, 24);
        listener.retitled("Title");
        listener.terminated(0);
    }
}
