use std::io;

use crate::app::services::Terminal;

/// A terminal with some back-end element attached to it.
///
/// Corresponds to `ghidra.debug.api.tracermi.TerminalSession`.
pub trait TerminalSession {
    /// Get the handle to the terminal.
    fn terminal(&self) -> &dyn Terminal;

    /// Get a mutable reference to the handle to the terminal.
    fn terminal_mut(&mut self) -> &mut dyn Terminal;

    /// Ensure the session is visible.
    ///
    /// The window should be displayed and brought to the front.
    fn show(&mut self) {
        self.terminal_mut().to_front();
    }

    /// Terminate the session without closing the terminal.
    fn terminate(&mut self) -> io::Result<()>;

    /// Check whether the terminal session is terminated or still active.
    ///
    /// Returns `true` if terminated, `false` if active.
    fn is_terminated(&self) -> bool {
        self.terminal().is_terminated()
    }

    /// Provide a human-readable description of the session.
    fn description(&self) -> String;

    /// Get the terminal contents as a string (no attributes).
    fn content(&self) -> String {
        self.terminal().get_full_text()
    }

    /// Get the current title of the terminal.
    fn title(&self) -> String {
        self.terminal().get_sub_title()
    }

    /// Close the session and terminal.
    ///
    /// This terminates the session and closes the terminal. It mirrors Java's
    /// `AutoCloseable.close()` contract.
    fn close(&mut self) -> io::Result<()> {
        self.terminate()?;
        self.terminal_mut().close();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::function::Callback;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeTerminal {
        sub_title: String,
        full_text: String,
        is_terminated: bool,
        to_front_called: bool,
        closed: bool,
    }

    impl Terminal for FakeTerminal {
        fn add_terminal_listener(&mut self, _listener: Box<dyn crate::app::plugin::core::terminal::TerminalListener>) {}
        fn remove_terminal_listener(&mut self, _listener: &dyn crate::app::plugin::core::terminal::TerminalListener) {}
        fn inject_display_output(&mut self, _buf: &[u8]) {}
        fn set_sub_title(&mut self, title: &str) {
            self.sub_title = title.to_string();
        }
        fn get_sub_title(&self) -> String {
            self.sub_title.clone()
        }
        fn set_fixed_size(&mut self, _cols: i16, _rows: i16) {}
        fn set_dynamic_size(&mut self) {}
        fn set_max_scroll_back_rows(&mut self, _rows: i32) {}
        fn get_columns(&self) -> i32 {
            80
        }
        fn get_rows(&self) -> i32 {
            24
        }
        fn get_scroll_back_rows(&self) -> i32 {
            0
        }
        fn get_full_text(&self) -> String {
            self.full_text.clone()
        }
        fn get_display_text(&self) -> String {
            self.full_text.clone()
        }
        fn get_line_text(&self, _line: i32) -> String {
            String::new()
        }
        fn get_range_text(&self, _start_col: i32, _start_line: i32, _end_col: i32, _end_line: i32) -> String {
            String::new()
        }
        fn get_cursor_row(&self) -> i32 {
            0
        }
        fn get_cursor_column(&self) -> i32 {
            0
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn terminated(&mut self, _exitcode: i32) {
            self.is_terminated = true;
        }
        fn set_terminate_action(&mut self, _action: Option<Callback>) {}
        fn is_terminated(&self) -> bool {
            self.is_terminated
        }
        fn to_front(&mut self) {
            self.to_front_called = true;
        }
    }

    struct TestTerminalSession {
        terminal: FakeTerminal,
        terminated: bool,
    }

    impl TestTerminalSession {
        fn new() -> Self {
            Self {
                terminal: FakeTerminal::default(),
                terminated: false,
            }
        }
    }

    impl TerminalSession for TestTerminalSession {
        fn terminal(&self) -> &dyn Terminal {
            &self.terminal
        }

        fn terminal_mut(&mut self) -> &mut dyn Terminal {
            &mut self.terminal
        }

        fn terminate(&mut self) -> io::Result<()> {
            self.terminated = true;
            Ok(())
        }

        fn description(&self) -> String {
            "test session".to_string()
        }
    }

    #[test]
    fn description_returns_configured_string() {
        let session = TestTerminalSession::new();
        assert_eq!(session.description(), "test session");
    }

    #[test]
    fn is_terminated_delegates_to_terminal() {
        let mut session = TestTerminalSession::new();
        assert!(!session.is_terminated());
        session.terminal.is_terminated = true;
        assert!(session.is_terminated());
    }

    #[test]
    fn show_calls_terminal_to_front() {
        let mut session = TestTerminalSession::new();
        session.show();
        assert!(session.terminal.to_front_called);
    }

    #[test]
    fn title_delegates_to_terminal_get_sub_title() {
        let mut session = TestTerminalSession::new();
        session.terminal.set_sub_title("bash");
        assert_eq!(session.title(), "bash");
    }

    #[test]
    fn content_delegates_to_terminal_get_full_text() {
        let mut session = TestTerminalSession::new();
        session.terminal.full_text = "output".to_string();
        assert_eq!(session.content(), "output");
    }

    #[test]
    fn terminate_updates_internal_state() {
        let mut session = TestTerminalSession::new();
        assert!(!session.terminated);
        session.terminate().unwrap();
        assert!(session.terminated);
    }

    #[test]
    fn close_calls_terminate_and_closes_terminal() {
        let mut session = TestTerminalSession::new();
        session.close().unwrap();
        assert!(session.terminated);
        assert!(session.terminal.closed);
    }

    #[test]
    fn close_terminates_before_closing_terminal() {
        let mut session = TestTerminalSession::new();
        session.close().unwrap();
        assert!(session.terminated);
        assert!(session.terminal.closed);
    }

    #[test]
    fn close_propagates_terminate_error() {
        struct FailingTerminalSession {
            terminal: FakeTerminal,
        }

        impl TerminalSession for FailingTerminalSession {
            fn terminal(&self) -> &dyn Terminal {
                &self.terminal
            }

            fn terminal_mut(&mut self) -> &mut dyn Terminal {
                &mut self.terminal
            }

            fn terminate(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::Other, "terminate failed"))
            }

            fn description(&self) -> String {
                "failing session".to_string()
            }
        }

        let mut session = FailingTerminalSession {
            terminal: FakeTerminal::default(),
        };
        let result = session.close();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn terminal_accessor_returns_reference() {
        let session = TestTerminalSession::new();
        let terminal_ref: &dyn Terminal = session.terminal();
        assert!(terminal_ref.is_terminated() == false);
    }

    #[test]
    fn terminal_mut_accessor_returns_mutable_reference() {
        let mut session = TestTerminalSession::new();
        let terminal_mut_ref: &mut dyn Terminal = session.terminal_mut();
        terminal_mut_ref.to_front();
        assert!(session.terminal.to_front_called);
    }
}
