use crate::app::plugin::core::terminal::TerminalListener;
use crate::util::function::Callback;

/// A handle to a terminal window in the UI.
pub trait Terminal {
    /// Add a listener for terminal events
    fn add_terminal_listener(&mut self, listener: Box<dyn TerminalListener>);

    /// Remove a listener for terminal events
    fn remove_terminal_listener(&mut self, listener: &dyn TerminalListener);

    /// Process the given buffer as if it were output by the terminal's application.
    ///
    /// **Warning:** While implementations may synchronize to ensure the additional buffer is
    /// not processed at the same time as actual application input, there may not be any effort
    /// to ensure that the buffer is not injected in the middle of an escape sequence. Even if
    /// the injection is outside an escape sequence, this may still lead to unexpected behavior,
    /// since the injected output may be affected by or otherwise interfere with the
    /// application's control of the terminal's state. Generally, this should only be used for
    /// testing, or other cases when the caller knows it has exclusive control of the terminal.
    fn inject_display_output(&mut self, buf: &[u8]);

    /// Set the pane's sub title
    ///
    /// The application may also set this sub title using an escape sequence.
    fn set_sub_title(&mut self, title: &str);

    /// Get the pane's current sub title
    fn get_sub_title(&self) -> String;

    /// Set the terminal size to the given dimensions, and do *not* resize it to the window.
    fn set_fixed_size(&mut self, cols: i16, rows: i16);

    /// Fit the terminal's dimensions to the containing window.
    fn set_dynamic_size(&mut self);

    /// Set the maximum size of the scroll-back buffer in lines
    ///
    /// This only affects the primary buffer. The alternate buffer has no scroll-back.
    fn set_max_scroll_back_rows(&mut self, rows: i32);

    /// Get the maximum number of characters in each row
    fn get_columns(&self) -> i32;

    /// Get the maximum number of rows in the display (not counting scroll-back)
    fn get_rows(&self) -> i32;

    /// Get the number of lines in the scroll-back buffer
    fn get_scroll_back_rows(&self) -> i32;

    /// Get all the text in the terminal, including the scroll-back buffer
    fn get_full_text(&self) -> String;

    /// Get the text in the terminal, excluding the scroll-back buffer
    fn get_display_text(&self) -> String;

    /// Get the given line's text
    ///
    /// The line at the top of the display has index 0. Lines in the scroll-back buffer have
    /// negative indices.
    fn get_line_text(&self, line: i32) -> String;

    /// Get the text in the given range
    ///
    /// The line at the top of the display has index 0. Lines in the scroll-back buffer have
    /// negative indices.
    fn get_range_text(&self, start_col: i32, start_line: i32, end_col: i32, end_line: i32) -> String;

    /// Get the cursor's current line
    ///
    /// Lines are indexed 0 up where the top line of the display is 0. The cursor can never be
    /// in the scroll-back buffer.
    fn get_cursor_row(&self) -> i32;

    /// Get the cursor's current column
    fn get_cursor_column(&self) -> i32;

    /// Close the terminal
    fn close(&mut self);

    /// Notify the terminal that its session has terminated
    ///
    /// The title and sub title are adjust and all listeners are removed. If/when the terminal
    /// is closed, it is permanently removed from the tool.
    fn terminated(&mut self, exitcode: i32);

    /// Allow the user to terminate the session forcefully
    ///
    /// Pass `None` to remove the action.
    fn set_terminate_action(&mut self, action: Option<Callback>);

    /// Check whether the terminal is terminated or active
    fn is_terminated(&self) -> bool;

    /// Bring the terminal to the front of the UI
    fn to_front(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeTerminal {
        listener_count: usize,
        buffer: Vec<u8>,
        sub_title: String,
        cols: i32,
        rows: i32,
        scroll_back_rows: i32,
        text: String,
        terminate_action: Option<Callback>,
        terminated: bool,
        last_exitcode: i32,
        front: bool,
        closed: bool,
    }

    impl Terminal for FakeTerminal {
        fn add_terminal_listener(&mut self, _listener: Box<dyn TerminalListener>) {
            self.listener_count += 1;
        }

        fn remove_terminal_listener(&mut self, _listener: &dyn TerminalListener) {
            self.listener_count = self.listener_count.saturating_sub(1);
        }

        fn inject_display_output(&mut self, buf: &[u8]) {
            self.buffer.extend_from_slice(buf);
        }

        fn set_sub_title(&mut self, title: &str) {
            self.sub_title = title.to_string();
        }

        fn get_sub_title(&self) -> String {
            self.sub_title.clone()
        }

        fn set_fixed_size(&mut self, cols: i16, rows: i16) {
            self.cols = cols as i32;
            self.rows = rows as i32;
        }

        fn set_dynamic_size(&mut self) {
            self.cols = 80;
            self.rows = 24;
        }

        fn set_max_scroll_back_rows(&mut self, rows: i32) {
            self.scroll_back_rows = rows;
        }

        fn get_columns(&self) -> i32 {
            self.cols
        }

        fn get_rows(&self) -> i32 {
            self.rows
        }

        fn get_scroll_back_rows(&self) -> i32 {
            self.scroll_back_rows
        }

        fn get_full_text(&self) -> String {
            self.text.clone()
        }

        fn get_display_text(&self) -> String {
            self.text.clone()
        }

        fn get_line_text(&self, _line: i32) -> String {
            String::new()
        }

        fn get_range_text(
            &self,
            _start_col: i32,
            _start_line: i32,
            _end_col: i32,
            _end_line: i32,
        ) -> String {
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

        fn terminated(&mut self, exitcode: i32) {
            self.terminated = true;
            self.last_exitcode = exitcode;
        }

        fn set_terminate_action(&mut self, action: Option<Callback>) {
            self.terminate_action = action;
        }

        fn is_terminated(&self) -> bool {
            self.terminated
        }

        fn to_front(&mut self) {
            self.front = true;
        }
    }

    #[test]
    fn add_and_remove_listener_tracks_count() {
        struct NoopListener;
        impl TerminalListener for NoopListener {}

        let mut terminal = FakeTerminal::default();
        terminal.add_terminal_listener(Box::new(NoopListener));
        assert_eq!(terminal.listener_count, 1);
        terminal.remove_terminal_listener(&NoopListener);
        assert_eq!(terminal.listener_count, 0);
    }

    #[test]
    fn inject_display_output_appends_bytes() {
        let mut terminal = FakeTerminal::default();
        terminal.inject_display_output(b"hello");
        terminal.inject_display_output(b" world");
        assert_eq!(terminal.buffer, b"hello world");
    }

    #[test]
    fn sub_title_round_trips() {
        let mut terminal = FakeTerminal::default();
        assert_eq!(terminal.get_sub_title(), "");
        terminal.set_sub_title("bash");
        assert_eq!(terminal.get_sub_title(), "bash");
    }

    #[test]
    fn set_fixed_size_sets_columns_and_rows() {
        let mut terminal = FakeTerminal::default();
        terminal.set_fixed_size(80, 24);
        assert_eq!(terminal.get_columns(), 80);
        assert_eq!(terminal.get_rows(), 24);
    }

    #[test]
    fn set_dynamic_size_updates_dimensions() {
        let mut terminal = FakeTerminal::default();
        terminal.set_dynamic_size();
        assert_eq!(terminal.get_columns(), 80);
        assert_eq!(terminal.get_rows(), 24);
    }

    #[test]
    fn max_scroll_back_rows_round_trips() {
        let mut terminal = FakeTerminal::default();
        terminal.set_max_scroll_back_rows(5000);
        assert_eq!(terminal.get_scroll_back_rows(), 5000);
    }

    #[test]
    fn terminated_sets_exitcode_and_flag() {
        let mut terminal = FakeTerminal::default();
        assert!(!terminal.is_terminated());
        terminal.terminated(42);
        assert!(terminal.is_terminated());
        assert_eq!(terminal.last_exitcode, 42);
    }

    #[test]
    fn terminate_action_can_be_set_and_cleared() {
        let mut terminal = FakeTerminal::default();
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);
        terminal.set_terminate_action(Some(Box::new(move || {
            *called_clone.lock().unwrap() = true;
        })));
        if let Some(action) = &terminal.terminate_action {
            action();
        }
        assert!(*called.lock().unwrap());

        terminal.set_terminate_action(None);
        assert!(terminal.terminate_action.is_none());
    }

    #[test]
    fn to_front_and_close_update_state() {
        let mut terminal = FakeTerminal::default();
        terminal.to_front();
        assert!(terminal.front);
        terminal.close();
        assert!(terminal.closed);
    }
}
