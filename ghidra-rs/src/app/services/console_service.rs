use std::io::Write;

/// Generic console interface allowing any plugin to print
/// messages to console window.
pub trait ConsoleService {
    /// Appends message to the console text area.
    ///
    /// For example:
    ///    "originator> message"
    ///
    /// * `originator` - a descriptive name of the message creator
    /// * `message` - the message to appear in the console
    fn add_message(&mut self, originator: &str, message: &str);

    /// Appends an error message to the console text area.
    /// The message should be rendered is such a way as to denote
    /// that it is an error. For example, display in "red".
    ///
    /// * `originator` - a descriptive name of the message creator
    /// * `message` - the message to appear in the console
    fn add_error_message(&mut self, originator: &str, message: &str);

    /// Appends an exception to the console text area.
    ///
    /// * `originator` - a descriptive name of the message creator
    /// * `exc` - the exception
    fn add_exception(&mut self, originator: &str, exc: &dyn std::error::Error);

    /// Clears all messages from the console.
    fn clear_messages(&mut self);

    /// Prints the message into the console.
    fn print(&mut self, msg: &str);

    /// Prints the messages into the console followed by a line feed.
    fn println(&mut self, msg: &str);

    /// Prints the error message into the console.
    /// It will be displayed in red.
    fn print_error(&mut self, errmsg: &str);

    /// Prints the error message into the console followed by a line feed.
    /// It will be displayed in red.
    fn println_error(&mut self, errmsg: &str);

    /// Returns a writer object to use as standard output.
    fn get_std_out(&self) -> Box<dyn Write>;

    /// Returns a writer object to use as standard error.
    fn get_std_err(&self) -> Box<dyn Write>;

    /// Returns number of characters of currently in the console.
    /// If the console is cleared, this number is reset.
    ///
    /// Please note:
    /// Support for this method is optional based on the underlying console
    /// implementation. If this method cannot be supported, implementations
    /// should panic with an "unsupported operation" message.
    fn get_text_length(&self) -> i32;

    /// Fetches the text contained within the given portion of the console.
    ///
    /// * `offset` - the offset into the console representing the desired start of the text >= 0
    /// * `length` - the length of the desired string >= 0
    ///
    /// Please note:
    /// Support for this method is optional based on the underlying console
    /// implementation. If this method cannot be supported, implementations
    /// should panic with an "unsupported operation" message.
    fn get_text(&self, offset: i32, length: i32) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeConsoleService {
        text: String,
        cleared: bool,
    }

    impl ConsoleService for FakeConsoleService {
        fn add_message(&mut self, originator: &str, message: &str) {
            self.text.push_str(&format!("{}> {}\n", originator, message));
        }

        fn add_error_message(&mut self, originator: &str, message: &str) {
            self.text.push_str(&format!("{}> ERROR: {}\n", originator, message));
        }

        fn add_exception(&mut self, originator: &str, exc: &dyn std::error::Error) {
            self.text.push_str(&format!("{}> EXCEPTION: {}\n", originator, exc));
        }

        fn clear_messages(&mut self) {
            self.text.clear();
            self.cleared = true;
        }

        fn print(&mut self, msg: &str) {
            self.text.push_str(msg);
        }

        fn println(&mut self, msg: &str) {
            self.text.push_str(msg);
            self.text.push('\n');
        }

        fn print_error(&mut self, errmsg: &str) {
            self.text.push_str(errmsg);
        }

        fn println_error(&mut self, errmsg: &str) {
            self.text.push_str(errmsg);
            self.text.push('\n');
        }

        fn get_std_out(&self) -> Box<dyn Write> {
            Box::new(std::io::sink())
        }

        fn get_std_err(&self) -> Box<dyn Write> {
            Box::new(std::io::sink())
        }

        fn get_text_length(&self) -> i32 {
            self.text.len() as i32
        }

        fn get_text(&self, offset: i32, length: i32) -> String {
            let offset = offset as usize;
            let length = length as usize;
            self.text.chars().skip(offset).take(length).collect()
        }
    }

    #[test]
    fn add_message_appends_formatted_text() {
        let mut console = FakeConsoleService::default();
        console.add_message("plugin", "hello");
        assert_eq!(console.get_text(0, console.get_text_length() as usize as i32), "plugin> hello\n");
    }

    #[test]
    fn clear_messages_resets_text() {
        let mut console = FakeConsoleService::default();
        console.println("some text");
        assert_ne!(console.get_text_length(), 0);
        console.clear_messages();
        assert_eq!(console.get_text_length(), 0);
        assert!(console.cleared);
    }

    #[test]
    fn add_exception_records_message() {
        #[derive(Debug)]
        struct MyError;
        impl std::fmt::Display for MyError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "boom")
            }
        }
        impl std::error::Error for MyError {}

        let mut console = FakeConsoleService::default();
        console.add_exception("plugin", &MyError);
        assert!(console.get_text(0, console.get_text_length()).contains("boom"));
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let console: Box<dyn ConsoleService> = Box::new(FakeConsoleService::default());
        let _ = console;
    }
}
