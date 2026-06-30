/// Listener called when a string should be written to the console.
pub trait ConsoleListener {
    /// Output the message to the console.
    ///
    /// `is_error` indicates whether this is an error message.
    fn put(&mut self, message: &str, is_error: bool);

    /// Output the message to the console followed by a newline.
    ///
    /// `is_error` indicates whether this is an error message.
    fn putln(&mut self, message: &str, is_error: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConsole {
        output: Vec<(String, bool)>,
    }

    impl TestConsole {
        fn new() -> Self {
            Self { output: Vec::new() }
        }
    }

    impl ConsoleListener for TestConsole {
        fn put(&mut self, message: &str, is_error: bool) {
            self.output.push((message.to_string(), is_error));
        }

        fn putln(&mut self, message: &str, is_error: bool) {
            self.output.push((format!("{}\n", message), is_error));
        }
    }

    #[test]
    fn put_records_message_and_error_flag() {
        let mut console = TestConsole::new();
        console.put("hello", false);
        assert_eq!(console.output, vec![("hello".to_string(), false)]);
    }

    #[test]
    fn put_error_flag_true() {
        let mut console = TestConsole::new();
        console.put("error!", true);
        assert_eq!(console.output, vec![("error!".to_string(), true)]);
    }

    #[test]
    fn putln_appends_newline() {
        let mut console = TestConsole::new();
        console.putln("line", false);
        assert_eq!(console.output, vec![("line\n".to_string(), false)]);
    }

    #[test]
    fn multiple_calls_accumulate() {
        let mut console = TestConsole::new();
        console.put("a", false);
        console.putln("b", true);
        assert_eq!(console.output.len(), 2);
        assert_eq!(console.output[0], ("a".to_string(), false));
        assert_eq!(console.output[1], ("b\n".to_string(), true));
    }
}
