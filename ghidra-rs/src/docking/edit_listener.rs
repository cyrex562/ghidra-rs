/// Provides notification when a text edit is completed.
///
/// Corresponds to `docking.EditListener`.
pub trait EditListener {
    /// Notifies the listener of the text entered by the user when a text edit is completed.
    fn edit_completed(&mut self, new_text: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestListener {
        last_text: String,
    }

    impl EditListener for TestListener {
        fn edit_completed(&mut self, new_text: &str) {
            self.last_text = new_text.to_string();
        }
    }

    #[test]
    fn edit_completed_stores_text() {
        let mut listener = TestListener { last_text: String::new() };
        listener.edit_completed("hello");
        assert_eq!(listener.last_text, "hello");
    }

    #[test]
    fn edit_completed_with_empty_string() {
        let mut listener = TestListener { last_text: "previous".to_string() };
        listener.edit_completed("");
        assert_eq!(listener.last_text, "");
    }
}
