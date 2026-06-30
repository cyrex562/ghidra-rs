/// A comment that can be shared by more than one code unit.
pub trait RepeatableComment {
    /// Returns the text of the repeatable comment.
    fn get_comment(&self) -> &str;

    /// Sets the text of this repeatable comment.
    fn set_comment(&mut self, comment: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleComment {
        text: String,
    }

    impl SimpleComment {
        fn new(text: &str) -> Self {
            Self { text: text.to_string() }
        }
    }

    impl RepeatableComment for SimpleComment {
        fn get_comment(&self) -> &str {
            &self.text
        }

        fn set_comment(&mut self, comment: &str) {
            self.text = comment.to_string();
        }
    }

    #[test]
    fn get_comment_returns_initial_text() {
        let c = SimpleComment::new("hello");
        assert_eq!(c.get_comment(), "hello");
    }

    #[test]
    fn set_comment_updates_text() {
        let mut c = SimpleComment::new("old");
        c.set_comment("new");
        assert_eq!(c.get_comment(), "new");
    }

    #[test]
    fn empty_comment() {
        let c = SimpleComment::new("");
        assert_eq!(c.get_comment(), "");
    }

    #[test]
    fn set_comment_to_empty() {
        let mut c = SimpleComment::new("non-empty");
        c.set_comment("");
        assert_eq!(c.get_comment(), "");
    }

    #[test]
    fn trait_object_dispatch() {
        let mut c: Box<dyn RepeatableComment> = Box::new(SimpleComment::new("first"));
        assert_eq!(c.get_comment(), "first");
        c.set_comment("second");
        assert_eq!(c.get_comment(), "second");
    }
}
