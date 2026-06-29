/// Callback invoked when the text filter changes.
///
/// Corresponds to `docking.widgets.filter.FilterListener`.
pub trait FilterListener {
    fn filter_changed(&mut self, text: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        calls: Vec<String>,
    }

    impl FilterListener for Recorder {
        fn filter_changed(&mut self, text: &str) {
            self.calls.push(text.to_owned());
        }
    }

    #[test]
    fn callback_is_invoked_with_text() {
        let mut r = Recorder { calls: Vec::new() };
        r.filter_changed("hello");
        assert_eq!(r.calls, vec!["hello"]);
    }

    #[test]
    fn callback_is_invoked_multiple_times() {
        let mut r = Recorder { calls: Vec::new() };
        r.filter_changed("foo");
        r.filter_changed("bar");
        assert_eq!(r.calls, vec!["foo", "bar"]);
    }

    #[test]
    fn callback_with_empty_string() {
        let mut r = Recorder { calls: Vec::new() };
        r.filter_changed("");
        assert_eq!(r.calls, vec![""]);
    }
}
