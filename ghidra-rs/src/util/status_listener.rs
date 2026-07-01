use super::message_type::MessageType;

/// A general-purpose status listener responsible for displaying and/or recording status messages.
///
/// Port of `ghidra.util.StatusListener`.
pub trait StatusListener: Send + Sync {
    /// Set the current status as type INFO.
    fn set_status_text(&self, text: &str);

    /// Set the current status as the specified type.
    fn set_status_text_with_type(&self, text: &str, msg_type: MessageType);

    /// Set the current status as the specified type.
    ///
    /// # Arguments
    ///
    /// * `text` - status text
    /// * `msg_type` - status type
    /// * `alert` - true to grab the user's attention
    fn set_status_text_with_alert(&self, text: &str, msg_type: MessageType, alert: bool);

    /// Clear the current status (same as `set_status_text("")` without being recorded).
    fn clear_status_text(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestStatusListener {
        calls: Mutex<Vec<(String, Option<MessageType>, Option<bool>)>>,
    }

    impl StatusListener for TestStatusListener {
        fn set_status_text(&self, text: &str) {
            self.calls
                .lock()
                .unwrap()
                .push((text.to_string(), None, None));
        }

        fn set_status_text_with_type(&self, text: &str, msg_type: MessageType) {
            self.calls
                .lock()
                .unwrap()
                .push((text.to_string(), Some(msg_type), None));
        }

        fn set_status_text_with_alert(&self, text: &str, msg_type: MessageType, alert: bool) {
            self.calls
                .lock()
                .unwrap()
                .push((text.to_string(), Some(msg_type), Some(alert)));
        }

        fn clear_status_text(&self) {
            self.calls.lock().unwrap().push((String::new(), None, None));
        }
    }

    #[test]
    fn set_status_text_default() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text("hello");
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "hello");
        assert_eq!(calls[0].1, None);
        assert_eq!(calls[0].2, None);
    }

    #[test]
    fn set_status_text_with_type_info() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_type("info message", MessageType::Info);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "info message");
        assert_eq!(calls[0].1, Some(MessageType::Info));
        assert_eq!(calls[0].2, None);
    }

    #[test]
    fn set_status_text_with_type_warning() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_type("warning", MessageType::Warning);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "warning");
        assert_eq!(calls[0].1, Some(MessageType::Warning));
    }

    #[test]
    fn set_status_text_with_type_alert() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_type("alert", MessageType::Alert);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "alert");
        assert_eq!(calls[0].1, Some(MessageType::Alert));
    }

    #[test]
    fn set_status_text_with_type_error() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_type("error", MessageType::Error);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "error");
        assert_eq!(calls[0].1, Some(MessageType::Error));
    }

    #[test]
    fn set_status_text_with_alert_true() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_alert("attention needed", MessageType::Alert, true);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "attention needed");
        assert_eq!(calls[0].1, Some(MessageType::Alert));
        assert_eq!(calls[0].2, Some(true));
    }

    #[test]
    fn set_status_text_with_alert_false() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text_with_alert("quiet", MessageType::Info, false);
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "quiet");
        assert_eq!(calls[0].1, Some(MessageType::Info));
        assert_eq!(calls[0].2, Some(false));
    }

    #[test]
    fn clear_status_text() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.clear_status_text();
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "");
        assert_eq!(calls[0].1, None);
        assert_eq!(calls[0].2, None);
    }

    #[test]
    fn multiple_calls() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text("first");
        listener.set_status_text_with_type("second", MessageType::Warning);
        listener.set_status_text_with_alert("third", MessageType::Alert, true);
        listener.clear_status_text();

        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].0, "first");
        assert_eq!(calls[1].0, "second");
        assert_eq!(calls[2].0, "third");
        assert_eq!(calls[3].0, "");
    }

    #[test]
    fn usable_as_trait_object() {
        let listener: Arc<dyn StatusListener> = Arc::new(TestStatusListener {
            calls: Mutex::new(Vec::new()),
        });
        listener.set_status_text("trait object");
        listener.set_status_text_with_type("with type", MessageType::Error);
        listener.set_status_text_with_alert("with alert", MessageType::Alert, true);
        listener.clear_status_text();
    }

    #[test]
    fn empty_text() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text("");
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "");
    }

    #[test]
    fn unicode_text() {
        let listener = TestStatusListener {
            calls: Mutex::new(Vec::new()),
        };
        listener.set_status_text("Unicode: 你好 🦀");
        let calls = listener.calls.lock().unwrap();
        assert_eq!(calls[0].0, "Unicode: 你好 🦀");
    }
}
