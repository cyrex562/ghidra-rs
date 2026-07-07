/// Allows clients to receive log messages.
pub trait LogListener: Send + Sync {
    /// Called when a log message is received.
    ///
    /// `is_error` is `true` if the message is an error rather than informational.
    fn message_logged(&self, message: &str, is_error: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Collector {
        entries: Mutex<Vec<(String, bool)>>,
    }

    impl LogListener for Collector {
        fn message_logged(&self, message: &str, is_error: bool) {
            self.entries.lock().unwrap().push((message.to_string(), is_error));
        }
    }

    #[test]
    fn records_informational_message() {
        let c = Collector { entries: Mutex::new(Vec::new()) };
        c.message_logged("hello", false);
        let entries = c.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ("hello".to_string(), false));
    }

    #[test]
    fn records_error_message() {
        let c = Collector { entries: Mutex::new(Vec::new()) };
        c.message_logged("boom", true);
        let entries = c.entries.lock().unwrap();
        assert_eq!(entries[0], ("boom".to_string(), true));
    }

    #[test]
    fn usable_as_trait_object() {
        let c: Arc<dyn LogListener> = Arc::new(Collector { entries: Mutex::new(Vec::new()) });
        c.message_logged("via dyn", false);
    }
}
