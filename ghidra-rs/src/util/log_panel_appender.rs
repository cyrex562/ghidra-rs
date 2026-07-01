use std::sync::{Arc, RwLock};

use tracing::Level;

use crate::util::log_listener::LogListener;

/// Routes log messages to the log panel in the main Ghidra window.
///
/// Port of `ghidra.util.log.LogPanelAppender`. The original is a log4j `Appender`
/// plugin that log4j instantiates from configuration; that plugin registration and
/// factory machinery has no equivalent here (this crate uses `tracing`, not log4j),
/// so this port keeps only the message-routing behavior.
///
/// Note: This appender starts receiving log messages immediately, but they are
/// dropped on the floor until a [`LogListener`] is installed via
/// [`LogPanelAppender::set_log_listener`].
pub struct LogPanelAppender {
    log_listener: RwLock<Option<Arc<dyn LogListener>>>,
}

impl LogPanelAppender {
    pub fn new() -> Self {
        LogPanelAppender { log_listener: RwLock::new(None) }
    }

    /// Handles a single log event, forwarding it to the installed listener if any.
    ///
    /// An error is identified as any log tagged `ERROR` (log4j also treats `FATAL`
    /// as an error, but `tracing` has no `FATAL` level).
    pub fn append(&self, level: Level, message: &str) {
        let listener = self.log_listener.read().unwrap();
        let Some(listener) = listener.as_ref() else {
            return;
        };
        let is_error = level == Level::ERROR;
        listener.message_logged(message, is_error);
    }

    /// Note: this method may be called multiple times in a single process, such as
    /// when testing.
    pub fn set_log_listener(&self, listener: Arc<dyn LogListener>) {
        *self.log_listener.write().unwrap() = Some(listener);
    }
}

impl Default for LogPanelAppender {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Collector {
        entries: Mutex<Vec<(String, bool)>>,
    }

    impl Collector {
        fn new() -> Self {
            Collector { entries: Mutex::new(Vec::new()) }
        }
    }

    impl LogListener for Collector {
        fn message_logged(&self, message: &str, is_error: bool) {
            self.entries.lock().unwrap().push((message.to_string(), is_error));
        }
    }

    #[test]
    fn messages_are_dropped_without_a_listener() {
        let appender = LogPanelAppender::new();
        // Must not panic even though no listener is installed.
        appender.append(Level::INFO, "no listener yet");
    }

    #[test]
    fn info_message_is_forwarded_as_non_error() {
        let appender = LogPanelAppender::new();
        let collector = Arc::new(Collector::new());
        appender.set_log_listener(collector.clone());

        appender.append(Level::INFO, "hello");

        let entries = collector.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], ("hello".to_string(), false));
    }

    #[test]
    fn error_message_is_forwarded_as_error() {
        let appender = LogPanelAppender::new();
        let collector = Arc::new(Collector::new());
        appender.set_log_listener(collector.clone());

        appender.append(Level::ERROR, "boom");

        let entries = collector.entries.lock().unwrap();
        assert_eq!(entries[0], ("boom".to_string(), true));
    }

    #[test]
    fn warn_message_is_not_treated_as_error() {
        let appender = LogPanelAppender::new();
        let collector = Arc::new(Collector::new());
        appender.set_log_listener(collector.clone());

        appender.append(Level::WARN, "careful");

        let entries = collector.entries.lock().unwrap();
        assert_eq!(entries[0], ("careful".to_string(), false));
    }

    #[test]
    fn listener_can_be_replaced() {
        let appender = LogPanelAppender::new();
        let first = Arc::new(Collector::new());
        let second = Arc::new(Collector::new());

        appender.set_log_listener(first.clone());
        appender.set_log_listener(second.clone());
        appender.append(Level::INFO, "to second");

        assert!(first.entries.lock().unwrap().is_empty());
        assert_eq!(second.entries.lock().unwrap().len(), 1);
    }
}
