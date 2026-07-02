use thiserror::Error;

/// Exception thrown if an error occurs when adding a plugin.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginException`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct PluginException(pub String);

impl PluginException {
    /// Construct a new `PluginException` with the given class name and details.
    ///
    /// `class_name` – name of the plugin class
    /// `details` – the reason the plugin failed to load
    pub fn new(class_name: &str, details: &str) -> Self {
        Self(format!("Can't add plugin: {}.  {}", class_name, details))
    }

    /// Construct a `PluginException` with the given message.
    ///
    /// `message` – message that is returned in the to_string() method
    pub fn with_message(message: &str) -> Self {
        Self(message.to_string())
    }

    /// Construct a `PluginException` with the given message and cause.
    ///
    /// `message` – the exception message
    /// `_cause` – the exception cause (stored separately via error chaining)
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(
        message: &str,
        _cause: E,
    ) -> Self {
        Self(message.to_string())
    }

    /// Creates a new `PluginException` by appending the message from this exception
    /// to the message of the given exception if it is not null. If `e` is None,
    /// returns self.
    ///
    /// `e` – exception whose message will be appended to this exception's message if Some
    ///
    /// Returns this exception if `e` is None, or a new exception with appended message
    pub fn combine(&self, e: Option<&PluginException>) -> Self {
        match e {
            None => Self(self.0.clone()),
            Some(exc) => Self(format!("{}\n{}", exc.0, self.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_formats_message_correctly() {
        let e = PluginException::new("TestPlugin", "missing dependency");
        assert_eq!(e.to_string(), "Can't add plugin: TestPlugin.  missing dependency");
    }

    #[test]
    fn new_with_empty_class_name() {
        let e = PluginException::new("", "unknown error");
        assert_eq!(e.to_string(), "Can't add plugin: .  unknown error");
    }

    #[test]
    fn new_with_empty_details() {
        let e = PluginException::new("MyPlugin", "");
        assert_eq!(e.to_string(), "Can't add plugin: MyPlugin.  ");
    }

    #[test]
    fn with_message_stores_message() {
        let e = PluginException::with_message("custom error message");
        assert_eq!(e.to_string(), "custom error message");
    }

    #[test]
    fn with_message_empty() {
        let e = PluginException::with_message("");
        assert_eq!(e.to_string(), "");
    }

    #[test]
    fn with_cause_stores_message() {
        let cause = PluginException::with_message("root cause");
        let e = PluginException::with_cause("operation failed", cause);
        assert_eq!(e.to_string(), "operation failed");
    }

    #[test]
    fn display_matches_message() {
        let e = PluginException::new("SamplePlugin", "initialization failed");
        assert_eq!(
            e.to_string(),
            "Can't add plugin: SamplePlugin.  initialization failed"
        );
    }

    #[test]
    fn debug_contains_message() {
        let e = PluginException::new("Plugin", "error");
        let s = format!("{:?}", e);
        assert!(s.contains("PluginException"));
    }

    #[test]
    fn implements_error_trait() {
        let e = PluginException::new("Plugin", "failed");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = PluginException::new("Plugin", "failed");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = PluginException::new("Plugin", "error");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_holds_for_same_message() {
        let a = PluginException::new("Plugin", "error");
        let b = PluginException::new("Plugin", "error");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = PluginException::new("PluginA", "error");
        let b = PluginException::new("PluginB", "error");
        assert_ne!(a, b);
    }

    #[test]
    fn direct_construction_via_tuple() {
        let e = PluginException("custom message".to_string());
        assert_eq!(e.to_string(), "custom message");
    }

    #[test]
    fn combine_with_none_returns_self() {
        let e = PluginException::new("Plugin", "error");
        let result = e.combine(None);
        assert_eq!(result, e);
    }

    #[test]
    fn combine_with_some_appends_messages() {
        let e1 = PluginException::with_message("second error");
        let e2 = PluginException::with_message("first error");
        let result = e1.combine(Some(&e2));
        assert_eq!(result.to_string(), "first error\nsecond error");
    }

    #[test]
    fn combine_preserves_both_messages() {
        let e1 = PluginException::new("PluginX", "failed");
        let e2 = PluginException::new("PluginY", "timeout");
        let result = e1.combine(Some(&e2));
        assert!(result.to_string().contains("Can't add plugin: PluginY"));
        assert!(result.to_string().contains("Can't add plugin: PluginX"));
    }
}
