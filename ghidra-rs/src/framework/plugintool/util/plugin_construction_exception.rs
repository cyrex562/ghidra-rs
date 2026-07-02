use thiserror::Error;

/// Exception thrown when an error occurs during the construction of a plugin.
///
/// Mirrors `ghidra.framework.plugintool.util.PluginConstructionException`.
#[derive(Error, Debug, PartialEq, Eq)]
#[error("{0}")]
pub struct PluginConstructionException(pub String);

impl PluginConstructionException {
    /// Construct a new exception.
    ///
    /// `class_name` – name of the plugin class that failed to load
    /// `details` – details of the construction failure
    pub fn new(class_name: &str, details: &str) -> Self {
        Self(format!("Cannot load plugin{}:{}", class_name, details))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn new_formats_message_correctly() {
        let e = PluginConstructionException::new("TestPlugin", "missing dependency");
        assert_eq!(e.to_string(), "Cannot load pluginTestPlugin:missing dependency");
    }

    #[test]
    fn new_with_empty_class_name() {
        let e = PluginConstructionException::new("", "unknown error");
        assert_eq!(e.to_string(), "Cannot load plugin:unknown error");
    }

    #[test]
    fn new_with_empty_details() {
        let e = PluginConstructionException::new("MyPlugin", "");
        assert_eq!(e.to_string(), "Cannot load pluginMyPlugin:");
    }

    #[test]
    fn new_with_both_empty() {
        let e = PluginConstructionException::new("", "");
        assert_eq!(e.to_string(), "Cannot load plugin:");
    }

    #[test]
    fn display_matches_message() {
        let e = PluginConstructionException::new("SamplePlugin", "initialization failed");
        assert_eq!(
            e.to_string(),
            "Cannot load pluginSamplePlugin:initialization failed"
        );
    }

    #[test]
    fn debug_contains_message() {
        let e = PluginConstructionException::new("Plugin", "error");
        let s = format!("{:?}", e);
        assert!(s.contains("PluginConstructionException"));
    }

    #[test]
    fn implements_error_trait() {
        let e = PluginConstructionException::new("Plugin", "failed");
        let _: &dyn Error = &e;
    }

    #[test]
    fn error_source_is_none() {
        let e = PluginConstructionException::new("Plugin", "failed");
        assert!(e.source().is_none());
    }

    #[test]
    fn clone_produces_equal_value() {
        let a = PluginConstructionException::new("Plugin", "error");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn equality_holds_for_same_message() {
        let a = PluginConstructionException::new("Plugin", "error");
        let b = PluginConstructionException::new("Plugin", "error");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_messages() {
        let a = PluginConstructionException::new("PluginA", "error");
        let b = PluginConstructionException::new("PluginB", "error");
        assert_ne!(a, b);
    }

    #[test]
    fn direct_construction_via_tuple() {
        let e = PluginConstructionException("Cannot load pluginTest:failed".to_string());
        assert_eq!(e.to_string(), "Cannot load pluginTest:failed");
    }
}
