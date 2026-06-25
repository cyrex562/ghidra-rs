/// A message wrapper for script logging that enables filtering in log4j.
///
/// This class allows filtering script log messages separately from other log messages.
/// The formatted message is the original client message, while the format string
/// is used by log4j filters (when `useRawMsg="true"`) to identify script messages.
///
/// Ported from `ghidra.app.script.ScriptMessage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptMessage {
    message: String,
}

impl ScriptMessage {
    /// Create a new script message from the given string.
    pub fn new(message: String) -> Self {
        ScriptMessage { message }
    }

    /// Get the formatted message that will be emitted to logs.
    ///
    /// This is the original client message as provided to the constructor.
    pub fn get_formatted_message(&self) -> &str {
        &self.message
    }

    /// Get the format string used by log4j filters.
    ///
    /// When a log4j filter has `useRawMsg="true"`, this method's return value
    /// is used to identify and filter script messages.
    pub fn get_format(&self) -> String {
        format!("Format:GhidraScript{}", self.get_formatted_message())
    }

    /// Get the message parameters (always None for script messages).
    pub fn get_parameters(&self) -> Option<()> {
        None
    }

    /// Get any associated throwable (always None for script messages).
    pub fn get_throwable(&self) -> Option<()> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_script_message() {
        let msg = ScriptMessage::new("Test message".to_string());
        assert_eq!(msg.get_formatted_message(), "Test message");
    }

    #[test]
    fn test_get_formatted_message() {
        let msg = ScriptMessage::new("Hello, Script!".to_string());
        assert_eq!(msg.get_formatted_message(), "Hello, Script!");
    }

    #[test]
    fn test_get_format_prefix() {
        let msg = ScriptMessage::new("test message".to_string());
        let format = msg.get_format();
        assert_eq!(format, "Format:GhidraScripttest message");
        assert!(format.starts_with("Format:GhidraScript"));
    }

    #[test]
    fn test_get_format_with_empty_message() {
        let msg = ScriptMessage::new(String::new());
        assert_eq!(msg.get_format(), "Format:GhidraScript");
    }

    #[test]
    fn test_get_format_with_special_characters() {
        let msg = ScriptMessage::new("Error: \n\t special chars!".to_string());
        assert_eq!(
            msg.get_format(),
            "Format:GhidraScriptError: \n\t special chars!"
        );
    }

    #[test]
    fn test_get_parameters_returns_none() {
        let msg = ScriptMessage::new("any message".to_string());
        assert_eq!(msg.get_parameters(), None);
    }

    #[test]
    fn test_get_throwable_returns_none() {
        let msg = ScriptMessage::new("any message".to_string());
        assert_eq!(msg.get_throwable(), None);
    }

    #[test]
    fn test_script_message_clone() {
        let msg = ScriptMessage::new("Clone me".to_string());
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn test_script_message_debug() {
        let msg = ScriptMessage::new("Debug test".to_string());
        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("Debug test"));
    }

    #[test]
    fn test_script_message_equality() {
        let msg1 = ScriptMessage::new("Same".to_string());
        let msg2 = ScriptMessage::new("Same".to_string());
        let msg3 = ScriptMessage::new("Different".to_string());

        assert_eq!(msg1, msg2);
        assert_ne!(msg1, msg3);
    }
}
