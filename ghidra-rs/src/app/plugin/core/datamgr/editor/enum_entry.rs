use serde::{Deserialize, Serialize};
use crate::generic::json::Json;

/// Represents an enumeration entry with a name, value, and optional comment.
///
/// Corresponds to the Java class `ghidra.app.plugin.core.datamgr.editor.EnumEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumEntry {
    name: String,
    value: i64,
    comment: String,
}

impl EnumEntry {
    /// Creates a new `EnumEntry`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the enum entry.
    /// * `value` - The numeric value of the entry.
    /// * `comment` - An optional comment describing the entry.
    pub fn new(name: String, value: i64, comment: String) -> Self {
        EnumEntry {
            name,
            value,
            comment,
        }
    }

    /// Returns the name of this entry.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the value of this entry.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Returns the comment of this entry.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Sets the name of this entry.
    pub fn set_name(&mut self, new_name: String) {
        self.name = new_name;
    }

    /// Sets the value of this entry.
    pub fn set_value(&mut self, new_value: i64) {
        self.value = new_value;
    }

    /// Sets the comment of this entry.
    pub fn set_comment(&mut self, new_comment: String) {
        self.comment = new_comment;
    }
}

impl std::fmt::Display for EnumEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Json::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_entry() {
        let entry = EnumEntry::new(
            "ENUM_VAL".to_string(),
            42,
            "A test enum value".to_string(),
        );
        assert_eq!(entry.name(), "ENUM_VAL");
        assert_eq!(entry.value(), 42);
        assert_eq!(entry.comment(), "A test enum value");
    }

    #[test]
    fn test_set_name() {
        let mut entry = EnumEntry::new(
            "OLD_NAME".to_string(),
            10,
            "comment".to_string(),
        );
        entry.set_name("NEW_NAME".to_string());
        assert_eq!(entry.name(), "NEW_NAME");
    }

    #[test]
    fn test_set_value() {
        let mut entry = EnumEntry::new(
            "VAL".to_string(),
            100,
            "comment".to_string(),
        );
        entry.set_value(200);
        assert_eq!(entry.value(), 200);
    }

    #[test]
    fn test_set_comment() {
        let mut entry = EnumEntry::new(
            "VAL".to_string(),
            1,
            "old comment".to_string(),
        );
        entry.set_comment("new comment".to_string());
        assert_eq!(entry.comment(), "new comment");
    }

    #[test]
    fn test_clone() {
        let entry = EnumEntry::new(
            "TEST".to_string(),
            99,
            "test comment".to_string(),
        );
        let cloned = entry.clone();
        assert_eq!(cloned.name(), "TEST");
        assert_eq!(cloned.value(), 99);
        assert_eq!(cloned.comment(), "test comment");
    }

    #[test]
    fn test_debug_format() {
        let entry = EnumEntry::new(
            "DBG".to_string(),
            7,
            "debug test".to_string(),
        );
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("EnumEntry"));
    }

    #[test]
    fn test_display_format() {
        let entry = EnumEntry::new(
            "DISPLAY".to_string(),
            33,
            "display test".to_string(),
        );
        let display_str = entry.to_string();
        assert!(display_str.contains("DISPLAY"));
        assert!(display_str.contains("33"));
    }

    #[test]
    fn test_negative_value() {
        let entry = EnumEntry::new(
            "NEG".to_string(),
            -1,
            "negative value".to_string(),
        );
        assert_eq!(entry.value(), -1);
    }

    #[test]
    fn test_zero_value() {
        let entry = EnumEntry::new(
            "ZERO".to_string(),
            0,
            "zero value".to_string(),
        );
        assert_eq!(entry.value(), 0);
    }

    #[test]
    fn test_large_value() {
        let entry = EnumEntry::new(
            "LARGE".to_string(),
            i64::MAX,
            "large value".to_string(),
        );
        assert_eq!(entry.value(), i64::MAX);
    }

    #[test]
    fn test_empty_strings() {
        let entry = EnumEntry::new(
            "".to_string(),
            5,
            "".to_string(),
        );
        assert_eq!(entry.name(), "");
        assert_eq!(entry.comment(), "");
    }
}
