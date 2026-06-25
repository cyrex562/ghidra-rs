/// Defines a "type" for items in the Clipboard.
///
/// A ClipboardType wraps a DataFlavor (represented as a MIME type string)
/// and a human-readable type name.
#[derive(Debug, Clone)]
pub struct ClipboardType {
    flavor: String,
    type_name: String,
}

impl ClipboardType {
    /// Constructs a new ClipboardType.
    ///
    /// # Arguments
    /// * `flavor` - The MIME type string representing the data flavor
    /// * `type_name` - The human-readable name for this ClipboardType
    pub fn new(flavor: String, type_name: String) -> Self {
        ClipboardType { flavor, type_name }
    }

    /// Returns the flavor (MIME type) for this type.
    pub fn flavor(&self) -> &str {
        &self.flavor
    }

    /// Returns the name of this type.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
}

impl std::fmt::Display for ClipboardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.type_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let clipboard_type = ClipboardType::new(
            "text/plain".to_string(),
            "Text".to_string(),
        );
        assert_eq!(clipboard_type.flavor(), "text/plain");
        assert_eq!(clipboard_type.type_name(), "Text");
    }

    #[test]
    fn test_display() {
        let clipboard_type = ClipboardType::new(
            "text/plain".to_string(),
            "Address".to_string(),
        );
        assert_eq!(clipboard_type.to_string(), "Address");
    }

    #[test]
    fn test_clone() {
        let original = ClipboardType::new(
            "text/plain".to_string(),
            "MyType".to_string(),
        );
        let cloned = original.clone();
        assert_eq!(cloned.flavor(), original.flavor());
        assert_eq!(cloned.type_name(), original.type_name());
    }
}
