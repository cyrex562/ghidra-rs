use std::fmt;

/// Exception thrown when attempting to open a datatype archive with a duplicate ID.
///
/// Corresponds to the Java class `ghidra.app.plugin.core.datamgr.archive.DuplicateIdException`.
#[derive(Debug, Clone)]
pub struct DuplicateIdException {
    new_archive_name: String,
    existing_archive_name: String,
}

impl DuplicateIdException {
    /// Creates a new `DuplicateIdException`.
    ///
    /// # Arguments
    ///
    /// * `new_archive_name` - The name of the archive being opened.
    /// * `existing_archive_name` - The name of the archive already open with the same ID.
    pub fn new(new_archive_name: String, existing_archive_name: String) -> Self {
        DuplicateIdException {
            new_archive_name,
            existing_archive_name,
        }
    }

    /// Returns the name of the archive being opened.
    pub fn new_archive_name(&self) -> &str {
        &self.new_archive_name
    }

    /// Returns the name of the archive already open with the same ID.
    pub fn existing_archive_name(&self) -> &str {
        &self.existing_archive_name
    }
}

impl fmt::Display for DuplicateIdException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attempted to open a datatype archive with the same ID as datatype archive that is\n already open. {} has same id as {}\nOne is probably a copy of the other.  Ghidra does not support using \narchive copies within the same project!",
            self.new_archive_name, self.existing_archive_name
        )
    }
}

impl std::error::Error for DuplicateIdException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let exc = DuplicateIdException::new(
            "archive_new.gdt".to_string(),
            "archive_existing.gdt".to_string(),
        );
        assert_eq!(exc.new_archive_name(), "archive_new.gdt");
        assert_eq!(exc.existing_archive_name(), "archive_existing.gdt");
    }

    #[test]
    fn test_display_message() {
        let exc = DuplicateIdException::new(
            "copy.gdt".to_string(),
            "original.gdt".to_string(),
        );
        let msg = exc.to_string();
        assert!(msg.contains("copy.gdt"));
        assert!(msg.contains("original.gdt"));
        assert!(msg.contains("same ID"));
    }

    #[test]
    fn test_error_trait() {
        let exc = DuplicateIdException::new(
            "test_new.gdt".to_string(),
            "test_existing.gdt".to_string(),
        );
        let _: &dyn std::error::Error = &exc;
    }

    #[test]
    fn test_clone() {
        let exc = DuplicateIdException::new(
            "archive1.gdt".to_string(),
            "archive2.gdt".to_string(),
        );
        let cloned = exc.clone();
        assert_eq!(cloned.new_archive_name(), "archive1.gdt");
        assert_eq!(cloned.existing_archive_name(), "archive2.gdt");
    }

    #[test]
    fn test_debug_format() {
        let exc = DuplicateIdException::new(
            "debug_new.gdt".to_string(),
            "debug_existing.gdt".to_string(),
        );
        let debug_str = format!("{:?}", exc);
        assert!(debug_str.contains("DuplicateIdException"));
        assert!(debug_str.contains("debug_new.gdt"));
        assert!(debug_str.contains("debug_existing.gdt"));
    }
}
