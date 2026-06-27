/// A data container holding a substring (field string) that exists within a parent string,
/// along with the offset of that substring into the parent.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.FieldStringInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldStringInfo {
    offset: usize,
    parent_string: String,
    field_string: String,
}

impl FieldStringInfo {
    /// Creates a new `FieldStringInfo`.
    ///
    /// # Parameters
    /// - `parent_string`: the string that contains `field_string`
    /// - `field_string`: the substring that exists within `parent_string`
    /// - `offset`: the byte offset of `field_string` within `parent_string`
    pub fn new(
        parent_string: impl Into<String>,
        field_string: impl Into<String>,
        offset: usize,
    ) -> Self {
        Self {
            parent_string: parent_string.into(),
            field_string: field_string.into(),
            offset,
        }
    }

    /// Returns the offset of the field string into the parent string.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the parent string that contains the field string.
    pub fn parent_string(&self) -> &str {
        &self.parent_string
    }

    /// Returns the substring that exists within the parent string.
    pub fn field_string(&self) -> &str {
        &self.field_string
    }
}

impl std::fmt::Display for FieldStringInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FieldStringInfo[\nfieldString={},\nparentString={}\n]",
            self.field_string, self.parent_string
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_getters() {
        let info = FieldStringInfo::new("hello world", "world", 6);
        assert_eq!(info.parent_string(), "hello world");
        assert_eq!(info.field_string(), "world");
        assert_eq!(info.offset(), 6);
    }

    #[test]
    fn test_zero_offset() {
        let info = FieldStringInfo::new("abcdef", "abc", 0);
        assert_eq!(info.offset(), 0);
        assert_eq!(info.field_string(), "abc");
        assert_eq!(info.parent_string(), "abcdef");
    }

    #[test]
    fn test_empty_strings() {
        let info = FieldStringInfo::new("", "", 0);
        assert_eq!(info.parent_string(), "");
        assert_eq!(info.field_string(), "");
        assert_eq!(info.offset(), 0);
    }

    #[test]
    fn test_display() {
        let info = FieldStringInfo::new("parent", "field", 3);
        let s = format!("{}", info);
        assert!(s.contains("fieldString=field"));
        assert!(s.contains("parentString=parent"));
        assert!(s.contains("FieldStringInfo["));
    }

    #[test]
    fn test_clone_and_eq() {
        let info = FieldStringInfo::new("parent", "field", 2);
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_field_string_at_end() {
        let parent = "foo bar baz";
        let info = FieldStringInfo::new(parent, "baz", 8);
        assert_eq!(info.offset(), 8);
        assert_eq!(&parent[info.offset()..], info.field_string());
    }
}
