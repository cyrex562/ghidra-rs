/// Carries data-reference markup metadata for a struct-mapping field.
///
/// In Java, `@MarkupReference` is a runtime field annotation used by the struct-mapping
/// framework to decorate the target of a tagged field with a data reference from the
/// field's location.  The optional `value` names a getter method on the containing
/// type; when absent (or empty) the field's own getter is used instead.  The getter
/// method must return something convertible to an `Address`.  Because Rust has no
/// field-level annotations, this metadata is expressed as a plain struct that the
/// framework stores alongside field descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkupReference {
    /// Name of the getter method whose return value supplies the address.
    ///
    /// `None` means "use the field's own getter method".  The getter method can be
    /// specified in full (e.g., "getTarget") or without the "get" prefix (e.g., "Target"),
    /// and either form is valid.
    pub getter: Option<String>,
}

impl MarkupReference {
    /// Creates a `MarkupReference` that uses the field's own getter
    /// (equivalent to `@MarkupReference` with no `value` argument in Java).
    pub fn default_getter() -> Self {
        Self { getter: None }
    }

    /// Creates a `MarkupReference` that delegates to the named getter method.
    ///
    /// An empty `name` is treated the same as [`default_getter`](Self::default_getter).
    /// The getter method name can be specified in full (e.g., "getTarget") or without
    /// the "get" prefix (e.g., "Target"), and either form is valid.
    pub fn with_getter(name: impl Into<String>) -> Self {
        let name = name.into();
        Self { getter: if name.is_empty() { None } else { Some(name) } }
    }

    /// Returns the configured getter name, or `None` when the field's own
    /// getter should be used.
    pub fn getter_name(&self) -> Option<&str> {
        self.getter.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::MarkupReference;

    // ── MarkupReference struct ───────────────────────────────────────────

    #[test]
    fn default_getter_has_no_getter_name() {
        let meta = MarkupReference::default_getter();
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta.getter, None);
    }

    #[test]
    fn with_getter_stores_non_empty_name() {
        let meta = MarkupReference::with_getter("getTarget");
        assert_eq!(meta.getter_name(), Some("getTarget"));
    }

    #[test]
    fn with_getter_stores_getter_without_prefix() {
        let meta = MarkupReference::with_getter("Target");
        assert_eq!(meta.getter_name(), Some("Target"));
    }

    #[test]
    fn with_getter_empty_string_becomes_none() {
        let meta = MarkupReference::with_getter("");
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta, MarkupReference::default_getter());
    }

    #[test]
    fn clone_and_eq_work() {
        let a = MarkupReference::with_getter("getAddress");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_getters_are_not_equal() {
        let a = MarkupReference::with_getter("getA");
        let b = MarkupReference::with_getter("getB");
        assert_ne!(a, b);
    }

    #[test]
    fn default_getter_not_equal_to_custom_getter() {
        let default = MarkupReference::default_getter();
        let custom = MarkupReference::with_getter("getTarget");
        assert_ne!(default, custom);
    }

    #[test]
    fn debug_display_is_reasonable() {
        let with_getter = MarkupReference::with_getter("getTarget");
        assert!(format!("{:?}", with_getter).contains("getTarget"));

        let default = MarkupReference::default_getter();
        let debug_str = format!("{:?}", default);
        assert!(debug_str.contains("getter") || debug_str.contains("None"));
    }

    #[test]
    fn into_string_conversion() {
        let meta = MarkupReference::with_getter("getAddress".to_string());
        assert_eq!(meta.getter_name(), Some("getAddress"));
    }
}
