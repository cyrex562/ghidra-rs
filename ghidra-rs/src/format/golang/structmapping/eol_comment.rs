/// Carries end-of-line comment metadata for a struct-mapping field.
///
/// In Java, `@EOLComment` is a runtime field annotation used by the struct-mapping
/// framework to attach an EOL comment to each mapped field instance.  The optional
/// `value` names a getter method on the containing type; when absent (or empty) the
/// field value's own `toString()` — modelled here as [`EolCommentProvider::eol_comment`]
/// — is used instead.  Because Rust has no field-level annotations, this metadata is
/// expressed as a plain struct that the framework stores alongside field descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EolComment {
    /// Name of the getter method whose return value supplies the comment text.
    ///
    /// `None` means "use the field value's own [`EolCommentProvider::eol_comment`]".
    pub getter: Option<String>,
}

impl EolComment {
    /// Creates an `EolComment` that uses the field's own display representation
    /// (equivalent to `@EOLComment` with no `value` argument in Java).
    pub fn default_getter() -> Self {
        Self { getter: None }
    }

    /// Creates an `EolComment` that delegates to the named getter method.
    ///
    /// An empty `name` is treated the same as [`default_getter`](Self::default_getter).
    pub fn with_getter(name: impl Into<String>) -> Self {
        let name = name.into();
        Self { getter: if name.is_empty() { None } else { Some(name) } }
    }

    /// Returns the configured getter name, or `None` when the field's own
    /// [`EolCommentProvider::eol_comment`] should be used.
    pub fn getter_name(&self) -> Option<&str> {
        self.getter.as_deref()
    }
}

/// Implemented by types that can produce an end-of-line comment string.
///
/// The struct-mapping framework calls this method when a field carries
/// [`EolComment`] metadata with no explicit getter name, mirroring the
/// Java behaviour where `Object.toString()` is used as the fallback.
pub trait EolCommentProvider {
    /// Returns the EOL comment string for this value.
    fn eol_comment(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::{EolComment, EolCommentProvider};

    // ── EolComment struct ────────────────────────────────────────────────

    #[test]
    fn default_getter_has_no_getter_name() {
        let meta = EolComment::default_getter();
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta.getter, None);
    }

    #[test]
    fn with_getter_stores_non_empty_name() {
        let meta = EolComment::with_getter("getDescription");
        assert_eq!(meta.getter_name(), Some("getDescription"));
    }

    #[test]
    fn with_getter_empty_string_becomes_none() {
        let meta = EolComment::with_getter("");
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta, EolComment::default_getter());
    }

    #[test]
    fn clone_and_eq_work() {
        let a = EolComment::with_getter("getName");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_getters_are_not_equal() {
        let a = EolComment::with_getter("getA");
        let b = EolComment::with_getter("getB");
        assert_ne!(a, b);
    }

    // ── EolCommentProvider trait ─────────────────────────────────────────

    struct MyField {
        value: u32,
    }

    impl EolCommentProvider for MyField {
        fn eol_comment(&self) -> String {
            format!("value={}", self.value)
        }
    }

    #[test]
    fn provider_returns_correct_string() {
        let f = MyField { value: 42 };
        assert_eq!(f.eol_comment(), "value=42");
    }

    #[test]
    fn provider_is_object_safe_via_box() {
        let f: Box<dyn EolCommentProvider> = Box::new(MyField { value: 7 });
        assert_eq!(f.eol_comment(), "value=7");
    }

    // ── Integration: metadata drives dispatch ────────────────────────────

    fn resolve_comment(meta: &EolComment, provider: &dyn EolCommentProvider) -> String {
        match meta.getter_name() {
            None => provider.eol_comment(),
            Some(name) => format!("<would call getter '{}'>", name),
        }
    }

    #[test]
    fn no_getter_uses_provider() {
        let meta = EolComment::default_getter();
        let f = MyField { value: 99 };
        assert_eq!(resolve_comment(&meta, &f), "value=99");
    }

    #[test]
    fn named_getter_routes_to_getter_name() {
        let meta = EolComment::with_getter("getLabel");
        let f = MyField { value: 1 };
        assert_eq!(resolve_comment(&meta, &f), "<would call getter 'getLabel'>");
    }
}
