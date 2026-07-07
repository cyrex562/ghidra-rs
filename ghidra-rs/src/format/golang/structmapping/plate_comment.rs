/// Carries plate-comment metadata for a struct-mapping field or type.
///
/// In Java, `@PlateComment` is a runtime annotation that can be applied to
/// fields *or* types (`@Target({ FIELD, TYPE })`).  When present on a field,
/// the optional `value` names a getter method whose return value is used as
/// the plate-comment text; when absent or empty the field value's own
/// `toString()` — modelled here as [`PlateCommentProvider::plate_comment`] —
/// is used instead.  When applied to a type the object's own `toString()` is
/// used.  Because Rust has no field- or type-level annotations, this metadata
/// is expressed as a plain struct that the framework stores alongside field
/// and type descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlateComment {
    /// Name of the getter method whose return value supplies the comment text.
    ///
    /// `None` means "use the value's own [`PlateCommentProvider::plate_comment`]".
    pub getter: Option<String>,
}

impl PlateComment {
    /// Creates a `PlateComment` that uses the value's own display representation
    /// (equivalent to `@PlateComment` with no `value` argument in Java).
    pub fn default_getter() -> Self {
        Self { getter: None }
    }

    /// Creates a `PlateComment` that delegates to the named getter method.
    ///
    /// An empty `name` is treated the same as [`default_getter`](Self::default_getter).
    pub fn with_getter(name: impl Into<String>) -> Self {
        let name = name.into();
        Self { getter: if name.is_empty() { None } else { Some(name) } }
    }

    /// Returns the configured getter name, or `None` when the value's own
    /// [`PlateCommentProvider::plate_comment`] should be used.
    pub fn getter_name(&self) -> Option<&str> {
        self.getter.as_deref()
    }
}

/// Implemented by types that can produce a plate-comment string.
///
/// The struct-mapping framework calls this method when a field or type carries
/// [`PlateComment`] metadata with no explicit getter name, mirroring the
/// Java behaviour where `Object.toString()` is used as the fallback.
pub trait PlateCommentProvider {
    /// Returns the plate-comment string for this value.
    fn plate_comment(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::{PlateComment, PlateCommentProvider};

    // ── PlateComment struct ──────────────────────────────────────────────

    #[test]
    fn default_getter_has_no_getter_name() {
        let meta = PlateComment::default_getter();
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta.getter, None);
    }

    #[test]
    fn with_getter_stores_non_empty_name() {
        let meta = PlateComment::with_getter("getDescription");
        assert_eq!(meta.getter_name(), Some("getDescription"));
    }

    #[test]
    fn with_getter_empty_string_becomes_none() {
        let meta = PlateComment::with_getter("");
        assert_eq!(meta.getter_name(), None);
        assert_eq!(meta, PlateComment::default_getter());
    }

    #[test]
    fn clone_and_eq_work() {
        let a = PlateComment::with_getter("getName");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_getters_are_not_equal() {
        let a = PlateComment::with_getter("getA");
        let b = PlateComment::with_getter("getB");
        assert_ne!(a, b);
    }

    // ── PlateCommentProvider trait ───────────────────────────────────────

    struct MyObject {
        label: &'static str,
    }

    impl PlateCommentProvider for MyObject {
        fn plate_comment(&self) -> String {
            self.label.to_string()
        }
    }

    #[test]
    fn provider_returns_correct_string() {
        let obj = MyObject { label: "GoSliceHeader" };
        assert_eq!(obj.plate_comment(), "GoSliceHeader");
    }

    #[test]
    fn provider_is_object_safe_via_box() {
        let obj: Box<dyn PlateCommentProvider> = Box::new(MyObject { label: "GoString" });
        assert_eq!(obj.plate_comment(), "GoString");
    }

    // ── Integration: metadata drives dispatch ────────────────────────────

    fn resolve_comment(meta: &PlateComment, provider: &dyn PlateCommentProvider) -> String {
        match meta.getter_name() {
            None => provider.plate_comment(),
            Some(name) => format!("<would call getter '{}'>", name),
        }
    }

    #[test]
    fn no_getter_uses_provider() {
        let meta = PlateComment::default_getter();
        let obj = MyObject { label: "GoMapHeader" };
        assert_eq!(resolve_comment(&meta, &obj), "GoMapHeader");
    }

    #[test]
    fn named_getter_routes_to_getter_name() {
        let meta = PlateComment::with_getter("getLabel");
        let obj = MyObject { label: "irrelevant" };
        assert_eq!(resolve_comment(&meta, &obj), "<would call getter 'getLabel'>");
    }

    // ── Type-level use (Java @Target TYPE) ──────────────────────────────

    struct GoStruct {
        name: String,
    }

    impl PlateCommentProvider for GoStruct {
        fn plate_comment(&self) -> String {
            format!("GoStruct({})", self.name)
        }
    }

    #[test]
    fn type_level_plate_comment_uses_provider() {
        let meta = PlateComment::default_getter();
        let s = GoStruct { name: "runtime.hmap".into() };
        assert_eq!(resolve_comment(&meta, &s), "GoStruct(runtime.hmap)");
    }
}
