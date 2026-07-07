/// Identifies which codec the auto-config-state framework should use for a field,
/// mirroring Java's `@AutoConfigStateField` runtime annotation.
///
/// In Java this annotation is placed on fields so that `AutoConfigState` can
/// automatically encode/decode the field's value. The `codec()` element names the
/// `ConfigFieldCodec` implementation to use; omitting it selects the default
/// (framework-chosen) codec. In Rust, where there is no reflective annotation
/// system, the same metadata is carried in this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoConfigStateField {
    /// Which codec the framework should use for the annotated field.
    pub codec: CodecKind,
}

/// Selects which `ConfigFieldCodec` implementation handles a field.
///
/// This mirrors the `codec()` element of Java's `@AutoConfigStateField`:
/// - `Default` corresponds to `DefaultConfigFieldCodec.class` (the sentinel class whose
///   constructor unconditionally throws `AssertionError` — it is never instantiated;
///   its presence simply signals "let the framework choose").
/// - `Named` carries an opaque name for a registered non-default codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecKind {
    /// Use the framework-selected default codec (Java: `DefaultConfigFieldCodec.class`).
    Default,
    /// Use a named, explicitly registered codec (Java: `SomeCodec.class`).
    Named(String),
}

impl AutoConfigStateField {
    /// Creates an `AutoConfigStateField` using the default codec,
    /// matching `@AutoConfigStateField` with no explicit `codec`.
    pub fn new() -> Self {
        Self { codec: CodecKind::Default }
    }

    /// Creates an `AutoConfigStateField` referencing a named codec,
    /// matching `@AutoConfigStateField(codec = SomeCodec.class)`.
    ///
    /// # Panics
    /// Panics when `name` is empty.
    pub fn with_codec(name: impl Into<String>) -> Self {
        let name = name.into();
        assert!(!name.is_empty(), "AutoConfigStateField: codec name must not be empty");
        Self { codec: CodecKind::Named(name) }
    }

    /// Returns `true` when an explicit non-default codec was specified.
    pub fn has_explicit_codec(&self) -> bool {
        matches!(self.codec, CodecKind::Named(_))
    }
}

impl Default for AutoConfigStateField {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uses_default_codec() {
        let f = AutoConfigStateField::new();
        assert_eq!(f.codec, CodecKind::Default);
        assert!(!f.has_explicit_codec());
    }

    #[test]
    fn default_trait_matches_new() {
        assert_eq!(AutoConfigStateField::default(), AutoConfigStateField::new());
    }

    #[test]
    fn with_codec_stores_name() {
        let f = AutoConfigStateField::with_codec("MyCodec");
        assert_eq!(f.codec, CodecKind::Named("MyCodec".to_string()));
        assert!(f.has_explicit_codec());
    }

    #[test]
    #[should_panic(expected = "codec name must not be empty")]
    fn with_empty_codec_name_panics() {
        AutoConfigStateField::with_codec("");
    }

    #[test]
    fn equality_holds_for_identical_default_instances() {
        assert_eq!(AutoConfigStateField::new(), AutoConfigStateField::new());
    }

    #[test]
    fn equality_holds_for_identical_named_instances() {
        let a = AutoConfigStateField::with_codec("Foo");
        let b = AutoConfigStateField::with_codec("Foo");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_between_default_and_named() {
        let a = AutoConfigStateField::new();
        let b = AutoConfigStateField::with_codec("Foo");
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_when_codec_names_differ() {
        let a = AutoConfigStateField::with_codec("Codec1");
        let b = AutoConfigStateField::with_codec("Codec2");
        assert_ne!(a, b);
    }

    #[test]
    fn clone_produces_equal_instance() {
        let a = AutoConfigStateField::with_codec("Clone");
        assert_eq!(a.clone(), a);
    }

    #[test]
    fn debug_contains_codec_name() {
        let a = AutoConfigStateField::with_codec("DebugCodec");
        let s = format!("{a:?}");
        assert!(s.contains("DebugCodec"));
    }
}
