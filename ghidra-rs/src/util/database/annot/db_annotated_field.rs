//! Mirrors `ghidra.util.database.annot.DBAnnotatedField`: the annotation marking a Java field
//! to be stored in a table column.
//!
//! Java annotations are compile-time metadata read via reflection at runtime; there is no direct
//! Rust equivalent, so this is ported as a trait describing the same per-field metadata
//! (`column`/`indexed`/`sparse`/`codec`), implemented by whatever stands in for an annotated
//! field's spec once the reflective object-store machinery (`DBAnnotatedObjectFactory`,
//! `DBCachedObjectStoreFactory`) is ported. `indexed`/`sparse` keep the annotation's `false`
//! defaults, and `codec` keeps the annotation's `DefaultCodec` sentinel default (`None`, meaning
//! "no custom codec requested; the framework should infer one").

use crate::util::seam_stubs::DBFieldCodec;

/// Per-field storage metadata, mirroring the members of the `@DBAnnotatedField` annotation.
pub trait DBAnnotatedField: Send + Sync {
    /// The name of the column, mirroring `DBAnnotatedField.column()`.
    fn column(&self) -> &str;

    /// True to index the column, mirroring `DBAnnotatedField.indexed()`.
    fn indexed(&self) -> bool {
        false
    }

    /// True to use sparse storage, mirroring `DBAnnotatedField.sparse()`.
    fn sparse(&self) -> bool {
        false
    }

    /// A custom codec, or `None` if the framework should check for a built-in codec, mirroring
    /// `DBAnnotatedField.codec()` (`None` stands in for the `DefaultCodec` sentinel class, whose
    /// Java constructor is private and always throws -- it is never actually instantiated).
    fn codec(&self) -> Option<Box<dyn DBFieldCodec>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCodec;
    impl DBFieldCodec for MockCodec {}

    /// Uses the annotation's `indexed`/`sparse`/`codec` defaults, overriding only `column`.
    struct PlainField(&'static str);
    impl DBAnnotatedField for PlainField {
        fn column(&self) -> &str {
            self.0
        }
    }

    /// Overrides every member, including supplying a custom codec.
    struct FullField;
    impl DBAnnotatedField for FullField {
        fn column(&self) -> &str {
            "VALUE"
        }
        fn indexed(&self) -> bool {
            true
        }
        fn sparse(&self) -> bool {
            true
        }
        fn codec(&self) -> Option<Box<dyn DBFieldCodec>> {
            Some(Box::new(MockCodec))
        }
    }

    #[test]
    fn object_safe_and_uses_annotation_defaults() {
        let field: Box<dyn DBAnnotatedField> = Box::new(PlainField("NAME"));
        assert_eq!(field.column(), "NAME");
        assert!(!field.indexed());
        assert!(!field.sparse());
        assert!(field.codec().is_none());
    }

    #[test]
    fn overrides_all_members() {
        let field: Box<dyn DBAnnotatedField> = Box::new(FullField);
        assert_eq!(field.column(), "VALUE");
        assert!(field.indexed());
        assert!(field.sparse());
        assert!(field.codec().is_some());
    }
}
