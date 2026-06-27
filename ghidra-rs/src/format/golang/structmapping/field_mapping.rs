/// Signedness attribute of a structure-mapped field.
///
/// Corresponds to the `Signedness` enum in the Java struct-mapping framework.
/// Defined here because it is a direct dependency of [`FieldMapping`] metadata;
/// a dedicated `signedness.rs` module may supersede this once that class is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signedness {
    /// No signedness override — use the data type's natural signedness.
    #[default]
    Unspecified,
    /// Force signed interpretation of the underlying numeric value.
    Signed,
    /// Force unsigned interpretation of the underlying numeric value.
    Unsigned,
}

/// Metadata expressing how a Rust struct field maps to a Ghidra structure field.
///
/// This is the Rust equivalent of the Java `@FieldMapping` annotation used by the
/// struct-mapping framework.  In Java the annotation is placed on individual fields
/// and read at runtime via reflection.  In Rust there are no field-level annotations,
/// so the same information is carried as a plain struct that the framework stores
/// alongside field descriptors.
///
/// # Field-name resolution
///
/// `field_names` lists the Ghidra structure field names that should be tried when
/// binding this Rust field.  An empty list means "use the Rust field's own name"
/// (the common case, equivalent to the Java annotation's default of `""`).  Multiple
/// names are tried in order, case-insensitively.
///
/// # Read-function override
///
/// `read_func_override` holds the fully-qualified class name of a
/// `FieldReadFunction` implementation that should be used to deserialise this
/// field.  `None` means "use the default deserialization mechanism" (equivalent
/// to `readFunc = FieldReadFunction.class` in Java).  The actual dispatch will be
/// wired up once `FieldReadFunction` and `FieldContext` are ported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMapping {
    /// Alternate Ghidra structure field names to match.
    ///
    /// Empty means "use the Rust field's name".  Matching is case-insensitive.
    pub field_names: Vec<String>,

    /// When `true`, a missing binding between this Rust field and a structure
    /// field is silently ignored rather than treated as an error.
    pub optional: bool,

    /// A free-form string interpreted by the concrete `DataTypeMapper` to decide
    /// whether this field should be bound at all.  Empty string means "always
    /// present".
    pub present_when: String,

    /// Name of an explicit setter method to use when assigning the deserialized
    /// value to the Rust field.  Empty means "try the canonical setter name, then
    /// fall back to direct assignment".
    pub setter: String,

    /// Fully-qualified class name of a `FieldReadFunction` implementation, or
    /// `None` to use the framework's default deserialization path.
    pub read_func_override: Option<String>,

    /// Explicit byte length for the structure field, overriding the data type's
    /// own length.  `None` means "use the field's data type length".
    pub length: Option<u32>,

    /// Signedness override for the underlying numeric value.
    pub signedness: Signedness,
}

impl FieldMapping {
    /// Creates a `FieldMapping` with all defaults matching the Java annotation's
    /// defaults: no name override, required, always present, no setter, default
    /// read function, no length override, unspecified signedness.
    pub fn new() -> Self {
        Self {
            field_names: Vec::new(),
            optional: false,
            present_when: String::new(),
            setter: String::new(),
            read_func_override: None,
            length: None,
            signedness: Signedness::Unspecified,
        }
    }

    /// Returns `true` when the `field_names` list is empty, meaning the framework
    /// should fall back to using the Rust field's own name.
    pub fn uses_field_name_as_default(&self) -> bool {
        self.field_names.is_empty()
    }
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldMapping, Signedness};

    // ── FieldMapping defaults ────────────────────────────────────────────────

    #[test]
    fn default_has_empty_field_names() {
        let m = FieldMapping::new();
        assert!(m.field_names.is_empty());
        assert!(m.uses_field_name_as_default());
    }

    #[test]
    fn default_is_not_optional() {
        let m = FieldMapping::new();
        assert!(!m.optional);
    }

    #[test]
    fn default_present_when_is_empty() {
        let m = FieldMapping::new();
        assert!(m.present_when.is_empty());
    }

    #[test]
    fn default_setter_is_empty() {
        let m = FieldMapping::new();
        assert!(m.setter.is_empty());
    }

    #[test]
    fn default_read_func_override_is_none() {
        let m = FieldMapping::new();
        assert!(m.read_func_override.is_none());
    }

    #[test]
    fn default_length_is_none() {
        let m = FieldMapping::new();
        assert!(m.length.is_none());
    }

    #[test]
    fn default_signedness_is_unspecified() {
        let m = FieldMapping::new();
        assert_eq!(m.signedness, Signedness::Unspecified);
    }

    #[test]
    fn default_trait_matches_new() {
        let a = FieldMapping::new();
        let b = FieldMapping::default();
        assert_eq!(a, b);
    }

    // ── FieldMapping builder mutations ──────────────────────────────────────

    #[test]
    fn field_names_can_be_set() {
        let m = FieldMapping {
            field_names: vec!["myField".to_string(), "MyField".to_string()],
            ..FieldMapping::default()
        };
        assert!(!m.uses_field_name_as_default());
        assert_eq!(m.field_names.len(), 2);
        assert_eq!(m.field_names[0], "myField");
    }

    #[test]
    fn optional_can_be_true() {
        let m = FieldMapping { optional: true, ..FieldMapping::default() };
        assert!(m.optional);
    }

    #[test]
    fn present_when_can_be_set() {
        let m = FieldMapping {
            present_when: "go1.18".to_string(),
            ..FieldMapping::default()
        };
        assert_eq!(m.present_when, "go1.18");
    }

    #[test]
    fn setter_can_be_set() {
        let m = FieldMapping {
            setter: "setCount".to_string(),
            ..FieldMapping::default()
        };
        assert_eq!(m.setter, "setCount");
    }

    #[test]
    fn read_func_override_can_be_set() {
        let m = FieldMapping {
            read_func_override: Some(
                "ghidra.app.util.bin.format.golang.structmapping.SomeReader".to_string(),
            ),
            ..FieldMapping::default()
        };
        assert!(m.read_func_override.is_some());
        assert!(m.read_func_override.as_deref().unwrap().contains("SomeReader"));
    }

    #[test]
    fn length_can_be_set() {
        let m = FieldMapping { length: Some(4), ..FieldMapping::default() };
        assert_eq!(m.length, Some(4));
    }

    #[test]
    fn signedness_can_be_signed() {
        let m = FieldMapping { signedness: Signedness::Signed, ..FieldMapping::default() };
        assert_eq!(m.signedness, Signedness::Signed);
    }

    #[test]
    fn signedness_can_be_unsigned() {
        let m = FieldMapping { signedness: Signedness::Unsigned, ..FieldMapping::default() };
        assert_eq!(m.signedness, Signedness::Unsigned);
    }

    #[test]
    fn clone_and_eq_work() {
        let a = FieldMapping {
            field_names: vec!["foo".to_string()],
            optional: true,
            present_when: "v2".to_string(),
            setter: "setFoo".to_string(),
            read_func_override: Some("com.example.FooReader".to_string()),
            length: Some(8),
            signedness: Signedness::Unsigned,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn two_distinct_instances_are_not_equal() {
        let a = FieldMapping::default();
        let b = FieldMapping { optional: true, ..FieldMapping::default() };
        assert_ne!(a, b);
    }

    // ── Signedness ───────────────────────────────────────────────────────────

    #[test]
    fn signedness_default_is_unspecified() {
        assert_eq!(Signedness::default(), Signedness::Unspecified);
    }

    #[test]
    fn signedness_variants_are_distinct() {
        assert_ne!(Signedness::Unspecified, Signedness::Signed);
        assert_ne!(Signedness::Signed, Signedness::Unsigned);
        assert_ne!(Signedness::Unspecified, Signedness::Unsigned);
    }

    #[test]
    fn signedness_clone_works() {
        let s = Signedness::Signed;
        assert_eq!(s, s.clone());
    }

    #[test]
    fn signedness_copy_works() {
        let s = Signedness::Unsigned;
        let t = s; // Copy
        assert_eq!(s, t);
    }
}
