/// Metadata binding a Rust struct type to a named Ghidra structure data type.
///
/// This is the Rust equivalent of the Java `@StructureMapping` annotation from
/// `ghidra.app.util.bin.format.golang.structmapping`.  In Java the annotation is
/// placed on classes and read at runtime via reflection; in Rust the same information
/// is expressed as a plain struct that the framework stores alongside type
/// descriptors.
///
/// # Fixed-length structures
///
/// For fixed/static length structures the framework searches for an existing Ghidra
/// structure data type whose name matches one of [`structure_names`](Self::structure_names)
/// and binds it to the implementing type.  Only fields tagged with [`FieldMapping`]
/// metadata need to be listed; the rest are ignored.
///
/// # Variable-length structures
///
/// For variable-length structures a unique Ghidra structure data type is created for
/// each combination of field lengths.  The tagged type must implement
/// `StructureReader` to deserialise itself (each variable-length field also carries
/// a `FieldOutput` descriptor).  The generated data type's name follows the pattern
/// `structurename_NN_MM_...` where `NN`, `MM`, … are the lengths of the
/// variable-length fields found in the structure.
///
/// # Custom markup
///
/// An optional [`markup_func`](Self::markup_func) names a `StructureMarkupFunction`
/// implementation that provides custom decoration for instances of the tagged type.
/// `None` means "use the framework default markup behaviour", mirroring the Java
/// annotation's `markupFunc = StructureMarkupFunction.class` sentinel.
///
/// # Registration
///
/// Structure-mapped types must be registered with the `DataTypeMapper` program
/// context (via `DataTypeMapper::register_structure`) before the suite of
/// struct-mapped types can be applied to a Ghidra binary.
///
/// [`FieldMapping`]: super::FieldMapping
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureMapping {
    /// Names (and alternate names) of the Ghidra structure data type.
    ///
    /// The framework searches for these names (case-insensitively) in the configured
    /// archive and program search paths.  At least one name must be provided.
    pub structure_names: Vec<String>,

    /// Fully-qualified class name of a `StructureMarkupFunction` implementation,
    /// or `None` to use the framework's default markup behaviour.
    ///
    /// `None` corresponds to the Java default: `markupFunc = StructureMarkupFunction.class`.
    pub markup_func: Option<String>,
}

impl StructureMapping {
    /// Creates a `StructureMapping` with a single structure name and the default
    /// markup behaviour.
    pub fn new(structure_name: impl Into<String>) -> Self {
        Self { structure_names: vec![structure_name.into()], markup_func: None }
    }

    /// Creates a `StructureMapping` from an iterator of structure names (primary +
    /// alternates) with the default markup behaviour.
    ///
    /// The first name in the iterator is treated as the primary name.
    pub fn with_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            structure_names: names.into_iter().map(Into::into).collect(),
            markup_func: None,
        }
    }

    /// Returns the primary structure name, i.e. the first entry in
    /// [`structure_names`](Self::structure_names).
    ///
    /// Returns `None` only when `structure_names` is empty, which should not happen
    /// in valid usage.
    pub fn primary_name(&self) -> Option<&str> {
        self.structure_names.first().map(String::as_str)
    }

    /// Returns all structure names (primary + alternates).
    pub fn names(&self) -> &[String] {
        &self.structure_names
    }

    /// Returns `true` when a custom `StructureMarkupFunction` has been specified.
    pub fn has_custom_markup(&self) -> bool {
        self.markup_func.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::StructureMapping;

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_sets_single_name_and_no_markup_func() {
        let m = StructureMapping::new("GoSliceHeader");
        assert_eq!(m.structure_names, vec!["GoSliceHeader"]);
        assert_eq!(m.markup_func, None);
        assert!(!m.has_custom_markup());
    }

    #[test]
    fn with_names_collects_all_names() {
        let m = StructureMapping::with_names(["GoSlice", "go_slice", "GoSliceHeader"]);
        assert_eq!(m.structure_names.len(), 3);
        assert_eq!(m.structure_names[0], "GoSlice");
        assert_eq!(m.structure_names[1], "go_slice");
        assert_eq!(m.structure_names[2], "GoSliceHeader");
        assert_eq!(m.markup_func, None);
    }

    #[test]
    fn with_names_single_element_matches_new() {
        let a = StructureMapping::new("GoString");
        let b = StructureMapping::with_names(["GoString"]);
        assert_eq!(a, b);
    }

    // ── primary_name ─────────────────────────────────────────────────────────

    #[test]
    fn primary_name_returns_first_name() {
        let m = StructureMapping::with_names(["Primary", "Alternate"]);
        assert_eq!(m.primary_name(), Some("Primary"));
    }

    #[test]
    fn primary_name_returns_none_for_empty_names() {
        let m = StructureMapping { structure_names: vec![], markup_func: None };
        assert_eq!(m.primary_name(), None);
    }

    #[test]
    fn names_slice_matches_structure_names() {
        let m = StructureMapping::with_names(["A", "B"]);
        assert_eq!(m.names(), m.structure_names.as_slice());
    }

    // ── markup_func ───────────────────────────────────────────────────────────

    #[test]
    fn no_custom_markup_by_default() {
        let m = StructureMapping::new("GoHMap");
        assert!(!m.has_custom_markup());
        assert_eq!(m.markup_func, None);
    }

    #[test]
    fn custom_markup_func_can_be_set() {
        let m = StructureMapping {
            structure_names: vec!["GoHMap".to_string()],
            markup_func: Some(
                "ghidra.app.util.bin.format.golang.GoHMapMarkup".to_string(),
            ),
        };
        assert!(m.has_custom_markup());
        assert_eq!(
            m.markup_func.as_deref(),
            Some("ghidra.app.util.bin.format.golang.GoHMapMarkup")
        );
    }

    // ── equality, clone ────────────────────────────────────────────────────────

    #[test]
    fn clone_and_eq_work() {
        let a = StructureMapping {
            structure_names: vec!["GoString".to_string(), "go_string".to_string()],
            markup_func: Some("some.MarkupFn".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn different_names_are_not_equal() {
        let a = StructureMapping::new("GoString");
        let b = StructureMapping::new("GoSlice");
        assert_ne!(a, b);
    }

    #[test]
    fn different_markup_func_is_not_equal() {
        let a = StructureMapping::new("GoString");
        let b = StructureMapping {
            structure_names: vec!["GoString".to_string()],
            markup_func: Some("custom.Fn".to_string()),
        };
        assert_ne!(a, b);
    }

    // ── multiple alternates ──────────────────────────────────────────────────

    #[test]
    fn alternates_allow_case_insensitive_lookup_simulation() {
        let m = StructureMapping::with_names(["GoItab", "go_itab", "Goitab"]);
        let query = "go_itab";
        let found = m.names().iter().any(|n| n.eq_ignore_ascii_case(query));
        assert!(found);
    }
}
