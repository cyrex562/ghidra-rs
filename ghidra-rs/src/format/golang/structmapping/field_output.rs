/// Metadata marking a Rust struct field for inclusion when a variable-length Ghidra structure data
/// type is constructed.
///
/// This is the Rust equivalent of the Java `@FieldOutput` annotation from
/// `ghidra.app.util.bin.format.golang.structmapping`. As with [`FieldMapping`](super::FieldMapping),
/// Rust has no field annotations, so the annotation's elements are carried as a plain struct stored
/// alongside the field's descriptor.
///
/// A structure with any `FieldOutput` field has variable-length fields, and its type must
/// implement [`StructureReader`](super::StructureReader) to deserialise itself.
///
/// Optional elements whose Java default is a sentinel (`-1`, `""`, or the
/// `FieldOutputFunction.class` interface itself) are `None` here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldOutput {
    /// Fully-qualified class name of a `FieldOutputFunction` implementation that overrides the
    /// default logic used to add the field to the structure, or `None` for the default logic
    /// (Java: `fieldOutputFunc = FieldOutputFunction.class`).
    pub field_output_func: Option<String>,

    /// Ordinal of the field in the structure being created. `None` (Java `-1`) keeps the declared
    /// field order.
    pub ordinal: Option<i32>,

    /// Offset to add the field at; the structure is padded up to it, and a structure already
    /// larger than it is an error. `None` (Java `-1`) uses the next location in the structure.
    pub offset: Option<i32>,

    /// Name of the Ghidra data type to use for the field. `None` (Java `""`) picks a data type from
    /// the Rust field's type.
    pub data_type_name: Option<String>,

    /// Marks the field as variable length, which gives the containing structure a `_NN` name
    /// suffix recording this instance's length.
    pub is_variable_length: bool,

    /// Name of a getter returning the Ghidra data type to use for the field, or `None` (Java `""`).
    pub getter: Option<String>,
}

impl FieldOutput {
    /// Creates a `FieldOutput` with every element at the Java annotation's default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a `FieldOutput` from the raw Java annotation element values, mapping the `-1` and
    /// empty-string sentinels to `None`.
    pub fn from_java_values(
        field_output_func: Option<String>,
        ordinal: i32,
        offset: i32,
        data_type_name: &str,
        is_variable_length: bool,
        getter: &str,
    ) -> Self {
        let non_negative = |v: i32| (v != -1).then_some(v);
        let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
        Self {
            field_output_func,
            ordinal: non_negative(ordinal),
            offset: non_negative(offset),
            data_type_name: non_empty(data_type_name),
            is_variable_length,
            getter: non_empty(getter),
        }
    }

    /// Returns the ordinal as Java reports it: `-1` when unset.
    pub fn java_ordinal(&self) -> i32 {
        self.ordinal.unwrap_or(-1)
    }

    /// Returns the offset as Java reports it: `-1` when unset.
    pub fn java_offset(&self) -> i32 {
        self.offset.unwrap_or(-1)
    }
}

#[cfg(test)]
mod tests {
    use super::FieldOutput;

    #[test]
    fn defaults_match_java_annotation_defaults() {
        let f = FieldOutput::new();
        assert_eq!(f.field_output_func, None);
        assert_eq!(f.java_ordinal(), -1);
        assert_eq!(f.java_offset(), -1);
        assert_eq!(f.data_type_name, None);
        assert!(!f.is_variable_length);
        assert_eq!(f.getter, None);
    }

    #[test]
    fn from_java_values_maps_sentinels_to_none() {
        assert_eq!(FieldOutput::from_java_values(None, -1, -1, "", false, ""), FieldOutput::new());
    }

    #[test]
    fn from_java_values_keeps_set_elements() {
        let f = FieldOutput::from_java_values(
            Some("ghidra.app.util.bin.format.golang.rtti.GoVarlenString".to_string()),
            2,
            0,
            "uint8",
            true,
            "getDataType",
        );
        assert_eq!(f.ordinal, Some(2));
        // offset 0 is a real offset, not the -1 sentinel
        assert_eq!(f.offset, Some(0));
        assert_eq!(f.java_offset(), 0);
        assert_eq!(f.data_type_name.as_deref(), Some("uint8"));
        assert!(f.is_variable_length);
        assert_eq!(f.getter.as_deref(), Some("getDataType"));
        assert!(f.field_output_func.unwrap().ends_with("GoVarlenString"));
    }
}
