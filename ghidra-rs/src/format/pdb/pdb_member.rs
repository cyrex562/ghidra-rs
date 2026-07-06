use crate::format::pdb::wrapped_data_type::WrappedDataType;
use crate::util::exception::CancelledException;

/// Conveys PDB member information used for datatype reconstruction.
///
/// Port of `ghidra.app.util.bin.format.pdb.PdbMember`. Implementors supply the member's
/// name, datatype name, offset, and optional comment, plus how to resolve the member's
/// associated [`WrappedDataType`] ([`data_type`](Self::data_type)); this trait supplies the
/// shared display behavior on top.
pub trait PdbMember {
    /// Returns the member's name, which will correspond to the field name.
    fn name(&self) -> &str;

    /// Returns the member's datatype name (may be namespace qualified).
    fn data_type_name(&self) -> &str;

    /// Returns the member's byte offset within the root composite.
    fn offset(&self) -> i32;

    /// Returns the optional member comment.
    fn comment(&self) -> Option<&str>;

    /// Returns this member's associated data type, which has already been cloned for the
    /// target program's data type manager. This indicates a dependency callback and may be
    /// used to trigger resolution for composites. When resolving dependencies, care must be
    /// taken to avoid circular dependencies which could occur under certain error conditions.
    ///
    /// Returns the data type which corresponds to the member's data-type name, or `None` if
    /// unable to resolve.
    fn data_type(&self) -> Result<Option<WrappedDataType>, CancelledException>;

    /// Renders this member as `name=..., type=..., offset=...`, mirroring Java's `toString`.
    fn to_display_string(&self) -> String {
        format!(
            "name={}, type={}, offset={}",
            self.name(),
            self.data_type_name(),
            self.offset()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;

    struct StubDataType {
        name: &'static str,
    }

    impl DataType for StubDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
    }

    struct TestMember {
        name: String,
        data_type_name: String,
        offset: i32,
        comment: Option<String>,
        resolvable: bool,
    }

    impl TestMember {
        fn new(name: &str, data_type_name: &str, offset: i32, comment: Option<&str>) -> Self {
            Self {
                name: name.to_string(),
                data_type_name: data_type_name.to_string(),
                offset,
                comment: comment.map(str::to_string),
                resolvable: true,
            }
        }
    }

    impl PdbMember for TestMember {
        fn name(&self) -> &str {
            &self.name
        }

        fn data_type_name(&self) -> &str {
            &self.data_type_name
        }

        fn offset(&self) -> i32 {
            self.offset
        }

        fn comment(&self) -> Option<&str> {
            self.comment.as_deref()
        }

        fn data_type(&self) -> Result<Option<WrappedDataType>, CancelledException> {
            if self.resolvable {
                Ok(Some(WrappedDataType::new(
                    Box::new(StubDataType { name: "int" }),
                    false,
                    false,
                )))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn accessors_return_constructor_values() {
        let m = TestMember::new("field1", "int", 4, Some("a comment"));
        assert_eq!(m.name(), "field1");
        assert_eq!(m.data_type_name(), "int");
        assert_eq!(m.offset(), 4);
        assert_eq!(m.comment(), Some("a comment"));
    }

    #[test]
    fn comment_defaults_to_none() {
        let m = TestMember::new("field2", "char", 0, None);
        assert_eq!(m.comment(), None);
    }

    #[test]
    fn to_display_string_matches_java_format() {
        let m = TestMember::new("field1", "int", 8, None);
        assert_eq!(m.to_display_string(), "name=field1, type=int, offset=8");
    }

    #[test]
    fn data_type_resolves_when_resolvable() {
        let m = TestMember::new("field1", "int", 0, None);
        let resolved = m.data_type().unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().data_type().get_name(), "int");
    }

    #[test]
    fn data_type_returns_none_when_unresolvable() {
        let mut m = TestMember::new("field1", "Unknown", 0, None);
        m.resolvable = false;
        let resolved = m.data_type().unwrap();
        assert!(resolved.is_none());
    }
}
