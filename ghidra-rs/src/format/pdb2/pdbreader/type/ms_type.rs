use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;
use crate::format::seam_stubs::RecordNumber;

/// Trait for PDB type items.
///
/// Corresponds to the Java interface
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.MsType`.
pub trait MsType: IdMsParsable {
    /// If the type has a name element, returns this name; else returns an empty string.
    fn name(&self) -> String {
        String::new()
    }

    /// Returns the record number of this type.
    fn record_number(&self) -> RecordNumber {
        RecordNumber::no_type()
    }

    /// Returns the size of the datatype.
    fn size(&self) -> i128 {
        0
    }

    /// Returns the size of the datatype.
    fn length(&self) -> i64 {
        i64::try_from(self.size()).expect("size does not fit in i64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockType;
    impl IdMsParsable for MockType {
        fn pdb_id(&self) -> i32 {
            0x1234
        }
    }
    impl MsType for MockType {}

    struct NamedType;
    impl IdMsParsable for NamedType {
        fn pdb_id(&self) -> i32 {
            0x5678
        }
    }
    impl MsType for NamedType {
        fn name(&self) -> String {
            "Foo".to_string()
        }

        fn size(&self) -> i128 {
            42
        }
    }

    #[test]
    fn defaults_match_java_defaults() {
        let t = MockType;
        assert_eq!(t.name(), "");
        assert_eq!(t.record_number(), RecordNumber::no_type());
        assert_eq!(t.size(), 0);
        assert_eq!(t.length(), 0);
    }

    #[test]
    fn overrides_apply() {
        let t = NamedType;
        assert_eq!(t.name(), "Foo");
        assert_eq!(t.size(), 42);
        assert_eq!(t.length(), 42);
    }

    #[test]
    fn is_object_safe() {
        let boxed: Box<dyn MsType> = Box::new(MockType);
        assert_eq!(boxed.pdb_id(), 0x1234);
    }
}
