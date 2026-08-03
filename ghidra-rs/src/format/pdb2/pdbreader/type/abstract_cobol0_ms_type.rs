use crate::format::pdb2::pdbreader::r#type::ms_type::MsType;
use crate::format::seam_stubs::{AbstractMsType, AbstractPdb, Bind, RecordNumber};

/// Trait for the various flavors of Cobol0 type.
///
/// Corresponds to the Java abstract class
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractCobol0MsType`.
///
/// Note: we do not necessarily understand each of these data type classes. Refer to the
/// base class for more information.
pub trait AbstractCobol0MsType: MsType {
    /// Returns the record number of the type that is pointed to.
    fn parent_record_number(&self) -> RecordNumber;

    /// Returns the additional (not-yet-understood) data trailing the parent record number.
    fn data(&self) -> &[u8];

    /// Returns the type that is pointed to.
    fn parent_type(&self, pdb: &dyn AbstractPdb) -> Box<dyn AbstractMsType> {
        pdb.get_type_record(self.parent_record_number())
    }

    /// Emits string output of this class into `builder`.
    ///
    /// `bind` is accepted for signature fidelity with the Java override but, matching the Java
    /// implementation, is not consulted: Cobol0 output never needs surrounding parentheses.
    fn emit(&self, builder: &mut String, _bind: Bind, pdb: &dyn AbstractPdb) {
        builder.push_str("Cobol0MsType\n");
        builder.push_str(&format!(
            "  parent type index: {}\n",
            self.parent_type(pdb).to_display_string()
        ));
        builder.push_str(&format!("  additional data length: {}\n", self.data().len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
    use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;
    use crate::format::seam_stubs::PdbReaderOptions;
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset;

    struct MockParentType;
    impl AbstractParsableItem for MockParentType {
        fn emit(&self, builder: &mut String) {
            builder.push_str("ParentType");
        }
    }
    impl AbstractMsType for MockParentType {}

    struct MockPdb {
        options: PdbReaderOptions,
    }
    impl AbstractPdb for MockPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            &self.options
        }

        fn get_type_record(&self, _record_number: RecordNumber) -> Box<dyn AbstractMsType> {
            Box::new(MockParentType)
        }
    }

    struct MockCobol0MsType {
        parent_record_number: RecordNumber,
        data: Vec<u8>,
    }
    impl IdMsParsable for MockCobol0MsType {
        fn pdb_id(&self) -> i32 {
            0x100a
        }
    }
    impl MsType for MockCobol0MsType {}
    impl AbstractCobol0MsType for MockCobol0MsType {
        fn parent_record_number(&self) -> RecordNumber {
            self.parent_record_number
        }

        fn data(&self) -> &[u8] {
            &self.data
        }
    }

    fn mock_pdb() -> MockPdb {
        MockPdb {
            options: PdbReaderOptions {
                one_byte_charset: PdbCharset::OneByte,
                two_byte_charset: PdbCharset::Utf16Le,
            },
        }
    }

    #[test]
    fn parent_type_resolves_via_pdb() {
        let t = MockCobol0MsType { parent_record_number: RecordNumber { number: 42 }, data: vec![] };
        let pdb = mock_pdb();
        assert_eq!(t.parent_type(&pdb).to_display_string(), "ParentType");
    }

    #[test]
    fn emit_matches_java_format() {
        let t = MockCobol0MsType {
            parent_record_number: RecordNumber { number: 42 },
            data: vec![1, 2, 3],
        };
        let pdb = mock_pdb();
        let mut builder = String::new();
        t.emit(&mut builder, Bind::None, &pdb);
        assert_eq!(
            builder,
            "Cobol0MsType\n  parent type index: ParentType\n  additional data length: 3\n"
        );
    }

    #[test]
    fn is_object_safe() {
        let t: Box<dyn AbstractCobol0MsType> =
            Box::new(MockCobol0MsType { parent_record_number: RecordNumber::no_type(), data: vec![] });
        assert_eq!(t.pdb_id(), 0x100a);
        assert_eq!(t.parent_record_number(), RecordNumber::no_type());
    }
}
