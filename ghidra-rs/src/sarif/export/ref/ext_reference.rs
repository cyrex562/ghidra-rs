use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::Reference;

/// Represents reference metadata extracted from a [`Reference`] for SARIF export.
///
/// Mirrors `ExtReference` from Ghidra's `sarif.export.ref` package.
/// This abstract base class captures the essential metadata from a reference.
pub struct ExtReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
}

impl ExtReference {
    /// Creates a new `ExtReference` from a [`Reference`].
    ///
    /// Extracts reference type value, name, operand index, and source type
    /// from the given reference and stores them as strings.
    pub fn new(reference: &dyn Reference) -> Self {
        let reference_type = reference.reference_type();
        let index = (reference_type.value() as u8).to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();

        Self {
            index,
            kind,
            op_index,
            source_type,
        }
    }
}

impl IsfObject for ExtReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{RefType, SourceType};

    struct MockReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
    }

    impl Reference for MockReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            Address::default()
        }

        fn to_address(&self) -> Address {
            Address::default()
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            self.ref_type
        }

        fn operand_index(&self) -> i32 {
            self.operand_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            self.operand_index == RefType::MNEMONIC
        }

        fn is_operand_reference(&self) -> bool {
            self.operand_index >= 0
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            false
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }
    }

    #[test]
    fn extracts_index_from_reference_type_value() {
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
        };
        let ext_ref = ExtReference::new(&mock_ref);
        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
    }

    #[test]
    fn extracts_kind_from_reference_type_name() {
        let mock_ref = MockReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 1,
            source: SourceType::Default,
        };
        let ext_ref = ExtReference::new(&mock_ref);
        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
    }

    #[test]
    fn extracts_operand_index() {
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: 2,
            source: SourceType::Default,
        };
        let ext_ref = ExtReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, 2);
    }

    #[test]
    fn extracts_negative_operand_index() {
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: -1,
            source: SourceType::Default,
        };
        let ext_ref = ExtReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, -1);
    }

    #[test]
    fn extracts_source_type_as_display_string() {
        let source_types = vec![
            SourceType::Default,
            SourceType::Analysis,
            SourceType::Imported,
            SourceType::UserDefined,
            SourceType::AI,
        ];

        for source in source_types {
            let mock_ref = MockReference {
                ref_type: RefType::Data,
                operand_index: 0,
                source,
            };
            let ext_ref = ExtReference::new(&mock_ref);
            assert_eq!(ext_ref.source_type, source.display_string());
        }
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
        };
        let ext_ref = ExtReference::new(&mock_ref);
        accepts_isf_object(&ext_ref);
    }

    #[test]
    fn handles_different_reference_types() {
        let test_cases = vec![
            RefType::Flow,
            RefType::Data,
            RefType::Read,
            RefType::Write,
            RefType::UnconditionalCall,
            RefType::ConditionalJump,
        ];

        for ref_type in test_cases {
            let mock_ref = MockReference {
                ref_type,
                operand_index: 0,
                source: SourceType::Default,
            };
            let ext_ref = ExtReference::new(&mock_ref);
            assert_eq!(ext_ref.kind, ref_type.name());
            assert_eq!(ext_ref.index, ref_type.value().to_string());
        }
    }
}
