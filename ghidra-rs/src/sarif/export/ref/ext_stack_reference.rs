use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::StackReference;

/// Represents stack reference metadata extracted from a [`StackReference`] for SARIF export.
///
/// Mirrors `ExtStackReference` from Ghidra's `sarif.export.ref` package.
/// Captures essential metadata from a stack reference, including the stack offset
/// where the reference points.
pub struct ExtStackReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
    pub offset: i32,
}

impl ExtStackReference {
    /// Creates a new `ExtStackReference` from a [`StackReference`].
    ///
    /// Extracts reference type value, name, operand index, source type, and stack offset
    /// from the given stack reference.
    pub fn new(reference: &dyn StackReference) -> Self {
        let reference_type = reference.reference_type();
        let index = (reference_type.value() as u8).to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();
        let offset = reference.stack_offset();

        Self {
            index,
            kind,
            op_index,
            source_type,
            offset,
        }
    }
}

impl IsfObject for ExtStackReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::symbol::{RefType, SourceType};

    struct MockStackReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        stack_offset: i32,
    }

    impl StackReference for MockStackReference {
        fn stack_offset(&self) -> i32 {
            self.stack_offset
        }
    }

    impl crate::program::model::symbol::Reference for MockStackReference {
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
            true
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
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            stack_offset: -0x10,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
    }

    #[test]
    fn extracts_kind_from_reference_type_name() {
        let mock_ref = MockStackReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 1,
            source: SourceType::Default,
            stack_offset: -0x20,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
    }

    #[test]
    fn extracts_operand_index() {
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 2,
            source: SourceType::Default,
            stack_offset: -0x30,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, 2);
    }

    #[test]
    fn extracts_stack_offset() {
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            stack_offset: -0x10,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, -0x10);
    }

    #[test]
    fn extracts_positive_stack_offset() {
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            stack_offset: 0x100,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, 0x100);
    }

    #[test]
    fn extracts_zero_stack_offset() {
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            stack_offset: 0,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, 0);
    }

    #[test]
    fn extracts_source_type() {
        let source_types = vec![
            SourceType::Default,
            SourceType::Analysis,
            SourceType::Imported,
            SourceType::UserDefined,
            SourceType::AI,
        ];

        for source in source_types {
            let mock_ref = MockStackReference {
                ref_type: RefType::Data,
                operand_index: 0,
                source,
                stack_offset: -0x08,
            };
            let ext_ref = ExtStackReference::new(&mock_ref);
            assert_eq!(ext_ref.source_type, source.display_string());
        }
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let mock_ref = MockStackReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            stack_offset: -0x04,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);
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
            let mock_ref = MockStackReference {
                ref_type,
                operand_index: 0,
                source: SourceType::Default,
                stack_offset: -0x20,
            };
            let ext_ref = ExtStackReference::new(&mock_ref);
            assert_eq!(ext_ref.kind, ref_type.name());
            assert_eq!(ext_ref.index, ref_type.value().to_string());
        }
    }

    #[test]
    fn preserves_all_fields_with_various_values() {
        let mock_ref = MockStackReference {
            ref_type: RefType::Read,
            operand_index: 3,
            source: SourceType::UserDefined,
            stack_offset: -0xdeadbeef,
        };
        let ext_ref = ExtStackReference::new(&mock_ref);

        assert_eq!(ext_ref.kind, RefType::Read.name());
        assert_eq!(ext_ref.index, RefType::Read.value().to_string());
        assert_eq!(ext_ref.op_index, 3);
        assert_eq!(ext_ref.source_type, SourceType::UserDefined.display_string());
        assert_eq!(ext_ref.offset, -0xdeadbeef);
    }
}
