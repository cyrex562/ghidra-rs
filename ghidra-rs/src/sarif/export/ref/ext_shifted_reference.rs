use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::ShiftedReference;

/// Represents shifted reference metadata extracted from a [`ShiftedReference`] for SARIF export.
///
/// Mirrors `ExtShiftedReference` from Ghidra's `sarif.export.ref` package.
/// Captures essential metadata from a shifted reference, including the shift amount
/// and base value used to compute the destination address.
pub struct ExtShiftedReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
    pub shift: i32,
    pub value: i64,
}

impl ExtShiftedReference {
    /// Creates a new `ExtShiftedReference` from a [`ShiftedReference`].
    ///
    /// Extracts reference type value, name, operand index, source type,
    /// shift amount, and base value from the given reference.
    pub fn new(reference: &dyn ShiftedReference) -> Self {
        let reference_type = reference.reference_type();
        let index = (reference_type.value() as u8).to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();
        let shift = reference.shift();
        let value = reference.value();

        Self {
            index,
            kind,
            op_index,
            source_type,
            shift,
            value,
        }
    }
}

impl IsfObject for ExtShiftedReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::symbol::{RefType, SourceType};

    struct MockShiftedReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        shift: i32,
        value: i64,
    }

    impl ShiftedReference for MockShiftedReference {
        fn shift(&self) -> i32 {
            self.shift
        }

        fn value(&self) -> i64 {
            self.value
        }
    }

    impl crate::program::model::symbol::Reference for MockShiftedReference {
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
            true
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            true
        }

        fn source(&self) -> SourceType {
            self.source
        }
    }

    #[test]
    fn extracts_index_from_reference_type_value() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 2,
            value: 0x100,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
    }

    #[test]
    fn extracts_kind_from_reference_type_name() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Read,
            operand_index: 1,
            source: SourceType::Default,
            shift: 4,
            value: 0x200,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.kind, RefType::Read.name());
    }

    #[test]
    fn extracts_operand_index() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Write,
            operand_index: 3,
            source: SourceType::Default,
            shift: 1,
            value: 0x300,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, 3);
    }

    #[test]
    fn extracts_shift_amount() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 8,
            value: 0x400,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.shift, 8);
    }

    #[test]
    fn extracts_value() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 3,
            value: 0xdeadbeef,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.value, 0xdeadbeef);
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
            let mock_ref = MockShiftedReference {
                ref_type: RefType::Data,
                operand_index: 0,
                source,
                shift: 2,
                value: 0x500,
            };
            let ext_ref = ExtShiftedReference::new(&mock_ref);
            assert_eq!(ext_ref.source_type, source.display_string());
        }
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 2,
            value: 0x600,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
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
            let mock_ref = MockShiftedReference {
                ref_type,
                operand_index: 0,
                source: SourceType::Default,
                shift: 2,
                value: 0x700,
            };
            let ext_ref = ExtShiftedReference::new(&mock_ref);
            assert_eq!(ext_ref.kind, ref_type.name());
            assert_eq!(ext_ref.index, ref_type.value().to_string());
        }
    }

    #[test]
    fn handles_zero_shift() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 0,
            value: 0x800,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.shift, 0);
        assert_eq!(ext_ref.value, 0x800);
    }

    #[test]
    fn handles_large_shift() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 31,
            value: 1,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.shift, 31);
        assert_eq!(ext_ref.value, 1);
    }

    #[test]
    fn handles_large_value() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            shift: 3,
            value: i64::MAX,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);
        assert_eq!(ext_ref.value, i64::MAX);
    }

    #[test]
    fn preserves_all_fields_with_various_values() {
        let mock_ref = MockShiftedReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 2,
            source: SourceType::UserDefined,
            shift: 5,
            value: 0x12345678,
        };
        let ext_ref = ExtShiftedReference::new(&mock_ref);

        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
        assert_eq!(ext_ref.index, RefType::UnconditionalCall.value().to_string());
        assert_eq!(ext_ref.op_index, 2);
        assert_eq!(ext_ref.source_type, SourceType::UserDefined.display_string());
        assert_eq!(ext_ref.shift, 5);
        assert_eq!(ext_ref.value, 0x12345678);
    }
}
