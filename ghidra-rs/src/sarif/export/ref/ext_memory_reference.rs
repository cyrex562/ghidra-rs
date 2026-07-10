use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::Reference;

/// Represents memory reference metadata extracted from a [`Reference`] for SARIF export.
///
/// Mirrors `ExtMemoryReference` from Ghidra's `sarif.export.ref` package.
/// Captures essential metadata from a memory reference, including the destination address,
/// and optional base address and offset for offset references.
pub struct ExtMemoryReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
    pub to: String,
    pub base: Option<String>,
    pub offset: Option<i64>,
    pub primary: bool,
}

impl ExtMemoryReference {
    /// Creates a new `ExtMemoryReference` from a [`Reference`].
    ///
    /// Extracts reference type value, name, operand index, source type, destination address,
    /// primary flag, and optionally base address and offset if the reference is an offset reference.
    pub fn new(reference: &dyn Reference) -> Self {
        let reference_type = reference.reference_type();
        let index = (reference_type.value() as u8).to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();
        let to = reference.to_address().to_string();
        let primary = reference.is_primary();

        let (base, offset) = (None, None);

        Self {
            index,
            kind,
            op_index,
            source_type,
            to,
            base,
            offset,
            primary,
        }
    }
}

impl IsfObject for ExtMemoryReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{OffsetReference, RefType, SourceType};

    struct MockMemoryReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        to_address: Address,
        is_primary: bool,
    }

    impl Reference for MockMemoryReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            Address::default()
        }

        fn to_address(&self) -> Address {
            self.to_address.clone()
        }

        fn is_primary(&self) -> bool {
            self.is_primary
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
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }
    }

    struct MockOffsetMemoryReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        to_address: Address,
        is_primary: bool,
        base_address: Address,
        offset_value: i64,
    }

    impl Reference for MockOffsetMemoryReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            Address::default()
        }

        fn to_address(&self) -> Address {
            self.to_address.clone()
        }

        fn is_primary(&self) -> bool {
            self.is_primary
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
            true
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }
    }

    impl OffsetReference for MockOffsetMemoryReference {
        fn offset(&self) -> i64 {
            self.offset_value
        }

        fn base_address(&self) -> Address {
            self.base_address.clone()
        }
    }

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn extracts_index_from_reference_type_value() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr(0x1000),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
    }

    #[test]
    fn extracts_kind_from_reference_type_name() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 1,
            source: SourceType::Default,
            to_address: test_addr(0x2000),
            is_primary: true,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
    }

    #[test]
    fn extracts_operand_index() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 3,
            source: SourceType::Default,
            to_address: test_addr(0x3000),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, 3);
    }

    #[test]
    fn extracts_to_address() {
        let test_addr_val = test_addr(0x4000);
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr_val.clone(),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.to, test_addr_val.to_string());
    }

    #[test]
    fn extracts_primary_flag_true() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr(0x5000),
            is_primary: true,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert!(ext_ref.primary);
    }

    #[test]
    fn extracts_primary_flag_false() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr(0x6000),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert!(!ext_ref.primary);
    }

    #[test]
    fn base_and_offset_none_for_non_offset_reference() {
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr(0x7000),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert!(ext_ref.base.is_none());
        assert!(ext_ref.offset.is_none());
    }

    #[test]
    fn base_and_offset_some_for_offset_reference() {
        let base = test_addr(0x1000);
        let to = test_addr(0x1100);
        let mock_ref = MockOffsetMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: to.clone(),
            is_primary: false,
            base_address: base.clone(),
            offset_value: 0x100,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.base, Some(base.to_string()));
        assert_eq!(ext_ref.offset, Some(0x100));
    }

    #[test]
    fn handles_zero_offset() {
        let base = test_addr(0x2000);
        let to = test_addr(0x2000);
        let mock_ref = MockOffsetMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: to,
            is_primary: false,
            base_address: base.clone(),
            offset_value: 0,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, Some(0));
    }

    #[test]
    fn handles_negative_offset() {
        let base = test_addr(0x3000);
        let to = test_addr(0x2ff0);
        let mock_ref = MockOffsetMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: to,
            is_primary: false,
            base_address: base.clone(),
            offset_value: -0x10,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, Some(-0x10));
    }

    #[test]
    fn handles_large_offset() {
        let base = test_addr(0x10000000);
        let to = test_addr(0x20000000);
        let mock_ref = MockOffsetMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: to,
            is_primary: false,
            base_address: base.clone(),
            offset_value: 0x10000000,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
        assert_eq!(ext_ref.offset, Some(0x10000000));
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
            let mock_ref = MockMemoryReference {
                ref_type: RefType::Data,
                operand_index: 0,
                source,
                to_address: test_addr(0x8000),
                is_primary: false,
            };
            let ext_ref = ExtMemoryReference::new(&mock_ref);
            assert_eq!(ext_ref.source_type, source.display_string());
        }
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let mock_ref = MockMemoryReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: test_addr(0x9000),
            is_primary: false,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);
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
            let mock_ref = MockMemoryReference {
                ref_type,
                operand_index: 0,
                source: SourceType::Default,
                to_address: test_addr(0xa000),
                is_primary: false,
            };
            let ext_ref = ExtMemoryReference::new(&mock_ref);
            assert_eq!(ext_ref.kind, ref_type.name());
            assert_eq!(ext_ref.index, ref_type.value().to_string());
        }
    }

    #[test]
    fn preserves_all_fields_with_various_values() {
        let base = test_addr(0x5000);
        let to = test_addr(0x5200);
        let mock_ref = MockOffsetMemoryReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 2,
            source: SourceType::UserDefined,
            to_address: to.clone(),
            is_primary: true,
            base_address: base.clone(),
            offset_value: 0x200,
        };
        let ext_ref = ExtMemoryReference::new(&mock_ref);

        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
        assert_eq!(ext_ref.index, RefType::UnconditionalCall.value().to_string());
        assert_eq!(ext_ref.op_index, 2);
        assert_eq!(ext_ref.source_type, SourceType::UserDefined.display_string());
        assert_eq!(ext_ref.to, to.to_string());
        assert_eq!(ext_ref.base, Some(base.to_string()));
        assert_eq!(ext_ref.offset, Some(0x200));
        assert!(ext_ref.primary);
    }
}
