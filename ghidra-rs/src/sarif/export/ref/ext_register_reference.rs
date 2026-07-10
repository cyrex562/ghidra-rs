use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::Reference;

/// Represents register reference metadata extracted from a [`Reference`] for SARIF export.
///
/// Mirrors `ExtRegisterReference` from Ghidra's `sarif.export.ref` package.
/// Captures essential metadata from a register reference, including the target address
/// and whether it is the primary reference.
pub struct ExtRegisterReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
    pub to: String,
    pub primary: bool,
}

impl ExtRegisterReference {
    /// Creates a new `ExtRegisterReference` from a [`Reference`].
    ///
    /// Extracts reference type value, name, operand index, source type, target address,
    /// and primary status from the given reference.
    pub fn new(reference: &dyn Reference) -> Self {
        let reference_type = reference.reference_type();
        let index = reference_type.value().to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();
        let to = reference.to_address().to_string();
        let primary = reference.is_primary();

        Self {
            index,
            kind,
            op_index,
            source_type,
            to,
            primary,
        }
    }
}

impl IsfObject for ExtRegisterReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{RefType, SourceType};

    fn default_space() -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    struct MockReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        to_address: Address,
        is_primary: bool,
    }

    impl Reference for MockReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            Address::new(default_space(), 0)
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
            to_address: Address::new(default_space(), 0x1000),
            is_primary: false,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);
        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
    }

    #[test]
    fn extracts_kind_from_reference_type_name() {
        let mock_ref = MockReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 1,
            source: SourceType::Default,
            to_address: Address::new(default_space(), 0x2000),
            is_primary: false,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);
        assert_eq!(ext_ref.kind, RefType::UnconditionalCall.name());
    }

    #[test]
    fn extracts_operand_index() {
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: 2,
            source: SourceType::Default,
            to_address: Address::new(default_space(), 0x3000),
            is_primary: false,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);
        assert_eq!(ext_ref.op_index, 2);
    }

    #[test]
    fn extracts_to_address() {
        let to_addr = Address::new(default_space(), 0x4000);
        let mock_ref = MockReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: to_addr.clone(),
            is_primary: false,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);
        assert_eq!(ext_ref.to, to_addr.to_string());
    }

    #[test]
    fn extracts_primary_status() {
        let mock_ref_primary = MockReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: Address::new(default_space(), 0x5000),
            is_primary: true,
        };
        let ext_ref_primary = ExtRegisterReference::new(&mock_ref_primary);
        assert!(ext_ref_primary.primary);

        let mock_ref_secondary = MockReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            to_address: Address::new(default_space(), 0x6000),
            is_primary: false,
        };
        let ext_ref_secondary = ExtRegisterReference::new(&mock_ref_secondary);
        assert!(!ext_ref_secondary.primary);
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
            let mock_ref = MockReference {
                ref_type: RefType::Data,
                operand_index: 0,
                source,
                to_address: Address::new(default_space(), 0x7000),
                is_primary: false,
            };
            let ext_ref = ExtRegisterReference::new(&mock_ref);
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
            to_address: Address::new(default_space(), 0x8000),
            is_primary: false,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);
        accepts_isf_object(&ext_ref);
    }

    #[test]
    fn handles_multiple_reference_types() {
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
                to_address: Address::new(default_space(), 0x9000),
                is_primary: false,
            };
            let ext_ref = ExtRegisterReference::new(&mock_ref);
            assert_eq!(ext_ref.kind, ref_type.name());
            assert_eq!(ext_ref.index, ref_type.value().to_string());
        }
    }

    #[test]
    fn preserves_all_fields_with_various_values() {
        let to_addr = Address::new(default_space(), 0xdeadbeef);
        let mock_ref = MockReference {
            ref_type: RefType::Read,
            operand_index: 3,
            source: SourceType::UserDefined,
            to_address: to_addr.clone(),
            is_primary: true,
        };
        let ext_ref = ExtRegisterReference::new(&mock_ref);

        assert_eq!(ext_ref.kind, RefType::Read.name());
        assert_eq!(ext_ref.index, RefType::Read.value().to_string());
        assert_eq!(ext_ref.op_index, 3);
        assert_eq!(ext_ref.source_type, SourceType::UserDefined.display_string());
        assert_eq!(ext_ref.to, to_addr.to_string());
        assert!(ext_ref.primary);
    }
}
