/// An enum for the different types that are represented by unique colors by the
/// AddressTypeOverviewColorService
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    Function,
    Uninitialized,
    ExternalRef,
    Instruction,
    Data,
    Undefined,
}

impl AddressType {
    /// Returns a description of this enum value.
    pub fn description(&self) -> &'static str {
        match self {
            AddressType::Function => "Function",
            AddressType::Uninitialized => "Uninitialized",
            AddressType::ExternalRef => "External Reference",
            AddressType::Instruction => "Instruction",
            AddressType::Data => "Data",
            AddressType::Undefined => "Undefined",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_description() {
        assert_eq!(AddressType::Function.description(), "Function");
    }

    #[test]
    fn test_uninitialized_description() {
        assert_eq!(AddressType::Uninitialized.description(), "Uninitialized");
    }

    #[test]
    fn test_external_ref_description() {
        assert_eq!(AddressType::ExternalRef.description(), "External Reference");
    }

    #[test]
    fn test_instruction_description() {
        assert_eq!(AddressType::Instruction.description(), "Instruction");
    }

    #[test]
    fn test_data_description() {
        assert_eq!(AddressType::Data.description(), "Data");
    }

    #[test]
    fn test_undefined_description() {
        assert_eq!(AddressType::Undefined.description(), "Undefined");
    }

    #[test]
    fn test_all_variants_have_descriptions() {
        let variants = [
            AddressType::Function,
            AddressType::Uninitialized,
            AddressType::ExternalRef,
            AddressType::Instruction,
            AddressType::Data,
            AddressType::Undefined,
        ];

        for variant in variants.iter() {
            let desc = variant.description();
            assert!(!desc.is_empty(), "Variant {:?} should have a description", variant);
        }
    }

    #[test]
    fn test_enum_clone_and_copy() {
        let addr_type = AddressType::Function;
        let cloned = addr_type;
        assert_eq!(addr_type, cloned);
    }

    #[test]
    fn test_enum_equality() {
        assert_eq!(AddressType::Function, AddressType::Function);
        assert_ne!(AddressType::Function, AddressType::Data);
    }
}
