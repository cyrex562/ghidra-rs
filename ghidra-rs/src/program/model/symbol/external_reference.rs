use crate::program::model::symbol::{ExternalLocation, Reference};

/// Reference to an external location (a symbol in another program/library).
///
/// This mirrors Ghidra's `ExternalReference` interface.
pub trait ExternalReference: Reference {
    /// Returns the object that represents the external location.
    fn get_external_location(&self) -> Box<dyn ExternalLocation>;

    /// Returns the name of the external library containing this location.
    fn get_library_name(&self) -> String;

    /// Returns the external label associated with this location (may be `None`).
    fn get_label(&self) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    struct MockExternalLocation;
    impl ExternalLocation for MockExternalLocation {}

    struct TestExternalReference;

    impl Reference for TestExternalReference {
        fn from_address(&self) -> Address {
            addr(0x1000)
        }

        fn to_address(&self) -> Address {
            addr(0x2000)
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            RefType::Data
        }

        fn operand_index(&self) -> i32 {
            0
        }

        fn is_mnemonic_reference(&self) -> bool {
            false
        }

        fn is_operand_reference(&self) -> bool {
            true
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            true
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
            SourceType::Default
        }
    }

    impl ExternalReference for TestExternalReference {
        fn get_external_location(&self) -> Box<dyn ExternalLocation> {
            Box::new(MockExternalLocation)
        }

        fn get_library_name(&self) -> String {
            "MyLib".to_string()
        }

        fn get_label(&self) -> Option<String> {
            Some("entry".to_string())
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn external_reference_exposes_location_library_and_label() {
        let reference = TestExternalReference;
        let _location: Box<dyn ExternalLocation> = reference.get_external_location();

        assert_eq!(reference.get_library_name(), "MyLib");
        assert_eq!(reference.get_label(), Some("entry".to_string()));
        assert!(reference.is_external_reference());
    }
}
