use crate::program::model::symbol::Reference;

/// Marker trait for references to entry points.
///
/// This mirrors Ghidra's `EntryPointReference` interface.
pub trait EntryPointReference: Reference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn entry_point_reference_is_reference_marker() {
        let reference = TestEntryPointReference;

        assert!(reference.is_entry_point_reference());
        assert_reference(&reference);
    }

    fn assert_reference(reference: &dyn Reference) {
        assert_eq!(reference.reference_type(), RefType::Data);
    }

    struct TestEntryPointReference;

    impl EntryPointReference for TestEntryPointReference {}

    impl Reference for TestEntryPointReference {
        fn from_address(&self) -> Address {
            addr(0x1000)
        }

        fn to_address(&self) -> Address {
            addr(0x2000)
        }

        fn is_primary(&self) -> bool {
            false
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
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            true
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
            SourceType::Default
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
