use crate::program::model::symbol::Reference;

/// Reference to a stack location.
///
/// This mirrors Ghidra's `StackReference` interface.
pub trait StackReference: Reference {
    /// Returns the offset of the referenced stack location.
    fn stack_offset(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn stack_reference_exposes_stack_offset() {
        let reference = TestStackReference {
            stack_offset: -0x10,
        };

        assert_eq!(reference.stack_offset(), -0x10);
        assert!(reference.is_stack_reference());
        assert!(!reference.is_memory_reference());
    }

    struct TestStackReference {
        stack_offset: i32,
    }

    impl StackReference for TestStackReference {
        fn stack_offset(&self) -> i32 {
            self.stack_offset
        }
    }

    impl Reference for TestStackReference {
        fn from_address(&self) -> Address {
            addr(0x1000, AddressSpaceType::Ram)
        }

        fn to_address(&self) -> Address {
            addr(self.stack_offset as i64, AddressSpaceType::Stack)
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            RefType::Read
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
            SourceType::Default
        }
    }

    fn addr(offset: i64, space_type: AddressSpaceType) -> Address {
        let space = AddressSpace::new("space", 32, 1, space_type, space_type as i32);
        Address::new(space, offset)
    }
}
