use crate::program::model::symbol::Reference;

/// Memory reference whose destination is computed from a base value left
/// shifted by a shift amount.
///
/// This mirrors Ghidra's `ShiftedReference` interface.
pub trait ShiftedReference: Reference {
    /// Returns the left-shift amount.
    fn shift(&self) -> i32;

    /// Returns the base value.
    fn value(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn shifted_reference_exposes_shift_and_value() {
        let reference = TestShiftedReference {
            value: 0x1234,
            shift: 4,
        };

        assert_eq!(reference.value(), 0x1234);
        assert_eq!(reference.shift(), 4);
        assert_eq!(reference.to_address(), addr(0x12340));
        assert!(reference.is_shifted_reference());
        assert!(reference.is_memory_reference());
    }

    struct TestShiftedReference {
        value: i64,
        shift: i32,
    }

    impl ShiftedReference for TestShiftedReference {
        fn shift(&self) -> i32 {
            self.shift
        }

        fn value(&self) -> i64 {
            self.value
        }
    }

    impl Reference for TestShiftedReference {
        fn from_address(&self) -> Address {
            addr(0x2000)
        }

        fn to_address(&self) -> Address {
            addr(self.value << self.shift)
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
            SourceType::Default
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
