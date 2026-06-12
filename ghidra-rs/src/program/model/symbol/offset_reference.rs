use crate::program::model::address::Address;
use crate::program::model::symbol::Reference;

/// Memory reference whose destination is computed from a base address plus an
/// offset.
///
/// This mirrors Ghidra's `OffsetReference` interface. Implementations that
/// refer into the reserved external block should return the base address from
/// `to_address`, matching Ghidra's external-block exception.
pub trait OffsetReference: Reference {
    /// Returns the offset from the base address.
    fn offset(&self) -> i64;

    /// Returns the base address.
    fn base_address(&self) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn offset_reference_exposes_base_offset_and_computed_to_address() {
        let reference = TestOffsetReference {
            base_address: addr(0x1000),
            offset: 0x20,
        };

        assert_eq!(reference.base_address(), addr(0x1000));
        assert_eq!(reference.offset(), 0x20);
        assert_eq!(reference.to_address(), addr(0x1020));
        assert!(reference.is_offset_reference());
        assert!(reference.is_memory_reference());
    }

    struct TestOffsetReference {
        base_address: Address,
        offset: i64,
    }

    impl OffsetReference for TestOffsetReference {
        fn offset(&self) -> i64 {
            self.offset
        }

        fn base_address(&self) -> Address {
            self.base_address.clone()
        }
    }

    impl Reference for TestOffsetReference {
        fn from_address(&self) -> Address {
            addr(0x2000)
        }

        fn to_address(&self) -> Address {
            self.base_address.add(self.offset).unwrap()
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
            true
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
