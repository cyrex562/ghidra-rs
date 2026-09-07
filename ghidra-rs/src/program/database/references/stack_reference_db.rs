//! Port of `ghidra.program.database.references.StackReferenceDB`.

use crate::program::database::references::MemReferenceDb;
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType, StackReference};

/// A reference to a stack location.
///
/// Port of `ghidra.program.database.references.StackReferenceDB`. Composes a [`MemReferenceDb`]
/// (Java: `extends MemReferenceDB`) rather than inheriting from it.
#[derive(Debug, Clone, PartialEq)]
pub struct StackReferenceDb {
    mem: MemReferenceDb,
}

impl StackReferenceDb {
    /// Stands in for `StackReferenceDB`'s constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        is_primary: bool,
        symbol_id: i64,
    ) -> Self {
        StackReferenceDb {
            mem: MemReferenceDb::new(
                from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id,
            ),
        }
    }

    /// Stands in for `StackReferenceDB.equals(Object)` (inherited unchanged from
    /// `MemReferenceDB`; `StackReferenceDB` declares no override of its own).
    pub fn equals(&self, other: &dyn Reference) -> bool {
        self.mem.equals(other)
    }
}

impl Reference for StackReferenceDb {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn from_address(&self) -> Address {
        self.mem.from_address()
    }

    fn to_address(&self) -> Address {
        self.mem.to_address()
    }

    fn is_primary(&self) -> bool {
        self.mem.is_primary()
    }

    fn symbol_id(&self) -> i64 {
        self.mem.symbol_id()
    }

    fn reference_type(&self) -> RefType {
        self.mem.reference_type()
    }

    fn operand_index(&self) -> i32 {
        self.mem.operand_index()
    }

    fn is_mnemonic_reference(&self) -> bool {
        self.mem.is_mnemonic_reference()
    }

    fn is_operand_reference(&self) -> bool {
        self.mem.is_operand_reference()
    }

    /// Stands in for `StackReferenceDB.isStackReference()`.
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
        self.mem.is_memory_reference()
    }

    fn is_register_reference(&self) -> bool {
        self.mem.is_register_reference()
    }

    fn is_offset_reference(&self) -> bool {
        self.mem.is_offset_reference()
    }

    fn is_shifted_reference(&self) -> bool {
        self.mem.is_shifted_reference()
    }

    fn source(&self) -> SourceType {
        self.mem.source()
    }

    fn as_stack_reference(&self) -> Option<&dyn StackReference> {
        Some(self)
    }
}

impl StackReference for StackReferenceDb {
    /// Stands in for `StackReferenceDB.getStackOffset()`.
    fn stack_offset(&self) -> i32 {
        self.to_address().offset() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn stack() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1)
    }

    fn stack_ref(offset: i64) -> StackReferenceDb {
        StackReferenceDb::new(
            Address::new(ram(), 0x1000),
            Address::new(stack(), offset),
            RefType::Data,
            0,
            SourceType::UserDefined,
            true,
            -1,
        )
    }

    #[test]
    fn stack_offset_is_derived_from_to_address() {
        let r = stack_ref(-8);
        assert_eq!(r.stack_offset(), -8);
        assert!(r.is_stack_reference());
    }

    #[test]
    fn is_stack_reference_is_always_true_and_other_type_flags_stay_false() {
        let r = stack_ref(4);
        assert!(r.is_stack_reference());
        assert!(!r.is_offset_reference());
        assert!(!r.is_shifted_reference());
        assert!(!r.is_external_reference());
        assert!(!r.is_entry_point_reference());
    }

    #[test]
    fn as_stack_reference_downcast_works() {
        let r = stack_ref(12);
        let dynref: &dyn Reference = &r;
        let downcast = dynref.as_stack_reference().expect("should downcast");
        assert_eq!(downcast.stack_offset(), 12);
    }

    #[test]
    fn equals_compares_fields() {
        let a = stack_ref(4);
        let b = stack_ref(4);
        assert!(a.equals(&b));

        let c = stack_ref(8);
        assert!(!a.equals(&c));
    }
}
