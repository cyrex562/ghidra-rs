//! Port of `ghidra.program.database.references.ShiftedReferenceDB`.

use crate::program::database::references::MemReferenceDb;
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, ShiftedReference, SourceType};

/// A memory reference whose destination is computed from a base value left-shifted by a shift
/// amount.
///
/// Port of `ghidra.program.database.references.ShiftedReferenceDB`. Composes a [`MemReferenceDb`]
/// (Java: `extends MemReferenceDB`) rather than inheriting from it.
#[derive(Debug, Clone, PartialEq)]
pub struct ShiftedReferenceDb {
    mem: MemReferenceDb,
}

impl ShiftedReferenceDb {
    /// Stands in for `ShiftedReferenceDB`'s constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        is_primary: bool,
        symbol_id: i64,
        shift: i32,
    ) -> Self {
        ShiftedReferenceDb {
            mem: MemReferenceDb::with_offset_or_shift(
                from_addr,
                to_addr,
                ref_type,
                op_index,
                source_type,
                is_primary,
                symbol_id,
                false,
                true,
                shift as i64,
            ),
        }
    }

    /// Stands in for `ShiftedReferenceDB.equals(Object)`.
    pub fn equals(&self, other: &dyn Reference) -> bool {
        if !other.is_shifted_reference() {
            return false;
        }
        if !self.mem.equals(other) {
            return false;
        }
        let Some(other_shifted) = other.as_any().downcast_ref::<ShiftedReferenceDb>() else {
            // Java compares against `((ShiftedReference) obj).getShift()` regardless of concrete
            // type; without a concrete `ShiftedReferenceDb` to downcast to, this port can only
            // compare shift amounts against another `ShiftedReferenceDb`, which is the only
            // implementor of `ShiftedReference` in this port.
            return false;
        };
        self.shift() == other_shifted.shift()
    }
}

impl Reference for ShiftedReferenceDb {
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
        self.mem.is_memory_reference()
    }

    fn is_register_reference(&self) -> bool {
        self.mem.is_register_reference()
    }

    fn is_offset_reference(&self) -> bool {
        false
    }

    /// Stands in for `MemReferenceDB.isShiftedReference()` as inherited (always `true` here since
    /// the constructor always passes `isShifted = true`).
    fn is_shifted_reference(&self) -> bool {
        true
    }

    fn source(&self) -> SourceType {
        self.mem.source()
    }
}

impl ShiftedReference for ShiftedReferenceDb {
    /// Stands in for `ShiftedReferenceDB.getShift()`.
    fn shift(&self) -> i32 {
        self.mem.offset_or_shift() as i32
    }

    /// Stands in for `ShiftedReferenceDB.getValue()`.
    fn value(&self) -> i64 {
        self.to_address().offset() >> self.mem.offset_or_shift()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn shifted(to: i64, shift: i32) -> ShiftedReferenceDb {
        ShiftedReferenceDb::new(
            addr(0x1000),
            addr(to),
            RefType::Data,
            0,
            SourceType::Analysis,
            true,
            -1,
            shift,
        )
    }

    #[test]
    fn shift_and_value_are_derived() {
        let r = shifted(0x12340, 4);
        assert_eq!(r.shift(), 4);
        assert_eq!(r.value(), 0x1234);
        assert!(r.is_shifted_reference());
        assert!(!r.is_offset_reference());
    }

    #[test]
    fn equals_requires_matching_shift() {
        let a = shifted(0x12340, 4);
        let b = shifted(0x12340, 4);
        assert!(a.equals(&b));

        let different_shift = shifted(0x12340, 8);
        assert!(!a.equals(&different_shift));
    }

    #[test]
    fn equals_rejects_non_shifted_references() {
        use crate::program::database::references::MemReferenceDb;
        let a = shifted(0x12340, 4);
        let plain = MemReferenceDb::new(
            addr(0x1000),
            addr(0x12340),
            RefType::Data,
            0,
            SourceType::Analysis,
            true,
            -1,
        );
        assert!(!a.equals(&plain));
    }
}
