//! Port of `ghidra.program.database.references.EntryPointReferenceDB`.

use crate::program::database::references::reference_db::{reference_fields_equal, ReferenceDbCore};
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType};

/// A reference marking an entry point.
///
/// Port of `ghidra.program.database.references.EntryPointReferenceDB`. Composes a
/// [`ReferenceDbCore`] (Java: `extends ReferenceDB`) rather than inheriting from it. Note that,
/// unlike [`StackReferenceDb`](crate::program::database::references::StackReferenceDb) et al.,
/// the Java class does not implement a marker `EntryPointReference` interface -- it is a plain
/// `Reference` whose `isEntryPointReference()` override returns `true` -- so this port does not
/// implement `program::model::symbol::EntryPointReference` either, matching Java exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryPointReferenceDb {
    core: ReferenceDbCore,
}

impl EntryPointReferenceDb {
    /// Stands in for `EntryPointReferenceDB`'s constructor.
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
        EntryPointReferenceDb {
            core: ReferenceDbCore::new(
                from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id,
            ),
        }
    }

    /// Stands in for `EntryPointReferenceDB.equals(Object)`.
    pub fn equals(&self, other: &dyn Reference) -> bool {
        self.is_entry_point_reference()
            && other.is_entry_point_reference()
            && reference_fields_equal(self, other)
    }
}

impl Reference for EntryPointReferenceDb {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn from_address(&self) -> Address {
        self.core.from_address()
    }

    fn to_address(&self) -> Address {
        self.core.to_address()
    }

    fn is_primary(&self) -> bool {
        self.core.is_primary()
    }

    fn symbol_id(&self) -> i64 {
        self.core.symbol_id()
    }

    fn reference_type(&self) -> RefType {
        self.core.reference_type()
    }

    fn operand_index(&self) -> i32 {
        self.core.operand_index()
    }

    fn is_mnemonic_reference(&self) -> bool {
        self.core.is_mnemonic_reference()
    }

    fn is_operand_reference(&self) -> bool {
        self.core.is_operand_reference()
    }

    fn is_stack_reference(&self) -> bool {
        false
    }

    fn is_external_reference(&self) -> bool {
        false
    }

    /// Stands in for `EntryPointReferenceDB.isEntryPointReference()`.
    fn is_entry_point_reference(&self) -> bool {
        true
    }

    fn is_memory_reference(&self) -> bool {
        self.core.is_memory_reference()
    }

    fn is_register_reference(&self) -> bool {
        self.core.is_register_reference()
    }

    fn is_offset_reference(&self) -> bool {
        false
    }

    fn is_shifted_reference(&self) -> bool {
        false
    }

    fn source(&self) -> SourceType {
        self.core.source()
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

    fn entry_ref() -> EntryPointReferenceDb {
        EntryPointReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            -1,
            SourceType::Analysis,
            true,
            -1,
        )
    }

    #[test]
    fn is_entry_point_reference_is_always_true() {
        let r = entry_ref();
        assert!(r.is_entry_point_reference());
        assert!(!r.is_stack_reference());
        assert!(!r.is_offset_reference());
        assert!(!r.is_shifted_reference());
        assert!(!r.is_external_reference());
    }

    #[test]
    fn equals_requires_both_sides_be_entry_point_references() {
        let a = entry_ref();
        let b = entry_ref();
        assert!(a.equals(&b));

        use crate::program::database::references::MemReferenceDb;
        let plain = MemReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            -1,
            SourceType::Analysis,
            true,
            -1,
        );
        assert!(!a.equals(&plain));
    }

    #[test]
    fn equals_compares_fields_when_both_are_entry_points() {
        let a = entry_ref();
        let different_to = EntryPointReferenceDb::new(
            addr(0x1000),
            addr(0x3000),
            RefType::Data,
            -1,
            SourceType::Analysis,
            true,
            -1,
        );
        assert!(!a.equals(&different_to));
    }
}
