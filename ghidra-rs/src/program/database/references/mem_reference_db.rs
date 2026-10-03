//! Port of `ghidra.program.database.references.MemReferenceDB`.
//!
//! `MemReferenceDB` is Java's plain in-memory reference: `ReferenceDB` plus an owning `Program`
//! and the offset/shift bookkeeping shared by [`StackReferenceDb`], [`ShiftedReferenceDb`], and
//! [`OffsetReferenceDb`] (in sibling modules of this package). It is also directly constructible
//! in Java (`RefListV0`/`BigRefListV0` build plain `MemReferenceDB`s for ordinary memory
//! references), so this port mirrors that: [`MemReferenceDb`] is a standalone, directly usable
//! [`Reference`] implementation, not merely an internal building block.
//!
//! **Not stored: the owning `Program`.** Java's `MemReferenceDB` keeps a `Program program` field
//! for two purposes: (1) `isExternalBlockReference()`, which calls
//! `program.getMemory().isExternalBlockAddress(toAddr)`, and (2) `equals()`, which branches on
//! `program == memRef.program` reference identity to decide whether to compare fields directly or
//! fall back to `SimpleDiffUtility.getCompatibleAddress` cross-program remapping. Neither of those
//! needs full `Program` behavior for the common case (comparing/using references that all belong
//! to the same open program), and pulling in a `Program`/`Memory` dependency here would be a much
//! larger coupling than this leaf value type otherwise needs. So:
//! - `is_external_block_reference` takes the answer as a parameter (the caller -- typically
//!   [`OffsetReferenceDb`]'s owner, which already knows the program -- supplies it) instead of
//!   querying a stored `Program`.
//! - `equals` always takes Java's "same program" comparison path via
//!   [`reference_fields_equal`](crate::program::database::references::reference_db::reference_fields_equal);
//!   the cross-program diff-correlation branch is not ported (see that function's doc comment).

use crate::program::database::references::reference_db::{reference_fields_equal, ReferenceDbCore};
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType};

/// A plain memory-to-memory (or memory-to-register/stack/etc.) reference.
///
/// Port of `ghidra.program.database.references.MemReferenceDB`. See the module docs for what was
/// intentionally left out (the stored `Program` and the cross-program `equals` branch).
#[derive(Debug, Clone, PartialEq)]
pub struct MemReferenceDb {
    core: ReferenceDbCore,
    is_offset: bool,
    is_shifted: bool,
    offset_or_shift: i64,
}

impl MemReferenceDb {
    /// Stands in for `MemReferenceDB`'s package-private 8-arg constructor (plain memory
    /// reference: not an offset or shifted reference).
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
        Self::with_offset_or_shift(
            from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id, false,
            false, 0,
        )
    }

    /// Stands in for `MemReferenceDB`'s protected 11-arg constructor, used by
    /// [`ShiftedReferenceDb`] and [`OffsetReferenceDb`] to set `isOffset`/`isShifted`/
    /// `offsetOrShift`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_offset_or_shift(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        is_primary: bool,
        symbol_id: i64,
        is_offset: bool,
        is_shifted: bool,
        offset_or_shift: i64,
    ) -> Self {
        MemReferenceDb {
            core: ReferenceDbCore::new(
                from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id,
            ),
            is_offset,
            is_shifted,
            offset_or_shift,
        }
    }

    /// Stands in for `MemReferenceDB.isExternalBlockReference()`. See the module docs for why
    /// this takes the answer as a parameter instead of querying a stored `Program`.
    pub fn is_external_block_reference(&self, is_external_block: bool) -> bool {
        is_external_block
    }

    /// Stands in for `MemReferenceDB.isOffset()`.
    pub fn is_offset(&self) -> bool {
        self.is_offset
    }

    /// Stands in for `MemReferenceDB.isShifted()`.
    pub fn is_shifted(&self) -> bool {
        self.is_shifted
    }

    /// Stands in for `MemReferenceDB.getOffsetOrShift()`.
    pub fn offset_or_shift(&self) -> i64 {
        self.offset_or_shift
    }

    /// Stands in for `MemReferenceDB.equals(Object)`. See the module docs for the cross-program
    /// simplification.
    pub fn equals(&self, other: &dyn Reference) -> bool {
        reference_fields_equal(self, other)
    }
}

impl Reference for MemReferenceDb {
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

    fn is_entry_point_reference(&self) -> bool {
        false
    }

    fn is_memory_reference(&self) -> bool {
        self.core.is_memory_reference()
    }

    fn is_register_reference(&self) -> bool {
        self.core.is_register_reference()
    }

    fn is_offset_reference(&self) -> bool {
        self.is_offset
    }

    fn is_shifted_reference(&self) -> bool {
        self.is_shifted
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

    fn plain_ref() -> MemReferenceDb {
        MemReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            0,
            SourceType::UserDefined,
            true,
            5,
        )
    }

    #[test]
    fn plain_constructor_defaults_offset_and_shift_flags_false() {
        let r = plain_ref();
        assert!(!r.is_offset());
        assert!(!r.is_shifted());
        assert_eq!(r.offset_or_shift(), 0);
        assert!(!r.is_offset_reference());
        assert!(!r.is_shifted_reference());
        assert!(!r.is_stack_reference());
        assert!(!r.is_external_reference());
        assert!(!r.is_entry_point_reference());
    }

    #[test]
    fn full_constructor_carries_offset_and_shift_flags() {
        let r = MemReferenceDb::with_offset_or_shift(
            addr(0x1000),
            addr(0x2010),
            RefType::Data,
            0,
            SourceType::Analysis,
            false,
            -1,
            true,
            false,
            0x10,
        );
        assert!(r.is_offset());
        assert!(r.is_offset_reference());
        assert!(!r.is_shifted());
        assert_eq!(r.offset_or_shift(), 0x10);
    }

    #[test]
    fn is_external_block_reference_reflects_supplied_flag() {
        let r = plain_ref();
        assert!(!r.is_external_block_reference(false));
        assert!(r.is_external_block_reference(true));
    }

    #[test]
    fn equals_compares_reference_fields() {
        let a = plain_ref();
        let b = plain_ref();
        assert!(a.equals(&b));

        let different_symbol = MemReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            0,
            SourceType::UserDefined,
            true,
            99,
        );
        assert!(!a.equals(&different_symbol));
    }

    #[test]
    fn behaves_as_trait_object() {
        let r: Box<dyn Reference> = Box::new(plain_ref());
        assert_eq!(r.from_address(), addr(0x1000));
        assert_eq!(r.to_address(), addr(0x2000));
        assert!(r.is_primary());
    }
}
