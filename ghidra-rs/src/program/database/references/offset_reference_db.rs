//! Port of `ghidra.program.database.references.OffsetReferenceDB`.
//!
//! **Not stored: a live `Program`/`Memory` lookup for `isExternalBlockReference()`.** Java's
//! `getBaseAddress()` calls `isExternalBlockReference()` (inherited from `MemReferenceDB`, which
//! queries `program.getMemory().isExternalBlockAddress(toAddr)`) on every call to decide whether
//! to report `toAddr` unchanged (the reserved "EXTERNAL" block exception) or subtract the offset.
//! Since a reference's `toAddr` and the memory layout that decides "is this the EXTERNAL block"
//! are both fixed for the reference's lifetime once constructed, this port resolves that check
//! once at construction time (the caller -- which already has `Program` access -- supplies it)
//! instead of storing a `Program` and re-querying it on every `base_address()` call. This is the
//! same simplification already anticipated by
//! [`OffsetReference`](crate::program::model::symbol::OffsetReference)'s own doc comment.

use crate::program::database::references::MemReferenceDb;
use crate::program::model::address::Address;
use crate::program::model::symbol::{OffsetReference, RefType, Reference, SourceType};

/// A memory reference whose destination is computed from a base address plus an offset.
///
/// Port of `ghidra.program.database.references.OffsetReferenceDB`. Composes a [`MemReferenceDb`]
/// (Java: `extends MemReferenceDB`) rather than inheriting from it. See the module docs for the
/// `is_external_block` simplification.
#[derive(Debug, Clone, PartialEq)]
pub struct OffsetReferenceDb {
    mem: MemReferenceDb,
    is_external_block: bool,
}

impl OffsetReferenceDb {
    /// Stands in for `OffsetReferenceDB`'s constructor. `is_external_block` stands in for a live
    /// `program.getMemory().isExternalBlockAddress(to_addr)` check -- see the module docs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        is_primary: bool,
        symbol_id: i64,
        offset: i64,
        is_external_block: bool,
    ) -> Self {
        OffsetReferenceDb {
            mem: MemReferenceDb::with_offset_or_shift(
                from_addr,
                to_addr,
                ref_type,
                op_index,
                source_type,
                is_primary,
                symbol_id,
                true,
                false,
                offset,
            ),
            is_external_block,
        }
    }

    /// Stands in for `OffsetReferenceDB.toString()` (via `MemReferenceDB.toString()` plus the
    /// `" Offset: 0x..."`/`" Offset: -0x..."` suffix from `NumericUtilities.toSignedHexString`).
    pub fn to_display_string(&self) -> String {
        let offset = self.offset();
        let offset_str = if offset < 0 {
            format!("-0x{:x}", offset.unsigned_abs())
        } else {
            format!("0x{:x}", offset)
        };
        format!(
            "From: {} To: {} Op: {} Offset: {}",
            self.from_address(),
            self.to_address(),
            self.operand_index(),
            offset_str
        )
    }

    /// Stands in for `OffsetReferenceDB.equals(Object)`.
    pub fn equals(&self, other: &dyn Reference) -> bool {
        if !other.is_offset_reference() {
            return false;
        }
        if !self.mem.equals(other) {
            return false;
        }
        let Some(other_offset) = other.as_offset_reference() else {
            return false;
        };
        self.offset() == other_offset.offset()
    }
}

impl Reference for OffsetReferenceDb {
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

    /// Stands in for `MemReferenceDB.isOffsetReference()` as inherited (always `true` here since
    /// the constructor always passes `isOffset = true`).
    fn is_offset_reference(&self) -> bool {
        true
    }

    fn is_shifted_reference(&self) -> bool {
        false
    }

    fn source(&self) -> SourceType {
        self.mem.source()
    }

    fn as_offset_reference(&self) -> Option<&dyn OffsetReference> {
        Some(self)
    }
}

impl OffsetReference for OffsetReferenceDb {
    /// Stands in for `OffsetReferenceDB.getOffset()`.
    fn offset(&self) -> i64 {
        self.mem.offset_or_shift()
    }

    /// Stands in for `OffsetReferenceDB.getBaseAddress()`.
    fn base_address(&self) -> Address {
        if self.mem.is_external_block_reference(self.is_external_block) {
            // EXTERNAL block: must report toAddr and base as the same regardless of offset
            return self.to_address();
        }
        self.to_address().subtract_wrap(self.offset())
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

    fn offset_ref(to: i64, offset: i64, is_external_block: bool) -> OffsetReferenceDb {
        OffsetReferenceDb::new(
            addr(0x1000),
            addr(to),
            RefType::Data,
            0,
            SourceType::Analysis,
            true,
            -1,
            offset,
            is_external_block,
        )
    }

    #[test]
    fn offset_and_base_address_are_derived() {
        let r = offset_ref(0x1020, 0x20, false);
        assert_eq!(r.offset(), 0x20);
        assert_eq!(r.base_address(), addr(0x1000));
        assert!(r.is_offset_reference());
        assert!(!r.is_shifted_reference());
    }

    #[test]
    fn external_block_reference_reports_to_address_as_base() {
        let r = offset_ref(0x1020, 0x20, true);
        assert_eq!(r.base_address(), addr(0x1020));
    }

    #[test]
    fn as_offset_reference_downcast_works() {
        let r = offset_ref(0x1020, 0x20, false);
        let dynref: &dyn Reference = &r;
        let downcast = dynref.as_offset_reference().expect("should downcast");
        assert_eq!(downcast.offset(), 0x20);
    }

    #[test]
    fn to_display_string_handles_negative_offset() {
        let r = offset_ref(0xfe0, -0x20, false);
        assert_eq!(
            r.to_display_string(),
            "From: ram:0x1000 To: ram:0xfe0 Op: 0 Offset: -0x20"
        );
    }

    #[test]
    fn equals_requires_matching_offset() {
        let a = offset_ref(0x1020, 0x20, false);
        let b = offset_ref(0x1020, 0x20, false);
        assert!(a.equals(&b));

        let different_offset = offset_ref(0x1020, 0x10, false);
        assert!(!a.equals(&different_offset));
    }
}
