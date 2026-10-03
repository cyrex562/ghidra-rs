//! Port of `ghidra.program.database.references.ReferenceDB`.
//!
//! The Java class is `abstract`, implementing every method of `Reference` except `equals`, which
//! each concrete subclass (`MemReferenceDB`, `EntryPointReferenceDB`, `ExternalReferenceDB`, ...)
//! supplies itself. Rather than model that as a Rust base trait/struct that leaf types inherit
//! from, this port keeps the shared field storage and default behavior in [`ReferenceDbCore`], a
//! plain composable struct: concrete leaf types (in sibling modules of this package) embed a
//! `ReferenceDbCore` field, delegate most [`Reference`] methods to it, and layer their own
//! `equals`/type-specific overrides on top -- this project's compose-not-inherit convention.
//!
//! `ReferenceDB.hashCode()` (`fromAddr.hashCode()`) is not ported as a standalone method: Rust's
//! `Address` already implements [`std::hash::Hash`], so a concrete leaf type wanting Java-parity
//! hashing can derive/forward to `from_addr.hash(state)` directly rather than going through this
//! core.

use std::cmp::Ordering;

use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType};

/// Shared field storage and default behavior for a database-backed [`Reference`].
///
/// Port of `ghidra.program.database.references.ReferenceDB`. See the module docs for how concrete
/// leaf types compose this instead of extending it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceDbCore {
    from_addr: Address,
    to_addr: Address,
    ref_type: RefType,
    op_index: i32,
    source_type: SourceType,
    symbol_id: i64,
    is_primary: bool,
}

impl ReferenceDbCore {
    /// Stands in for `ReferenceDB`'s package-private constructor.
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        is_primary: bool,
        symbol_id: i64,
    ) -> Self {
        ReferenceDbCore {
            from_addr,
            to_addr,
            ref_type,
            op_index,
            source_type,
            symbol_id,
            is_primary,
        }
    }

    /// Stands in for `ReferenceDB.getFromAddress()`.
    pub fn from_address(&self) -> Address {
        self.from_addr.clone()
    }

    /// Stands in for `ReferenceDB.getToAddress()`.
    pub fn to_address(&self) -> Address {
        self.to_addr.clone()
    }

    /// Stands in for `ReferenceDB.getReferenceType()`.
    pub fn reference_type(&self) -> RefType {
        self.ref_type
    }

    /// Stands in for `ReferenceDB.getOperandIndex()`.
    pub fn operand_index(&self) -> i32 {
        self.op_index
    }

    /// Stands in for `ReferenceDB.isOperandReference()`.
    pub fn is_operand_reference(&self) -> bool {
        self.op_index >= 0
    }

    /// Stands in for `ReferenceDB.isMnemonicReference()`.
    pub fn is_mnemonic_reference(&self) -> bool {
        !self.is_operand_reference()
    }

    /// Stands in for `ReferenceDB.getSymbolID()`.
    pub fn symbol_id(&self) -> i64 {
        self.symbol_id
    }

    /// Stands in for `ReferenceDB.isPrimary()`.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Stands in for `ReferenceDB.getSource()`.
    pub fn source(&self) -> SourceType {
        self.source_type
    }

    /// Stands in for `ReferenceDB.isMemoryReference()`.
    pub fn is_memory_reference(&self) -> bool {
        self.to_addr.is_memory_address()
    }

    /// Stands in for `ReferenceDB.isRegisterReference()`.
    pub fn is_register_reference(&self) -> bool {
        self.to_addr.is_register_address()
    }

    /// Stands in for `ReferenceDB.toString()`.
    pub fn to_display_string(&self) -> String {
        format!(
            "From: {} To: {} Type: {} Op: {} {}",
            self.from_addr,
            self.to_addr,
            self.ref_type,
            self.op_index,
            self.source_type.display_string()
        )
    }

    /// Stands in for `ReferenceDB.compareTo(Reference)`.
    pub fn compare_to(&self, other: &dyn Reference) -> Ordering {
        let result = self.from_addr.cmp(&other.from_address());
        if result != Ordering::Equal {
            return result;
        }
        let result = self.op_index.cmp(&other.operand_index());
        if result != Ordering::Equal {
            return result;
        }
        self.to_addr.cmp(&other.to_address())
    }
}

/// Stands in for the field-by-field comparison shared by `ReferenceDB` subclasses' `equals`
/// overrides: `MemReferenceDB.equals`'s same-program branch and its `instanceof Reference`
/// fallback branch compare exactly these fields, as does `EntryPointReferenceDB.equals` (which
/// additionally requires `isEntryPointReference()`).
///
/// This port does not model per-`Program` identity the way `MemReferenceDB`/`EntryPointReferenceDB`
/// do (see `mem_reference_db.rs`'s module docs for why), so callers always get the "same program"
/// comparison Java's `program == memRef.program` branch takes; Java's cross-program
/// `SimpleDiffUtility.getCompatibleAddress` remapping branch (taken only when comparing references
/// that live in two distinct, already-open `Program` instances) is not ported.
pub fn reference_fields_equal(a: &dyn Reference, b: &dyn Reference) -> bool {
    a.from_address() == b.from_address()
        && a.to_address() == b.to_address()
        && a.operand_index() == b.operand_index()
        && a.symbol_id() == b.symbol_id()
        && a.is_primary() == b.is_primary()
        && a.source() == b.source()
        && a.reference_type() == b.reference_type()
        && a.is_shifted_reference() == b.is_shifted_reference()
        && a.is_offset_reference() == b.is_offset_reference()
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

    fn core(op_index: i32) -> ReferenceDbCore {
        ReferenceDbCore::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            op_index,
            SourceType::UserDefined,
            true,
            7,
        )
    }

    #[test]
    fn getters_read_through_to_stored_fields() {
        let core = core(1);
        assert_eq!(core.from_address(), addr(0x1000));
        assert_eq!(core.to_address(), addr(0x2000));
        assert_eq!(core.reference_type(), RefType::Data);
        assert_eq!(core.operand_index(), 1);
        assert_eq!(core.symbol_id(), 7);
        assert!(core.is_primary());
        assert_eq!(core.source(), SourceType::UserDefined);
    }

    #[test]
    fn mnemonic_vs_operand_reference_is_derived_from_op_index() {
        let mnemonic = core(-1);
        assert!(mnemonic.is_mnemonic_reference());
        assert!(!mnemonic.is_operand_reference());

        let operand = core(0);
        assert!(!operand.is_mnemonic_reference());
        assert!(operand.is_operand_reference());
    }

    #[test]
    fn memory_and_register_reference_come_from_to_address_space() {
        let mem = core(0);
        assert!(mem.is_memory_reference());
        assert!(!mem.is_register_reference());

        let reg_space = AddressSpace::new("reg", 32, 1, AddressSpaceType::Register, 1);
        let reg_core = ReferenceDbCore::new(
            addr(0x1000),
            Address::new(reg_space, 0),
            RefType::Data,
            0,
            SourceType::Default,
            false,
            -1,
        );
        assert!(!reg_core.is_memory_reference());
        assert!(reg_core.is_register_reference());
    }

    #[test]
    fn to_display_string_matches_java_format() {
        let core = core(0);
        assert_eq!(
            core.to_display_string(),
            "From: ram:0x1000 To: ram:0x2000 Type: DATA Op: 0 User Defined"
        );
    }

    #[test]
    fn compare_to_orders_by_from_then_op_index_then_to() {
        struct Other {
            from: Address,
            to: Address,
            op_index: i32,
        }
        impl Reference for Other {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
            fn from_address(&self) -> Address {
                self.from.clone()
            }
            fn to_address(&self) -> Address {
                self.to.clone()
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
                self.op_index
            }
            fn is_mnemonic_reference(&self) -> bool {
                self.op_index < 0
            }
            fn is_operand_reference(&self) -> bool {
                self.op_index >= 0
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
                false
            }
            fn source(&self) -> SourceType {
                SourceType::Default
            }
        }

        let core = core(0);
        let same = Other {
            from: addr(0x1000),
            to: addr(0x2000),
            op_index: 0,
        };
        assert_eq!(core.compare_to(&same), Ordering::Equal);

        let earlier_from = Other {
            from: addr(0x500),
            to: addr(0x2000),
            op_index: 0,
        };
        assert_eq!(core.compare_to(&earlier_from), Ordering::Greater);

        let later_op = Other {
            from: addr(0x1000),
            to: addr(0x2000),
            op_index: 5,
        };
        assert_eq!(core.compare_to(&later_op), Ordering::Less);
    }
}
